// Package netio provides the low-level socket plumbing: a raw IPv4
// sender (IP_HDRINCL, we own every byte) and a raw TCP receiver
// bound to the target port (hping-style) to count SYN-ACK / RST
// replies.
package netio

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"cve98432/internal/packet"
)

// Sender transmits pre-built IP datagrams.
type Sender struct {
	fd     int
	closed bool
}

// OpenSender creates the raw TCP socket. Requires CAP_NET_RAW
// (root or setcap). If srcIP is empty the socket stays unbound.
func OpenSender(srcIP string) (*Sender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, errors.New("opening raw socket requires CAP_NET_RAW (run with sudo or setcap cap_net_raw+ep)")
		}
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	s := &Sender{fd: fd}
	if srcIP != "" {
		ip := net.ParseIP(srcIP).To4()
		if ip == nil {
			unix.Close(fd)
			return nil, errors.New("bad source IP")
		}
		sa := &unix.SockaddrInet4{Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]}}
		if err := unix.Bind(fd, sa); err != nil {
			unix.Close(fd)
			return nil, errors.New("bind source IP: " + err.Error())
		}
	}
	return s, nil
}

// Send pushes one datagram to dstIP:dstPort.
func (s *Sender) Send(pkt []byte, dstIP net.IP, dstPort uint16) error {
	ip := dstIP.To4()
	if ip == nil {
		return errors.New("bad destination IP")
	}
	sa := &unix.SockaddrInet4{Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]}, Port: int(htons(dstPort))}
	return unix.Sendto(s.fd, pkt, 0, sa)
}

// Close releases the socket.
func (s *Sender) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}

// Receiver listens for TCP replies to the target 4-tuple and
// classifies them. A raw socket matches by protocol only, so it
// ALSO receives our own SYNs (they loop back on 127.0.0.1) and
// all unrelated host traffic; matchesReply() filters that out.
type Receiver struct {
	fd        int
	synAck    atomic.Int64
	rst       atomic.Int64
	other     atomic.Int64
	lastReply atomic.Int64 // unix nano of the last SYN-ACK/RST
	fromIP    net.IP       // replies must come from this address
	fromPort  uint16       // ... and this port (the target's)
}

// OpenReceiver creates the raw TCP receiver. targetIP/targetPort
// describe the 4-tuple replies are expected from (the target
// host); pass a nil targetIP to disable the filter.
func OpenReceiver(targetIP net.IP, targetPort uint16) (*Receiver, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, errors.New("opening raw socket requires CAP_NET_RAW (run with sudo or setcap cap_net_raw+ep)")
		}
		return nil, err
	}
	// A raw-socket bind carries only the address (the kernel
	// ignores the port), so keep the default INADDR_ANY.
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// 500 ms receive timeout so the loop can observe context
	// cancellation.
	tv := unix.Timeval{Sec: 0, Usec: 500_000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	r := &Receiver{fd: fd}
	if targetIP != nil {
		r.fromIP = targetIP
		r.fromPort = targetPort
	}
	return r, nil
}

// Run consumes replies until ctx is done. Only packets from
// (fromIP, fromPort) are counted; lastReply is updated for
// SYN-ACK and RST only — those are what a healthy kernel answers
// with, so "other" traffic cannot mask silence.
func (r *Receiver) Run(ctx context.Context, onReply func(kind string)) {
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
			// Fatal (closed fd, etc.) or slow path: yield and retry
			// so context cancellation stays responsive.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		if n < 20 {
			continue
		}
		if r.fromIP != nil && !matchesReply(buf[:n], r.fromIP, r.fromPort) {
			continue // our own SYNs / unrelated host traffic
		}
		kind := classify(buf[:n])
		switch kind {
		case "synack":
			r.synAck.Add(1)
			r.lastReply.Store(time.Now().UnixNano())
		case "rst":
			r.rst.Add(1)
			r.lastReply.Store(time.Now().UnixNano())
		default:
			r.other.Add(1)
		}
		if onReply != nil {
			onReply(kind)
		}
	}
}

// matchesReply reports whether b is a TCP packet whose source is
// (fromIP, fromPort).
func matchesReply(b []byte, fromIP net.IP, fromPort uint16) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0F) * 4
	if b[9] != 6 || ihl < 20 || len(b) < ihl+2 {
		return false
	}
	v4 := fromIP.To4()
	if v4 == nil {
		return false
	}
	if b[12] != v4[0] || b[13] != v4[1] || b[14] != v4[2] || b[15] != v4[3] {
		return false
	}
	return binary.BigEndian.Uint16(b[ihl:ihl+2]) == fromPort
}

// ReplyCounts returns (synack, rst, other).
func (r *Receiver) ReplyCounts() (uint64, uint64, uint64) {
	return uint64(r.synAck.Load()), uint64(r.rst.Load()), uint64(r.other.Load())
}

// LastReplyNano returns the time of the last SYN-ACK/RST reply (0
// if none).
func (r *Receiver) LastReplyNano() int64 {
	return r.lastReply.Load()
}

// Close releases the socket.
func (r *Receiver) Close() error {
	return unix.Close(r.fd)
}

// classify inspects an IP packet and returns "synack", "rst" or
// "other".
func classify(b []byte) string {
	if len(b) < 20 || b[0]>>4 != 4 {
		return "other"
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || len(b) < ihl+20 {
		return "other"
	}
	if b[9] != 6 {
		return "other"
	}
	tcp := b[ihl:]
	flags := tcp[13]
	if flags&0x02 != 0 && flags&0x10 != 0 {
		return "synack"
	}
	if flags&0x04 != 0 {
		return "rst"
	}
	return "other"
}

// ErrTimeout is returned by Tap.Recv when no packet arrived within
// the requested window.
var ErrTimeout = errors.New("tap: receive timeout")

// Tap is a raw TCP socket used to receive and timestamp individual
// reply packets with full 4-tuple context (the Receiver only
// counts). Used by the handshake mode: it must see the exact
// SYN-ACK for the round's 4-tuple (to recover the server ISN for
// the completing ACK) and, afterwards, any second SYN-ACK — the
// reader-evidence that the retransmitted SYN still hit the request
// socket.
type Tap struct {
	fd     int
	closed bool
	// fromIP/fromPort filter what Recv() returns (0 = no filter).
	fromIP   net.IP
	fromPort uint16
	// recvBuf is a reusable receive buffer. Recv() runs in a single
	// goroutine (the coordinator), so sharing is safe; reusing avoids
	// a 2 KB allocation per call, which would accumulate without
	// bound while the engine has GC disabled for the run.
	recvBuf [2048]byte
}

// OpenTap creates the raw receiver. Pass a nil fromIP to disable
// the 4-tuple filter.
func OpenTap(fromIP net.IP, fromPort uint16) (*Tap, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, errors.New("opening raw socket requires CAP_NET_RAW (run with sudo or setcap cap_net_raw+ep)")
		}
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// 1 ms receive timeout: the caller loops with its own deadline
	// and this bounds each individual recv.
	tv := unix.Timeval{Sec: 0, Usec: 1_000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	t := &Tap{fd: fd}
	if fromIP != nil {
		t.fromIP = fromIP
		t.fromPort = fromPort
	}
	return t, nil
}

// Recv returns the next IP packet from the target (fromIP:fromPort)
// that is not older than timeout, with a timestamp taken right after
// the kernel hands the bytes to userspace. Packets that do not
// match the filter are consumed silently. The returned slice is a
// fresh copy and safe to keep.
func (t *Tap) Recv(timeout time.Duration) (pkt []byte, at time.Time, err error) {
	deadline := time.Now().Add(timeout)
	buf := t.recvBuf[:]
	for {
		n, _, recvErr := unix.Recvfrom(t.fd, buf, 0)
		now := time.Now()
		if recvErr != nil {
			if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK || recvErr == unix.EINTR {
				if now.After(deadline) {
					return nil, now, ErrTimeout
				}
				continue
			}
			return nil, now, recvErr
		}
		if n < 20 {
			if now.After(deadline) {
				return nil, now, ErrTimeout
			}
			continue
		}
		if t.fromIP != nil && !matchesReply(buf[:n], t.fromIP, t.fromPort) {
			if now.After(deadline) {
				return nil, now, ErrTimeout
			}
			continue
		}
		pkt = make([]byte, n)
		copy(pkt, buf[:n])
		return pkt, now, nil
	}
}

// Close releases the socket.
func (t *Tap) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	return unix.Close(t.fd)
}

// TCPPkt is the parsed view of one IPv4/TCP datagram.
type TCPPkt struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	Flags    byte // raw TCP flags byte
	DataOff  int  // TCP data offset in bytes (20 + options)
	IPOptLen int  // IP options length in bytes
	IPID     uint16
	TTL      uint8
	Raw      []byte
}

// ParseTCP parses an IPv4 datagram carrying TCP. ok is false for
// anything else (non-IP, non-TCP, truncated).
func ParseTCP(b []byte) (p TCPPkt, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || ihl+20 > len(b) {
		return
	}
	if b[9] != 6 {
		return
	}
	tcp := b[ihl:]
	p.IPOptLen = ihl - 20
	p.IPID = binary.BigEndian.Uint16(b[4:6])
	p.TTL = b[8]
	p.SrcIP = net.IPv4(b[12], b[13], b[14], b[15])
	p.DstIP = net.IPv4(b[16], b[17], b[18], b[19])
	p.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	p.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	p.Seq = binary.BigEndian.Uint32(tcp[4:8])
	p.Ack = binary.BigEndian.Uint32(tcp[8:12])
	p.DataOff = int(tcp[12]>>4) * 4
	p.Flags = tcp[13]
	p.Raw = b
	return p, true
}

// IsSynAck reports whether the packet is a SYN+ACK.
func (p TCPPkt) IsSynAck() bool {
	return p.Flags&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN|packet.FlagACK
}

// IsRST reports whether the RST bit is set.
func (p TCPPkt) IsRST() bool {
	return p.Flags&packet.FlagRST != 0
}

// htons converts a host-order port to network order.
func htons(p uint16) uint16 {
	return (p<<8)&0xFF00 | p>>8
}
