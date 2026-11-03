package netio

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// buildIP wraps a TCP payload in a minimal IPv4 header for the
// classifier tests.
func buildIP(proto byte, tcp []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(tcp)))
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], []byte{10, 0, 0, 1})
	copy(hdr[16:20], []byte{10, 0, 0, 2})
	return append(hdr, tcp...)
}

func buildTCP(flags byte) []byte {
	t := make([]byte, 20)
	t[0], t[1] = 0x00, 0x50 // sport 80
	t[2], t[3] = 0x00, 0x50 // dport 80
	t[12] = 0x50            // data offset 5
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:16], 65535)
	return t
}

func TestClassifySynAck(t *testing.T) {
	if got := classify(buildIP(6, buildTCP(0x12))); got != "synack" {
		t.Errorf("got %q, want synack", got)
	}
}

func TestClassifyRST(t *testing.T) {
	if got := classify(buildIP(6, buildTCP(0x04))); got != "rst" {
		t.Errorf("got %q, want rst", got)
	}
}

func TestClassifyOther(t *testing.T) {
	// plain ACK
	if got := classify(buildIP(6, buildTCP(0x10))); got != "other" {
		t.Errorf("got %q, want other", got)
	}
	// not TCP
	if got := classify(buildIP(17, buildTCP(0x12))); got != "other" {
		t.Errorf("got %q, want other (udp)", got)
	}
	// too short
	if got := classify([]byte{0x45, 0, 0, 40}); got != "other" {
		t.Errorf("got %q, want other (short)", got)
	}
}

// M1: the raw receiver gets ALL host traffic (its bind ignores the
// port), so only replies from the target's (ip, port) may be
// counted. matchesReply implements that 4-tuple filter.
func TestMatchesReply(t *testing.T) {
	from := net.IPv4(10, 0, 0, 1)
	// A reply from (10.0.0.1, 80) matches.
	if !matchesReply(buildIP(6, buildTCP(0x12)), from, 80) {
		t.Error("target 4-tuple source must match")
	}
	// A different source port does not match.
	if matchesReply(buildIP(6, buildTCP(0x12)), from, 81) {
		t.Error("different source port must not match")
	}
	// A different source IP does not match.
	b := buildIP(6, buildTCP(0x12))
	b[12], b[13], b[14], b[15] = 10, 0, 0, 9
	if matchesReply(b, from, 80) {
		t.Error("different source IP must not match")
	}
	// Non-TCP does not match.
	if matchesReply(buildIP(17, buildTCP(0x12)), from, 80) {
		t.Error("non-TCP must not match")
	}
	// A too-short packet does not match.
	if matchesReply([]byte{0x45, 0, 0, 40}, from, 80) {
		t.Error("short packet must not match")
	}
}

func TestHtons(t *testing.T) {
	if got := htons(80); got != 0x5000 {
		t.Errorf("htons(80)=%#x, want 0x5000", got)
	}
	if got := htons(0x1234); got != 0x3412 {
		t.Errorf("htons(0x1234)=%#x, want 0x3412", got)
	}
}

// buildIPOpt wraps a TCP payload in an IPv4 header with 12 bytes of
// IP options (IHL=8: 20 bytes base + 12 bytes options), so
// ParseTCP's option accounting is exercised.
func buildIPOpt(proto byte, tcp []byte) []byte {
	hdr := make([]byte, 32)
	hdr[0] = 0x48
	binary.BigEndian.PutUint16(hdr[2:4], uint16(32+len(tcp)))
	hdr[8] = 99
	hdr[9] = proto
	copy(hdr[12:16], []byte{10, 0, 0, 1})
	copy(hdr[16:20], []byte{10, 0, 0, 2})
	return append(hdr, tcp...)
}

// TestParseTCP: full field extraction on a datagram with IP options
// and a SYN-ACK — exactly the shape of the reply the handshake mode
// timestamps.
func TestParseTCP(t *testing.T) {
	tcp := make([]byte, 32)
	tcp[0], tcp[1] = 0xC0, 0x00                       // sport 49152
	tcp[2], tcp[3] = 0x00, 0x50                       // dport 80
	binary.BigEndian.PutUint32(tcp[4:8], 0x11223344)  // seq
	binary.BigEndian.PutUint32(tcp[8:12], 0x55667788) // ack
	tcp[12] = 0x80                                    // data offset 8 (12B tcp options)
	tcp[13] = 0x12                                    // SYN|ACK
	b := buildIPOpt(6, tcp)
	b[4], b[5] = 0xAB, 0xCD // IP ID

	p, ok := ParseTCP(b)
	if !ok {
		t.Fatal("ParseTCP: ok=false on valid datagram")
	}
	if p.SrcIP.String() != "10.0.0.1" || p.DstIP.String() != "10.0.0.2" {
		t.Errorf("ips: %s -> %s", p.SrcIP, p.DstIP)
	}
	if p.SrcPort != 49152 || p.DstPort != 80 {
		t.Errorf("ports: %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.Seq != 0x11223344 || p.Ack != 0x55667788 {
		t.Errorf("seq/ack: %x/%x", p.Seq, p.Ack)
	}
	if p.IPOptLen != 12 {
		t.Errorf("ipopt = %d, want 12", p.IPOptLen)
	}
	if p.IPID != 0xABCD || p.TTL != 99 {
		t.Errorf("ipid/ttl = %x/%d", p.IPID, p.TTL)
	}
	if p.DataOff != 32 {
		t.Errorf("data offset = %d, want 32", p.DataOff)
	}
	if !p.IsSynAck() {
		t.Error("flags must classify as SYN-ACK")
	}
	if p.IsRST() {
		t.Error("SYN-ACK must not classify as RST")
	}
}

// TestParseTCPRejects: non-IP, non-TCP and truncated input must
// yield ok=false (the caller treats them as "not a reply").
func TestParseTCPRejects(t *testing.T) {
	if _, ok := ParseTCP([]byte{0x45, 0, 0, 40}); ok {
		t.Error("truncated datagram must not parse")
	}
	if _, ok := ParseTCP(buildIP(17, buildTCP(0x02))); ok {
		t.Error("UDP datagram must not parse")
	}
	ipv6 := append([]byte{0x60, 0, 0, 0}, make([]byte, 40)...)
	if _, ok := ParseTCP(ipv6); ok {
		t.Error("IPv6 datagram must not parse")
	}
}

// TestTapRecvTimeout: with no matching traffic Recv() must return
// ErrTimeout within the requested window (the handshake round uses
// this as its per-poll deadline). Requires CAP_NET_RAW.
func TestTapRecvTimeout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires CAP_NET_RAW (run as root)")
	}
	tap, err := OpenTap(net.ParseIP("127.0.0.1"), 9)
	if err != nil {
		t.Fatalf("OpenTap: %v", err)
	}
	defer tap.Close()
	t0 := time.Now()
	_, _, err = tap.Recv(50 * time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want ErrTimeout", err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Errorf("Recv took %v, want ~50ms", d)
	}
}
