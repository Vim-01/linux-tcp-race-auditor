package packet

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex vector %q: %v", s, err)
	}
	return b
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fold16 sums 16-bit words with end-around carry; a correct
// checksum makes the sum over the covered region fold to 0xFFFF.
func fold16(b []byte) uint32 {
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
	return sum
}

// TestGoldenA: IHL=7 (4x NOP options), plain TCP SYN, no TCP
// options. Vector computed independently (python, RFC 1071).
func TestGoldenA(t *testing.T) {
	seg := Seg{
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   1000,
		DstPort:   80,
		IPID:      0x1234,
		TTL:       64,
		IPFlags:   0x4000,
		TCPFlags:  FlagSYN,
		Seq:       0xCAFEB00D,
		Window:    65535,
		IPOptions: []byte{1, 1, 1, 1},
	}
	got, err := seg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := hexDecode(t, "4600002c12344000400611940a0000010a0000020101010103e80050cafeb00d000000005002ffff1c9c0000")
	if !equal(got, want) {
		t.Fatalf("golden A mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestGoldenB: 12-byte timestamp(T)/TSANDADDR IP option +
// MSS/SACK/WS TCP options, SYN+ACK flags. Vector computed
// independently (python, RFC 1071).
func TestGoldenB(t *testing.T) {
	seg := Seg{
		SrcIP:    net.ParseIP("10.0.0.9"),
		DstIP:    net.ParseIP("10.0.0.10"),
		SrcPort:  5555,
		DstPort:  443,
		IPID:     0xABCD,
		TOS:      0x08,
		TTL:      128,
		TCPFlags: FlagSYN | FlagACK,
		Seq:      7,
		Window:   64240,
		IPOptions: []byte{
			0x44, 0x0C, 0x05, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		TCPOptions: []byte{
			2, 4, 5, 0xB4, 4, 2, 3, 3, 7, 1, 1, 0x01,
		},
	}
	got, err := seg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := hexDecode(t, "48080040abcd000080062ec30a0000090a00000a440c0501000000000000000015b301bb00000007000000008012faf0428f0000020405b40402030307010101")
	if !equal(got, want) {
		t.Fatalf("golden B mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestChecksumProperty: the RFC 1071 invariant. The IP checksum
// region (header+options) must fold to 0xFFFF, and so must
// pseudo-header + TCP segment.
func TestChecksumProperty(t *testing.T) {
	seg := Seg{
		SrcIP:     net.ParseIP("1.2.3.4"),
		DstIP:     net.ParseIP("5.6.7.8"),
		SrcPort:   1234,
		DstPort:   9999,
		TTL:       100,
		TCPFlags:  FlagSYN,
		Seq:       0xDEADBEEF,
		Window:    1024,
		IPOptions: []byte{0x07, 0x04, 0x00, 0x00},
	}
	pkt, err := seg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ihl := int(pkt[0]&0x0F) * 4
	if got := fold16(pkt[:ihl]); got != 0xFFFF {
		t.Errorf("ip checksum property violated: fold=%04x", got)
	}
	pseudo := make([]byte, 0, 12+len(pkt)-ihl)
	pseudo = append(pseudo, seg.SrcIP.To4()...)
	pseudo = append(pseudo, seg.DstIP.To4()...)
	pseudo = append(pseudo, 0x00, 0x06)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(pkt)-ihl))
	pseudo = append(pseudo, l[:]...)
	if got := fold16(append(pseudo, pkt[ihl:]...)); got != 0xFFFF {
		t.Errorf("tcp checksum property violated: fold=%04x", got)
	}
}

// TestIPOptionsPresets: all presets are 4-aligned and within the
// IHL limit (20+40 bytes max header).
func TestIPOptionsPresets(t *testing.T) {
	for _, p := range []string{PresetNOP, PresetTS, PresetRR, PresetSSRR} {
		opt, err := BuildIPOptions(p, net.ParseIP("10.0.0.1"))
		if err != nil {
			t.Fatalf("preset %s: %v", p, err)
		}
		if len(opt)%4 != 0 {
			t.Errorf("preset %s: len %d not a multiple of 4", p, len(opt))
		}
		if len(opt) > 40 {
			t.Errorf("preset %s: too long (%d)", p, len(opt))
		}
	}
}

// L2: BuildIPOptions is case-insensitive, so a capitalized preset
// from TOML or the CLI resolves to the same option bytes.
func TestBuildIPOptionsCaseInsensitive(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	lower, err := BuildIPOptions("ssrr", src)
	if err != nil {
		t.Fatalf("ssrr: %v", err)
	}
	upper, err := BuildIPOptions("SSRR", src)
	if err != nil {
		t.Fatalf("SSRR: %v", err)
	}
	if !equal(lower, upper) {
		t.Errorf("SSRR != ssrr: %x vs %x", upper, lower)
	}
	// An unknown preset (any casing) still errors.
	if _, err := BuildIPOptions("Bogus", src); err == nil {
		t.Error("unknown preset should error")
	}
}

// TestParseIPOptionsHex covers separator handling and errors.
func TestParseIPOptionsHex(t *testing.T) {
	want := []byte{0x2C, 0x0C, 0, 0, 0, 0, 0, 0x0A, 0, 0, 0x01}
	for _, s := range []string{
		"2c0c00000000000a000001",
		"2c:0c:00:00:00:00:00:0a:00:00:01",
		"2c 0c 00 00 00 00 00 0a 00 00 01",
	} {
		got, err := ParseIPOptionsHex(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if !equal(got, want) {
			t.Errorf("%q -> %x (want %x)", s, got, want)
		}
	}
	if _, err := ParseIPOptionsHex("zz"); err == nil {
		t.Error("expected error for bad hex")
	}
}

// TestRetransmitIdentity: the engine relies on the retransmit being
// byte-identical to the first SYN; building twice must yield
// identical bytes.
func TestRetransmitIdentity(t *testing.T) {
	seg := Seg{
		SrcIP:     net.ParseIP("0.0.0.0"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   10000,
		DstPort:   80,
		IPID:      5,
		TTL:       64,
		TCPFlags:  FlagSYN,
		Seq:       42,
		Window:    65535,
		IPOptions: []byte{0x2C, 0x0C, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	a, err := seg.Build()
	if err != nil {
		t.Fatal(err)
	}
	b, err := seg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !equal(a, b) {
		t.Error("identical Seg must build identical bytes")
	}
}

// TestAckRstBuildChecksums: the handshake mode's completing ACK and
// closing RST carry no IP options and no TCP options; the built
// datagrams must be exactly 40 bytes with both checksum regions
// folding to 0xFFFF.
func TestAckRstBuildChecksums(t *testing.T) {
	for _, fl := range []byte{FlagACK, FlagRST} {
		seg := Seg{
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("10.0.0.2"),
			SrcPort:  40000,
			DstPort:  9000,
			TTL:      64,
			TCPFlags: fl,
			Seq:      0x01020304,
			Ack:      0x99887767,
			Window:   65535,
		}
		pkt, err := seg.Build()
		if err != nil {
			t.Fatalf("build flags=%#x: %v", fl, err)
		}
		if len(pkt) != 40 {
			t.Errorf("flags=%#x: len = %d, want 40 (bare TCP)", fl, len(pkt))
		}
		if got := fold16(pkt[:20]); got != 0xFFFF {
			t.Errorf("flags=%#x: ip checksum property violated: fold=%04x", fl, got)
		}
		pseudo := make([]byte, 0, 12+len(pkt)-20)
		pseudo = append(pseudo, pkt[12:16]...)
		pseudo = append(pseudo, pkt[16:20]...)
		pseudo = append(pseudo, 0x00, 0x06)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(pkt)-20))
		pseudo = append(pseudo, l[:]...)
		if got := fold16(append(pseudo, pkt[20:]...)); got != 0xFFFF {
			t.Errorf("flags=%#x: tcp checksum property violated: fold=%04x", fl, got)
		}
	}
}

// TestRechecksumAfterPatch: build with placeholder ID/port/seq,
// patch the mutable fields in place, then Rechecksum. Both the IP
// region and pseudo+TCP region must fold to 0xFFFF. Without the
// Rechecksum call the IP ID and seq changes invalidate the sums.
func TestRechecksumAfterPatch(t *testing.T) {
	seg := Seg{
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   10000,
		DstPort:   80,
		TTL:       64,
		TCPFlags:  FlagSYN,
		Window:    65535,
		IPOptions: []byte{0x44, 0x0C, 0x05, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	pkt, err := seg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ihl := int(pkt[0]&0x0F) * 4
	// patch-style in-place mutation of IP ID and TCP seq
	binary.BigEndian.PutUint16(pkt[4:6], 0xBEEF)
	binary.BigEndian.PutUint32(pkt[ihl+4:ihl+8], 0x01020304)
	Rechecksum(pkt)
	if got := fold16(pkt[:ihl]); got != 0xFFFF {
		t.Errorf("ip checksum property violated after rechecksum: fold=%04x", got)
	}
	pseudo := make([]byte, 0, 12+(len(pkt)-ihl))
	pseudo = append(pseudo, pkt[12:16]...)
	pseudo = append(pseudo, pkt[16:20]...)
	pseudo = append(pseudo, 0x00, 0x06)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(pkt)-ihl))
	pseudo = append(pseudo, l[:]...)
	if got := fold16(append(pseudo, pkt[ihl:]...)); got != 0xFFFF {
		t.Errorf("tcp checksum property violated after rechecksum: fold=%04x", got)
	}
}

// TestValidate catches structurally bad segments.
func TestValidate(t *testing.T) {
	base := Seg{
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		DstPort:   80,
		TTL:       64,
		TCPFlags:  FlagSYN,
		IPOptions: []byte{1, 1, 1, 1},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("good seg rejected: %v", err)
	}
	bad := base
	bad.IPOptions = []byte{1, 1, 1} // not a multiple of 4
	if err := bad.Validate(); err == nil {
		t.Error("expected error for 3-byte options")
	}
	long := make([]byte, 44)
	bad.IPOptions = long
	if err := bad.Validate(); err == nil {
		t.Error("expected error for 44-byte options")
	}
	bad = base
	bad.DstPort = 0
	if err := bad.Validate(); err == nil {
		t.Error("expected error for zero dst port")
	}
	bad = base
	bad.TCPOptions = []byte{2, 4, 5, 0xB4, 4, 2} // not a multiple of 4
	if err := bad.Validate(); err == nil {
		t.Error("expected error for misaligned tcp options")
	}
}
