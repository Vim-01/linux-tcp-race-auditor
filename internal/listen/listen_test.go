package listen

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// waitUntil polls cond until it holds or the deadline expires.
func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// eventTuple is one parsed events-log line: kind (A/R), unix ns, port.
type eventTuple struct {
	kind byte
	ns   int64
	port int
}

// eventWriter is a mutex-guarded events log for the tests: it
// records the (kind, unix_ns, port) tuples so the A/R pairing can be
// checked (R follows A for the same port, close in time).
type eventWriter struct {
	mu      sync.Mutex
	evs     []eventTuple
	pending []byte
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	for {
		idx := bytes.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := string(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		var kind byte
		var ns int64
		var port int
		if _, err := fmt.Sscanf(line, "%c %d %d", &kind, &ns, &port); err == nil {
			w.evs = append(w.evs, eventTuple{kind, ns, port})
		}
	}
	return len(p), nil
}

// pairGapUS returns (R_ns - A_ns) in microseconds for the first
// A/R pair sharing a port (0, false if none).
func (w *eventWriter) pairGapUS() (int64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	byPort := map[int]int64{}
	for _, e := range w.evs {
		if e.kind == 'A' {
			if _, ok := byPort[e.port]; !ok {
				byPort[e.port] = e.ns
			}
		} else if e.kind == 'R' {
			if a, ok := byPort[e.port]; ok && e.ns >= a {
				return (e.ns - a) / 1000, true
			}
		}
	}
	return 0, false
}

// TestStartAcceptClose: Start("0") binds an ephemeral port, the
// accept loop takes a dialed connection, and Close releases
// everything (idempotently).
func TestStartAcceptClose(t *testing.T) {
	srv, err := Start("0", 0, nil, nil, Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	port := srv.Addr().(*net.TCPAddr).Port
	if port == 0 {
		t.Fatal("port 0 must resolve to a real ephemeral port")
	}
	conn, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	waitUntil(t, 3*time.Second, "accepted >= 1", func() bool {
		return srv.Counters().Accepted >= 1
	})
	waitUntil(t, 3*time.Second, "held >= 1", func() bool {
		return srv.Counters().Held >= 1
	})
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	waitUntil(t, 3*time.Second, "held drained to 0", func() bool {
		return srv.Counters().Held == 0
	})
}

// TestHoldReleasesOnClientClose: a held connection ends when the
// peer sends FIN (Read -> EOF), which is the same path our RST
// takes on the real target (ECONNRESET). The released counter must
// move.
func TestHoldReleasesOnClientClose(t *testing.T) {
	srv, err := Start("0", 0, nil, nil, Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	conn, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitUntil(t, 3*time.Second, "accepted >= 1", func() bool {
		return srv.Counters().Accepted >= 1
	})
	conn.Close() // FIN -> hold ends
	waitUntil(t, 3*time.Second, "released >= 1", func() bool {
		return srv.Counters().Released >= 1
	})
}

// TestReporterOff: a nil out means no reporter goroutine; the
// server still works.
func TestReporterOff(t *testing.T) {
	srv, err := Start("0", 0, nil, nil, Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// expectResetRead checks that a Read on the client side fails with
// ECONNRESET (the kernel's active RST from an abort-close).
func expectResetRead(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("Read after abort-close: want error, got nil")
	}
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read after abort-close: want ECONNRESET, got %v", err)
	}
}

// TestImmediateReleases: Immediate mode (netpoll accept path)
// abort-closes the child right after accept; the client sees the
// kernel RST, and the events log carries an A/R pair close in time.
func TestImmediateReleases(t *testing.T) {
	ew := &eventWriter{}
	srv, err := Start("0", 0, nil, ew, Options{Immediate: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	conn, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	waitUntil(t, 3*time.Second, "released >= 1 (abort-close)", func() bool {
		return srv.Counters().Released >= 1
	})
	if g, ok := ew.pairGapUS(); !ok || g < 0 || g > 2000 {
		t.Fatalf("A/R pair gap = %dus (ok=%v), want 0..2000us", g, ok)
	}
	expectResetRead(t, conn)
}

// TestBusyPollAccept: BusyPoll mode (accept4 spin, hold path via
// rawConn) accepts, holds, and releases on FIN like the netpoll
// path.
func TestBusyPollAccept(t *testing.T) {
	srv, err := Start("0", 0, nil, nil, Options{BusyPoll: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	conn, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitUntil(t, 3*time.Second, "accepted >= 1", func() bool {
		return srv.Counters().Accepted >= 1
	})
	waitUntil(t, 3*time.Second, "held >= 1", func() bool {
		return srv.Counters().Held >= 1
	})
	conn.Close() // FIN -> hold ends (rawConn Read -> EOF)
	waitUntil(t, 3*time.Second, "released >= 1", func() bool {
		return srv.Counters().Released >= 1
	})
}

// dialRST dials and closes the client with SO_LINGER{1,0}: the
// kernel aborts with an RST (tcp_reset -> tcp_done); in 6.1.189 the
// unaccepted child is NOT freed by that path — it stays in the
// accept queue in TCP_CLOSE (freed only at listener close), exactly
// like fire #16b.
func dialRST(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("Dial: unexpected conn type %T", conn)
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := rc.Control(func(fd uintptr) {
		linger := unix.Linger{Onoff: 1, Linger: 0}
		unix.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, &linger)
	}); err != nil {
		t.Fatalf("SetsockoptLinger: %v", err)
	}
	conn.Close()
}

// TestNoAccept: NoAccept mode runs no accept loop — completed
// children sit in the accept queue (Accepted stays 0). A client RST
// does NOT free the unaccepted child in 6.1.189 (it stays in the
// queue in TCP_CLOSE, freed only at listener close); Close()
// therefore drains ALL queued children, RST'd ones included.
func TestNoAccept(t *testing.T) {
	srv, err := Start("0", 8, nil, nil, Options{NoAccept: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	hold := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp4", srv.Addr().String())
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		hold = append(hold, conn)
	}
	dialRST(t, srv.Addr().String()) // kernel-frees its child in the queue
	time.Sleep(200 * time.Millisecond)
	if c := srv.Counters(); c.Accepted != 0 || c.Held != 0 {
		t.Fatalf("NoAccept: want accepted=0 held=0 (no accept loop), got %d/%d",
			c.Accepted, c.Held)
	}
	for _, conn := range hold {
		conn.Close() // FIN: the children stay in the queue (CLOSE-WAIT)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// 4, not 3: the RST'd child is NOT freed by tcp_reset in 6.1.189
	// while unaccepted (tcp_done -> sk_state_change is a no-op with
	// sk_socket == NULL; no SOCK_DEAD), so it lingers in the accept
	// queue in TCP_CLOSE and the shutdown drain picks it up too
	// (source-pinned + verified on the VM: ss shows it only after
	// the listener close, via inet_csk_listen_stop).
	if got := srv.Counters().Accepted; got != 4 {
		t.Fatalf("shutdown drain: want accepted=4 (3 FIN'd + 1 RST'd CLOSE-lingering children), got %d", got)
	}
}

// TestBusyPollImmediate: the Option B lab configuration — busy-poll
// accept + inline abort-close. The events log must carry an A/R pair
// (R-A ~ µs..ms) and the client must see the kernel RST.
func TestBusyPollImmediate(t *testing.T) {
	ew := &eventWriter{}
	srv, err := Start("0", 0, nil, ew, Options{BusyPoll: true, Immediate: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	conn, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	waitUntil(t, 3*time.Second, "released >= 1 (inline abort-close)", func() bool {
		return srv.Counters().Released >= 1
	})
	g, ok := ew.pairGapUS()
	if !ok || g < 0 || g > 2000 {
		t.Fatalf("A/R pair gap = %dus (ok=%v), want 0..2000us", g, ok)
	}
	expectResetRead(t, conn)
}
