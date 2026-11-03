// Package listen provides the lab-side TCP endpoint for the
// handshake mode: a plain listener that ACCEPTS connections (and
// optionally abort-closes them immediately) instead of answering
// them.
//
// Why: the fire #1 lab listener (busybox nc in a loop) exited after
// one connection, so the kernel's child socket (created when our
// completing ACK completes the handshake) was accepted and closed
// by the APPLICATION at an uncontrolled moment. The listener here
// controls exactly WHEN the child is closed:
//
//   - hold mode (default): accept and hold until the kernel ends the
//     connection (our RST); Close() — and thus kfree(inet_opt) in
//     inet_sock_destruct — happens on the kernel-side reset path.
//
//   - immediate mode (Option B, fire #10+): on accept, set
//     SO_LINGER{1,0} and close the child right away. The kernel
//     aborts the connection with an active RST and tears the child
//     down in the close path itself (__tcp_close -> tcp_disconnect ->
//     sk_common_release -> __sk_free -> inet_sock_destruct ->
//     kfree(inet_opt)), a few microseconds after accept — long before
//     the in-flight retransmitted SYN hits the (already swapped-in)
//     child and dereferences the dangling inet_opt pointer (KASAN
//     UAF hit).
//
// busy-poll mode replaces the netpoll-based Accept() with a raw
// accept4() spin loop (LockOSThread, optional CPU pin) so the accept
// happens without a netpoll wake-up round trip (tens of µs).
package listen

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Options tune the listener behaviour (lab calibration knobs).
type Options struct {
	// Immediate abort-closes each accepted child with
	// SO_LINGER{1,0}: the kernel sends an active RST and frees the
	// child (kfree(inet_opt) in inet_sock_destruct) a few µs after
	// accept (Option B).
	Immediate bool
	// BusyPoll spins accept4() in a locked OS thread instead of using
	// netpoll (removes the netpoll wake-up latency from the accept
	// path, which matters for the µs-scale kfree-vs-deref race).
	BusyPoll bool
	// PinCPU pins the busy-poll accept thread to this vCPU (-1 =
	// unpinned; only meaningful with BusyPoll).
	PinCPU int
	// NoAccept runs NO accept loop: completed children stay in the
	// accept queue (cap = listen(2) backlog). In 6.1.189 a client RST
	// does NOT free the unaccepted child (tcp_done: sk_socket is
	// still NULL, no SOCK_DEAD) — it lingers in TCP_CLOSE in the
	// queue and is freed only when Close() drains it (accept4 ->
	// close) or by inet_csk_listen_stop. Fire #16b: structural
	// negative — no fast kfree(inet_opt) inside the reader window.
	NoAccept bool
}

// Server is a hold-and-count TCP listener.
type Server struct {
	ln     *net.TCPListener
	out    io.Writer
	events io.Writer // optional per-event timestamp log (lab calibration)
	opts   Options

	rawFD int // listener fd (busy-poll: accept4; no-accept: shutdown drain)

	done     chan struct{}
	closeMu  sync.Mutex
	closed   bool
	closeErr error

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	accepts  atomic.Uint64
	released atomic.Uint64
}

// Counters is a point-in-time view of the listener activity.
type Counters struct {
	Accepted uint64 // connections taken from the backlog
	Held     uint64 // currently held (accepted, not yet released)
	Released uint64 // connections whose hold ended (abort-close/RST/EOF/close)
}

// Start binds a TCP listener on addr ("PORT" or "IP:PORT"; "0" for
// an ephemeral port) with the given backlog (<=0 means 4096), and
// starts the accept/hold loops. If out is non-nil a reporter line
// is written there every 5 seconds. If events is non-nil, one line
// per accepted/reset connection is written there (see logEvent) for
// lab timing calibration (correlate with the attack pcap).
func Start(addr string, backlog int, out io.Writer, events io.Writer, opts Options) (*Server, error) {
	if backlog <= 0 {
		backlog = 4096
	}
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	// Build the listener with raw syscalls so we control the
	// listen(2) backlog ourselves. Go's net.Listen hardcodes
	// listenerBacklog() (= somaxconn, 4096 on modern kernels), and
	// there is no working setsockopt override: SO_BACKLOG is not a
	// real Linux socket option, and inet_listen() unconditionally
	// writes sk_max_ack_backlog = listen()'s backlog argument. The
	// accept-queue cap therefore comes ONLY from listen(fd, backlog)
	// — required for fire #16 (accept-queue OVERFLOW fast-kfree
	// channel: small backlog + slow netpoll acceptor).
	host, portStr, perr := net.SplitHostPort(addr)
	if perr != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, perr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		return nil, fmt.Errorf("listen %s: bad port %q: %w", addr, portStr, perr)
	}
	var ip [4]byte // zero = 0.0.0.0 (wildcard)
	if host != "" && host != "0.0.0.0" {
		ip4 := net.ParseIP(host).To4()
		if ip4 == nil {
			return nil, fmt.Errorf("listen %s: bad ip %q", addr, host)
		}
		ip = [4]byte(ip4)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("listen %s: socket: %w", addr, err)
	}
	if serr := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen %s: setsockopt: %w", addr, serr)
	}
	if berr := unix.Bind(fd, &unix.SockaddrInet4{Addr: ip, Port: port}); berr != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen %s: bind: %w", addr, berr)
	}
	if lerr := unix.Listen(fd, backlog); lerr != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen %s: listen backlog=%d: %w", addr, backlog, lerr)
	}
	// Wrap the listening fd into a *net.TCPListener. FileListener
	// dup()s the fd internally, so we release our copy right away.
	f := os.NewFile(uintptr(fd), "tcp-listener")
	lnI, werr := net.FileListener(f)
	f.Close()
	if werr != nil {
		return nil, fmt.Errorf("listen %s: wrap: %w", addr, werr)
	}
	ln := lnI.(*net.TCPListener)
	s := &Server{
		ln:     ln,
		out:    out,
		events: events,
		opts:   opts,
		done:   make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
	rc, rerr := s.ln.SyscallConn()
	if rerr != nil {
		ln.Close()
		return nil, fmt.Errorf("listener fd: %w", rerr)
	}
	if cerr := rc.Control(func(fd uintptr) {
		s.rawFD = int(fd)
	}); cerr != nil {
		ln.Close()
		return nil, fmt.Errorf("listener fd: %w", cerr)
	}
	if opts.NoAccept {
		// No accept loop at all: children accumulate in the accept
		// queue (cap = the listen(2) backlog); a client RST leaves
		// them in the queue in TCP_CLOSE (6.1.189: not freed while
		// unaccepted). The queue is drained best-effort in Close().
	} else if opts.BusyPoll {
		go s.busyAcceptLoop()
	} else {
		go s.acceptLoop()
	}
	if out != nil {
		go s.reporter()
	}
	return s, nil
}

// Addr returns the bound local address (resolves port 0).
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// remotePort returns the peer's TCP port (-1 if not a TCP address).
func remotePort(c net.Conn) int {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.Port
	}
	if rc, ok := c.(*rawConn); ok {
		return rc.port
	}
	return -1
}

// remotePortSA returns the peer's TCP port from an accept4 sockaddr.
func remotePortSA(sa unix.Sockaddr) int {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return a.Port
	case *unix.SockaddrInet6:
		return a.Port
	}
	return -1
}

// logEvent appends one calibration line per connection event:
//
//	A <unix_ns> <remote_port>   accept loop took the child from the backlog
//	R <unix_ns> <remote_port>   right before Close() (Option B: inline,
//	                             a few µs after A; kfree(inet_opt) follows
//	                             in ~5 µs per the uaf_f1 kprobe)
//
// R is logged immediately before Close() (the kfree trigger), so it
// approximates the kfree wall-clock time. The lines are correlated
// with the attack pcap by remote_port (== the round's source port).
// Writing is best-effort and non-fatal.
func (s *Server) logEvent(kind byte, c net.Conn) {
	s.logEventNS(kind, time.Now().UnixNano(), remotePort(c))
}

// logEventNS is the raw variant of logEvent (ns + port precomputed,
// for the busy-poll path where the conn is not wrapped yet).
func (s *Server) logEventNS(kind byte, ns int64, port int) {
	if s.events == nil {
		return
	}
	fmt.Fprintf(s.events, "%c %d %d\n", kind, ns, port)
}

// Counters returns the activity counters.
func (s *Server) Counters() Counters {
	return Counters{
		Accepted: s.accepts.Load(),
		Held:     held(s),
		Released: s.released.Load(),
	}
}

// isClosed reports whether Close() has started.
func (s *Server) isClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// Close stops the listener and releases all held connections. It is
// idempotent: the listener fd is closed exactly once, later calls
// return nil (or the original close error).
func (s *Server) Close() error {
	s.closeMu.Lock()
	if !s.closed {
		s.closed = true
		close(s.done)
		if s.opts.NoAccept {
			s.drainQueue()
		}
		s.closeErr = s.ln.Close()
	}
	err := s.closeErr
	s.closeMu.Unlock()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()
	return err
}

// drainQueue best-effort empties the accept queue on shutdown
// (NoAccept mode): the kernel RSTs unaccepted children when the
// listener closes anyway (inet_csk_listen_stop frees the remaining
// queued children), but taking them out first gives a final counter
// of how many connections completed while unaccepted.
func (s *Server) drainQueue() {
	fd := s.rawFD
	if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl|unix.O_NONBLOCK)
	}
	for {
		cfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			return
		}
		unix.Close(cfd)
		s.accepts.Add(1)
	}
}

// abortClose sets SO_LINGER{1,0} on the connection and closes it:
// the kernel aborts the TCP connection with an active RST and tears
// the child down in the close path itself (kfree(inet_opt) in
// inet_sock_destruct, a few µs later) instead of the graceful
// FIN/ACK exchange.
func abortClose(c net.Conn) error {
	var lerr error
	if tc, ok := c.(*net.TCPConn); ok {
		if rc, rerr := tc.SyscallConn(); rerr == nil {
			if cerr := rc.Control(func(fd uintptr) {
				linger := unix.Linger{Onoff: 1, Linger: 0}
				lerr = unix.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, &linger)
			}); cerr != nil {
				return cerr
			}
		}
	}
	if cerr := c.Close(); cerr != nil {
		return cerr
	}
	return lerr
}

// acceptLoop takes connections forever, holding each one in its own
// goroutine (holds are short: our RST resets the kernel child and
// the hold ends immediately). In Immediate mode the child is
// abort-closed right after accept (Option B).
func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			s.closeMu.Lock()
			wasClosed := s.closed
			s.closeMu.Unlock()
			if wasClosed {
				return
			}
			// Transient: retry (ln.Close unblocks this Accept).
			select {
			case <-s.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		s.accepts.Add(1)
		s.logEvent('A', c) // calibration: child taken from the accept queue
		if s.opts.Immediate {
			abortClose(c)      // best-effort; the close below is what matters
			s.logEvent('R', c) // calibration: right before/after Close() -> kfree
			s.released.Add(1)
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.hold(c)
	}
}

// busyAcceptLoop spins accept4() on the raw listener fd
// (non-blocking) in a locked OS thread, optionally pinned to a
// single vCPU. In Immediate mode the child is abort-closed inline;
// otherwise it is wrapped in a rawConn and held like in the netpoll
// accept loop.
func (s *Server) busyAcceptLoop() {
	runtime.LockOSThread()
	if s.opts.PinCPU >= 0 {
		cs := &unix.CPUSet{}
		cs[s.opts.PinCPU/64] |= 1 << (uint(s.opts.PinCPU % 64))
		if err := unix.SchedSetaffinity(0, cs); err != nil {
			if s.out != nil {
				fmt.Fprintf(s.out, "[listener] sched_setaffinity cpu=%d: %v (continuing unpinned)\n",
					s.opts.PinCPU, err)
			}
		}
	}
	fd := s.rawFD
	if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl|unix.O_NONBLOCK)
	}
	for {
		cfd, sa, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err != nil {
			switch err {
			case unix.EAGAIN: // == EWOULDBLOCK on Linux
				if s.isClosed() {
					return
				}
				runtime.Gosched()
				continue
			case unix.EINTR:
				continue
			}
			if s.isClosed() {
				return
			}
			select {
			case <-s.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		s.accepts.Add(1)
		if s.opts.Immediate {
			// Option B: abort-close inline, no goroutine. The kernel
			// sends an active RST and kfree(inet_opt) follows a few
			// µs after Close (verified with the uaf_f1 kprobe).
			linger := unix.Linger{Onoff: 1, Linger: 0}
			unix.SetsockoptLinger(cfd, unix.SOL_SOCKET, unix.SO_LINGER, &linger)
			port := remotePortSA(sa)
			s.logEventNS('A', time.Now().UnixNano(), port)
			s.logEventNS('R', time.Now().UnixNano(), port)
			unix.Close(cfd)
			s.released.Add(1)
			continue
		}
		c := newRawConn(cfd, sa)
		s.logEvent('A', c)
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.hold(c)
	}
}

// held returns the number of connections currently in a hold.
func held(s *Server) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.conns))
}

// hold reads the connection until the kernel ends it: n==0 (FIN) or
// an error (ECONNRESET from our RST, or Close()). Data is expected
// to be absent; anything received is simply drained.
func (s *Server) hold(c net.Conn) {
	defer func() {
		s.logEvent('R', c) // calibration: right before Close() -> kfree
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		s.released.Add(1)
	}()
	buf := make([]byte, 256)
	for {
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(buf)
		if err == nil {
			continue // drain received data, keep holding
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			select {
			case <-s.done:
				return
			default:
				// BusyPoll: the fd is non-blocking and Read returns
				// EAGAIN-mapped timeouts in ~µs; sleep so the poll
				// cadence is ~200 µs instead of a hot spin.
				if s.opts.BusyPoll {
					time.Sleep(200 * time.Microsecond)
				}
				continue
			}
		}
		return // EOF / ECONNRESET / closed: the kernel freed the child
	}
}

// rawConn is a minimal net.Conn over an fd accepted by accept4(2)
// (no dup, unlike net.FileConn). The fd stays non-blocking; EAGAIN
// on Read is reported as a net timeout when a read deadline is set,
// so hold() can poll at its 200 µs cadence. The local/remote
// addresses are the accept4 sockaddrs, exposed as net.Addr through
// rawAddr (x/sys sockaddrs do not implement net.Addr themselves).
type rawConn struct {
	fd     int
	local  unix.Sockaddr // Getsockname (nil if unavailable)
	remote unix.Sockaddr // from accept4
	port   int           // remote TCP port, cached for the events log

	closeMu sync.Mutex
	closed  bool
	readDL  int64 // unix nanoseconds; 0 = no deadline
}

func newRawConn(fd int, sa unix.Sockaddr) *rawConn {
	rc := &rawConn{fd: fd, remote: sa, port: remotePortSA(sa)}
	if la, err := unix.Getsockname(fd); err == nil {
		rc.local = la
	}
	return rc
}

// rawAddr wraps a unix.Sockaddr into a net.Addr.
type rawAddr struct{ sa unix.Sockaddr }

func (a rawAddr) Network() string {
	switch a.sa.(type) {
	case *unix.SockaddrInet4:
		return "ip4"
	case *unix.SockaddrInet6:
		return "ip6"
	}
	return "ip"
}

func (a rawAddr) String() string {
	switch v := a.sa.(type) {
	case *unix.SockaddrInet4:
		return net.IPv4(v.Addr[0], v.Addr[1], v.Addr[2], v.Addr[3]).String() + ":" + strconv.Itoa(v.Port)
	case *unix.SockaddrInet6:
		return "[" + net.IP(v.Addr[:]).String() + "]:" + strconv.Itoa(v.Port)
	}
	return "unknown"
}

// rawTimeoutError is the EAGAIN-mapped net timeout.
type rawTimeoutError struct{}

func (rawTimeoutError) Error() string   { return "listener: no data yet (non-blocking EAGAIN)" }
func (rawTimeoutError) Timeout() bool   { return true }
func (rawTimeoutError) Temporary() bool { return true }

func (rc *rawConn) Read(b []byte) (int, error) {
	rc.closeMu.Lock()
	closed := rc.closed
	dl := rc.readDL
	rc.closeMu.Unlock()
	if closed {
		return 0, syscall.EINVAL
	}
	if dl != 0 && time.Now().UnixNano() >= dl {
		return 0, rawTimeoutError{}
	}
	n, err := unix.Read(rc.fd, b)
	if n == 0 && err == nil {
		return 0, io.EOF // peer closed (FIN): the kernel's read() returned 0
	}
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
		if dl != 0 {
			return n, rawTimeoutError{}
		}
		return n, err
	}
	return n, err
}

func (rc *rawConn) Write(b []byte) (int, error) {
	rc.closeMu.Lock()
	closed := rc.closed
	rc.closeMu.Unlock()
	if closed {
		return 0, syscall.EINVAL
	}
	return unix.Write(rc.fd, b)
}

func (rc *rawConn) Close() error {
	rc.closeMu.Lock()
	defer rc.closeMu.Unlock()
	if rc.closed {
		return nil
	}
	rc.closed = true
	return unix.Close(rc.fd)
}

func (rc *rawConn) LocalAddr() net.Addr {
	if rc.local == nil {
		return rawAddr{}
	}
	return rawAddr{rc.local}
}
func (rc *rawConn) RemoteAddr() net.Addr { return rawAddr{rc.remote} }

func (rc *rawConn) SetDeadline(_ time.Time) error { return nil }

func (rc *rawConn) SetReadDeadline(t time.Time) error {
	rc.closeMu.Lock()
	defer rc.closeMu.Unlock()
	rc.readDL = t.UnixNano()
	return nil
}

func (rc *rawConn) SetWriteDeadline(_ time.Time) error { return nil }

// reporter writes a status line to out every 5 seconds.
func (s *Server) reporter() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		c := s.Counters()
		fmt.Fprintf(s.out, "listener %s: accepted=%d held=%d released=%d\n",
			s.Addr(), c.Accepted, c.Held, c.Released)
	}
}
