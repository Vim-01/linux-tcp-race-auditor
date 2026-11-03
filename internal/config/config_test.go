package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config must be valid: %v", err)
	}
}

// M4: the default race delay must sit inside the reference PoC's
// 100-200 us dither window (30 us sat below it and never won).
func TestDefaultDeltaUs(t *testing.T) {
	if got := Default().Timing.DeltaUs; got != 150 {
		t.Errorf("default DeltaUs = %d, want 150", got)
	}
}

// L2: preset names are case-insensitive (TOML/CLI may capitalize).
func TestPresetCaseInsensitive(t *testing.T) {
	for _, p := range []string{"TS", "Ts", "NOp", "SSRR", "Custom"} {
		c := Default()
		c.Payload.OptionsPreset = p
		if p == "Custom" {
			c.Payload.CustomHex = "01 01 01 01"
		}
		if err := c.Validate(); err != nil {
			t.Errorf("preset %q should be valid: %v", p, err)
		}
	}
}

func TestValidateRanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"bad mode", func(c *Config) { c.Target.Mode = Mode("bogus") }},
		{"port zero", func(c *Config) { c.Target.Port = 0 }},
		{"port big", func(c *Config) { c.Target.Port = 70000 }},
		{"bad preset", func(c *Config) { c.Payload.OptionsPreset = "bogus" }},
		{"custom without hex", func(c *Config) { c.Payload.OptionsPreset = "custom" }},
		// L3: custom hex bounds (must be a multiple of 4 bytes, <= 40).
		{"custom hex odd digits", func(c *Config) { c.Payload.OptionsPreset = "custom"; c.Payload.CustomHex = "01023" }},
		{"custom hex not multiple of 4", func(c *Config) { c.Payload.OptionsPreset = "custom"; c.Payload.CustomHex = "01 01 01" }},
		{"custom hex over 40 bytes", func(c *Config) { c.Payload.OptionsPreset = "custom"; c.Payload.CustomHex = strings.Repeat("01", 44) }},
		{"ttl zero", func(c *Config) { c.Payload.TTL = 0 }},
		{"ttl big", func(c *Config) { c.Payload.TTL = 256 }},
		{"window big", func(c *Config) { c.Payload.Window = 70000 }},
		{"delta zero", func(c *Config) { c.Timing.DeltaUs = 0 }},
		{"flows zero", func(c *Config) { c.Timing.Flows = 0 }},
		{"flows big", func(c *Config) { c.Timing.Flows = 5000 }},
		{"duration zero", func(c *Config) { c.Timing.DurationSec = 0 }},
		{"bad lang", func(c *Config) { c.General.Lang = "de" }},
	}
	for _, tc := range cases {
		c := Default()
		tc.mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestCustomWithHexValid(t *testing.T) {
	c := Default()
	c.Payload.OptionsPreset = "custom"
	c.Payload.CustomHex = "01 01 01 01"
	if err := c.Validate(); err != nil {
		t.Fatalf("custom with hex must be valid: %v", err)
	}
}

// L3 boundary: exactly 40 option bytes (the IHL limit) is valid.
func TestCustomHexAt40ByteLimit(t *testing.T) {
	c := Default()
	c.Payload.OptionsPreset = "custom"
	c.Payload.CustomHex = strings.Repeat("01", 40)
	if err := c.Validate(); err != nil {
		t.Fatalf("40 option bytes must be valid: %v", err)
	}
}

func TestLoadAndSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attack.toml")
	c := Default()
	c.Target.IP = "192.168.7.7"
	c.Timing.Flows = 7
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Target.IP != "192.168.7.7" || got.Timing.Flows != 7 {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissingFileIsDefault(t *testing.T) {
	c, err := Load("/nonexistent/attack.toml")
	if err != nil {
		t.Fatalf("missing file should give defaults: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	// empty path == defaults (Config is no longer comparable:
	// Handshake.DeltaSweepUs is a slice)
	c2, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c2, Default()) {
		t.Errorf("empty path must equal Default(): %+v", c2)
	}
}

func TestLoadBadTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("target = { ip: "), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected parse error for broken TOML")
	}
}

// TestHandshakeValidate: the [handshake] section must be valid by
// default and reject the degenerate configurations that would
// silently break the race (same CPU for both threads, out-of-range
// timings, out-of-range sweep values).
func TestHandshakeValidate(t *testing.T) {
	c := Default()
	c.Target.Mode = ModeHandshake
	if err := c.Validate(); err != nil {
		t.Fatalf("default handshake config must be valid: %v", err)
	}
	// All three send CPUs pinned and distinct, sweep populated: valid.
	c.Handshake.CPURtx, c.Handshake.CPUAck, c.Handshake.CPURst = 1, 2, 3
	c.Handshake.DeltaSweepUs = []int{0, 2, 4}
	if err := c.Validate(); err != nil {
		t.Fatalf("pinned handshake config must be valid: %v", err)
	}
	// negative rst_gap_us is valid (RST lands before the retransmit;
	// the calibrated hit window is around the retransmit, both signs).
	c.Handshake.RstGapUs = -80
	if err := c.Validate(); err != nil {
		t.Fatalf("negative rst_gap_us must be valid: %v", err)
	}
	// gap_sweep_us: like rst_gap_us, negative values are legal (the
	// sweep must be able to cover the window on both sides of the
	// retransmit), and the default (empty) config stays valid.
	c.Handshake.GapSweepUs = []int{-15, 0, 15}
	if err := c.Validate(); err != nil {
		t.Fatalf("gap_sweep_us with negatives must be valid: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(*Config)
	}{
		{"cpus equal", func(c *Config) { c.Handshake.CPURtx, c.Handshake.CPUAck = 3, 3 }},
		{"cpu_rst equals rtx", func(c *Config) { c.Handshake.CPURtx, c.Handshake.CPURst = 1, 1 }},
		{"cpu_rst equals ack", func(c *Config) { c.Handshake.CPUAck, c.Handshake.CPURst = 2, 2 }},
		{"cpu_rtx negative", func(c *Config) { c.Handshake.CPURtx = -1 }},
		{"cpu_ack negative", func(c *Config) { c.Handshake.CPUAck = -1 }},
		{"cpu_rst negative", func(c *Config) { c.Handshake.CPURst = -1 }},
		{"delta_ack negative", func(c *Config) { c.Handshake.DeltaAckUs = -1 }},
		{"delta_ack huge", func(c *Config) { c.Handshake.DeltaAckUs = 2_000_000 }},
		{"rst_gap tiny", func(c *Config) { c.Handshake.RstGapUs = -2_000_000 }},
		{"rst_gap huge", func(c *Config) { c.Handshake.RstGapUs = 2_000_000 }},
		{"synack_timeout zero", func(c *Config) { c.Handshake.SynackTimeoutMs = 0 }},
		{"synack_timeout huge", func(c *Config) { c.Handshake.SynackTimeoutMs = 10_001 }},
		{"observe negative", func(c *Config) { c.Handshake.ObserveUs = -1 }},
		{"observe huge", func(c *Config) { c.Handshake.ObserveUs = 10_001 }},
		{"sweep negative", func(c *Config) { c.Handshake.DeltaSweepUs = []int{-1} }},
		{"sweep huge", func(c *Config) { c.Handshake.DeltaSweepUs = []int{2_000_000} }},
		{"gap_sweep tiny", func(c *Config) { c.Handshake.GapSweepUs = []int{-2_000_000} }},
		{"gap_sweep huge", func(c *Config) { c.Handshake.GapSweepUs = []int{2_000_000} }},
	}
	for _, tc := range bad {
		c := Default()
		tc.mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}
