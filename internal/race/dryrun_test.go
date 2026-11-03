package race

import (
	"strings"
	"testing"

	"cve98432/internal/config"
)

// TestDryRunTextDefault: the default config must render a valid
// dry-run view; no socket is opened, no packet is sent.
func TestDryRunTextDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Target.IP = "10.0.0.2"
	text, err := DryRunText(cfg)
	if err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	for _, want := range []string{
		"SYN (first",
		"retransmit",
		"ipopt=12B", // default preset is ts (12 bytes)
		"dst=10.0.0.2:80",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in output:\n%s", want, text)
		}
	}
}

// TestDryRunTextCustom: custom hex options must be reflected.
func TestDryRunTextCustom(t *testing.T) {
	cfg := config.Default()
	cfg.Target.IP = "10.0.0.2"
	cfg.Payload.OptionsPreset = "custom"
	cfg.Payload.CustomHex = "01 01 01 01"
	text, err := DryRunText(cfg)
	if err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	if !strings.Contains(text, "ipopt=4B") {
		t.Errorf("expected ipopt=4B in output:\n%s", text)
	}
}

// TestDryRunTextHandshake: handshake mode renders all four
// datagrams (SYN, retransmit, completing ACK, closing RST) plus the
// per-round timeline with the pinned CPUs and the sweep.
func TestDryRunTextHandshake(t *testing.T) {
	cfg := config.Default()
	cfg.Target.IP = "10.0.0.2"
	cfg.Target.Mode = config.ModeHandshake
	cfg.Handshake.CPURtx, cfg.Handshake.CPUAck = 1, 2
	cfg.Handshake.DeltaAckUs = 4
	cfg.Handshake.DeltaSweepUs = []int{0, 2, 4}
	text, err := DryRunText(cfg)
	if err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	for _, want := range []string{
		"SYN (first",
		"retransmit",
		"ACK (completing",
		"RST (closing",
		"0x99887766", // demo server ISN
		"cpu_rtx=1",
		"cpu_ack=2",
		"delta_ack_us is swept per round: [0 2 4]",
		"reader evidence",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in output:\n%s", want, text)
		}
	}
}

// TestDryRunTextNoOptions: a config without IP options is valid for
// the builder, but the CVE needs options - the dry run must still
// render (validation only checks structure).
func TestDryRunTextNop(t *testing.T) {
	cfg := config.Default()
	cfg.Target.IP = "10.0.0.2"
	cfg.Payload.OptionsPreset = "nop"
	text, err := DryRunText(cfg)
	if err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	if !strings.Contains(text, "ipopt=4B") {
		t.Errorf("expected ipopt=4B in output:\n%s", text)
	}
}
