// tui_test.go is a regression test for the value-receiver bug: the
// mutators startEngine/stopEngine/pushEvent/quitNow used to be
// declared with value receivers, so a SPACE on the fire page mutated
// a copy of the model — the returned model kept engine==nil and
// startErr=="" while a background engine leaked. The test lives in
// package tui to reach the unexported fields.
package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"cve98432/internal/config"
	"cve98432/internal/netio"
)

// TestFireKeyStartsEngineOrSetsStartErr: SPACE on the fire page must
// always be visible in the returned model — either the engine is
// attached and firing, or startErr carries the failure. Before the
// receiver fix both fields were empty and this test failed.
func TestFireKeyStartsEngineOrSetsStartErr(t *testing.T) {
	cfg := config.Default()
	cfg.Timing.Flows = 1 // keep the privileged branch as quiet as possible
	m := New(&cfg, false)
	m.page = PageFire

	// Probe the raw-socket privilege of THIS process instead of
	// checking euid: unprivileged containers commonly hold
	// CAP_NET_RAW and would start a real engine here.
	rawErr := func() error {
		snd, err := netio.OpenSender("")
		if err != nil {
			return err
		}
		snd.Close()
		return nil
	}()

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m2, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want Model", next)
	}
	if m2.engine == nil && m2.startErr == "" {
		t.Fatal("SPACE produced neither engine nor startErr: mutators lost state (value receiver?)")
	}

	if rawErr != nil {
		// Without a raw socket the engine must fail and the model
		// must surface it: error text plus an ERROR event in the
		// ring (pushEvent used to drop it into a copy as well).
		if m2.startErr == "" {
			t.Error("startErr must be set when the raw socket is unavailable")
		}
		if strings.Contains(rawErr.Error(), "CAP_NET_RAW") && !strings.Contains(m2.startErr, "CAP_NET_RAW") {
			t.Errorf("startErr = %q, want a CAP_NET_RAW hint", m2.startErr)
		}
		if len(m2.events) == 0 {
			t.Error("expected an ERROR event in the ring")
		}
		if m2.firing {
			t.Error("firing must stay false when the engine failed to start")
		}
		return
	}

	// Privileged: the engine really started (brief loopback, 1 flow).
	if m2.engine == nil || !m2.firing {
		t.Fatal("root: engine must be attached and firing")
	}
	next2, _ := m2.Update(tea.KeyMsg{Type: tea.KeySpace})
	m3, ok := next2.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want Model", next2)
	}
	if m3.firing {
		t.Error("second SPACE must stop the engine")
	}
	// stopEngine() stops asynchronously; a synchronous Stop()
	// (idempotent) drains the workers before the test ends.
	if m3.engine != nil {
		m3.engine.Stop()
	}
}
