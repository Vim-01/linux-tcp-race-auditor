// Package tui implements the bubbletea terminal UI for the
// CVE-2026-98432 exploit tool.
package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"cve98432/internal/config"
	"cve98432/internal/race"
)

type Page int

const (
	PageTarget Page = iota
	PagePayload
	PageFire
	PageResult
)

// Field indices in the flat input list.
const (
	fTargetIP = iota
	fTargetPort
	fKernelVer
	fMode
	fOptPreset
	fCustomHex
	fTTL
	fWindow
	fTCPipt
	fSrcIP
	fDelta
	fFlows
	fGap
	fDuration
	fCount
)

const maxEvents = 8

type engineEventMsg struct{ ev race.Event }
type engineStatsMsg struct{ st race.Stats }
type engineTickMsg struct{}

// Model is the root TUI state.
type Model struct {
	cfg      *config.Config
	l10n     *L10n
	page     Page
	focus    int
	inputs   []textinput.Model
	engine   *race.Engine
	firing   bool
	stats    race.Stats
	events   []string
	dryRun   bool
	dryText  string
	width    int
	height   int
	errMsg   string
	startErr string
}

// New builds the model from a config.
func New(cfg *config.Config, dryRun bool) Model {
	m := Model{
		cfg:    cfg,
		l10n:   NewL10n(cfg.General.Lang),
		dryRun: dryRun,
	}
	m.inputs = make([]textinput.Model, fCount)
	vals := map[int]string{
		fTargetIP:   cfg.Target.IP,
		fTargetPort: strconv.Itoa(cfg.Target.Port),
		fKernelVer:  cfg.Target.KernelVersion,
		fMode:       string(cfg.Target.Mode),
		fOptPreset:  cfg.Payload.OptionsPreset,
		fCustomHex:  cfg.Payload.CustomHex,
		fTTL:        strconv.Itoa(cfg.Payload.TTL),
		fWindow:     strconv.Itoa(cfg.Payload.Window),
		fTCPipt:     boolStr(cfg.Payload.TCPCommonOpts),
		fSrcIP:      cfg.Payload.SourceIP,
		fDelta:      strconv.Itoa(cfg.Timing.DeltaUs),
		fFlows:      strconv.Itoa(cfg.Timing.Flows),
		fGap:        strconv.Itoa(cfg.Timing.FlowGapMs),
		fDuration:   strconv.Itoa(cfg.Timing.DurationSec),
	}
	for i := 0; i < fCount; i++ {
		ti := textinput.New()
		ti.SetValue(vals[i])
		ti.CharLimit = 64
		ti.Width = 30
		m.inputs[i] = ti
	}
	m.inputs[fTargetIP].Placeholder = "192.168.1.50"
	m.inputs[fCustomHex].Placeholder = "2c 0c 00 00 00 00 00 0a 00 00 01"
	m.inputs[fTCPipt].CharLimit = 3
	return m
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// Run starts the TUI program.
func Run(cfg *config.Config, dryRun bool) error {
	p := tea.NewProgram(New(cfg, dryRun), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---- Update ----

func (m Model) Init() tea.Cmd {
	return m.inputs[fTargetIP].Focus()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		w := msg.Width - 40
		if w < 8 {
			w = 8
		}
		for i := range m.inputs {
			m.inputs[i].Width = w
		}
		return m, nil

	case engineStatsMsg:
		m.stats = msg.st
		if m.firing && int(m.stats.Elapsed.Seconds()) >= m.cfg.Timing.DurationSec {
			m.stopEngine("duration elapsed")
		}
		return m, m.enginePoll()

	case engineEventMsg:
		ts := msg.ev.Time.Round(time.Millisecond)
		m.pushEvent(fmt.Sprintf("t+%s %s: %s", ts, colorLevel(msg.ev.Level), msg.ev.Msg))
		return m, m.enginePoll()

	case engineTickMsg:
		return m, m.enginePoll()

	case tea.KeyMsg:
		return m.updateKey(msg)
	}
	return m, nil
}

func (m Model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	switch k {
	case "q", "ctrl+c":
		m.quitNow()
		return m, func() tea.Msg { return tea.Quit() }
	case "l":
		m.l10n = m.l10n.Toggle()
		m.cfg.General.Lang = m.l10n.Lang()
		return m, nil
	}
	switch m.page {
	case PageTarget, PagePayload:
		return m.updateFormKey(k, msg)
	case PageFire:
		return m.updateFireKey(k)
	case PageResult:
		switch k {
		case "enter", "tab":
			m.page = PagePayload
			m.focus = 0
			return m, m.focusInput()
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) quitNow() {
	m.firing = false
	if m.engine != nil && m.engine.Firing() {
		go m.engine.Stop()
	}
}

// updateFormKey handles the two configuration pages.
func (m Model) updateFormKey(k string, msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	first, last := m.pageRange()
	count := last - first + 1
	idx := first + m.focus
	switch k {
	case "tab":
		m.commit()
		m.page = m.nextPage()
		m.focus = 0
		return m, m.focusInput()
	case "backtab":
		m.commit()
		if m.page == PagePayload {
			m.page = PageTarget
		} else {
			m.page = PageResult
		}
		m.focus = 0
		return m, m.focusInput()
	case "up":
		m.focus = (m.focus + count - 1) % count
		return m, m.focusInput()
	case "down", "j":
		m.focus = (m.focus + 1) % count
		return m, m.focusInput()
	case "enter":
		m.commit()
		if m.page == PageTarget {
			m.page = PagePayload
			m.focus = 0
			return m, m.focusInput()
		}
		// Payload -> Fire
		if err := m.cfg.Validate(); err != nil {
			m.errMsg = m.l10n.T("err_validation") + ": " + err.Error()
			return m, nil
		}
		m.errMsg = ""
		m.page = PageFire
		if m.dryRun {
			t, err := race.DryRunText(*m.cfg)
			if err != nil {
				m.errMsg = err.Error()
			} else {
				m.dryText = t
			}
		}
		return m, nil
	default:
		ti, cmd := m.inputs[idx].Update(msg)
		m.inputs[idx] = ti
		m.errMsg = ""
		return m, cmd
	}
}

func (m Model) updateFireKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case " ":
		if m.dryRun {
			return m, nil
		}
		if m.firing {
			m.stopEngine("user stop")
		} else {
			m.startEngine()
		}
		return m, m.enginePoll()
	case "r":
		m.page = PageResult
		return m, nil
	}
	return m, nil
}

func (m Model) pageRange() (int, int) {
	switch m.page {
	case PageTarget:
		return fTargetIP, fMode
	case PagePayload:
		return fOptPreset, fDuration
	}
	return 0, fCount - 1
}

func (m Model) nextPage() Page {
	if m.page == PageTarget {
		return PagePayload
	}
	return PageFire
}

func (m Model) focusInput() tea.Cmd {
	// blur all, focus current
	for i := range m.inputs {
		m.inputs[i].Blur()
	}
	first, _ := m.pageRange()
	return m.inputs[first+m.focus].Focus()
}

// commit copies the visible fields into the config (best effort).
func (m Model) commit() {
	m.cfg.Target.IP = strings.TrimSpace(m.inputs[fTargetIP].Value())
	if p, err := strconv.Atoi(strings.TrimSpace(m.inputs[fTargetPort].Value())); err == nil {
		m.cfg.Target.Port = p
	}
	m.cfg.Target.KernelVersion = strings.TrimSpace(m.inputs[fKernelVer].Value())
	m.cfg.Target.Mode = config.Mode(strings.ToLower(strings.TrimSpace(m.inputs[fMode].Value())))
	m.cfg.Payload.OptionsPreset = strings.ToLower(strings.TrimSpace(m.inputs[fOptPreset].Value()))
	m.cfg.Payload.CustomHex = strings.TrimSpace(m.inputs[fCustomHex].Value())
	if v, err := strconv.Atoi(m.inputs[fTTL].Value()); err == nil {
		m.cfg.Payload.TTL = v
	}
	if v, err := strconv.Atoi(m.inputs[fWindow].Value()); err == nil {
		m.cfg.Payload.Window = v
	}
	m.cfg.Payload.TCPCommonOpts = strings.ToLower(m.inputs[fTCPipt].Value()) == "on"
	m.cfg.Payload.SourceIP = strings.TrimSpace(m.inputs[fSrcIP].Value())
	if v, err := strconv.Atoi(m.inputs[fDelta].Value()); err == nil {
		m.cfg.Timing.DeltaUs = v
	}
	if v, err := strconv.Atoi(m.inputs[fFlows].Value()); err == nil {
		m.cfg.Timing.Flows = v
	}
	if v, err := strconv.Atoi(m.inputs[fGap].Value()); err == nil {
		m.cfg.Timing.FlowGapMs = v
	}
	if v, err := strconv.Atoi(m.inputs[fDuration].Value()); err == nil {
		m.cfg.Timing.DurationSec = v
	}
}

// ---- Engine control ----

func (m *Model) startEngine() {
	m.engine = race.New(*m.cfg)
	if err := m.engine.Start(); err != nil {
		m.startErr = err.Error()
		m.pushEvent(fmt.Sprintf("ERROR: %s", err.Error()))
		if strings.Contains(err.Error(), "CAP_NET_RAW") {
			m.startErr += "\n" + m.l10n.T("err_need_root")
		}
		return
	}
	// Start succeeded: drop any stale error from a previous attempt.
	m.startErr = ""
	m.firing = true
	m.stats = race.Stats{}
}

func (m *Model) stopEngine(reason string) {
	if m.engine == nil {
		return
	}
	m.firing = false
	go func() {
		m.engine.Stop()
	}()
	m.pushEvent(fmt.Sprintf("%s: %s", m.l10n.T("stopped"), reason))
}

// enginePoll keeps draining engine channels while firing.
func (m Model) enginePoll() tea.Cmd {
	eng := m.engine
	if eng == nil || !m.firing {
		return nil
	}
	return func() tea.Msg {
		select {
		case ev := <-eng.Events():
			return engineEventMsg{ev}
		case st := <-eng.Snapshots():
			return engineStatsMsg{st}
		case <-time.After(100 * time.Millisecond):
			return engineTickMsg{}
		}
	}
}

// ---- Events ring ----

func (m *Model) pushEvent(s string) {
	m.events = append(m.events, s)
	if len(m.events) > maxEvents {
		m.events = m.events[len(m.events)-maxEvents:]
	}
}

// ---- View ----

var (
	stTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	stSub    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	stLabel  = lipgloss.NewStyle().Foreground(lipgloss.Color("111"))
	stFocus  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	stValue  = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	stStatK  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	stStatV  = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	stAlert  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	stOK     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	stWarn   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	stDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	stBorder = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63"))
	stPage   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
)

func colorLevel(level string) string {
	switch level {
	case "alert":
		return "ALERT"
	case "warn":
		return "WARN"
	default:
		return "info"
	}
}

func (m Model) View() string {
	var b strings.Builder
	title := m.l10n.T("title")
	if m.dryRun {
		title = "[DRY RUN] " + title
	}
	b.WriteString(stTitle.Render(title))
	b.WriteString("\n")
	b.WriteString(stSub.Render(m.l10n.T("subtitle")))
	b.WriteString("\n")
	pages := []string{
		m.l10n.T("page_target"), m.l10n.T("page_payload"),
		m.l10n.T("page_fire"), m.l10n.T("page_result"),
	}
	crumbs := make([]string, len(pages))
	for i, p := range pages {
		if i == int(m.page) {
			crumbs[i] = stPage.Render(p)
		} else {
			crumbs[i] = stDim.Render(p)
		}
	}
	b.WriteString("  " + strings.Join(crumbs, " > ") + "   ")
	b.WriteString(stDim.Render(fmt.Sprintf("[%s] %s", m.l10n.Lang(), m.l10n.T("lang"))))
	b.WriteString("\n\n")

	if m.errMsg != "" {
		b.WriteString(stAlert.Render("  "+m.errMsg) + "\n\n")
	}

	switch m.page {
	case PageTarget:
		b.WriteString(m.renderFormPage("target"))
	case PagePayload:
		b.WriteString(m.renderFormPage("payload"))
	case PageFire:
		if m.dryRun {
			b.WriteString(m.renderDryRun())
		} else {
			b.WriteString(m.renderFire())
		}
	case PageResult:
		b.WriteString(m.renderResult())
	}
	b.WriteString("\n")
	b.WriteString(stDim.Render("  " + m.l10n.T("footer")))
	return b.String()
}

func (m Model) renderFormPage(kind string) string {
	var b strings.Builder
	b.WriteString(stLabel.Render("  "+m.l10n.T("mode")) + "  ")
	b.WriteString(stDim.Render(m.l10n.T("mode_hammer")))
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("mode_spray")))
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("mode_mptcp")))
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("mode_handshake")))
	b.WriteString("\n\n")

	if kind == "target" {
		rows := []struct {
			key string
			idx int
		}{
			{"target_ip", fTargetIP},
			{"target_port", fTargetPort},
			{"kernel_ver", fKernelVer},
			{"mode", fMode},
		}
		first, last := m.pageRange()
		for i, r := range rows {
			focused := i == m.focus
			label := padRight(m.l10n.T(r.key), 22)
			if focused {
				b.WriteString("  " + stFocus.Render(label))
			} else {
				b.WriteString("  " + stLabel.Render(label))
			}
			b.WriteString(" " + m.inputs[r.idx].View())
			b.WriteString("\n")
			_ = first
			_ = last
		}
	} else {
		rows := []struct {
			key  string
			idx  int
			hint string
		}{
			{"opt_preset", fOptPreset, "nop | ts | rr | ssrr | custom (ssrr: non-loopback target only)"},
			{"opt_custom", fCustomHex, "hex, multiple of 4 bytes, <=40"},
			{"ttl", fTTL, "1-255"},
			{"window", fWindow, "0-65535"},
			{"tcpipt", fTCPipt, "on | off"},
			{"src_ip", fSrcIP, "e.g. 192.168.1.10 (bind; empty = auto egress IP)"},
			{"delta", fDelta, "microseconds, 100-200 typical, 1-1000000"},
			{"flows", fFlows, "parallel 4-tuples, 1-4096"},
			{"gap", fGap, "ms between rounds of one flow"},
			{"duration", fDuration, "seconds"},
		}
		for i, r := range rows {
			focused := i == m.focus
			label := padRight(m.l10n.T(r.key), 22)
			if focused {
				b.WriteString("  " + stFocus.Render(label))
			} else {
				b.WriteString("  " + stLabel.Render(label))
			}
			b.WriteString(" " + m.inputs[r.idx].View())
			b.WriteString("  ")
			b.WriteString(stDim.Render(" # " + r.hint))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("nav")))
	return b.String()
}

func (m Model) renderFire() string {
	var b strings.Builder
	status := m.l10n.T("status_idle")
	var statusStyle lipgloss.Style = stDim
	if m.firing {
		status = m.l10n.T("status_firing")
		statusStyle = stOK
	} else if m.stats.Elapsed != 0 {
		status = m.l10n.T("status_done")
		statusStyle = stWarn
	}
	b.WriteString("  " + statusStyle.Render(status) + "   ")
	b.WriteString(stDim.Render(fmt.Sprintf("target %s:%d  mode %s", m.cfg.Target.IP, m.cfg.Target.Port, m.cfg.Target.Mode)))
	b.WriteString("\n\n")

	if m.dryRun {
		b.WriteString(m.l10n.T("dry_run") + "\n")
	}
	if m.startErr != "" {
		b.WriteString(stAlert.Render("  "+m.startErr) + "\n\n")
	}

	rows := [][2]string{
		{m.l10n.T("stat_elapsed"), dur(m.stats.Elapsed)},
		{m.l10n.T("stat_syn"), fmt.Sprint(m.stats.SynSent)},
		{m.l10n.T("stat_rtx"), fmt.Sprint(m.stats.RtxSent)},
		{m.l10n.T("stat_pps"), fmt.Sprintf("%.0f", m.stats.Pps)},
		{m.l10n.T("stat_synack"), fmt.Sprint(m.stats.SynAck)},
		{m.l10n.T("stat_rst"), fmt.Sprint(m.stats.Rst)},
		{m.l10n.T("stat_err"), fmt.Sprint(m.stats.SendErrors)},
	}
	for _, r := range rows {
		b.WriteString("  " + stStatK.Render(padRight(r[0], 22)) + " ")
		b.WriteString(stStatV.Render(r[1]))
		b.WriteString("\n")
	}
	if m.stats.Silent {
		b.WriteString("  " + stAlert.Render(m.l10n.T("silent")) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(stLabel.Render("  "+m.l10n.T("events")+":") + "\n")
	for _, e := range m.events {
		b.WriteString("  " + stDim.Render(e) + "\n")
	}
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("fire_hint")))
	return b.String()
}

func (m Model) renderDryRun() string {
	var b strings.Builder
	b.WriteString(stLabel.Render(m.l10n.T("dry_run")) + "\n\n")
	if m.dryText != "" {
		for _, line := range strings.Split(m.dryText, "\n") {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString("\n  ")
	b.WriteString(stDim.Render(m.l10n.T("fire_hint")))
	return b.String()
}

func (m Model) renderResult() string {
	var b strings.Builder
	b.WriteString(stTitle.Render(m.l10n.T("result_title")) + "\n\n")
	rows := [][2]string{
		{m.l10n.T("stat_elapsed"), dur(m.stats.Elapsed)},
		{m.l10n.T("stat_syn"), fmt.Sprint(m.stats.SynSent)},
		{m.l10n.T("stat_rtx"), fmt.Sprint(m.stats.RtxSent)},
		{m.l10n.T("stat_synack"), fmt.Sprint(m.stats.SynAck)},
		{m.l10n.T("stat_rst"), fmt.Sprint(m.stats.Rst)},
		{m.l10n.T("stat_err"), fmt.Sprint(m.stats.SendErrors)},
	}
	for _, r := range rows {
		b.WriteString("  " + stStatK.Render(padRight(r[0], 22)) + " ")
		b.WriteString(stStatV.Render(r[1]))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(stWarn.Render("  "+m.l10n.T("result_note")) + "\n\n")
	b.WriteString(stDim.Render("  "+m.l10n.T("result_advice")) + "\n\n")
	b.WriteString("  " + stDim.Render("ENTER: "+m.l10n.T("page_payload")+"  |  Q: exit"))
	return b.String()
}

// padRight pads s with spaces up to w cells (labels are ASCII or
// single-width Cyrillic, so rune count == cell count).
func padRight(s string, w int) string {
	r := []rune(s)
	if len(r) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(r))
}

func dur(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
