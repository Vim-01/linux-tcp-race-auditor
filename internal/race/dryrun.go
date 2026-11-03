package race

import (
	"encoding/binary"
	"fmt"
	"strings"

	"cve98432/internal/config"
	"cve98432/internal/packet"
)

// DryRunText renders the exact datagrams the engine would send
// without opening any socket. Used by --dry-run and the TUI
// dry-run view.
func DryRunText(cfg config.Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	e := New(cfg)
	if cfg.Target.Mode == config.ModeHandshake {
		return e.dryRunHandshake()
	}
	return e.dryRunHammer()
}

// dryRunHammer renders one SYN and its byte-identical retransmit
// (hammer/spray/mptcp modes).
func (e *Engine) dryRunHammer() (string, error) {
	syn1, syn2, tcpStart, err := e.buildTemplates()
	if err != nil {
		return "", err
	}
	p1 := make([]byte, len(syn1))
	copy(p1, syn1)
	p2 := make([]byte, len(syn2))
	copy(p2, syn2)
	const demoPort = 10000
	const demoSeq = 0x01020304
	const demoID = 0x1234
	patch(p1, tcpStart, demoPort, demoSeq, demoID)
	patch(p2, tcpStart, demoPort, demoSeq, demoID)
	// patch rewrote IP ID and TCP port/seq; recompute checksums
	// exactly as the live engine does, so the rendered bytes are
	// what would actually go on the wire.
	packet.Rechecksum(p1)
	packet.Rechecksum(p2)

	var b strings.Builder
	b.WriteString("SYN (first, demo port/seq/ID):\n")
	b.WriteString(packet.HexFormat(p1, 16))
	b.WriteString("\n\nSYN (retransmit, byte-identical to first):\n")
	b.WriteString(packet.HexFormat(p2, 16))
	ipoptLen := tcpStart - 20
	tcpiptLen := len(p1) - tcpStart - 20
	b.WriteString(fmt.Sprintf("\n\nlen=%d bytes | ipopt=%dB | tcpipt=%dB | ttl=%d | dst=%s:%d\n",
		len(p1), ipoptLen, tcpiptLen, p1[8], e.cfg.Target.IP, e.cfg.Target.Port))
	return b.String(), nil
}

// dryRunHandshake renders the four datagrams of one handshake-mode
// round (SYN, retransmit, completing ACK, closing RST) plus the
// timing timeline the engine will execute. The ACK/RST carry a demo
// server ISN (0x99887766): at runtime it is the real ISN recovered
// from the target's SYN-ACK.
func (e *Engine) dryRunHandshake() (string, error) {
	synT, ackT, rstT, tcpStart, err := e.buildHandshakeTemplates()
	if err != nil {
		return "", err
	}
	syn := make([]byte, len(synT))
	copy(syn, synT)
	rtx := make([]byte, len(synT))
	copy(rtx, synT)
	ack := make([]byte, len(ackT))
	copy(ack, ackT)
	rst := make([]byte, len(rstT))
	copy(rst, rstT)

	const demoPort = 10000
	const demoSeq = 0x01020304
	const demoID = 0x1234
	const demoISN2 = 0x99887766
	patch(syn, tcpStart, demoPort, demoSeq, demoID)
	patch(rtx, tcpStart, demoPort, demoSeq, demoID)
	// ACK/RST templates have no IP options: TCP starts at 20.
	patch(ack, 20, demoPort, demoSeq, demoID)
	patch(rst, 20, demoPort, demoSeq+1, demoID)
	binary.BigEndian.PutUint32(ack[20+8:20+12], demoISN2+1)
	binary.BigEndian.PutUint32(rst[20+8:20+12], demoISN2+1)
	for _, p := range [][]byte{syn, rtx, ack, rst} {
		packet.Rechecksum(p)
	}

	h := e.cfg.Handshake
	var b strings.Builder
	b.WriteString("SYN (first, with IP options, demo port/seq/ID):\n")
	b.WriteString(packet.HexFormat(syn, 16))
	b.WriteString("\n\nSYN (retransmit, byte-identical to first; sent from the CPU_rtx thread):\n")
	b.WriteString(packet.HexFormat(rtx, 16))
	b.WriteString("\n\nACK (completing; ack = server-ISN+1, ISN shown as demo 0x99887766):\n")
	b.WriteString(packet.HexFormat(ack, 16))
	b.WriteString("\n\nRST (closing the child; seq = ISN+1, in the child's window):\n")
	b.WriteString(packet.HexFormat(rst, 16))

	ipoptLen := tcpStart - 20
	tcpiptLen := len(syn) - tcpStart - 20
	b.WriteString(fmt.Sprintf("\n\nlen=%d bytes | ipopt=%dB | tcpipt=%dB | ttl=%d | dst=%s:%d\n",
		len(syn), ipoptLen, tcpiptLen, syn[8], e.cfg.Target.IP, e.cfg.Target.Port))

	var tl strings.Builder
	fmt.Fprintf(&tl, "\nPer-round timeline (one 4-tuple at a time; ACK/RTX/RST dispatched in parallel from t=0):\n")
	fmt.Fprintf(&tl, "  t=-~ms   SYN -> %s:%d                     [coordinator]\n",
		e.cfg.Target.IP, e.cfg.Target.Port)
	fmt.Fprintf(&tl, "  t=0      <- SYN-ACK (server ISN recovered)\n")
	fmt.Fprintf(&tl, "  t=0      ACK  (seq=ISN,  ack=ISN2+1)     [cpu_ack=%d]\n", h.CPUAck)
	fmt.Fprintf(&tl, "  t=+%dus   SYN retransmit (byte-identical)  [cpu_rtx=%d]\n",
		h.DeltaAckUs, h.CPURtx)
	// signed: a negative rst_gap_us puts the RST before the
	// retransmit (and possibly before t=0) — the calibrated window.
	// The RST goes out from a dedicated worker (cpu_rst).
	fmt.Fprintf(&tl, "  t=%+5dus  RST  (seq=ISN+1, ack=ISN2+1)    [cpu_rst=%d]\n",
		h.DeltaAckUs+h.RstGapUs, h.CPURst)
	if len(h.DeltaSweepUs) > 0 {
		fmt.Fprintf(&tl, "  delta_ack_us is swept per round: %v\n", h.DeltaSweepUs)
	}
	if len(h.GapSweepUs) > 0 {
		fmt.Fprintf(&tl, "  rst_gap_us is swept per round: %v\n", h.GapSweepUs)
	}
	fmt.Fprintf(&tl, "  then observe %d us (early exit on first response): 2nd SYN-ACK = reader evidence\n", h.ObserveUs)
	b.WriteString(tl.String())
	return b.String(), nil
}
