# cve2026-98432-exp: Linux Kernel TCP Race Condition Research Tool

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20x86__64-blue.svg)](https://kernel.org)

High-precision security research and diagnostic tool designed to analyze sub-200 microsecond race conditions in the Linux kernel network stack, focused on **CVE-2026-98432** (IPv4 TCP SYN / request-socket Use-After-Free in `inet_opt` / `ireq_opt`).

The tool provides an interactive terminal user interface (Bubble Tea TUI), a headless CLI engine for automated lab runs, and a standalone **Model Context Protocol (MCP)** server for programmatic analysis.

---

## Key Research Findings

Empirical testing across 20 lab runs on Linux kernel 6.1.189 (KASAN+BTF) and patched kernel 6.1.190 yielded two fundamental insights into kernel race conditions:

### 1. The "KASAN Paradox" (Negative Detector Phenomenon)
For microsecond-scale races ($< 200\,\mu\text{s}$), the sanitizer deployed to catch memory corruption structurally prevents the race from occurring:
- **Kernel Reader Span:** The concurrent reader execution from `inet_csk_route_req` to `ip_options_build` finishes within **$\le 160\,\mu\text{s}$**.
- **Sanitizer Delay:** KASAN inflates slab deallocation routines by 3–5×. The fastest possible userspace-triggered `kfree(P)` (tight `accept()` + `close()` loop) has a measured lower bound of **$232\,\mu\text{s}$**.
- **Outcome:** Because $T_{\text{free\_min}} > T_{\text{read\_max}}$, KASAN acts as an unintended negative detector — the free always lands after the reader has finished, leaving dmesg clean.

### 2. eBPF Runtime Security Blindspots
Evaluating the trigger under Aqua **Tracee v0.24.1** (container scope) demonstrated the architectural boundary of eBPF observability:
- **100% Boundary Visibility:** The agent intercepted every `socket`, `sendto`, and `close` system call, as well as 100% of raw wire packets via cgroup-SKB hooks.
- **In-Kernel Invisibility:** The vulnerable state transition and concurrent dereference unfold entirely within the TCP protocol state machine (`tcp_v4_send_synack` / `inet_sock_destruct`). Because no boundary policies are broken, runtime agents cannot detect or prevent the race by design.

---

## Safe Mode by Default (`--dry-run`)

By default, safety is prioritized:
- Running with `--dry-run` synthesizes all raw IP and TCP structures, encodes option headers (SSRR, Timestamp, NOPs), and prints the complete per-round timeline and packet dumps to stdout.
- **Zero raw sockets are opened and no network packets leave the system.**

```bash
./cve2026-98432-exp --dry-run --config lab/attack-lab.toml
```

---

## Building

Requires Go 1.22+ and standard build tools. Pure Go with no CGO dependencies.

```bash
# Build host binary
make build

# Or standard go build
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o cve2026-98432-exp .

# Run static checks and unit tests
make vet
make test
```

---

## Usage

### 1. Safe Dry-Run Inspection
```bash
./cve2026-98432-exp --dry-run
```

### 2. Interactive TUI Mode
Launch the bilingual terminal user interface (English / Russian) to adjust timing intervals, sweep parameters, and packet options interactively:
```bash
./cve2026-98432-exp --config lab/attack-lab.toml
```

### 3. Headless CLI Mode (Lab Automation)
For scripting, CI, or container testbeds:
```bash
./cve2026-98432-exp --cli \
  --config lab/attack-lab.toml \
  --duration 60 \
  --delta-us 150
```

### 4. Target Listener Endpoint
In lab environments, the tool can act as the receiving server (holding embryonic request sockets or testing rapid abort-close behavior):
```bash
# Hold accepted connections until client-side reset
./cve2026-98432-exp --listen 9000 --listen-backlog 4

# Test rapid abort-close with SO_LINGER{1,0}
./cve2026-98432-exp --listen 9000 --listen-immediate --listen-busy-poll
```

---

## Operating Modes

| Mode | Flag | Description |
|---|---|---|
| **Handshake** | `handshake` | Calibrated 3-way handshake with microsecond $\Delta_{\text{ack}}$ and $\epsilon$-sweep timing. |
| **Hammer** | `hammer` | High-frequency parallel raw SYN injection across multiple flows. |
| **Spray** | `spray` | Heap grooming mode targeting slab `kmalloc-96` allocations. |
| **MPTCP** | `mptcp` | Multi-path TCP option headers and join token injection. |
| **Listener** | `--listen` | Target-side socket handler for holding or aborting connections in lab experiments. |

---

## Model Context Protocol (MCP) Server

The repository includes a standalone Python-based MCP server (`mcp/server.py`) adhering to the 2024-11-05 protocol specification. It provides automated tools for security analysis agents:

- `audit_kernel_version`: Audits Linux kernel versions against affected and patched releases for CVE-2026-98432.
- `calculate_timing_window`: Models the race feasibility gap and explains the KASAN Negative Detector effect.
- `inspect_tcp_options`: Synthesizes and inspects IPv4 option byte arrays safely in dry-run mode.
- `parse_dmesg_kasan`: Parses kernel dmesg dumps for `kmalloc-96` slab UAF call traces.
- `explain_ebpf_observability`: Explains eBPF runtime security boundaries and internal protocol blindspots.

Run the MCP server self-test:
```bash
python3 mcp/server.py --test
```

See [mcp/README.md](mcp/README.md) for configuration instructions with Claude Desktop and custom agents.

---

## Documentation & Lab Artifacts

Detailed technical reports and reproducibility assets:

- [Technical Assessment (EN)](docs/ASSESSMENT.md) / [Итоговый отчёт (RU)](docs/ASSESSMENT-ru.md) — Rigorous assessment of the 20 lab fires, timing mathematics, and structural findings.
- [Research Overview (EN)](docs/OVERVIEW.md) / [Обзор исследования (RU)](docs/OVERVIEW-ru.md) — High-level summary of the methodology, results, and implications.
- [Kernel Mechanism Analysis](docs/CVE-2026-98432-ANALYSIS.md) — Comprehensive technical breakdown of `inet_opt` lifecycle, socket allocation, and race dynamics.
- [Artifact Manifest](artifacts/ARTIFACTS.md) — Verification hashes, log summaries, and environment details.
- [Lab Directory](lab/) — One-command execution script (`lab-fire.sh`), kernel build configuration (`config-6.1.189-kasan`), and eBPF policies (`tracee-policy.yaml`).

---

## Vulnerability Matrix

| Branch | Vulnerable Range | Patched In | Upstream Fix Commit |
|---|---|---|---|
| **5.10.y** | 5.10.271 and earlier | `5.10.272` | `e3f33b0a1d89` (`kfree_rcu`) |
| **5.15.y** | 5.15.222 and earlier | `5.15.223` | `e3f33b0a1d89` (`kfree_rcu`) |
| **6.1.y**  | 6.1.189 and earlier  | `6.1.190`  | `e3f33b0a1d89` (`kfree_rcu`) |
| **6.6.y**  | 6.6.158 and earlier  | `6.6.159`  | `e3f33b0a1d89` (`kfree_rcu`) |
| **6.12.y** | 6.12.112 and earlier | `6.12.113` | `e3f33b0a1d89` (`kfree_rcu`) |
| **6.18.y** | 6.18.55 and earlier  | `6.18.56`  | `e3f33b0a1d89` (`kfree_rcu`) |
| **7.2.y**  | 7.2.9 and earlier    | `7.2.10`   | `e3f33b0a1d89` (`kfree_rcu`) |

---

## Legal & Safety Notice

This tool is strictly intended for authorized educational testing, defensive resilience validation, and kernel research on systems you own or are explicitly authorized to test. Directing raw network frames with custom options against production or third-party networks may disrupt service or trigger kernel panics.

See [DISCLAIMER.md](DISCLAIMER.md) for full legal disclaimers.

---

## License

This project is licensed under the [MIT License](LICENSE).
