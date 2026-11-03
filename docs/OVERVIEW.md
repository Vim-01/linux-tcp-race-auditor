# Technical Report: Empirical Evaluation of CVE-2026-98432 — Research Overview

RU mirror: `OVERVIEW-ru.md`. Technical assessment & timing bounds: `ASSESSMENT.md`. Detailed kernel mechanism: `CVE-2026-98432-ANALYSIS.md`.

## 1. Executive Summary

This project documents an empirical study of the race condition geometry in **CVE-2026-98432** (a Linux kernel TCP use-after-free within the IPv4 SYN and request-socket handling path).

We developed a high-precision triggering tool (`cve2026-98432-exp`) and evaluated it across 20 test runs in an isolated virtualized lab environment running Linux kernel **6.1.189** (built with KASAN and BTF support), accompanied by a negative control evaluation on the patched kernel **6.1.190**.

Across all test runs, the trigger successfully induced concurrent execution of the vulnerable path: retransmitted byte-identical SYN packets reliably accessed the shared IPv4 options structure (`P`, 72 bytes in slab `kmalloc-96`) while owned by the embryonic request socket. However, no memory corruption or KASAN report occurred because `kfree(P)` never executed within the active window of the concurrent reader.

## 2. The "KASAN Paradox" (Timing Analysis)

The window for concurrent execution in CVE-2026-98432 is sub-200 microseconds:

- **Reader Window:** The reader thread's access span between initial pointer dereference in `inet_csk_route_req` and completion in `ip_options_build` finishes within **≤ 160 µs** from the initial SYN-ACK reference $S$.
- **Free Delay:** Under **KASAN**, memory deallocation routines in the slab allocator experience 3–5× execution overhead. As a result, the fastest userspace-triggered deallocation (`accept()` followed immediately by `close()`) requires at least **232 µs** (busy-poll) to **352–411 µs** (standard event loop).

Because $T_{\text{free\_min}} > T_{\text{read\_max}}$, KASAN acts as a **negative detector**: the instrumentation required to observe memory corruption inadvertently delays the deallocation past the reader's execution window, preventing the race from manifesting. On uninstrumented production kernels, the deallocation occurs fast enough to overlap the reader window, but lacks built-in runtime detection.

## 3. Key Technical Contributions

1. **Deterministic Trigger Tool (`cve2026-98432-exp`):**
   A specialized Go utility that generates raw SYN/ACK sequences with strict timing control ($\Delta_{\text{ack}}$, $\epsilon$-sweep) from an unprivileged container with only `CAP_NET_RAW` enabled. Active concurrent reader execution was validated using kernel dynamic instrumentation (kprobes).

2. **Kernel Lifecycle & Vulnerability Matrix:**
   Comprehensive mapping of affected kernel branches (5.10.271 through 6.18.55) and patched releases (.272 / .223 / .190 / .159 / .113 / .56 / 7.2.10 / 7.3-rc7). Root-cause analysis covers the transition from direct `kfree()` to deferred RCU deallocation (`kfree_rcu()`).

3. **eBPF Runtime Security Blindspots:**
   Evaluation under Aqua **Tracee v0.24.1** demonstrated that while the runtime agent captured 100% of container system calls (`sendto`, `socket`, `close`) and raw network packets via cgroup-SKB hooks, it cannot detect or prevent in-kernel state transitions occurring strictly inside the TCP protocol state machine.

4. **Reproducible Testbed:**
   A complete standalone environment definition, including kernel configuration (`config-6.1.189-kasan`), automated runner scripts (`lab/lab-fire.sh`), and runtime monitoring policies (`lab/tracee-policy.yaml`).

## 4. Repository Structure

- `internal/` — Source code for the CLI tool, raw packet assembly, timing engine, and TUI.
- `docs/` — Technical assessment (`ASSESSMENT.md`), overview (`OVERVIEW.md`), and in-depth kernel analysis (`CVE-2026-98432-ANALYSIS.md`).
- `lab/` — Kernel configuration, test automation scripts, and eBPF security policies.
- `artifacts/` — Execution logs, dmesg outputs, and test artifacts.
- `mcp/` — Model Context Protocol server exposing automated kernel auditing and timing calculation tools.
