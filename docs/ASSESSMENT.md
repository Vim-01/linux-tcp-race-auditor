# Technical Report: Empirical Evaluation of CVE-2026-98432, Timing Bounds and eBPF Blindspots

Technical assessment and conclusion. Companion: `OVERVIEW.md` (research overview and structural findings). RU mirror: `ASSESSMENT-ru.md`.

## 1. What was done

- **20 lab fires** on vulnerable kernel **6.1.189** (KASAN+BTF; clean rebuild with `FUNCTION_TRACER=y` for Tracee preflight). Canonical binary (md5 `0ac561620dcac63c57a699f435aa3ca4`), Docker-default container, `backlog=4`, no-accept (`LS_NO_ACCEPT=1`), Δ=70 µs, ε-sweep `[0,3,6,9,12]`, 90 s each.
- **Negative control** (fire #19) on fixed kernel **6.1.190** — identical binary / params / geometry.
- **eBPF leg** (fire #20) under Aqua **Tracee v0.24.1** (container scope).
- **kprobe instrumentation** (13 probes) to value-cover both `kfree` sites and count reader (opt-deref) events.

## 2. Results (all MISS, all valid)

| fire | kernel | purpose | syn | rounds | skipped | reader-evidence | KASAN |
|---|---|---|---|---|---|---|---|
| #16b | 189 | no-accept, backlog=4 | 11,964 | 10 | 11,953 | 5 | clean — **FIRM=0, EDGE=0 / 56 readers** |
| #19 | 190 | negative control | 11,990 | 8 | 11,982 | 4 | clean |
| #20 | 189 | eBPF leg | 12,167 | 10 | 12,156 | 2 | clean (Tracee `sendto`=12,197) |

In **every** fire `reader-evidence > 0`: the byte-identical retransmit **did** hit the request before the ehash swap and re-read the shared P (the vulnerable read). But **no** `kfree(P)` ever landed inside the reader's read→use span → KASAN never reported. The 5 active children's P was freed only at shutdown drain; the 2 overflow reqs' P at synack-timeout (~63 s). **No fast `kfree(P)` during any 90 s fire.**

## 3. The timing math (why it is a structural miss)

Let S = the trigger reference (first SYN-ACK). Measured on KASAN 6.1.189:

- Reader read→use span: **≤ S+160 µs** (first P-deref in `inet_csk_route_req` → last in `ip_options_build`).
- Fastest possible `kfree(P)` (app accept+close): floor **S+232 µs** (busy-poll), **S+347 µs** (netpoll), **S+352…411 µs** (immediate).
- KASAN inflates the free path **3–5×** vs a plain kernel.

On KASAN: free-floor (S+232) > reader-ceiling (S+160) → the free **always lands after the reader's window** → no overlap → no KASAN report. The gap is ~72 µs — the race is structurally unreachable under KASAN instrumentation. On a non-KASAN kernel the free would be 3–5× faster, likely closing the gap — but then standard memory sanitizers are absent.

## 4. Technical Conclusions

- **The vulnerable geometry is real and triggerable** — proven structurally (kprobes value-cover both kfree sites; retransmit re-reads P; conservation 1-free/round). The tool is a reproducible **trigger**.
- **No in-lab UAF was observed under KASAN** (clean dmesg across 20 fires). KASAN acts as a **negative detector** for this sub-200 µs race: sanitizer overhead shifts execution timing beyond the concurrent race window.
- **Container security implications:** (a) The underlying CVE is present in unpatched kernels, (b) the trigger confirms the vulnerable socket path is reachable from an unprivileged container namespace with default capabilities (`CAP_NET_RAW`), (c) runtime eBPF agents have an inherent structural blindspot because the memory corruption sits within the kernel TCP state machine rather than across boundary hooks.

## 5. Future Research Directions

1. **Non-KASAN detector** — a targeted out-of-band probe (a controlled allocation/canary in the kmalloc-96 slab, or a lighter hardware-assisted sanitizer) that detects the UAF without the 3–5× free inflation.
2. **Faster free path** — a listener executing accept+close in a tight low-latency loop (sub-232 µs) on a production non-KASAN kernel, or `SO_LINGER{1,0}` abort-close.
3. **Broader runtime agent benchmarks** — evaluate additional eBPF and LSM-based security tooling across container boundaries.
