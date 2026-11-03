# Artifact manifest — CVE-2026-98432 closure package

All hashes below computed 2026-11-03. `hits.txt` is **0 bytes** (md5
`d41d8cd9…` = empty) = no UAF hit, consistent with the all-MISS closure.

## Tool (PoC)

| file | md5 |
|---|---|
| `tool/cve2026-98432-exp` (static amd64, v0.3.0) | `0ac561620dcac63c57a699f435aa3ca4` |
| `tool/cve2026-98432-exp-linux-amd64.tar.gz` | `5101b67b9dbc9bb82b164ac029f0676d` |

Build: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.3.0"`.

## Lab scripts / config

| file | md5 |
|---|---|
| `lab/lab-fire.sh` | `39a097b474bd1444ad46b08798b21229` |
| `lab/tracee-policy.yaml` (container scope) | `b3939fabcde05ed91412a93bc96e8be7` |
| `lab/config-6.1.189-kasan` | `fde32b0afe5a82015463800d3f77c42d` |

Deployed lab kernel: 6.1.189 (KASAN+BTF, `FUNCTION_TRACER=y` clean
rebuild); negative-control kernel 6.1.190. Kernel tarball
`vps-kernel-189f.tar.gz` (sha256
`0f6b816f495da23388f4b32ee85abd993c3ee7074af93004e8ac0e961fc6ff37`) is on
the lab VM `~/lab/` (not shipped here — large).

## Analysis

| file | lines |
|---|---|
| `analysis/uaf-trigger-analysis.md` | 780 |

## Key small artifacts (representative fires)

| file | fire | md5 |
|---|---|---|
| `artifacts/fire20.log` | #20 (eBPF leg, 189) | `991498a434872b07280ce096d49499f5` |
| `artifacts/tracee-agent.log` | #20 | `f3449b98b3cd8d2034e5c2cfad8ca2f0` |
| `artifacts/env-sysctl-vm.txt` | #20 | `5ce038236cd71ac8e06b38e00f61a645` |
| `artifacts/dmesg-new.txt` | #19 (negative control, 190) | `56f12592404ec15f34c14be1fc9ada4c` |
| `artifacts/env.txt` | #19 | `514bc2d981a55e23a7a39df6e2e8d3cf` |
| `artifacts/config-used.toml` | #19 | `42a65a5ff29d0870c51c90aa2ae5fd7e` |
| `artifacts/listener.log` | #19 | `b416d3f2ed7d410a8c6c6065c505d9b9` |
| `artifacts/hits.txt` | #19 (**empty** = no hit) | `d41d8cd98f00b204e9800998ecf8427e` |

## Where the full per-fire tarballs live (not shipped — large)

On the lab VM `198.51.100.25` (via jump `labuser@lab-gw.internal:2222`),
user `labuser`, under `~/lab/`:

- `~/lab/artifacts-hs-*` — one tarball per fire (TOML actually used,
  env.txt with uname/kasan-syms/md5, dmesg baseline+new, pcap, listener
  logs, hits.txt, ktrace).
- `~/lab/tracee-events.json` (fire #20, ~108 MB) — the eBPF-leg agent
  events (agent `sendto` = 12,197 = PoC total; cgroup packet events =
  2×12,177).
- Local pulled copies: `./artifacts/fire19/`, `./artifacts/fire20/`,
  `./artifacts/fire17/`.

## Fire summary (all MISS, all valid, KASAN clean)

| fire | kernel | purpose | syn | rounds | skipped | reader-evidence |
|---|---|---|---|---|---|---|
| #16b | 189 | no-accept, backlog=4 | 11,964 | 10 | 11,953 | 5 |
| #19 | 190 | negative control | 11,990 | 8 | 11,982 | 4 |
| #20 | 189 | eBPF leg | 12,167 | 10 | 12,156 | 2 |

(Fires #1–#15 and #17–#18: earlier calibration/kprobe legs, same
all-MISS outcome; full per-fire decomposition in `analysis/`.)
