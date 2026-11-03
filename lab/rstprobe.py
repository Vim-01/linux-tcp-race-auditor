#!/usr/bin/env python3
"""Probe: which sendto() calls fail on a raw TCP socket with IP_HDRINCL,
and with what errno. Replicates the cve2026-98432-exp handshake-mode
packets (SYN with IP options, plain ACK, plain RST+ACK) from the
sender-side netns. Usage (as root, on the VM):

    SPID=$(sudo docker inspect -f '{{.State.Pid}}' sender)
    sudo nsenter -t $SPID -n /usr/bin/python3 /tmp/rstprobe.py
"""
import socket
import struct
import sys


def csum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) >> 1), data))
    while s >> 16:
        s = (s & 0xFFFF) | (s >> 16)
    return (~s) & 0xFFFF


def build(src, dst, sport, dport, seq, ack, flags, win=65535,
          ipopts=b"", ipid=0, ttl=64):
    tot = 20 + len(ipopts) + 20
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, ipid, 0x4000, ttl,
                      6, 0, bytes(src), bytes(dst))
    tcph = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                       5 << 4, flags, win, 0, 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack("!BBH", 0, 6, len(tcph))
    c = csum16(pseudo + tcph)
    tcph = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                       5 << 4, flags, win, c, 0)
    return iph + ipopts + tcph


def main():
    src = socket.inet_aton("172.17.0.3")
    dst = socket.inet_aton("172.17.0.2")
    daddr = ("172.17.0.2", 9000)

    # IP options preset "ts" (same 12 bytes the tool uses):
    # nop, nop, timestamp kind=8 len=10 val=0 ts=0  + 2 more nops?
    # tool's ts preset = nop,nop,ts(8,10,0,0),nop,nop  -> 2+8+2 = 12
    ipopts = b"\x01\x01\x08\x0a\x00\x00\x00\x00\x00\x00\x01\x01"

    isn, isn2 = 0x11223344, 0x55667788
    syn = build(src, dst, 12345, 9000, isn, 0, 0x02, ipopts=ipopts, ipid=7)
    rtx = syn  # byte-identical retransmit
    ack = build(src, dst, 12345, 9000, isn + 1, isn2 + 1, 0x10, ipid=7)
    rst = build(src, dst, 12345, 9000, isn + 1, isn2 + 1, 0x14, ipid=7)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    stats = {k: [0, None] for k in ("syn", "rtx", "ack", "rst")}
    for i in range(n):
        for k, pkt in (("syn", syn), ("rtx", rtx), ("ack", ack), ("rst", rst)):
            try:
                s.sendto(pkt, daddr)
            except OSError as e:
                stats[k][0] += 1
                if stats[k][1] is None:
                    stats[k][1] = (i, e.errno, str(e))
    for k in ("syn", "rtx", "ack", "rst"):
        cnt, first = stats[k]
        print("%-4s errs=%d/%d first=%s" % (k, cnt, n, first))


if __name__ == "__main__":
    main()
