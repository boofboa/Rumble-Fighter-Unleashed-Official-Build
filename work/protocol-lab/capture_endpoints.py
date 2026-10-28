"""Endpoint/port census of a capture, all IP protocols. Metadata only.

Prints per (protocol, local-side port, remote port) packet and byte counts and
first/last time, with remote addresses classified (loopback/private/global) and
global addresses reduced to a /24 so a public report does not expose peers.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
from pathlib import Path
import socket
import struct

from inspect_capture import read_pcapng


def classify(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    return "global:" + str(ipaddress.ip_network(address + "/24", strict=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    packets, _, _ = read_pcapng(args.capture.read_bytes())
    t0 = min(p["time"] for p in packets)
    stats = collections.defaultdict(lambda: [0, 0, None, None])
    other = collections.Counter()
    for p in packets:
        raw = p["raw"]
        if p["link"] != 1 or len(raw) < 34:
            other[f"link{p['link']}"] += 1
            continue
        ethertype = struct.unpack_from("!H", raw, 12)[0]
        if ethertype != 0x0800:
            other[f"ethertype_{ethertype:04x}"] += 1
            continue
        ihl = (raw[14] & 15) * 4
        proto = raw[23]
        src, dst = socket.inet_ntoa(raw[26:30]), socket.inet_ntoa(raw[30:34])
        l4 = raw[14 + ihl:]
        sport = dport = 0
        if proto in (6, 17) and len(l4) >= 4:
            sport, dport = struct.unpack_from("!HH", l4)
        local_is_src = ipaddress.ip_address(src).is_private
        local_port, remote, remote_port = (sport, dst, dport) if local_is_src else (dport, src, sport)
        name = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, f"ip{proto}")
        key = (name, classify(remote), remote_port if name != "udp" or remote_port < 49152 else "ephemeral",
               "out" if local_is_src else "in")
        s = stats[key]
        s[0] += 1
        s[1] += len(raw)
        t = round(p["time"] - t0, 3)
        s[2] = t if s[2] is None else s[2]
        s[3] = t
    for key, (count, size, first, last) in sorted(stats.items(), key=lambda kv: -kv[1][0]):
        print(f"{key[0]:5} {key[3]:3} remote={key[1]:24} rport={str(key[2]):9} packets={count:6} bytes={size:8} t={first}..{last}")
    if other:
        print("other:", dict(other))


if __name__ == "__main__":
    main()
