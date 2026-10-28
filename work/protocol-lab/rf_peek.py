"""Print the opening bytes of selected TCP flows and UDP datagrams (PRIVATE output).

Raw bytes may include session data: redirect output only under private/.
"""
from __future__ import annotations

import argparse
import collections
from pathlib import Path
import socket
import struct

from inspect_capture import read_pcapng, group_flows, reassemble


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--tcp-port", type=int, action="append", default=[])
    parser.add_argument("--udp-port", type=int, action="append", default=[])
    parser.add_argument("--bytes", type=int, default=64)
    parser.add_argument("--datagrams", type=int, default=12)
    args = parser.parse_args()
    packets, _, _ = read_pcapng(args.capture.read_bytes())
    t0 = min(p["time"] for p in packets)
    for flow in group_flows(packets, collections.Counter()):
        server = next((e for e in flow["endpoints"] if e[1] in args.tcp_port), None)
        if server is None:
            continue
        client = next(e for e in flow["endpoints"] if e != server)
        print(f"TCP {server[0]}:{server[1]}")
        for tag, endpoint in (("C", client), ("S", server)):
            meta, ranges, events = reassemble([p for p in flow["packets"] if p["source"] == endpoint])
            data = ranges[0][1] if ranges else b""
            print(f"  {tag} total={len(data)} first segments={[e['payload_bytes'] for e in events[:12]]}")
            print(f"    {data[:args.bytes].hex(' ')}")
    shown = collections.Counter()
    for p in packets:
        raw = p["raw"]
        if p["link"] != 1 or len(raw) < 42 or raw[12:14] != b"\x08\x00" or raw[23] != 17:
            continue
        ihl = (raw[14] & 15) * 4
        sport, dport, length = struct.unpack_from("!HHH", raw, 14 + ihl)
        port = next((x for x in args.udp_port if x in (sport, dport)), None)
        if port is None or shown[port] >= args.datagrams:
            continue
        shown[port] += 1
        payload = raw[14 + ihl + 8:14 + ihl + length]
        direction = "S->C" if sport == port else "C->S"
        src = socket.inet_ntoa(raw[26:30]) if sport == port else socket.inet_ntoa(raw[30:34])
        print(f"UDP {src}:{port} {direction} t={p['time'] - t0:.3f} len={len(payload)} {payload[:args.bytes].hex(' ')}")


if __name__ == "__main__":
    main()
