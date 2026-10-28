"""List TCP flows to a server prefix and test RF framing (RC4 'abcde') on each.

Metadata only. Server addresses inside --server-prefix are printed (they are
the operator's servers, not users); client addresses are never printed.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
from pathlib import Path

from inspect_capture import read_pcapng, group_flows, reassemble
from protocol_probe import rc4, scan_frames


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--server-prefix", default="5.188.32.0/24")
    args = parser.parse_args()
    net = ipaddress.ip_network(args.server_prefix)
    packets, _, _ = read_pcapng(args.capture.read_bytes())
    t0 = min(p["time"] for p in packets)
    for number, flow in enumerate(group_flows(packets, collections.Counter()), 1):
        ps = flow["packets"]
        server = next((e for e in flow["endpoints"] if ipaddress.ip_address(e[0]) in net), None)
        if server is None:
            continue
        client = next(e for e in flow["endpoints"] if e != server)
        line = [f"flow{number} server={server[0]}:{server[1]} t={ps[0]['time'] - t0:.3f}..{ps[-1]['time'] - t0:.3f}"]
        for tag, endpoint in (("C", client), ("S", server)):
            meta, ranges, _ = reassemble([p for p in ps if p["source"] == endpoint])
            if not ranges:
                line.append(f"{tag}:empty")
                continue
            if len(ranges) != 1 or ranges[0][0] != 0:
                line.append(f"{tag}:gaps({len(ranges)} ranges, start {ranges[0][0]})")
                continue
            framing = scan_frames(rc4(ranges[0][1], b"abcde"))
            line.append(f"{tag}:{framing['status']} frames={framing['frame_count']} bytes={framing['input_bytes']}")
        print(" ".join(line))


if __name__ == "__main__":
    main()
