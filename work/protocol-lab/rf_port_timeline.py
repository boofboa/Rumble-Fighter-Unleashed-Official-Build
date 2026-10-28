"""Per-segment timeline (time, direction, payload length) of one TCP port's flows.

Metadata only (no payload bytes), relative to the capture start. Usage:
rf_port_timeline.py CAPTURE PORT [LIMIT]
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from inspect_capture import read_pcapng, group_flows


def main() -> None:
    packets, _, _ = read_pcapng(Path(sys.argv[1]).read_bytes())
    port, limit = int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 40
    t0 = min(p["time"] for p in packets)
    for flow in group_flows(packets, collections.Counter()):
        syn = next((p for p in flow["packets"] if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != port:
            continue
        shown = 0
        for p in flow["packets"]:
            d = "C->S" if p["source"] == syn["source"] else "S->C"
            flags = "".join(n for b, n in ((2, "S"), (16, "A"), (1, "F"), (4, "R"), (8, "P")) if p["flags"] & b)
            if len(p["payload"]) or p["flags"] & 7:
                print(f"{p['time'] - t0:9.3f} {d} flags={flags:5} len={len(p['payload'])}")
                shown += 1
            if shown >= limit:
                break


if __name__ == "__main__":
    main()
