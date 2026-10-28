"""Print the captured plaza 04 hint payload as one hex line (the server's public key and
settings; no client data). Used by Run-PersistenceChecks.ps1 to compare our hint
byte-for-byte outside the key. Usage: rf_official_hint.py CAPTURE
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from inspect_capture import read_pcapng, group_flows, reassemble
from rf_proudnet_frames import frames


def main() -> None:
    packets, _, _ = read_pcapng(Path(sys.argv[1]).read_bytes())
    for flow in group_flows(packets, collections.Counter()):
        syn = next((p for p in flow["packets"] if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != 33343:
            continue
        _, ranges, _ = reassemble([p for p in flow["packets"] if p["source"] == syn["destination"]])
        for _, _, kind, payload in frames(ranges[0][1]):
            if kind == "frame" and payload[0] == 0x04:
                print(payload.hex())
                return
    raise SystemExit("no hint found")


if __name__ == "__main__":
    main()
