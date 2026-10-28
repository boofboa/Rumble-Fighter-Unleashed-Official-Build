"""Full payloads of the ProudNet handshake frames on TCP 33343 (PRIVATE output).

Prints opcodes 0x2e, 0x04, 0x05, 0x06, 0x07 and 0x0a in full; in 0x0a the client's
public address text is replaced by <ip>. Write output only under private/.
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

from inspect_capture import read_pcapng, group_flows, reassemble
from rf_proudnet_frames import frames

WANTED = {0x2e, 0x04, 0x05, 0x06, 0x07, 0x0a}


def main() -> None:
    packets, _, _ = read_pcapng(Path(sys.argv[1]).read_bytes())
    for flow in group_flows(packets, collections.Counter()):
        syn = next((p for p in flow["packets"] if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != 33343:
            continue
        for tag, endpoint in (("C", syn["source"]), ("S", syn["destination"])):
            meta, ranges, events = reassemble([p for p in flow["packets"] if p["source"] == endpoint])
            for start, end, kind, payload in frames(ranges[0][1]):
                if kind == "policy_xml":
                    print(tag, "policy", payload)
                    continue
                if kind != "frame" or payload[0] not in WANTED:
                    continue
                text = payload.hex(" ")
                if payload[0] == 0x0a:
                    text = re.sub(r"(31|32|33|34|35|36|37|38|39|30|2e)( (31|32|33|34|35|36|37|38|39|30|2e)){6,}", "<ip>", text)
                print(f"{tag} op={payload[0]:#04x} len={len(payload)}")
                for o in range(0, len(text), 96):
                    print("   ", text[o:o + 96])


if __name__ == "__main__":
    main()
