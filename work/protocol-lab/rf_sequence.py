"""Time-ordered RF frame sequence for one capture (both directions interleaved).

Default output is headers only (direction, time, type, action, length).
--dump TYPE:ACTION prints decrypted bodies of matching frames as hex; write
that output only under private/, because bodies can carry account data.
Login request bodies (0x10/0x84 client->server) are never dumped.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
from pathlib import Path
import struct

from inspect_capture import read_pcapng, group_flows, reassemble
from protocol_probe import rc4

NEVER_DUMP = {("C", 0x10, 0x84)}


def frames_with_offsets(data: bytes):
    offset = 0
    while offset + 6 <= len(data):
        ftype, total = struct.unpack_from(">HH", data, offset)
        action = struct.unpack_from("<H", data, offset + 4)[0]
        if total < 6 or offset + total > len(data):
            break
        yield offset, ftype, action, data[offset + 6:offset + total]
        offset += total


def sequence(blob: bytes, server_port: int = 7000) -> list[dict]:
    packets, _, _ = read_pcapng(blob)
    flows = group_flows(packets, collections.Counter())
    out = []
    for number, flow in enumerate(flows, 1):
        ps = flow["packets"]
        syn = next((p for p in ps if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != server_port:
            continue
        t0 = min(p["time"] for p in packets)
        for tag, endpoint in (("C", syn["source"]), ("S", syn["destination"])):
            meta, ranges, events = reassemble([p for p in ps if p["source"] == endpoint])
            if len(ranges) != 1 or ranges[0][0] != 0 or meta["conflicting_overlap_bytes"]:
                raise ValueError(f"flow {number} {tag}: stream not contiguous")
            data = rc4(ranges[0][1], b"abcde")
            # A frame is "sent" when the packet carrying its last byte arrives.
            ends = sorted((e["stream_offset"] + e["payload_bytes"], e["time"]) for e in events)
            end_offsets = [e for e, _ in ends]
            for index, (offset, ftype, action, body) in enumerate(frames_with_offsets(data)):
                last = offset + 6 + len(body)
                at = ends[bisect.bisect_left(end_offsets, last)][1]
                out.append(dict(flow=number, dir=tag, index=index, t=round(at - t0, 6),
                                stream_offset=offset, type=ftype, action=action,
                                total=6 + len(body), body=body))
    out.sort(key=lambda f: (f["t"], f["flow"], f["dir"] != "C", f["stream_offset"]))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--dump", action="append", default=[], metavar="TYPE:ACTION",
                        help="hex, e.g. 0x10:0xa8; repeatable")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    wanted = {tuple(int(x, 0) for x in item.split(":")) for item in args.dump}
    seq = sequence(args.capture.read_bytes())
    for f in seq:
        dump = (f["type"], f["action"]) in wanted and (f["dir"], f["type"], f["action"]) not in NEVER_DUMP
        body = f.pop("body")
        if args.json:
            if dump:
                f["body_hex"] = body.hex()
            print(json.dumps(f))
            continue
        print(f"{f['t']:10.3f} {f['dir']} #{f['index']:<3} type=0x{f['type']:02x} "
              f"action=0x{f['action']:02x} total={f['total']}")
        if dump:
            for i in range(0, len(body), 32):
                print(f"{'':16}{i:05x}: {body[i:i + 32].hex(' ')}")


if __name__ == "__main__":
    main()
