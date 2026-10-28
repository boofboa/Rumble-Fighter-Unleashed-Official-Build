"""ProudNet-style framing of the 5.188.32.116:33343 TCP stream (PRIVATE output).

Frame: magic 13 57, scalar size (prefix byte 1/2/4 then LE integer), payload;
payload[0] is the core opcode. A server-first Flash policy XML (NUL-terminated)
precedes the first frame. Prints per frame: time, direction, size, opcode and,
with --hex, the payload. Output can include key material and session data:
write it only under private/.
"""
from __future__ import annotations

import argparse
import bisect
import collections
from pathlib import Path
import struct

from inspect_capture import read_pcapng, group_flows, reassemble


def read_scalar(data: bytes, at: int):
    prefix = data[at]
    if prefix == 1:
        return data[at + 1], at + 2
    if prefix == 2:
        return struct.unpack_from("<H", data, at + 1)[0], at + 3
    if prefix == 4:
        return struct.unpack_from("<I", data, at + 1)[0], at + 5
    raise ValueError(f"scalar prefix {prefix:#x} at {at}")


def frames(data: bytes):
    at = 0
    if data.startswith(b"<?xml"):
        end = data.index(b"\x00") + 1
        yield 0, end, "policy_xml", data[:end]
        at = end
    while at + 3 <= len(data):
        if data[at:at + 2] != b"\x13\x57":
            yield at, len(data), "desync", data[at:at + 16]
            return
        size, body_at = read_scalar(data, at + 2)
        if body_at + size > len(data):
            yield at, len(data), "truncated", data[at:]
            return
        yield at, body_at + size, "frame", data[body_at:body_at + size]
        at = body_at + size


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--port", type=int, default=33343)
    parser.add_argument("--hex", action="store_true")
    parser.add_argument("--limit", type=int, default=100000)
    args = parser.parse_args()
    packets, _, _ = read_pcapng(args.capture.read_bytes())
    t0 = min(p["time"] for p in packets)
    out = []
    for flow in group_flows(packets, collections.Counter()):
        syn = next((p for p in flow["packets"] if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != args.port:
            continue
        for tag, endpoint in (("C", syn["source"]), ("S", syn["destination"])):
            meta, ranges, events = reassemble([p for p in flow["packets"] if p["source"] == endpoint])
            if not ranges:
                continue
            data = ranges[0][1]
            ends = sorted((e["stream_offset"] + e["payload_bytes"], e["time"]) for e in events)
            offsets = [e for e, _ in ends]
            for start, end, kind, payload in frames(data):
                t = ends[min(bisect.bisect_left(offsets, end), len(ends) - 1)][1] - t0
                out.append((t, tag, kind, payload))
    out.sort(key=lambda x: x[0])
    counts = collections.Counter()
    for t, tag, kind, payload in out[:args.limit]:
        op = payload[0] if kind == "frame" and payload else -1
        counts[(tag, op, len(payload) if op in (0x1a, 0x1b) else -1)] += 1
        line = f"{t:9.3f} {tag} {kind} len={len(payload)} op={op:#04x}"
        if args.hex:
            line += " " + payload[:96].hex(" ")
        print(line)
    print("--- opcode counts (dir, op, len for pings)")
    for k, v in sorted(counts.items()):
        print(k, v)


if __name__ == "__main__":
    main()
