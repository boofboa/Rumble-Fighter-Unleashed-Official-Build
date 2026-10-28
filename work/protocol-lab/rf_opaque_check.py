"""Characterize the opaque record region +12..28 (PRIVATE output: prints bytes).

For rods and for all records: which offsets are non-zero, whether rod bytes are
identical across captures, and whether +23..28 decodes plausibly as a date.
"""
from __future__ import annotations

import collections
import datetime
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
ROD = 5135224


def records(path: Path):
    frames = sequence(path.read_bytes())
    out = {}
    for f in frames:
        if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0x85):
            count = struct.unpack_from("<H", f["body"])[0]
            for n in range(count):
                rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                out[struct.unpack_from("<I", rec)[0]] = rec
    return out


def main() -> None:
    nonzero_by_offset = collections.Counter()
    total = 0
    by_end = collections.Counter()
    for path in map(Path, sys.argv[1:]):
        recs = records(path)
        for rec in recs.values():
            total += 1
            region = rec[12:29]
            for i, b in enumerate(region):
                if b:
                    nonzero_by_offset[12 + i] += 1
            end = struct.unpack_from("<I", rec, 29)[0]
            by_end[(end == 0, region == bytes(17))] += 1
            if struct.unpack_from("<I", rec, 4)[0] == ROD:
                print(f"{path.name} rod +12..28: {region.hex(' ')}")
                tail = rec[23:29]
                print(f"   +23..28 as bytes: {list(tail)}; LE16 pairs: {[int.from_bytes(tail[i:i+2], 'little') for i in (0, 2, 4)]}")
    print(f"records={total}; non-zero count per offset in +12..28: {dict(sorted(nonzero_by_offset.items()))}")
    print("(end==0, opaque all zero) -> records:", dict(by_end))


if __name__ == "__main__":
    main()
