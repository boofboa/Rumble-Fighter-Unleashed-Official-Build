"""Dump 30/A1 grade records (PRIVATE output) and per-offset value statistics.

Record = 13 bytes after a u8 count. Prints each capture's first reply records
and, across captures, distinct values per byte offset.
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from rf_sequence import sequence

STRIDE = 13


def main() -> None:
    per_offset = collections.defaultdict(collections.Counter)
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        replies = [f for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0xA1)]
        bodies = {f["body"] for f in replies}
        print(f"== {path.name}: replies={len(replies)} distinct bodies={len(bodies)}")
        b = replies[0]["body"]
        for n in range(b[0]):
            rec = b[1 + n * STRIDE:1 + (n + 1) * STRIDE]
            print(f"   {n:3}: {rec.hex(' ')}")
            for i, x in enumerate(rec):
                per_offset[i][x] += 1
    for i in range(STRIDE):
        print(f"offset {i:2}: distinct={len(per_offset[i])} top={per_offset[i].most_common(6)}")


if __name__ == "__main__":
    main()
