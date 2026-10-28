"""Grade/medal IDs present in every capture's 30/A1, and whether each was seen with
all-zero values. Prints IDs (small type numbers) and counts only."""
from __future__ import annotations

import sys
from pathlib import Path

from rf_sequence import sequence

STRIDE = 13


def ids_and_zero(path: Path):
    frames = sequence(path.read_bytes())
    ids, zero = set(), set()
    for f in frames:
        if (f["dir"], f["type"], f["action"]) != ("S", 0x30, 0xA1):
            continue
        b = f["body"]
        for n in range(b[0]):
            rec = b[1 + n * STRIDE:1 + (n + 1) * STRIDE]
            ids.add(rec[0])
            if rec[1:] == bytes(12):
                zero.add(rec[0])
        prev = [b[1 + n * STRIDE] for n in range(b[0])]
        assert prev == sorted(prev), "IDs not ascending"
    return ids, zero


def main() -> None:
    sets = [ids_and_zero(Path(p)) for p in sys.argv[1:]]
    common = set.intersection(*(s[0] for s in sets))
    zero_somewhere = set.union(*(s[1] for s in sets))
    print("per-capture id counts:", [len(s[0]) for s in sets])
    print(f"common ids ({len(common)}):", sorted(common))
    print("common ids never seen all-zero:", sorted(common - zero_somewhere))
    print("ids 1 and 2 common:", {1, 2} <= common, "; zero-valued somewhere:", {1, 2} <= zero_somewhere)


if __name__ == "__main__":
    main()
