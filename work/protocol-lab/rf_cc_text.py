"""Does 30/CD carry text (e.g. player names)? Prints record-relative offsets and
lengths of printable runs per category, never the text itself."""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from rf_sequence import sequence


def runs(rec: bytes):
    out, start = [], None
    for i, x in enumerate(rec + b"\0"):
        if 0x20 <= x < 0x7F:
            start = i if start is None else start
        else:
            if start is not None and i - start >= 3:
                out.append((start, i - start))
            start = None
    return out


def main() -> None:
    frames = sequence(Path(sys.argv[1]).read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    for i, f in enumerate(frames):
        if key(f) != ("C", 0x30, 0xCC):
            continue
        cat = f["body"][0]
        b = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0xCD))["body"]
        count = int.from_bytes(b[:4], "little")
        offsets = collections.Counter()
        for n in range(count):
            for off, ln in runs(b[4 + 60 * n:4 + 60 * (n + 1)]):
                offsets[(off, ln >= 3)] += 1
        print(f"category {cat}: count={count} text-run starts (record offset -> records): {dict(offsets)}")


if __name__ == "__main__":
    main()
