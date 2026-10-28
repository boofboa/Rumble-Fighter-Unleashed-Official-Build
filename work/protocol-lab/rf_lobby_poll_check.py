"""10/B6 -> 0x210/B7 and 40/84 -> 40/85 in official captures (PRIVATE output).

Prints request bodies, reply bodies (first 48 bytes), non-zero counts, whether
repeated 40/85 replies are identical, and text-run offsets (not text)."""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        print(f"== {path.name}")
        for i, f in enumerate(frames):
            if key(f) == ("C", 0x10, 0xB6):
                rep = next(g for g in frames[i + 1:] if g["dir"] == "S")
                print(f"  10/B6 t={f['t']:.1f} req={f['body'].hex()} -> {rep['type']:03x}/{rep['action']:02x} body={rep['body'].hex()}")
        polls = collections.Counter()
        reqs = collections.Counter()
        for i, f in enumerate(frames):
            if key(f) == ("C", 0x40, 0x84):
                rep = next((g for g in frames[i + 1:] if key(g) == ("S", 0x40, 0x85)), None)
                if rep is None:
                    continue  # capture ended before the reply
                polls[(len(rep["body"]), rep["body"])] += 1
                reqs[f["body"].hex()] += 1
        print(f"  40/84 request bodies: {dict(reqs)}")
        for (ln, body), n in polls.items():
            text = [k for k in range(len(body) - 2) if all(0x20 <= x < 0x7F for x in body[k:k + 3])]
            print(f"  40/85 len={ln} x{n} nonzero={sum(1 for x in body if x)} text_bytes={len(text)} head={body[:48].hex(' ')}")


if __name__ == "__main__":
    main()
