"""30/CC (8-byte body) -> 30/CD (1804-byte body) structure. PRIVATE output.

Prints request bodies, reply length, leading bytes, non-zero byte count, and a
candidate count/stride, per request, for the first CC burst of each capture.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        print(f"== {path.name}")
        shown = 0
        for i, f in enumerate(frames):
            if key(f) != ("C", 0x30, 0xCC) or shown >= 6:
                continue
            rep = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0xCD))
            b = rep["body"]
            u16, u32 = struct.unpack_from("<H", b)[0], struct.unpack_from("<I", b)[0]
            strides = [s for s in range(4, 200) if u16 and (len(b) - 2) % s == 0 and (len(b) - 2) // s >= u16]
            print(f"  req={f['body'].hex(' ')} -> len={len(b)} u16={u16} u32={u32} nonzero={sum(1 for x in b if x)}"
                  f" head={b[:24].hex(' ')}")
            shown += 1


if __name__ == "__main__":
    main()
