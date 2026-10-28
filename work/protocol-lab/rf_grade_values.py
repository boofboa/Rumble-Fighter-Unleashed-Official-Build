"""Per-ID grade record values across captures (PRIVATE output: game counters).

For selected IDs prints (a, b, c) LE32 values per capture and per reply, to tell
fixed initial values from per-account progress.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

STRIDE = 13


def main() -> None:
    wanted = [int(x) for x in sys.argv[1].split(",")]
    for path in map(Path, sys.argv[2:]):
        frames = sequence(path.read_bytes())
        print(f"== {path.name}")
        for k, f in enumerate(f for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0xA1)):
            b = f["body"]
            values = {}
            for n in range(b[0]):
                rec = b[1 + n * STRIDE:1 + (n + 1) * STRIDE]
                values[rec[0]] = struct.unpack_from("<III", rec, 1)
            print(f"   reply {k} t={f['t']:.0f}: " + "  ".join(f"{i}={values.get(i)}" for i in wanted))


if __name__ == "__main__":
    main()
