"""Follow-ups (PRIVATE output; no names printed).

1. Record profiles of catalog 3043117 (the 95-claim reward) and whether equipped.
2. Room list 40/85 with a 10-byte header: u16 fields, u16 count, and each record's
   room number, to relate header fields to records.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD, ROOM, REWARD = 49, 223, 3043117


def main() -> None:
    key = lambda f: (f["dir"], f["type"], f["action"])
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        print(f"== {path.name}")
        inv = {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inv[struct.unpack_from("<I", rec)[0]] = rec
        refs = {r for f in frames if key(f) == ("S", 0x30, 0x89) for r in struct.unpack_from("<45I", f["body"])}
        for inst, rec in inv.items():
            if struct.unpack_from("<I", rec, 4)[0] == REWARD:
                print(f"  reward record: +8={struct.unpack_from('<I', rec, 8)[0]} end={struct.unpack_from('<I', rec, 29)[0]}"
                      f" stat={struct.unpack_from('<I', rec, 33)[0]} opaque_zero={rec[12:29] == bytes(17) and rec[37:49] == bytes(12)}"
                      f" equipped={inst in refs}")
        seen = set()
        for i, f in enumerate(frames):
            if key(f) != ("S", 0x40, 0x85) or f["body"] in seen:
                continue
            seen.add(f["body"])
            b = f["body"]
            h = struct.unpack_from("<HHHHH", b)
            n = h[4]
            fits = len(b) == 10 + ROOM * n
            nums = [struct.unpack_from("<HH", b, 10 + ROOM * k) for k in range(n)]
            print(f"  40/85 len={len(b)} fits10={fits} header={[hex(x) for x in h[:4]]} count={n} record(u16@0,u16@2)={nums}")


if __name__ == "__main__":
    main()
