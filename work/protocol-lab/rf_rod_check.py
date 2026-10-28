"""Does every official inventory hold a Fishing Rod (catalog 5135224), and what
record profiles do rods have? Also: is a rod referenced by any equipment slot?

Prints catalog-level facts and (+8, end, stat, opaque-zero) profiles only.
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
ROD = 5135224


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        inventory = {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inventory[struct.unpack_from("<I", rec)[0]] = rec
        rods = [r for r in inventory.values() if struct.unpack_from("<I", r, 4)[0] == ROD]
        profiles = collections.Counter()
        for r in rods:
            word8, = struct.unpack_from("<I", r, 8)
            end, stat = struct.unpack_from("<II", r, 29)
            profiles[(word8, end, stat, r[12:29] == bytes(17), r[37:49] == bytes(12))] += 1
        refs = set()
        slots_with_rod = collections.Counter()
        for f in frames:
            if key(f) == ("S", 0x30, 0x89):
                for slot, ref in enumerate(struct.unpack_from("<45I", f["body"])):
                    if ref and ref in inventory and struct.unpack_from("<I", inventory[ref], 4)[0] == ROD:
                        slots_with_rod[slot] += 1
        c6 = sum(1 for f in frames if key(f) == ("C", 0x31, 0xC6))
        print(f"== {path.name}: rods={len(rods)} sent 31/C6={c6}")
        print("   rod profiles (+8, end, stat, +12..28 zero, +37..48 zero):", dict(profiles))
        print("   equipment slots referencing a rod:", dict(slots_with_rod))


if __name__ == "__main__":
    main()
