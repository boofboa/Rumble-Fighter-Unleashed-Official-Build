"""Supplementary aggregate facts for choosing a local class fixture (no IDs printed).

- How common each +8 value of class records is across all inventory records.
- Whether avatars share one class instance.
- Property request count vs. page counts (pagination rule).
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        inventory = {}
        pages = []
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                pages.append(count)
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inventory[struct.unpack_from("<I", rec)[0]] = rec
        requests = sum(1 for f in frames if key(f) == ("C", 0x30, 0x84))
        unk8 = collections.Counter(struct.unpack_from("<I", r, 8)[0] for r in inventory.values())
        slot0 = [struct.unpack_from("<I", f["body"])[0] for f in frames if key(f) == ("S", 0x30, 0x89)]
        print(f"== {path.name}: property requests={requests} page counts={pages}")
        print(f"   records with +8=20046: {unk8.get(20046, 0)}; +8=85593: {unk8.get(85593, 0)};"
              f" distinct +8 values={len(unk8)} of {len(inventory)} records")
        print(f"   avatars={len(slot0)} distinct slot-0 instances={len(set(slot0))}")


if __name__ == "__main__":
    main()
