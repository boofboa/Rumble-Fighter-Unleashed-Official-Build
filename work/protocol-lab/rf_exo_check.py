"""Per session: is each in-use class's default Exo owned and equipped?

Default Exo per class is from the checkpoint's public-source table
(item-catalog-findings.json). Equipment slot order is Gemnet's (slot 0 Job,
slot 11 ExoA, slot 12 ExoB). Prints catalog numbers and counts only.
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
DEFAULT_EXO = {1000175: 2040034, 1000176: 2040035, 1000177: 2040037, 1000178: 2040038,
               1000247: 2040034, 1000248: 2040035, 1000249: 2040037, 1000250: 2040038,
               1001792: 2040086, 1001793: 2040086}


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        inv = {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inv[struct.unpack_from("<I", rec)[0]] = rec
        catalog = {i: struct.unpack_from("<I", r, 4)[0] for i, r in inv.items()}
        owned = collections.Counter(catalog.values())
        equipments = [struct.unpack_from("<45I", f["body"]) for f in frames if key(f) == ("S", 0x30, 0x89)]
        classes = collections.Counter(catalog[e[0]] for e in equipments)
        print(f"== {path.name}: avatars={len(equipments)} classes in slot 0={dict(classes)}")
        for cls in classes:
            exo = DEFAULT_EXO.get(cls)
            exo_instances = [i for i, c in catalog.items() if c == exo]
            exoa = sum(1 for e in equipments if e[0] in catalog and catalog[e[0]] == cls and e[11] in exo_instances)
            print(f"   class {cls}: default Exo {exo} owned x{owned.get(exo, 0)};"
                  f" avatars of this class with that Exo in slot 11 (ExoA): {exoa}/{classes[cls]}")
            for inst in exo_instances:
                r = inv[inst]
                word8, = struct.unpack_from("<I", r, 8)
                end, stat = struct.unpack_from("<II", r, 29)
                print(f"     exo record: +8={word8} end={end} stat={stat} opaque_zero={r[12:29] == bytes(17) and r[37:49] == bytes(12)}")
        slot_use = collections.Counter(i for e in equipments for i, v in enumerate(e) if v)
        print(f"   equipment slots in use (slot: avatars): {dict(sorted(slot_use.items()))}")


if __name__ == "__main__":
    main()
