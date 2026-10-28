"""Inventory/equipment reference consistency across official captures.

Inventory (30/85): LE16 count at body 0, then 49-byte records from body 2
(+0 instance LE32, +4 catalog LE32, +8 unknown LE32, +12..28 opaque,
+29 item_end LE32, +33 stat LE32, +37..48 opaque) - Gemnet-derived layout.
Equipment (30/89): 45 LE32 instance references + 180-byte tail.

Prints aggregate facts. Catalog IDs of class items (public item numbers) and
the +8/+29/+33 integers of class records are printed; instance IDs, account
and avatar IDs are not. Opaque regions are shown only as zero/non-zero masks.
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49


def main() -> None:
    total_eq = slot0_nonzero = slot0_resolves = only_slot0 = all_refs_resolve = 0
    class_catalogs = collections.Counter()
    record_profiles = collections.Counter()
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        inventory = {}
        for f in frames:
            if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0x85):
                body = f["body"]
                count = struct.unpack_from("<H", body)[0]
                for n in range(count):
                    rec = body[2 + n * RECORD:2 + (n + 1) * RECORD]
                    inventory[struct.unpack_from("<I", rec)[0]] = rec
        file_eq = 0
        for f in frames:
            if (f["dir"], f["type"], f["action"]) != ("S", 0x30, 0x89):
                continue
            file_eq += 1
            refs = struct.unpack_from("<45I", f["body"])
            total_eq += 1
            nonzero = [i for i, r in enumerate(refs) if r]
            slot0_nonzero += refs[0] != 0
            if refs[0] in inventory:
                slot0_resolves += 1
                rec = inventory[refs[0]]
                catalog, unk8 = struct.unpack_from("<II", rec, 4)
                end, stat = struct.unpack_from("<II", rec, 29)
                class_catalogs[catalog] += 1
                mask = lambda a, b: "".join("1" if x else "0" for x in rec[a:b])
                record_profiles[(catalog, unk8, end, stat, mask(12, 29), mask(37, 49))] += 1
            only_slot0 += nonzero == [0]
            all_refs_resolve += all(refs[i] in inventory for i in nonzero)
        print(f"{path.name}: inventory instances={len(inventory)} equipment replies={file_eq}")
    print(f"equipment replies={total_eq} slot0 nonzero={slot0_nonzero} slot0 resolves to inventory={slot0_resolves}"
          f" only slot0 populated={only_slot0} all nonzero refs resolve={all_refs_resolve}")
    print("slot-0 catalog IDs (count of avatars):", dict(class_catalogs))
    print("class record profiles: (catalog, +8, end, stat, mask+12..28, mask+37..48) -> avatars")
    for key, n in record_profiles.items():
        print("  ", key, n)


if __name__ == "__main__":
    main()
