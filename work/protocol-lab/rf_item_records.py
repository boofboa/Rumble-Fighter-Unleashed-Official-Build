"""Build the observed item-record table from official captures (PRIVATE output file).

For each catalog ID seen in any 30/85 inventory page: one exact observed 49-byte
record with the instance ID zeroed (the first instance seen), how many instances
and distinct record variants were observed, and every equipment slot (30/89 index)
an instance of that catalog occupied. Local grants copy such a record and assign a
local instance ID, so every granted record is an observed record for its catalog.

Usage: rf_item_records.py OUT.tsv CAPTURE...   (OUT must be under private/)
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
SLOTS = 45


def main() -> None:
    out = Path(sys.argv[1])
    records = {}
    instances = collections.defaultdict(set)
    variants = collections.defaultdict(set)
    slots = collections.defaultdict(set)
    sources = collections.defaultdict(set)
    for path in map(Path, sys.argv[2:]):
        frames = sequence(path.read_bytes())
        by_instance = {}
        for f in frames:
            if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0x85):
                body = f["body"]
                for n in range(struct.unpack_from("<H", body)[0]):
                    rec = bytearray(body[2 + n * RECORD:2 + (n + 1) * RECORD])
                    inst, cat = struct.unpack_from("<II", rec)
                    by_instance[inst] = cat
                    rec[0:4] = b"\0\0\0\0"
                    records.setdefault(cat, bytes(rec))
                    instances[cat].add((path.name, inst))
                    variants[cat].add(bytes(rec))
                    sources[cat].add(path.name)
        for f in frames:
            if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0x89):
                refs = struct.unpack_from("<45I", f["body"])
                for slot, inst in enumerate(refs):
                    if inst and inst in by_instance:
                        slots[by_instance[inst]].add(slot)
    with out.open("w", encoding="ascii", newline="\n") as handle:
        handle.write("# rf-item-records-v1: catalog\tword8\titem_end\tstat\tinstances\tvariants\tslots\trecord_hex(instance zeroed)\n")
        for cat in sorted(records):
            rec = records[cat]
            word8 = struct.unpack_from("<I", rec, 8)[0]
            end, stat = struct.unpack_from("<II", rec, 29)
            slot_text = ",".join(str(s) for s in sorted(slots[cat])) or "-"
            handle.write(f"{cat}\t{word8}\t{end}\t{stat}\t{len(instances[cat])}\t{len(variants[cat])}\t{slot_text}\t{rec.hex()}\n")
    by_prefix = collections.Counter(cat // 10000 for cat in records)
    equipped = sum(1 for c in records if slots[c])
    print(f"catalogs={len(records)} equipped-somewhere={equipped} -> {out}")
    print("catalog prefix (x10000) counts:", sorted(by_prefix.items()))
    slot_prefix = collections.defaultdict(collections.Counter)
    for cat, ss in slots.items():
        for s in ss:
            slot_prefix[s][cat // 10000] += 1
    for s in sorted(slot_prefix):
        print(f"  slot {s:2}: catalog prefixes {dict(slot_prefix[s])}")


if __name__ == "__main__":
    main()
