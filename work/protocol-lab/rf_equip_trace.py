"""Trace My Info equipment and user-info exchanges against inventory/equipment (PRIVATE output).

For each 30/D6, 40/A2, 40/A4, 40/A6 request: which LE32 values are inventory
instance IDs or catalog IDs, which avatar/slot they name, and the reply. Also
prints 30/81 (GET_USER_INFO reply) field matches against the account's known
values. Output contains instance/avatar IDs: write it only under private/.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49


def u32s(body: bytes, start: int = 0):
    return [struct.unpack_from("<I", body, o)[0] for o in range(start, len(body) - 3, 4)]


def main() -> None:
    frames = sequence(Path(sys.argv[1]).read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    inventory = {}
    by_catalog = {}
    avatars = []
    equipment = []
    for f in frames:
        if key(f) == ("S", 0x30, 0x85):
            body = f["body"]
            for n in range(struct.unpack_from("<H", body)[0]):
                rec = body[2 + n * RECORD:2 + (n + 1) * RECORD]
                inst, cat, unk8 = struct.unpack_from("<III", rec)
                end, stat = struct.unpack_from("<II", rec, 29)
                inventory[inst] = dict(cat=cat, unk8=unk8, end=end, stat=stat, raw=rec.hex())
                by_catalog.setdefault(cat, []).append(inst)
        if key(f) == ("S", 0x30, 0x87):
            avatars.append(f["body"].hex())
        if key(f) == ("C", 0x30, 0x88):
            equipment.append(("req", struct.unpack_from("<I", f["body"])[0]))
        if key(f) == ("S", 0x30, 0x89):
            equipment.append(("eq", u32s(f["body"][:180])))
    print(f"inventory records={len(inventory)}")
    print("avatar list 30/87:", avatars)
    for kind, value in equipment:
        if kind == "req":
            print(f"30/88 avatar={value}")
        else:
            named = [(i, v, inventory.get(v, {}).get("cat")) for i, v in enumerate(value) if v]
            print(f"   30/89 nonzero slots: {named}")

    def describe(value: int) -> str:
        if value in inventory:
            r = inventory[value]
            return f"{value}=INSTANCE(cat {r['cat']} +8 {r['unk8']} end {r['end']} stat {r['stat']})"
        if value in by_catalog:
            return f"{value}=CATALOG(instances {by_catalog[value]})"
        return str(value)

    for f in frames:
        k = key(f)
        if k in {("C", 0x30, 0xd6), ("S", 0x30, 0xd7), ("C", 0x40, 0xa2), ("C", 0x40, 0xa4),
                 ("C", 0x40, 0xa6), ("C", 0x30, 0x8e), ("S", 0x30, 0x8f), ("C", 0x31, 0x8e), ("S", 0x31, 0x8f)}:
            body = f["body"]
            vals = [describe(v) for v in u32s(body)]
            extra = ""
            if k in {("C", 0x40, 0xa4), ("C", 0x40, 0xa6)} and len(body) >= 9:
                avatar, slot = struct.unpack_from("<IB", body)
                extra = f" avatar={avatar} slot={slot} item={describe(struct.unpack_from('<I', body, 5)[0])}"
                if len(body) > 9:
                    extra += f" tail={body[9:].hex()}"
            print(f"{f['t']:9.3f} {f['dir']} {f['type']:02x}/{f['action']:02x} body={body.hex()} u32={vals}{extra}")
    for f in frames:
        if key(f) == ("S", 0x30, 0x81):
            body = f["body"]
            print(f"{f['t']:9.3f} S 30/81 len={len(body)}")
            for o in range(0, len(body), 32):
                print(f"   {o:05x}: {body[o:o + 32].hex(' ')}")
            hits = [(o, describe(v)) for o, v in ((o, struct.unpack_from('<I', body, o)[0]) for o in range(0, len(body) - 3))
                    if v in inventory or v in by_catalog]
            print("   inventory/catalog matches (offset, value):", hits[:80])
            break


if __name__ == "__main__":
    main()
