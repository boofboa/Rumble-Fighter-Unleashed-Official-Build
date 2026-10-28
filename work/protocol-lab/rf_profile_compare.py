"""Reconstruct the session-start character profile from ONE capture and compare
profile invariants across sessions and against the local minimal profile.

Profile = inventory pages (30/85), avatar list (30/87), equipped avatar (40/A1),
per-avatar equipment (30/89) and the FIRST grade list (30/A1) of that session.
Login reply, tokens, account fields and every other frame are NOT extracted.

--extract CAPTURE OUT.json writes the private profile (raw record bytes as hex).
Without --extract, prints a metadata-only invariant table (no IDs).
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from rf_sequence import sequence
from lobby_wire import (CLASS_FIXTURE_RECORD, EXO_FIXTURE_RECORD, LOCAL_GRADE_IDS, ROD_FIXTURE_RECORD)

RECORD = 49
ROD = 5135224
DEFAULT_EXO = {1000175: 2040034, 1000176: 2040035, 1000177: 2040037, 1000178: 2040038,
               1000247: 2040034, 1000248: 2040035, 1000249: 2040037, 1000250: 2040038,
               1001792: 2040086, 1001793: 2040086}
CHECKED_CHANNELS = {90, 100, 30, 31, 32, 33, 34, 93, 95, 96, 94}   # v1.15/v1.16 game logs
COMMON_CHANNELS = {1, 2, 3, 5, 10, 11, 12, 30, 31, 32, 33, 34, 35, 50, 55, 56, 80, 81, 90, 93, 94,
                   95, 96, 99, 100, 108, 109, 121, 122, 123}


def extract(path: Path) -> dict:
    frames = sequence(path.read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    first = lambda k: next(f for f in frames if key(f) == k)["body"]
    records = []
    for f in frames:
        if key(f) == ("S", 0x30, 0x85):
            count = struct.unpack_from("<H", f["body"])[0]
            records += [f["body"][2 + n * RECORD:2 + (n + 1) * RECORD] for n in range(count)]
    avatar_body = first(("S", 0x30, 0x87))
    avatars = list(struct.unpack_from("<20I", avatar_body, 1)[:avatar_body[0]])
    equipment = {}
    for i, f in enumerate(frames):
        if key(f) == ("C", 0x30, 0x88):
            rep = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0x89))
            equipment[struct.unpack("<I", f["body"])[0]] = list(struct.unpack_from("<45I", rep["body"]))
    grade = first(("S", 0x30, 0xA1))
    return dict(
        source=path.name,
        inventory=[dict(instance=struct.unpack_from("<I", r)[0], catalog=struct.unpack_from("<I", r, 4)[0],
                        word8=struct.unpack_from("<I", r, 8)[0], item_end=struct.unpack_from("<I", r, 29)[0],
                        stat=struct.unpack_from("<I", r, 33)[0], raw=r.hex()) for r in records],
        avatars=avatars,
        equipped=struct.unpack("<I", first(("S", 0x40, 0xA1)))[0],
        equipment={str(k): v for k, v in equipment.items()},
        grade=[dict(id=grade[1 + 13 * n], values=list(struct.unpack_from("<III", grade, 2 + 13 * n)))
               for n in range(grade[0])],
        unresolved=["inventory +8 (category-like code), +12..28 and +37..48 opaque, item_end meaning",
                    "equipment 180-byte tail (zero in every capture)",
                    "grade value fields a, b, c (live counters)",
                    "server-side state not in these frames (guild, buddies, gifts, cash, B4 boss data)"])


def minimal(with_exo: bool) -> dict:
    cls, rod = CLASS_FIXTURE_RECORD, ROD_FIXTURE_RECORD
    records = (cls, rod, EXO_FIXTURE_RECORD) if with_exo else (cls, rod)
    return dict(
        source="local v1.18" if with_exo else "local v1.17",
        inventory=[dict(instance=r[0], catalog=r[1], word8=r[2], item_end=r[3], stat=r[4]) for r in records],
        avatars=[1], equipped=1, equipment={"1": [cls[0]] + [0] * 44},
        grade=[dict(id=i, values=[0, 0, 2] if i == 95 else [0, 0, 0]) for i in LOCAL_GRADE_IDS])


def invariants(p: dict) -> dict:
    catalog = {r["instance"]: r["catalog"] for r in p["inventory"]}
    owned = [r["catalog"] for r in p["inventory"]]
    eq = p["equipment"]
    classes = {catalog.get(v[0]) for v in eq.values()}
    grade_ids = {g["id"] for g in p["grade"]}
    return {
        "all avatars have slot0 -> owned class": all(v[0] in catalog and 1000000 <= catalog[v[0]] < 1010000 for v in eq.values()),
        "all equipment refs resolve": all(x in catalog for v in eq.values() for x in v if x),
        "equipped avatar is listed": p["equipped"] in p["avatars"],
        "equipment requested for every avatar": sorted(map(int, eq)) == sorted(p["avatars"]),
        "exactly one fishing rod owned": owned.count(ROD) == 1,
        "each in-use class owns its default Exo": all(DEFAULT_EXO.get(c) in owned for c in classes),
        "grade has every client-checked channel": CHECKED_CHANNELS <= grade_ids,
        "grade has all 30 common channels": COMMON_CHANNELS <= grade_ids,
        "avatar count": len(p["avatars"]),
        "inventory items": len(p["inventory"]),
        "distinct catalog items": len(set(owned)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="*", type=Path)
    parser.add_argument("--extract", nargs=2, metavar=("CAPTURE", "OUT"), type=Path)
    args = parser.parse_args()
    if args.extract:
        profile = extract(args.extract[0])
        args.extract[1].write_text(json.dumps(profile, indent=1), encoding="utf-8")
        print(f"wrote private profile from {args.extract[0].name}: {len(profile['inventory'])} items, "
              f"{len(profile['avatars'])} avatars, {len(profile['grade'])} grade records")
        return
    profiles = [extract(p) for p in args.captures] + [minimal(False), minimal(True)]
    table = [(p["source"], invariants(p)) for p in profiles]
    names = list(table[0][1])
    print(f"{'invariant':45}" + "".join(f"{s[:18]:>20}" for s, _ in table))
    for n in names:
        print(f"{n:45}" + "".join(f"{str(inv[n]):>20}" for _, inv in table))


if __name__ == "__main__":
    main()
