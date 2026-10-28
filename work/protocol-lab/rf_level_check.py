"""Level/experience and level-reward evidence (PRIVATE output).

1. Login reply (10/85, 326 B): experience (frame 34), carats (38), medals (150) and the
   unresolved frame range 42..96 as LE32 words. GUID/token/name fields are NOT printed.
2. Inventory ownership of catalog 5023329 (the v1.20 GetLevelUpItem request) and of
   catalog IDs numerically near it; equipment references to them.
3. Every client 31/8A body kind (byte 0) seen in the captures.
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
LEVEL_ITEM = 5023329


def main() -> None:
    key = lambda f: (f["dir"], f["type"], f["action"])
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        print(f"== {path.name}")
        login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))
        frame = bytes([0, 0x10, 1, 0x46, 0x85, 0]) + login["body"]
        exp, carats = struct.unpack_from("<ii", frame, 34)
        medals, = struct.unpack_from("<i", frame, 150)
        region = [struct.unpack_from("<I", frame, o)[0] for o in range(42, 94, 4)]
        print(f"  login: experience={exp} carats={carats} medals={medals}")
        print(f"  login frame 42..93 as LE32: {region}")
        inv = {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inv[struct.unpack_from("<I", rec)[0]] = rec
        owned = collections.Counter(struct.unpack_from("<I", r, 4)[0] for r in inv.values())
        near = {c: n for c, n in owned.items() if 5023000 <= c <= 5023999}
        print(f"  owns {LEVEL_ITEM}: x{owned.get(LEVEL_ITEM, 0)}; catalogs 5023000-5023999 owned: {near}")
        for inst, rec in inv.items():
            if struct.unpack_from("<I", rec, 4)[0] == LEVEL_ITEM:
                print(f"    record: +8={struct.unpack_from('<I', rec, 8)[0]} end={struct.unpack_from('<I', rec, 29)[0]}"
                      f" stat={struct.unpack_from('<I', rec, 33)[0]} opaque_zero={rec[12:29] == bytes(17) and rec[37:49] == bytes(12)}")
        kinds = collections.Counter(f["body"][0] for f in frames if key(f) == ("C", 0x31, 0x8A))
        print(f"  31/8A body kinds: {dict(kinds)}")


if __name__ == "__main__":
    main()
