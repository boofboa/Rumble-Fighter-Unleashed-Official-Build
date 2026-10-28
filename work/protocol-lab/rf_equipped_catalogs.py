"""Catalog IDs worn by any player in official captures (room records 0x240/0x89, joins
0x240/0x10, user info 30/81): the 45-slot CATALOG blocks. Prints catalog, slot, count
(numbers only; no names). Usage: rf_equipped_catalogs.py OUT.tsv CAPTURE...
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def slot_blocks(body: bytes):
    # A block starts at a class catalog (1000170..1000199) and holds 45 LE32 catalogs.
    for o in range(0, len(body) - 180 + 1):
        first = struct.unpack_from("<I", body, o)[0]
        if 1000170 <= first <= 1000199:
            yield struct.unpack_from("<45I", body, o)


def main() -> None:
    seen = collections.Counter()
    slots = collections.defaultdict(set)
    for path in map(Path, sys.argv[2:]):
        for f in sequence(path.read_bytes()):
            if f["dir"] != "S" or (f["type"], f["action"]) not in {(0x240, 0x89), (0x240, 0x10), (0x30, 0x81)}:
                continue
            for block in slot_blocks(f["body"]):
                for slot, cat in enumerate(block):
                    if 1000000 <= cat <= 9999999:
                        seen[cat] += 1
                        slots[cat].add(slot)
    with open(sys.argv[1], "w", encoding="ascii", newline="\n") as out:
        out.write("# rf-equipped-catalogs-v1: catalog\tslots\tsightings\n")
        for cat in sorted(seen):
            out.write(f"{cat}\t{','.join(map(str, sorted(slots[cat])))}\t{seen[cat]}\n")
    print(f"{len(seen)} distinct worn catalogs -> {sys.argv[1]}")


if __name__ == "__main__":
    main()
