"""Collect (level, experience) pairs from official captures (PRIVATE output).

Sources: own login replies 10/85 (+24 level, +28 exp, verified against 30/81) and
player records inside room pushes 0x240/0x10 and room info 0x240/0x89, located by the
player name (NUL-padded, 20 bytes) followed by the same level/exp layout candidates.
Prints numbers only (no names); used to bound, never invent, the experience table.
Usage: rf_level_pairs.py CAPTURE... [--probe]
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    probe = "--probe" in sys.argv
    pairs = []
    for path in [Path(a) for a in sys.argv[1:] if not a.startswith("--")]:
        for f in sequence(path.read_bytes()):
            k = (f["dir"], f["type"], f["action"])
            body = f["body"]
            if k == ("S", 0x10, 0x85):
                lvl, exp = struct.unpack_from("<II", body, 24)
                pairs.append((path.name, "login", lvl, exp))
            if k == ("S", 0x240, 0x89):
                # Anchored on the capture owner's own record (level 18 / exp 1763532 found at
                # class-slot offset - 66 / - 62 in both room-info replies).
                for o in range(66, len(body) - 3):
                    if 1000170 <= struct.unpack_from("<I", body, o)[0] <= 1000199:
                        lvl, exp = struct.unpack_from("<II", body, o - 66)
                        if 0 < lvl < 256:
                            pairs.append((path.name, "room_record", lvl, exp))
            if k in {("S", 0x240, 0x10), ("S", 0x240, 0x89)} and probe:
                # Layout probe: class catalogs 1000175..1000199 mark the 45-slot block.
                hits = [o for o in range(0, len(body) - 3) if 1000170 <= struct.unpack_from("<I", body, o)[0] <= 1000199]
                print(f"{path.name} {f['type']:x}/{f['action']:x} len={len(body)} class-catalog offsets={hits[:12]}")
                for o in hits[:3]:
                    print("   ", body[max(0, o - 48):o].hex(" "))
    if probe:
        # Own record: find the login's (level, exp) values inside room records.
        for path in [Path(a) for a in sys.argv[1:] if not a.startswith("--")]:
            frames = sequence(path.read_bytes())
            login = next((f["body"] for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x10, 0x85)), None)
            if login is None:
                continue
            lvl, exp = struct.unpack_from("<II", login, 24)
            for f in frames:
                if (f["dir"], f["type"], f["action"]) in {("S", 0x240, 0x89), ("S", 0x240, 0x10)}:
                    b = f["body"]
                    exp_at = [o for o in range(len(b) - 3) if struct.unpack_from("<I", b, o)[0] == exp]
                    print(f"{path.name} {f['type']:x}/{f['action']:x}: exp {exp} at {exp_at}; bytes before: " +
                          "; ".join(b[max(0, o - 12):o].hex(" ") for o in exp_at[:3]))
    for p in pairs:
        print(*p)


if __name__ == "__main__":
    main()
