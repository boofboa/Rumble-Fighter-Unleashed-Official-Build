"""Relate the 40/A6 body's LE32 value to IDs seen earlier in the same session.

Prints only which kind of earlier value it equals (and positions), never values.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    frames = sequence(Path(sys.argv[1]).read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    for i, f in enumerate(frames):
        if key(f) != ("C", 0x40, 0xA6):
            continue
        value = f["body"][:4]
        print(f"40/A6 at t={f['t']} body_len={len(f['body'])} trailing_byte={f['body'][4:].hex()}")
        before = frames[:i]
        login = next(g for g in before if key(g) == ("S", 0x10, 0x85))
        print("  equals login account id:", login["body"][:4] == value)
        avatars = next(g for g in before if key(g) == ("S", 0x30, 0x87))["body"]
        ids = [avatars[1 + 4 * n:5 + 4 * n] for n in range(avatars[0])]
        print("  in avatar list:", value in ids, "index:", ids.index(value) if value in ids else None)
        equipped = [g["body"][:4] for g in before if key(g) == ("S", 0x40, 0xA1)]
        print("  equals equipped avatar:", value in equipped)
        refs = set()
        for g in before:
            if key(g) == ("S", 0x30, 0x89):
                refs.update(g["body"][4 * n:4 * n + 4] for n in range(45))
        print("  in any equipment refs:", value in refs)
        for g in before:
            if g["dir"] == "S" and value in g["body"]:
                print(f"  appears in earlier server frame {g['type']:02x}/{g['action']:02x} t={g['t']} at offset {g['body'].find(value)}")
        a6_prior = [g for g in before if g["dir"] == "C" and value in g["body"]]
        for g in a6_prior[-5:]:
            print(f"  appears in earlier client frame {g['type']:02x}/{g['action']:02x} t={g['t']} offset {g['body'].find(value)}")
        after = [g for g in frames[i + 1:] if g["dir"] == "C"][:4]
        print("  following client requests:", [f"{g['type']:02x}/{g['action']:02x}" for g in after])
        for g in frames[i + 1:]:
            if g["dir"] == "C" and (g["type"], g["action"]) == (0x40, 0xA4):
                print("  next 40/A4 body contains value:", value in g["body"], "len", len(g["body"]))
                break


if __name__ == "__main__":
    main()
