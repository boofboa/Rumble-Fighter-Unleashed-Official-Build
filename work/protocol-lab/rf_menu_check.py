"""Main-menu entry exchanges in official captures (PRIVATE output: shows bytes).

For 30/B2 -> 30/B3 and 30/BA -> 30/BB (and 30/BC -> 30/BD for context): request
bodies, reply bodies, and which reply bytes equal login-reply fields, the
account ID, or each other across captures.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

PAIRS = [((0x30, 0xB2), (0x30, 0xB3)), ((0x30, 0xBA), (0x30, 0xBB)), ((0x30, 0xBC), (0x30, 0xBD))]


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))["body"]
        account = login[:4]
        print(f"== {path.name}")
        for req_k, rep_k in PAIRS:
            for i, f in enumerate(frames):
                if key(f) != ("C",) + req_k:
                    continue
                rep = next((g for g in frames[i + 1:] if key(g) == ("S",) + rep_k), None)
                if rep is None:
                    continue
                b = rep["body"]
                notes = []
                if account in b:
                    notes.append(f"account@{b.find(account)}")
                for off in range(0, len(b) - 7):
                    chunk = b[off:off + 8]
                    if chunk != bytes(8) and chunk in login:
                        notes.append(f"login8@{off}->login@{login.find(chunk)}")
                        break
                print(f"  {req_k[0]:02x}/{req_k[1]:02x} t={f['t']:.1f} req={f['body'].hex()} -> "
                      f"{rep_k[0]:02x}/{rep_k[1]:02x} body({len(b)})={b.hex(' ')} {notes}")
                break


if __name__ == "__main__":
    main()
