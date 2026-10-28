"""Inventory pagination facts: 30/84 request bodies vs 30/85 page counts (PRIVATE output).

Request bodies begin with the account ID (not printed); the remaining seven
bytes and each page's count/first-record position are printed.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
PAGE = 80


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        print("==", path.name)
        last = None
        for f in sequence(path.read_bytes()):
            k = (f["dir"], f["type"], f["action"])
            body = f["body"]
            if k == ("C", 0x30, 0x84):
                cursor = struct.unpack_from("<I", body, 7)[0]
                rel = "first" if last is None else f"cursor-last={cursor - last}"
                print(f"  {f['t']:8.3f} C 30/84 len={len(body)} sep={body[4:7].hex()} {rel}")
            elif k == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", body)[0]
                insts = [struct.unpack_from("<I", body, 2 + RECORD * n)[0] for n in range(count)]
                ascending = all(a < b for a, b in zip(insts, insts[1:]))
                last = insts[-1] if insts else last
                print(f"  {f['t']:8.3f} S 30/85 count={count} len={len(body)} ascending={ascending}"
                      f" unused-records-zero={not any(body[2 + RECORD * count:])}")


if __name__ == "__main__":
    main()
