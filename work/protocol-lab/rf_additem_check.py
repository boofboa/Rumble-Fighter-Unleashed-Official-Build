"""ADD_ITEM (31/8A) exchanges in official captures (PRIVATE output).

Request bodies in hex; failure 31/18B decoded as LE16 code + NUL-terminated
text; success 31/8B body in hex with its LE32 words related to the account,
inventory instances/catalog IDs and the request.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))["body"][:4]
        instances, catalogs = {}, {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                count = struct.unpack_from("<H", f["body"])[0]
                for n in range(count):
                    rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                    inst, cat = struct.unpack_from("<II", rec)
                    instances[inst] = cat
                    catalogs.setdefault(cat, inst)
        print(f"== {path.name}")
        for i, f in enumerate(frames):
            if key(f) != ("C", 0x31, 0x8A):
                continue
            body = f["body"]
            words = struct.unpack_from("<I", body)[0], struct.unpack_from("<I", body, 4)[0], body[8:].hex()
            print(f"  t={f['t']:.2f} request body={body.hex(' ')}  u32@0={words[0]} u32@4={words[1]} tail={words[2]}"
                  f"  u32@0 is catalog in inventory={words[0] in catalogs} u32@4 is catalog in inventory={words[1] in catalogs}")
            rep = next(g for g in frames[i + 1:] if g["dir"] == "S" and g["type"] == 0x31 and g["action"] in (0x8B, 0x18B))
            b = rep["body"]
            if rep["action"] == 0x18B:
                code = struct.unpack_from("<H", b)[0]
                text = b[2:].split(b"\0", 1)[0]
                print(f"     -> 31/18B code={code} text={text!r} tail_nonzero={sum(1 for x in b[2 + len(text):] if x)}")
            else:
                print(f"     -> 31/8B body={b.hex(' ')}")
                for off in range(0, len(b) - 3):
                    v = struct.unpack_from("<I", b, off)[0]
                    tags = []
                    if b[off:off + 4] == login: tags.append("account")
                    if v in instances: tags.append(f"instance(cat {instances[v]})")
                    if v in catalogs: tags.append("catalog")
                    if b[off:off + 4] == body[0:4]: tags.append("req@0")
                    if b[off:off + 4] == body[4:8]: tags.append("req@4")
                    if tags: print(f"        @{off}: {v} {tags}")
                later = [g for g in frames[i + 1:] if g["dir"] == "C"][:3]
                print("     next client requests:", [f"{g['type']:02x}/{g['action']:02x}" for g in later])


if __name__ == "__main__":
    main()
