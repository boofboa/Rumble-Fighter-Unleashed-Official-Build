"""Map 30/81 (GET_USER_INFO reply) fields against the same session's own records (PRIVATE output).

Compares every LE32/LE16 value of the first 30/81 body with: the login reply
10/85 (numeric fields only; GUID/token text ranges are skipped), the cash
reply 31/89, the current avatar's 30/89 equipment (refs and 180-byte tail),
the grade list 30/A1 and the room-player pushes 0x240/0x10. Prints offsets
and values that match. Write output only under private/.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence

LOGIN_TEXT_RANGES = [(4, 28), (91, 128), (152, 192), (192, 256), (256, 320)]  # body offsets (name/guid/region/token/name)


def le32_map(body: bytes, skip=()):
    out = {}
    for o in range(0, len(body) - 3):
        if any(a <= o < b for a, b in skip):
            continue
        v = struct.unpack_from("<I", body, o)[0]
        if v > 1:
            out.setdefault(v, []).append(o)
    return out


def main() -> None:
    frames = sequence(Path(sys.argv[1]).read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    get = lambda k: [f["body"] for f in frames if key(f) == k]
    info = get(("S", 0x30, 0x81))[0]
    login = get(("S", 0x10, 0x85))[0]
    cash = get(("S", 0x31, 0x89))
    pushes = get(("S", 0x240, 0x10))
    print(f"30/81 body={len(info)} login body={len(login)} pushes={[len(p) for p in pushes]}")
    nonzero = [(o, info[o]) for o in range(len(info)) if info[o] and not 4 <= o < 24]
    print("30/81 nonzero byte offsets outside name:", [o for o, _ in nonzero if o >= 212])
    sources = {"login10/85": le32_map(login, LOGIN_TEXT_RANGES)}
    for i, c in enumerate(cash[:1]):
        sources["cash31/89"] = le32_map(c)
    for name, m in sources.items():
        for o in list(range(0, 4)) + list(range(24, 32)) + [o for o, _ in nonzero if o >= 212 and o % 1 == 0]:
            v = struct.unpack_from("<I", info, o)[0] if o + 4 <= len(info) else 0
            if v > 1 and v in m:
                print(f"  30/81+{o} = {v} ({v:#x}) found in {name} at {m[v][:6]}")
    print("30/81 tail fields (offset: u32 / u16 pair / bytes):")
    for o in sorted({o - o % 4 for o, _ in nonzero if o >= 212}):
        w = info[o:o + 4]
        print(f"  +{o} ({o:#x}): u32={struct.unpack_from('<I', w)[0]} u16={struct.unpack_from('<HH', w)} raw={w.hex()}")
    # The same player's record inside a 0x240/0x10 push (room member join): find the name.
    name = info[4:24].split(b"\0")[0]
    for p in pushes:
        at = p.find(name + b"\0")
        print(f"  push len={len(p)} own-name at {at}")


if __name__ == "__main__":
    main()
