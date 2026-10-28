"""30/B4 (body 4) -> 30/B5 (body 19): relate request/reply fields. Facts only."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))
        avatars = next(f for f in frames if key(f) == ("S", 0x30, 0x87))["body"]
        ids = [avatars[1 + 4 * n:5 + 4 * n] for n in range(avatars[0])]
        print(f"== {path.name}")
        for i, f in enumerate(frames):
            if key(f) != ("C", 0x30, 0xB4):
                continue
            rep = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0xB5))
            req, b = f["body"], rep["body"]
            print(f"  req u32={struct.unpack('<I', req)[0]} is_account={req == login['body'][:4]} is_avatar={req in ids}"
                  f" | reply len={len(b)} echoes_req_at={b.find(req)} mask={''.join('1' if x else '0' for x in b)}")


if __name__ == "__main__":
    main()
