"""Compare the only captured ADD_ITEM success (31/8B) with inventory records of the
same catalog in other sessions, byte by byte (PRIVATE output)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    key = lambda f: (f["dir"], f["type"], f["action"])
    caps = {Path(p).name: sequence(Path(p).read_bytes()) for p in sys.argv[1:]}
    success = next(f["body"] for fr in caps.values() for f in fr if key(f) == ("S", 0x31, 0x8B))
    print("31/8B body (47):", success.hex(" "))
    print("  as offsets: [0..1]", success[:2].hex(), " then LE32 at 2,6,10,14,18,22:",
          [struct.unpack_from("<I", success, o)[0] for o in (2, 6, 10, 14, 18, 22)])
    for name, frames in caps.items():
        for f in frames:
            if key(f) != ("S", 0x30, 0x85):
                continue
            count = struct.unpack_from("<H", f["body"])[0]
            for n in range(count):
                rec = f["body"][2 + n * 49:2 + (n + 1) * 49]
                if struct.unpack_from("<I", rec, 4)[0] == 3043117:
                    print(f"{name} 3043117 record (49): {rec.hex(' ')}")
        login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))["body"]
        print(f"{name} login body[36..90]: {login[36:91].hex(' ')}")


if __name__ == "__main__":
    main()
