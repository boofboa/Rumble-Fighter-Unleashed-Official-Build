"""Among records sharing a (+8, end, stat) profile, how many have all-zero opaque
regions? Prints counts and catalog IDs (public item numbers) only.
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_opaque_check import records


def main() -> None:
    want = (int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    zero, nonzero = collections.Counter(), collections.Counter()
    for path in map(Path, sys.argv[4:]):
        for rec in records(path).values():
            catalog, word8 = struct.unpack_from("<II", rec, 4)
            end, stat = struct.unpack_from("<II", rec, 29)
            if (word8, end, stat) != want:
                continue
            target = zero if rec[12:29] == bytes(17) and rec[37:49] == bytes(12) else nonzero
            target[catalog] += 1
    print(f"profile {want}: all-zero opaque records={sum(zero.values())} (catalogs {dict(zero.most_common(8))})")
    print(f"                 non-zero opaque records={sum(nonzero.values())} (catalogs {dict(nonzero.most_common(8))})")


if __name__ == "__main__":
    main()
