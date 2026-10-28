"""List entries of the client's res/*.nsz archives (metadata only; no contents extracted).

Observed layout: ZIP local file headers with the "PK\\3\\4" magic replaced by "NSZ!".
Prints per entry: archive, name, flags, method, sizes, extra-field IDs, so table files
can be located. Usage: rf_nsz_list.py RES_DIR [NAME_REGEX]
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

MAGIC = b"NSZ!"


def entries(data: bytes):
    at = 0
    while True:
        at = data.find(MAGIC, at)
        if at < 0 or at + 30 > len(data):
            return
        ver, flags, method, mtime, mdate, crc, csize, usize, nlen, xlen = struct.unpack_from("<HHHHHIIIHH", data, at + 4)
        if nlen == 0 or nlen > 260 or at + 30 + nlen + xlen > len(data):
            at += 4
            continue
        name = data[at + 30:at + 30 + nlen].decode("latin-1")
        extra = data[at + 30 + nlen:at + 30 + nlen + xlen]
        ids, x = [], 0
        while x + 4 <= len(extra):
            fid, flen = struct.unpack_from("<HH", extra, x)
            ids.append(f"{fid:#06x}:{flen}")
            x += 4 + flen
        yield dict(offset=at, name=name, flags=flags, method=method, csize=csize, usize=usize, extra=",".join(ids))
        at += 30 + nlen + xlen + (csize if csize else 0)


def main() -> None:
    pattern = re.compile(sys.argv[2], re.I) if len(sys.argv) > 2 else None
    for path in sorted(Path(sys.argv[1]).glob("*.nsz")):
        data = path.read_bytes()
        if not data.startswith(MAGIC):
            print(f"{path.name}: no NSZ! header (first bytes {data[:8].hex()}) size={len(data)}")
            continue
        for e in entries(data):
            if pattern is None or pattern.search(e["name"]) or pattern.search(path.name):
                print(f"{path.name}\t{e['name']}\tflags={e['flags']:#06x}\tmethod={e['method']}\tc={e['csize']}\tu={e['usize']}\textra={e['extra']}")


if __name__ == "__main__":
    main()
