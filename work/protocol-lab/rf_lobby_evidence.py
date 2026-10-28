"""Lobby evidence (PRIVATE output: may show IDs; never prints names).

1. The successful 95 claim reply (31/8B) decoded as LE32 words; whether those
   words appear as instance/catalog IDs in any session's inventory.
2. Room list 40/85: header fields (body 0..11) and per-record room numbers,
   so header semantics can be related to the records. Names are not printed.
3. Client requests after the first 40/84 (lobby entry), per capture.
4. Server frames that do not answer a client request (unsolicited pushes).
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

from rf_sequence import sequence

RECORD = 49
ROOM = 223


def inventory(frames):
    inv = {}
    for f in frames:
        if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0x85):
            count = struct.unpack_from("<H", f["body"])[0]
            for n in range(count):
                rec = f["body"][2 + n * RECORD:2 + (n + 1) * RECORD]
                inv[struct.unpack_from("<I", rec)[0]] = struct.unpack_from("<I", rec, 4)[0]
    return inv


def main() -> None:
    caps = {Path(p).name: sequence(Path(p).read_bytes()) for p in sys.argv[1:]}
    key = lambda f: (f["dir"], f["type"], f["action"])
    print("== 1. 95-claim success reply")
    for name, frames in caps.items():
        for f in frames:
            if key(f) == ("S", 0x31, 0x8B):
                b = f["body"]
                words = [struct.unpack_from("<I", b, 2 + 4 * k)[0] for k in range(10)]
                print(f"  {name}: prefix={b[:2].hex()} words@2..={words}")
                for other, fr in caps.items():
                    inv = inventory(fr)
                    cats = set(inv.values())
                    hits = [(k, w) for k, w in enumerate(words) if w and (w in inv or w in cats)]
                    print(f"     words found in {other} inventory (index, value, as): "
                          f"{[(k, w, 'instance' if w in inv else 'catalog') for k, w in hits]}")
    print("== 2. room list header vs records")
    for name, frames in caps.items():
        seen = set()
        for f in frames:
            if key(f) != ("S", 0x40, 0x85) or f["body"] in seen:
                continue
            seen.add(f["body"])
            b = f["body"]
            h = struct.unpack_from("<HHHHI", b)
            n = h[4]
            rooms = [struct.unpack_from("<HH", b, 12 + ROOM * k) for k in range(n)]
            ok = len(b) == 12 + ROOM * n
            print(f"  {name}: len={len(b)} fits={ok} header u16s={[hex(x) for x in h[:4]]} count={n} "
                  f"record u16@0,u16@2={rooms}")
    print("== 3. client requests after lobby entry (first 40/84)")
    for name, frames in caps.items():
        start = next((f["t"] for f in frames if key(f) == ("C", 0x40, 0x84)), None)
        if start is None:
            continue
        c = collections.Counter(f"{f['type']:02x}/{f['action']:02x}" for f in frames if f["dir"] == "C" and f["t"] >= start)
        dur = max(f["t"] for f in frames) - start
        print(f"  {name}: lobby span {dur:.0f}s requests={dict(c)}")
    print("== 4. unsolicited server frames (not preceded by an unanswered client request)")
    for name, frames in caps.items():
        pending = 0
        pushes = collections.Counter()
        for f in frames:
            if f["dir"] == "C":
                pending += 1
            elif pending > 0:
                pending -= 1
            else:
                pushes[f"{f['type']:03x}/{f['action']:02x}"] += 1
        print(f"  {name}: {dict(pushes)}")


if __name__ == "__main__":
    main()
