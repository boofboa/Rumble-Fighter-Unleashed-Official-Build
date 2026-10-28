"""Structural check of avatar enumeration (30/86 -> 30/87), equipped avatar
(40/A0 -> 40/A1) and per-avatar equipment (30/88 -> 30/89) in official captures.

Prints relationships (equalities, counts, offsets) and never prints IDs.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def pairs(frames, request, reply):
    out = []
    for i, f in enumerate(frames):
        if f["dir"] == "C" and (f["type"], f["action"]) == request:
            r = next((g for g in frames[i + 1:] if g["dir"] == "S" and (g["type"], g["action"]) == reply), None)
            out.append((f, r))
    return out


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        login = next(f for f in frames if f["dir"] == "S" and (f["type"], f["action"]) == (0x10, 0x85))
        account = login["body"][0:4]
        print(f"== {path.name}")
        (req, rep), = pairs(frames, (0x30, 0x86), (0x30, 0x87))
        body = rep["body"]
        count = body[0]
        ids = [body[1 + 4 * n:5 + 4 * n] for n in range(20)]
        print(f"30/86 req body len={len(req['body'])} equals login account id={req['body'] == account}")
        print(f"30/87 body len={len(body)} count={count} slots=(81-1)/4={(len(body) - 1) / 4}"
              f" active nonzero={all(x != bytes(4) for x in ids[:count])}"
              f" unused zero={[x == bytes(4) for x in ids[count:]].count(True)}/{20 - count}")
        (req, rep), = pairs(frames, (0x40, 0xA0), (0x40, 0xA1))
        print(f"40/A0 req body len={len(req['body'])}; 40/A1 body len={len(rep['body'])}"
              f" equipped in active ids={rep['body'][:4] in ids[:count]}"
              f" index={ids.index(rep['body'][:4]) if rep['body'][:4] in ids else None}")
        eq = pairs(frames, (0x30, 0x88), (0x30, 0x89))
        req_ids = [r["body"][:4] for r, _ in eq]
        print(f"30/88 count={len(eq)} req ids == active ids in order: {req_ids == ids[:count]}"
              f" reply lens={sorted({x['total'] for _, x in eq})}")
        for r, x in eq[:1]:
            b = x["body"]
            refs = struct.unpack_from("<45I", b, 0)
            print(f"  first 30/89: body len={len(b)} nonzero refs={sum(1 for v in refs if v)}"
                  f" tail nonzero bytes={sum(1 for v in b[180:] if v)} first4 equals avatar id={b[:4] == r['body'][:4]}")
        nxt = [f for f in frames if f["dir"] == "C" and f["t"] > eq[-1][1]["t"]][:3]
        print("  next client requests:", [f"{f['type']:02x}/{f['action']:02x}({f['total']})" for f in nxt])


if __name__ == "__main__":
    main()
