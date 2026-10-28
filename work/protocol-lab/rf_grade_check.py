"""Structure of 30/A0 -> 30/A1 (GET_GRADE in Gemnet naming) and 48/42 handling.

Prints lengths, candidate count fields and strides; record contents are shown
only as zero/non-zero masks. PRIVATE output (masks may still be distinctive).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from rf_sequence import sequence


def main() -> None:
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        key = lambda f: (f["dir"], f["type"], f["action"])
        print(f"== {path.name}")
        for i, f in enumerate(frames):
            if key(f) == ("C", 0x30, 0xA0):
                rep = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0xA1))
                b = rep["body"]
                u8, u16, u32 = b[0], struct.unpack_from("<H", b)[0], struct.unpack_from("<I", b)[0]
                cands = [s for s in range(2, 80) if u8 and (len(b) - 1) == u8 * s or u16 and (len(b) - 2) == u16 * s
                         or u32 and (len(b) - 4) == u32 * s]
                print(f"  30/A1 t={rep['t']:.1f} body={len(b)} u8={u8} u16={u16} u32={u32} exact strides={cands}")
                print(f"     first 48 mask: {''.join('1' if x else '0' for x in b[:48])}")
        gg = [f for f in frames if key(f) == ("C", 0x48, 0x42)]
        replies_48 = sorted({(g['type'], g['action']) for g in frames if g['dir'] == 'S' and g['type'] == 0x48})
        print(f"  48/42 requests={len(gg)} lens={sorted({len(f['body']) for f in gg})}; server 0x48 frames seen: {[f'{t:02x}/{a:02x}' for t, a in replies_48]}")
        for f in gg:
            nxt = next((g for g in frames if g['t'] > f['t']), None)
            print(f"     48/42 at t={f['t']:.1f}; next frame: {nxt['dir']} {nxt['type']:02x}/{nxt['action']:02x}" if nxt else "")


if __name__ == "__main__":
    main()
