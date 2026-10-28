"""Build the private main-menu fixture from ONE official session (rf-boss-baseline).

Extracts the exact plaintext server frames answering the client's first
30/B2, 30/BA and 30/BC, and the five 30/CC -> 30/CD pages (keyed by the 8-byte
request body). These are game/global data frames; no login reply, token or
account field is included. Output is written under private/ only.

File format (all little-endian):
  magic b"RFLF1\\0", u16 entry count, then per entry:
  u8 kind (1 = B3 reply, 2 = BB reply, 3 = BD reply, 4 = CD reply),
  u8 request-body length, request body, u16 frame length, frame (header included).
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from protocol_probe import encode_frame
from rf_sequence import sequence

KINDS = {(0x30, 0xB2): (1, (0x30, 0xB3)), (0x30, 0xBA): (2, (0x30, 0xBB)), (0x30, 0xBC): (3, (0x30, 0xBD))}


def build(capture: Path) -> bytes:
    frames = sequence(capture.read_bytes())
    key = lambda f: (f["dir"], f["type"], f["action"])
    entries, seen = [], set()
    for i, f in enumerate(frames):
        if f["dir"] != "C":
            continue
        k = (f["type"], f["action"])
        if k in KINDS and k not in seen:
            kind, reply_key = KINDS[k]
            rep = next(g for g in frames[i + 1:] if key(g) == ("S",) + reply_key)
            entries.append((kind, b"", encode_frame(*reply_key, rep["body"])))
            seen.add(k)
        elif k == (0x30, 0xCC) and sum(1 for e in entries if e[0] == 4) < 5:
            rep = next(g for g in frames[i + 1:] if key(g) == ("S", 0x30, 0xCD))
            entries.append((4, f["body"], encode_frame(0x30, 0xCD, rep["body"])))
    if sorted(e[0] for e in entries) != [1, 2, 3, 4, 4, 4, 4, 4]:
        raise ValueError("expected B3, BB, BD and five CD pages")
    # v2: the same session's inventory record of catalog 3043117 (95-claim reward),
    # exact 49 bytes; the probe replaces only its instance ID.
    rewards = []
    for f in frames:
        if key(f) == ("S", 0x30, 0x85):
            count = struct.unpack_from("<H", f["body"])[0]
            for n in range(count):
                rec = f["body"][2 + n * 49:2 + (n + 1) * 49]
                if struct.unpack_from("<I", rec, 4)[0] == 3043117:
                    rewards.append(rec)
    if len(rewards) != 1:
        raise ValueError("expected exactly one 3043117 record in the session")
    entries.append((5, b"", rewards[0]))
    out = bytearray(b"RFLF1\0") + struct.pack("<H", len(entries))
    for kind, req, frame in entries:
        out += struct.pack("<BB", kind, len(req)) + req + struct.pack("<H", len(frame)) + frame
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = build(args.capture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"wrote {args.output} ({len(data)} bytes) sha256={hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
