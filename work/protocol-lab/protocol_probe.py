"""Offline, metadata-only probe for a candidate Rumble Fighter frame format.

Never prints packet bodies, account values, or session tokens. It makes no
network connections and does not modify the input stream. A successful parse
is evidence for framing, not proof of gameplay/server compatibility.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct


KNOWN_TYPES = {0x10, 0x20, 0x30, 0x31, 0x33, 0x40, 0x48}


class RC4:
    """Legacy protocol cipher; retains state across TCP reads/writes."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("A non-empty key is required")
        self.state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) & 255
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.i = self.j = 0

    def apply(self, data: bytes) -> bytes:
        out = bytearray()
        s = self.state
        for value in data:
            self.i = (self.i + 1) & 255
            self.j = (self.j + s[self.i]) & 255
            s[self.i], s[self.j] = s[self.j], s[self.i]
            out.append(value ^ s[(s[self.i] + s[self.j]) & 255])
        return bytes(out)


def rc4(data: bytes, key: bytes) -> bytes:
    return RC4(key).apply(data)


def encode_frame(frame_type: int, action: int, body: bytes = b"") -> bytes:
    total = 6 + len(body)
    if total > 65535:
        raise ValueError("Frame exceeds the 16-bit length field")
    return struct.pack(">HH", frame_type, total) + struct.pack("<H", action) + body


class FrameStream:
    """Frame accumulator. Feed already decrypted bytes exactly once."""

    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, int, bytes]]:
        self.buffer.extend(data)
        out = []
        while len(self.buffer) >= 6:
            frame_type, length = struct.unpack_from(">HH", self.buffer)
            action = struct.unpack_from("<H", self.buffer, 4)[0]
            if length < 6:
                raise ValueError("Invalid frame length")
            if len(self.buffer) < length:
                break
            out.append((frame_type, action, bytes(self.buffer[6:length])))
            del self.buffer[:length]
        return out


def scan_frames(data: bytes) -> dict:
    """Probe BE16 type, BE16 total size, LE16 action; no payload output."""
    offset = 0
    frames = []
    status = "complete"
    while offset < len(data):
        if len(data) - offset < 6:
            status = "incomplete_header"
            break
        frame_type, total = struct.unpack_from(">HH", data, offset)
        action = struct.unpack_from("<H", data, offset + 4)[0]
        if total < 6:
            status = "invalid_length"
            break
        if total > len(data) - offset:
            status = "incomplete_frame"
            break
        frames.append({
            "offset": offset,
            "type": f"0x{frame_type:04x}",
            "action": f"0x{action:04x}",
            "total_bytes": total,
            "body_bytes": total - 6,
            "type_known_to_reference": frame_type in KNOWN_TYPES,
        })
        offset += total
    return {
        "input_bytes": len(data),
        "parsed_bytes": offset,
        "unparsed_bytes": len(data) - offset,
        "status": status,
        "frame_count": len(frames),
        "known_type_count": sum(f["type_known_to_reference"] for f in frames),
        "frames": frames,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stream", type=Path, help="One ordered, gap-free TCP direction")
    parser.add_argument("--key-file", type=Path, help="Optional raw RC4 hypothesis key; not printed")
    args = parser.parse_args()
    data = args.stream.read_bytes()
    if args.key_file:
        data = rc4(data, args.key_file.read_bytes())
    print(json.dumps(scan_frames(data), indent=2))


if __name__ == "__main__":
    main()
