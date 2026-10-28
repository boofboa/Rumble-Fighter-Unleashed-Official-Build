"""DNS query names and answers in a capture (PRIVATE output: may reveal browsing).

Prints time, queried name, and A-record answers, so service hostnames used by the
game/launcher can be separated from unrelated traffic. Usage: rf_dns_names.py CAPTURE
"""
from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

from inspect_capture import read_pcapng


def name_at(data: bytes, at: int):
    labels, jumped, end = [], False, at
    for _ in range(64):
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at = ((n & 0x3F) << 8) | data[at + 1]
            jumped = True
            continue
        labels.append(data[at + 1:at + 1 + n].decode("ascii", "replace"))
        at += 1 + n
    return ".".join(labels), (end if jumped else at)


def main() -> None:
    packets, _, _ = read_pcapng(Path(sys.argv[1]).read_bytes())
    t0 = min(p["time"] for p in packets)
    for p in packets:
        raw = p["raw"]
        if p["link"] != 1 or len(raw) < 42 or raw[12:14] != b"\x08\x00" or raw[23] != 17:
            continue
        ihl = (raw[14] & 15) * 4
        sport, dport, length = struct.unpack_from("!HHH", raw, 14 + ihl)
        if 53 not in (sport, dport):
            continue
        dns = raw[14 + ihl + 8:14 + ihl + length]
        try:
            flags, qd, an = struct.unpack_from("!HHH", dns, 2)
            name, at = name_at(dns, 12)
            at += 4
            answers = []
            for _ in range(an):
                _, at = name_at(dns, at)
                rtype, _, _, rlen = struct.unpack_from("!HHIH", dns, at)
                at += 10
                if rtype == 1 and rlen == 4:
                    answers.append(socket.inet_ntoa(dns[at:at + 4]))
                at += rlen
            kind = "R" if flags & 0x8000 else "Q"
            print(f"{p['time'] - t0:9.3f} {kind} {name} {' '.join(answers)}")
        except (struct.error, IndexError):
            continue


if __name__ == "__main__":
    main()
