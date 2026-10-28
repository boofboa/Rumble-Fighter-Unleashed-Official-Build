"""30/CE (UpdateQuest) exchanges and lobby enter/leave sequences (PRIVATE output).

1. Every 30/CE request body and its reply (type/action/len/body), with the
   preceding and following client requests.
2. Client request order around each first/last 40/84 poll burst (lobby enter /
   leave), and the server replies of the requests that bracket them.
"""
from __future__ import annotations

import sys
from pathlib import Path

from rf_sequence import sequence


def label(f):
    return f"{f['dir']} {f['type']:03x}/{f['action']:02x}({f['total']})"


def main() -> None:
    key = lambda f: (f["dir"], f["type"], f["action"])
    for path in map(Path, sys.argv[1:]):
        frames = sequence(path.read_bytes())
        print(f"== {path.name}")
        for i, f in enumerate(frames):
            if key(f) != ("C", 0x30, 0xCE):
                continue
            rep = next((g for g in frames[i + 1:] if g["dir"] == "S"), None)
            before = [label(g) for g in frames[max(0, i - 4):i] if g["dir"] == "C"]
            after = [label(g) for g in frames[i + 1:i + 8] if g["dir"] == "C"][:3]
            print(f"  30/CE t={f['t']:.1f} body={f['body'].hex(' ')} -> {label(rep)} body={rep['body'].hex(' ')}")
            print(f"     before={before} after={after}")
        client = [f for f in frames if f["dir"] == "C" and (f["type"], f["action"]) != (0x10, 0x92)]
        polls = [n for n, f in enumerate(client) if (f["type"], f["action"]) == (0x40, 0x84)]
        if not polls:
            continue
        bursts, start = [], polls[0]
        for a, b in zip(polls, polls[1:] + [None]):
            if b is None or b != a + 1:
                bursts.append((start, a))
                start = b
        for s, e in bursts:
            pre = [f"{f['type']:02x}/{f['action']:02x}" for f in client[max(0, s - 4):s]]
            post = [f"{f['type']:02x}/{f['action']:02x}" for f in client[e + 1:e + 5]]
            print(f"  poll burst t={client[s]['t']:.0f}..{client[e]['t']:.0f} ({e - s + 1} polls) before={pre} after={post}")


if __name__ == "__main__":
    main()
