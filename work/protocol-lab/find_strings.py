"""Report whether known runtime log/dialog strings exist in given binaries.

Searches ASCII and UTF-16LE forms; prints file offsets only.
"""
import sys
from pathlib import Path

NEEDLES = ["Item_BuildPartfrom", "FUNC_Q_GET_BUDDY_LIST", "GemFighter --- Init End", "ProudManager",
           "GameTask.cpp", "JamFighter", "P2P Connected", "ServerErr", "GotoStage"]

for path in map(Path, sys.argv[1:]):
    data = path.read_bytes()
    print(f"== {path.name} ({len(data)} bytes)")
    for needle in NEEDLES:
        hits = [data.find(needle.encode("ascii")), data.find(needle.encode("utf-16-le"))]
        print(f"   {needle!r}: ascii@{hits[0]} utf16@{hits[1]}")
