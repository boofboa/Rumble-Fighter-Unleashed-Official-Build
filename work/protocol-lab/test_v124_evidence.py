"""1.24 evidence: the capture facts the account, My Info and plaza code relies on.

Reads ../../private/captures (user captures, never committed); skipped when absent.
Assertions only; nothing private is printed.
"""
from __future__ import annotations

import collections
import struct
import unittest
from pathlib import Path

from inspect_capture import read_pcapng, group_flows, reassemble
from rf_proudnet_frames import frames as proudnet_frames
from rf_sequence import sequence

CAPTURES = Path(__file__).resolve().parents[2] / "private" / "captures"
NAMES = ["rf-boss-baseline.pcapng", "rf-startup.pcapng", "rf-empty-buddy.pcapng"]
RECORD = 49
_cache: dict = {}


def seq(name):
    if name not in _cache:
        _cache[name] = sequence((CAPTURES / name).read_bytes())
    return _cache[name]


def key(f):
    return f["dir"], f["type"], f["action"]


def next_server_frame(frames, index):
    for f in frames[index + 1:]:
        if f["dir"] == "S":
            return f
    return None


@unittest.skipUnless(all((CAPTURES / n).exists() for n in NAMES), "private captures not present")
class InventoryPagination(unittest.TestCase):
    def test_pages_ascend_80_per_page_cursor_is_last_plus_one(self):
        for name in NAMES:
            last = None
            pages = 0
            for f in seq(name):
                if key(f) == ("C", 0x30, 0x84):
                    self.assertEqual(f["body"][4:7], b"\xff\xff\xff")
                    cursor = struct.unpack_from("<I", f["body"], 7)[0]
                    self.assertEqual(cursor, 1 if last is None else last + 1, name)
                elif key(f) == ("S", 0x30, 0x85):
                    body = f["body"]
                    count = struct.unpack_from("<H", body)[0]
                    self.assertEqual(len(body), 2 + RECORD * 80)
                    ids = [struct.unpack_from("<I", body, 2 + RECORD * n)[0] for n in range(count)]
                    self.assertEqual(ids, sorted(ids))
                    self.assertEqual(len(set(ids)), len(ids))
                    pages += 1
                    if ids:
                        last = ids[-1]
                    if count < 80:
                        break
            self.assertGreaterEqual(pages, 3, name)


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class MyInfoEquip(unittest.TestCase):
    def setUp(self):
        frames = seq("rf-boss-baseline.pcapng")
        self.frames = frames
        self.inventory = {}
        for f in frames:
            if key(f) == ("S", 0x30, 0x85):
                body = f["body"]
                for n in range(struct.unpack_from("<H", body)[0]):
                    inst, cat = struct.unpack_from("<II", body, 2 + RECORD * n)
                    end = struct.unpack_from("<I", body, 2 + RECORD * n + 29)[0]
                    self.inventory[inst] = (cat, end)

    def test_d6_names_owned_catalog_and_its_item_end_and_gets_d7_01(self):
        owned = collections.defaultdict(set)
        for cat, end in self.inventory.values():
            owned[cat].add(end)
        seen = 0
        for i, f in enumerate(self.frames):
            if key(f) == ("C", 0x30, 0xd6):
                cat, end = struct.unpack("<II", f["body"])
                self.assertIn(end, owned[cat])
                reply = next_server_frame(self.frames, i)
                self.assertEqual((reply["type"], reply["action"], reply["body"]), (0x30, 0xd7, b"\x01"))
                seen += 1
        self.assertEqual(seen, 4)

    def test_a4_slot_item_is_an_owned_instance_and_ack_is_header_only(self):
        for i, f in enumerate(self.frames):
            if key(f) in {("C", 0x40, 0xa4), ("C", 0x40, 0xa6), ("C", 0x40, 0xa2)}:
                reply = next_server_frame(self.frames, i)
                self.assertEqual((reply["type"], reply["action"], reply["body"]), (0x40, f["action"] + 1, b""))
                if f["action"] == 0xa4:
                    inst = struct.unpack_from("<I", f["body"], 5)[0]
                    self.assertIn(inst, self.inventory)

    def test_user_info_reply_layout(self):
        login = next(f["body"] for f in self.frames if key(f) == ("S", 0x10, 0x85))
        replies = [(i, f) for i, f in enumerate(self.frames) if key(f) == ("C", 0x30, 0x80)]
        self.assertEqual(len(replies), 4)
        for i, f in replies:
            self.assertEqual(len(f["body"]), 20)
            reply = next_server_frame(self.frames, i)
            self.assertEqual((reply["type"], reply["action"], len(reply["body"])), (0x30, 0x81, 1561))
            body = reply["body"]
            self.assertEqual(body[4:24], f["body"])                      # the requested name
            self.assertEqual(body[0:4], login[0:4])                       # account ID
            self.assertEqual(body[24:32], login[24:32])                   # level, experience
            for slot in range(45):
                cat = struct.unpack_from("<I", body, 32 + 4 * slot)[0]
                if cat:
                    self.assertIn(cat, {c for c, _ in self.inventory.values()})

    def test_1f10_keepalive_never_answered(self):
        for i, f in enumerate(self.frames):
            if key(f) == ("C", 0x1f, 0x10):
                reply = next_server_frame(self.frames, i)
                self.assertNotEqual(reply["type"], 0x1f)
        self.assertEqual(sum(1 for f in self.frames if key(f) == ("C", 0x1f, 0x10)), 3)


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class PlazaHandshake(unittest.TestCase):
    def setUp(self):
        packets, _, _ = read_pcapng((CAPTURES / "rf-boss-baseline.pcapng").read_bytes())
        self.client, self.server = [], []
        for flow in group_flows(packets, collections.Counter()):
            syn = next((p for p in flow["packets"] if p["flags"] & 2 and not p["flags"] & 16), None)
            if syn is None or syn["destination"][1] != 33343:
                continue
            for out, endpoint in ((self.client, syn["source"]), (self.server, syn["destination"])):
                _, ranges, _ = reassemble([p for p in flow["packets"] if p["source"] == endpoint])
                out.extend((kind, payload) for _, _, kind, payload in proudnet_frames(ranges[0][1]))

    def test_core_handshake_order_and_shapes(self):
        c = [p[0] for kind, p in self.client[:3]]
        self.assertEqual(c, [0x2e, 0x05, 0x07])
        self.assertEqual(self.server[0][0], "policy_xml")
        hint = self.server[1][1]
        self.assertEqual((hint[0], len(hint), hint[39:42], hint[42:45]), (0x04, 182, b"\x02\x8c\x00", b"\x30\x81\x89"))
        self.assertEqual(self.server[2][1], b"\x06")
        self.assertEqual(self.server[3][1][0], 0x0a)
        key_message = self.client[1][1]
        self.assertEqual(key_message[1:4], b"\x02\x80\x00")             # 128-byte RSA block
        self.assertEqual(key_message[132:134], b"\x01\x10")             # then a 16-byte array

    def test_heartbeat_pairs_and_unanswered_messages(self):
        c_rmi = collections.Counter(p[1:3] for kind, p in self.client if kind == "frame" and p[0] == 0x01)
        s_rmi = collections.Counter(p[1:3] for kind, p in self.server if kind == "frame" and p[0] == 0x01)
        self.assertGreater(c_rmi[b"\x01\xfa"], 100)
        self.assertLessEqual(abs(c_rmi[b"\x01\xfa"] - s_rmi[b"\xfc\xfb"]), 12)   # 212 vs 200 (capture ends mid-flight)
        self.assertNotIn(b"\x14\xfa", s_rmi)                                 # FA13 never gets a reply RMI FA14
        pings = sum(1 for kind, p in self.client if kind == "frame" and p[0] == 0x1a)
        pongs = sum(1 for kind, p in self.server if kind == "frame" and p[0] == 0x1c)
        self.assertEqual(pings, pongs)
        for kind, p in self.server:
            if kind == "frame" and p[0] == 0x1c:
                self.assertEqual(len(p), 17)


if __name__ == "__main__":
    unittest.main()
