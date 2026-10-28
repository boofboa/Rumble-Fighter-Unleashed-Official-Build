"""Buddy-list codec tests: synthetic always; official-capture checks when present.

Capture checks read ../../private/captures (user captures, never committed or
shared). They assert structure only and print no names or identifiers.
"""
from pathlib import Path
import hashlib
import struct
import unittest

from lobby_wire import (AVATAR_UPDATE_BODY_BYTES, build_avatar_update_ack)
from lobby_wire import (CLASS_FIXTURE_RECORD, LOCAL_CLASS_INSTANCE, PROPERTY_RECORD,
                        PROPERTY_REPLY, build_property_page)
from lobby_wire import (B4_REPLY, B4_REPLY_BODY, B4_REQUEST, FISHING_ROD_CATALOG, GRADE_RECORD,
                        GRADE_REPLY, GUARD_ANSWER, LOCAL_ROD_INSTANCE, ROD_FIXTURE_RECORD,
                        build_empty_grade_list, build_zero_b4_status)
from lobby_wire import LOCAL_GRADE_IDS, build_local_grade_list
from lobby_wire import (B6_REQUEST, GRADE_95_CLAIMED, REWARD_95_CATALOG, ROOM_HEADER, ROOM_LIST, ROOM_POLL,
                        ROOM_POLL_BODY, ROOM_RECORD, build_b6_reply, build_empty_room_list)
from protocol_probe import encode_frame
from lobby_wire import (ADD_ITEM_FAILURE, ADD_ITEM_REQUEST, CHANNEL_100_CLAIM, LOCAL_GRADE_VALUES,
                        build_add_item_failure)
from lobby_wire import (EXO_FIXTURE_RECORD, LOCAL_EXO_INSTANCE, SOUL_FIGHTER_DEFAULT_EXO,
                        parse_add_item_request)
from lobby_wire import (AVATAR_LIST_REPLY, AVATAR_LIST_REQUEST, BUDDY_BODY_BYTES,
                        BUDDY_CAPACITY, BUDDY_REPLY, EQUIPMENT_REPLY, EQUIPMENT_REQUEST,
                        EQUIPMENT_SLOTS, EQUIPMENT_TAIL_BYTES, EQUIPPED_REPLY, EQUIPPED_REQUEST,
                        build_avatar_equipment, build_avatar_list, build_buddy_list,
                        build_equipped_avatar, parse_avatar_equipment, parse_avatar_list,
                        parse_buddy_list)
from protocol_probe import FrameStream

CAPTURES = Path(__file__).resolve().parents[2] / "private" / "captures"


def capture_frames(name):
    from rf_sequence import sequence
    return sequence((CAPTURES / name).read_bytes())


class BuddyCodecTests(unittest.TestCase):
    def test_empty_reply_layout(self):
        frame = build_buddy_list()
        self.assertEqual(len(frame), 3008)
        self.assertEqual(frame[:6], bytes([0, 0x10, 0x0B, 0xC0, 0xA9, 0]))
        self.assertEqual(frame[6:], bytes(BUDDY_BODY_BYTES))
        # Same bytes as RFHandshakeProbe.BuildEmptyBuddyList (header + 3002 zeros).
        self.assertEqual(hashlib.sha256(frame).hexdigest(),
                         hashlib.sha256(bytes([0, 0x10, 0x0B, 0xC0, 0xA9, 0]) + bytes(3002)).hexdigest())

    def test_round_trip_and_bounds(self):
        frame = build_buddy_list([(7, "Synthetic", b"NF"), (9, "Other", b"NF")])
        (ftype, action, body), = FrameStream().feed(frame)
        self.assertEqual((ftype, action), BUDDY_REPLY)
        self.assertEqual(parse_buddy_list(body), [(7, "Synthetic", b"NF"), (9, "Other", b"NF")])
        with self.assertRaises(ValueError):
            build_buddy_list([(1, "x", b"NF")] * (BUDDY_CAPACITY + 1))
        with self.assertRaises(ValueError):
            build_buddy_list([(1, "x" * 24, b"NF")])


class AvatarCodecTests(unittest.TestCase):
    def test_local_single_avatar_matches_probe_bytes(self):
        # Same bytes as RFHandshakeProbe BuildLocalAvatarList / Equipped / EmptyEquipment.
        self.assertEqual(build_avatar_list([1]),
                         bytes([0, 0x30, 0, 87, 0x87, 0, 1, 1]) + bytes(79))
        self.assertEqual(build_equipped_avatar(1), bytes([0, 0x40, 0, 10, 0xA1, 0, 1, 0, 0, 0]))
        self.assertEqual(build_avatar_equipment(), bytes([0, 0x30, 1, 0x6E, 0x89, 0]) + bytes(360))

    def test_round_trip_and_bounds(self):
        (_, _, body), = FrameStream().feed(build_avatar_list([5, 9]))
        self.assertEqual(parse_avatar_list(body), [5, 9])
        (_, _, body), = FrameStream().feed(build_avatar_equipment([7, 0, 8]))
        self.assertEqual(parse_avatar_equipment(body)[:4], [7, 0, 8, 0])
        for bad in ([0], list(range(1, 22))):
            with self.assertRaises(ValueError):
                build_avatar_list(bad)


@unittest.skipUnless((CAPTURES / "rf-empty-buddy.pcapng").exists(), "private captures not present")
class OfficialAvatarCaptureTests(unittest.TestCase):
    """Relationships the local candidate relies on, in all three official captures."""

    def test_avatar_chain_relationships(self):
        for name in ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):
            with self.subTest(capture=name):
                frames = capture_frames(name)
                key = lambda f: (f["dir"], f["type"], f["action"])
                login = next(f for f in frames if key(f) == ("S", 0x10, 0x85))
                buddy_at = next(i for i, f in enumerate(frames) if key(f) == ("C", 0x10, 0xA8))
                after = frames[buddy_at:]
                req = next(f for f in after if key(f) == ("C",) + AVATAR_LIST_REQUEST)
                self.assertEqual(req["body"], login["body"][:4])  # account ID
                rep = next(f for f in after if key(f) == ("S",) + AVATAR_LIST_REPLY)
                ids = parse_avatar_list(rep["body"])
                self.assertTrue(ids and all(ids))
                equipped = next(f for f in after if key(f) == ("S",) + EQUIPPED_REPLY)
                self.assertIn(struct.unpack("<I", equipped["body"])[0], ids)
                eq_reqs = [f for f in after if key(f) == ("C",) + EQUIPMENT_REQUEST]
                self.assertEqual([struct.unpack("<I", f["body"])[0] for f in eq_reqs], ids)
                for f in after:
                    if key(f) == ("S",) + EQUIPMENT_REPLY:
                        self.assertEqual(f["body"][4 * EQUIPMENT_SLOTS:], bytes(EQUIPMENT_TAIL_BYTES))
                order = [(f["type"], f["action"]) for f in after if f["dir"] == "C"
                         and (f["type"], f["action"]) != (0x10, 0x92)]
                first = order.index(AVATAR_LIST_REQUEST)
                self.assertEqual(order[first + 1], EQUIPPED_REQUEST)
                self.assertEqual(order[first + 2:first + 2 + len(ids)], [EQUIPMENT_REQUEST] * len(ids))
                self.assertEqual(order[first + 2 + len(ids)], (0x30, 0xA0))


class AvatarUpdateAckTests(unittest.TestCase):
    def test_ack_bytes_match_probe(self):
        for action in (0xA2, 0xA4, 0xA6):
            self.assertEqual(build_avatar_update_ack(action), bytes([0, 0x40, 0, 6, action + 1, 0]))
        with self.assertRaises(ValueError):
            build_avatar_update_ack(0xA0)


class ClassFixtureTests(unittest.TestCase):
    def test_fixture_bytes_match_probe_and_reference_rule(self):
        page = build_property_page([CLASS_FIXTURE_RECORD, ROD_FIXTURE_RECORD, EXO_FIXTURE_RECORD])
        equipment = build_avatar_equipment([LOCAL_CLASS_INSTANCE])
        expected_page = bytearray(bytes([0, 0x30, 0x0F, 0x58, 0x85, 0]) + bytes(3922))
        expected_page[6] = 3
        struct.pack_into("<III", expected_page, 8, 1001, 1000176, 20046)
        struct.pack_into("<III", expected_page, 57, 1002, 5135224, 85582)
        struct.pack_into("<I", expected_page, 86, 1000)
        struct.pack_into("<III", expected_page, 106, 1003, 2040035, 85582)
        struct.pack_into("<I", expected_page, 135, 1000)
        self.assertEqual(page, bytes(expected_page))   # same bytes as the v1.18 probe
        self.assertNotIn(LOCAL_ROD_INSTANCE, parse_avatar_equipment(equipment[6:]))
        self.assertNotIn(LOCAL_EXO_INSTANCE, parse_avatar_equipment(equipment[6:]))
        self.assertEqual(equipment, bytes([0, 0x30, 1, 0x6E, 0x89, 0]) + struct.pack("<I", 1001) + bytes(356))
        slot0 = parse_avatar_equipment(equipment[6:])[0]
        self.assertEqual(slot0, CLASS_FIXTURE_RECORD[0])     # instance, not catalog
        self.assertNotEqual(slot0, CLASS_FIXTURE_RECORD[1])

    def test_v117_add_item_body_requests_the_missing_default_exo(self):
        # Body recorded by the v1.17 real-client run (report …164901-3b79ba75).
        parsed = parse_add_item_request(bytes.fromhex("0000e3201f00e8030000"))
        self.assertEqual(parsed, {"kind": "item_grant", "catalog": SOUL_FIGHTER_DEFAULT_EXO, "u16_at_6": 1000})
        self.assertEqual(EXO_FIXTURE_RECORD[1], parsed["catalog"])
        self.assertEqual(EXO_FIXTURE_RECORD[3], parsed["u16_at_6"])
        self.assertEqual(parse_add_item_request(CHANNEL_100_CLAIM), {"kind": "medal_claim", "channel": 100})

    def test_v120_level_up_grant_body_and_rejection_bytes(self):
        from lobby_wire import LEVEL_ONE_REWARD_GRANT
        self.assertEqual(parse_add_item_request(LEVEL_ONE_REWARD_GRANT),
                         {"kind": "level_up_grant", "catalog": 5023329, "u16_at_6": 1000})
        # v1.21 answers it with the same observed failure frame as the channel-100 claim.
        self.assertEqual(build_add_item_failure(10001)[:22],
                         bytes([0, 0x31, 2, 8, 0x8B, 1, 0x11, 0x27]) + b"FAIL(unknown)\0")

    def test_query_reply_bytes_match_probe(self):
        self.assertEqual(build_empty_grade_list(), bytes([0, 0x30, 0, 7, 0xA1, 0, 0]))
        grade = build_local_grade_list()
        expected = bytearray(345)
        expected[1], expected[2], expected[3], expected[4], expected[6] = 0x30, 1, 0x59, 0xA1, 26
        for n, gid in enumerate(LOCAL_GRADE_IDS):
            expected[7 + 13 * n] = gid
            if gid == 95:
                struct.pack_into("<I", expected, 7 + 13 * n + 9, 2)
        self.assertEqual(grade, bytes(expected))  # same bytes as RFHandshakeProbe.BuildLocalGradeList
        self.assertEqual(build_zero_b4_status(), bytes([0, 0x30, 0, 25, 0xB5, 0]) + bytes(19))


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class OfficialClassReferenceTests(unittest.TestCase):
    """The fixture is justified only if the captures show these rules."""

    def test_slot0_resolves_and_fixture_profile_was_observed(self):
        profiles, replies = set(), 0
        for name in ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):
            frames = capture_frames(name)
            inventory = {}
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + PROPERTY_REPLY:
                    count = struct.unpack_from("<H", f["body"])[0]
                    for n in range(count):
                        rec = f["body"][2 + n * PROPERTY_RECORD:2 + (n + 1) * PROPERTY_RECORD]
                        inventory[struct.unpack_from("<I", rec)[0]] = rec
            for f in frames:
                if (f["dir"], f["type"], f["action"]) != ("S",) + EQUIPMENT_REPLY:
                    continue
                replies += 1
                refs = parse_avatar_equipment(f["body"])
                self.assertNotEqual(refs[0], 0)
                rec = inventory[refs[0]]
                for r in refs:
                    if r:
                        self.assertIn(r, inventory)
                catalog, word8 = struct.unpack_from("<II", rec, 4)
                end, stat = struct.unpack_from("<II", rec, 29)
                zero_opaque = rec[12:29] == bytes(17) and rec[37:49] == bytes(12)
                profiles.add((catalog, word8, end, stat, zero_opaque))
        self.assertEqual(replies, 40)
        self.assertIn(CLASS_FIXTURE_RECORD[1:] + (True,), profiles)


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class OfficialV114EvidenceTests(unittest.TestCase):
    """Each v1.14 rule, checked against all three official captures."""

    def frames_by_capture(self):
        for name in ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):
            yield name, capture_frames(name)

    def test_rod_owned_never_equipped_and_31c6_never_sent(self):
        for name, frames in self.frames_by_capture():
            rods = []
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + PROPERTY_REPLY:
                    count = struct.unpack_from("<H", f["body"])[0]
                    for n in range(count):
                        rec = f["body"][2 + n * PROPERTY_RECORD:2 + (n + 1) * PROPERTY_RECORD]
                        if struct.unpack_from("<I", rec, 4)[0] == FISHING_ROD_CATALOG:
                            rods.append(rec)
            self.assertEqual(len(rods), 1, name)
            word8, = struct.unpack_from("<I", rods[0], 8)
            end, stat = struct.unpack_from("<II", rods[0], 29)
            self.assertEqual((word8, end, stat), ROD_FIXTURE_RECORD[2:], name)
            self.assertFalse(any((f["dir"], f["type"], f["action"]) == ("C", 0x31, 0xC6) for f in frames))

    def test_grade_reply_is_count_plus_13_byte_records(self):
        for name, frames in self.frames_by_capture():
            replies = [f for f in frames if (f["dir"], f["type"], f["action"]) == ("S",) + GRADE_REPLY]
            self.assertTrue(replies)
            for f in replies:
                self.assertEqual(len(f["body"]), 1 + GRADE_RECORD * f["body"][0], name)

    def test_every_local_grade_record_was_observed_exactly_and_in_every_capture(self):
        observed_records, ids_per_capture = set(), []
        for name, frames in self.frames_by_capture():
            ids = set()
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + GRADE_REPLY:
                    b = f["body"]
                    for n in range(b[0]):
                        rec = b[1 + GRADE_RECORD * n:1 + GRADE_RECORD * (n + 1)]
                        observed_records.add(rec)
                        ids.add(rec[0])
            ids_per_capture.append(ids)
        body = build_local_grade_list()[7:]
        for n, gid in enumerate(LOCAL_GRADE_IDS):
            self.assertIn(body[GRADE_RECORD * n:GRADE_RECORD * (n + 1)], observed_records, gid)
            self.assertTrue(all(gid in ids for ids in ids_per_capture), gid)

    def test_first_add_item_is_channel_100_claim_answered_by_code_10001(self):
        local = build_add_item_failure(10001)
        self.assertEqual(local[:6], bytes([0, 0x31, 0x02, 0x08, 0x8B, 0x01]))  # same as the probe
        for name, frames in self.frames_by_capture():
            key = lambda f: (f["dir"], f["type"], f["action"])
            i = next(n for n, f in enumerate(frames) if key(f) == ("C",) + ADD_ITEM_REQUEST)
            self.assertEqual(frames[i]["body"], CHANNEL_100_CLAIM, name)
            prev_grade = [f for f in frames[:i] if key(f) == ("S",) + GRADE_REPLY][-1]["body"]
            values = {prev_grade[1 + 13 * n]: prev_grade[2 + 13 * n:14 + 13 * n] for n in range(prev_grade[0])}
            self.assertEqual(values[100], bytes(12), name)      # channel 100 at (0,0,0), as ours
            reply = next(f for f in frames[i + 1:] if f["dir"] == "S" and f["type"] == 0x31)
            self.assertEqual((reply["type"], reply["action"]), ADD_ITEM_FAILURE, name)
            self.assertEqual(reply["total"], len(local))
            self.assertEqual(reply["body"][:32], local[6:38], name)  # code, text, NUL, zeros
            self.assertTrue(any(f["dir"] == "C" for f in frames[i + 2:]))  # the client continued

    def test_channel_95_claim_only_when_its_first_value_is_zero(self):
        # Basis of the v1.17 prediction: a 95 claim was sent iff 95's value a == 0
        # (rf-startup: (0,0,2) -> claimed and granted; other captures: a >= 1 -> not claimed).
        for name, frames in self.frames_by_capture():
            key = lambda f: (f["dir"], f["type"], f["action"])
            grade = next(f for f in frames if key(f) == ("S",) + GRADE_REPLY)["body"]
            values = {grade[1 + 13 * n]: struct.unpack_from("<III", grade, 2 + 13 * n) for n in range(grade[0])}
            claimed_95 = any(key(f) == ("C",) + ADD_ITEM_REQUEST and f["body"][:2] == bytes([2, 95]) for f in frames)
            self.assertEqual(claimed_95, values[95][0] == 0, name)
        self.assertEqual(LOCAL_GRADE_VALUES[95][0], 0)

    def test_default_exo_owned_unequipped_and_fixture_profile_observed(self):
        from rf_profile_compare import DEFAULT_EXO
        exo_profiles = set()
        for name, frames in self.frames_by_capture():
            inv, equip = {}, []
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + PROPERTY_REPLY:
                    count = struct.unpack_from("<H", f["body"])[0]
                    for n in range(count):
                        rec = f["body"][2 + n * PROPERTY_RECORD:2 + (n + 1) * PROPERTY_RECORD]
                        inv[struct.unpack_from("<I", rec)[0]] = rec
                if (f["dir"], f["type"], f["action"]) == ("S",) + EQUIPMENT_REPLY:
                    equip.append(parse_avatar_equipment(f["body"]))
            cat = {i: struct.unpack_from("<I", r, 4)[0] for i, r in inv.items()}
            for cls in {cat[e[0]] for e in equip}:
                exos = [i for i, c in cat.items() if c == DEFAULT_EXO[cls]]
                self.assertEqual(len(exos), 1, (name, cls))
                self.assertFalse(any(exos[0] in e for e in equip), (name, cls))   # never equipped
                r = inv[exos[0]]
                exo_profiles.add((DEFAULT_EXO[cls],) + struct.unpack_from("<I", r, 8) + struct.unpack_from("<II", r, 29)
                                 + (r[12:29] == bytes(17) and r[37:49] == bytes(12),))
        self.assertIn(EXO_FIXTURE_RECORD[1:] + (True,), exo_profiles)

    def test_b4_indices_and_zero_reply_observed(self):
        zero_seen = 0
        for name, frames in self.frames_by_capture():
            reqs = [f for f in frames if (f["dir"], f["type"], f["action"]) == ("C",) + B4_REQUEST]
            self.assertEqual([struct.unpack("<I", f["body"])[0] for f in reqs][:5], [1, 2, 3, 4, 5], name)
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + B4_REPLY:
                    self.assertEqual(len(f["body"]), B4_REPLY_BODY)
                    zero_seen += f["body"] == bytes(B4_REPLY_BODY)
        self.assertGreater(zero_seen, 0)

    def test_guard_answer_never_answered(self):
        for name, frames in self.frames_by_capture():
            self.assertTrue(any((f["dir"], f["type"], f["action"]) == ("C",) + GUARD_ANSWER for f in frames))
            server_guard = {(f["type"], f["action"]) for f in frames if f["dir"] == "S" and f["type"] == 0x48}
            self.assertEqual(server_guard, {(0x48, 0x81)}, name)


FIXTURE = CAPTURES.parent / "fixtures" / "lobby-boss-v2.bin"


@unittest.skipUnless(FIXTURE.exists() and (CAPTURES / "rf-boss-baseline.pcapng").exists(), "private data not present")
class MainMenuFixtureTests(unittest.TestCase):
    def test_fixture_is_exactly_the_boss_session_frames_and_deterministic(self):
        import hashlib
        from rf_make_lobby_fixture import build
        data = build(CAPTURES / "rf-boss-baseline.pcapng")
        self.assertEqual(data, FIXTURE.read_bytes())
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "4605704f0ee2b9002551039fd1789c43e32423c972b2889284c5368df1b172b6")  # pinned in the probe

    def test_menu_flow_and_reply_relations(self):
        for name in ("rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):   # guild-less sessions
            frames = capture_frames(name)
            client = [(f["type"], f["action"]) for f in frames if f["dir"] == "C" and (f["type"], f["action"]) != (0x10, 0x92)]
            i = client.index((0x30, 0xB2))
            self.assertEqual(client[i:i + 8], [(0x30, 0xB2), (0x30, 0xBA), (0x30, 0xBC)] + [(0x30, 0xCC)] * 5, name)
            bb = next(f for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0xBB))["body"]
            bd = next(f for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0xBD))["body"]
            self.assertEqual(bd[:8], bb, name)                         # BD begins with BB
        for name in ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):
            b3 = next(f for f in capture_frames(name) if (f["dir"], f["type"], f["action"]) == ("S", 0x30, 0xB3))["body"]
            self.assertEqual(struct.unpack_from("<I", b3, 32)[0], 0x03381018, name)   # constant field 8

    def test_channel_95_claim_precedes_lobby_entry_when_95_is_unclaimed(self):
        # Prediction basis for v1.19 (fixture unchanged, 95 = (0,0,2)): in rf-startup the
        # 95 claim follows the channel-100 failure and comes before 10/B6 and 40/84 polling.
        frames = capture_frames("rf-startup.pcapng")
        client = [f for f in frames if f["dir"] == "C"]
        claim95 = next(n for n, f in enumerate(client) if (f["type"], f["action"]) == ADD_ITEM_REQUEST and f["body"][:2] == bytes([2, 95]))
        claim100 = next(n for n, f in enumerate(client) if (f["type"], f["action"]) == ADD_ITEM_REQUEST and f["body"] == CHANNEL_100_CLAIM)
        b6 = next(n for n, f in enumerate(client) if (f["type"], f["action"]) == (0x10, 0xB6))
        poll = next(n for n, f in enumerate(client) if (f["type"], f["action"]) == (0x40, 0x84))
        self.assertEqual(claim95, claim100 + 1)
        self.assertLess(claim95, b6)
        self.assertLess(claim95, poll)


class LobbyReplyTests(unittest.TestCase):
    def test_bytes_match_probe(self):
        self.assertEqual(build_b6_reply(), bytes([0x02, 0x10, 0, 7, 0xB7, 0, 1]))
        self.assertEqual(build_empty_room_list(), bytes([0, 0x40, 0, 16, 0x85, 0]) + bytes(10))


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class OfficialLobbyEvidenceTests(unittest.TestCase):
    NAMES = ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng")

    def test_b6_reply_constant_and_poll_body_constant(self):
        b6 = polls = 0
        for name in self.NAMES:
            frames = capture_frames(name)
            for i, f in enumerate(frames):
                if (f["dir"], f["type"], f["action"]) == ("C",) + B6_REQUEST:
                    self.assertEqual(f["body"], b"\x01")
                    rep = next(g for g in frames[i + 1:] if g["dir"] == "S")
                    self.assertEqual(encode_frame(rep["type"], rep["action"], rep["body"]), build_b6_reply())
                    b6 += 1
                if (f["dir"], f["type"], f["action"]) == ("C",) + ROOM_POLL:
                    self.assertEqual(f["body"], ROOM_POLL_BODY)
                    polls += 1
        self.assertEqual((b6, polls), (11, 42))

    def test_room_list_structure_and_header_relations(self):
        lists = 0
        for name in self.NAMES:
            for f in capture_frames(name):
                if (f["dir"], f["type"], f["action"]) != ("S",) + ROOM_LIST:
                    continue
                b = f["body"]
                z0, first, z1, last, n = struct.unpack_from("<5H", b)
                self.assertEqual(len(b), ROOM_HEADER + ROOM_RECORD * n)
                self.assertGreater(n, 0)                                 # N = 0 never observed
                self.assertEqual((z0, z1), (0, 0))
                rooms = [struct.unpack_from("<H", b, ROOM_HEADER + ROOM_RECORD * k + 4)[0] for k in range(n)]
                self.assertEqual(last, 0x8000 | rooms[-1])
                self.assertEqual(first & 0x7FFF, rooms[0])
                lists += 1
        self.assertGreaterEqual(lists, 40)

    def test_idle_lobby_needs_only_room_polls(self):
        # Guild-less, user-idle lobbies (no room joins) send nothing but 40/84 after entry.
        frames = capture_frames("rf-empty-buddy.pcapng")
        start = next(f["t"] for f in frames if (f["dir"], f["type"], f["action"]) == ("C",) + ROOM_POLL)
        after = {(f["type"], f["action"]) for f in frames if f["dir"] == "C" and f["t"] >= start}
        self.assertEqual(after, {ROOM_POLL})

    def test_update_quest_reply_echoes_request_body(self):
        from lobby_wire import QUEST_UPDATE, build_quest_update_ack
        seen = 0
        for name in self.NAMES:
            frames = capture_frames(name)
            for i, f in enumerate(frames):
                if (f["dir"], f["type"], f["action"]) == ("C",) + QUEST_UPDATE:
                    rep = next(g for g in frames[i + 1:] if g["dir"] == "S")
                    self.assertEqual(encode_frame(rep["type"], rep["action"], rep["body"]),
                                     build_quest_update_ack(f["body"]))
                    seen += 1
        self.assertEqual(seen, 2)   # small sample: both in rf-boss-baseline

    def test_every_lobby_entry_is_bc_then_b6(self):
        # A poll burst that does not directly follow a room action (type 0x40) is a lobby
        # entry, and every such entry is preceded by exactly 30/BC, 10/B6.
        entries = 0
        for name in self.NAMES:
            client = [(f["type"], f["action"]) for f in capture_frames(name)
                      if f["dir"] == "C" and (f["type"], f["action"]) != (0x10, 0x92)]
            for n, k in enumerate(client):
                if k == ROOM_POLL and client[n - 1] != ROOM_POLL and client[n - 1][0] != 0x40 or \
                        k == ROOM_POLL and client[n - 1] == B6_REQUEST:
                    self.assertEqual(client[n - 2:n], [(0x30, 0xBC), B6_REQUEST], name)
                    entries += 1
        self.assertGreaterEqual(entries, 10)

    def test_no_official_account_owns_or_requests_the_level_item(self):
        # Basis for "not an inventory-ownership check" and "no captured kind-1 success".
        from lobby_wire import LEVEL_ONE_REWARD_GRANT
        for name in self.NAMES:
            frames = capture_frames(name)
            owned = set()
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + PROPERTY_REPLY:
                    count = struct.unpack_from("<H", f["body"])[0]
                    owned |= {struct.unpack_from("<I", f["body"], 2 + n * PROPERTY_RECORD + 4)[0] for n in range(count)}
            self.assertNotIn(5023329, owned, name)
            kinds = {f["body"][0] for f in frames if (f["dir"], f["type"], f["action"]) == ("C",) + ADD_ITEM_REQUEST}
            self.assertEqual(kinds, {2}, name)
            self.assertFalse(any(f["body"] == LEVEL_ONE_REWARD_GRANT for f in frames if f["dir"] == "C"))

    def test_claimed_95_state_owns_reward_and_matches_startup_post_claim_value(self):
        for name in self.NAMES:
            frames = capture_frames(name)
            grade = next(f for f in frames if (f["dir"], f["type"], f["action"]) == ("S",) + GRADE_REPLY)["body"]
            values = {grade[1 + 13 * n]: struct.unpack_from("<III", grade, 2 + 13 * n) for n in range(grade[0])}
            owned = set()
            for f in frames:
                if (f["dir"], f["type"], f["action"]) == ("S",) + PROPERTY_REPLY:
                    count = struct.unpack_from("<H", f["body"])[0]
                    owned |= {struct.unpack_from("<I", f["body"], 2 + n * PROPERTY_RECORD + 4)[0] for n in range(count)}
            self.assertEqual(values[95][0] >= 1, REWARD_95_CATALOG in owned, name)   # claimed <=> reward owned
        startup = capture_frames("rf-startup.pcapng")
        grades = [f["body"] for f in startup if (f["dir"], f["type"], f["action"]) == ("S",) + GRADE_REPLY]
        post = {g[1 + 13 * n]: struct.unpack_from("<III", g, 2 + 13 * n) for g in grades[-1:] for n in range(g[0])}
        self.assertEqual(post[95], GRADE_95_CLAIMED)


@unittest.skipUnless((CAPTURES / "rf-boss-baseline.pcapng").exists(), "private captures not present")
class OfficialAvatarUpdateCaptureTests(unittest.TestCase):
    def test_every_update_gets_one_empty_ack_and_names_a_listed_avatar(self):
        totals = {}
        for name in ("rf-startup.pcapng", "rf-empty-buddy.pcapng", "rf-boss-baseline.pcapng"):
            frames = capture_frames(name)
            ids = parse_avatar_list(next(f["body"] for f in frames
                                         if (f["dir"], f["type"], f["action"]) == ("S",) + AVATAR_LIST_REPLY))
            for action, body_bytes in AVATAR_UPDATE_BODY_BYTES.items():
                reqs = [f for f in frames if (f["dir"], f["type"], f["action"]) == ("C", 0x40, action)]
                acks = [f for f in frames if (f["dir"], f["type"], f["action"]) == ("S", 0x40, action + 1)]
                self.assertEqual(len(reqs), len(acks), (name, hex(action)))
                for f in reqs:
                    self.assertEqual(len(f["body"]), body_bytes)
                    self.assertIn(struct.unpack_from("<I", f["body"])[0], ids)
                for f in acks:
                    self.assertEqual(f["body"], b"")
                totals[action] = totals.get(action, 0) + len(reqs)
        self.assertEqual(totals, {0xA2: 3, 0xA4: 23, 0xA6: 1})


@unittest.skipUnless((CAPTURES / "rf-empty-buddy.pcapng").exists(), "private captures not present")
class OfficialCaptureTests(unittest.TestCase):
    def check(self, name, expected_count):
        frames = capture_frames(name)
        index = next(i for i, f in enumerate(frames) if f["dir"] == "C" and (f["type"], f["action"]) == (0x10, 0xA8))
        request = frames[index]
        self.assertEqual(request["body"], bytes(4))
        reply = next(f for f in frames[index:] if f["dir"] == "S" and (f["type"], f["action"]) == BUDDY_REPLY)
        self.assertEqual(reply["total"], len(build_buddy_list()))
        self.assertEqual(struct.unpack_from("<H", reply["body"])[0], expected_count)
        records = parse_buddy_list(reply["body"])
        self.assertEqual(len(records), expected_count)
        for buddy_id, name, trailing in records:
            self.assertTrue(name and name.isprintable())
            self.assertEqual(trailing, b"NF")
        return frames, index

    def test_populated_reply_layout(self):
        self.check("rf-startup.pcapng", 6)

    def test_empty_reply_then_client_continues(self):
        frames, index = self.check("rf-empty-buddy.pcapng", 0)
        later = [f for f in frames[index + 1:] if f["dir"] == "C"]
        self.assertEqual((later[0]["type"], later[0]["action"]), (0x30, 0x86))


if __name__ == "__main__":
    unittest.main()
