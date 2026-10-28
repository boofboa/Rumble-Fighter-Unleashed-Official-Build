"""Post-login lobby list codecs, derived from user-supplied official captures.

Buddy list (client 0x10/0xA8, 4-byte body; server 0x10/0xA9, 3008 bytes total):
  LE16 count, then BUDDY_CAPACITY fixed 30-byte records:
  LE32 id, 24-byte NUL-padded name, 2 trailing bytes (b"NF" in every observed
  populated record; meaning not established).
Evidence: rf-startup (count 6) and rf-empty-buddy (count 0, client continued).
The official server leaves unused record slots uninitialized; zeros are sent here.
"""
from __future__ import annotations

import struct

from protocol_probe import encode_frame

BUDDY_REQUEST = (0x10, 0xA8)
BUDDY_REPLY = (0x10, 0xA9)
BUDDY_CAPACITY = 100
BUDDY_RECORD = struct.Struct("<I24s2s")  # 30 bytes
BUDDY_BODY_BYTES = 2 + BUDDY_CAPACITY * BUDDY_RECORD.size  # 3002


def build_buddy_list(buddies: list[tuple[int, str, bytes]] = ()) -> bytes:
    """buddies: (id, name, trailing two bytes). Empty list is the verified case."""
    if len(buddies) > BUDDY_CAPACITY:
        raise ValueError("Buddy list exceeds the fixed 100-record capacity")
    body = bytearray(BUDDY_BODY_BYTES)
    struct.pack_into("<H", body, 0, len(buddies))
    for index, (buddy_id, name, trailing) in enumerate(buddies):
        raw = name.encode("ascii")
        if not raw or len(raw) >= 24 or len(trailing) != 2:
            raise ValueError("Buddy name must be 1-23 ASCII bytes; trailing field 2 bytes")
        BUDDY_RECORD.pack_into(body, 2 + index * BUDDY_RECORD.size, buddy_id, raw, trailing)
    return encode_frame(*BUDDY_REPLY, bytes(body))


AVATAR_LIST_REQUEST = (0x30, 0x86)  # body: LE32 account ID (= login account)
AVATAR_LIST_REPLY = (0x30, 0x87)    # body: count byte + 20 LE32 avatar IDs (81)
AVATAR_CAPACITY = 20
EQUIPPED_REQUEST = (0x40, 0xA0)     # no body
EQUIPPED_REPLY = (0x40, 0xA1)       # body: LE32 avatar ID, one of the listed IDs
EQUIPMENT_REQUEST = (0x30, 0x88)    # body: LE32 avatar ID; once per listed avatar, in order
EQUIPMENT_REPLY = (0x30, 0x89)      # body: 45 LE32 item-instance refs + 180-byte tail
EQUIPMENT_SLOTS = 45
EQUIPMENT_TAIL_BYTES = 180  # zero in every observed reply; meaning unknown


def build_avatar_list(avatar_ids: list[int]) -> bytes:
    if len(avatar_ids) > AVATAR_CAPACITY or any(not 0 < x < 2**32 for x in avatar_ids):
        raise ValueError("1-20 non-zero LE32 avatar IDs")
    ids = list(avatar_ids) + [0] * (AVATAR_CAPACITY - len(avatar_ids))
    return encode_frame(*AVATAR_LIST_REPLY, bytes([len(avatar_ids)]) + struct.pack("<20I", *ids))


def parse_avatar_list(body: bytes) -> list[int]:
    if len(body) != 1 + 4 * AVATAR_CAPACITY or body[0] > AVATAR_CAPACITY:
        raise ValueError("Unexpected avatar list body")
    return list(struct.unpack_from("<20I", body, 1)[:body[0]])


def build_equipped_avatar(avatar_id: int) -> bytes:
    return encode_frame(*EQUIPPED_REPLY, struct.pack("<I", avatar_id))


def build_avatar_equipment(refs: list[int] = ()) -> bytes:
    """refs: up to 45 item-instance references in slot order; unused slots are 0."""
    if len(refs) > EQUIPMENT_SLOTS:
        raise ValueError("At most 45 equipment slots")
    slots = list(refs) + [0] * (EQUIPMENT_SLOTS - len(refs))
    return encode_frame(*EQUIPMENT_REPLY, struct.pack("<45I", *slots) + bytes(EQUIPMENT_TAIL_BYTES))


def parse_avatar_equipment(body: bytes) -> list[int]:
    if len(body) != 4 * EQUIPMENT_SLOTS + EQUIPMENT_TAIL_BYTES:
        raise ValueError("Unexpected equipment body")
    return list(struct.unpack_from("<45I", body))


# Avatar update requests: body starts with a listed LE32 avatar ID. Every captured
# occurrence (A2 x3, A4 x23, A6 x1) got exactly one header-only ack (action + 1).
AVATAR_UPDATE_BODY_BYTES = {0xA2: 4, 0xA4: 9, 0xA6: 5}


def build_avatar_update_ack(request_action: int) -> bytes:
    if request_action not in AVATAR_UPDATE_BODY_BYTES:
        raise ValueError("Not an avatar update request")
    return encode_frame(0x40, request_action + 1)


# Inventory page (30/85, 3928 bytes): LE16 count, then 80 x 49-byte records.
# Gemnet-derived record layout, length-checked on captures; field meanings beyond
# instance/catalog are unresolved: +0 instance LE32, +4 catalog LE32, +8 unknown
# LE32 (shared category-like code), +12..28 opaque, +29 item_end LE32,
# +33 stat LE32, +37..48 opaque. The client requests another page while count == 80.
PROPERTY_REPLY = (0x30, 0x85)
PROPERTY_CAPACITY = 80
PROPERTY_RECORD = 49


def build_property_page(records: list[tuple[int, int, int, int, int]]) -> bytes:
    """records: (instance_id, catalog_id, word8, item_end, stat); other bytes zero."""
    if len(records) > PROPERTY_CAPACITY:
        raise ValueError("At most 80 records per page")
    body = bytearray(2 + PROPERTY_CAPACITY * PROPERTY_RECORD)
    struct.pack_into("<H", body, 0, len(records))
    for n, (instance, catalog, word8, end, stat) in enumerate(records):
        if not instance:
            raise ValueError("Instance IDs are non-zero")
        base = 2 + n * PROPERTY_RECORD
        struct.pack_into("<III", body, base, instance, catalog, word8)
        struct.pack_into("<II", body, base + 29, end, stat)
    return encode_frame(*PROPERTY_REPLY, bytes(body))


# v1.13/1.14 local fixture (see RFHandshakeProbe.BuildLocalClassPropertyResponse).
LOCAL_CLASS_INSTANCE = 1001
CLASS_FIXTURE_RECORD = (LOCAL_CLASS_INSTANCE, 1000176, 20046, 0, 0)
LOCAL_ROD_INSTANCE = 1002
FISHING_ROD_CATALOG = 5135224
ROD_FIXTURE_RECORD = (LOCAL_ROD_INSTANCE, FISHING_ROD_CATALOG, 85582, 1000, 0)  # opaque zero: candidate
# v1.18: default Exo of class 1000176 (Soul Fighter (M)); exact rf-boss-baseline record
# profile (+8 85582, end 1000, stat 0, all opaque zero); owned, never equipped.
LOCAL_EXO_INSTANCE = 1003
SOUL_FIGHTER_DEFAULT_EXO = 2040035
EXO_FIXTURE_RECORD = (LOCAL_EXO_INSTANCE, SOUL_FIGHTER_DEFAULT_EXO, 85582, 1000, 0)


def parse_add_item_request(body: bytes) -> dict:
    """31/8A body. Two observed shapes: medal claim 02 <channel> 00*8 (official
    captures) and item grant 00 00 <LE32 catalog> <LE16 1000> 00 00 (v1.17 client
    lacking its default Exo). Field names beyond that are not established."""
    if len(body) != 10:
        raise ValueError("ADD_ITEM body is 10 bytes")
    if body[0] == 2 and body[2:] == bytes(8):
        return {"kind": "medal_claim", "channel": body[1]}
    if body[0] in (0, 1) and body[1] == 0 and body[8:] == b"\0\0":
        # kind 0: missing default-Exo grant (v1.17); kind 1: GetLevelUpItem (v1.20 log).
        return {"kind": "item_grant" if body[0] == 0 else "level_up_grant",
                "catalog": struct.unpack_from("<I", body, 2)[0],
                "u16_at_6": struct.unpack_from("<H", body, 6)[0]}
    return {"kind": "unknown"}


# v1.21: the exact GetLevelUpItem body of the fresh local account (3/3 v1.20 runs).
LEVEL_ONE_REWARD_GRANT = bytes.fromhex("010061a64c00e8030000")

# 30/A0 -> 30/A1 (GET_GRADE in Gemnet naming): u8 count + count x 13-byte records.
GRADE_REQUEST, GRADE_REPLY, GRADE_RECORD = (0x30, 0xA0), (0x30, 0xA1), 13
# 30/B4 (LE32 index 1..5 in order) -> 30/B5 (19-byte body; all-zero bodies observed).
B4_REQUEST, B4_REPLY, B4_REPLY_BODY = (0x30, 0xB4), (0x30, 0xB5), 19
# 48/42 GameGuard answer from the client: the official server never replies.
GUARD_ANSWER = (0x48, 0x42)


# v1.15: the 25 grade IDs common to all captures and observed with all-zero values.
# v1.16: + 95 (the channel the v1.15 client requested via 31/8C) with (0, 0, 2), its
# exact values in the first rf-startup reply. Initial values for a fresh channel are
# not observable in the captures.
LOCAL_GRADE_IDS = (1, 2, 3, 5, 10, 11, 12, 30, 31, 32, 33, 34, 50, 55, 56, 80, 81, 90, 93, 94,
                   95, 96, 99, 100, 109, 123)
LOCAL_GRADE_VALUES = {95: (0, 0, 2)}
GRADE_UP_REQUEST = (0x31, 0x8C)  # 1-byte body: grade/medal ID the client wants created


def build_grade_list(records: list[tuple[int, int, int, int]]) -> bytes:
    """records: (u8 id, LE32 a, LE32 b, LE32 c), ascending ids."""
    if len(records) > 255 or [r[0] for r in records] != sorted({r[0] for r in records}):
        raise ValueError("At most 255 records with unique ascending IDs")
    body = bytes([len(records)]) + b"".join(struct.pack("<BIII", *r) for r in records)
    return encode_frame(*GRADE_REPLY, body)


def build_local_grade_list() -> bytes:
    return build_grade_list([(i,) + LOCAL_GRADE_VALUES.get(i, (0, 0, 0)) for i in LOCAL_GRADE_IDS])


# ADD_ITEM 31/8A (Gemnet name; here a medal-channel claim): 10-byte body, byte 0 = 2,
# byte 1 = channel ID. Failure reply 31/18B (action 0x18B): LE16 code + "FAIL(unknown)" NUL,
# total 520. Success 31/8B (47-byte body, echoes bytes 0-1) has unidentified fields.
ADD_ITEM_REQUEST, ADD_ITEM_FAILURE, ADD_ITEM_SUCCESS = (0x31, 0x8A), (0x31, 0x18B), (0x31, 0x8B)
CHANNEL_100_CLAIM = bytes([2, 100]) + bytes(8)


def build_add_item_failure(code: int) -> bytes:
    body = bytearray(514)
    struct.pack_into("<H", body, 0, code)
    body[2:2 + 13] = b"FAIL(unknown)"
    return encode_frame(*ADD_ITEM_FAILURE, bytes(body))


# v1.20 lobby. 10/B6 body 01 -> type 0x210 action 0xB7 body 01 (11/11 identical).
B6_REQUEST, B6_REPLY = (0x10, 0xB6), (0x210, 0xB7)
# 40/84 room poll (body constant) -> 40/85: u16 0, u16 first room no., u16 0,
# u16 0x8000|last room no., u16 N, then N x 223-byte rooms (contain player names:
# never replayed). N = 0 never observed: the empty list below is UNVERIFIED.
ROOM_POLL, ROOM_LIST = (0x40, 0x84), (0x40, 0x85)
ROOM_POLL_BODY = bytes.fromhex("0a00000000000046")
ROOM_HEADER, ROOM_RECORD = 10, 223
REWARD_95_CATALOG = 3043117
GRADE_95_CLAIMED = (1, 1, 2)   # rf-startup value right after its official 95 claim


# v1.22: 30/CE UpdateQuest (12-byte body) -> 30/CF echoing the body (2/2 captured).
QUEST_UPDATE, QUEST_UPDATE_ACK = (0x30, 0xCE), (0x30, 0xCF)


def build_quest_update_ack(request_body: bytes) -> bytes:
    if len(request_body) != 12:
        raise ValueError("UpdateQuest body is 12 bytes")
    return encode_frame(*QUEST_UPDATE_ACK, request_body)


def build_b6_reply() -> bytes:
    return encode_frame(*B6_REPLY, b"\x01")


def build_empty_room_list() -> bytes:
    return encode_frame(*ROOM_LIST, bytes(ROOM_HEADER))


def build_empty_grade_list() -> bytes:
    """v1.14 candidate; the real client then requested grade creation (31/8C)."""
    return build_grade_list([])


def build_zero_b4_status() -> bytes:
    return encode_frame(*B4_REPLY, bytes(B4_REPLY_BODY))


def parse_buddy_list(body: bytes) -> list[tuple[int, str, bytes]]:
    if len(body) != BUDDY_BODY_BYTES:
        raise ValueError("Unexpected buddy reply body length")
    count = struct.unpack_from("<H", body)[0]
    if count > BUDDY_CAPACITY:
        raise ValueError("Buddy count exceeds capacity")
    out = []
    for index in range(count):
        buddy_id, name, trailing = BUDDY_RECORD.unpack_from(body, 2 + index * BUDDY_RECORD.size)
        out.append((buddy_id, name.split(b"\0", 1)[0].decode("ascii", "replace"), trailing))
    return out
