"""Original, conservative character wire helpers for local protocol research.

Only response lengths have been compared with the supplied capture. Field
meanings come from public protocol research and remain unverified against the
current client's behavior. No captured account, item, asset or session values
are embedded here. Reserved bytes are synthetic zeros, not captured data.

The caller must authenticate the local session and enforce ownership before
serving any requested account or avatar. This module performs no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct

from protocol_probe import encode_frame


PROPERTY_BODY_BYTES = 3922
EQUIPMENT_BODY_BYTES = 360
EQUIPMENT_SLOT_COUNT = 45
INT32_MAX = (1 << 31) - 1

# Publicly described slot positions; these are local item-instance references,
# not an item catalog or a list of valid game assets.
SLOT_NAMES = (
    "Job", "Hair", "Forehead", "Top", "Bottom", "Gloves", "Shoes", "Eyes",
    "Nose", "Mouth", "Scroll", "ExoA", "ExoB", "Null", "Back", "Neck",
    "Ears", "Glasses", "Mask", "Waist", "Scroll_BU", "Unknown_1", "Unknown_2",
    "Inventory_1", "Inventory_2", "Inventory_3", "Unknown_3", "Unknown_4",
    "Unknown_5", "Unknown_6", "Unknown_7", "Title", "Merit", "Avalon",
    "Hair_BP", "Top_BP", "Bottom_BP", "Gloves_BP", "Shoes_BP", "Back_BP",
    "Neck_BP", "Ears_BP", "Glasses_BP", "Mask_BP", "Waist_BP",
)


def _integer(value: int, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= INT32_MAX:
        raise ValueError(f"{label} must fit the supported nonnegative int32 range")
    return value


def _request(body: bytes, size: int, label: str) -> bytes:
    if not isinstance(body, (bytes, bytearray, memoryview)) or len(body) != size:
        raise ValueError(f"{label} has an unsupported body length")
    return bytes(body)


@dataclass(frozen=True)
class PropertyRequest:
    account_id: int
    opaque_tail: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _integer(self.account_id, "Account identifier", positive=True)
        object.__setattr__(self, "opaque_tail", _request(self.opaque_tail, 7, "Property tail"))


@dataclass(frozen=True)
class AvatarEquipment:
    avatar_id: int
    slot_server_ids: tuple[int, ...] = (0,) * EQUIPMENT_SLOT_COUNT

    def __post_init__(self) -> None:
        _integer(self.avatar_id, "Avatar identifier", positive=True)
        if not isinstance(self.slot_server_ids, (tuple, list)):
            raise ValueError("Equipment slots must be a fixed sequence")
        slots = tuple(self.slot_server_ids)
        if len(slots) != EQUIPMENT_SLOT_COUNT:
            raise ValueError("Equipment must contain exactly 45 slots")
        for value in slots:
            _integer(value, "Equipment instance identifier")
        object.__setattr__(self, "slot_server_ids", slots)


def parse_property_request(body: bytes) -> PropertyRequest:
    """Parse observed 30/84 shape: owner LE32 plus seven uninterpreted bytes.

    The tail is neither interpreted as pagination nor required to be zero.
    The caller must compare account_id with the authenticated local account.
    """
    raw = _request(body, 11, "Property request")
    return PropertyRequest(struct.unpack_from("<i", raw)[0], raw[4:])


def parse_avatar_equipment_request(body: bytes) -> int:
    """Parse observed 30/88 shape; ownership checks belong to the caller."""
    raw = _request(body, 4, "Avatar equipment request")
    return _integer(struct.unpack("<i", raw)[0], "Avatar identifier", positive=True)


def require_empty_request(body: bytes) -> None:
    """Validate the observed body shape for 31/88 and 40/A0 requests."""
    _request(body, 0, "Empty request")


def empty_property_response() -> bytes:
    """Return 30/85 with zero count and zeroed fixed-capacity inventory body.

    No populated item serializer is provided: most of each 49-byte record is
    unidentified, and public reference fields contain overlapping writes.
    """
    return encode_frame(0x30, 0x85, bytes(PROPERTY_BODY_BYTES))


def avatar_equipment_response(avatar: AvatarEquipment) -> bytes:
    """Return 30/89: 45 LE32 slot references and 180 synthetic zero bytes.

    avatar_id identifies the caller's model but is not serialized in this
    response. The current client's acceptance of the zeroed tail is unproven.
    """
    if not isinstance(avatar, AvatarEquipment):
        raise ValueError("An AvatarEquipment model is required")
    body = bytearray(EQUIPMENT_BODY_BYTES)
    struct.pack_into("<45i", body, 0, *avatar.slot_server_ids)
    return encode_frame(0x30, 0x89, bytes(body))


def equipped_avatar_response(avatar_id: int) -> bytes:
    """Return 40/A1 containing the authenticated account's local avatar ID."""
    value = _integer(avatar_id, "Avatar identifier", positive=True)
    return encode_frame(0x40, 0xA1, struct.pack("<i", value))


def cash_response(account_id: int, cash: int, medals: int) -> bytes:
    """Return 31/89 with account ID, cash and medals as three LE32 values."""
    values = (
        _integer(account_id, "Account identifier", positive=True),
        _integer(cash, "Cash balance"),
        _integer(medals, "Medal balance"),
    )
    return encode_frame(0x31, 0x89, struct.pack("<3i", *values))
