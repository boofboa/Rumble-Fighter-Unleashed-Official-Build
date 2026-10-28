"""Synthetic wire-contract checks; no capture bodies or game assets are used."""
import struct
import unittest

from character_wire import (
    AvatarEquipment, PropertyRequest, SLOT_NAMES,
    avatar_equipment_response, cash_response, empty_property_response,
    equipped_avatar_response, parse_avatar_equipment_request,
    parse_property_request, require_empty_request,
)


class CharacterWireTests(unittest.TestCase):
    def test_request_widths_and_opaque_property_tail(self):
        # Identifiers above 255 catch the reference's single-byte read bug.
        tail = b"UNKNOWN"
        request = parse_property_request(struct.pack("<i", 1001) + tail)
        self.assertEqual(request.account_id, 1001)
        self.assertEqual(request.opaque_tail, tail)
        self.assertNotIn("UNKNOWN", repr(request))
        self.assertEqual(parse_avatar_equipment_request(struct.pack("<i", 2001)), 2001)
        require_empty_request(b"")
        for size in (0, 4, 10, 12):
            with self.subTest(size=size), self.assertRaises(ValueError):
                parse_property_request(bytes(size))
        for raw in (b"", bytes(3), bytes(5), struct.pack("<i", -1), bytes(4)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                parse_avatar_equipment_request(raw)
        with self.assertRaises(ValueError):
            require_empty_request(b"x")

    def test_empty_inventory_fixed_capacity(self):
        reply = empty_property_response()
        self.assertEqual(reply[:6], bytes.fromhex("00300f588500"))
        self.assertEqual(len(reply), 3928)
        self.assertEqual(reply[6:], bytes(3922))

    def test_equipment_offsets_and_unknown_region(self):
        slots = [0] * 45
        slots[0], slots[10], slots[44] = 1001, 1011, 1045
        avatar = AvatarEquipment(2001, slots)
        slots[0] = 9999  # A caller's mutable list cannot alter the model.
        reply = avatar_equipment_response(avatar)
        self.assertEqual(reply[:6], bytes.fromhex("0030016e8900"))
        self.assertEqual(len(reply), 366)
        self.assertEqual(struct.unpack_from("<i", reply, 6)[0], 1001)
        self.assertEqual(struct.unpack_from("<i", reply, 46)[0], 1011)
        self.assertEqual(struct.unpack_from("<i", reply, 182)[0], 1045)
        self.assertEqual(reply[186:], bytes(180))
        self.assertEqual((SLOT_NAMES[0], SLOT_NAMES[10], SLOT_NAMES[44]),
                         ("Job", "Scroll", "Waist_BP"))
        self.assertEqual(avatar_equipment_response(AvatarEquipment(2001))[6:], bytes(360))

    def test_equipped_avatar_and_cash_field_order(self):
        equipped = equipped_avatar_response(2001)
        self.assertEqual(equipped[:6], bytes.fromhex("0040000aa100"))
        self.assertEqual(equipped[6:], struct.pack("<i", 2001))
        cash = cash_response(1001, 250, 12)
        self.assertEqual(cash[:6], bytes.fromhex("003100128900"))
        self.assertEqual(cash[6:], struct.pack("<3i", 1001, 250, 12))

    def test_reject_unsupported_or_ambiguous_numeric_inputs(self):
        for value in (-1, 1 << 31, True, 1.0):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    cash_response(1, value, 0)
                with self.assertRaises(ValueError):
                    equipped_avatar_response(value)
        with self.assertRaises(ValueError):
            equipped_avatar_response(0)
        with self.assertRaises(ValueError):
            AvatarEquipment(1, (0,) * 44)
        with self.assertRaises(ValueError):
            AvatarEquipment(1, (0,) * 44 + (-1,))
        with self.assertRaises(ValueError):
            PropertyRequest(1, bytes(6))


if __name__ == "__main__":
    unittest.main()
