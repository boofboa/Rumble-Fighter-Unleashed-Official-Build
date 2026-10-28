"""Read-only, selective inventory analysis of an ordered RF server TCP stream.

Outputs candidate product/catalog IDs and aggregate layout evidence. Account
IDs, item-instance IDs, avatar IDs, credentials, session values and raw record
bytes are never output. Bodies outside property/equipment responses are not
decrypted. This is a partial observed inventory catalog, never a complete game
catalog or an item-grant tool. Input must be an already reassembled, gap-free
server-to-client stream using the demonstrated legacy cipher.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from protocol_probe import RC4


MAX_INPUT_BYTES = 32 * 1024 * 1024
PUBLIC_STARTERS = {
    1000175: "Striker (M)",
    2040034: "Default Striker Exo",
    5135224: "Fishing Rod",
}


def _distribution(values):
    return [{"value": value, "records": count}
            for value, count in sorted(Counter(values).items())]


def inspect_inventory(stream: bytes) -> dict:
    if not isinstance(stream, bytes) or not 0 < len(stream) <= MAX_INPUT_BYTES:
        raise ValueError("Expected a bounded nonempty encrypted TCP stream")
    cipher = RC4(b"abcde")
    offset = 0
    frames = 0
    pages = []
    equipment = []
    catalog_ids = set()
    instance_ids = set()
    active_records = []
    duplicate_instances = 0
    while offset < len(stream):
        if len(stream) - offset < 6 or frames >= 100_000:
            raise ValueError("Incomplete frame header or frame limit")
        header = cipher.apply(stream[offset:offset + 6])
        kind, length = struct.unpack_from(">HH", header)
        action = struct.unpack_from("<H", header, 4)[0]
        if length < 6 or offset + length > len(stream):
            raise ValueError("Invalid or truncated frame length")
        body_size = length - 6
        selected = (kind, action) in ((0x30, 0x85), (0x30, 0x89))
        if selected:
            body = cipher.apply(stream[offset + 6:offset + length])
        else:
            # Advance the keystream without decrypting unrelated payloads.
            cipher.apply(bytes(body_size))
        if (kind, action) == (0x30, 0x85):
            if body_size != 3922:
                raise ValueError("Unsupported property-response shape")
            count = struct.unpack_from("<H", body)[0]
            if count > 80:
                raise ValueError("Property count exceeds demonstrated capacity")
            records = [body[2 + i * 49:2 + (i + 1) * 49] for i in range(count)]
            ids = [struct.unpack_from("<I", record, 4)[0] for record in records]
            instances = [struct.unpack_from("<I", record)[0] for record in records]
            if any(value == 0 for value in ids + instances):
                raise ValueError("Active record lacks a positive candidate identifier")
            for instance in instances:
                duplicate_instances += instance in instance_ids
                instance_ids.add(instance)
            catalog_ids.update(ids)
            active_records.extend(records)
            pages.append({
                "stream_frame_offset": offset,
                "logical_record_count": count,
                "distinct_catalog_ids_in_page": len(set(ids)),
                "instance_ids_unique_in_page": len(set(instances)) == len(instances),
                "padding_after_logical_count_all_zero": not any(body[2 + count * 49:]),
                "nonzero_capacity_records": sum(any(body[2 + i * 49:2 + (i + 1) * 49]) for i in range(80)),
            })
        elif (kind, action) == (0x30, 0x89):
            if body_size != 360:
                raise ValueError("Unsupported equipment-response shape")
            references = struct.unpack_from("<45I", body)
            used = [reference for reference in references if reference]
            equipment.append({
                "stream_frame_offset": offset,
                "nonzero_slot_count": len(used),
                "all_nonzero_slots_reference_preceding_inventory_instances": all(reference in instance_ids for reference in used),
                "unknown_180byte_tail_all_zero": not any(body[180:]),
            })
        offset += length
        frames += 1
    if not pages:
        raise ValueError("No demonstrated inventory responses in stream")
    starters = []
    for catalog_id, name in PUBLIC_STARTERS.items():
        records = [record for record in active_records if struct.unpack_from("<I", record, 4)[0] == catalog_id]
        if records:
            starters.append({
                "catalog_id": catalog_id,
                "name_from_public_source": name,
                "observed_records": len(records),
                "record_u32_at_8": _distribution(struct.unpack_from("<I", record, 8)[0] for record in records),
                "record_u32_at_29": _distribution(struct.unpack_from("<I", record, 29)[0] for record in records),
                "record_u32_at_33": _distribution(struct.unpack_from("<I", record, 33)[0] for record in records),
                "unknown_region_12_to_22_all_zero": all(not any(record[12:23]) for record in records),
                "unknown_region_23_to_28_all_zero": all(not any(record[23:29]) for record in records),
                "unknown_region_37_to_48_all_zero": all(not any(record[37:49]) for record in records),
            })
    return {
        "schema": "rf-observed-item-catalog-v1",
        "scope": "Incomplete deduplicated product-ID candidates observed in the user-supplied capture; not the complete game catalog and not a usable item grant",
        "input_stream_sha256": hashlib.sha256(stream).hexdigest(),
        "input_bytes": len(stream),
        "frame_count": frames,
        "record_layout": {"count_body_offset": 0, "count_bytes": 2, "count_endian": "little", "records_body_offset": 2, "record_stride": 49, "capacity": 80, "catalog_id_record_offset": 4},
        "catalog_candidate_count": len(catalog_ids),
        "catalog_candidate_ids": sorted(catalog_ids),
        "names_and_categories_for_remaining_ids": "Unknown; numeric prefixes and asset filenames are not treated as verified category/name mappings",
        "active_record_count": len(active_records),
        "distinct_instance_count": len(instance_ids),
        "duplicate_instance_occurrences": duplicate_instances,
        "pages": pages,
        "equipment": equipment,
        "aggregates": {
            "record_u32_at_8": _distribution(struct.unpack_from("<I", record, 8)[0] for record in active_records),
            "record_u32_at_29": _distribution(struct.unpack_from("<I", record, 29)[0] for record in active_records),
            "record_u32_at_33": _distribution(struct.unpack_from("<I", record, 33)[0] for record in active_records),
            "unknown_region_12_to_28_nonzero_record_count_by_byte_offset": [{"offset": i, "records": sum(record[i] != 0 for record in active_records)} for i in range(12, 29)],
            "unknown_region_37_to_48_all_zero": all(not any(record[37:49]) for record in active_records),
        },
        "public_starter_matches": starters,
        "public_starter_source": "https://github.com/Primitheus/Gemnet/blob/c56f4dccdad72f2d4337ffe6fe650d8c436114d0/Gemnet/PacketProcessors/Login.cs",
        "limits": [
            "Only count, record stride and catalog/instance field placement have strong cross-checks; unnamed integer field semantics remain unknown.",
            "Count controls validity: unused capacity may contain nonzero bytes.",
            "Observed inventory contains only this account's subset, including duplicates of some catalog IDs.",
            "No private instance/account/avatar identifiers or opaque record bytes are included.",
            "Presence in the capture supports product ID compatibility but does not validate an original populated response serializer.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server_stream", type=Path)
    args = parser.parse_args()
    with args.server_stream.open("rb") as handle:
        stream = handle.read(MAX_INPUT_BYTES + 1)
    print(json.dumps(inspect_inventory(stream), indent=2))


if __name__ == "__main__":
    main()
