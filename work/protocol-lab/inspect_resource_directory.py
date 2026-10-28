"""List bounded ZIP-like NSZ!/ZIP directory metadata without extracting assets.

Original metadata reader. It does not decrypt, decompress, execute or modify
payloads. Opaque/other NSZ variants are explicitly unsupported. Format reference:
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT sections 4.3 and 4.4.
The NSZ! local signature is observed in the supplied files; payload compatibility
with standard ZIP encryption is not established by matching metadata alone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import zlib

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 10000
END = struct.Struct('<4s4H2IH')
CENTRAL = struct.Struct('<4s6H3I5H2I')
LOCAL = struct.Struct('<4s5H3I2H')


class FormatError(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise FormatError(code)


def extras(data: bytes) -> list[dict]:
    result = []
    cursor = 0
    while cursor < len(data):
        require(cursor + 4 <= len(data), 'extra_header_truncated')
        tag, size = struct.unpack_from('<HH', data, cursor)
        cursor += 4
        require(cursor + size <= len(data), 'extra_body_truncated')
        result.append({'tag_hex': f'{tag:04x}', 'bytes': size})
        cursor += size
    return result


def inspect_bytes(data: bytes) -> dict:
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_FILE_BYTES,
            'input_size_out_of_bounds')
    base = {'schema': 'rf-resource-directory-v1', 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'crc32_hex': f'{zlib.crc32(data):08x}',
            'payload_extracted_or_decrypted': False}
    if data[:4] not in (b'NSZ!', b'PK\x03\x04', b'PK\x05\x06'):
        return dict(base, status='unsupported_metadata_layout', entries=[])
    end_at = -1
    for candidate in range(len(data) - END.size, max(-1, len(data) - END.size - 65536), -1):
        if data[candidate:candidate + 4] == b'PK\x05\x06':
            comment_size = struct.unpack_from('<H', data, candidate + 20)[0]
            if candidate + END.size + comment_size == len(data):
                end_at = candidate
                break
    require(end_at >= 0, 'end_record_missing')
    _, disk, directory_disk, disk_count, count, directory_size, directory_at, _ = END.unpack_from(data, end_at)
    require(disk == directory_disk == 0 and disk_count == count, 'split_archive_unsupported')
    require(count <= MAX_ENTRIES and directory_size != 0xffffffff and directory_at != 0xffffffff,
            'entry_limit_or_zip64_unsupported')
    require(directory_at + directory_size == end_at, 'directory_bounds_mismatch')
    entries = []
    occupied = []
    cursor = directory_at
    for _ in range(count):
        require(cursor + CENTRAL.size <= end_at, 'central_header_truncated')
        fields = CENTRAL.unpack_from(data, cursor)
        signature, _, version, flags, method, mtime, mdate, crc, compressed, raw, name_len, extra_len, comment_len, start_disk, _, _, local_at = fields
        require(signature == b'PK\x01\x02', 'central_signature_mismatch')
        require(start_disk == 0 and 0xffffffff not in (compressed, raw, local_at),
                'entry_split_or_zip64_unsupported')
        record_end = cursor + CENTRAL.size + name_len + extra_len + comment_len
        require(record_end <= end_at and name_len > 0, 'central_record_bounds')
        name_bytes = data[cursor + CENTRAL.size:cursor + CENTRAL.size + name_len]
        name = name_bytes.decode('utf-8' if flags & 0x800 else 'cp437', errors='replace')
        central_extra = extras(data[cursor + CENTRAL.size + name_len:cursor + CENTRAL.size + name_len + extra_len])
        require(local_at + LOCAL.size <= directory_at, 'local_header_bounds')
        local = LOCAL.unpack_from(data, local_at)
        local_sig, local_version, local_flags, local_method, local_time, local_date, local_crc, local_compressed, local_raw, local_name_len, local_extra_len = local
        require(local_sig in (b'NSZ!', b'PK\x03\x04'), 'local_signature_unsupported')
        require((version, flags, method, mtime, mdate) == (local_version, local_flags, local_method, local_time, local_date),
                'local_central_fields_mismatch')
        payload_at = local_at + LOCAL.size + local_name_len + local_extra_len
        payload_end = payload_at + compressed
        require(payload_at <= directory_at and payload_end <= directory_at, 'payload_bounds')
        require(data[local_at + LOCAL.size:local_at + LOCAL.size + local_name_len] == name_bytes,
                'local_central_name_mismatch')
        local_extra = extras(data[local_at + LOCAL.size + local_name_len:payload_at])
        descriptor_matches = None
        entry_end = payload_end
        if flags & 8:
            # An unsigned descriptor can have CRC32 equal to the optional
            # signature. Compare both bounded layouts with the directory.
            candidates = [payload_end]
            if data[payload_end:payload_end + 4] == b'PK\x07\x08':
                candidates.append(payload_end + 4)
            matches = [at for at in candidates if at + 12 <= directory_at
                       and struct.unpack_from('<III', data, at) == (crc, compressed, raw)]
            require(bool(matches), 'descriptor_mismatch_or_bounds')
            descriptor_matches = True
            entry_end = matches[0] + 12
            require((local_crc in (0, crc) and local_compressed in (0, compressed) and local_raw in (0, raw)),
                    'local_descriptor_values_mismatch')
        else:
            require((local_crc, local_compressed, local_raw) == (crc, compressed, raw),
                    'local_central_sizes_mismatch')
        occupied.append((local_at, entry_end))
        normalized = name.replace('\\', '/')
        unsafe_path = normalized.startswith('/') or '..' in PurePosixPath(normalized).parts or ':' in normalized or '\x00' in name
        entries.append({'name': name, 'unsafe_path_for_extraction': unsafe_path,
                        'local_header_offset': local_at, 'data_offset': payload_at,
                        'compressed_bytes': compressed, 'uncompressed_bytes': raw,
                        'entry_crc32_hex': f'{crc:08x}', 'flags_hex': f'{flags:04x}',
                        'standard_zip_encryption_bit': bool(flags & 1),
                        'compression_method': method, 'local_extra_fields': local_extra,
                        'central_extra_fields': central_extra,
                        'descriptor_matches_directory': descriptor_matches})
        cursor = record_end
    require(cursor == end_at, 'directory_size_or_count_mismatch')
    occupied.sort()
    require(all(previous[1] <= following[0] for previous, following in zip(occupied, occupied[1:])),
            'overlapping_entries')
    return dict(base, status='metadata_validated_payload_unverified',
                entry_count=count, directory_offset=directory_at, entries=entries)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', type=Path)
    args = parser.parse_args()
    reports = []
    for path in args.files:
        try:
            with path.open('rb') as handle:
                report = inspect_bytes(handle.read(MAX_FILE_BYTES + 1))
        except FormatError as exc:
            report = {'status': 'unsupported_or_invalid_metadata', 'error_code': str(exc)}
        except OSError:
            report = {'status': 'input_unreadable'}
        reports.append(dict(report, file_name=path.name))
    print(json.dumps({'files': reports}, indent=2))


if __name__ == '__main__':
    main()
