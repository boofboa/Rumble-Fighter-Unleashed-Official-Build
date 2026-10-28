"""Original codecs for an experimental, separate local RF test account.

Evidence: public reference Login.cs offsets and sanitized capture frame lengths.
These codecs do not use captured credentials, account values, or session tokens.

IMPORTANT: the 326-byte success response is experimental. Bytes 42..96 are
unmapped by the public reference, and current captured traffic does not justify
calling that range padding. This implementation explicitly leaves it zero.
The account's ``cash`` value is validated but is NOT guessed into that range.
GUID tail bytes 134..149 and bytes 154..157 are also left zero.
A valid frame is not evidence that the client reaches a lobby or playable game.
"""
from __future__ import annotations

from collections.abc import Mapping
import struct
import uuid

LOGIN_REQUEST_BODY_LENGTH = 85
LOGIN_SUCCESS_LENGTH = 326
LOGIN_FAILURE_LENGTH = 520
LOGIN_RESPONSE_EXPERIMENTAL = True
UNRESOLVED_LOGIN_RANGES = ((42, 97), (134, 150), (154, 158))
MAX_SIGNED_INT32 = (1 << 31) - 1


class LoginWireError(ValueError):
    """Invalid local field or wire shape; messages never include field values."""


def _ascii_string(value: object, name: str, maximum: int, *, nonempty: bool = True) -> bytes:
    if not isinstance(value, str):
        raise LoginWireError(f'{name} must be a string')
    try:
        encoded = value.encode('ascii')
    except UnicodeEncodeError:
        raise LoginWireError(f'{name} must contain ASCII characters only') from None
    if (nonempty and not encoded) or len(encoded) > maximum:
        raise LoginWireError(f'{name} has an invalid encoded length')
    if any(byte < 32 or byte > 126 for byte in encoded):
        raise LoginWireError(f'{name} contains a disallowed control character')
    return encoded


def _read_fixed_ascii(slot: bytes, name: str, maximum: int) -> str:
    terminator = slot.find(b'\0')
    if terminator < 0:
        raise LoginWireError(f'{name} is not NUL-terminated')
    # Bytes after NUL may contain stale client buffer data; they are neither
    # part of the credential nor required to be zero by the reference parser.
    try:
        value = slot[:terminator].decode('ascii')
    except UnicodeDecodeError:
        raise LoginWireError(f'{name} must contain ASCII characters only') from None
    _ascii_string(value, name, maximum)
    return value


def parse_login(body: bytes) -> tuple[str, str]:
    """Read exactly the 85-byte body; return local email/password privately.

    Body offsets: email 0..63, password 64..84. The reference reads only the
    first 63 bytes of the email slot, so a conservative maximum of 62 content
    bytes leaves its terminator within that window. Password maximum is 20.
    Trailing bytes after NUL are ignored within each bounded slot; current
    client requests do not consistently zero-fill them. This parser does not
    establish the official client's full set of accepted input characters.
    Never log or persist the returned password as plaintext.
    """
    if not isinstance(body, bytes) or len(body) != LOGIN_REQUEST_BODY_LENGTH:
        raise LoginWireError('Login body must be exactly 85 bytes')
    return (_read_fixed_ascii(body[:64], 'email', 62),
            _read_fixed_ascii(body[64:], 'password', 20))


def _required(account: Mapping, field: str) -> object:
    try:
        return account[field]
    except KeyError:
        raise LoginWireError(f'Missing local account field: {field}') from None


def _integer(account: Mapping, field: str, *, positive: bool = False) -> int:
    value = _required(account, field)
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= MAX_SIGNED_INT32:
        raise LoginWireError(f'{field} must fit the permitted signed 32-bit range')
    return value


def _put_string(buffer: bytearray, offset: int, width: int, encoded: bytes) -> None:
    # Caller has checked content size; preserve a terminator within the slot.
    if len(encoded) >= width:
        raise LoginWireError('Internal fixed-width string bounds error')
    buffer[offset:offset + len(encoded)] = encoded
    buffer[offset + len(encoded)] = 0


def _frame_header(frame_type: int, total: int, action: int) -> bytes:
    return struct.pack('>HH', frame_type, total) + struct.pack('<H', action)


def serialize_login(account: Mapping, token: str) -> bytes:
    """Return full 326-byte 0x0010/0x0085 frame using NEW local account data.

    Required account fields: account_id, display_name, experience, carats,
    cash, medals, guid, country, region. cash is deliberately not serialized:
    its current login offset has not been established. The display name is
    reused as the local forum name. UUID must be canonical hyphenated text.
    All string maxima reserve one byte for NUL; no silent truncation occurs.
    """
    if not isinstance(account, Mapping):
        raise LoginWireError('Local account must be a mapping')
    values = {
        'account_id': _integer(account, 'account_id', positive=True),
        'experience': _integer(account, 'experience'),
        'carats': _integer(account, 'carats'),
        'medals': _integer(account, 'medals'),
    }
    _integer(account, 'cash')  # Validate, but do not invent its wire offset.
    display = _ascii_string(_required(account, 'display_name'), 'display_name', 23)
    guid = _ascii_string(_required(account, 'guid'), 'guid', 36)
    try:
        parsed_uuid = uuid.UUID(guid.decode('ascii'))
    except (ValueError, AttributeError):
        raise LoginWireError('guid must be a canonical hyphenated UUID') from None
    if len(guid) != 36 or str(parsed_uuid) != guid.decode('ascii').lower():
        raise LoginWireError('guid must be a canonical hyphenated UUID')
    country = _ascii_string(_required(account, 'country'), 'country', 7)
    region = _ascii_string(_required(account, 'region'), 'region', 31)
    token_bytes = _ascii_string(token, 'token', 63)

    frame = bytearray(LOGIN_SUCCESS_LENGTH)
    frame[:6] = _frame_header(0x0010, LOGIN_SUCCESS_LENGTH, 0x0085)
    for field, offset in [('account_id', 6), ('experience', 34), ('carats', 38), ('medals', 150)]:
        struct.pack_into('<i', frame, offset, values[field])
    for offset, width, value in [(10, 24, display), (97, 37, guid),
                                 (158, 8, country), (166, 32, region),
                                 (198, 64, token_bytes), (262, 64, display)]:
        _put_string(frame, offset, width, value)
    return bytes(frame)


def serialize_failure(message: str) -> bytes:
    """Return full 520-byte 0x0210/0x0285 local login-failure frame.

    Public reference's effective layout is a 16-bit code at frame offset 6
    and a 512-byte ASCII message slot at offset 8. The reference's temporary
    32-bit write is partially overwritten by its text; it is not copied here.
    """
    encoded = _ascii_string(message, 'failure_message', 511)
    frame = bytearray(LOGIN_FAILURE_LENGTH)
    frame[:6] = _frame_header(0x0210, LOGIN_FAILURE_LENGTH, 0x0285)
    struct.pack_into('<H', frame, 6, 29374)  # Public reference failure code.
    _put_string(frame, 8, 512, encoded)
    return bytes(frame)
