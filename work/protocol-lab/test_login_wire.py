"""Synthetic-only boundary tests; no production capture or credentials used."""
import struct
import unittest

from login_wire import (LoginWireError, MAX_SIGNED_INT32, UNRESOLVED_LOGIN_RANGES,
                        parse_login, serialize_failure, serialize_login)


def local_account(**changes):
    result = dict(account_id=7, display_name='LocalTester', experience=12,
                  carats=345, cash=678, medals=9,
                  guid='12345678-1234-5678-9234-123456789abc', country='US', region='NA')
    result.update(changes)
    return result


def request_body(email=b'tester@example.test', password=b'local-only-pass'):
    return email.ljust(64, b'\0') + password.ljust(21, b'\0')


class LoginRequestTests(unittest.TestCase):
    def test_local_request(self):
        self.assertEqual(parse_login(request_body()), ('tester@example.test', 'local-only-pass'))

    def test_boundaries(self):
        self.assertEqual(parse_login(request_body(b'e' * 62, b'p' * 20)), ('e' * 62, 'p' * 20))
        for body in [request_body(b'e' * 63), request_body(b'e' * 64),
                     request_body(password=b'p' * 21), b'', request_body()[:-1],
                     request_body() + b'\0', bytearray(request_body())]:
            with self.subTest(length=len(body)), self.assertRaises(LoginWireError):
                parse_login(body)

    def test_invalid_strings(self):
        for email, password in [(b'', b'pass'), (b'email', b''),
                                (b'x\xff', b'pass'), (b'email', b'p\xff'),
                                (b'x\n', b'pass'), (b'email', b'p\t')]:
            with self.subTest(case='synthetic-invalid'), self.assertRaises(LoginWireError):
                parse_login(request_body(email, password))

    def test_trailing_client_buffer_bytes_are_ignored(self):
        self.assertEqual(parse_login(request_body(b'email\0stale', b'pass\0stale')),
                         ('email', 'pass'))
        self.assertEqual(parse_login(request_body(b'email\0\xff', b'pass\0\xfe')),
                         ('email', 'pass'))


class LoginSuccessTests(unittest.TestCase):
    def test_layout_and_unresolved_ranges(self):
        frame = serialize_login(local_account(), 'local-session')
        self.assertEqual(len(frame), 326)
        self.assertEqual(frame[:6], b'\x00\x10\x01\x46\x85\x00')
        for offset, expected in [(6, 7), (34, 12), (38, 345), (150, 9)]:
            self.assertEqual(struct.unpack_from('<i', frame, offset)[0], expected)
        for offset, width, expected in [(10, 24, b'LocalTester'),
                                       (97, 37, b'12345678-1234-5678-9234-123456789abc'),
                                       (158, 8, b'US'), (166, 32, b'NA'),
                                       (198, 64, b'local-session'), (262, 64, b'LocalTester')]:
            self.assertEqual(frame[offset:offset + width], expected.ljust(width, b'\0'))
        for start, stop in UNRESOLVED_LOGIN_RANGES:
            self.assertEqual(frame[start:stop], b'\0' * (stop - start))
        self.assertEqual(frame, serialize_login(local_account(cash=0), 'local-session'))

    def test_string_and_integer_maxima(self):
        account = local_account(display_name='x' * 23, country='C' * 7, region='R' * 31,
                                account_id=MAX_SIGNED_INT32, experience=MAX_SIGNED_INT32,
                                carats=MAX_SIGNED_INT32, cash=MAX_SIGNED_INT32, medals=MAX_SIGNED_INT32)
        frame = serialize_login(account, 't' * 63)
        for offset in [33, 133, 165, 197, 261]:
            self.assertEqual(frame[offset], 0)

    def test_integer_rejections(self):
        for field in ['account_id', 'experience', 'carats', 'cash', 'medals']:
            for value in [-1, MAX_SIGNED_INT32 + 1, True, 1.0, '1', None]:
                with self.subTest(field=field), self.assertRaises(LoginWireError):
                    serialize_login(local_account(**{field: value}), 'local-session')
        with self.assertRaises(LoginWireError):
            serialize_login(local_account(account_id=0), 'local-session')

    def test_string_rejections(self):
        for field, value in [('display_name', 'x' * 24), ('country', 'C' * 8), ('region', 'R' * 32),
                             ('guid', 'invalid'), ('guid', '12345678123456789234123456789abc'),
                             ('display_name', ''), ('display_name', 'name\0tail'),
                             ('country', 'U\n'), ('region', '\u00e9'), ('display_name', 3)]:
            with self.subTest(field=field), self.assertRaises(LoginWireError):
                serialize_login(local_account(**{field: value}), 'local-session')
        for token in ['', 't' * 64, 'x\0tail', '\u00e9', 1]:
            with self.assertRaises(LoginWireError):
                serialize_login(local_account(), token)

    def test_missing_mapping_and_private_error(self):
        account = local_account()
        del account['experience']
        with self.assertRaises(LoginWireError):
            serialize_login(account, 'local-session')
        with self.assertRaises(LoginWireError):
            serialize_login([], 'local-session')
        secret = 'SYNTHETIC_PRIVATE_SENTINEL\0'
        try:
            serialize_login(local_account(), secret)
        except LoginWireError as exc:
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', str(exc))
        else:
            self.fail('Expected malformed token rejection')


class LoginFailureTests(unittest.TestCase):
    def test_failure_layout_and_boundary(self):
        frame = serialize_failure('Local login failed')
        self.assertEqual(len(frame), 520)
        self.assertEqual(frame[:6], b'\x02\x10\x02\x08\x85\x02')
        self.assertEqual(struct.unpack_from('<H', frame, 6)[0], 29374)
        self.assertEqual(frame[8:], b'Local login failed'.ljust(512, b'\0'))
        self.assertEqual(serialize_failure('x' * 511)[-1], 0)
        for message in ['x' * 512, '', 'x\0tail', '\u00e9', 1]:
            with self.assertRaises(LoginWireError):
                serialize_failure(message)


if __name__ == '__main__':
    unittest.main()
