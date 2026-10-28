"""Local-only integration tests with invented accounts and temporary databases."""
import asyncio
import contextlib
from dataclasses import asdict
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from local_backend import Backend, Session, ProtocolViolation, UnsupportedRequest
from local_store import AccountStore
from protocol_probe import RC4, encode_frame


def credentials(login="one@test.invalid", password="SyntheticPass42!"):
    return login.encode("ascii").ljust(64, b"\0") + password.encode("ascii").ljust(21, b"\0")


class WireClient:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.encrypt, self.decrypt = RC4(b"abcde"), RC4(b"abcde")

    async def send(self, data, split=None):
        wire = self.encrypt.apply(data)
        if split:
            self.writer.write(wire[:split])
            await self.writer.drain()
            await asyncio.sleep(0)
            self.writer.write(wire[split:])
        else:
            self.writer.write(wire)
        await self.writer.drain()

    async def receive(self):
        header = self.decrypt.apply(await asyncio.wait_for(self.reader.readexactly(6), 3))
        kind, length = struct.unpack_from(">HH", header)
        action = struct.unpack_from("<H", header, 4)[0]
        if length < 6:
            raise AssertionError("Invalid server frame length")
        body = self.decrypt.apply(await asyncio.wait_for(self.reader.readexactly(length - 6), 3))
        return kind, action, body

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()


class StoreTests(unittest.TestCase):
    def test_persistence_unique_accounts_salted_hashes_and_avatars(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.sqlite3"
            store = AccountStore(path)
            first = store.create("one@test.invalid", "SyntheticPass42!", "TestOne")
            second = store.create("two@test.invalid", "SyntheticPass42!", "TestTwo")
            with self.assertRaises(ValueError):
                store.create("ONE@test.invalid", "OtherTestPassword", "TestThree")
            reopened = AccountStore(path)
            self.assertEqual(reopened.authenticate("ONE@test.invalid", "SyntheticPass42!"), first)
            self.assertIsNone(reopened.authenticate("one@test.invalid", "WrongPassword"))
            self.assertIsNone(reopened.authenticate("missing@test.invalid", "SyntheticPass42!"))
            self.assertEqual(reopened.count(), 2)
            self.assertNotEqual(reopened.avatar_for(first.account_id), reopened.avatar_for(second.account_id))
            # closing(): sqlite3's own context manager commits but never closes,
            # which leaves the file locked on Windows.
            with contextlib.closing(sqlite3.connect(path)) as db:
                rows =db.execute("SELECT password_salt,password_digest FROM accounts").fetchall()
            self.assertNotEqual(rows[0], rows[1])
            self.assertNotIn(b"SyntheticPass42!", path.read_bytes())

    def test_missing_early_avatar_rows_are_backfilled_without_changing_existing_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "early.sqlite3"
            store = AccountStore(path)
            first = store.create("one@test.invalid", "SyntheticPass42!", "TestOne")
            second = store.create("two@test.invalid", "SyntheticPass42!", "TestTwo")
            second_avatar = store.avatar_for(second.account_id)
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                db.execute("DELETE FROM avatars WHERE account_id=?", (first.account_id,))
            reopened = AccountStore(path)
            first_avatar = reopened.avatar_for(first.account_id)
            self.assertNotEqual(first_avatar, second_avatar)
            self.assertEqual(reopened.avatar_for(second.account_id), second_avatar)
            again = AccountStore(path)
            self.assertEqual(again.avatar_for(first.account_id), first_avatar)
            self.assertEqual(again.authenticate("one@test.invalid", "SyntheticPass42!"), first)


class BackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = AccountStore(Path(self.tmp.name) / "test.sqlite3")
        self.account = await asyncio.to_thread(self.store.create, "one@test.invalid", "SyntheticPass42!", "TestOne")
        self.events = []
        self.backend = Backend(self.store, log=self.events.append)
        self.server = await asyncio.start_server(self.backend.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            await client.close()
        self.server.close()
        await self.server.wait_closed()
        # Give already-open handlers time to observe EOF and finish.
        for _ in range(50):
            if self.backend.active_connections == 0:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.backend.active_connections, 0)
        self.tmp.cleanup()

    async def connect(self):
        client = WireClient(*await asyncio.open_connection("127.0.0.1", self.port))
        self.clients.append(client)
        return client

    async def login(self, client):
        await client.send(encode_frame(0x10, 0x90, bytes(20)) +
                          encode_frame(0x10, 0x84, credentials()), split=3)
        self.assertEqual(await client.receive(), (0x10, 0x91, b""))
        kind, action, body = await client.receive()
        self.assertEqual((kind, action, len(body)), (0x10, 0x85, 320))
        self.assertEqual(struct.unpack_from("<i", body)[0], self.account.account_id)
        self.assertEqual(body[4:28].split(b"\0", 1)[0], b"TestOne")
        return body

    async def test_encrypted_login_profile_and_empty_inventory_roundtrip(self):
        client = await self.connect()
        login_body = await self.login(client)
        avatar = self.store.avatar_for(self.account.account_id)
        await client.send(
            encode_frame(0x40, 0xA0) + encode_frame(0x31, 0x88) +
            encode_frame(0x30, 0x84, struct.pack("<i", self.account.account_id) + b"TAIL123") +
            encode_frame(0x30, 0x88, struct.pack("<i", avatar)))
        self.assertEqual(await client.receive(), (0x40, 0xA1, struct.pack("<i", avatar)))
        self.assertEqual(await client.receive(), (0x31, 0x89, struct.pack("<3i", self.account.account_id, 0, 0)))
        self.assertEqual(await client.receive(), (0x30, 0x85, bytes(3922)))
        self.assertEqual(await client.receive(), (0x30, 0x89, bytes(360)))
        logs = str(self.events)
        for secret in ("one@test.invalid", "SyntheticPass42!", "TestOne",
                       login_body[192:256].split(b"\0", 1)[0].decode("ascii")):
            self.assertNotIn(secret, logs)

    async def test_failed_login_can_retry_without_becoming_authenticated(self):
        client = await self.connect()
        await client.send(encode_frame(0x10, 0x90, bytes(20)))
        await client.receive()
        await client.send(encode_frame(0x10, 0x84, credentials(password="WrongPassword")))
        kind, action, body = await client.receive()
        self.assertEqual((kind, action, len(body)), (0x210, 0x285, 514))
        self.assertNotIn(b"WrongPassword", body)
        await client.send(encode_frame(0x10, 0x84, credentials()))
        self.assertEqual((await client.receive())[:2], (0x10, 0x85))

    async def test_unauthenticated_and_cross_account_queries_are_rejected(self):
        session = Session()
        with self.assertRaises(ProtocolViolation):
            await self.backend.dispatch(session, 0x31, 0x88, b"")
        session.account_id = self.account.account_id
        with self.assertRaises(ProtocolViolation):
            await self.backend.dispatch(session, 0x30, 0x84, struct.pack("<i", self.account.account_id + 1) + bytes(7))
        with self.assertRaises(ProtocolViolation):
            await self.backend.dispatch(session, 0x30, 0x88, struct.pack("<i", self.store.avatar_for(self.account.account_id) + 1))

    async def test_unknown_gameguard_request_closes_without_fake_success(self):
        client = await self.connect()
        await self.login(client)
        await client.send(encode_frame(0x48, 0x80))
        self.assertEqual(await asyncio.wait_for(client.reader.read(1), 2), b"")
        self.assertTrue(any(e.get("event") == "unsupported_request" and e["type"] == "0x0048"
                            for e in self.events))

    async def test_new_connection_resets_cipher_and_requires_new_authentication(self):
        first = await self.connect()
        first_body = await self.login(first)
        second = await self.connect()
        second_body = await self.login(second)
        self.assertNotEqual(first_body[192:256], second_body[192:256])
        third = await self.connect()
        await third.send(encode_frame(0x10, 0x84, credentials()))
        self.assertEqual(await asyncio.wait_for(third.reader.read(1), 2), b"")


if __name__ == "__main__":
    unittest.main()
