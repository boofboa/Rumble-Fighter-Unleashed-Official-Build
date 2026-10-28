"""Original loopback-only RF account protocol laboratory.

This implements a subset of reference-derived messages, not a playable server.
Unknown requests, including GameGuard, stop the session rather than returning
invented success. No captured account, token, asset, or response is replayed.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass
import getpass
import itertools
import json
from pathlib import Path
import secrets
import sqlite3
import sys
from typing import Callable

from protocol_probe import RC4, FrameStream
from handshake_probe import response as handshake_response
from local_store import AccountStore
from login_wire import parse_login, serialize_login, serialize_failure
from character_wire import (AvatarEquipment, parse_property_request,
                            parse_avatar_equipment_request, require_empty_request,
                            empty_property_response, avatar_equipment_response,
                            equipped_avatar_response, cash_response)

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "state" / "rf-local.sqlite3"
KEY = b"abcde"


class ProtocolViolation(ValueError):
    pass


class UnsupportedRequest(Exception):
    pass


@dataclass
class Session:
    version_seen: bool = False
    account_id: int | None = None
    failed_logins: int = 0


class Backend:
    def __init__(self, store: AccountStore, clock_offset_hours: int = -7,
                 log: Callable[[dict], None] | None = None):
        self.store = store
        self.clock_offset_hours = clock_offset_hours
        self.log = log or (lambda event: print(json.dumps(event), flush=True))
        self.connection_ids = itertools.count(1)
        self.active_connections = 0

    async def dispatch(self, session: Session, frame_type: int,
                       action: int, body: bytes) -> bytes:
        request = (frame_type, action)
        if request == (0x10, 0x90):
            if session.account_id is not None:
                raise ProtocolViolation("Version request after authentication")
            result = handshake_response(frame_type, action, body, self.clock_offset_hours)
            session.version_seen = True
            return result
        if request == (0x10, 0x92):
            return handshake_response(frame_type, action, body, self.clock_offset_hours)
        if request == (0x10, 0x84):
            if not session.version_seen or session.account_id is not None:
                raise ProtocolViolation("Invalid login state")
            if session.failed_logins >= 3:
                raise ProtocolViolation("Local retry limit reached")
            login, password = parse_login(body)
            account = await asyncio.to_thread(self.store.authenticate, login, password)
            # Never store credentials in Session, protocol logs, or replay data.
            del login, password
            if account is None:
                session.failed_logins += 1
                return serialize_failure("Local login failed. Use a separately created local account.")
            session.account_id = account.account_id
            return serialize_login(asdict(account), secrets.token_hex(16))

        if session.account_id is None:
            raise ProtocolViolation("Authentication required")
        account = self.store.get(session.account_id)
        if account is None:
            raise ProtocolViolation("Local account is unavailable")
        if request == (0x30, 0x84):
            parsed = parse_property_request(body)
            if parsed.account_id != account.account_id:
                raise ProtocolViolation("Property owner mismatch")
            return empty_property_response()
        if request == (0x30, 0x88):
            avatar_id = self.store.avatar_for(account.account_id)
            requested_avatar = parse_avatar_equipment_request(body)
            if requested_avatar != avatar_id:
                raise ProtocolViolation("Avatar owner mismatch")
            return avatar_equipment_response(AvatarEquipment(avatar_id, (0,) * 45))
        if request == (0x40, 0xA0):
            require_empty_request(body)
            return equipped_avatar_response(self.store.avatar_for(account.account_id))
        if request == (0x31, 0x88):
            require_empty_request(body)
            return cash_response(account.account_id, account.cash, account.medals)
        # In particular, never fake a successful GameGuard or lobby exchange.
        raise UnsupportedRequest()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.active_connections >= 8:
            writer.close()
            await writer.wait_closed()
            return
        self.active_connections += 1
        connection_id = next(self.connection_ids)
        incoming, outgoing = RC4(KEY), RC4(KEY)
        frames, session = FrameStream(), Session()
        event_base = {"connection": connection_id}
        self.log({**event_base, "event": "connected"})
        try:
            while data := await asyncio.wait_for(reader.read(4096), timeout=120):
                for frame_type, action, body in frames.feed(incoming.apply(data)):
                    metadata = {**event_base, "type": f"0x{frame_type:04x}",
                                "action": f"0x{action:04x}", "body_bytes": len(body)}
                    self.log({**metadata, "event": "request"})
                    previous_account = session.account_id
                    try:
                        reply = await self.dispatch(session, frame_type, action, body)
                    except UnsupportedRequest:
                        self.log({**metadata, "event": "unsupported_request"})
                        return
                    if previous_account is None and session.account_id is not None:
                        self.log({**event_base, "event": "local_account_authenticated"})
                    writer.write(outgoing.apply(reply))
                    await writer.drain()
            if frames.buffer:
                self.log({**event_base, "event": "truncated_frame_at_disconnect"})
        except (ValueError, asyncio.TimeoutError, ConnectionError):
            # Do not expose exception messages that might contain a payload.
            self.log({**event_base, "event": "invalid_request_or_connection_ended"})
        except sqlite3.Error:
            self.log({**event_base, "event": "local_database_error"})
        finally:
            self.active_connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.log({**event_base, "event": "disconnected"})


async def serve(store: AccountStore, port: int, offset: int) -> None:
    backend = Backend(store, offset)
    server = await asyncio.start_server(backend.handle, "127.0.0.1", port)
    print(f"Local account protocol lab: 127.0.0.1:{port}", flush=True)
    print("Experimental responses; no game redirection or playable lobby.", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-account", help="Create a new local-only test account")
    create.add_argument("--login", default="local@test.invalid")
    create.add_argument("--name", default="LocalFighter")
    run = commands.add_parser("serve", help="Start the loopback-only experimental backend")
    run.add_argument("--port", type=int, default=17000)
    run.add_argument("--clock-offset-hours", type=int, default=-7)
    args = parser.parse_args()
    try:
        if args.command == "serve":
            if not 1024 <= args.port <= 65535:
                parser.error("Choose a port from 1024 through 65535")
            if not -14 <= args.clock_offset_hours <= 14:
                parser.error("Clock offset must be between -14 and 14")
        store = AccountStore(args.db)
        if args.command == "create-account":
            if not sys.stdin.isatty():
                parser.error("Create accounts interactively; do not pass passwords in command lines")
            print("Choose a NEW local test password (8–20 printable ASCII characters).")
            first = getpass.getpass("Local password: ")
            second = getpass.getpass("Repeat local password: ")
            if first != second:
                parser.error("Passwords did not match")
            account = store.create(args.login, first, args.name)
            del first, second
            print(f"Created local account {account.login} with character {account.display_name}.")
            print("The password is stored only as a salted password hash.")
        else:
            if store.count() == 0:
                parser.error("Create a local account first using create-account")
            asyncio.run(serve(store, args.port, args.clock_offset_hours))
    except KeyboardInterrupt:
        print("Local lab stopped.")
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Local setup error: {exc}\n")


if __name__ == "__main__":
    main()
