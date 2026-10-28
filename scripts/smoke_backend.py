#!/usr/bin/env python3
"""Exercise the Python backend CLI using a disposable account and loopback port.

This validates the protocol laboratory, not the Windows game client. No retained
account database is read or changed. The subprocess started here is always stopped.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time

LAB = Path(__file__).resolve().parents[1] / "work" / "protocol-lab"
sys.path.insert(0, str(LAB))

from local_store import AccountStore
from protocol_probe import RC4, encode_frame


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        data = connection.recv(length - len(chunks))
        if not data:
            raise RuntimeError("Backend closed the connection before its response completed")
        chunks.extend(data)
    return bytes(chunks)


def receive_frame(connection: socket.socket, decrypt: RC4) -> tuple[int, int, bytes]:
    header = decrypt.apply(receive_exact(connection, 6))
    kind, length = struct.unpack_from(">HH", header)
    action = struct.unpack_from("<H", header, 4)[0]
    require(length >= 6, "Backend returned an invalid frame length")
    return kind, action, decrypt.apply(receive_exact(connection, length - 6))


def connect_when_ready(process: subprocess.Popen, port: int) -> socket.socket:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, "Backend process exited during startup")
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=1)
        except ConnectionRefusedError:
            time.sleep(0.05)
        else:
            connection.settimeout(5)
            return connection
    raise RuntimeError("Backend did not accept a loopback connection within 10 seconds")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rf-backend-smoke-") as temporary:
        database = Path(temporary) / "smoke.sqlite3"
        store = AccountStore(database)
        password = secrets.token_hex(8)
        account = store.create("smoke@test.invalid", password, "SmokeFighter")
        avatar_id = store.avatar_for(account.account_id)
        # Reserve an available ephemeral port, then release it for the CLI.
        # If another process takes it before startup, the backend fails; we never
        # stop a process by its port or reuse an existing account database.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryFile(mode="w+b") as output:
            process = subprocess.Popen(
                [sys.executable, str(LAB / "local_backend.py"), "--db",
                 str(database), "serve", "--port", str(port)],
                cwd=LAB, env=environment, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                with connect_when_ready(process, port) as connection:
                    encrypt, decrypt = RC4(b"abcde"), RC4(b"abcde")
                    credentials = (account.login.encode("ascii").ljust(64, b"\0") +
                                   password.encode("ascii").ljust(21, b"\0"))
                    connection.sendall(encrypt.apply(
                        encode_frame(0x10, 0x90, bytes(20)) +
                        encode_frame(0x10, 0x84, credentials)))
                    require(receive_frame(connection, decrypt) == (0x10, 0x91, b""),
                            "Version response did not match the protocol")
                    kind, action, body = receive_frame(connection, decrypt)
                    require((kind, action, len(body)) == (0x10, 0x85, 320),
                            "Local login did not succeed")
                    require(struct.unpack_from("<i", body)[0] == account.account_id,
                            "Login returned the wrong account")
                    require(body[4:28].split(b"\0", 1)[0] == b"SmokeFighter",
                            "Login returned the wrong character name")

                    connection.sendall(encrypt.apply(
                        encode_frame(0x40, 0xA0) + encode_frame(0x31, 0x88) +
                        encode_frame(0x30, 0x84,
                                     struct.pack("<i", account.account_id) + b"TAIL123") +
                        encode_frame(0x30, 0x88, struct.pack("<i", avatar_id))))
                    require(receive_frame(connection, decrypt) ==
                            (0x40, 0xA1, struct.pack("<i", avatar_id)),
                            "Equipped avatar response did not match local state")
                    require(receive_frame(connection, decrypt) ==
                            (0x31, 0x89, struct.pack("<3i", account.account_id,
                                                    account.cash, account.medals)),
                            "Currency response did not match local state")
                    require(receive_frame(connection, decrypt) ==
                            (0x30, 0x85, bytes(3922)),
                            "Empty inventory response was incorrect")
                    require(receive_frame(connection, decrypt) ==
                            (0x30, 0x89, bytes(360)),
                            "Empty equipment response was incorrect")
                    require(process.poll() is None, "Backend exited during its smoke test")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    print("PASS backend CLI: encrypted version/login, avatar, currency, inventory, equipment; disposable state cleaned up")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL backend CLI smoke: {error}", file=sys.stderr)
        sys.exit(1)
