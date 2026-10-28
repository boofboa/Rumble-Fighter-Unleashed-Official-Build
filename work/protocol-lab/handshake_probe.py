"""Original localhost-only protocol probe. NOT a playable game server.

Implements version acknowledgement, clock response, and a fixed synthetic
login rejection. It never replays captured responses or stores credentials.
It does not redirect/patch the client or implement GameGuard, inventory,
rooms, peer networking, or gameplay.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import time

from protocol_probe import RC4, FrameStream, encode_frame

KEY = b"abcde"  # Public legacy protocol constant; verified on the supplied trace.
FILETIME_UNIX_OFFSET = 116444736000000000


def response(frame_type: int, action: int, body: bytes,
             clock_offset_hours: int = -7, unix_ns: int | None = None) -> bytes:
    if frame_type == 0x10 and action == 0x90 and len(body) == 20:
        return encode_frame(0x10, 0x91)
    if frame_type == 0x10 and action == 0x92 and not body:
        now = time.time_ns() if unix_ns is None else unix_ns
        ticks = now // 100 + FILETIME_UNIX_OFFSET + clock_offset_hours * 3600 * 10_000_000
        return encode_frame(0x10, 0x93, struct.pack("<q", ticks))
    if frame_type == 0x10 and action == 0x84:
        # The supplied credential body is deliberately ignored.
        message = b"Local protocol probe: account login is not implemented."
        payload = struct.pack("<H", 29374) + message.ljust(512, b"\0")
        return encode_frame(0x0210, 0x0285, payload)
    raise ValueError("Unsupported request or request length")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 clock_offset_hours: int = -7) -> None:
    incoming, outgoing = RC4(KEY), RC4(KEY)
    frames = FrameStream()
    try:
        while data := await asyncio.wait_for(reader.read(4096), timeout=120):
            for frame_type, action, body in frames.feed(incoming.apply(data)):
                # Protocol metadata only: do not log body, username or peer data.
                print(json.dumps({"type": f"0x{frame_type:04x}",
                                  "action": f"0x{action:04x}",
                                  "body_bytes": len(body)}), flush=True)
                reply = response(frame_type, action, body, clock_offset_hours)
                writer.write(outgoing.apply(reply))
                await writer.drain()
    except (ValueError, asyncio.TimeoutError, ConnectionError):
        print("Probe session ended; no payload values recorded.", flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def serve(port: int, clock_offset_hours: int) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, clock_offset_hours), "127.0.0.1", port)
    print(f"Local protocol probe: 127.0.0.1:{port}; not a playable server.", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=17000)
    parser.add_argument("--clock-offset-hours", type=int, default=-7,
                        help="Observed capture convention; fixed offset, not DST handling")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a local test port from 1024 through 65535")
    if not -14 <= args.clock_offset_hours <= 14:
        parser.error("Clock offset must be between -14 and 14 hours")
    try:
        asyncio.run(serve(args.port, args.clock_offset_hours))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
