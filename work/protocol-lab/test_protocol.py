"""Synthetic tests only. No capture, game installation or external server used."""
import asyncio
import contextlib
import io
import struct
import unittest

from protocol_probe import RC4, FrameStream, encode_frame, rc4, scan_frames
from handshake_probe import handle, response, FILETIME_UNIX_OFFSET


class ProtocolTests(unittest.TestCase):
    def test_rc4_known_vector_and_chunk_state(self):
        self.assertEqual(rc4(b"Plaintext", b"Key").hex(), "bbf316e8d940af0ad3")
        ctx = RC4(b"Key")
        self.assertEqual(ctx.apply(b"Plain") + ctx.apply(b"text"), rc4(b"Plaintext", b"Key"))

    def test_fragmented_and_coalesced_frames(self):
        a = encode_frame(0x10, 0x90, bytes(20))
        b = encode_frame(0x10, 0x92)
        data = a + b
        for split in range(len(data) + 1):
            f = FrameStream()
            self.assertEqual(f.feed(data[:split]) + f.feed(data[split:]),
                             [(0x10, 0x90, bytes(20)), (0x10, 0x92, b"")])
            self.assertEqual(f.buffer, bytearray())
        f = FrameStream()
        result = []
        for byte in data:
            result += f.feed(bytes([byte]))
        self.assertEqual(len(result), 2)

    def test_invalid_and_incomplete_lengths(self):
        with self.assertRaises(ValueError):
            FrameStream().feed(bytes.fromhex("001000059000"))
        self.assertEqual(scan_frames(encode_frame(0x10, 0x90, bytes(20))[:-1])["status"],
                         "incomplete_frame")
        with self.assertRaises(ValueError):
            encode_frame(0x10, 0x90, bytes(65530))

    def test_version_clock_and_synthetic_rejection(self):
        self.assertEqual(response(0x10, 0x90, bytes(20)).hex(), "001000069100")
        reply = response(0x10, 0x92, b"", -7, unix_ns=0)
        self.assertEqual(reply[:6].hex(), "0010000e9300")
        self.assertEqual(struct.unpack("<q", reply[6:])[0],
                         FILETIME_UNIX_OFFSET - 7 * 3600 * 10_000_000)
        fake_secret = b"SYNTHETIC-CREDENTIAL-MUST-NOT-LEAK"
        rejected = response(0x10, 0x84, fake_secret)
        self.assertEqual(len(rejected), 520)
        self.assertNotIn(fake_secret, rejected)
        with self.assertRaises(ValueError):
            response(0x48, 0x80, b"")


class LoopbackTest(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_roundtrip_and_connection_reset(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                for _ in range(2):
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    enc, dec = RC4(b"abcde"), RC4(b"abcde")
                    message = enc.apply(encode_frame(0x10, 0x90, bytes(20)) +
                                        encode_frame(0x10, 0x92))
                    writer.write(message[:3]); await writer.drain()
                    writer.write(message[3:]); await writer.drain()
                    reply = dec.apply(await asyncio.wait_for(reader.readexactly(20), 2))
                    frames = FrameStream().feed(reply)
                    self.assertEqual([(t,a,len(b)) for t,a,b in frames],
                                     [(0x10,0x91,0),(0x10,0x93,8)])
                    writer.write(enc.apply(encode_frame(0x10,0x84,b"SYNTHETIC-SECRET")))
                    await writer.drain()
                    rejected = dec.apply(await asyncio.wait_for(reader.readexactly(520),2))
                    self.assertEqual(scan_frames(rejected)["frame_count"],1)
                    self.assertNotIn(b"SYNTHETIC-SECRET",rejected)
                    writer.close(); await writer.wait_closed()
                    await asyncio.sleep(0)
            finally:
                server.close(); await server.wait_closed()
                await asyncio.sleep(0.02)
        self.assertNotIn("SYNTHETIC-SECRET",out.getvalue())


if __name__ == "__main__":
    unittest.main()
