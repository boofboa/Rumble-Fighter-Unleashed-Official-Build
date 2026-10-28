#!/usr/bin/env python3
"""Bounded offline translation of a local loader's decompression routine only.

This is not an x86 emulator: no PE execution, imports, client/system calls,
relocations, or live process access. Metadata is the only default output.
Derived bytes require an explicit local --derived-output path and must not be
packaged or redistributed; they are not a runnable original game executable.
Algorithm translated from instructions at preferred VA 0xcc905d..0xcc91a5.
"""
from pathlib import Path
import argparse
import hashlib
import json
from collections import Counter

EXPECTED_SOURCE_BYTES = 4_217_600
EXPECTED_SHA256 = '94194afa95d3d2cc81a55438a0f584bfaf039ca85adab5b07966ae3e4d593a59'
COUNT_OFFSET = 0x16F806
INPUT_START = COUNT_OFFSET + 1
INPUT_STOP = 0x403200
DESTINATION_VA = 0x819000
OUTPUT_CAP = 0x4B0000
ENTRY_OFFSET = 0x1F4005
OPERATION_CAP = 64_000_000
BLOCK_CAP = 32
EXPECTED_BLOCK_BYTES = 614_400
EXPECTED_INPUT_END = 0x402F8D
EXPECTED_OUTPUT_SHA256 = '674441d3542447def6b1f79a5344882b22b1d1d34f56d8608f0dd042e13e9cd5'
EXPECTED_BLOCK_SHA256 = ('4525efe493c671e4e094ac537bb732028e67c074925b50d5f4f1086cc5f9120d', '4a37aa713bf10ba225638ea6500c45967d8e4e35e646c74b670d02cd3d867d46', '31bacd7a052e047d053b087a69f156054c239e6a88cf6246103267602bc68bbc', '734734c0b4bdf905c04cc31484b54a23acacd28dbc755bcc2411ca0e722402b2', '779edfc7796b282fbfa9040d88f937e29afb54e63a30ead8cc25ebc3d999b56f', 'e38b4d03b2705e0c38a5df4e61aca3f37cf5de03db55ad5734854c326cfe33b4', '142de0baae667bfe8bae68eca40754d0b03af6f16d74de74a92b71a81dc89a1e', 'f4fc51b81f4bbed1ef415e5b87feb5f1aa8bac0ecf16e4f63a816258d3fad294')


class DecodeError(ValueError):
    pass


class Decoder:
    def __init__(self, source: bytes, start: int, stop: int, output_cap: int):
        if not 0 <= start <= stop <= len(source):
            raise DecodeError('Invalid fixed input bounds')
        self.source = source
        self.pos = start
        self.stop = stop
        self.output = bytearray()
        self.output_cap = output_cap
        self.previous_offset = None
        self.operations = 0
        self.events = Counter()
        self.bit_tag = 0
        self.bits_left = 0
        self.cross_block_copies = 0
        self.block_start = 0

    def tick(self, amount=1):
        self.operations += amount
        if self.operations > OPERATION_CAP:
            raise DecodeError('Iteration budget exceeded')

    def raw(self):
        self.tick()
        if self.pos >= self.stop:
            raise DecodeError('Compressed source exhausted within .boot boundary')
        value = self.source[self.pos]
        self.pos += 1
        return value

    def bit(self):
        self.tick()
        if self.bits_left == 0:
            self.bit_tag = self.raw()
            self.bits_left = 8
        self.bits_left -= 1
        return (self.bit_tag >> self.bits_left) & 1

    def gamma(self):
        value = 1
        for _ in range(31):
            value = value * 2 + self.bit()
            if value > 0xFFFFFFFF:
                raise DecodeError('Gamma value exceeds the original 32-bit range')
            if self.bit() == 0:
                return value
        raise DecodeError('Gamma prefix exceeds bounded 32-bit range')

    def emit(self, value):
        self.tick()
        if len(self.output) >= self.output_cap:
            raise DecodeError('Output exceeds reserved .winlice virtual range')
        self.output.append(value)

    def copy(self, distance, length):
        self.tick()
        if distance is None or distance <= 0 or distance > len(self.output):
            raise DecodeError('Invalid or uninitialized backward reference')
        if length <= 0 or len(self.output) + length > self.output_cap:
            raise DecodeError('Backward copy exceeds reserved output range')
        if len(self.output) - distance < self.block_start:
            self.cross_block_copies += 1
        # REP MOVSB grows its own source for overlapping matches.
        for _ in range(length):
            self.emit(self.output[-distance])

    def block(self):
        source_start = self.pos
        self.block_start = len(self.output)
        self.bit_tag = self.bits_left = 0
        starting_operations = self.operations
        self.emit(self.raw())
        state = 2
        while True:
            self.tick()
            if self.bit() == 0:
                self.events['literal'] += 1
                self.emit(self.raw())
                state = 2
            elif self.bit() == 0:
                code = self.gamma() - state
                state = 1
                if code < 0:
                    raise DecodeError('Long-reference arithmetic underflow')
                if code == 0:
                    self.events['repeat_distance'] += 1
                    self.copy(self.previous_offset, self.gamma())
                else:
                    self.events['new_long_distance'] += 1
                    distance = ((code - 1) << 8) | self.raw()
                    if distance > 0xFFFFFFFF:
                        raise DecodeError('Long distance exceeds original 32-bit range')
                    self.previous_offset = distance
                    length = self.gamma()
                    if distance <= 0x7F or distance >= 0x7D00:
                        length += 2
                    elif distance >= 0x500:
                        length += 1
                    self.copy(distance, length)
            elif self.bit() == 0:
                packed = self.raw()
                distance = packed >> 1
                if distance == 0:
                    self.events['block_terminator'] += 1
                    break
                self.events['short_distance'] += 1
                self.previous_offset = distance
                self.copy(distance, 2 + (packed & 1))
                state = 1
            else:
                distance = 0
                for _ in range(4):
                    distance = distance * 2 + self.bit()
                if distance:
                    self.events['single_copy'] += 1
                    self.copy(distance, 1)
                else:
                    self.events['zero_literal'] += 1
                    self.emit(0)
                state = 2
        return dict(source_file_start=hex(source_start), source_file_stop=hex(self.pos),
                    compressed_bytes=self.pos - source_start,
                    output_offset_start=hex(self.block_start), output_offset_stop=hex(len(self.output)),
                    output_bytes=len(self.output) - self.block_start,
                    operations=self.operations - starting_operations)


def inspect(raw: bytes):
    if len(raw) != EXPECTED_SOURCE_BYTES:
        raise DecodeError('Input size does not match the inspected build')
    source_hash = hashlib.sha256(raw).hexdigest()
    if source_hash != EXPECTED_SHA256:
        raise DecodeError('Input hash does not match the statically inspected build')
    count = raw[COUNT_OFFSET]
    if count != len(EXPECTED_BLOCK_SHA256) or count > BLOCK_CAP:
        raise DecodeError('Block count does not match the inspected build')
    decoder = Decoder(raw, INPUT_START, INPUT_STOP, OUTPUT_CAP)
    blocks = []
    for expected_hash in EXPECTED_BLOCK_SHA256:
        block = decoder.block()
        start = int(block['output_offset_start'], 16)
        block_hash = hashlib.sha256(decoder.output[start:]).hexdigest()
        if block['output_bytes'] != EXPECTED_BLOCK_BYTES or block_hash != expected_hash:
            raise DecodeError('Decoded block does not match independent reference checks')
        block['output_sha256'] = block_hash
        blocks.append(block)
    output_hash = hashlib.sha256(decoder.output).hexdigest()
    if (decoder.pos != EXPECTED_INPUT_END or len(decoder.output) != OUTPUT_CAP or
            output_hash != EXPECTED_OUTPUT_SHA256):
        raise DecodeError('Decoded total bounds or hash do not match independent checks')
    metadata = dict(
        scope='Offline decompression only; no Windows code execution, imports, fixups or system calls.',
        source_sha256=source_hash,
        algorithm='Bitstream/back-reference decoder structurally consistent with aPLib; translated from this loader, not copied from a library.',
        compressed_block_count=count,
        compressed_start_file_offset=hex(INPUT_START),
        compressed_stop_file_offset=hex(decoder.pos),
        permitted_source_stop_file_offset=hex(INPUT_STOP),
        unconsumed_boot_tail_bytes=INPUT_STOP-decoder.pos,
        decoded_size_bytes=len(decoder.output),
        decoded_sha256=output_hash,
        independent_block_and_total_checks_passed=True,
        mapped_preferred_va_start=hex(DESTINATION_VA),
        mapped_preferred_va_stop=hex(DESTINATION_VA+len(decoder.output)),
        reserved_virtual_size=OUTPUT_CAP,
        next_entry_offset=hex(ENTRY_OFFSET),
        next_entry_preferred_va=hex(DESTINATION_VA+ENTRY_OFFSET),
        next_entry_within_decoded_range=ENTRY_OFFSET<len(decoder.output),
        iterations=decoder.operations, iteration_cap=OPERATION_CAP,
        cross_block_copy_count=decoder.cross_block_copies,
        operation_counts=dict(decoder.events), blocks=blocks,
        handling='Derived bytes are temporary analysis only and must not be packaged or redistributed.',
        limitation='First-stage protector reconstruction is not the original application image or proof of endpoint setup.')
    return metadata, decoder.output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('client', type=Path, help='Original inspected rumblefighter.exe')
    parser.add_argument('--output', type=Path, help='New metadata JSON file; default stdout')
    parser.add_argument('--derived-output', type=Path,
                        help='Optional new local analysis-only file of derived bytes; never distribute')
    args = parser.parse_args()
    try:
        if args.client.stat().st_size != EXPECTED_SOURCE_BYTES:
            raise DecodeError('Input size does not match the inspected build')
        for destination in (args.output, args.derived_output):
            if destination is not None and destination.exists():
                raise DecodeError('Output already exists; select a new filename')
        if (args.output is not None and args.derived_output is not None and
                args.output.resolve() == args.derived_output.resolve()):
            raise DecodeError('Output paths must be different')
        metadata, decoded = inspect(args.client.read_bytes())
        metadata['derived_bytes_written'] = args.derived_output is not None
        if args.derived_output:
            with args.derived_output.open('xb') as stream:
                stream.write(decoded)
        text = json.dumps(metadata, indent=2) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
            print('Saved verified metadata-only first-stage report.')
        else:
            print(text, end='')
    except (OSError, DecodeError) as exc:
        parser.exit(1, f'Inspection failed: {exc}\n')


if __name__ == '__main__':
    main()
