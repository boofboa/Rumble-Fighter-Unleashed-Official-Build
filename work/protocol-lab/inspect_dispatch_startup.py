"""Bounded offline data extraction for a manually reduced protector startup path.

No x86 execution/emulation, native imports, calls, writes to client bytes, or VM
instruction runner. Only reads pinned local files and computes a fixed table
normalization plus four separately inspected bytecode transitions.
"""
import argparse
from pathlib import Path
import hashlib
import json
import struct

SOURCE_HASH = '94194afa95d3d2cc81a55438a0f584bfaf039ca85adab5b07966ae3e4d593a59'
STAGE_HASH = '674441d3542447def6b1f79a5344882b22b1d1d34f56d8608f0dd042e13e9cd5'
BASE, STAGE_BASE, TABLE, COUNT = 0x400000, 0x819000, 0x80685c, 498
SOURCE_BYTES, STAGE_BYTES = 4_217_600, 4_915_200


def inspect(original: bytes, stage: bytes) -> dict:
    if len(original) != SOURCE_BYTES or len(stage) != STAGE_BYTES:
        raise ValueError('Input sizes do not match the inspected build')
    if hashlib.sha256(original).hexdigest() != SOURCE_HASH or hashlib.sha256(stage).hexdigest() != STAGE_HASH:
        raise ValueError('Pinned input hashes do not match')

    def image_u32(va):
        if not 0x7fe000 <= va <= 0x80dffc:
            raise ValueError('Read outside original .vm_sec raw range')
        return struct.unpack_from('<I', original, 0x156a00+va-0x7fe000)[0]

    def stage_read(va, fmt):
        off = va-STAGE_BASE
        if not 0 <= off <= len(stage)-struct.calcsize(fmt):
            raise ValueError('Read outside verified first stage')
        return struct.unpack_from(fmt, stage, off)[0]

    relative = [image_u32(TABLE+4*i) for i in range(COUNT)]
    normalized = [(v+BASE)&0xffffffff for v in relative]
    if not all(STAGE_BASE <= v < STAGE_BASE+len(stage)-5 for v in normalized):
        raise ValueError('Normalized target outside verified first stage')

    def target(index):
        if not 0 <= index < COUNT:
            raise ValueError('Dispatch index outside bounded table')
        stub = normalized[index]
        if stage_read(stub, '<B') != 0xe9:
            raise ValueError('Expected direct jump stub not present')
        handler = stub+5+stage_read(stub+1, '<i')
        if not STAGE_BASE <= handler < STAGE_BASE+len(stage):
            raise ValueError('Handler outside verified first stage')
        return {'index': index, 'stub_preferred_va': hex(stub), 'handler_preferred_va': hex(handler)}

    # Each step below is a separate, inspected handler-specific layout. This is
    # deliberately not a generic VM decoder, and does not run the handler code.
    transitions = []
    ip = 0xa0d3ae
    index, delta = stage_read(ip, '<H'), stage_read(ip+4, '<i')
    transitions.append({'current': target(0x116), 'bytecode_preferred_va': hex(ip),
                        'effect': 'clear context+0x98; read next index and signed bytecode delta',
                        'next': target(index), 'next_bytecode_preferred_va': hex(ip+delta)})
    ip += delta
    offset, index, delta = stage_read(ip, '<H'), stage_read(ip+2, '<H'), stage_read(ip+4, '<i')
    transitions.append({'current': target(143), 'bytecode_preferred_va': hex(ip),
                        'effect': 'save symbolic native stack pointer to context field',
                        'context_destination_offset': hex(offset), 'next': target(index),
                        'next_bytecode_preferred_va': hex(ip+delta)})
    ip += delta
    index, delta = stage_read(ip, '<H'), stage_read(ip+2, '<i')
    transitions.append({'current': target(122), 'bytecode_preferred_va': hex(ip),
                        'effect': 'clear rolling operand/dispatch fields', 'next': target(index),
                        'next_bytecode_preferred_va': hex(ip+delta)})
    ip += delta
    a, b = stage_read(ip, '<H'), stage_read(ip+2, '<H')
    key = stage_read(ip+8, '<H') ^ 0x5656d127  # incoming context+0x160 was cleared
    index, delta = key & 0xffff, stage_read(ip+4, '<i')
    transitions.append({'current': target(330), 'bytecode_preferred_va': hex(ip),
                        'effect': 'copy one context dword using decoded field offsets',
                        'source_context_offset': hex((a-0x2a15)&0xffff),
                        'destination_context_offset': hex((b-0x6934)&0xffff),
                        'next': target(index), 'next_bytecode_preferred_va': hex(ip+delta),
                        'rolling_state_is_updated': True})
    expected = [(278,143),(143,122),(122,330),(330,119)]
    if [(t['current']['index'],t['next']['index']) for t in transitions] != expected:
        raise ValueError('Inspected transition invariant failed')

    result = {
        'scope': 'Bounded static dataflow/stack reduction and fixed data extraction only; no Windows code, native imports or interpreter execution.',
        'source_sha256': SOURCE_HASH, 'first_stage_sha256': STAGE_HASH,
        'context_slots': {'instruction_preferred_va': '0x9b230c', 'operation': 'atomic compare-and-exchange zero to one',
                          'first_slot_base': '0x802e50','stride_bytes':464,'count':32,'lock_offset':'0xd0',
                          'lock_preferred_va_first':'0x802f20','lock_preferred_va_last':'0x806750',
                          'all_original_file_locks_zero':all(image_u32(0x802f20+i*0x1d0)==0 for i in range(32)),
                          'assumption':'Initial file state; prior runtime mutation or concurrency could select a later slot.'},
        'table_normalization': {'loop_preferred_va_start':'0x9b26f5','loop_preferred_va_stop':'0x9b2777',
                                'table_preferred_va':hex(TABLE),'dwords':COUNT,'bytes':COUNT*4,
                                'rule':'Add image base modulo 2^32 to each relative target',
                                'relative_table_sha256':hashlib.sha256(struct.pack('<498I',*relative)).hexdigest(),
                                'normalized_table_sha256':hashlib.sha256(struct.pack('<498I',*normalized)).hexdigest(),
                                'all_targets_in_first_stage':True,
                                'initial_first_slot_marker':hex(image_u32(0x802e50+0x190)),
                                'marker_offset':'0x190','normalized_marker':hex(TABLE)},
        'initial_context_fields': {'0x80':'bytecode pointer 0xa0d3ae','0xe8':'preferred image base 0x400000',
                                   '0x190':'normalized dispatch table 0x80685c','0x198':'actual image base (0x400000 at preferred mapping)'},
        'entry_stack_proof': {'entry':'0x9b20aa','entry_stack_slots':{'0':'saved flags','4':'dispatch index 0x116','8':'bytecode RVA 0x60d3ae'},
                              'saved_register_bytes':32,'initial_index_load':'0x9b27f3','initial_bytecode_load':'0x9b2583',
                              'initial_dispatch_pointer':'0x806cb4','independent_manual_review_agrees':True},
        'transitions':transitions,
        'observed_structure':'A stateful custom bytecode dispatcher: native handlers read a context bytecode pointer, update it with relative deltas, transform operands with context state, and dispatch through a normalized target table.',
        'boundary': {'next_handler':'0x98d3b4','next_bytecode':'0xa0d10a',
                     'known_state':'Rolling fields have reproducible updates from preceding handlers; the native stack pointer is retained symbolically in context+0x70 and copied to +0xa8.',
                     'not_established':['A second whole-image unpack/copy transform','An imported API resolver or native API call on this inspected path','A server-destination configuration path'],
                     'next_work':'Decode the reached handler semantics with mixed-width context updates and symbolic stack data; do not substitute a fixed record format or treat the whole interpreter as a decompressor.',
                     'limit':'This checkpoint does not prove that runtime execution is required; no external API/state read has yet been established on this bounded path.'}}
    return result


def read_bounded(path: Path, size: int) -> bytes:
    if path.stat().st_size != size:
        raise ValueError('Input size does not match the inspected build')
    with path.open('rb') as stream:
        # Keep reads bounded even if the file changes after the size check.
        data = stream.read(size + 1)
    if len(data) != size:
        raise ValueError('Input size changed or does not match the inspected build')
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('client', type=Path, help='Original inspected rumblefighter.exe')
    parser.add_argument('stage', type=Path, help='Verified local first-stage analysis file')
    parser.add_argument('--output', type=Path, help='New metadata JSON file; default stdout')
    args = parser.parse_args()
    try:
        if args.output is not None and args.output.exists():
            raise ValueError('Output already exists; select a new filename')
        result = inspect(read_bounded(args.client, SOURCE_BYTES),
                         read_bounded(args.stage, STAGE_BYTES))
        text = json.dumps(result, indent=2) + '\n'
        if args.output is not None:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
            print('Saved metadata-only startup dispatch report.')
        else:
            print(text, end='')
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Inspection failed: {exc}\n')


if __name__ == '__main__':
    main()
