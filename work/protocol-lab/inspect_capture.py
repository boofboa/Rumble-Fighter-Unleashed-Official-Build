#!/usr/bin/env python3
"""Offline pcapng Ethernet/IPv4/TCP metadata and loss-aware reassembly.

No network operations and no payload printing. Raw stream export is opt-in.
Supported: pcapng enhanced packet blocks, Ethernet (optional VLAN), IPv4 TCP.
Unsupported link/network types and fragmented IP packets are counted, not decoded.
Sequence offsets use serial arithmetic: each connection must span < 2**31 bytes.
Missing traffic before a capture starts or after it ends cannot be reconstructed.
"""
from __future__ import annotations
import argparse
import collections
import datetime
import hashlib
import ipaddress
import json
import pathlib
import socket
import struct
import sys


class CaptureError(ValueError):
    """Invalid or unsupported capture structure; never includes payload contents."""


def parse_options(raw: bytes, endian: str) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    pos = 0
    while pos < len(raw):
        if len(raw) - pos < 4:
            raise CaptureError('Truncated pcapng option header')
        code, length = struct.unpack_from(endian + 'HH', raw, pos)
        pos += 4
        if code == 0:
            if length:
                raise CaptureError('Invalid pcapng end-of-options length')
            return result
        padded = (length + 3) & ~3
        if pos + padded > len(raw):
            raise CaptureError('Truncated pcapng option value')
        result[code] = raw[pos:pos + length]
        pos += padded
    return result


def read_pcapng(blob: bytes) -> tuple[list[dict], list[dict], dict]:
    pos = 0
    endian = None
    active_interfaces: list[dict] = []
    interfaces: list[dict] = []
    packets: list[dict] = []
    block_counts = collections.Counter()
    section = -1
    while pos < len(blob):
        if len(blob) - pos < 12:
            raise CaptureError(f'Truncated pcapng block at offset {pos}')
        is_section = blob[pos:pos + 4] == b'\x0a\x0d\x0d\x0a'
        if is_section:
            magic = blob[pos + 8:pos + 12]
            if magic == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif magic == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise CaptureError(f'Invalid pcapng byte-order magic at offset {pos}')
        if endian is None:
            raise CaptureError('Expected a pcapng section header')
        kind, length = struct.unpack_from(endian + 'II', blob, pos)
        if length < 12 or length % 4 or pos + length > len(blob):
            raise CaptureError(f'Invalid pcapng block length at offset {pos}')
        if struct.unpack_from(endian + 'I', blob, pos + length - 4)[0] != length:
            raise CaptureError(f'Pcapng block length trailer mismatch at offset {pos}')
        body = blob[pos + 8:pos + length - 4]
        block_counts[hex(kind)] += 1
        if is_section:
            if len(body) < 16:
                raise CaptureError('Short pcapng section header')
            major, minor = struct.unpack_from(endian + 'HH', body, 4)
            if major != 1:
                raise CaptureError('Unsupported pcapng major version')
            section += 1
            active_interfaces = []
            parse_options(body[16:], endian)
        elif kind == 1:
            if len(body) < 8:
                raise CaptureError('Short pcapng interface block')
            link, _, snaplen = struct.unpack_from(endian + 'HHI', body)
            opts = parse_options(body[8:], endian)
            resolution = opts.get(9, b'\x06')
            if len(resolution) != 1:
                raise CaptureError('Invalid pcapng timestamp resolution')
            exponent = resolution[0]
            units_per_second = 2 ** (exponent & 127) if exponent & 128 else 10 ** exponent
            offset = opts.get(14, b'\0' * 8)
            if len(offset) != 8:
                raise CaptureError('Invalid pcapng timestamp offset')
            interface = dict(section=section, interface_id=len(active_interfaces), link=link,
                             snaplen=snaplen, units_per_second=units_per_second,
                             offset_seconds=struct.unpack(endian + 'q', offset)[0])
            active_interfaces.append(interface)
            interfaces.append(interface)
        elif kind == 6:
            if len(body) < 20:
                raise CaptureError('Short pcapng enhanced packet block')
            iface, high, low, caplen, wirelen = struct.unpack_from(endian + 'IIIII', body)
            if iface >= len(active_interfaces):
                raise CaptureError('Packet refers to an unknown pcapng interface')
            interface = active_interfaces[iface]
            padded = (caplen + 3) & ~3
            if 20 + padded > len(body) or caplen > wirelen:
                raise CaptureError('Invalid pcapng captured packet length')
            if interface['snaplen'] and caplen > interface['snaplen']:
                raise CaptureError('Captured packet exceeds interface snap length')
            parse_options(body[20 + padded:], endian)
            ticks = (high << 32) | low
            timestamp = ticks / interface['units_per_second'] + interface['offset_seconds']
            packets.append(dict(index=len(packets) + 1, time=timestamp,
                                captured=caplen, wire=wirelen, link=interface['link'],
                                section=section, interface_id=iface,
                                raw=body[20:20 + caplen]))
        pos += length
    return packets, interfaces, dict(block_counts)


def decode_tcp(packet: dict, skipped: collections.Counter) -> dict | None:
    raw = packet['raw']
    if packet['link'] != 1:
        skipped['unsupported_link_type'] += 1
        return None
    if len(raw) < 14:
        skipped['short_ethernet'] += 1
        return None
    ethertype = struct.unpack_from('!H', raw, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88a8):
        if len(raw) < offset + 4:
            skipped['short_vlan'] += 1
            return None
        ethertype = struct.unpack_from('!H', raw, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800:
        skipped[f'ethertype_{ethertype:04x}'] += 1
        return None
    if len(raw) < offset + 20:
        skipped['short_ipv4'] += 1
        return None
    ihl = (raw[offset] & 15) * 4
    total = struct.unpack_from('!H', raw, offset + 2)[0]
    if raw[offset] >> 4 != 4 or ihl < 20 or total < ihl:
        skipped['invalid_ipv4_header'] += 1
        return None
    if len(raw) < offset + ihl:
        skipped['short_ipv4_header'] += 1
        return None
    if len(raw) < offset + total:
        # Do not silently turn a truncated TCP packet into a complete segment.
        skipped['truncated_ipv4_packet'] += 1
        return None
    fragment = struct.unpack_from('!H', raw, offset + 6)[0]
    if fragment & 0x3fff:
        skipped['ipv4_fragment'] += 1
        return None
    protocol = raw[offset + 9]
    if protocol != 6:
        skipped[f'ip_protocol_{protocol}'] += 1
        return None
    tcp = raw[offset + ihl:offset + total]
    if len(tcp) < 20:
        skipped['short_tcp'] += 1
        return None
    hlen = (tcp[12] >> 4) * 4
    if hlen < 20 or hlen > len(tcp):
        skipped['invalid_tcp_header'] += 1
        return None
    sport, dport, seq, ack = struct.unpack_from('!HHII', tcp)
    return dict(index=packet['index'], time=packet['time'],
                source=(socket.inet_ntoa(raw[offset + 12:offset + 16]), sport),
                destination=(socket.inet_ntoa(raw[offset + 16:offset + 20]), dport),
                seq=seq, ack=ack, flags=tcp[13], payload=tcp[hlen:],
                section=packet['section'], interface_id=packet['interface_id'])


def serial_offset(sequence: int, base: int) -> int:
    return ((sequence - base + 0x80000000) & 0xffffffff) - 0x80000000


def group_flows(packets: list[dict], skipped: collections.Counter) -> list[dict]:
    flows = []
    current = {}
    for packet in packets:
        tcp = decode_tcp(packet, skipped)
        if tcp is None:
            continue
        endpoints = tuple(sorted((tcp['source'], tcp['destination'])))
        # Keep distinct interfaces/sections separate to avoid false duplicates.
        key = (tcp['section'], tcp['interface_id'], endpoints)
        flow = current.get(key)
        initial_syn = bool(tcp['flags'] & 2 and not tcp['flags'] & 16)
        if flow is not None and initial_syn:
            prior_syn = next((x for x in flow['packets'] if x['flags'] & 2 and not x['flags'] & 16), None)
            same_syn = prior_syn is not None and prior_syn['source'] == tcp['source'] and prior_syn['seq'] == tcp['seq']
            closed = any(x['flags'] & 5 for x in flow['packets'])
            if not same_syn or closed:
                flow = None
        if flow is None:
            flow = dict(endpoints=endpoints, packets=[])
            flows.append(flow)
            current[key] = flow
        flow['packets'].append(tcp)
    return flows


def reassemble(packets: list[dict]) -> tuple[dict, list[tuple[int, bytes]], list[dict]]:
    """First observed bytes win conflicts; ranges are sorted, disjoint, gap-aware."""
    syn = next((x for x in packets if x['flags'] & 2), None)
    data = [x for x in packets if x['payload']]
    base = ((syn['seq'] + 1) & 0xffffffff) if syn else (data[0]['seq'] if data else 0)
    ranges: list[tuple[int, bytes]] = []
    events = []
    total_overlap = total_conflicts = 0
    for packet in data:
        start = serial_offset(packet['seq'], base) + bool(packet['flags'] & 2)
        payload = packet['payload']
        end = start + len(payload)
        if end >= 0x80000000 or start <= -0x80000000:
            raise CaptureError('TCP sequence span exceeds supported serial arithmetic window')
        intersect = [(a, d) for a, d in ranges if a <= end and a + len(d) >= start]
        keep = [(a, d) for a, d in ranges if not (a <= end and a + len(d) >= start)]
        overlap = conflicts = 0
        for a, old in intersect:
            low, high = max(a, start), min(a + len(old), end)
            if low < high:
                overlap += high - low
                conflicts += sum(x != y for x, y in zip(old[low - a:high - a], payload[low - start:high - start]))
        low = min([start] + [a for a, _ in intersect])
        high = max([end] + [a + len(d) for a, d in intersect])
        merged = bytearray(high - low)
        merged[start - low:end - low] = payload
        for a, old in intersect:
            merged[a - low:a - low + len(old)] = old
        ranges = sorted(keep + [(low, bytes(merged))])
        total_overlap += overlap
        total_conflicts += conflicts
        events.append(dict(packet=packet['index'], time=packet['time'],
                           payload_bytes=len(payload), stream_offset=start,
                           overlap_bytes=overlap, conflicting_bytes=conflicts))
    intervals = [[a, a + len(d)] for a, d in ranges]
    gaps = [[intervals[i][1], intervals[i + 1][0]] for i in range(len(intervals) - 1)]
    if syn and intervals and intervals[0][0] > 0:
        gaps.insert(0, [0, intervals[0][0]])
    first = ranges[0][1][:5] if ranges else b''
    tls_header = bool(len(first) >= 5 and first[0] in (20, 21, 22, 23, 24)
                      and first[1] == 3 and first[2] <= 4
                      and 0 < int.from_bytes(first[3:5], 'big') <= 18432)
    meta = dict(packets=len(packets), payload_packets=len(data),
                captured_payload_bytes=sum(len(x['payload']) for x in data),
                unique_payload_bytes=sum(len(d) for _, d in ranges),
                overlap_bytes=total_overlap, conflicting_overlap_bytes=total_conflicts,
                payload_packets_with_overlap=sum(x['overlap_bytes'] > 0 for x in events),
                sequence_ranges_relative=intervals, missing_ranges_relative=gaps,
                start_observed_via_syn=syn is not None, possible_tls_record_header=tls_header)
    return meta, ranges, events


def analyze(blob: bytes, output: pathlib.Path, write_streams: bool = False) -> dict:
    packets, interfaces, block_counts = read_pcapng(blob)
    skipped = collections.Counter()
    flows = group_flows(packets, skipped)
    times = [x['time'] for x in packets]
    first, last = (min(times), max(times)) if times else (None, None)
    utc = lambda value: datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat() if value is not None else None
    summary = dict(size=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                   capture_start_utc=utc(first), capture_end_utc=utc(last),
                   duration_seconds=round(last - first, 6) if times else 0,
                   packets=len(packets), truncated_packets=sum(x['captured'] < x['wire'] for x in packets),
                   interfaces=interfaces, block_counts=block_counts, skipped_packets=dict(skipped),
                   raw_stream_export=write_streams, flows=[])
    output.mkdir(parents=True, exist_ok=True)
    for number, flow in enumerate(flows, 1):
        ps = flow['packets']
        syn = next((x for x in ps if x['flags'] & 2 and not x['flags'] & 16), None)
        synack = next((x for x in ps if x['flags'] & 0x12 == 0x12), None)
        if syn:
            client = syn['source']
        elif synack:
            client = synack['destination']
        else:
            client = next((x for x in flow['endpoints'] if not ipaddress.ip_address(x[0]).is_global), ps[0]['source'])
        server = next(x for x in flow['endpoints'] if x != client)
        server_address = server[0] if ipaddress.ip_address(server[0]).is_global else '<private-server>'
        folder = output / f'flow-{number:02d}'
        folder.mkdir(exist_ok=True)
        meta = dict(id=number, client=f'<client>:{client[1]}', server=f'{server_address}:{server[1]}',
                    packet_count=len(ps), start_offset_seconds=round(min(x['time'] for x in ps) - first, 6),
                    duration_seconds=round(max(x['time'] for x in ps) - min(x['time'] for x in ps), 6),
                    initial_syn_present=syn is not None, syn_ack_present=synack is not None,
                    fin_packet_count=sum(bool(x['flags'] & 1) for x in ps),
                    rst_packet_count=sum(bool(x['flags'] & 4) for x in ps), directions={})
        chronology = []
        for direction, endpoint in [('client_to_server', client), ('server_to_client', server)]:
            directional = [x for x in ps if x['source'] == endpoint]
            direction_meta, ranges, events = reassemble(directional)
            direction_meta['stream_files'] = []
            if write_streams:
                for part, (_, data) in enumerate(ranges):
                    name = direction + ('.bin' if len(ranges) == 1 else f'.part-{part:02d}.bin')
                    target = folder / name
                    target.write_bytes(data)
                    direction_meta['stream_files'].append(target.relative_to(output).as_posix())
            meta['directions'][direction] = direction_meta
            for event in events:
                event['offset_seconds'] = round(event.pop('time') - first, 6)
                event['direction'] = direction
                chronology.append(event)
        chronology.sort(key=lambda x: x['packet'])
        chronology_path = folder / 'chronology.json'
        chronology_path.write_text(json.dumps(chronology, indent=2) + '\n', encoding='utf-8')
        meta['chronology_file'] = chronology_path.relative_to(output).as_posix()
        summary['flows'].append(meta)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=pathlib.Path, help='Local .pcapng file; no downloads or live capture')
    parser.add_argument('--output', type=pathlib.Path, required=True, help='New output directory')
    parser.add_argument('--write-streams', action='store_true', help='Opt in to exporting raw TCP bytes, which may contain credentials or session data')
    parser.add_argument('--max-mib', type=int, default=128, help='Maximum input size in MiB (default: 128)')
    args = parser.parse_args(argv)
    try:
        if args.max_mib <= 0 or args.capture.stat().st_size > args.max_mib * 1024 * 1024:
            raise CaptureError('Input exceeds configured positive size limit')
        if args.output.exists():
            raise CaptureError('Output directory already exists; choose a new directory to prevent stale artifacts')
        summary = analyze(args.capture.read_bytes(), args.output, args.write_streams)
    except (CaptureError, OSError, OverflowError, ValueError) as exc:
        # File errors may reveal local file paths, but payload bytes are never included.
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
