"""Offline RF framing analysis. Outputs metadata only; no raw stream files.

Uses the public reference cipher constant verified on the supplied capture.
It does not connect to servers, replay messages, or print decrypted bodies.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from inspect_capture import CaptureError, read_pcapng, group_flows, reassemble
from protocol_probe import rc4, scan_frames


def analyze(blob: bytes, server_port: int = 7000) -> dict:
    packets, _, _ = read_pcapng(blob)
    skipped = collections.Counter()
    flows = group_flows(packets, skipped)
    result = {"capture_sha256": hashlib.sha256(blob).hexdigest(),
              "capture_bytes": len(blob),
              "cipher_hypothesis": "independent continuous RC4 per direction; reference key",
              "payload_output": False,
              "warning": "Framing compatibility does not establish a working game server.",
              "flows": []}
    for flow in flows:
        ps = flow["packets"]
        syn = next((p for p in ps if p["flags"] & 2 and not p["flags"] & 16), None)
        if syn is None or syn["destination"][1] != server_port:
            continue
        client, server = syn["source"], syn["destination"]
        info = {"flow_index": len(result["flows"]) + 1,
                "server_port": server_port,
                "client_address": "redacted", "server_address": "redacted",
                "directions": {}}
        for direction, endpoint in [("client_to_server", client), ("server_to_client", server)]:
            meta, ranges, _ = reassemble([p for p in ps if p["source"] == endpoint])
            if (not meta["start_observed_via_syn"] or meta["missing_ranges_relative"] or
                    meta["conflicting_overlap_bytes"] or len(ranges) != 1 or ranges[0][0] != 0):
                info["directions"][direction] = {
                    "status": "not_decoded_due_to_missing_start_gaps_conflicts_or_empty_stream"}
                continue
            decoded = rc4(ranges[0][1], b"abcde")
            framing = scan_frames(decoded)
            # Only headers/lengths escape this scope. No account or session values.
            info["directions"][direction] = framing
        result["flows"].append(info)
    result["skipped_packet_types"] = dict(skipped)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, help="New JSON file; default is stdout")
    args = parser.parse_args()
    try:
        if args.capture.stat().st_size > 128 * 1024 * 1024:
            parser.error("Input exceeds the 128 MiB bound")
        if args.output and args.output.exists():
            parser.error("Output already exists; select a new filename")
        result = analyze(args.capture.read_bytes())
        text = json.dumps(result, indent=2) + "\n"
        if args.output:
            # Exclusive creation also protects against an overwrite race.
            with args.output.open("x", encoding="utf-8") as output:
                output.write(text)
            print("Saved metadata-only framing report.")
        else:
            print(text, end="")
    except OSError as exc:
        parser.exit(1, f"File error: {exc}\n")
    except (CaptureError, ValueError, OverflowError) as exc:
        parser.exit(1, f"Capture structure error: {exc}\n")


if __name__ == "__main__":
    main()
