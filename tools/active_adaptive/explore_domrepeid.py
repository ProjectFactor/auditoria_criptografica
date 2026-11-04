#!/usr/bin/env python3
"""Boundary-14 sweep: the DomRepEID proprietary application (read-only).

Over CAN/PACE this selects the DomRepEID application (AID D276000098446F6D4944,
"DomID") and enumerates its readable children conservatively:
  - dumps the application FCI;
  - reads every short-file-identifier EF (SFI 1..30), 16-byte prefix each;
  - records the SM-protected status of every probe.

It uses the STOCK npa-tool --translate (which continues past non-9000), so one
PACE session covers the whole sweep. Nothing is written; no VERIFY/PIN/retry
query is sent; each EF is read at most once (reads do not consume retry counters).
Any SFI that returns data can then be fully read with adaptive_read-style paging.

Content may include personal data (this is the proprietary eID app); raw bytes are
kept only in git-ignored objects/, and this tool prints status + a short structural
prefix. Run privately and review locally.

Usage:  printf '<CAN>' | python3 explore_domrepeid.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv
import runbook_common as rb
from evidence import parse_apdu_dumps, parse_decrypted_dumps, status_text

HERE = Path(__file__).resolve().parent

AID = "D2 76 00 00 98 44 6F 6D 49 44"  # DomRepEID / "DomID"
SELECT_AID_POS = f"00 A4 04 0C 0A {AID}"       # position into the DF (no FCI, case 3)
SELECT_AID_FCI = f"00 A4 04 00 0A {AID} 00"    # FCI capture (case 4, Le=00)
SENTINEL = "# Unread EOF sentinel; the blank line above terminates translation cleanly."


def build_profile() -> tuple[list[str], list[str]]:
    """Return (labels, apdus) for the sweep, in matching order."""
    labels = ["SELECT DomRepEID AID (position)", "SELECT DomRepEID AID (FCI)"]
    apdus = [SELECT_AID_POS, SELECT_AID_FCI]
    for sfi in range(1, 31):
        labels.append(f"READ SFI {sfi} (16B)")
        apdus.append(f"00 B0 {0x80 | sfi:02X} 00 10")
    return labels, apdus


def sm_segments(trace: bytes) -> list[tuple[int, int, bytes]]:
    """Walk the post-PACE trace; for each secure-messaging (CLA&0x0C) command,
    return (sw1, sw2, decrypted_data). Order matches the profile's SM commands."""
    marker = trace.find(b"Selected eMRTD application.")
    region = trace[marker:] if marker >= 0 else trace
    # Split into per-command chunks at each outgoing APDU.
    chunks = region.split(b"Outgoing APDU")
    out: list[tuple[int, int, bytes]] = []
    for chunk in chunks[1:]:
        piece = b"Outgoing APDU" + chunk
        pairs = parse_apdu_dumps(piece)
        outgoing = next((raw for d, raw in pairs if d == "outgoing"), None)
        incoming = next((raw for d, raw in pairs if d == "incoming"), None)
        if not outgoing or len(outgoing) < 1 or not (outgoing[0] & 0x0C):
            continue  # skip plaintext PACE handshake commands
        sw1 = sw2 = 0
        if incoming and len(incoming) >= 2:
            # SM-protected status is the 99 02 SW1 SW2 data object, else trailing SW.
            i = incoming.find(b"\x99\x02")
            if i >= 0 and i + 4 <= len(incoming):
                sw1, sw2 = incoming[i + 2], incoming[i + 3]
            else:
                sw1, sw2 = incoming[-2], incoming[-1]
        dec = parse_decrypted_dumps(piece)
        data = dec[0] if dec else b""
        out.append((sw1, sw2, data))
    return out


def sweep(can: bytearray, atr: str, workdir: Path) -> dict:
    labels, apdus = build_profile()
    prof = workdir / "domrepeid_sweep.apdus"
    prof.write_text("\n".join(apdus + ["", SENTINEL]) + "\n", encoding="ascii")
    code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    (workdir / "domrepeid_sweep.trace").write_bytes(trace)

    segs = sm_segments(trace)
    probes = []
    readable = []
    for i, label in enumerate(labels):
        if i >= len(segs):
            probes.append({"probe": label, "status": "no-response-parsed"})
            continue
        sw1, sw2, data = segs[i]
        sw = f"{sw1:02X}{sw2:02X}"
        entry = {"probe": label, "sw": sw, "status": status_text(sw1, sw2)}
        if data:
            entry["len"] = len(data)
            entry["prefix_hex"] = data[:16].hex()
            ascii_preview = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[:16])
            entry["prefix_ascii"] = ascii_preview
            if label.startswith("READ SFI"):
                readable.append(label)
        probes.append(entry)
    return {
        "atr": atr,
        "application": "DomRepEID / DomID (AID D276000098446F6D4944)",
        "npa_exit": code,
        "readable_sfi": readable,
        "probes": probes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        labels, apdus = build_profile()
        print("DRY RUN — boundary-14 read-only sweep of the DomRepEID application.")
        print(f"Probes ({len(apdus)}): SELECT AID FCI, then READ SFI 1..30 (16B each).")
        print("Stock npa-tool --translate continues past non-9000; no write/VERIFY/retry.")
        return 0
    if not Path("/run/pcscd/pcscd.comm").exists():
        raise SystemExit("PC/SC socket is unavailable")
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    can = bytearray(sys.stdin.buffer.readline().strip())
    if not drv.valid_can(can):
        drv.cleanse(can)
        raise SystemExit("CAN must be exactly six decimal digits on stdin")
    ident = rb.identify_card()
    atr, uid = ident["atr"], ident["uid"]
    workdir = rb.make_session_dir(uid, "domrepeid")
    try:
        report = sweep(can, atr, workdir)
        report["uid"] = uid
    finally:
        drv.cleanse(can)
    (workdir / "domrepeid.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSession artifacts: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
