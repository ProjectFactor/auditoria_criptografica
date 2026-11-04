#!/usr/bin/env python3
"""Adaptive, card-agnostic reader for non-PII eID security objects.

For each requested object it (1) opens CAN/PACE and reads a short header to learn
the object's DER length, then (2) opens CAN/PACE again and reads exactly that many
bytes in <=224-byte chunks, so every READ BINARY returns 9000 and the fail-closed
npa-tool never halts on an end-of-file warning. The reconstructed DER is hashed and
fingerprinted (signer certs, public-key SPKI digests); no personal data group is
read. The CAN is taken from stdin, kept in memory, and cleansed.

Usage:
  printf '<6-digit-CAN>' | python3 adaptive_read.py --can-stdin \
      --objects cardsecurity,dg14,sod,com [--execute]

Default is a dry run (prints the exact APDU plan; no card or credential access).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv
import runbook_common as rb
from fingerprint import FINGERPRINTERS

HERE = Path(__file__).resolve().parent
# object -> (SELECT APDUs issued before the read; P2=0C so selects yield no data)
OBJECTS: dict[str, list[str]] = {
    "cardsecurity": ["00 A4 00 0C 02 3F 00", "00 A4 02 0C 02 01 1D"],  # MF / EF.CardSecurity
    "dg14": ["00 A4 02 0C 02 01 0E"],  # eMRTD DF / DG14
    "sod": ["00 A4 02 0C 02 01 1D"],  # eMRTD DF / EF.SOD
    "com": ["00 A4 02 0C 02 01 1E"],  # eMRTD DF / EF.COM
    "cvca": ["00 A4 02 0C 02 01 1C"],  # eMRTD DF / EF.CVCA (EAC trust-anchor reference)
}


def read_object(name: str, can: bytearray, atr: str, uid: str, workdir: Path) -> dict:
    result: dict = {"object": name}
    der, err = drv.read_ef(can, atr, OBJECTS[name], workdir, name)
    if err:
        result["error"] = err
        return result
    result["declared_der_length"] = len(der)
    der_path = rb.object_path(uid, name)
    der_path.write_bytes(der)
    result["der_file"] = str(der_path)
    try:
        result["fingerprint"] = FINGERPRINTERS[name](der)
    except Exception as exc:
        result["fingerprint_error"] = f"{type(exc).__name__}: {exc}"
    return result


def dry_run(objects: list[str]) -> None:
    print("DRY RUN — no card or credential access.\n")
    for name in objects:
        print(f"[{name}]  selects: {OBJECTS[name]}")
        print(f"          phase A: {drv.read_apdu(0, 8)}  (header -> DER length)")
        print(f"          phase B: {drv.read_apdu(0, drv.CHUNK)} ... sized to the declared length")
    print("\nEach invocation runs CAN/PACE; every APDU must return 9000 or npa-tool halts.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--objects", default="cardsecurity,dg14,sod,com")
    parser.add_argument("--can-stdin", action="store_true", help="read the 6-digit CAN from stdin")
    parser.add_argument("--execute", action="store_true", help="perform the live session (default: dry run)")
    args = parser.parse_args()

    objects = [o.strip() for o in args.objects.split(",") if o.strip()]
    unknown = [o for o in objects if o not in OBJECTS]
    if unknown:
        raise SystemExit(f"unknown objects: {unknown}; known: {sorted(OBJECTS)}")

    if not args.execute:
        dry_run(objects)
        return 0

    if not Path("/run/pcscd/pcscd.comm").exists():
        raise SystemExit("PC/SC socket is unavailable; this runner will not start it")
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    raw = sys.stdin.buffer.readline().strip()
    can = bytearray(raw)
    if not drv.valid_can(can):
        drv.cleanse(can)
        raise SystemExit("CAN must be exactly six decimal digits on stdin")

    try:
        ident = rb.identify_card()
    except SystemExit:
        drv.cleanse(can)
        raise
    atr, uid = ident["atr"], ident["uid"]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    workdir = rb.make_session_dir(uid, "adaptive_read")
    summary = {"utc": stamp, "atr": atr, "uid": uid, "objects": {}}
    try:
        for name in objects:
            print(f"-> reading {name} (uid {uid}) ...", flush=True)
            summary["objects"][name] = read_object(name, can, atr, uid, workdir)
            time.sleep(0.2)
    finally:
        drv.cleanse(can)
    (workdir / "summary.json").write_text(json.dumps(summary, indent=2))
    print("\n" + json.dumps(summary, indent=2))
    print(f"\nSession artifacts: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
