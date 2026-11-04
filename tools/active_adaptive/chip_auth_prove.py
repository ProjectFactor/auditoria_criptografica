#!/usr/bin/env python3
"""Live Chip-Authentication v1 possession proof for an arbitrary cédula.

Runs the card-agnostic CA binary (built by build-chip-auth-generic.sh) which, after
CAN/PACE, performs CA-v1 using the card's live DG14 public key and then reads EF.COM
under CA-derived secure messaging. A successful CA-protected read proves the chip
holds the non-exportable private counterpart of its DG14 public key (anti-clone).

No PIN/PUK/TA/DG3/write. EF.COM's first bytes (not personal data) are the only read.

Usage:  printf '<CAN>' | python3 chip_auth_prove.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv

HERE = Path(__file__).resolve().parent
CA_BINARY = HERE / "build" / "npa-tool-chip-auth-generic"
SESSIONS_DIR = HERE / "sessions"

SUCCESS = b"chip possession proven"
CA_OID_IN_DG14 = "060a04007f00070202030204"  # id-CA-ECDH-AES-CBC-CMAC-256


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print("DRY RUN — would run CA-v1 against the live DG14 key and read EF.COM under CA SM.")
        print("Binary:", CA_BINARY, "(exists)" if CA_BINARY.is_file() else "(NOT BUILT — run build-chip-auth-generic.sh)")
        return 0
    if not CA_BINARY.is_file():
        raise SystemExit(f"CA binary missing: {CA_BINARY}\nBuild it: sh build-chip-auth-generic.sh <src-dir>")
    if not Path("/run/pcscd/pcscd.comm").exists():
        raise SystemExit("PC/SC socket is unavailable")
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    can = bytearray(sys.stdin.buffer.readline().strip())
    if not drv.valid_can(can):
        drv.cleanse(can)
        raise SystemExit("CAN must be exactly six decimal digits on stdin")

    from smartcard.scard import (
        SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        SCardEstablishContext, SCardListReaders, SCardConnect, SCardStatus,
        SCardDisconnect, SCARD_LEAVE_CARD,
    )
    hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    hr, rdrs = SCardListReaders(ctx, [])
    picc = [r for r in rdrs if "PICC" in r][0]
    hr, card, proto = SCardConnect(ctx, picc, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)
    atr = "".join(f"{b:02X}" for b in SCardStatus(card)[4])
    SCardDisconnect(card, SCARD_LEAVE_CARD)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    workdir = SESSIONS_DIR / f"{stamp}_{atr[-8:]}_chipauth"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        code, trace = drv.run(can, atr, extra_args=["--read-dg14"], binary=CA_BINARY)
    finally:
        drv.cleanse(can)
    (workdir / "chip_auth.trace").write_bytes(trace)

    proven = code == 0 and SUCCESS in trace
    ga_ok = b"General Authenticate failed" not in trace
    print(f"ATR: {atr}")
    print(f"exit code: {code}")
    print(f"CA General Authenticate accepted: {ga_ok}")
    print(f"POSSESSION PROVEN: {proven}")
    if not proven:
        for line in trace.split(b"\n"):
            if re.search(rb"CA-v1|guard|fail|Error", line, re.I):
                print("  |", line.decode("latin1").strip()[:120])
    print(f"\nSession artifacts: {workdir}")
    return 0 if proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
