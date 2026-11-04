#!/usr/bin/env python3
"""Tier 2 (raw) — secure-channel enforcement at the PC/SC level (no npa-tool, no PACE).

npa-tool always builds the SM wrapper correctly, so it cannot send a plaintext, a
MAC-tampered, or a downgraded APDU. This tool therefore tests the one enforcement
property reachable without a custom PACE/SM stack: **protected data must be
inaccessible without establishing the secure channel**. It talks to the card directly
with raw SCardTransmit, having done NO PACE:

  CONTROL  read EF.CardAccess (public)              -> expect 9000 (reader works)
  P1       read EF.COM over the eMRTD app, no PACE  -> expect DENIED
  P2       read DG1  over the eMRTD app, no PACE    -> expect DENIED
  P3       UPDATE BINARY on EF.CardAccess, no PACE  -> expect DENIED

PASS = control succeeds AND every protected read/write is refused. A protected read
returning data would be a serious access-control bug. No CAN, no PIN, no PACE, no write
actually lands (writes are expected to be refused).

NOT covered here (require a from-scratch PACE+SM implementation, documented in
VALIDATION_PLAN.md): in-session SM MAC tamper, and PACE/CA suite downgrade.

Usage:
  python3 tier2_raw.py              # dry run (plan)
  python3 tier2_raw.py --execute    # run (no credential needed)
"""

from __future__ import annotations

import argparse
import json

import runbook_common as rb

SELECT_MF = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]
SELECT_CARDACCESS = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C]
SELECT_EMRTD = [0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
SELECT_COM = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E]
SELECT_DG1 = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01]
READ_16 = [0x00, 0xB0, 0x00, 0x00, 0x10]
READ_32 = [0x00, 0xB0, 0x00, 0x00, 0x20]
UPDATE_1 = [0x00, 0xD6, 0x00, 0x00, 0x01, 0x00]

# (id, description, setup APDUs, judged APDU, expect)
PROBES = [
    ("CONTROL", "read EF.CardAccess (public, no PACE)",
     [SELECT_MF, SELECT_CARDACCESS], READ_32, "success"),
    ("P1", "read EF.COM over eMRTD app, no PACE",
     [SELECT_EMRTD, SELECT_COM], READ_16, "denied"),
    ("P2", "read DG1 over eMRTD app, no PACE",
     [SELECT_EMRTD, SELECT_DG1], READ_16, "denied"),
    ("P3", "UPDATE BINARY on EF.CardAccess, no PACE",
     [SELECT_MF, SELECT_CARDACCESS], UPDATE_1, "denied"),
]


def hx(apdu: list[int]) -> str:
    return " ".join(f"{b:02X}" for b in apdu)


def succeeded(sw1: int, data: list[int]) -> bool:
    # A read "succeeded" (or, for a protected file, leaked) if the card returned any
    # data, or a plain success SW. 6282 ("EOF reached") still returns the file's bytes.
    return bool(data) or sw1 in (0x90, 0x61)


def run() -> dict:
    from smartcard.scard import (
        SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        SCardEstablishContext, SCardListReaders, SCardConnect, SCardStatus,
        SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD,
    )
    hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    hr, rdrs = SCardListReaders(ctx, [])
    picc = [r for r in rdrs if "PICC" in r]
    if not picc:
        raise SystemExit("no PICC reader found")
    ident = rb.identify_card()
    hr, card, proto = SCardConnect(ctx, picc[0], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)

    def transmit(apdu: list[int]) -> tuple[list[int], int, int]:
        hr, resp = SCardTransmit(card, proto, apdu)
        if len(resp) >= 2:
            return list(resp[:-2]), resp[-2], resp[-1]
        return [], 0x00, 0x00

    results = []
    all_pass = True
    try:
        for pid, desc, setup, judged, expect in PROBES:
            for s in setup:
                transmit(s)  # setup selects; their SW not judged
            data, sw1, sw2 = transmit(judged)
            ok_success = succeeded(sw1, data)
            passed = ok_success if expect == "success" else (not ok_success)
            all_pass = all_pass and passed
            results.append({
                "id": pid, "probe": desc, "judged_apdu": hx(judged),
                "sw": rb.sw_hex(sw1, sw2), "meaning": rb.describe_sw(sw1, sw2),
                "data_bytes_returned": len(data),
                "expected": expect,
                "pass": passed,
                "verdict": ("OK" if passed else
                            ("UNEXPECTED DENIAL" if expect == "success"
                             else "UNEXPECTED SUCCESS (access-control bug)")),
            })
    finally:
        SCardDisconnect(card, SCARD_LEAVE_CARD)

    return {"tier": "2-raw", "atr": ident["atr"], "uid": ident["uid"],
            "check": "secure-channel mandatory for protected data (raw, no PACE)",
            "pass": all_pass, "probes": results,
            "not_covered": ["in-session SM MAC tamper", "PACE/CA suite downgrade"]}


def dry_run() -> None:
    print("DRY RUN — Tier 2 (raw) secure-channel enforcement; no PACE, no credential.\n")
    for pid, desc, setup, judged, expect in PROBES:
        print(f"[{pid}] {desc}")
        for s in setup:
            print(f"      setup : {hx(s)}")
        print(f"      JUDGED: {hx(judged)}   -> expect {expect}")
    print("\nPASS = control reads EF.CardAccess (9000) AND every protected read/write is refused.")
    print("Not covered (need a from-scratch PACE+SM stack): SM MAC tamper, PACE/CA downgrade.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()
    if not args.execute:
        dry_run()
        return 0
    rb.require_pcsc()
    report = run()
    workdir = rb.make_session_dir(report["uid"], "tier2raw")
    (workdir / "tier2raw.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n{'PASS — secure channel is mandatory' if report['pass'] else 'FAIL — protected data reachable without PACE'}"
          f"  (artifacts: {workdir})")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
