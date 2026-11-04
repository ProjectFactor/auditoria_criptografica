#!/usr/bin/env python3
"""Tier 1 — read-only live checks (no state change, no counter use).

Over CAN/PACE, confirms two enforced-security properties without ever submitting a
credential or mutating card state:

  A. PACE reproducibility — read a non-PII object (EF.CardSecurity) twice in two
     independent PACE sessions; the bytes must be identical.
  B. Non-mutating PIN status — send the case-1 status query `00 20 00 <ref>` for each
     PIN/PUK and read its `63Cx` retry counter WITHOUT decrementing it; the SO query
     is issued twice as a no-decrement control (both reads must match).

No VERIFY with a value, no write, no retry consumed. Uses the stock npa-tool for the
status sweep (so it continues past the expected non-9000 `63Cx`). The CAN is read from
stdin, held in memory, cleansed, and redacted from saved traces.

Usage:
  python3 tier1_readonly.py                               # dry run (plan)
  printf '<CAN>' | python3 tier1_readonly.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import npa_driver as drv
import runbook_common as rb

# PKCS#15 ADF (holds User PIN 0x83, SO PIN 0x84) and SSCD ADF (Signature PIN 0x92, PUK 0x93).
P15_AID_SELECT = "00 A4 04 0C 0C A0 00 00 00 63 50 4B 43 53 2D 31 35"
SSCD_AID_SELECT = "00 A4 04 0C 09 A0 00 00 00 63 53 53 43 44"
SENTINEL = "# Unread EOF sentinel; the blank line above terminates translation cleanly."

# EF.CardSecurity (non-PII) selects, reused for the reproducibility read.
CARDSECURITY_SELECTS = ["00 A4 00 0C 02 3F 00", "00 A4 02 0C 02 01 1D"]

# (label, apdu) for the status sweep, in order.
STATUS_SWEEP = [
    ("select PKCS#15 ADF", P15_AID_SELECT),
    ("status User PIN (ref 0x83)", "00 20 00 83"),
    ("status SO PIN (ref 0x84)", "00 20 00 84"),
    ("status SO PIN (ref 0x84) — control", "00 20 00 84"),
    ("select SSCD ADF", SSCD_AID_SELECT),
    ("status Signature PIN (ref 0x92)", "00 20 00 92"),
    ("status Signature PUK (ref 0x93)", "00 20 00 93"),
]


def retry_counter(sw1: int, sw2: int) -> int | None:
    return (sw2 & 0x0F) if (sw1 == 0x63 and (sw2 & 0xF0) == 0xC0) else None


def reproducibility(can: bytearray, atr: str, workdir: Path) -> dict:
    der1, e1 = drv.read_ef(can, atr, CARDSECURITY_SELECTS, workdir, "cardsec_read1")
    der2, e2 = drv.read_ef(can, atr, CARDSECURITY_SELECTS, workdir, "cardsec_read2")
    if e1 or e2:
        return {"check": "PACE reproducibility (EF.CardSecurity x2)", "pass": False,
                "error": e1 or e2}
    h1 = hashlib.sha256(der1).hexdigest()
    h2 = hashlib.sha256(der2).hexdigest()
    return {"check": "PACE reproducibility (EF.CardSecurity x2)", "pass": h1 == h2,
            "read1_sha256": h1, "read2_sha256": h2, "bytes": len(der1)}


def pin_status(can: bytearray, atr: str, workdir: Path) -> dict:
    labels = [lbl for lbl, _ in STATUS_SWEEP]
    apdus = [apdu for _, apdu in STATUS_SWEEP]
    prof = workdir / "pin_status.apdus"
    prof.write_text("\n".join(apdus + ["", SENTINEL]) + "\n", encoding="ascii")
    code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    (workdir / "pin_status.trace").write_bytes(trace)

    segs = rb.sm_segments(trace)
    rows = []
    by_label: dict[str, dict] = {}
    for i, label in enumerate(labels):
        if i >= len(segs):
            row = {"probe": label, "status": "no-response-parsed"}
        else:
            sw1, sw2, _ = segs[i]
            row = {"probe": label, "sw": rb.sw_hex(sw1, sw2),
                   "meaning": rb.describe_sw(sw1, sw2)}
            rc = retry_counter(sw1, sw2)
            if rc is not None:
                row["retries_remaining"] = rc
        rows.append(row)
        by_label[label] = row

    user = by_label.get("status User PIN (ref 0x83)", {})
    so1 = by_label.get("status SO PIN (ref 0x84)", {})
    so2 = by_label.get("status SO PIN (ref 0x84) — control", {})
    user_ok = "retries_remaining" in user
    so_ok = "retries_remaining" in so1
    no_decrement = so1.get("sw") == so2.get("sw") and so1.get("sw") is not None
    passed = bool(user_ok and so_ok and no_decrement)
    return {
        "check": "non-mutating PIN status (no decrement)",
        "pass": passed,
        "npa_exit": code,
        "user_pin": user.get("retries_remaining"),
        "so_pin": so1.get("retries_remaining"),
        "so_pin_no_decrement": no_decrement,
        "signature_pin": by_label.get("status Signature PIN (ref 0x92)", {}).get("retries_remaining"),
        "signature_puk": by_label.get("status Signature PUK (ref 0x93)", {}).get("retries_remaining"),
        "note": "User/SO counters are the pass criterion; Signature refs are supplementary "
                "(depend on SSCD select context) and reported raw.",
        "probes": rows,
    }


def dry_run() -> None:
    print("DRY RUN — Tier 1 read-only live checks (no state change, no counter use).\n")
    print("A. PACE reproducibility:")
    print(f"     read EF.CardSecurity twice: selects {CARDSECURITY_SELECTS}")
    print("     -> pass if the two reads are byte-identical")
    print("\nB. Non-mutating PIN status (stock npa-tool, continues past 63Cx):")
    for lbl, apdu in STATUS_SWEEP:
        print(f"     {apdu:<34}  {lbl}")
    print("\n   -> pass if User (0x83) and SO (0x84) return 63Cx AND both SO reads match (no decrement).")
    print("      No PIN value is submitted; status queries do not consume retries.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    if not args.execute:
        dry_run()
        return 0
    rb.require_pcsc()
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    (can,) = rb.read_lines_from_stdin(1)
    if not drv.valid_can(can):
        rb.cleanse_all(can)
        raise SystemExit("CAN must be exactly six decimal digits on stdin")
    try:
        ident = rb.identify_card()
        atr, uid = ident["atr"], ident["uid"]
        workdir = rb.make_session_dir(uid, "tier1")
        report = {"tier": 1, "atr": atr, "uid": uid, "checks": []}
        report["checks"].append(reproducibility(can, atr, workdir))
        report["checks"].append(pin_status(can, atr, workdir))
    finally:
        rb.cleanse_all(can)
    report["pass"] = all(c.get("pass") for c in report["checks"])
    (workdir / "tier1.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n{'PASS' if report['pass'] else 'FAIL'} — Tier 1  (artifacts: {workdir})")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
