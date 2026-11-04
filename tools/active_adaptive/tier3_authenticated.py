#!/usr/bin/env python3
"""Tier 3 — authenticated ops with a credential you legitimately hold (transient state).

Requires the held PIN. Confirms two enforced-security properties and changes only
transient (reset-on-power) security state — no persistent change:

  1. VERIFY the held PIN -> 9000, and a follow-up status query shows the counter still
     at full (a successful verify resets it; nothing is consumed).
  2. (User PIN only) Boundary-8 key-op gating: after the User-PIN verify, MSE:SET +
     INTERNAL AUTHENTICATE on key 0x42 must be DENIED (expected 6982 — DF 5015 is in
     initialisation 0x03). A 9000 would be an unexpected capability.

Safety:
  * ONE VERIFY per run (never a retry loop) — guarded by --i-hold-this-pin so the tool
    cannot be used to brute-force. Submitting a WRONG PIN would decrement the counter.
  * The PIN is read from stdin (line 2, after the CAN on line 1), held in memory,
    cleansed, written only to a 0600 temp profile that is zeroed and unlinked, and
    redacted from the saved trace. It is never written to the session directory.
  * Safe on the production cédula (read/transient only).

Usage:
  python3 tier3_authenticated.py                           # dry run (plan)
  printf '<CAN>\\n<PIN>' | python3 tier3_authenticated.py --can-stdin --pin-stdin \\
      --pin-ref user --i-hold-this-pin --execute
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import npa_driver as drv
import runbook_common as rb

P15_AID_SELECT = "00 A4 04 0C 0C A0 00 00 00 63 50 4B 43 53 2D 31 35"
SENTINEL = "# Unread EOF sentinel; the blank line above terminates translation cleanly."

PIN_REF = {"user": 0x83, "so": 0x84}
FULL_COUNTER = {"user": 3, "so": 5}  # observed full retry counters (supplementary check)

# Boundary-8 key-op gating (User PIN only): MSE:SET AT for key 0x42, then INTERNAL AUTHENTICATE.
KEYOP_MSE = "00 22 41 A4 03 84 01 42"
KEYOP_INTAUTH = "00 88 00 00 08 00 01 02 03 04 05 06 07 00"


def verify_apdu(p2: int, pin: bytes) -> str:
    body = " ".join(f"{b:02X}" for b in pin)
    return f"00 20 00 {p2:02X} {len(pin):02X} {body}"


def status_apdu(p2: int) -> str:
    return f"00 20 00 {p2:02X}"


def retry_counter(sw1: int, sw2: int) -> int | None:
    return (sw2 & 0x0F) if (sw1 == 0x63 and (sw2 & 0xF0) == 0xC0) else None


def run_with_secret(apdu_lines: list[str], secret: bytes, can: bytearray,
                    atr: str, workdir: Path) -> tuple[int, bytes]:
    """Write a 0600 temp profile (containing the VERIFY+PIN), run it, then zero+unlink
    the profile and redact the secret from the returned trace."""
    fd, path = tempfile.mkstemp(prefix=".tier3_", suffix=".apdus", dir=str(workdir))
    prof = Path(path)
    try:
        os.write(fd, ("\n".join(apdu_lines + ["", SENTINEL]) + "\n").encode("ascii"))
        os.close(fd)
        code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    finally:
        try:
            size = prof.stat().st_size
            with open(prof, "r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
        try:
            prof.unlink()
        except OSError:
            pass
    return code, rb.redact_secret(trace, secret)


def run_tier3(pin_ref: str, can: bytearray, pin: bytearray, atr: str, workdir: Path) -> dict:
    p2 = PIN_REF[pin_ref]
    labels = ["select PKCS#15 ADF", "status before VERIFY", "VERIFY (held PIN)", "status after VERIFY"]
    apdus = [P15_AID_SELECT, status_apdu(p2), verify_apdu(p2, bytes(pin)), status_apdu(p2)]
    if pin_ref == "user":
        labels += ["MSE:SET key 0x42", "INTERNAL AUTHENTICATE key 0x42"]
        apdus += [KEYOP_MSE, KEYOP_INTAUTH]

    code, trace = run_with_secret(apdus, bytes(pin), can, atr, workdir)
    (workdir / "tier3.trace").write_bytes(trace)  # already redacted
    segs = rb.sm_segments(trace)

    def seg(i: int) -> tuple[int, int, bytes]:
        return segs[i] if i < len(segs) else (0, 0, b"")

    rows = []
    for i, label in enumerate(labels):
        sw1, sw2, _ = seg(i)
        row = {"step": label, "sw": rb.sw_hex(sw1, sw2), "meaning": rb.describe_sw(sw1, sw2)}
        rc = retry_counter(sw1, sw2)
        if rc is not None:
            row["retries_remaining"] = rc
        rows.append(row)

    v_sw1, v_sw2, _ = seg(2)
    verify_ok = (v_sw1 == 0x90 and v_sw2 == 0x00)
    a_sw1, a_sw2, _ = seg(3)
    before = retry_counter(*seg(1)[:2])
    after = retry_counter(a_sw1, a_sw2)
    # After a successful VERIFY, re-sending the case-1 status query returns 9000
    # ("already verified" — the PIN state is satisfied for this session), or a 63Cx
    # counter that must not have decremented. Either proves nothing was consumed.
    already_verified = (a_sw1 == 0x90 and a_sw2 == 0x00)
    counter_ok = already_verified or (after is not None and (before is None or after >= before))

    checks = [{
        "check": f"VERIFY held {pin_ref.upper()} PIN -> 9000, counter not consumed",
        "pass": bool(verify_ok and counter_ok),
        "verify_sw": rb.sw_hex(v_sw1, v_sw2),
        "status_after_verify": "already-verified (9000)" if already_verified
                               else f"counter={after}",
        "counter_before": before, "counter_after": after,
        "counter_full_expected": FULL_COUNTER[pin_ref],
    }]

    if pin_ref == "user":
        k_sw1, k_sw2, _ = seg(5)
        denied = not (k_sw1 in (0x90, 0x61))
        checks.append({
            "check": "Boundary-8 key-op gating: INTERNAL AUTHENTICATE key 0x42 denied",
            "pass": bool(denied),
            "int_auth_sw": rb.sw_hex(k_sw1, k_sw2),
            "meaning": rb.describe_sw(k_sw1, k_sw2),
            "verdict": "DENIED (expected — DF 5015 in init 0x03)" if denied
                       else "UNEXPECTED SUCCESS (key usable?)",
            "note": "MSE bytes are best-effort; a 6xxx denial confirms the key is not usable.",
        })

    return {"tier": 3, "atr": atr, "pin_ref": pin_ref,
            "pass": all(c["pass"] for c in checks), "checks": checks, "steps": rows}


def dry_run(pin_ref: str) -> None:
    p2 = PIN_REF[pin_ref]
    print(f"DRY RUN — Tier 3 authenticated ops for the {pin_ref.upper()} PIN (ref 0x{p2:02X}).\n")
    print("Single PACE session; stock npa-tool. Steps:")
    print(f"   select PKCS#15 ADF : {P15_AID_SELECT}")
    print(f"   status before      : {status_apdu(p2)}        -> 63Cx")
    print(f"   VERIFY held PIN    : 00 20 00 {p2:02X} <len> <PIN bytes>   -> expect 9000")
    print(f"   status after       : {status_apdu(p2)}        -> 63Cx (back at full)")
    if pin_ref == "user":
        print(f"   MSE:SET key 0x42   : {KEYOP_MSE}")
        print(f"   INTERNAL AUTH      : {KEYOP_INTAUTH}   -> expect DENIED (6982)")
    print("\nSafety: ONE verify, no retry loop. Submitting a WRONG PIN would decrement the counter,")
    print("so run only with the value you hold (acknowledge with --i-hold-this-pin).")
    print("The PIN is never written to the session dir and is redacted from the trace.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pin-ref", choices=sorted(PIN_REF), default="user")
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--pin-stdin", action="store_true")
    parser.add_argument("--i-hold-this-pin", action="store_true",
                        help="acknowledge the PIN on stdin is the correct held credential")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    if not args.execute:
        dry_run(args.pin_ref)
        return 0
    rb.require_pcsc()
    if not (args.can_stdin and args.pin_stdin):
        raise SystemExit("live mode requires --can-stdin and --pin-stdin (CAN on line 1, PIN on line 2)")
    if not args.i_hold_this_pin:
        raise SystemExit("refusing to VERIFY without --i-hold-this-pin (a wrong PIN decrements the counter)")
    can, pin = rb.read_lines_from_stdin(2)
    if not drv.valid_can(can) or not rb.valid_pin(pin):
        rb.cleanse_all(can, pin)
        raise SystemExit("need a 6-digit CAN on line 1 and a 4–12 digit PIN on line 2")
    try:
        ident = rb.identify_card()
        atr, uid = ident["atr"], ident["uid"]
        workdir = rb.make_session_dir(uid, f"tier3_{args.pin_ref}")
        report = run_tier3(args.pin_ref, can, pin, atr, workdir)
        report["uid"] = uid
    finally:
        rb.cleanse_all(can, pin)
    (workdir / "tier3.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n{'PASS' if report['pass'] else 'FAIL'} — Tier 3  (artifacts: {workdir})")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
