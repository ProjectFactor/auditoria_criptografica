#!/usr/bin/env python3
"""Tier 0 — offline tamper-detection (no card, no CAN).

Proves the integrity checks actually *reject* bad input, not just accept good input:
  1. Baseline (positive control): the cached EF.SOD CMS signature verifies and every
     vouched data group reconciles to its SOD hash.
  2. DG tamper: flipping one byte in each cached DG must break its SOD hash match.
  3. SOD tamper: flipping bytes in the cached EF.SOD must make CMS verification fail.

Operates only on DERs already captured under the git-ignored objects/ (written earlier
by reconcile_sod.py / adaptive_read.py). Prints only hashes and pass/fail — never DG
content. A card whose objects/ lacks a SOD must be read first with reconcile_sod.py.

Usage:
  python3 tier0_tamper.py                 # dry run (plan)
  python3 tier0_tamper.py --execute       # run the offline checks
  python3 tier0_tamper.py --execute --card <atr8>   # pick a specific cached card
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import fingerprint as fp
import reconcile_sod as rec

HERE = Path(__file__).resolve().parent
OBJECTS_DIR = HERE / "objects"


def available_cards() -> dict[str, list[int]]:
    """Map each cached card (UID dir) -> sorted list of DG numbers present (needs a SOD)."""
    cards: dict[str, list[int]] = {}
    for sod in OBJECTS_DIR.glob("*/sod.der"):
        uid = sod.parent.name
        dgs = sorted(int(p.stem[2:]) for p in sod.parent.glob("dg*.der"))
        cards[uid] = dgs
    return cards


def cms_verify(inner_cms: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        cms = Path(td) / "cms.der"
        out = Path(td) / "lds.der"
        cms.write_bytes(inner_cms)
        proc = subprocess.run(
            ["openssl", "cms", "-verify", "-noverify", "-inform", "DER",
             "-in", str(cms), "-out", str(out), "-binary"],
            capture_output=True,
        )
        return proc.returncode == 0 and out.is_file() and out.stat().st_size > 0


def inner_cms_of(sod_der: bytes) -> bytes:
    """Strip the tag-0x77 EF.SOD wrapper to the CMS ContentInfo."""
    if sod_der and sod_der[0] == 0x77:
        for _tag, start, header, _vlen, total in fp._walk(sod_der, 0, len(sod_der)):
            return sod_der[start + header : start + total]
    return sod_der


def flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def run_card(uid: str) -> dict:
    cdir = OBJECTS_DIR / uid
    sod = (cdir / "sod.der").read_bytes()
    lds, sig_ok = rec.extract_lds_security_object(sod)
    alg, stored = rec.parse_lds(lds)
    report: dict = {"card_uid": uid, "hash_algorithm": alg,
                    "checks": [], "pass": True}

    def record(name: str, passed: bool, detail: dict) -> None:
        report["checks"].append({"check": name, "pass": passed, **detail})
        report["pass"] = report["pass"] and passed

    # 1. Baseline positive control -------------------------------------------
    record("baseline: SOD CMS signature verifies", bool(sig_ok),
           {"sod_sha256": fp.sha256_hex(sod)})
    if not alg:
        record("baseline: SOD hash algorithm resolved", False, {"error": "no algorithm"})
        return report

    baseline_matches = {}
    for num in sorted(stored):
        if num == 3:
            continue  # DG3 is EAC-gated; never cached
        path = cdir / f"dg{num}.der"
        if not path.is_file():
            continue
        der = path.read_bytes()
        digest = hashlib.new(alg, der).hexdigest()
        baseline_matches[num] = (digest == stored[num])
    present = sorted(baseline_matches)
    record("baseline: every cached DG reconciles to SOD",
           bool(present) and all(baseline_matches.values()),
           {"dgs_checked": present,
            "dgs_matched": [n for n, ok in baseline_matches.items() if ok]})

    # 2. DG tamper: flipping a byte must break the hash match ------------------
    dg_detected = {}
    for num in present:
        der = (cdir / f"dg{num}.der").read_bytes()
        mid = len(der) // 2
        tampered = flip(der, mid)
        digest = hashlib.new(alg, tampered).hexdigest()
        dg_detected[num] = (digest != stored[num])
    record("DG tamper detected (1-byte flip breaks SOD hash match)",
           bool(dg_detected) and all(dg_detected.values()),
           {"tamper_detected_for_dgs": [n for n, ok in dg_detected.items() if ok],
            "undetected_dgs": [n for n, ok in dg_detected.items() if not ok]})

    # 3. SOD tamper: flipping SIGNED bytes must make CMS verification fail -----
    # Only the signature value and the signed eContent (the LDS DG-hash object) are
    # integrity-protected. The carried Document Signer *certificate* is NOT signed by
    # the SOD, so flipping a byte there correctly still verifies — that is proper CMS
    # behaviour, not a card bug, so we target only the signed regions.
    inner = inner_cms_of(sod)
    if sig_ok and len(inner) > 8:
        targets: dict[str, bool] = {}
        # (a) signature value — flip the last byte (tail of signatureValue)
        targets["signatureValue_tail"] = not cms_verify(flip(inner, len(inner) - 1))
        # (b) signed eContent — locate the LDS object inside the CMS and flip its middle
        idx = inner.find(lds)
        if idx >= 0 and len(lds) > 2:
            targets["eContent_dg_hashes"] = not cms_verify(flip(inner, idx + len(lds) // 2))
        record("SOD tamper detected (signed-region byte flips fail CMS verify)",
               all(targets.values()),
               {"regions_tested": sorted(targets),
                "verify_failed_for": [k for k, failed in targets.items() if failed],
                "verify_STILL_PASSED_for": [k for k, failed in targets.items() if not failed],
                "note": "carried DS certificate is unsigned by the SOD and is intentionally not tested"})
    else:
        record("SOD tamper detected", False,
               {"error": "baseline SOD did not verify or CMS too short to tamper"})
    return report


def dry_run() -> None:
    cards = available_cards()
    print("DRY RUN — Tier 0 offline tamper-detection (no card, no CAN).\n")
    print("Plan:")
    print("  1. baseline: CMS-verify cached EF.SOD; reconcile every cached DG to its SOD hash")
    print("  2. DG tamper: flip the middle byte of each DG -> expect SOD hash MISMATCH (detected)")
    print("  3. SOD tamper: flip 4 bytes of the inner CMS -> expect CMS verify FAILS (detected)")
    if not cards:
        print("\nNo cached cards in objects/. Run reconcile_sod.py --execute first to capture a SOD + DGs.")
        return
    print("\nCached cards available (UID -> DG numbers):")
    for uid, dgs in cards.items():
        print(f"  {uid}: DGs {dgs}")
    print("\nAdd --execute to run; --card <uid> to select one (default: the card with the most DGs).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true", help="run the offline checks (default: dry run)")
    parser.add_argument("--card", help="UID of a cached card (default: most DGs)")
    args = parser.parse_args()

    if not args.execute:
        dry_run()
        return 0

    cards = available_cards()
    if not cards:
        raise SystemExit("no cached SOD in objects/<uid>/; run reconcile_sod.py --execute first")
    uid = args.card or max(cards, key=lambda k: len(cards[k]))
    if uid not in cards:
        raise SystemExit(f"unknown card {uid!r}; available: {sorted(cards)}")

    report = run_card(uid)
    print(json.dumps(report, indent=2))
    verdict = "PASS — integrity checks reject tampered input" if report["pass"] \
        else "FAIL — a tampered input was NOT rejected (see checks)"
    print(f"\n{verdict}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
