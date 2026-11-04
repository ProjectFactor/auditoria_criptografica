#!/usr/bin/env python3
"""Per-card fingerprint registry (Task 4).

Builds a non-PII crypto fingerprint per physical card, keyed by ISO14443 UID, so
distinct cards can be told apart and multi-card patterns (e.g. the RSA-1024 dev
Document Signer) can be tabulated. Reads only the already-captured security objects
under objects/<uid>/ (DG14, EF.CardSecurity, EF.SOD) — no PII, no personal DGs.

The registry is objects/_registry.json (git-ignored, private). Per card it records:
  - chip_auth_spki_sha256  — DG14 CA public key(s); per-card unique anti-clone key
  - cardsecurity_*         — EF.CardSecurity hash + its Document Signer (subject, SPKI,
                             signature hash, development-OU flag)  [RSA-1024 dev-DS marker]
  - sod_*                  — EF.SOD hash + its Document Signer subject / signature hash

Usage:
  python3 card_registry.py --list                 # show the registry
  python3 card_registry.py --current              # register the card on the reader (UID only)
  python3 card_registry.py --card <uid>           # (re)build an entry from objects/<uid>/
  python3 card_registry.py --current --note "free-text label"
"""

from __future__ import annotations

import argparse
import json

import fingerprint as fp
import runbook_common as rb


def build_fields(uid: str) -> dict:
    cdir = rb.OBJECTS_DIR / uid
    if not cdir.is_dir():
        raise SystemExit(f"no captured objects for uid {uid!r} (expected {cdir}/)")
    fields: dict = {"uid": uid, "objects_present": sorted(p.name for p in cdir.glob("*.der"))}

    dg14 = cdir / "dg14.der"
    if dg14.is_file():
        f = fp.fingerprint_dg14(dg14.read_bytes())
        fields["chip_auth_spki_sha256"] = f.get("ec_public_keys_spki_sha256")
        fields["chip_auth_unique_vs_reference"] = f.get("per_card_unique_vs_reference")

    cs = cdir / "cardsecurity.der"
    if cs.is_file():
        f = fp.fingerprint_cardsecurity(cs.read_bytes())
        ds = f.get("document_signer") or {}
        fields["cardsecurity_sha256"] = f.get("sha256")
        fields["cardsecurity_ds_subject"] = ds.get("subject")
        fields["cardsecurity_ds_spki_sha256"] = ds.get("spki_sha256")
        fields["cardsecurity_ds_sig_hash"] = ds.get("signature_hash")
        fields["cardsecurity_development_ou"] = f.get("development_ou")

    sod = cdir / "sod.der"
    if sod.is_file():
        f = fp.fingerprint_sod(sod.read_bytes())
        ds = f.get("document_signer") or {}
        fields["sod_sha256"] = f.get("sha256")
        fields["sod_ds_subject"] = ds.get("subject")
        fields["sod_ds_sig_hash"] = ds.get("signature_hash")
    return fields


def print_registry() -> None:
    reg = rb.load_registry()
    if not reg:
        print("(registry empty — run with --current or --card <uid>)")
        return
    print(f"{len(reg)} card(s) in {rb.REGISTRY_PATH}:\n")
    for uid, e in sorted(reg.items()):
        print(f"UID {uid}")
        print(f"   atr                : {e.get('atr')}")
        print(f"   note               : {e.get('note', '')}")
        print(f"   chip-auth SPKI      : {e.get('chip_auth_spki_sha256')}")
        print(f"   CardSecurity sha256 : {e.get('cardsecurity_sha256')}")
        print(f"   CardSecurity DS     : {e.get('cardsecurity_ds_subject')}  "
              f"(dev_ou={e.get('cardsecurity_development_ou')}, sig={e.get('cardsecurity_ds_sig_hash')})")
        print(f"   SOD DS              : {e.get('sod_ds_subject')}  (sig={e.get('sod_ds_sig_hash')})")
        print(f"   seen               : {e.get('first_seen')} .. {e.get('last_seen')}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="print the registry")
    ap.add_argument("--current", action="store_true", help="register the card on the reader (reads UID only)")
    ap.add_argument("--card", help="(re)build an entry from objects/<uid>/")
    ap.add_argument("--note", help="attach a note to the card being updated")
    args = ap.parse_args()

    if args.current:
        rb.require_pcsc()
        ident = rb.identify_card()
        fields = build_fields(ident["uid"])
        fields["atr"] = ident["atr"]
        if args.note:
            fields["note"] = args.note
        entry = rb.update_registry(ident["uid"], fields)
        print(json.dumps(entry, indent=2, sort_keys=True))
        return 0

    if args.card:
        fields = build_fields(args.card)
        if args.note:
            fields["note"] = args.note
        entry = rb.update_registry(args.card, fields)
        print(json.dumps(entry, indent=2, sort_keys=True))
        return 0

    print_registry()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
