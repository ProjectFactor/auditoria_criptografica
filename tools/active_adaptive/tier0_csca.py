#!/usr/bin/env python3
"""Tier 0 — CSCA chain + revocation validator (offline, no card).

The supplied CSCA must be obtained and authenticated through an authorized
channel. This offline tool checks a direct DS/CSCA relationship and optional
revocation evidence; a self-consistent supplied root does not establish issuer
provenance. Missing revocation evidence is reported as not checked.

Checks, against a candidate CSCA:
  1. CSCA is self-consistent (self-signed signature verifies).
  2. DS AuthorityKeyIdentifier  == CSCA SubjectKeyIdentifier.
  3. DS issuer DN               == CSCA subject DN.
  4. DS signature verifies under the CSCA public key.
  5. Both certificates are within their validity window (at --at or now).
  6. CSCA keyUsage asserts keyCertSign (and cRLSign if a CRL is supplied).
  7. If --crl given: CRL verifies under the CSCA and the DS serial is not revoked.

PASS requires every applicable check to hold. Matching country/issuer name alone
is INSUFFICIENT: the AKI/SKI identity and the signature must both check out.

Usage:
  python3 tier0_csca.py                           # dry run: print the required CSCA
  python3 tier0_csca.py --csca jce-csca.pem       # validate the chain
  python3 tier0_csca.py --csca c.pem --crl r.crl  # + revocation
  python3 tier0_csca.py --selftest                # offline logic self-test
"""
from __future__ import annotations
import argparse, subprocess, re, sys, tempfile, os, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "icao"))
from verify_passive_auth import (
    _aki, _ski, authority_constraints, crl_freshness_at, load_certificates,
    load_crl, parse_time, unsupported_critical_extensions, validity_at, verify_crl_signature, verify_signed_by,
)

DEFAULT_DS = Path(__file__).resolve().parents[2] / "exports/certificates/jce-ds-02.pem"


def ossl(args, inp=None):
    return subprocess.run(["openssl", *args], input=inp, capture_output=True, text=True)


def field(cert, kind):
    """kind in {subject, issuer, serial, startdate, enddate, SKI, AKI, keyusage}."""
    if kind in ("subject", "issuer", "serial", "startdate", "enddate"):
        flag = {"subject": "-subject", "issuer": "-issuer", "serial": "-serial",
                "startdate": "-startdate", "enddate": "-enddate"}[kind]
        out = ossl(["x509", "-in", cert, "-noout", flag]).stdout.strip()
        return out.split("=", 1)[1].strip() if "=" in out else out
    text = ossl(["x509", "-in", cert, "-noout", "-text"]).stdout
    if kind == "SKI":
        m = re.search(r"Subject Key Identifier:\s*\n\s*([0-9A-Fa-f:]+)", text)
        return m.group(1).replace(":", "").lower() if m else None
    if kind == "AKI":
        m = re.search(r"Authority Key Identifier:\s*\n\s*(?:keyid:)?([0-9A-Fa-f:]+)", text)
        return m.group(1).replace(":", "").lower() if m else None
    if kind == "keyusage":
        m = re.search(r"Key Usage[^\n]*\n\s*([^\n]+)", text)
        return m.group(1).strip() if m else ""
    return None


def required_descriptor(ds):
    return {"ds_subject": field(ds, "subject"), "ds_issuer": field(ds, "issuer"),
            "ds_serial": field(ds, "serial"), "required_csca_SKI_equals_ds_AKI": field(ds, "AKI"),
            "ds_valid_from": field(ds, "startdate"), "ds_valid_to": field(ds, "enddate")}


def validate(csca, ds, crl, at=None):
    root = load_certificates(Path(csca))
    signer = load_certificates(Path(ds))
    if len(root) != 1 or len(signer) != 1:
        raise ValueError("exactly one CSCA and one DS certificate are required")
    root, signer = root[0], signer[0]
    moment = (datetime.fromtimestamp(float(at), timezone.utc) if at and re.fullmatch(r"\d+(?:\.\d+)?", at)
              else parse_time(at) if at else datetime.now(timezone.utc))
    r = {"checks": {}, "validation_time": moment.isoformat(),
         "validation_policy": "Require CSCA and DS certificate validity at the requested time (default: now)",
         "trust_basis": "supplied_candidate; issuer_provenance_must_be_authenticated_out_of_band",
         "revocation": "not_checked",
         "unsupported_critical_extensions": {
             "csca": unsupported_critical_extensions(root), "ds": unsupported_critical_extensions(signer)}}
    ds_aki, csca_ski = _aki(signer), _ski(root)
    r["checks"]["aki_ski_match"] = (ds_aki is not None and ds_aki == csca_ski)
    r["checks"]["issuer_subject_match"] = signer.issuer == root.subject
    self_signed, self_reason = verify_signed_by(root, root)
    r["checks"]["csca_self_signed"] = root.subject == root.issuer and self_signed
    signed, reason = verify_signed_by(signer, root)
    r["checks"]["ds_sig_under_csca"] = signed
    r["verify_output"] = reason
    r["self_signature_result"] = self_reason
    r["checks"]["ds_in_validity"] = validity_at(signer, moment) == "valid"
    r["checks"]["csca_in_validity"] = validity_at(root, moment) == "valid"
    role_valid, role_reason = authority_constraints(root)
    r["checks"]["csca_keyCertSign"] = role_valid
    r["csca_keyusage"] = role_reason
    if crl:
        from cryptography import x509
        candidate = load_crl(Path(crl))
        crl_role, crl_role_reason = authority_constraints(root, for_crl=True)
        r["checks"]["csca_cRLSign"] = crl_role
        r["checks"]["crl_issuer_match"] = candidate.issuer == root.subject
        try:
            aki = candidate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        except x509.ExtensionNotFound:
            aki = None
        r["checks"]["crl_key_identifier_match"] = not (aki and csca_ski and aki.hex() != csca_ski)
        r["checks"]["crl_signature_valid"] = verify_crl_signature(candidate, root)
        r["unsupported_critical_extensions"]["crl"] = unsupported_critical_extensions(candidate, crl=True)
        r["crl_freshness"] = crl_freshness_at(candidate, moment)
        r["checks"]["crl_current"] = r["crl_freshness"] == "current"
        r["checks"]["full_issuer_crl"] = not any(
            isinstance(e.value, (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint)) for e in candidate.extensions)
        authentic_current = all(r["checks"].values())
        entry = candidate.get_revoked_certificate_by_serial_number(signer.serial_number)
        ds_revoked = entry is not None and entry.revocation_date_utc <= moment
        r["checks"]["ds_not_revoked"] = authentic_current and not ds_revoked
        r["revocation"] = ("revoked" if ds_revoked else "good") if authentic_current else "unknown"
        r["crl_output"] = crl_role_reason + "; " + r["crl_freshness"]
    r["pass"] = all(r["checks"].values())
    return r


def _crl_pem(crl):
    txt = Path(crl).read_text(errors="ignore")
    if "BEGIN X509 CRL" in txt:
        return txt
    return ossl(["crl", "-inform", "DER", "-in", crl]).stdout


def selftest():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        def o(*a, **k): return subprocess.run(["openssl", *a], cwd=td, capture_output=True, text=True, **k)
        o("ecparam", "-name", "prime256v1", "-genkey", "-out", "ca.key")
        o("req", "-x509", "-new", "-key", "ca.key", "-days", "3650", "-subj", "/CN=TEST CSCA/O=T",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
          "-addext", "subjectKeyIdentifier=hash", "-out", "ca.crt")
        o("ecparam", "-name", "prime256v1", "-genkey", "-out", "ds.key")
        o("req", "-new", "-key", "ds.key", "-subj", "/CN=TEST DS/O=T", "-out", "ds.csr")
        ext = td / "ext.cnf"
        ext.write_text("authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\nkeyUsage=critical,digitalSignature\n")
        o("x509", "-req", "-in", "ds.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
          "-days", "365", "-extfile", str(ext), "-out", "ds.crt")
        # wrong CA for the negative case
        o("ecparam", "-name", "prime256v1", "-genkey", "-out", "bad.key")
        o("req", "-x509", "-new", "-key", "bad.key", "-days", "3650", "-subj", "/CN=TEST CSCA/O=T",
          "-addext", "subjectKeyIdentifier=hash", "-out", "bad.crt")
        good = validate(str(td/"ca.crt"), str(td/"ds.crt"), None)
        bad = validate(str(td/"bad.crt"), str(td/"ds.crt"), None)
        ok = good["pass"] and not bad["pass"]
        print("SELFTEST", "PASS" if ok else "FAIL",
              "— authentic chain validates:", good["pass"],
              "| wrong-CSCA rejected:", not bad["pass"])
        print("  good checks:", json.dumps(good["checks"]))
        print("  bad  checks:", json.dumps(bad["checks"]))
        return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csca"); ap.add_argument("--crl"); ap.add_argument("--at", help="ISO 8601 time or Unix epoch; default now")
    ap.add_argument("--ds", default=str(DEFAULT_DS)); ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.csca:
        print("DRY RUN — no CSCA supplied. The Document Signer requires this issuer:\n")
        print(json.dumps(required_descriptor(args.ds), indent=2))
        print("\nObtain that CSCA (SKI == the DS AKI above) via an authorized channel, then:")
        print("  python3 tier0_csca.py --csca <jce-csca.pem> [--crl <crl>]")
        return 0
    res = validate(args.csca, args.ds, args.crl, args.at)
    print(json.dumps(res, indent=2))
    if res["pass"]:
        summary = ("PASS — DS chains to the supplied CSCA; current CRL reports it unrevoked"
                   if res["revocation"] == "good" else
                   "PASS — DS chains to the supplied CSCA; revocation not checked")
    else:
        summary = "FAIL — supplied chain/revocation checks not established"
    print("\n" + summary)
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
