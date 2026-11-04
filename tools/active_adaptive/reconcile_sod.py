#!/usr/bin/env python3
"""Full Passive-Authentication reconciliation for an arbitrary cédula.

Verifies the EF.SOD CMS signature against its embedded Document Signer (integrity,
not issuer trust), then reads each data group the SOD vouches for, hashes it with
the SOD's declared algorithm, and checks it against the SOD's stored hash.

Privacy: data groups may contain personal data. Raw DGs are written only to the
git-ignored objects/ area; this tool prints ONLY hashes and match/no-match results,
never DG content. DG3 (fingerprints) is EAC-protected and is skipped.

Usage:
  printf '<CAN>' | python3 reconcile_sod.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv
import runbook_common as rb
import fingerprint as fp

HERE = Path(__file__).resolve().parent

# ICAO LDS data-group number -> eMRTD file id (hex). DG3 omitted (EAC-gated).
DG_FID = {1: "0101", 2: "0102", 4: "0104", 5: "0105", 7: "0107",
          11: "010B", 12: "010C", 13: "010D", 14: "010E", 15: "010F", 16: "0110"}

HASH_OID = {
    "608648016503040201": "sha256", "608648016503040202": "sha384",
    "608648016503040203": "sha512", "2b0e03021a": "sha1",
}


def selects_for_fid(fid: str) -> list[str]:
    return [f"00 A4 02 0C 02 {fid[:2]} {fid[2:]}"]


def extract_lds_security_object(sod_der: bytes) -> tuple[bytes, bool]:
    """Strip the tag-0x77 wrapper, CMS-verify (no chain), return (eContent, sig_ok)."""
    # EF.SOD = [APPLICATION 23] (0x77) wrapping a CMS ContentInfo SEQUENCE.
    inner = sod_der
    if sod_der and sod_der[0] == 0x77:
        for tag, start, header, vlen, total in fp._walk(sod_der, 0, len(sod_der)):
            inner = sod_der[start + header : start + total]
            break
    with tempfile.TemporaryDirectory() as td:
        cms = Path(td) / "sod_cms.der"
        out = Path(td) / "lds.der"
        cms.write_bytes(inner)
        proc = subprocess.run(
            ["openssl", "cms", "-verify", "-noverify", "-inform", "DER",
             "-in", str(cms), "-out", str(out), "-binary"],
            capture_output=True,
        )
        sig_ok = proc.returncode == 0 and out.is_file()
        lds = out.read_bytes() if sig_ok else inner
    return lds, sig_ok


def parse_lds(lds: bytes) -> tuple[str | None, dict[int, str]]:
    """Return (hash algorithm name, {dg_number: stored_hash_hex}) from LDSSecurityObject."""
    # LDSSecurityObject ::= SEQ { INTEGER version, AlgorithmIdentifier hashAlg,
    #                             SEQ OF SEQ { INTEGER dgNumber, OCTET STRING hash } }
    top = next(iter(fp._walk(lds, 0, len(lds))), None)
    if not top:
        return None, {}
    _, s, h, _, t = top
    children = list(fp._walk(lds, s + h, s + t))
    alg = None
    if len(children) >= 2:
        _, a_start, a_hdr, _, a_total = children[1]
        for ctag, cs, chh, cvl, ct in fp._walk(lds, a_start + a_hdr, a_start + a_total):
            if ctag == 0x06:
                alg = HASH_OID.get(lds[cs + chh : cs + chh + cvl].hex())
                break
    hashes: dict[int, str] = {}
    # LDSSecurityObject ::= { version, hashAlg, dataGroupHashValues [, ldsVersionInfo] }
    # dataGroupHashValues is the element right after hashAlg (index 2), NOT the last
    # child (which may be the optional ldsVersionInfo).
    if len(children) >= 3:
        _, q_start, q_hdr, _, q_total = children[2]
        for _, es, eh, evl, et in fp._walk(lds, q_start + q_hdr, q_start + q_total):
            num = None
            hx = None
            for itag, isa, ih, ivl, it in fp._walk(lds, es + eh, es + et):
                if itag == 0x02 and num is None:
                    num = int.from_bytes(lds[isa + ih : isa + ih + ivl], "big")
                elif itag == 0x04:
                    hx = lds[isa + ih : isa + ih + ivl].hex()
            if num is not None and hx is not None:
                hashes[num] = hx
    return alg, hashes


def _walk_children(der, node):
    # helper retained for readability; node is a (tag,start,header,vlen,total) tuple
    tag, start, header, vlen, total = node
    return list(fp._walk(der, start + header, start + total))


def reconcile(can: bytearray, atr: str, uid: str, workdir: Path) -> dict:
    out: dict = {"atr": atr, "uid": uid}

    # EF.SOD (reuse cached DER if present for this card; else read it)
    cached = rb.object_path(uid, "sod")
    if cached.is_file():
        sod = cached.read_bytes()
    else:
        sod, err = drv.read_ef(can, atr, selects_for_fid("011D"), workdir, "sod")
        if err:
            return {"error": f"SOD read failed: {err}"}
        cached.write_bytes(sod)

    lds, sig_ok = extract_lds_security_object(sod)
    alg, stored = parse_lds(lds)
    out["sod"] = {
        "sha256": fp.sha256_hex(sod),
        "cms_signature_valid": sig_ok,
        "document_signer": (fp.fingerprint_sod(sod).get("document_signer") or {}).get("subject"),
        "hash_algorithm": alg,
        "data_groups_vouched": sorted(stored),
    }
    if not alg:
        out["error"] = "could not determine SOD hash algorithm"
        return out

    results: dict[int, dict] = {}
    for num in sorted(stored):
        if num == 3:
            results[num] = {"status": "skipped", "reason": "DG3 biometrics EAC-gated"}
            continue
        fid = DG_FID.get(num)
        if not fid:
            results[num] = {"status": "unknown-fid"}
            continue
        der, err = drv.read_ef(can, atr, selects_for_fid(fid), workdir, f"dg{num}")
        if err:
            results[num] = {"status": "read-failed", "reason": err}
            continue
        rb.object_path(uid, f"dg{num}").write_bytes(der)
        digest = hashlib.new(alg, der).hexdigest()
        results[num] = {
            "status": "ok",
            "size_bytes": len(der),
            "hash_matches_sod": digest == stored[num],
        }
    out["data_groups"] = {str(k): v for k, v in results.items()}
    checked = [v for v in results.values() if v.get("status") == "ok"]
    out["summary"] = {
        "dgs_checked": len(checked),
        "dgs_matched": sum(1 for v in checked if v["hash_matches_sod"]),
        "all_matched": bool(checked) and all(v["hash_matches_sod"] for v in checked),
        "sod_signature_valid": sig_ok,
    }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print("DRY RUN — reads EF.SOD, verifies its CMS signature, then hashes each vouched DG")
        print("(DG3 skipped; only hashes/match results are printed, never DG content).")
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
    workdir = rb.make_session_dir(uid, "reconcile")
    try:
        report = reconcile(can, atr, uid, workdir)
    finally:
        drv.cleanse(can)
    (workdir / "reconciliation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSession artifacts: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
