#!/usr/bin/env python3
"""Boundary-7 explorer: PKCS#15 token + object-directory METADATA over CAN/PACE.

Reads EF.TokenInfo and EF.ODF, follows the ODF to each object-directory file
(PrKDF/PuKDF/CDF/AODF/DODF/SKDF) and reports their structure: how many objects,
their labels, IDs, key references, auth IDs and the paths they point to.

It deliberately STOPS at the directory level: it never dereferences a path to read
an actual certificate or key body (that would expose personal / secret material).
Everything printed is non-secret token/object metadata. No VERIFY / PIN / retry
query / write is ever sent. Raw directory DER is kept only in git-ignored objects/.

Usage:  printf '<CAN>' | python3 explore_pkcs15.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv
import fingerprint as fp

import runbook_common as rb

HERE = Path(__file__).resolve().parent

P15_AID_SELECT = "00 A4 04 0C 0C A0 00 00 00 63 50 4B 43 53 2D 31 35"

# well-known PKCS#15 EF ids under the P15 application
EF_ODF = "5031"
EF_TOKENINFO = "5032"

# ODF context tags -> directory kind
ODF_TAG = {0xA0: "privateKeys", 0xA1: "publicKeys", 0xA2: "trustedPublicKeys",
           0xA3: "secretKeys", 0xA4: "certificates", 0xA5: "trustedCertificates",
           0xA6: "usefulCertificates", 0xA7: "dataObjects", 0xA8: "authObjects"}


def selects_for(fid: str) -> list[str]:
    return [P15_AID_SELECT, f"00 A4 02 0C 02 {fid[:2]} {fid[2:]}"]


def ascii_strings(der: bytes) -> list[str]:
    """UTF8String/PrintableString (0x0C/0x13) values, as a light label view."""
    out = []
    for tlv in fp._iter_all_tlvs(der):
        if tlv and tlv[0] in (0x0C, 0x13):
            n = fp.der_total_value_offset(tlv) if hasattr(fp, "der_total_value_offset") else None
            # value starts after tag+len header
            first = tlv[1]
            hdr = 2 if first < 0x80 else 2 + (first & 0x7F)
            try:
                s = tlv[hdr:].decode("latin1").strip()
            except Exception:
                s = ""
            if s:
                out.append(s)
    return out


def paths_in(der: bytes) -> list[str]:
    """2- or 4-byte OCTET STRING values that look like EF ids / paths."""
    out = []
    for tlv in fp._iter_all_tlvs(der):
        if tlv and tlv[0] == 0x04:
            first = tlv[1]
            hdr = 2 if first < 0x80 else 2 + (first & 0x7F)
            val = tlv[hdr:]
            if len(val) in (2, 4):
                out.append(val.hex().upper())
    return out


def parse_odf(der: bytes) -> dict[str, list[str]]:
    """Map directory kind -> list of EF paths it is stored in."""
    found: dict[str, list[str]] = {}
    for tlv in fp._iter_all_tlvs(der):
        if tlv and tlv[0] in ODF_TAG:
            kind = ODF_TAG[tlv[0]]
            found.setdefault(kind, [])
            for p in paths_in(tlv):
                if p not in found[kind]:
                    found[kind].append(p)
    return found


def summarize_directory(der: bytes) -> dict:
    """Count PKCS15Object records (top-level SEQUENCEs) and list their metadata."""
    recs = []
    top = next(iter(fp._walk(der, 0, len(der))), None)
    # a directory EF is usually a bare concatenation of records, or a SEQUENCE OF
    scan_start, scan_end = 0, len(der)
    if top and top[0] in (0x30, 0x31) and top[4] == len(der):
        scan_start, scan_end = top[1] + top[2], top[1] + top[4]
    for tag, s, h, vl, t in fp._walk(der, scan_start, scan_end):
        rec = der[s : s + t]
        recs.append({
            "tag": f"{tag:02X}",
            "size": t,
            "labels": ascii_strings(rec)[:3],
            "paths": paths_in(rec),
        })
    return {"record_count": len(recs), "records": recs}


def read_meta(can: bytearray, atr: str, uid: str, fid: str, workdir: Path, label: str) -> tuple[bytes | None, str | None]:
    der, err = drv.read_ef(can, atr, selects_for(fid), workdir, label)
    if der is not None:
        rb.object_path(uid, f"p15_{label}").write_bytes(der)
    return der, err


def explore(can: bytearray, atr: str, uid: str, workdir: Path) -> dict:
    out: dict = {"atr": atr, "uid": uid, "application": "PKCS#15 (A000000063504B43532D3135)"}

    ti, err = read_meta(can, atr, uid, EF_TOKENINFO, workdir, "tokeninfo")
    if err:
        out["tokeninfo_error"] = err
    else:
        out["tokeninfo"] = {"size": len(ti), "sha256": fp.sha256_hex(ti), "strings": ascii_strings(ti)}

    odf, err = read_meta(can, atr, uid, EF_ODF, workdir, "odf")
    if err:
        out["odf_error"] = err
        return out
    out["odf"] = {"size": len(odf), "sha256": fp.sha256_hex(odf)}
    directories = parse_odf(odf)
    out["directories_declared"] = directories

    contents: dict[str, dict] = {}
    for kind, paths in directories.items():
        for p in paths:
            fid = p[-4:]  # last 2 bytes of the path
            der, e = read_meta(can, atr, uid, fid, workdir, f"{kind}_{fid}")
            if e:
                contents[f"{kind}:{fid}"] = {"error": e}
            else:
                contents[f"{kind}:{fid}"] = {"size": len(der), "sha256": fp.sha256_hex(der), **summarize_directory(der)}
    out["directory_contents"] = contents
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--can-stdin", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print("DRY RUN — reads EF.TokenInfo, EF.ODF and each ODF-referenced directory (metadata only).")
        print("Never dereferences a certificate/key body; no VERIFY/PIN/write.")
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
    workdir = rb.make_session_dir(uid, "pkcs15")
    try:
        report = explore(can, atr, uid, workdir)
    finally:
        drv.cleanse(can)
    (workdir / "pkcs15.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSession artifacts: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
