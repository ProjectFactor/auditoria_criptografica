#!/usr/bin/env python3
"""Full read of boundary 7 (PKCS#15) and boundary 14 (DomRepEID), for review.

Boundary 7: selects the PKCS#15 AID, discovers which candidate FIDs exist (FCI),
and reads each existing EF IN FULL.
Boundary 14: selects the DomRepEID AID (= MF) and reads its public EFs IN FULL.

Uses the STOCK npa-tool --translate (continues past non-9000), so discovery is one
PACE session and the full reads are one more. Read-only; no write/VERIFY/PIN.

Full raw content goes to the git-ignored objects/ area; a human-readable review is
written to live_data/ (git-ignored). The cardholder's data is kept to those private
files; stdout prints only FID / size / status.

Usage:  printf '<CAN>' | python3 explore_full_sweep.py --can-stdin --execute
"""
from __future__ import annotations
import argparse, datetime, json, sys
from pathlib import Path

import npa_driver as drv
import runbook_common as rb
import fingerprint as fp
from explore_domrepeid import sm_segments

HERE = Path(__file__).resolve().parent

P15_AID = "A0 00 00 00 63 50 4B 43 53 2D 31 35"
P15_SEL = f"00 A4 04 0C 0C {P15_AID}"
DOM_SEL = "00 A4 04 0C 0A D2 76 00 00 98 44 6F 6D 49 44"

# PKCS#15 object-directory + minidriver candidate files
P15_CANDIDATES = [
    ("4400", "PrKDF (private keys)"), ("4401", "PuKDF (public keys)"),
    ("4402", "trusted public keys"), ("4403", "SKDF (secret keys)"),
    ("4404", "CDF (certificates)"), ("4405", "trusted certificates"),
    ("4406", "useful certificates"), ("4407", "DODF (data objects)"),
    ("4408", "AODF (auth objects)"), ("5031", "ODF"), ("5032", "TokenInfo"),
    ("5033", "UnusedSpace"), ("5701", "cardapps"), ("5702", "mscp"),
    ("5703", "cmapfile"), ("6377", "cardid"), ("6378", "cardcf"),
]
# DomRepEID (= MF) public EFs
DOM_CANDIDATES = [
    ("2F00", "EF.DIR"), ("2F01", "EF.ATR/INFO"),
    ("011C", "EF.CardAccess"), ("011D", "EF.CardSecurity"),
]


def fci_size(fci: bytes):
    if not fci:
        return None
    start, end = 0, len(fci)
    top = next(iter(fp._walk(fci, 0, len(fci))), None)
    if top and fci[top[1]] == 0x6F:
        _, s, h, _, t = top
        start, end = s + h, s + t
    for tag, cs, ch, cvl, ct in fp._walk(fci, start, end):
        if tag in (0x80, 0x81) and cvl:
            return int.from_bytes(fci[cs + ch:cs + ch + cvl], "big")
    return None


def discover(can, atr, wd, aid_sel, candidates, tag):
    cmds = [aid_sel] + [f"00 A4 02 00 02 {f[:2]} {f[2:]} 00" for f, _ in candidates]
    prof = wd / f"{tag}_disc.apdus"
    prof.write_text("\n".join(cmds) + "\n\n# end\n", encoding="ascii")
    code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    (wd / f"{tag}_disc.trace").write_bytes(trace)
    segs = sm_segments(trace)
    found = {}
    for i, (fid, lbl) in enumerate(candidates, start=1):
        if i < len(segs):
            sw1, sw2, data = segs[i]
            if (sw1, sw2) == (0x90, 0x00):
                found[fid] = {"label": lbl, "fci_size": fci_size(data)}
    return found


def read_full(can, atr, wd, aid_sel, found, tag):
    cmds = [aid_sel]
    plan = []  # (fid, n_reads)
    for fid, info in found.items():
        size = info.get("fci_size") or 1024
        cmds.append(f"00 A4 02 0C 02 {fid[:2]} {fid[2:]}")
        nreads = max(1, -(-size // drv.PAGE))  # ceil
        for r in range(nreads):
            cmds.append(drv.read_apdu(r * drv.PAGE, drv.CHUNK))
        plan.append((fid, nreads))
    prof = wd / f"{tag}_read.apdus"
    prof.write_text("\n".join(cmds) + "\n\n# end\n", encoding="ascii")
    code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    (wd / f"{tag}_read.trace").write_bytes(trace)
    segs = sm_segments(trace)

    contents = {}
    idx = 1  # seg 0 = AID select
    for fid, nreads in plan:
        idx += 1  # skip the EF SELECT segment
        buf = bytearray()
        for _ in range(nreads):
            if idx < len(segs):
                buf.extend(segs[idx][2])
            idx += 1
        contents[fid] = bytes(buf)
    return contents


def describe(fid, label, data):
    d = {"fid": fid, "label": label, "size": len(data), "sha256": fp.sha256_hex(data)}
    if data:
        d["leading_tag"] = f"{data[0]:02X}"
        dt = drv.der_total(data[:6]) if data[0] in (0x30, 0x31, 0x6F, 0x77, 0x61, 0xA0, 0x62) else None
        if dt and dt <= len(data):
            d["der_content_len"] = dt
    return d


def run_boundary(can, atr, uid, wd, aid_sel, candidates, tag, prefix):
    found = discover(can, atr, wd, aid_sel, candidates, tag)
    contents = read_full(can, atr, wd, aid_sel, found, tag) if found else {}
    report = []
    for fid, info in found.items():
        data = contents.get(fid, b"")
        if data:
            rb.object_path(uid, f"{prefix}_{fid}").write_bytes(data)
        report.append({**describe(fid, info["label"], data), "fci_size": info.get("fci_size")})
    missing = [f for f, _ in candidates if f not in found]
    return {"present": report, "absent": missing}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can-stdin", action="store_true")
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()
    if not args.execute:
        print("DRY RUN — boundary 7 (PKCS#15 FIDs) + boundary 14 (DomRepEID EFs), full read.")
        print("PKCS#15 candidates:", [f for f, _ in P15_CANDIDATES])
        print("DomRepEID EFs:", [f for f, _ in DOM_CANDIDATES])
        return 0
    if not Path("/run/pcscd/pcscd.comm").exists():
        raise SystemExit("PC/SC socket unavailable")
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    can = bytearray(sys.stdin.buffer.readline().strip())
    if not drv.valid_can(can):
        drv.cleanse(can); raise SystemExit("CAN must be six digits on stdin")
    ident = rb.identify_card()
    atr, uid = ident["atr"], ident["uid"]
    wd = rb.make_session_dir(uid, "fullsweep")
    try:
        b7 = run_boundary(can, atr, uid, wd, P15_SEL, P15_CANDIDATES, "b7", "p15")
        b14 = run_boundary(can, atr, uid, wd, DOM_SEL, DOM_CANDIDATES, "b14", "b14")
    finally:
        drv.cleanse(can)
    summary = {"atr": atr, "uid": uid, "boundary7_pkcs15": b7, "boundary14_domrepeid": b14}
    (wd / "fullsweep.json").write_text(json.dumps(summary, indent=2))
    # terminal: metadata only
    print("BOUNDARY 7 (PKCS#15) present:")
    for e in b7["present"]:
        print(f"  {e['fid']} {e['label']:26s} size={e['size']:5d} fci={e['fci_size']} sha={e['sha256'][:12]}")
    print("  absent:", b7["absent"])
    print("BOUNDARY 14 (DomRepEID) present:")
    for e in b14["present"]:
        print(f"  {e['fid']} {e['label']:16s} size={e['size']:5d} sha={e['sha256'][:12]}")
    print(f"\nFull raw files -> {rb.card_objects_dir(uid)} (git-ignored)\nSession -> {wd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
