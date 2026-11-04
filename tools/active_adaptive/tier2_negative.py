#!/usr/bin/env python3
"""Tier 2 — negative access-control probes (fail-closed), no secret submitted.

Over a single CAN/PACE session (stock npa-tool, which continues past non-9000), send
operations that the card MUST refuse, and confirm each is denied. A `9000`/data reply to
any of these is a FAIL — a potential access-control bug. No credential is submitted and
no PIN counter is touched (these are write/EAC-gate probes, not VERIFY).

Automated here (clear pass/fail from the status word):
  W1  UPDATE BINARY on a read-only public EF      -> expect denied
  W2  CREATE FILE in the MF                        -> expect denied
  W3  PUT DATA                                     -> expect denied
  B6  SELECT + READ DG3 without EAC/Terminal Auth  -> expect denied (6982)

Documented but NOT automatable through npa-tool --translate (it builds the SM wrapper
itself, so the wire form can't be forced here) — verify by trace review or a lower-level
APDU tool:
  - plaintext (no-SM) read of a protected EF after PACE
  - secure-messaging MAC tamper
  - PACE/CA downgrade to a weaker suite than EF.CardAccess advertises

The CAN is read from stdin, held in memory, cleansed, and redacted from the trace.

Usage:
  python3 tier2_negative.py                               # dry run (plan)
  printf '<CAN>' | python3 tier2_negative.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import npa_driver as drv
import runbook_common as rb

SENTINEL = "# Unread EOF sentinel; the blank line above terminates translation cleanly."

# Each probe: setup selects (expected 9000) then one JUDGED operation that must be refused.
PROBES = [
    {
        "id": "W1", "op": "UPDATE BINARY on read-only EF.CardSecurity",
        "setup": ["00 A4 00 0C 02 3F 00", "00 A4 02 0C 02 01 1D"],
        "judged": "00 D6 00 00 01 00",
    },
    {
        "id": "W2", "op": "CREATE FILE in MF",
        "setup": ["00 A4 00 0C 02 3F 00"],
        "judged": "00 E0 00 00 11 62 0F 82 02 01 00 83 02 2F 99 8A 01 05 80 02 00 10",
    },
    {
        "id": "W3", "op": "PUT DATA",
        "setup": ["00 A4 00 0C 02 3F 00"],
        "judged": "00 DA 01 00 01 00",
    },
    {
        "id": "B6", "op": "READ DG3 (fingerprints) without EAC",
        "setup": ["00 A4 04 0C 07 A0 00 00 02 47 10 01", "00 A4 02 0C 02 01 03"],
        "judged": "00 B0 00 00 08",
    },
]

MANUAL = [
    "plaintext (no-SM) read of a protected EF after PACE — expect rejection",
    "secure-messaging MAC tamper — expect 6987/6988",
    "PACE/CA downgrade to a weaker suite than advertised — expect refusal",
]


def build_profile() -> tuple[list[dict], list[str]]:
    """Return (judged-index map, apdu list). Each map entry marks which trace segment is judged."""
    apdus: list[str] = []
    index: list[dict] = []
    for p in PROBES:
        for s in p["setup"]:
            apdus.append(s)
        apdus.append(p["judged"])
        index.append({"id": p["id"], "op": p["op"], "seg": len(apdus) - 1})
    return index, apdus


def succeeded(sw1: int) -> bool:
    """A judged op 'succeeded' (would be a bug) if the card returned success/more-data."""
    return sw1 in (0x90, 0x61)


def run_probes(can: bytearray, atr: str, workdir: Path) -> dict:
    index, apdus = build_profile()
    prof = workdir / "tier2_negative.apdus"
    prof.write_text("\n".join(apdus + ["", SENTINEL]) + "\n", encoding="ascii")
    code, trace = drv.run(can, atr, translate_path=prof, binary=drv.PACE_BINARY)
    (workdir / "tier2_negative.trace").write_bytes(trace)

    segs = rb.sm_segments(trace)
    results = []
    all_pass = True
    for entry in index:
        seg = entry["seg"]
        if seg >= len(segs):
            results.append({**entry, "status": "no-response-parsed", "pass": False})
            all_pass = False
            continue
        sw1, sw2, data = segs[seg]
        bug = succeeded(sw1)
        passed = not bug
        all_pass = all_pass and passed
        row = {
            "id": entry["id"], "op": entry["op"],
            "sw": rb.sw_hex(sw1, sw2), "meaning": rb.describe_sw(sw1, sw2),
            "pass": passed,
            "verdict": "DENIED (ok)" if passed else "UNEXPECTED SUCCESS (potential bug)",
        }
        if data:
            row["unexpected_data_len"] = len(data)
        results.append(row)
    return {
        "check": "negative access-control probes (must be refused)",
        "npa_exit": code,
        "pass": all_pass,
        "probes": results,
        "manual_followups": MANUAL,
    }


def dry_run() -> None:
    index, apdus = build_profile()
    print("DRY RUN — Tier 2 negative access-control probes (no secret submitted).\n")
    print("Single PACE session; stock npa-tool continues past non-9000. Judged ops must be REFUSED;")
    print("a 9000/data reply is a FAIL (potential bug).\n")
    for p in PROBES:
        print(f"[{p['id']}] {p['op']}")
        for s in p["setup"]:
            print(f"       setup : {s}")
        print(f"       JUDGED: {p['judged']}   -> expect denial (e.g. 6982/6985/6A82)")
    print("\nManual / trace-review follow-ups (not automatable via npa-tool --translate):")
    for m in MANUAL:
        print(f"   - {m}")


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
        workdir = rb.make_session_dir(uid, "tier2")
        report = {"tier": 2, "atr": atr, "uid": uid}
        report.update(run_probes(can, atr, workdir))
    finally:
        rb.cleanse_all(can)
    (workdir / "tier2.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n{'PASS — all probes denied' if report['pass'] else 'FAIL — a probe was not denied (see above)'}"
          f"  (artifacts: {workdir})")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
