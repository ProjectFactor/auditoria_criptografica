#!/usr/bin/env python3
"""Tier 2 (SM) — the two negative tests npa-tool cannot perform.

npa-tool always builds Secure Messaging correctly, so it can never emit a
MAC-tampered or a downgraded APDU. This harness drives our own from-scratch
PACE+SM stack (pace_sm.py) to do exactly that, against the card on the reader:

  POSITIVE CONTROL  establish PACE with the CAN, then SM-read the public
                    EF.CardAccess and check the decrypted bytes equal the
                    plaintext read raw (no PACE). This proves our SM stack is
                    correct in BOTH directions; only then is a tamper result
                    trustworthy. (EF.CardAccess is public, non-PII.)

  SM MAC TAMPER     send an otherwise-valid SM command with (a) one MAC byte
                    corrupted and (b) the MAC data object removed, each at the
                    SSC the card expects — so only the MAC/DO is wrong.
                    PASS = card refuses both (6987/6988/69xx), no data leaked.

  PACE DOWNGRADE    MSE:Set AT requesting suites the card does NOT advertise
                    (AES-128, 3DES, and the advertised cipher on a weaker
                    curve). PASS = card refuses each. No GENERAL AUTHENTICATE
                    is attempted for a weak suite, so no PACE password counter
                    is touched.

Safety: read-only on the card plus a few rejected/ malformed commands. The real
PACE runs exactly once with the correct CAN; the downgrade probes stop at
negotiation. The CAN is read from stdin, held in memory, cleansed after use, and
never appears in any APDU (PACE never transmits it). Session keys are never logged.

Usage:
  python3 tier2_sm_tamper.py                                   # dry run (plan)
  printf '<CAN>' | python3 tier2_sm_tamper.py --can-stdin --execute
"""

from __future__ import annotations

import argparse
import json

import pace_sm as ps
import runbook_common as rb

SELECT_MF = bytes([0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])
SELECT_CARDACCESS = bytes([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C])
READ_BINARY_CA = (0x00, 0xB0, 0x00, 0x00)  # Le supplied per call


def hx(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


# Local labels for the SM/negotiation status words the shared table doesn't name.
_SW_LABELS = {
    "6A80": "incorrect parameters in command data (suite refused)",
    "6988": "incorrect SM data objects (MAC check failed)",
    "6987": "expected SM data object missing",
    "6A88": "referenced data not found",
    "6A81": "function not supported",
}


def sw_meaning(sw1: int, sw2: int) -> str:
    code = f"{sw1:02X}{sw2:02X}"
    if code in _SW_LABELS:
        return _SW_LABELS[code]
    text = rb.describe_sw(sw1, sw2)
    return text if text and "unclassified" not in text else f"status {code}"


class Channel:
    """Owns one PC/SC connection; transmit() matches pace_sm's Transmit type."""

    def __init__(self):
        from smartcard.scard import (
            SCARD_SCOPE_USER, SCardEstablishContext, SCardListReaders,
        )
        hr, self.ctx = SCardEstablishContext(SCARD_SCOPE_USER)
        hr, rdrs = SCardListReaders(self.ctx, [])
        picc = [r for r in rdrs if "PICC" in r]
        if not picc:
            raise SystemExit("no PICC reader found")
        self.reader = picc[0]
        self.card = None
        self.proto = None
        self.log: list[dict] = []
        self.connect()

    def connect(self):
        from smartcard.scard import (
            SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_S_SUCCESS, SCardConnect,
        )
        hr, self.card, self.proto = SCardConnect(
            self.ctx, self.reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)
        if hr != SCARD_S_SUCCESS or self.card is None:
            raise SystemExit(f"SCardConnect failed (hr=0x{hr & 0xFFFFFFFF:08X})")

    def reset(self):
        """Cold-reset the card to clear any PACE/SM security state."""
        from smartcard.scard import (
            SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_UNPOWER_CARD,
            SCARD_S_SUCCESS, SCardReconnect,
        )
        hr, self.proto = SCardReconnect(
            self.card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_UNPOWER_CARD)
        if hr != SCARD_S_SUCCESS:
            raise ps.CardError(f"SCardReconnect (reset) failed (hr=0x{hr & 0xFFFFFFFF:08X})")

    def transmit(self, apdu: bytes, note: str = "") -> tuple[bytes, int, int]:
        from smartcard.scard import SCardTransmit, SCARD_S_SUCCESS
        hr, resp = SCardTransmit(self.card, self.proto, list(apdu))
        if hr != SCARD_S_SUCCESS or resp is None or len(resp) < 2:
            raise ps.CardError(f"PC/SC transmit failed (hr=0x{hr & 0xFFFFFFFF:08X}) on '{note}'")
        data, sw1, sw2 = list(resp[:-2]), resp[-2], resp[-1]
        self.log.append({"note": note, "cmd": hx(apdu),
                         "sw": f"{sw1:02X}{sw2:02X}", "resp_len": len(data)})
        return bytes(data), sw1, sw2

    def disconnect(self):
        from smartcard.scard import SCardDisconnect, SCARD_UNPOWER_CARD
        if self.card is not None:
            SCardDisconnect(self.card, SCARD_UNPOWER_CARD)
            self.card = None


# --------------------------------------------------------------------------
def read_cardaccess_raw(ch: Channel) -> bytes:
    """Ground truth: read public EF.CardAccess with no PACE (plaintext)."""
    ch.transmit(SELECT_MF, "select MF (raw)")
    ch.transmit(SELECT_CARDACCESS, "select EF.CardAccess (raw)")
    data, sw1, sw2 = ch.transmit(bytes(READ_BINARY_CA) + b"\x00", "read EF.CardAccess (raw)")
    # 6282 = EOF reached before Le bytes; the file's bytes are still returned.
    ok = bool(data) or sw1 in (0x90, 0x61)
    if not ok:
        raise SystemExit(f"could not read EF.CardAccess raw (SW={sw1:02X}{sw2:02X})")
    return data


def downgrade_probes(ch: Channel) -> list[dict]:
    """MSE:Set AT for suites the card does not advertise. Refusal = pass."""
    cases = [
        ("AES-128 GM (weaker cipher)", ps.OID_PACE_ECDH_GM_AES_128, None),
        ("3DES GM (legacy cipher)", ps.OID_PACE_ECDH_GM_3DES, None),
        ("AES-256 on P-256 (weaker curve, param 12)", ps.OID_PACE_ECDH_GM_AES_256, 12),
    ]
    out = []
    for desc, oid, dp in cases:
        ch.reset()
        sw1, sw2 = ps.mse_set_at_pace(ch.transmit, oid, ps.PASSWORD_REF_CAN, domain_param=dp)
        refused = (sw1, sw2) != (0x90, 0x00)
        out.append({
            "probe": desc, "requested_oid": oid.hex(),
            "domain_param": dp, "sw": f"{sw1:02X}{sw2:02X}",
            "meaning": sw_meaning(sw1, sw2),
            "expected": "refused", "refused": refused,
            "verdict": "OK (refused)" if refused else "UNEXPECTED ACCEPTANCE (downgrade)",
        })
    return out


def tamper_probes(ch: Channel, sm: ps.SecureMessaging, read_len: int) -> list[dict]:
    """Two SM commands denied for authentication reasons alone.

    T1 is the rigorous MAC test: it is the FIRST command after the successful
    positive control, so the card's SSC is exactly what our build() uses — only
    the MAC byte is wrong. T2 (MAC object removed) demonstrates that a command
    carrying no MAC at all is refused; that outcome does not depend on the SSC,
    so no SSC resync is assumed. After T1 the SM session state is indeterminate
    (the card may tear it down or advance its own SSC on a MAC failure); we make
    no claim about it and judge each probe only by its denial."""
    out = []

    # T1: otherwise-valid SM read with one MAC byte corrupted (correct SSC).
    apdu = bytearray(sm.build(*READ_BINARY_CA, le=read_len))
    apdu[-2] ^= 0xFF  # last body byte before Le is the final MAC byte of DO8E
    data, sw1, sw2 = ch.transmit(bytes(apdu), "SM read w/ corrupted MAC")
    denied = (sw1, sw2) != (0x90, 0x00) and not data
    out.append({"probe": "corrupt one SM MAC byte", "sw": f"{sw1:02X}{sw2:02X}",
                "meaning": sw_meaning(sw1, sw2), "data_bytes": len(data),
                "expected": "denied", "denied": denied,
                "verdict": "OK (denied)" if denied else "UNEXPECTED SUCCESS (MAC not enforced)"})

    # T2: MAC data object (DO8E) removed entirely (SSC-independent denial).
    apdu = sm.build(*READ_BINARY_CA, le=read_len)
    body = ps.parse_tlvs(apdu[5:-1])
    stripped = b"".join(raw for tag, _, raw in body if tag != 0x8E)
    apdu_no_mac = bytes(apdu[:4]) + bytes([len(stripped)]) + stripped + b"\x00"
    data, sw1, sw2 = ch.transmit(apdu_no_mac, "SM read w/ MAC (DO8E) removed")
    denied = (sw1, sw2) != (0x90, 0x00) and not data
    out.append({"probe": "remove SM MAC object (DO8E)", "sw": f"{sw1:02X}{sw2:02X}",
                "meaning": sw_meaning(sw1, sw2), "data_bytes": len(data),
                "expected": "denied", "denied": denied,
                "verdict": "OK (denied)" if denied else "UNEXPECTED SUCCESS (unauthenticated cmd accepted)"})
    return out


def run(can: bytearray) -> dict:
    ident = rb.identify_card()
    ch = Channel()
    report: dict = {"tier": "2-sm", "atr": ident["atr"], "uid": ident["uid"],
                    "suite": "PACE-ECDH-GM-AES-CBC-CMAC-256 / NIST P-384 (param 15)"}
    try:
        truth = read_cardaccess_raw(ch)
        report["cardaccess_plaintext"] = truth.hex()

        # Downgrade probes first (cheapest, stop at negotiation).
        report["downgrade"] = downgrade_probes(ch)

        # Real PACE exactly once, then the positive control.
        ch.reset()
        pace = ps.establish_pace(ch.transmit, bytes(can))
        report["pace_established"] = True
        sm = ps.SecureMessaging(pace.k_enc, pace.k_mac)

        # SELECT + READ EF.CardAccess, all SM-protected.
        a = sm.build(*SELECT_MF[:4], data=SELECT_MF[5:])
        d, s1, s2 = ch.transmit(a, "SM select MF")
        _, rs1, rs2 = sm.unwrap(d, s1, s2)
        a = sm.build(*SELECT_CARDACCESS[:4], data=SELECT_CARDACCESS[5:])
        d, s1, s2 = ch.transmit(a, "SM select EF.CardAccess")
        _, rs1, rs2 = sm.unwrap(d, s1, s2)
        # Read the SAME number of bytes the raw read returned, so the two are
        # directly comparable regardless of this card's EF.CardAccess size.
        read_len = len(truth) if 0 < len(truth) <= 0xFF else 0x00
        a = sm.build(*READ_BINARY_CA, le=read_len)
        d, s1, s2 = ch.transmit(a, "SM read EF.CardAccess")
        plain, rs1, rs2 = sm.unwrap(d, s1, s2)
        match = plain == truth
        report["positive_control"] = {
            "sm_read_sw": f"{rs1:02X}{rs2:02X}",
            "decrypted_matches_plaintext": match,
            "bytes": len(plain),
            "verdict": "OK (SM stack verified)" if match else "FAIL (SM stack wrong)",
        }
        if not match:
            report["pass"] = False
            report["note"] = "positive control failed; tamper results would be meaningless"
            return report

        # Tamper tests only once SM is proven correct.
        report["tamper"] = tamper_probes(ch, sm, read_len)
    except (ps.CardError, ValueError, KeyError) as exc:
        # ValueError/KeyError cover PACE protocol/crypto inconsistencies
        # (e.g. a PICC authentication-token mismatch) and missing DOs; record
        # them as a clean failure rather than crashing the harness.
        report["pace_established"] = report.get("pace_established", False)
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        ch.disconnect()

    dg_ok = all(p["refused"] for p in report.get("downgrade", []))
    pc_ok = report.get("positive_control", {}).get("decrypted_matches_plaintext", False)
    tp_ok = all(p["denied"] for p in report.get("tamper", [])) and bool(report.get("tamper"))
    report["pass"] = bool(report.get("pace_established") and dg_ok and pc_ok and tp_ok)
    return report


def dry_run() -> None:
    print("DRY RUN — Tier 2 (SM) MAC-tamper + PACE-downgrade; needs CAN on --execute.\n")
    print("Suite under test: PACE-ECDH-GM-AES-CBC-CMAC-256 on NIST P-384 (EF.CardAccess param 15).\n")
    print("1) POSITIVE CONTROL: raw-read EF.CardAccess, then PACE + SM-read it; bytes must match.")
    print("2) DOWNGRADE (MSE:Set AT, no GENERAL AUTHENTICATE):")
    for desc, oid, dp in [("AES-128 GM", ps.OID_PACE_ECDH_GM_AES_128, None),
                          ("3DES GM", ps.OID_PACE_ECDH_GM_3DES, None),
                          ("AES-256 on P-256", ps.OID_PACE_ECDH_GM_AES_256, 12)]:
        print(f"     request {desc:18s} OID {oid.hex()} dp={dp}  -> expect REFUSED")
    print("3) SM MAC TAMPER (at the expected SSC):")
    print("     corrupt one MAC byte            -> expect DENIED (6988/69xx)")
    print("     remove the MAC object (DO8E)    -> expect DENIED (6987/69xx)")
    print("\nPASS = PACE established AND control matches AND every downgrade refused "
          "AND every tamper denied.")
    print("Offline crypto self-check: python3 pace_sm.py --selftest")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--can-stdin", action="store_true", help="read the 6-digit CAN from stdin")
    args = ap.parse_args()
    if not args.execute:
        dry_run()
        return 0
    if not args.can_stdin:
        raise SystemExit("live mode requires --can-stdin")
    rb.require_pcsc()
    (can,) = rb.read_lines_from_stdin(1)
    try:
        if len(can) != 6 or not all(0x30 <= b <= 0x39 for b in can):
            raise SystemExit("CAN must be exactly six decimal digits")
        report = run(can)
    finally:
        rb.cleanse_all(can)

    workdir = rb.make_session_dir(report["uid"], "tier2sm")
    (workdir / "tier2sm.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n{'PASS — MAC enforced and downgrade refused' if report.get('pass') else 'FAIL — see report'}"
          f"  (artifacts: {workdir})")
    return 0 if report.get("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
