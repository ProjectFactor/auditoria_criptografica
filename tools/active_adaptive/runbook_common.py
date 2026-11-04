#!/usr/bin/env python3
"""Shared orchestration for the Tier 0–3 validation runbook.

Thin helpers reused by tier1/tier2/tier3: read the CAN (and, for Tier 3, the PIN)
from stdin without echoing or persisting them, detect the contactless reader's ATR,
create a git-ignored session directory, walk a post-PACE trace into per-command
(SW1, SW2, decrypted-data) tuples, and redact a secret from a trace.

Nothing here touches the card by itself; it only prepares inputs for npa_driver and
interprets the sanitized traces it returns. The proven npa_driver / evidence modules
are imported, not modified.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import npa_driver as drv  # also puts tools/session on sys.path for `evidence`
from evidence import parse_apdu_dumps, parse_decrypted_dumps, status_text  # noqa: E402

HERE = Path(__file__).resolve().parent
OBJECTS_DIR = HERE / "objects"
SESSIONS_DIR = HERE / "sessions"
REGISTRY_PATH = OBJECTS_DIR / "_registry.json"  # private (objects/ is git-ignored)

APP_MARKER = b"Selected eMRTD application."
UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]  # PC/SC pseudo-APDU: ISO14443 UID


# --- credential input (never echoed, never written) -------------------------
def read_lines_from_stdin(count: int) -> list[bytearray]:
    """Read `count` newline-terminated secrets from stdin as mutable bytearrays."""
    import sys

    out: list[bytearray] = []
    for _ in range(count):
        out.append(bytearray(sys.stdin.buffer.readline().strip()))
    return out


def valid_pin(value: bytes | bytearray) -> bool:
    """ASCII-numeric, 4..12 digits (covers User 4–8, SO/Signature 10)."""
    return 4 <= len(value) <= 12 and all(0x30 <= b <= 0x39 for b in value)


def cleanse_all(*buffers: bytearray) -> None:
    for buf in buffers:
        drv.cleanse(buf)


# --- reader / card identity --------------------------------------------------
# The DomIDv1 ATR is identical across cards, so atr[-8:] COLLIDES and would mix
# evidence. Every card is instead keyed by its ISO14443 UID (FF CA 00 00 00), a
# per-card hardware id read before any PACE/CAN step. If the UID read fails, the
# key falls back to an explicit "atrunk_<atr8>" so a capture is never silently
# filed under another card's id.
def require_pcsc() -> None:
    if not Path("/run/pcscd/pcscd.comm").exists():
        raise SystemExit("PC/SC socket is unavailable; this runner will not start it")


def identify_card() -> dict:
    """Connect once, return {'atr', 'uid', 'uid_sw'}. UID is lowercase hex."""
    from smartcard.scard import (
        SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        SCardEstablishContext, SCardListReaders, SCardConnect, SCardStatus,
        SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD,
    )
    hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    hr, rdrs = SCardListReaders(ctx, [])
    picc = [r for r in rdrs if "PICC" in r]
    if not picc:
        raise SystemExit("no PICC reader found — reconnect the reader and place the card")
    hr, card, proto = SCardConnect(ctx, picc[0], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)
    atr = "".join(f"{b:02X}" for b in SCardStatus(card)[4])
    uid, uid_sw = "", ""
    try:
        hr, resp = SCardTransmit(card, proto, UID_APDU)
        if len(resp) >= 2:
            uid_sw = "".join(f"{b:02X}" for b in resp[-2:])
            if uid_sw == "9000":
                uid = "".join(f"{b:02x}" for b in resp[:-2])
    except Exception:
        pass
    SCardDisconnect(card, SCARD_LEAVE_CARD)
    if not uid:
        uid = f"atrunk_{atr[-8:]}"
    return {"atr": atr, "uid": uid, "uid_sw": uid_sw}


def detect_picc_atr() -> str:
    """Back-compat: ATR only."""
    return identify_card()["atr"]


# --- per-card evidence paths -------------------------------------------------
def card_objects_dir(uid: str) -> Path:
    d = OBJECTS_DIR / uid
    d.mkdir(parents=True, exist_ok=True)
    return d


def object_path(uid: str, name: str) -> Path:
    """Raw DER path for a card, e.g. objects/<uid>/cardsecurity.der."""
    return card_objects_dir(uid) / f"{name}.der"


def make_session_dir(uid: str, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    workdir = SESSIONS_DIR / uid / f"{stamp}_{label}"
    workdir.mkdir(parents=True, exist_ok=True)
    return workdir


# --- per-card fingerprint registry (private) ---------------------------------
def load_registry() -> dict:
    try:
        return json.loads(REGISTRY_PATH.read_text())
    except (OSError, ValueError):
        return {}


def update_registry(uid: str, fields: dict) -> dict:
    reg = load_registry()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = reg.get(uid, {"uid": uid, "first_seen": now})
    entry.update(fields)
    entry["last_seen"] = now
    reg[uid] = entry
    OBJECTS_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(reg, indent=2, sort_keys=True))
    return entry


# --- trace interpretation ----------------------------------------------------
def sm_segments(trace: bytes) -> list[tuple[int, int, bytes]]:
    """Per secure-messaging command (CLA & 0x0C) after PACE: (sw1, sw2, decrypted_data).

    Order matches the SM commands in the profile. Plaintext PACE-handshake commands
    are skipped. The SM-protected status is the `99 02 SW1 SW2` data object when present,
    else the trailing two bytes.
    """
    marker = trace.find(APP_MARKER)
    region = trace[marker:] if marker >= 0 else trace
    out: list[tuple[int, int, bytes]] = []
    for chunk in region.split(b"Outgoing APDU")[1:]:
        piece = b"Outgoing APDU" + chunk
        pairs = parse_apdu_dumps(piece)
        outgoing = next((raw for d, raw in pairs if d == "outgoing"), None)
        incoming = next((raw for d, raw in pairs if d == "incoming"), None)
        if not outgoing or len(outgoing) < 1 or not (outgoing[0] & 0x0C):
            continue  # skip plaintext handshake commands
        sw1 = sw2 = 0
        if incoming and len(incoming) >= 2:
            i = incoming.find(b"\x99\x02")
            if i >= 0 and i + 4 <= len(incoming):
                sw1, sw2 = incoming[i + 2], incoming[i + 3]
            else:
                sw1, sw2 = incoming[-2], incoming[-1]
        dec = parse_decrypted_dumps(piece)
        out.append((sw1, sw2, dec[0] if dec else b""))
    return out


def sw_hex(sw1: int, sw2: int) -> str:
    return f"{sw1:02X}{sw2:02X}"


def describe_sw(sw1: int, sw2: int) -> str:
    return status_text(sw1, sw2)


def redact_secret(trace: bytes, secret: bytes | bytearray) -> bytes:
    """Belt-and-braces: redact a secret's ASCII and uppercase/lowercase hex forms from
    a trace, on top of npa_driver's own six-digit/ANSI sanitizer."""
    if not secret:
        return trace
    sec = bytes(secret)
    out = trace.replace(sec, b"<pin-redacted>")
    hexup = sec.hex().upper().encode()
    hexlo = sec.hex().encode()
    # spaced hex form too (e.g. "31 32 33 34")
    spaced = " ".join(f"{b:02X}" for b in sec).encode()
    for form in (hexup, hexlo, spaced):
        out = re.sub(re.escape(form), b"<pin-redacted>", out)
    return out
