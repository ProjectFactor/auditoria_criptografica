#!/usr/bin/env python3
"""From-scratch PACE-ECDH-GM-AES-256 + ISO-7816 Secure Messaging.

This module establishes a PACE channel and derives the session keys *ourselves*
(no npa-tool, no OpenSC), so we can then build APDUs the real client never would:
a MAC-tampered SM command, or a downgraded PACE suite. npa-tool always wraps SM
correctly and so cannot emit those; this stack can, which is what Tier-2's open
negative tests (SM MAC tamper, PACE/CA downgrade) require.

Scope is exactly the suite this card advertises in EF.CardAccess:
  OID  0.4.0.127.0.7.2.2.4.2.4  = id-PACE-ECDH-GM-AES-CBC-CMAC-256
  domain parameter 15           = NIST P-384 (secp384r1)
  KDF hash SHA-256, MAC = AES-CMAC truncated to 8 bytes, SM cipher AES-256-CBC.

Cryptography used from the `cryptography` package: AES-ECB/CBC and AES-CMAC only.
All elliptic-curve arithmetic (needed because Generic Mapping computes G' = s*G + H,
a raw point addition the library does not expose) is implemented here over the
published P-384 parameters and self-checked at import-time-optional --selftest.

Secrets discipline: the CAN-derived key, session keys and SSC never leave memory
and are never written to disk by this module. Callers log APDUs/SWs, not keys.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

# --- PACE suite identifiers --------------------------------------------------
# OID *value* bytes (content of the OBJECT IDENTIFIER, i.e. without the 06 LEN prefix).
OID_PACE_ECDH_GM_AES_256 = bytes.fromhex("04007F000702020402 04".replace(" ", ""))
OID_PACE_ECDH_GM_AES_128 = bytes.fromhex("04007F000702020402 02".replace(" ", ""))
OID_PACE_ECDH_GM_3DES    = bytes.fromhex("04007F000702020402 01".replace(" ", ""))

PASSWORD_REF_MRZ = 0x01
PASSWORD_REF_CAN = 0x02

# --- NIST P-384 / secp384r1 domain parameters (standardized param 15) --------
_P = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
         "ffffffff0000000000000000ffffffff", 16)
_A = (_P - 3) % _P
_B = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
         "c656398d8a2ed19d2a85c8edd3ec2aef", 16)
_GX = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
          "5502f25dbf55296c3a545e3872760ab7", 16)
_GY = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
          "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
_N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
         "581a0db248b0a77aecec196accc52973", 16)
_COORD_LEN = 48  # 384 bits


# ============================================================================
# Elliptic-curve arithmetic over P-384 (affine; None = point at infinity)
# ============================================================================
Point = Optional[tuple[int, int]]


def _inv(x: int) -> int:
    return pow(x % _P, _P - 2, _P)


def ec_is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def ec_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def ec_mul(k: int, pt: Point) -> Point:
    k %= _N
    result: Point = None
    addend = pt
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


_G: Point = (_GX, _GY)


def ec_decode(blob: bytes) -> Point:
    """Decode an uncompressed point 0x04 || X(48) || Y(48)."""
    if len(blob) != 1 + 2 * _COORD_LEN or blob[0] != 0x04:
        raise ValueError(f"not an uncompressed P-384 point ({len(blob)} bytes)")
    x = int.from_bytes(blob[1:1 + _COORD_LEN], "big")
    y = int.from_bytes(blob[1 + _COORD_LEN:], "big")
    pt = (x, y)
    if not ec_is_on_curve(pt):
        raise ValueError("decoded point is not on the P-384 curve")
    return pt


def ec_encode(pt: Point) -> bytes:
    assert pt is not None
    x, y = pt
    return b"\x04" + x.to_bytes(_COORD_LEN, "big") + y.to_bytes(_COORD_LEN, "big")


# ============================================================================
# Symmetric crypto (AES / CMAC) and KDF
# ============================================================================
def aes_ecb_enc(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - block-cipher IV derivation per ICAO
    return enc.update(block) + enc.finalize()


def aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def kdf(shared: bytes, counter: int, keylen: int = 32) -> bytes:
    """ICAO 9303 KDF for AES-256: SHA-256(shared || counter)[:32]."""
    return hashlib.sha256(shared + counter.to_bytes(4, "big")).digest()[:keylen]


def iso7816_pad(data: bytes, block: int = 16) -> bytes:
    data = data + b"\x80"
    while len(data) % block:
        data += b"\x00"
    return data


def iso7816_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("padded AES plaintext must contain complete blocks")
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80 or len(data) - i > 16:
        raise ValueError("bad ISO-7816 padding")
    return data[:i]


# ============================================================================
# Minimal BER-TLV (tags used by PACE/SM: 7C, 80-86, 7F49, 87, 97, 99, 8E)
# ============================================================================
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def tlv(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes((tag.bit_length() + 7) // 8 or 1, "big")
    return tag_bytes + _enc_len(len(value)) + value


def parse_tlvs(buf: bytes) -> list[tuple[int, bytes, bytes]]:
    """Parse complete definite-length TLVs in this stack's one/two-byte tag profile.

    Reject truncated headers/values, indefinite or non-minimal lengths and tag
    encodings outside the supported profile rather than silently slicing them.
    """
    out: list[tuple[int, bytes, bytes]] = []
    i = 0
    while i < len(buf):
        start = i
        tag = buf[i]
        i += 1
        if tag in (0x00, 0xFF):
            raise ValueError("invalid TLV tag")
        if (tag & 0x1F) == 0x1F:  # multi-byte tag
            if i >= len(buf):
                raise ValueError("truncated TLV tag")
            if buf[i] & 0x80 or buf[i] < 0x1F:
                raise ValueError("unsupported or non-minimal TLV tag")
            tag = (tag << 8) | buf[i]
            i += 1
        if i >= len(buf):
            raise ValueError("truncated TLV length")
        length = buf[i]
        i += 1
        if length & 0x80:
            k = length & 0x7F
            if not k or k > 4:
                raise ValueError("indefinite or unsupported TLV length")
            if k > len(buf) - i:
                raise ValueError("truncated TLV length")
            if buf[i] == 0:
                raise ValueError("non-minimal TLV length")
            length = int.from_bytes(buf[i:i + k], "big")
            i += k
            if length < 0x80:
                raise ValueError("non-minimal TLV length")
        if length > len(buf) - i:
            raise ValueError("truncated TLV value")
        value = buf[i:i + length]
        i += length
        out.append((tag, value, buf[start:i]))
    return out


def find_tag(tlvs: list[tuple[int, bytes, bytes]], tag: int) -> bytes:
    for t, v, _ in tlvs:
        if t == tag:
            return v
    raise KeyError(f"tag {tag:X} not found")


# ============================================================================
# APDU transport: a transmit callable (apdu_bytes) -> (data, sw1, sw2)
# ============================================================================
Transmit = Callable[[bytes], tuple[bytes, int, int]]


class CardError(Exception):
    def __init__(self, msg: str, sw1: int = 0, sw2: int = 0):
        super().__init__(f"{msg} (SW={sw1:02X}{sw2:02X})" if (sw1 or sw2) else msg)
        self.sw1, self.sw2 = sw1, sw2


# ============================================================================
# PACE-ECDH-GM handshake
# ============================================================================
@dataclass
class PaceResult:
    k_enc: bytes
    k_mac: bytes
    pcd_ephemeral_pub: Point  # our X2 (for the record)
    picc_ephemeral_pub: Point  # card's Y2
    nonce: bytes = b""  # decrypted PACE nonce s (card RNG output; for freshness/RNG checks)


def _pubkey_do(oid_value: bytes, point: Point) -> bytes:
    """7F49 { 06 OID, 86 point } — input to the PACE authentication token."""
    inner = tlv(0x06, oid_value) + tlv(0x86, ec_encode(point))
    return tlv(0x7F49, inner)


def _ga(transmit: Transmit, data_7c: bytes, last: bool) -> list[tuple[int, bytes, bytes]]:
    """One GENERAL AUTHENTICATE step. CLA 0x10 chains; 0x00 is the final step."""
    cla = 0x00 if last else 0x10
    body = tlv(0x7C, data_7c)
    apdu = bytes([cla, 0x86, 0x00, 0x00, len(body)]) + body + b"\x00"
    data, sw1, sw2 = transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("GENERAL AUTHENTICATE failed", sw1, sw2)
    return parse_tlvs(find_tag(parse_tlvs(data), 0x7C) if data and data[0] == 0x7C else data)


def mse_set_at_pace(transmit: Transmit, oid_value: bytes, password_ref: int,
                    domain_param: Optional[int] = None) -> tuple[int, int]:
    """Send MSE:Set AT selecting a PACE suite. Returns (sw1, sw2) without raising,
    so callers (e.g. the downgrade probe) can judge acceptance vs refusal."""
    data = tlv(0x80, oid_value) + tlv(0x83, bytes([password_ref]))
    if domain_param is not None:
        data += tlv(0x84, bytes([domain_param]))
    apdu = bytes([0x00, 0x22, 0xC1, 0xA4, len(data)]) + data
    _, sw1, sw2 = transmit(apdu)
    return sw1, sw2


def establish_pace(transmit: Transmit, can: bytes,
                   oid_value: bytes = OID_PACE_ECDH_GM_AES_256) -> PaceResult:
    """Run the full PACE-ECDH-GM handshake with the CAN. Raises CardError on any
    card refusal, ValueError on a protocol/crypto inconsistency."""
    # 1. MSE:Set AT
    sw1, sw2 = mse_set_at_pace(transmit, oid_value, PASSWORD_REF_CAN)
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("MSE:Set AT (PACE) refused", sw1, sw2)

    # 2. GA step 1 — request the encrypted nonce (DO 80)
    step1 = _ga(transmit, b"", last=False)
    enc_nonce = find_tag(step1, 0x80)
    k_pi = kdf(can, 3)                      # password-derived key
    s = aes_cbc_dec(k_pi, b"\x00" * 16, enc_nonce)   # nonce, one AES block
    s_int = int.from_bytes(s, "big")

    # 3. GA step 2 — anonymous ECDH to map the nonce (Generic Mapping)
    x1 = secrets.randbelow(_N - 1) + 1
    X1 = ec_mul(x1, _G)
    step2 = _ga(transmit, tlv(0x81, ec_encode(X1)), last=False)
    Y1 = ec_decode(find_tag(step2, 0x82))
    if Y1 == X1:
        raise ValueError("card mapping key equals ours (reflection)")
    H = ec_mul(x1, Y1)                      # shared mapping secret
    G_mapped = ec_add(ec_mul(s_int, _G), H)  # G' = s*G + H
    if G_mapped is None or not ec_is_on_curve(G_mapped):
        raise ValueError("mapped generator is invalid")

    # 4. GA step 3 — ephemeral key agreement on the mapped generator
    x2 = secrets.randbelow(_N - 1) + 1
    X2 = ec_mul(x2, G_mapped)
    step3 = _ga(transmit, tlv(0x83, ec_encode(X2)), last=False)
    Y2 = ec_decode(find_tag(step3, 0x84))
    if Y2 == X2:
        raise ValueError("card ephemeral key equals ours (reflection)")
    K = ec_mul(x2, Y2)
    if K is None:
        raise ValueError("shared secret is the point at infinity")
    k_shared = K[0].to_bytes(_COORD_LEN, "big")  # x-coordinate
    k_enc = kdf(k_shared, 1)
    k_mac = kdf(k_shared, 2)

    # 5. GA step 4 — mutual authentication tokens (CMAC over the *other* key)
    t_pcd = aes_cmac(k_mac, _pubkey_do(oid_value, Y2))[:8]
    step4 = _ga(transmit, tlv(0x85, t_pcd), last=True)
    t_picc = find_tag(step4, 0x86)
    expected = aes_cmac(k_mac, _pubkey_do(oid_value, X2))[:8]
    if t_picc != expected:
        raise ValueError("PICC authentication token mismatch — PACE not established")

    return PaceResult(k_enc=k_enc, k_mac=k_mac, pcd_ephemeral_pub=X2, picc_ephemeral_pub=Y2, nonce=s)


# ============================================================================
# Secure Messaging (AES-256-CBC + AES-CMAC-8, SSC per ICAO 9303)
# ============================================================================
class SecureMessaging:
    def __init__(self, k_enc: bytes, k_mac: bytes):
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.ssc = 0
        self.alive = True  # set False once a response fails, to prevent SSC-desynced reuse

    def _ssc_block(self) -> bytes:
        return self.ssc.to_bytes(16, "big")

    def _iv(self) -> bytes:
        return aes_ecb_enc(self.k_enc, self._ssc_block())

    def build(self, cla: int, ins: int, p1: int, p2: int,
              data: bytes = b"", le: Optional[int] = None) -> bytes:
        """Return a fully wrapped SM command APDU and advance the SSC for it."""
        if not self.alive:
            raise CardError("SM session is dead after a prior failure; re-establish PACE")
        self.ssc += 1
        cla_sm = cla | 0x0C
        do87 = b""
        do97 = b""
        if data:
            ct = aes_cbc_enc(self.k_enc, self._iv(), iso7816_pad(data))
            do87 = tlv(0x87, b"\x01" + ct)
        if le is not None:
            le_bytes = b"\x00" if le == 0 else bytes([le])
            do97 = tlv(0x97, le_bytes)
        header = bytes([cla_sm, ins, p1, p2])
        mac_data = iso7816_pad(header) + do87 + do97
        # BSI TR-03110-3 Figure 5: case 1 authenticates the already padded
        # header directly. Only commands carrying DO87/DO97 append a second
        # padding boundary (Figure 4); another full block in case 1 is wrong.
        if do87 or do97:
            mac_data = iso7816_pad(mac_data)
        mac = aes_cmac(self.k_mac, self._ssc_block() + mac_data)[:8]
        do8e = tlv(0x8E, mac)
        body = do87 + do97 + do8e
        return bytes([cla_sm, ins, p1, p2, len(body)]) + body + b"\x00"

    def unwrap(self, resp: bytes, sw1: int, sw2: int) -> tuple[bytes, int, int]:
        """Verify the response MAC and return (plaintext_data, sw1, sw2) from DO99.
        `resp` is the response body (DOs), `sw1/sw2` the transport status.
        On any failure the SM session is marked dead (SSC would be desynced)."""
        if not self.alive:
            raise CardError("SM session is dead after a prior failure; re-establish PACE")
        try:
            if (sw1, sw2) != (0x90, 0x00):
                raise CardError("SM transport status not 9000", sw1, sw2)
            # Compute against the response SSC without committing it until the
            # complete authenticated response has been validated and decoded.
            resp_ssc = self.ssc + 1
            resp_ssc_block = resp_ssc.to_bytes(16, "big")
            tlvs = parse_tlvs(resp)
            tags = [tag for tag, _, _ in tlvs]
            if tags not in ([0x99, 0x8E], [0x87, 0x99, 0x8E]):
                raise CardError("unexpected SM response objects or order")
            do99 = tlvs[-2][1]
            do8e_val = tlvs[-1][1]
            if len(do99) != 2:
                raise CardError("response DO99 must contain exactly two status bytes")
            if len(do8e_val) != 8:
                raise CardError("response DO8E must contain exactly eight MAC bytes")
            do87_val = tlvs[0][1] if tags[0] == 0x87 else None
            if do87_val is not None and (
                len(do87_val) < 17 or do87_val[0] != 0x01 or (len(do87_val) - 1) % 16
            ):
                raise CardError("invalid response DO87 indicator or ciphertext length")
            mac_input = resp_ssc_block + b"".join(raw for _, _, raw in tlvs[:-1])
            expected = aes_cmac(self.k_mac, iso7816_pad(mac_input))[:8]
            if not secrets.compare_digest(expected, do8e_val):
                raise CardError("response SM MAC verification FAILED")
            plain = b""
            if do87_val is not None:
                iv = aes_ecb_enc(self.k_enc, resp_ssc_block)
                plain = iso7816_unpad(aes_cbc_dec(self.k_enc, iv, do87_val[1:]))
            self.ssc = resp_ssc
            return plain, do99[0], do99[1]
        except Exception:
            # Parsing, structural validation, cryptography and padding can all
            # fail. Every failure terminates this channel; an uncommitted SSC
            # alone is insufficient protection against accidental reuse.
            self.alive = False
            raise


# ============================================================================
# Self-test (offline): EC sanity + SM framing round-trip. No card.
# ============================================================================
def _selftest() -> int:
    assert ec_is_on_curve(_G), "base point G off curve"
    assert ec_mul(_N, _G) is None, "n*G != O"
    assert ec_add(_G, _G) == ec_mul(2, _G), "2G != G+G"
    assert ec_add(_G, None) == _G and ec_add(None, _G) == _G, "identity add"
    # scalar associativity: (a+b)*G == a*G + b*G
    a, b = 1234567, 7654321
    assert ec_add(ec_mul(a, _G), ec_mul(b, _G)) == ec_mul(a + b, _G), "lin"
    # round-trip point codec
    assert ec_decode(ec_encode(_G)) == _G
    # KDF length / determinism
    assert len(kdf(b"abc", 1)) == 32
    # TLV round-trip incl. long form
    big = os.urandom(200)
    assert find_tag(parse_tlvs(tlv(0x87, big)), 0x87) == big
    # SM MAC input framing is stable and 8-byte truncated
    sm = SecureMessaging(b"\x11" * 32, b"\x22" * 32)
    apdu = sm.build(0x00, 0xB0, 0x00, 0x00, le=0x16)
    t = parse_tlvs(apdu[5:-1])
    assert any(tg == 0x97 for tg, _, _ in t), "DO97 missing"
    assert any(tg == 0x8E and len(v) == 8 for tg, v, _ in t), "DO8E not 8 bytes"
    # ISO padding round-trip
    assert iso7816_unpad(iso7816_pad(b"hello")) == b"hello"
    assert iso7816_unpad(iso7816_pad(b"\x00" * 16)) == b"\x00" * 16
    print("pace_sm selftest: PASS (EC, KDF, TLV, SM framing, padding)")
    return 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print(__doc__)
    print("Run with --selftest for offline checks. This module is a library; "
          "see tier2_sm_tamper.py for the live PACE/SM negative tests.")
