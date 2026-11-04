#!/usr/bin/env python3
"""Non-PII cryptographic fingerprinting of eID security objects.

Input is the reconstructed DER of a security object (EF.CardSecurity, DG14,
EF.SOD, EF.COM). Output is JSON-able metadata: sizes, hashes, embedded signer
certificates (subject/issuer/algorithm/key size), and public-key SPKI digests.
No personal data group is parsed here; the caller must not pass DG1/2/7/11/12/13.

Only the `cryptography` library is required. ASN.1 is walked with a minimal DER
reader so no extra dependency is needed; parsing failures degrade to size+hash.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Reference fingerprint values for same/different flags.
REFERENCE = {
    "cardsecurity_ds_cert_sha256": "4eb27936eeee488c8409044d8db3ff22210155443b89db7e4b21aee2f95704e2",
    "cardsecurity_ds_spki_sha256": "ec77a452c2c5f0b54c2c106c665301eac245cc596e8614e62448365fcafbaabc",
    "sod_ds_cert_sha256": "1412267945fdd2d6d196bcc49acff007dd91f61de761b8ab7e0e16bcf327dfb5",
    "sod_ds_spki_sha256": "1668370ca5f4a0625159d5334d8202b7b27d4220e4139eb02a4d22c8043beef3",
    "chip_auth_spki_sha256": "1be95a55a1e161be083b750e1bbef845256bc937fca165b0d9a3ef92a1ebb499",
}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _walk(der: bytes, start: int = 0, end: int | None = None):
    """Yield (tag, start, header_len, value_len, total_len) for each TLV in a range."""
    if end is None:
        end = len(der)
    i = start
    while i < end:
        if i + 2 > end:
            return
        tag = der[i]
        tag_len = 1
        if tag & 0x1F == 0x1F:  # multi-byte (high-tag-number) tag
            while i + tag_len < end and der[i + tag_len] & 0x80:
                tag_len += 1
            tag_len += 1
        if i + tag_len >= end:
            return
        length_byte = der[i + tag_len]
        len_at = i + tag_len
        if length_byte < 0x80:
            header = tag_len + 1
            vlen = length_byte
        else:
            nbytes = length_byte & 0x7F
            if nbytes == 0 or len_at + 1 + nbytes > end:
                return
            header = tag_len + 1 + nbytes
            vlen = int.from_bytes(der[len_at + 1 : len_at + 1 + nbytes], "big")
        total = header + vlen
        if i + total > end:
            return
        yield tag, i, header, vlen, total
        i += total


def _iter_all_tlvs(der: bytes):
    """Depth-first over every TLV, recursing into constructed (tag & 0x20) ones."""
    stack = [(0, len(der))]
    while stack:
        s, e = stack.pop()
        for tag, start, header, vlen, total in _walk(der, s, e):
            yield der[start : start + total]
            if tag & 0x20:  # constructed
                stack.append((start + header, start + total))


EC_PUBLIC_KEY_OID = bytes.fromhex("06072A8648CE3D0201")  # id-ecPublicKey


def _ec_spki_digests(der: bytes) -> list[str]:
    """SHA-256 of every SubjectPublicKeyInfo SEQUENCE carrying id-ecPublicKey.

    Works for explicit-parameter EC keys that `cryptography` refuses to load, by
    hashing the SPKI DER bytes verbatim (SEQUENCE{ AlgorithmIdentifier, BIT STRING }).
    """
    out: list[str] = []
    seen: set[str] = set()
    for tlv in _iter_all_tlvs(der):
        if not tlv or tlv[0] != 0x30:
            continue
        children = [tlv[s : s + t] for _, s, _, _, t in _walk(tlv, 2 if tlv[1] < 0x80 else 2 + (tlv[1] & 0x7F), len(tlv))]
        if len(children) != 2 or children[0][:1] != b"\x30" or children[1][:1] != b"\x03":
            continue
        if EC_PUBLIC_KEY_OID not in children[0]:
            continue
        h = sha256_hex(tlv)
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _key_profile(cert: x509.Certificate, cert_der: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        pub = cert.public_key()
        spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        info["spki_sha256"] = sha256_hex(spki)
        if isinstance(pub, rsa.RSAPublicKey):
            info["algorithm"] = "RSA"
            info["key_bits"] = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["algorithm"] = "EC"
            info["curve"] = pub.curve.name
            info["key_bits"] = pub.curve.key_size
        else:
            info["algorithm"] = type(pub).__name__
    except Exception:
        # Explicit-parameter EC (e.g. Brainpool-explicit): hash the SPKI bytes directly.
        spki_digests = _ec_spki_digests(cert_der)
        info["algorithm"] = "EC (explicit parameters)"
        info["spki_sha256"] = spki_digests[0] if spki_digests else None
    try:
        info["signature_hash"] = cert.signature_hash_algorithm.name
    except Exception:
        info["signature_hash"] = None
    return info


def _extract_certs(der: bytes) -> list[dict[str, Any]]:
    seen: set[bytes] = set()
    certs: list[dict[str, Any]] = []
    for tlv in _iter_all_tlvs(der):
        if not tlv or tlv[0] != 0x30:
            continue
        try:
            cert = x509.load_der_x509_certificate(tlv)
        except Exception:
            continue
        fp = hashlib.sha256(tlv).digest()
        if fp in seen:
            continue
        seen.add(fp)
        entry: dict[str, Any] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_hex": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "cert_sha256": sha256_hex(tlv),
        }
        entry.update(_key_profile(cert, tlv))
        certs.append(entry)
    return certs


def _base(name: str, der: bytes) -> dict[str, Any]:
    return {"object": name, "size_bytes": len(der), "sha256": sha256_hex(der), "leading_tag": f"{der[0]:02X}" if der else None}


def fingerprint_cardsecurity(der: bytes) -> dict[str, Any]:
    out = _base("EF.CardSecurity", der)
    certs = _extract_certs(der)
    out["embedded_certificates"] = certs
    ds = certs[0] if certs else None
    out["document_signer"] = ds
    if ds:
        out["is_reference_development_signer"] = ds["cert_sha256"] == REFERENCE["cardsecurity_ds_cert_sha256"]
        out["weak_rsa1024"] = ds.get("algorithm") == "RSA" and ds.get("key_bits", 0) <= 1024
        out["development_ou"] = "development" in (ds["subject"] + ds["issuer"]).lower()
    return out


def fingerprint_dg14(der: bytes) -> dict[str, Any]:
    out = _base("DG14", der)
    keys = _ec_spki_digests(der)
    out["ec_public_keys_spki_sha256"] = keys
    out["chip_auth_key_matches_reference"] = REFERENCE["chip_auth_spki_sha256"] in keys
    out["per_card_unique_vs_reference"] = bool(keys) and REFERENCE["chip_auth_spki_sha256"] not in keys
    return out


def fingerprint_sod(der: bytes) -> dict[str, Any]:
    out = _base("EF.SOD", der)
    certs = _extract_certs(der)
    out["embedded_certificates"] = certs
    ds = certs[0] if certs else None
    out["document_signer"] = ds
    if ds:
        out["is_reference_sod_signer"] = ds["cert_sha256"] == REFERENCE["sod_ds_cert_sha256"]
        out["strong_identity_signer"] = str(ds.get("algorithm", "")).startswith("EC")
    return out


def fingerprint_com(der: bytes) -> dict[str, Any]:
    out = _base("EF.COM", der)
    # EF.COM tag list 5C enumerates present DG tags (structure only, not content).
    present: list[str] = []
    for tlv in _iter_all_tlvs(der):
        if tlv and tlv[0] == 0x5C and len(tlv) >= 2:
            present = [f"{b:02X}" for b in tlv[2:]]
            break
    out["data_group_tag_list"] = present
    return out


def fingerprint_cvca(der: bytes) -> dict[str, Any]:
    """EF.CVCA: the Certification Authority References (CARs) the card trusts for EAC."""
    out = _base("EF.CVCA", der)
    cars: list[str] = []
    for tlv in _iter_all_tlvs(der):
        if tlv and tlv[0] == 0x42:  # Certification Authority Reference
            first = tlv[1]
            hdr = 2 if first < 0x80 else 2 + (first & 0x7F)
            txt = tlv[hdr:].decode("latin1").strip("\x00 ").strip()
            if txt:
                cars.append(txt)
    # Fallback: EF.CVCA may be a bare padded CAR string without a 0x42 wrapper.
    if not cars:
        txt = "".join(chr(b) for b in der if 0x20 <= b < 0x7F)
        if txt:
            cars.append(txt)
    out["trust_anchor_references"] = cars
    return out


FINGERPRINTERS = {
    "cardsecurity": fingerprint_cardsecurity,
    "dg14": fingerprint_dg14,
    "sod": fingerprint_sod,
    "com": fingerprint_com,
    "cvca": fingerprint_cvca,
}
