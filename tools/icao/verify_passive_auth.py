#!/usr/bin/env python3
"""Strict, offline ICAO Passive Authentication verifier.

This tool never accesses a reader, card, network service, or credential. It verifies a
saved EF.SOD CMS object, reconciles EF.COM and supplied data groups, profiles the
embedded Document Signer certificate, tests explicit trust anchors, and evaluates
explicitly supplied CRLs. Unknown trust or revocation is reported as unknown, not as
an integrity failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID


DG_TAG_TO_NUMBER = {
    0x61: 1,
    0x75: 2,
    0x63: 3,
    0x76: 4,
    0x65: 5,
    0x66: 6,
    0x67: 7,
    0x68: 8,
    0x69: 9,
    0x6A: 10,
    0x6B: 11,
    0x6C: 12,
    0x6D: 13,
    0x6E: 14,
    0x6F: 15,
    0x70: 16,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_tag(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER tag")
    first = data[offset]
    offset += 1
    if first & 0x1F != 0x1F:
        return first, offset
    tag = first
    seen = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated high-tag-number form")
        byte = data[offset]
        offset += 1
        if seen == 0 and byte == 0x80:
            raise ValueError("non-minimal high-tag-number form")
        tag = (tag << 8) | byte
        seen += 1
        if seen > 4:
            raise ValueError("unsupported tag width")
        if byte & 0x80 == 0:
            return tag, offset


def read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    width = first & 0x7F
    if width == 0:
        raise ValueError("indefinite length is not DER")
    if width > 4 or offset + width > len(data):
        raise ValueError("unsupported or truncated DER length")
    raw = data[offset : offset + width]
    if raw[0] == 0 or (width == 1 and raw[0] < 0x80):
        raise ValueError("non-minimal DER length")
    return int.from_bytes(raw, "big"), offset + width


def tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag, cursor = read_tag(data, offset)
    length, cursor = read_length(data, cursor)
    end = cursor + length
    if end > len(data):
        raise ValueError("DER value exceeds input")
    return tag, data[cursor:end], end


def complete_der(data: bytes) -> bool:
    _, _, end = tlv(data, 0)
    return end == len(data)


def children(data: bytes) -> list[tuple[int, bytes]]:
    result = []
    offset = 0
    while offset < len(data):
        tag, value, offset = tlv(data, offset)
        result.append((tag, value))
    return result


def encoded_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encoded_tlv(tag: int, value: bytes) -> bytes:
    if not 0 <= tag <= 0xFF:
        raise ValueError("only single-octet tags can be re-encoded")
    return bytes([tag]) + encoded_length(len(value)) + value


def certificate_issuer_serial(certificate_der: bytes) -> tuple[bytes, int]:
    cert_tag, cert_value, cert_end = tlv(certificate_der, 0)
    if cert_tag != 0x30 or cert_end != len(certificate_der):
        raise ValueError("certificate is not one DER SEQUENCE")
    certificate_fields = children(cert_value)
    if not certificate_fields or certificate_fields[0][0] != 0x30:
        raise ValueError("certificate has no TBSCertificate")
    tbs = children(certificate_fields[0][1])
    offset = 1 if tbs and tbs[0][0] == 0xA0 else 0
    if len(tbs) <= offset + 2 or tbs[offset][0] != 0x02 or tbs[offset + 2][0] != 0x30:
        raise ValueError("malformed TBSCertificate issuer/serial")
    return encoded_tlv(tbs[offset + 2][0], tbs[offset + 2][1]), parse_integer(tbs[offset][1])


def algorithm_identifier(data: bytes) -> dict[str, Any]:
    fields = children(data)
    if not fields or fields[0][0] != 0x06:
        raise ValueError("AlgorithmIdentifier has no OID")
    return {
        "oid": parse_oid(fields[0][1]),
        "parameters": (
            "absent" if len(fields) == 1 else "null" if fields[1] == (0x05, b"") else f"tag_{fields[1][0]:X}"
        ),
    }


def ec_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
    prime: int,
    coefficient_a: int,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % prime == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + coefficient_a) * pow(2 * y1, -1, prime)) % prime
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % prime, -1, prime)) % prime
    x3 = (slope * slope - x1 - x2) % prime
    y3 = (slope * (x1 - x3) - y1) % prime
    return x3, y3


def ec_multiply(
    scalar: int,
    point: tuple[int, int],
    prime: int,
    coefficient_a: int,
) -> tuple[int, int] | None:
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = ec_add(result, addend, prime, coefficient_a)
        addend = ec_add(addend, addend, prime, coefficient_a)
        scalar >>= 1
    return result


def parse_uncompressed_point(raw: bytes, width: int) -> tuple[int, int]:
    if len(raw) != 1 + 2 * width or raw[0] != 0x04:
        raise ValueError("only an uncompressed EC point is accepted")
    return int.from_bytes(raw[1 : 1 + width], "big"), int.from_bytes(raw[1 + width :], "big")


def parse_explicit_ec_spki(certificate_der: bytes) -> dict[str, Any]:
    cert_tag, cert_value, cert_end = tlv(certificate_der, 0)
    if cert_tag != 0x30 or cert_end != len(certificate_der):
        raise ValueError("certificate is not one DER SEQUENCE")
    certificate_fields = children(cert_value)
    if len(certificate_fields) != 3 or certificate_fields[0][0] != 0x30:
        raise ValueError("unexpected Certificate structure")
    tbs = children(certificate_fields[0][1])
    spki_index = 6 if tbs and tbs[0][0] == 0xA0 else 5
    if len(tbs) <= spki_index or tbs[spki_index][0] != 0x30:
        raise ValueError("missing SubjectPublicKeyInfo")
    spki = children(tbs[spki_index][1])
    if len(spki) != 2 or spki[0][0] != 0x30 or spki[1][0] != 0x03:
        raise ValueError("malformed SubjectPublicKeyInfo")
    algorithm = children(spki[0][1])
    if len(algorithm) != 2 or algorithm[0][0] != 0x06 or algorithm[1][0] != 0x30:
        raise ValueError("EC parameters are not explicit")
    if parse_oid(algorithm[0][1]) != "1.2.840.10045.2.1":
        raise ValueError("SubjectPublicKeyInfo is not id-ecPublicKey")
    parameters = children(algorithm[1][1])
    if len(parameters) < 5 or [item[0] for item in parameters[:5]] != [0x02, 0x30, 0x30, 0x04, 0x02]:
        raise ValueError("malformed explicit ECParameters")
    field = children(parameters[1][1])
    curve = children(parameters[2][1])
    if len(field) != 2 or field[0][0] != 0x06 or field[1][0] != 0x02:
        raise ValueError("malformed EC FieldID")
    if parse_oid(field[0][1]) != "1.2.840.10045.1.1":
        raise ValueError("only prime-field EC is accepted")
    if len(curve) < 2 or curve[0][0] != 0x04 or curve[1][0] != 0x04:
        raise ValueError("malformed EC Curve")
    prime = parse_integer(field[1][1])
    width = (prime.bit_length() + 7) // 8
    coefficient_a = int.from_bytes(curve[0][1], "big")
    coefficient_b = int.from_bytes(curve[1][1], "big")
    base = parse_uncompressed_point(parameters[3][1], width)
    order = parse_integer(parameters[4][1])
    cofactor = parse_integer(parameters[5][1]) if len(parameters) > 5 and parameters[5][0] == 0x02 else None
    bit_string = spki[1][1]
    if not bit_string or bit_string[0] != 0:
        raise ValueError("EC public-key BIT STRING has unused bits")
    public = parse_uncompressed_point(bit_string[1:], width)
    for name, point in (("base", base), ("public", public)):
        x, y = point
        if (y * y - (x * x * x + coefficient_a * x + coefficient_b)) % prime:
            raise ValueError(f"{name} point is not on the declared curve")
    if ec_multiply(order, base, prime, coefficient_a) is not None:
        raise ValueError("declared EC base/order pair is inconsistent")
    brainpool_p256r1 = {
        "prime": int("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
        "a": int("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
        "b": int("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16),
        "base": (
            int("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
            int("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16),
        ),
        "order": int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
        "cofactor": 1,
    }
    observed = {
        "prime": prime,
        "a": coefficient_a,
        "b": coefficient_b,
        "base": base,
        "order": order,
        "cofactor": cofactor,
    }
    return {
        "a": coefficient_a,
        "b": coefficient_b,
        "base": base,
        "cofactor": cofactor,
        "order": order,
        "prime": prime,
        "public": public,
        "width": width,
        "equivalent_named_curve": "brainpoolP256r1" if observed == brainpool_p256r1 else None,
    }


def independent_cms_ecdsa_verify(cms: bytes, certificate_der: bytes) -> dict[str, Any]:
    """Verify this profile's CMS signature using only the local DER and integer arithmetic."""
    top_tag, top_value, top_end = tlv(cms, 0)
    if top_tag != 0x30 or top_end != len(cms):
        raise ValueError("CMS is not one ContentInfo SEQUENCE")
    content_info = children(top_value)
    if len(content_info) != 2 or content_info[0][0] != 0x06 or content_info[1][0] != 0xA0:
        raise ValueError("malformed CMS ContentInfo")
    if parse_oid(content_info[0][1]) != "1.2.840.113549.1.7.2":
        raise ValueError("CMS is not SignedData")
    explicit = children(content_info[1][1])
    if len(explicit) != 1 or explicit[0][0] != 0x30:
        raise ValueError("malformed SignedData wrapper")
    signed_data = children(explicit[0][1])
    if len(signed_data) < 5 or signed_data[0][0] != 0x02 or signed_data[1][0] != 0x31 or signed_data[2][0] != 0x30:
        raise ValueError("malformed SignedData")
    encap = children(signed_data[2][1])
    if len(encap) != 2 or encap[0][0] != 0x06 or encap[1][0] != 0xA0:
        raise ValueError("malformed EncapsulatedContentInfo")
    content_wrapper = children(encap[1][1])
    if len(content_wrapper) != 1 or content_wrapper[0][0] != 0x04:
        raise ValueError("encapsulated content is not one OCTET STRING")
    content = content_wrapper[0][1]
    signer_set = signed_data[-1]
    if signer_set[0] != 0x31:
        raise ValueError("missing SignerInfos")
    signers = children(signer_set[1])
    if len(signers) != 1 or signers[0][0] != 0x30:
        raise ValueError("expected exactly one SignerInfo")
    signer = children(signers[0][1])
    if len(signer) < 6 or signer[3][0] != 0xA0 or signer[4][0] != 0x30 or signer[5][0] != 0x04:
        raise ValueError("unexpected SignerInfo structure")
    if signer[1][0] != 0x30:
        raise ValueError("SignerIdentifier is not issuerAndSerialNumber")
    signer_id = children(signer[1][1])
    if len(signer_id) != 2 or signer_id[0][0] != 0x30 or signer_id[1][0] != 0x02:
        raise ValueError("malformed issuerAndSerialNumber")
    issuer_der, certificate_serial = certificate_issuer_serial(certificate_der)
    if encoded_tlv(signer_id[0][0], signer_id[0][1]) != issuer_der or parse_integer(signer_id[1][1]) != certificate_serial:
        raise ValueError("SignerIdentifier does not match embedded certificate")
    digest_algorithm = algorithm_identifier(signer[2][1])
    signature_algorithm = algorithm_identifier(signer[4][1])
    if digest_algorithm["oid"] != "2.16.840.1.101.3.4.2.1":
        raise ValueError("independent verifier accepts only observed SHA-256 digest")
    if signature_algorithm["oid"] != "1.2.840.10045.4.3.2":
        raise ValueError("independent verifier accepts only observed ECDSA-with-SHA256")
    attributes: dict[str, list[tuple[int, bytes]]] = {}
    for attribute_tag, attribute_value in children(signer[3][1]):
        attribute = children(attribute_value) if attribute_tag == 0x30 else []
        if len(attribute) != 2 or attribute[0][0] != 0x06 or attribute[1][0] != 0x31:
            raise ValueError("malformed signed attribute")
        oid = parse_oid(attribute[0][1])
        if oid in attributes:
            raise ValueError("duplicate signed attribute")
        attributes[oid] = children(attribute[1][1])
    expected_attributes = {"1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"}
    if set(attributes) != expected_attributes:
        raise ValueError("unexpected signed-attribute set")
    content_type_values = attributes["1.2.840.113549.1.9.3"]
    digest_values = attributes["1.2.840.113549.1.9.4"]
    if len(content_type_values) != 1 or content_type_values[0][0] != 0x06:
        raise ValueError("invalid contentType signed attribute")
    if parse_oid(content_type_values[0][1]) != "2.23.136.1.1.1":
        raise ValueError("signed contentType is not id-icao-ldsSecurityObject")
    if len(digest_values) != 1 or digest_values[0][0] != 0x04:
        raise ValueError("invalid messageDigest signed attribute")
    content_digest = hashlib.sha256(content).digest()
    if digest_values[0][1] != content_digest:
        raise ValueError("signed messageDigest does not match content")
    signed_attributes_der = b"\x31" + encoded_length(len(signer[3][1])) + signer[3][1]
    signature_fields_tag, signature_fields_value, signature_end = tlv(signer[5][1], 0)
    if signature_fields_tag != 0x30 or signature_end != len(signer[5][1]):
        raise ValueError("ECDSA signature is not one DER SEQUENCE")
    signature_fields = children(signature_fields_value)
    if len(signature_fields) != 2 or [item[0] for item in signature_fields] != [0x02, 0x02]:
        raise ValueError("malformed ECDSA signature")
    r_value = parse_integer(signature_fields[0][1])
    s_value = parse_integer(signature_fields[1][1])
    curve = parse_explicit_ec_spki(certificate_der)
    order = curve["order"]
    if not (0 < r_value < order and 0 < s_value < order):
        raise ValueError("ECDSA signature scalar out of range")
    digest = hashlib.sha256(signed_attributes_der).digest()
    z_value = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - order.bit_length()
    if excess > 0:
        z_value >>= excess
    inverse = pow(s_value, -1, order)
    point = ec_add(
        ec_multiply((z_value * inverse) % order, curve["base"], curve["prime"], curve["a"]),
        ec_multiply((r_value * inverse) % order, curve["public"], curve["prime"], curve["a"]),
        curve["prime"],
        curve["a"],
    )
    valid = point is not None and point[0] % order == r_value
    return {
        "content_sha256": content_digest.hex(),
        "content_type": "2.23.136.1.1.1",
        "digest_algorithm": digest_algorithm,
        "duplicate_signed_attributes": False,
        "ec_cofactor": curve["cofactor"],
        "ec_field_bits": curve["prime"].bit_length(),
        "equivalent_named_curve": curve["equivalent_named_curve"],
        "message_digest_matches": True,
        "signer_identifier_matches_certificate": True,
        "signed_attribute_oids": sorted(attributes),
        "signed_attributes_sha256": digest.hex(),
        "signature_algorithm": signature_algorithm,
        "signature_valid": valid,
        "verifier": "pure-python DER + prime-field EC integer arithmetic",
    }


def parse_integer(raw: bytes) -> int:
    if not raw or raw[0] & 0x80:
        raise ValueError("negative or empty INTEGER")
    if len(raw) > 1 and raw[0] == 0 and raw[1] & 0x80 == 0:
        raise ValueError("non-minimal INTEGER")
    return int.from_bytes(raw, "big")


def parse_oid(raw: bytes) -> str:
    if not raw:
        raise ValueError("empty OID")
    first = raw[0]
    arcs = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    value = 0
    in_arc = False
    for byte in raw[1:]:
        if not in_arc and byte == 0x80:
            raise ValueError("non-minimal OID arc")
        value = (value << 7) | (byte & 0x7F)
        in_arc = True
        if byte & 0x80 == 0:
            arcs.append(value)
            value = 0
            in_arc = False
    if in_arc:
        raise ValueError("truncated OID arc")
    return ".".join(map(str, arcs))


def parse_lds_security_object(data: bytes) -> dict[str, Any]:
    tag, root, end = tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise ValueError("LDS Security Object is not one complete DER SEQUENCE")
    fields = children(root)
    if len(fields) < 3 or [item[0] for item in fields[:3]] != [0x02, 0x30, 0x30]:
        raise ValueError("unexpected LDS Security Object fields")
    version = parse_integer(fields[0][1])
    algorithm = children(fields[1][1])
    if not algorithm or algorithm[0][0] != 0x06:
        raise ValueError("missing LDS digest algorithm OID")
    digest_oid = parse_oid(algorithm[0][1])
    digest_name = {
        "1.3.14.3.2.26": "sha1",
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }.get(digest_oid)
    if digest_name is None:
        raise ValueError(f"unsupported LDS digest OID {digest_oid}")
    expected_width = hashlib.new(digest_name).digest_size
    hashes_by_dg: dict[int, str] = {}
    for entry_tag, entry_value in children(fields[2][1]):
        entry = children(entry_value) if entry_tag == 0x30 else []
        if len(entry) != 2 or entry[0][0] != 0x02 or entry[1][0] != 0x04:
            raise ValueError("malformed DataGroupHash entry")
        number = parse_integer(entry[0][1])
        digest = entry[1][1]
        if number not in range(1, 17) or number in hashes_by_dg:
            raise ValueError("invalid or duplicate DG number")
        if len(digest) != expected_width:
            raise ValueError("wrong DataGroupHash digest width")
        hashes_by_dg[number] = digest.hex()
    if len(fields) > 4:
        raise ValueError("unexpected trailing LDS Security Object fields")
    return {
        "der_complete": True,
        "digest_algorithm": digest_name,
        "digest_oid": digest_oid,
        "hashes": hashes_by_dg,
        "version": version,
        "version_info_present": len(fields) == 4,
    }


def parse_com(data: bytes) -> dict[str, Any]:
    tag, root, end = tlv(data, 0)
    if tag != 0x60 or end != len(data):
        raise ValueError("EF.COM is not one complete tag 60 object")
    fields = children(root)
    tag_list = next((value for field_tag, value in fields if field_tag == 0x5C), None)
    if tag_list is None:
        raise ValueError("EF.COM has no tag list")
    tags = []
    offset = 0
    while offset < len(tag_list):
        dg_tag, offset = read_tag(tag_list, offset)
        tags.append(dg_tag)
    unknown = [f"{item:X}" for item in tags if item not in DG_TAG_TO_NUMBER]
    if unknown:
        raise ValueError("EF.COM contains unknown DG tags: " + ", ".join(unknown))
    return {
        "der_complete": True,
        "dg_tags_hex": [f"{item:02X}" for item in tags],
        "data_groups": [DG_TAG_TO_NUMBER[item] for item in tags],
    }


def public_key_metadata(key: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "spki_sha256": sha256(
            key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    }
    if isinstance(key, rsa.RSAPublicKey):
        result.update(algorithm="RSA", bits=key.key_size)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        result.update(algorithm="EC", bits=key.key_size, curve=key.curve.name)
    elif isinstance(key, dsa.DSAPublicKey):
        result.update(algorithm="DSA", bits=key.key_size)
    elif isinstance(key, ed25519.Ed25519PublicKey):
        result.update(algorithm="Ed25519", bits=256)
    elif isinstance(key, ed448.Ed448PublicKey):
        result.update(algorithm="Ed448", bits=448)
    else:
        result.update(algorithm=type(key).__name__)
    return result


def certificate_public_key_metadata(cert: x509.Certificate) -> dict[str, Any]:
    try:
        return public_key_metadata(cert.public_key())
    except ValueError as exc:
        # cryptography intentionally rejects EC SubjectPublicKeyInfo values encoded with
        # explicit parameters. OpenSSL can still inspect and canonicalize the observed
        # public value, so retain that condition instead of losing the certificate report.
        der = cert.public_bytes(serialization.Encoding.DER)
        with tempfile.TemporaryDirectory(prefix="cedula-cert-") as temporary:
            certificate = Path(temporary) / "certificate.der"
            public_pem = Path(temporary) / "public.pem"
            public_der = Path(temporary) / "public.der"
            certificate.write_bytes(der)
            extract = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", str(certificate), "-pubkey", "-noout"],
                capture_output=True,
                check=False,
            )
            if extract.returncode != 0:
                raise ValueError("OpenSSL could not extract explicit-parameter SPKI") from exc
            public_pem.write_bytes(extract.stdout)
            convert = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(public_pem), "-outform", "DER", "-out", str(public_der)],
                capture_output=True,
                check=False,
            )
            details = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(public_pem), "-text_pub", "-noout"],
                capture_output=True,
                text=True,
                check=False,
            )
            if convert.returncode != 0 or details.returncode != 0:
                raise ValueError("OpenSSL could not decode explicit-parameter SPKI") from exc
            match = re.search(r"Public-Key:\s*\((\d+) bit\)", details.stdout)
            explicit = parse_explicit_ec_spki(der)
            return {
                "algorithm": "EC-explicit-parameters",
                "bits": int(match.group(1)) if match else None,
                "cryptography_error": str(exc),
                "equivalent_named_curve": explicit["equivalent_named_curve"],
                "openssl_text_sha256": sha256(details.stdout.encode()),
                "spki_sha256": sha256(public_der.read_bytes()),
            }


def extension_value(extension: x509.Extension[Any]) -> Any:
    value = extension.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        return value.digest.hex()
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return {
            "authority_cert_issuer": [str(item) for item in value.authority_cert_issuer or []],
            "authority_cert_serial_number": (
                format(value.authority_cert_serial_number, "X")
                if value.authority_cert_serial_number is not None
                else None
            ),
            "key_identifier": value.key_identifier.hex() if value.key_identifier else None,
        }
    if isinstance(value, x509.BasicConstraints):
        return {"ca": value.ca, "path_length": value.path_length}
    if isinstance(value, x509.KeyUsage):
        return {
            "content_commitment": value.content_commitment,
            "crl_sign": value.crl_sign,
            "data_encipherment": value.data_encipherment,
            "decipher_only": value.decipher_only if value.key_agreement else False,
            "digital_signature": value.digital_signature,
            "encipher_only": value.encipher_only if value.key_agreement else False,
            "key_agreement": value.key_agreement,
            "key_cert_sign": value.key_cert_sign,
            "key_encipherment": value.key_encipherment,
        }
    if isinstance(value, x509.ExtendedKeyUsage):
        return [item.dotted_string for item in value]
    if isinstance(value, x509.CertificatePolicies):
        return [item.policy_identifier.dotted_string for item in value]
    if isinstance(value, x509.CRLDistributionPoints):
        return [str(name) for point in value for name in (point.full_name or [])]
    if isinstance(value, x509.AuthorityInformationAccess):
        return [
            {"method": item.access_method.dotted_string, "location": str(item.access_location)}
            for item in value
        ]
    if isinstance(value, x509.SubjectAlternativeName):
        return [str(item) for item in value]
    if isinstance(value, x509.UnrecognizedExtension):
        if extension.oid.dotted_string == "2.5.29.16":
            tag, root, end = tlv(value.value, 0)
            if tag == 0x30 and end == len(value.value):
                parsed: dict[str, str] = {}
                for field_tag, field_value in children(root):
                    if field_tag in (0x80, 0x81):
                        moment = datetime.strptime(field_value.decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                        parsed["not_before" if field_tag == 0x80 else "not_after"] = moment.isoformat()
                if parsed:
                    return parsed
        if extension.oid.dotted_string == "2.23.136.1.1.6.2":
            tag, root, end = tlv(value.value, 0)
            if tag == 0x30 and end == len(value.value):
                fields = children(root)
                if len(fields) == 2 and fields[0][0] == 0x02 and fields[1][0] == 0x31:
                    document_types = [item[1].decode("ascii") for item in children(fields[1][1]) if item[0] == 0x13]
                    return {"extension": "icao_document_type_list", "version": parse_integer(fields[0][1]), "document_types": document_types}
        return {"raw_hex": value.value.hex()}
    return str(value)


def certificate_metadata(cert: x509.Certificate) -> dict[str, Any]:
    certificate_der = cert.public_bytes(serialization.Encoding.DER)
    cert_tag, cert_value, cert_end = tlv(certificate_der, 0)
    if cert_tag != 0x30 or cert_end != len(certificate_der):
        raise ValueError("certificate is not one complete DER SEQUENCE")
    certificate_fields = children(cert_value)
    outer_signature_algorithm = algorithm_identifier(certificate_fields[1][1])
    return {
        "authority_key_identifier": _aki(cert),
        "extensions": [
            {
                "critical": extension.critical,
                "name": extension.oid._name,
                "oid": extension.oid.dotted_string,
                "value": extension_value(extension),
            }
            for extension in cert.extensions
        ],
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "public_key": certificate_public_key_metadata(cert),
        "serial_hex": format(cert.serial_number, "X"),
        "sha1_fingerprint": cert.fingerprint(hashes.SHA1()).hex(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_algorithm_identifier": outer_signature_algorithm,
        "signature_hash_algorithm": (
            cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        ),
        "subject": cert.subject.rfc4514_string(),
        "subject_key_identifier": _ski(cert),
        "version": cert.version.name,
    }


def _ski(cert: x509.Certificate) -> str | None:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
    except x509.ExtensionNotFound:
        return None


def _aki(cert: x509.Certificate) -> str | None:
    try:
        value = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        return value.key_identifier.hex() if value.key_identifier else None
    except x509.ExtensionNotFound:
        return None


def load_certificates(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def load_crl(path: Path) -> x509.CertificateRevocationList:
    data = path.read_bytes()
    if b"-----BEGIN X509 CRL-----" in data:
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def certificate_verification_key(cert: x509.Certificate) -> Any:
    """Accept the observed explicit EC encoding only after exact known-domain matching."""
    try:
        return cert.public_key()
    except ValueError:
        explicit = parse_explicit_ec_spki(cert.public_bytes(serialization.Encoding.DER))
        if explicit["equivalent_named_curve"] != "brainpoolP256r1":
            raise ValueError("unsupported explicit EC domain; no certificate checks disabled")
        x, y = explicit["public"]
        return ec.EllipticCurvePublicNumbers(x, y, ec.BrainpoolP256R1()).public_key()


def unsupported_critical_extensions(value: Any, *, crl: bool = False) -> list[str]:
    """The direct-issuer profile must fail closed on extension semantics it does not implement.

    In particular, recognizing an extension's ASN.1 type is not enforcement of
    name constraints, certificate policies, EKU or policy constraints.
    """
    supported = ({"2.5.29.35", "2.5.29.20"} if crl else
                 {"2.5.29.19", "2.5.29.15", "2.5.29.14", "2.5.29.35"})
    unknown = [e.oid.dotted_string for e in value.extensions if e.critical and e.oid.dotted_string not in supported]
    if crl:
        for entry in value:
            unknown.extend("entry:" + e.oid.dotted_string for e in entry.extensions if e.critical)
    return sorted(set(unknown))


def verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> tuple[bool, str]:
    unsupported = sorted(set(unsupported_critical_extensions(cert) + unsupported_critical_extensions(issuer)))
    if unsupported:
        return False, "unsupported_critical_extensions:" + ",".join(unsupported)
    if cert.issuer != issuer.subject:
        return False, "issuer_subject_mismatch"
    aki, ski = _aki(cert), _ski(issuer)
    if aki and ski and aki != ski:
        return False, "aki_ski_mismatch"
    try:
        key = certificate_verification_key(issuer)
        if isinstance(key, rsa.RSAPublicKey):
            parameters = cert.signature_algorithm_parameters
            chosen_padding = parameters if isinstance(parameters, padding.AsymmetricPadding) else padding.PKCS1v15()
            key.verify(cert.signature, cert.tbs_certificate_bytes, chosen_padding, cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False, "unsupported_issuer_key"
    except Exception as exc:  # cryptography exposes backend-specific InvalidSignature subclasses
        return False, f"signature_invalid:{type(exc).__name__}"
    return True, "valid"


def authority_constraints(cert: x509.Certificate, *, for_crl: bool = False) -> tuple[bool, str]:
    """Check the role of a configured direct issuer; this does not authenticate its provenance."""
    unsupported = unsupported_critical_extensions(cert)
    if unsupported:
        return False, "unsupported_critical_extensions:" + ",".join(unsupported)
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False, "missing_ca_basic_constraints"
    if not constraints.ca:
        return False, "issuer_is_not_ca"
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return False, "missing_ca_key_usage"
    if not usage.key_cert_sign:
        return False, "issuer_lacks_keyCertSign"
    if for_crl and not usage.crl_sign:
        return False, "issuer_lacks_cRLSign"
    return True, "valid"


def crl_freshness_at(crl: x509.CertificateRevocationList, moment: datetime) -> str:
    if moment < crl.last_update_utc:
        return "not_yet_effective"
    if crl.next_update_utc is None:
        return "missing_next_update"
    if moment >= crl.next_update_utc:
        return "expired"
    return "current"


def verify_crl_signature(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> bool:
    if unsupported_critical_extensions(crl, crl=True) or unsupported_critical_extensions(issuer):
        return False
    try:
        key = certificate_verification_key(issuer)
        if isinstance(key, rsa.RSAPublicKey):
            parameters = crl.signature_algorithm_parameters
            chosen_padding = parameters if isinstance(parameters, padding.AsymmetricPadding) else padding.PKCS1v15()
            key.verify(crl.signature, crl.tbs_certlist_bytes, chosen_padding, crl.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(crl.signature, crl.tbs_certlist_bytes, crl.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(crl.signature, crl.tbs_certlist_bytes)
        else:
            return False
    except Exception:
        return False
    return True


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validity_at(cert: x509.Certificate, moment: datetime) -> str:
    if moment < cert.not_valid_before_utc:
        return "not_yet_valid"
    if moment > cert.not_valid_after_utc:
        return "expired"
    return "valid"


def private_key_usage_period(cert: x509.Certificate) -> tuple[datetime | None, datetime | None]:
    try:
        extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("2.5.29.16"))
    except x509.ExtensionNotFound:
        return None, None
    parsed = extension_value(extension)
    if not isinstance(parsed, dict):
        return None, None
    return (
        datetime.fromisoformat(parsed["not_before"]) if parsed.get("not_before") else None,
        datetime.fromisoformat(parsed["not_after"]) if parsed.get("not_after") else None,
    )


def interval_state(moment: datetime, start: datetime | None, end: datetime | None) -> str:
    if start is not None and moment < start:
        return "not_yet_valid"
    if end is not None and moment > end:
        return "expired"
    return "valid" if start is not None or end is not None else "not_present"


def verify_cms(cms_path: Path) -> tuple[bytes, dict[str, Any]]:
    cms = cms_path.read_bytes()
    if not complete_der(cms):
        raise ValueError("CMS input has trailing data or invalid DER")
    with tempfile.TemporaryDirectory(prefix="cedula-pa-") as temporary:
        output = Path(temporary) / "content.der"
        command = [
            "openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(cms_path),
            "-noverify", "-out", str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            raise ValueError("OpenSSL CMS signature verification failed: " + completed.stderr.strip())
        content = output.read_bytes()
        dump = subprocess.run(
            ["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", str(cms_path)],
            capture_output=True,
            check=False,
        )
        if dump.returncode != 0:
            raise ValueError("OpenSSL CMS structural dump failed")
    certificates = pkcs7.load_der_pkcs7_certificates(cms)
    return content, {
        "cms_bytes": len(cms),
        "cms_der_complete": True,
        "cms_sha256": sha256(cms),
        "embedded_certificate_count": len(certificates),
        "openssl_dump_sha256": sha256(dump.stdout),
        "openssl_stderr": completed.stderr.strip(),
        "signature_valid": True,
        "verified_content_bytes": len(content),
        "verified_content_sha256": sha256(content),
    }


def parse_dg_argument(value: str) -> tuple[int, Path]:
    number, separator, path = value.partition("=")
    if not separator or not number.isdigit() or int(number) not in range(1, 17) or not path:
        raise argparse.ArgumentTypeError("expected DG_NUMBER=PATH")
    return int(number), Path(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cms", required=True, type=Path, help="EF.SOD tag 77 value (CMS DER)")
    parser.add_argument("--com", required=True, type=Path, help="complete EF.COM object")
    parser.add_argument("--dg", action="append", default=[], type=parse_dg_argument)
    parser.add_argument("--trust-anchor", action="append", default=[], type=Path)
    parser.add_argument("--crl", action="append", default=[], type=Path)
    parser.add_argument("--validation-time", action="append", default=[])
    parser.add_argument("--require-dg", action="append", default=[], type=int, choices=range(1, 17),
                        help="DG that must be acquired and valid for this relying-party policy; repeatable")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    content, cms_report = verify_cms(args.cms)
    lds = parse_lds_security_object(content)
    com = parse_com(args.com.read_bytes())
    embedded = pkcs7.load_der_pkcs7_certificates(args.cms.read_bytes())
    if len(embedded) != 1:
        raise ValueError(f"expected exactly one embedded Document Signer certificate, got {len(embedded)}")
    document_signer = embedded[0]
    cms_report["independent_verification"] = independent_cms_ecdsa_verify(
        args.cms.read_bytes(), document_signer.public_bytes(serialization.Encoding.DER)
    )
    digest_name = lds["digest_algorithm"]

    supplied: dict[int, Path] = {}
    for number, path in args.dg:
        if number in supplied:
            raise ValueError(f"duplicate DG{number} input")
        supplied[number] = path
    unexpected = sorted(set(supplied) - set(lds["hashes"]))
    if unexpected:
        raise ValueError("supplied unsigned DGs: " + ", ".join(map(str, unexpected)))
    rows = []
    for number in sorted(lds["hashes"]):
        if number not in supplied:
            rows.append({"dg": number, "state": "signed_not_acquired"})
            continue
        raw = supplied[number].read_bytes()
        actual = hashlib.new(digest_name, raw).hexdigest()
        rows.append({
            "actual_digest": actual,
            "bytes": len(raw),
            "der_complete": complete_der(raw),
            "dg": number,
            "expected_digest": lds["hashes"][number],
            "path": str(supplied[number]),
            "sha256": sha256(raw),
            "state": "match" if actual == lds["hashes"][number] else "mismatch",
        })

    times = [parse_time(item) for item in args.validation_time] or [datetime.now(timezone.utc)]
    key_use_start, key_use_end = private_key_usage_period(document_signer)
    time_report = {
        moment.isoformat(): {
            "certificate_validity": validity_at(document_signer, moment),
            "private_key_usage_period": interval_state(moment, key_use_start, key_use_end),
        }
        for moment in times
    }
    certificate_time_valid = all(validity_at(document_signer, moment) == "valid" for moment in times)

    trust_candidates = []
    trusted_anchor: x509.Certificate | None = None
    for path in args.trust_anchor:
        for candidate in load_certificates(path):
            valid, reason = verify_signed_by(document_signer, candidate)
            role_valid, role_reason = authority_constraints(candidate)
            candidate_validity = {moment.isoformat(): validity_at(candidate, moment) for moment in times}
            candidate_time_valid = all(state == "valid" for state in candidate_validity.values())
            eligible = valid and role_valid and candidate_time_valid
            record = {
                "path": str(path),
                "subject": candidate.subject.rfc4514_string(),
                "sha256_fingerprint": candidate.fingerprint(hashes.SHA256()).hex(),
                "document_signer_signature": reason,
                "signature_matches": valid,
                "authority_constraints": role_reason,
                "certificate_validity": candidate_validity,
                "matches": eligible,
                "trust_basis": "explicitly_configured; provenance_not_authenticated_by_this_tool",
            }
            trust_candidates.append(record)
            if eligible and trusted_anchor is None:
                trusted_anchor = candidate

    crl_rows = []
    revoked = False
    usable_crl = False
    for path in args.crl:
        crl = load_crl(path)
        row: dict[str, Any] = {
            "issuer": crl.issuer.rfc4514_string(),
            "last_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
            "path": str(path),
            "sha256": sha256(path.read_bytes()),
            "freshness": {moment.isoformat(): crl_freshness_at(crl, moment) for moment in times},
            "unsupported_critical_extensions": unsupported_critical_extensions(crl, crl=True),
        }
        if trusted_anchor and crl.issuer == trusted_anchor.subject:
            row["signature_valid"] = verify_crl_signature(crl, trusted_anchor)
            role_valid, role_reason = authority_constraints(trusted_anchor, for_crl=True)
            row["authority_constraints"] = role_reason
            try:
                crl_aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            except x509.ExtensionNotFound:
                crl_aki = None
            anchor_ski = _ski(trusted_anchor)
            row["key_identifier_matches"] = not (crl_aki and anchor_ski and crl_aki.hex() != anchor_ski)
            unsupported_scope = any(isinstance(extension.value, (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint))
                                    for extension in crl.extensions)
            row["full_issuer_crl"] = not unsupported_scope
            current = all(state == "current" for state in row["freshness"].values())
            row["usable"] = (row["signature_valid"] and role_valid and row["key_identifier_matches"]
                             and row["full_issuer_crl"] and current)
            entry = crl.get_revoked_certificate_by_serial_number(document_signer.serial_number)
            row["document_signer_revoked"] = (
                any(entry.revocation_date_utc <= moment for moment in times) if row["usable"] and entry else
                False if row["usable"] else None)
            usable_crl = usable_crl or row["usable"]
            revoked = revoked or row["document_signer_revoked"] is True
        else:
            row["signature_valid"] = None
            row["document_signer_revoked"] = None
            row["usable"] = False
        crl_rows.append(row)

    integrity_valid = cms_report["signature_valid"] and all(
        row["state"] != "mismatch" for row in rows
    )
    inventory_matches = sorted(com["data_groups"]) == sorted(lds["hashes"])
    required_dgs = sorted(set(args.require_dg))
    missing_required = sorted(set(required_dgs) - {row["dg"] for row in rows if row["state"] == "match"})
    missing_acquired = [row["dg"] for row in rows if row["state"] == "signed_not_acquired"]
    chain_state = "trusted" if trusted_anchor else "unresolved"
    if revoked:
        revocation_state = "revoked"
    elif usable_crl:
        revocation_state = "good"
    else:
        revocation_state = "unknown"
    if not integrity_valid or not inventory_matches or missing_required:
        overall = "invalid"
    elif chain_state == "trusted" and revocation_state == "good" and certificate_time_valid:
        overall = "externally_trusted_partial" if missing_acquired else "externally_trusted"
    else:
        overall = "internally_valid_external_trust_unresolved"

    report = {
        "certificate": certificate_metadata(document_signer),
        "certificate_validity": time_report,
        "cms": cms_report,
        "crls": crl_rows,
        "data_groups": rows,
        "ef_com": com,
        "final": {
            "acquired_dg_hashes_valid": all(row["state"] != "mismatch" for row in rows),
            "chain": chain_state,
            "ef_com_sod_inventory_match": inventory_matches,
            "integrity": "valid" if integrity_valid else "invalid",
            "overall": overall,
            "revocation": revocation_state,
            "signed_not_acquired": missing_acquired,
            "certificate_time_policy_passed": certificate_time_valid,
            "required_dgs": required_dgs,
            "missing_required_dgs": missing_required,
            "acquisition_complete": not missing_acquired,
            "trust_basis": "explicitly_configured_anchor; provenance_not_authenticated_by_this_tool",
        },
        "validation_policy": {
            "certificate_time": "DS and configured issuer must be valid at every requested time; default is now",
            "historical_documents": "No implicit historical issuance-time exception; select an appropriate validation time explicitly",
            "private_key_usage_period": "Reported for signing-policy analysis; not treated as a read-time certificate lifetime",
            "revocation": "Signed, current full issuer CRL with matching key identifier and cRLSign role required",
            "partial_acquisition": "Explicitly qualified; --require-dg enforces relying-party required inputs",
        },
        "lds_security_object": lds,
        "schema": "cedula-passive-authentication/v2",
        "trust_candidates": trust_candidates,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_output:
        args.json_output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if integrity_valid and inventory_matches and not revoked and certificate_time_valid and not missing_required else 1


if __name__ == "__main__":
    raise SystemExit(main())
