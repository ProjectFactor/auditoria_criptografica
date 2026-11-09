<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Passive authentication analysis

Scope: stored bytes only; no PC/SC, card commands, PIN/CAN operations, OCSP requests, or serial-number-specific network queries.

## Result

The stored EF.SOD is internally valid. OpenSSL and an independent strict local verifier both validate
the CMS signature. The latter parses the DER itself and checks ECDSA with prime-field integer
arithmetic. EF.COM and the LDS Security Object name the same data groups: `1, 2, 3, 7, 11, 12,
13, 14`. Each acquired signed object (`1, 2, 7, 11, 12, 13, 14`) has a hash exactly equal to its
digest in EF.SOD. DG3 remains signed but was not acquired because its access boundary was not crossed.

This demonstrates integrity and possession of the signer key for the stored card image, but not
external trust. The embedded `JCE DS 02` certificate still cannot be chained to an authenticated
`JCE CSCA`, and there is no applicable CRL. Therefore, the correct fail-closed status is:

`internally_valid_external_trust_unresolved`

Machine-readable evidence: `lab/PASSIVE_AUTHENTICATION_REPORT.json`.

## Document Signer certificate

| Field | Exact result |
|---|---|
| Subject | `CN=JCE DS 02,OU=DOM,O=Junta Central Electoral - JCE,C=DO` |
| Issuer | `CN=JCE CSCA,O=Junta Central Electoral - JCE,C=DO` |
| Serial | `199686BB721AD7689CB5` |
| SHA-256 fingerprint | `1412267945fdd2d6d196bcc49acff007dd91f61de761b8ab7e0e16bcf327dfb5` |
| SKI | `f4047b2a821fea2b8c537f474a274f2a97d0460f` |
| AKI | `e8090eb7d5c71ffe568f0654a4675af5ea264bb8` |
| Certificate validity | 2026-04-17 20:35:41Z to 2036-08-17 20:35:41Z |
| Private key usage period | 2026-04-17 20:35:41Z to 2026-08-17 20:35:41Z |
| Key | EC with explicit parameters; the exact parameters are equivalent to `brainpoolP256r1` |
| SPKI SHA-256 | `1668370ca5f4a0625159d5334d8202b7b27d4220e4139eb02a4d22c8043beef3` |
| Key usage | `digitalSignature` only, critical |
| ICAO document type list | version 0; type `I` (identity card) |
| Certificate signature | ECDSA with SHA-384; the AlgorithmIdentifier has invalid `NULL` parameters |
| EF.SOD signature | ECDSA with SHA-256; the AlgorithmIdentifier has invalid `NULL` parameters |

The earlier abbreviation `P-256` in the repository was ambiguous and erroneous if read as NIST P-256. The
exact explicit values match BrainpoolP256r1 and the relevant summaries have been corrected.

DG12 contains the issuer `JUNTA CENTRAL ELECTORAL` and the issue date `20260712`. That date falls within
both the certificate validity interval and the private key usage period. At the time of analysis
the certificate is still valid, while the usage period of its signing key has ended. This does not
invalidate a document demonstrably produced during the permitted signing interval.

## CMS and data group checks

- EF.SOD CMS SHA-256: `ea789c1c53bc58a1aff07d2aa83d2e45410768bc94a7b496c13f49f3ab906dcf`.
- SHA-256 of the signed LDS Security Object: `bbbb3c7af8e6565951dadbcff579fef998053ccf396531da80e473332ff08fa9`.
- The signed attributes are exactly `contentType` and `messageDigest`; there is no `signingTime`.
- The signed `messageDigest` matches the encapsulated content.
- The seven acquired DG digests match byte for byte.
- The DG3 digest is present in the signed object, but no DG3 bytes were supplied to the verifier.

## Update on external trust

The most recent stored ICAO PKD bulk objects are the complete version `10293` and
version `527` of the CSCA Master List. The official public status page consulted during the analysis
reports those same versions. The separately published Master List page reports an issuance
of 15 July 2026 and 579 certificates; the set extracted from the stored signed file has 581
certificate objects. The two figures are recorded as a discrepancy between the public page and the
file, without assuming its cause.

There is only one `C=DO` CSCA in that stored Master List. It is the Dominican passport CSCA with SHA-256
`74237c758a8f894a9a2932fb370da669563647483dfd2616c5332a4f4671e25d` and SKI
`d0d9f1ad5648a4fb141d24c9f7b77ae72176f033`. It does not match `JCE DS 02` by issuer DN or by
AKI/SKI and cannot substitute for it.

The DS certificate publishes `https://ca.jce.gob.do/csca` and `https://ca.jce.gob.do/crl_csca`. Full-object
GETs were attempted, but no HTTP connection was possible. A stored Google DNS-over-HTTPS A query
returned status 3 (NXDOMAIN) with the authoritative SOA of `jce.gob.do`. Consequently,
chain and revocation remain unresolved, neither failed nor good. The exact public responses and the
transfer metadata are in `downloads/passive_auth/`.

## Reproduction

```sh
python3 tools/icao/verify_passive_auth.py \
  --cms logs/sessions/session_TEST-01_EF_SOD_FULL/artifacts/assembled_der_001.tag77-value.der \
  --com logs/sessions/session_TEST-01_EF_COM_FULL/artifacts/decrypted_response_002.bin \
  --dg 1=logs/sessions/session_TEST-01_DG1_FULL/artifacts/assembled_der_001.bin \
  --dg 2=logs/sessions/session_TEST-01_DG2_FULL/artifacts/assembled_der_001.bin \
  --dg 7=logs/sessions/session_TEST-01_DG7_FULL/artifacts/assembled_der_001.bin \
  --dg 11=logs/sessions/session_TEST-01_DG11_FULL/artifacts/assembled_der_001.bin \
  --dg 12=logs/sessions/session_TEST-01_DG12_FULL/artifacts/assembled_der_001.bin \
  --dg 13=logs/sessions/session_TEST-01_DG13_FULL/artifacts/assembled_der_001.bin \
  --dg 14=logs/sessions/session_TEST-01_DG14_FULL/artifacts/assembled_der_001.bin \
  --trust-anchor exports/certificates/dominican-republic-icao-masterlist-csca.pem \
  --validation-time 2026-07-12T00:00:00Z \
  --validation-time 2026-08-17T20:35:41Z \
  --json-output lab/PASSIVE_AUTHENTICATION_REPORT.json
```

Exit code: `0`. The exact diagnostic stream is stored in
`lab/PASSIVE_AUTHENTICATION_VERIFIER.stderr.txt`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
