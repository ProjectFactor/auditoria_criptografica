<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Result of the discovery of the JCE CSCA trust anchor

## Scope and security boundary

This document records the offline analysis of the JCE Document Signer trust anchor embedded in
a card's EF.SOD. It used stored card evidence and locally downloaded ICAO PKD collections. It performed no PC/SC connection, card command, credential access,
change to the system trust store, direct request, or contact with personnel.

## Required JCE trust anchor

The embedded signer `exports/certificates/jce-ds-02.pem` requires an issuer with this identity and
key identifier:

| Field | Value |
|---|---|
| DS subject | `C=DO, O=Junta Central Electoral - JCE, OU=DOM, CN=JCE DS 02` |
| DS issuer | `C=DO, O=Junta Central Electoral - JCE, CN=JCE CSCA` |
| DS serial | `199686BB721AD7689CB5` |
| Required CSCA SKI / DS AKI | `e8090eb7d5c71ffe568f0654a4675af5ea264bb8` |
| CSCA URI included in the DS | `https://ca.jce.gob.do/csca` |
| CRL distribution point | `https://ca.jce.gob.do/crl_csca` |
| DS SHA-256 | `1412267945fdd2d6d196bcc49acff007dd91f61de761b8ab7e0e16bcf327dfb5` |

Matching only the country or the issuer name is insufficient. A candidate must match the DS AKI
and verify the signature of the DS certificate.

## Reachability of the anchor and the CRL host

Both the CSCA URI and the CRL distribution point above resolve to the same host,
`ca.jce.gob.do`. A DNS query for that host returns **NXDOMAIN** (nonexistent domain): it is not
simply down or slow; the name does not resolve at all. This was verified repeatedly during this
investigation and reconfirmed with a fresh live DNS query at the time of publication,
with the same NXDOMAIN result. A verifier that
depends on fetching the CSCA or its CRL from this published location cannot do so, and cannot
distinguish that failure from a transient outage without independently knowing the correct anchor
by other means.

## ICAO inputs and integrity

The complete LDIF collections match the SHA-1 sums displayed by ICAO:

| Local input | SHA-1 | SHA-256 |
|---|---|---|
| `icaopkd-001-complete-10293.ldif` | `872256130cdacaf97216fd2aa4fb8876bbe7fa3a` | `af79c202e0b4ce903847a27b67e6a6fc68e243d27ef983c29e392663783f7b67` |
| `icaopkd-002-complete-527.ldif` | `9868cf6f42acb7e79da3a75faf82b81487e9c487` | `91e73a516942f4537000f86dca965ca7a1fa1ecaf452c9d57ac524876bccdeb0` |

Neither LDIF has a `c=DO` entry. The accompanying Master List CMS,
`ICAO_ML_20260721154956.ml`, has SHA-256
`412bdd0c0fe1a06bcbe65c18f4f6429ab1ac52f63907bff5e47e572895bc9b94`.
`openssl cms -verify -binary -inform DER -noverify` validates the integrity of its CMS with its embedded
signer and extracts the eContent with SHA-256
`f2921558ed1ccceffeb47c0f38eb623f4ff8acb530fdd975d433fb336aa947a9`.
The `-noverify` result does not establish external trust in the Master List signer.

## Dominican certificate found

The 581-certificate Master List contains exactly one certificate with subject country `DO`:

| Field | Value |
|---|---|
| Subject and issuer | `CN=CSCA, OU=Certification Authorities, OU=Passport Emitting Entity, O=Government of Dominican Republic, C=DO` |
| Serial | `529B3550C387DDE9E986FFC146DE106A` |
| Validity | 2025-11-05 18:33:37Z to 2041-06-05 19:03:37Z |
| SKI / AKI | `d0d9f1ad5648a4fb141d24c9f7b77ae72176f033` |
| Certificate SHA-256 | `74237c758a8f894a9a2932fb370da669563647483dfd2616c5332a4f4671e25d` |
| Public SPKI SHA-256 | `31701ebdcac1c18bfe5d6f49925858d70ba25332529349fb93bc1ceb666579c5` |

It is exported as `exports/certificates/dominican-republic-icao-masterlist-csca.pem`; the complete
machine-readable metadata is in `evidence/ICAO_MASTER_LIST_DO.json`.

This is not the required JCE CSCA: its organization, organizational units, and subject differ, and its
SKI `d0d9...f033` does not match the JCE DS AKI `e809...4bb8`. Therefore, strict
chain verification with OpenSSL fails with `unable to get local issuer certificate`.

## Passive authentication conclusion

The evidence supports three distinct results:

1. The EF.SOD CMS signature is mathematically valid with its embedded JCE DS public key.
2. The seven acquired LDS data groups match the hashes signed in EF.SOD.
3. External trust and revocation remain unestablished: the available ICAO Dominican CSCA
   is a different authority, and no certificate with the required JCE CSCA SKI is in these
   inputs.

The correct status is: **signature and acquired DG hashes valid; JCE CSCA chain and revocation
not established**. The Master List result is a strict candidate mismatch, not
proof that the JCE CSCA does not exist elsewhere.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
