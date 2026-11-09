<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Offline signature analysis of EF.CardSecurity

This analysis uses only the stored 1,225-byte object. It does not establish or exercise a session with the
card.

OpenSSL and an independent local DER/RSA modular-arithmetic verifier both validate the embedded CMS
signature and its `messageDigest`. The 22-byte signed content matches EF.CardAccess exactly:

- content type `0.4.0.127.0.7.3.2.1`;
- `id-PACE-ECDH-GM-AES-CBC-CMAC-256`;
- version 2;
- standardized domain parameter identifier 15.

The content is a declaration of capabilities, not a card key or personal data.

The embedded signer is `CN=DS,OU=development,O=cryptovision,C=DE`, issued by the unsupplied
`CN=CSCA,OU=development,O=cryptovision,C=DE`. It uses RSA-1024, has the certificate fingerprint
`4eb27936eeee488c8409044d8db3ff22210155443b89db7e4b21aee2f95704e2`, and its CMS signing time
is 2026-02-04 11:44:47Z. The signature is mathematically valid, but its chain is unresolved and the
development label makes it unsuitable as an external production trust anchor.

This is a different trust domain from EF.SOD. The Cryptovision development CSCA cannot validate
`JCE DS 02`, and it cannot be assumed that the JCE/ICAO CSCA validates EF.CardSecurity.

Machine-readable evidence: `lab/CARDSECURITY_PASSIVE_AUTH_REPORT.json`.

Reproduction:

```sh
python3 tools/icao/analyze_cardsecurity.py \
  logs/sessions/session_TEST-01_CARDSECURITY_FULL/artifacts/assembled_der_001.bin \
  --json-output lab/CARDSECURITY_PASSIVE_AUTH_REPORT.json
```

Exit code: `0`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
