<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Evidence

This directory contains only the technical evidence that directly supports the three findings in
[`../FINDINGS_EN.md`](../FINDINGS_EN.md). It intentionally does not include the discovery process,
the reverse-engineering notes, or the exploratory research that led to these findings; only the
results that support them.

## Finding 1 — "Development" RSA-1024 Document Signer in `EF.CardSecurity`

- [`CARDSECURITY_PASSIVE_AUTH_ANALYSIS_EN.md`](CARDSECURITY_PASSIVE_AUTH_ANALYSIS_EN.md) /
  [`CARDSECURITY_PASSIVE_AUTH_REPORT.json`](CARDSECURITY_PASSIVE_AUTH_REPORT.json) — the verification
  of the `EF.CardSecurity` signature: the embedded `cryptovision/development` RSA-1024 Document Signer
  certificate and the validity of its signature.

## Finding 2 — JCE CSCA trust gap

- [`CSCA_TRUST_DISCOVERY_EN.md`](CSCA_TRUST_DISCOVERY_EN.md) — the JCE Document Signer chain
  up to its declared CSCA, and why the published URI of that CSCA does not resolve.
- [`ICAO_MASTER_LIST_DO.json`](ICAO_MASTER_LIST_DO.json) — the Dominican Republic entry in the
  public ICAO Master List, used to confirm that the only CSCA available in that
  public list is the passport CSCA, not the cédula CSCA.
- [`TRUST_DOMAIN_SEPARATION_EN.md`](TRUST_DOMAIN_SEPARATION_EN.md) — a concise table separating which signer
  covers each signed object and which trust anchor each requires; it is the basis for not confusing the
  trust domains of `EF.SOD` (JCE DS) and `EF.CardSecurity` (development DS).

## Finding 3 — Identity integrity holds (on the cards examined in this detail)

- [`PASSIVE_AUTHENTICATION_RESULT_EN.md`](PASSIVE_AUTHENTICATION_RESULT_EN.md) — the complete table of
  per-data-group hash reconciliation against the signed `EF.SOD` (7/7 acquired data groups
  match; DG3 correctly excluded as not acquired).
- [`PASSIVE_AUTHENTICATION_ANALYSIS_EN.md`](PASSIVE_AUTHENTICATION_ANALYSIS_EN.md) /
  [`PASSIVE_AUTHENTICATION_REPORT.json`](PASSIVE_AUTHENTICATION_REPORT.json) — the independent
  verification of the CMS/ECDSA signature of `EF.SOD` that underpins that reconciliation.
- [`SOD_DG_RECONCILIATION.json`](SOD_DG_RECONCILIATION.json) — the machine-readable form of the same
  reconciliation, reproducible with `tools/icao/verify_passive_auth.py`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
