<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/factor-landscape-reverse.svg"><img src="docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Reproducing these findings

The findings in this repository were produced with the tools in [`tools/active_adaptive/`](tools/active_adaptive/)
and [`tools/icao/verify_passive_auth.py`](tools/icao/verify_passive_auth.py), run against a
contactless cédula through a PC/SC reader. Everything is read-only or non-destructively reversible,
unless otherwise stated.

## Before you begin

- **Run this only against a card that you lawfully own and are authorized to test**, and ideally
  first on a card that you own and are authorized to test, never on a third party's cédula.
- All tools default to a **dry run**: they print the exact APDU plan without touching the card
  or any credentials. Nothing touches the card until `--execute` is passed.
- Credentials (CAN, PIN) are entered via stdin at runtime, kept only in memory, and cleared
  after use. They are never written to argv, logs, or versioned files; do not change that
  when adapting these scripts.
- The evidence this kit writes (raw DER, session traces, decoded personal data) goes to
  `objects/`, `sessions/`, and `live_data/`, which must be kept unversioned and private. If you fork this
  repository and continue the research: no citizen data, images, or credentials may be in a shared
  or public copy; maintain that rule even where the scripts themselves do not enforce it.

## Required hardware and software

- A PC/SC-compatible contactless reader (ISO 14443 / ISO 7816).
- Python 3.9+, `pyscard` (PC/SC bindings), and the cryptographic library that `pace_sm.py` imports
  (see its own header for the exact dependency; it implements PACE/SM from scratch rather than
  depending on a vendor driver, precisely so that it can issue APDUs a conforming client would never send).
- `active_adaptive/npa-ca-v1-generic.inc` + `build-chip-auth-generic.sh` to build a card-independent
  Chip Authentication helper (it pins its own OpenSC checkout; treat the checkout directory as untrusted,
  as the script's own header indicates).

## Running the tiers, in order

The full order, the rationale ("why negative tests establish the absence of errors better than
positive ones"), and the per-card evidence storage layout (`objects/<uid>/`, `sessions/<uid>/<ts>_<label>/`,
indexed by the card's ISO14443 UID) are in
[`tools/active_adaptive/VALIDATION_PLAN_EN.md`](tools/active_adaptive/VALIDATION_PLAN_EN.md). Summary:

| Tier | Script | What it verifies | Card contact |
|---|---|---|---|
| 0 | `tier0_csca.py`, `tier0_tamper.py` | CSCA chain/revocation logic; offline tamper detection on cached objects | None |
| 1 | `tier1_readonly.py` | PACE reproducibility; PIN status queries that modify nothing | Read-only, no credentials sent |
| 2 | `tier2_negative.py` | Fail-closed checks: writes, DG3 without EAC, and other operations the card must reject | Negative probes only, no credentials, no counters touched |
| 2 (SM) | `tier2_sm_tamper.py` + `pace_sm.py` | Rejection of SM MAC tampering and rejection of PACE algorithm downgrade, from a PACE+SM stack built from scratch | Deliberately malformed APDUs; no counters touched |
| 3 | `tier3_authenticated.py` | VERIFY with a PIN that you legitimately own; confirms a transient-only state change | Requires your own CAN + PIN via stdin |

Typical invocation pattern (always a dry run first):

```bash
cd tools/active_adaptive
python3 tier1_readonly.py                               # prints the plan, touches nothing
printf '<your CAN>' | python3 tier1_readonly.py --can-stdin --execute
```

Chip Authentication / card fingerprint and SOD reconciliation:

```bash
python3 chip_auth_prove.py ...        # proves possession of the DG14 CA private key
python3 reconcile_sod.py --can-stdin --execute   # SHA-256-reconciles every readable DG against EF.SOD
python3 card_registry.py --current    # record this card's UID + crypto fingerprint (non-PII)
```

RNG/DRBG assurance battery (used for the randomness results related to the findings):

```bash
cd tools/active_adaptive/assurance
python3 collect_rng_n.py ...
python3 rng_battery.py ...
python3 entropy_study.py ...
```

## Independent passive authentication verification

[`tools/icao/verify_passive_auth.py`](tools/icao/verify_passive_auth.py) is an independent verifier of
passive authentication per ICAO Doc 9303: given `EF.SOD` and the data groups it covers, it re-derives and checks
independently the hashes of each DG and the CMS signature of the SOD, without relying on any of the session-management code in
`active_adaptive/`. Use it to cross-check any PASS/FAIL claim in the reports against raw DER objects
that you capture yourself.

## Reports

The reports in [`report/`](report/) are published as final PDF documents. No typesetting source
code for them is included or maintained in this repository.

## What you should NOT be able to reproduce from this repository alone

By design, none of the following can be reconstructed from what is published here:
citizen identity data, portraits, signatures, the PIN/CAN/PUK of any specific card, or any private
key. If you discover that you *can* reconstruct any of them from the published material,
that is itself a finding: report it rather than publishing it further.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
