<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../../docs/brand/factor-landscape-reverse.svg"><img src="../../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Cédula security-compliance validation plan

Scope: validate that the card's security measures are **upheld** and that there are no
access-control or integrity errors, ordered from least to most intrusive. It covers the cards examined, including an
independent production cédula (reserved UID). The findings describe
only the cards observed and are not generalized to the issued population.

> **Why negative tests.** A card that *accepts* a valid session proves nothing about whether it
> *would reject* a forged one. "No errors / measures upheld" is established primarily through
> negative tests: confirming that locks fail safe (`6982`/`69xx`) and that integrity
> checks actually reject tampered inputs. Those are the cheapest and most important
> checks, and they are found in Tiers 0–2.

Legend: ✅ already done · 🆕 new here · 🔒 requires JCE cooperation.
Every live tool runs by default as a **dry run** (it prints the exact APDU plan; no access to the card or credentials) and
performs the session only with `--execute`. The CAN (and, in Tier 3, the PIN) is read from stdin,
kept in memory, cleared after use, and hidden from every stored trace.

### Evidence organization (per card, by UID)
The DomIDv1 ATR is identical across cards, so the old `atr[-8:]` key collided and overwrote evidence.
Each card is now identified by its **ISO14443 UID** (`FF CA 00 00 00`, read before any PACE step):

```
objects/<uid>/<name>.der          raw DERs (cardsecurity, dg1, p15_4400, b14_011C, ...)
objects/_registry.json            per-card fingerprint registry (card_registry.py)
sessions/<uid>/<ts>_<label>/      traces, profiles, JSON per run
```

Cards examined: production (reserved UID). (The CANs are entered via stdin at
runtime and deliberately not stored in this versioned file.)
`card_registry.py` records each card's chip-authentication SPKI, EF.CardSecurity + DS, and the SOD DS, so that
cards can be told apart and the RSA-1024 development DS pattern tabulated. If the UID read fails, the key
falls back to `atrunk_<atr8>` so that a capture is never silently filed under another card.

---

## Tier 0 — Offline, no card contact (zero intrusion)
Tests whether the verification *logic* detects tampering. Implemented in `tier0_tamper.py`
(operates on DER cached in `objects/`, ignored by git; no card, no CAN).

| Test | What it validates | Pass |
|---|---|---|
| DG hash tampering 🆕 | Passive authentication is not a no-op | Change one byte of a DG → hash mismatch → the reconciliation **fails** |
| SOD signature tampering 🆕 | CMS signature verification is real | Mutate one byte of the signature → CMS verification **fails** |
| Passive authentication baseline ✅ | Positive integrity control | SOD CMS valid; all attested DGs reconcile (`reconcile_sod.py`) |
| CSCA chain + revocation 🆕🔒 | Issuer trust at Boundary 4 | DS → JCE cédula CSCA validates once the CSCA is obtained through an external channel |
| Algorithm strength review ✅ | Obsolete primitives | RSA-1024 Document Signer of development provenance flagged (`fingerprint.py`) |

## Tier 1 — Live, authenticated read; no state change, no counter use
Implemented in `tier1_readonly.py`. One or more CAN/PACE sessions; each APDU is a read or a
non-mutating status query. No VERIFY, no write, no retry consumption.

| Test | What it validates | Pass |
|---|---|---|
| PACE reproducibility 🆕 | Deterministic authenticated read | Re-reading public/permitted objects produces identical bytes |
| Non-mutating PIN status 🆕 | Counter visibility without spending it | `00 20 00 <ref>` → `63Cx`, and a repeat returns the **same** counter (no decrement) |
| Information-leak sweep ✅ | No hidden readable PII | The SFI/FID/AID sweep exposes only public files (`explore_full_sweep.py`, `explore_domrepeid.py`) |

Expected PIN references: User `0x83`, SO `0x84`, signing PIN `0x92`, signing PUK `0x93`.

## Tier 2 — Negative access-control probes (fail-safe), no secrets sent
Implemented in `tier2_negative.py`. One CAN/PACE session, standard `npa-tool` (continues after non-9000 responses).
Each probe **expects a denial**; a `9000`/data-bearing response is a **FAILURE (possible bug)**. No credential is sent
and no PIN counter is touched.

| Probe | Expected (pass) | What a bug would look like |
|---|---|---|
| Write: `UPDATE BINARY` on a read-only EF | `6982`/`6985`/`6A82` | `9000` (write accepted) |
| Write: `CREATE FILE` | `6982`/`6985` | `9000` |
| Write: `PUT DATA` | `6982`/`6985` | `9000` |
| `SELECT` + read DG3 without EAC | `6982` | data is returned |
| Read a protected DG **without SM** (plaintext after PACE) | rejected / `69xx` | plaintext data is returned |
| SM tampering (corrupted MAC) ✅ | `6987`/`6988` | the command is processed |
| Downgrade: PACE/CA suite weaker than advertised ✅ | rejected | accepted |

**Confirmed:** `npa-tool --translate` *always* builds the SM envelope (a plaintext `CLA=00`
command is silently wrapped in SM and succeeds), so it cannot send a plaintext, MAC-tampered,
or downgraded APDU. For that reason, the three follow-ups are split as follows:
- **`tier2_raw.py` 🆕 — the secure channel is mandatory (feasible now, no PACE needed).** Direct PC/SC, without
  npa-tool: reads EF.CardAccess (public control → data is returned) but confirms that EF.COM, DG1, and a write
  are all rejected without PACE (observed `6986`/`6986`/`6982`). PASS = protected data is unreachable
  without the secure channel. This is the lowest-level "SM mandatory" compliance check.
- **`pace_sm.py` + `tier2_sm_tamper.py` 🆕 — SM MAC tampering and PACE downgrade (DONE).**
  A from-scratch PACE-ECDH-GM-AES-256 handshake over NIST P-384 (`pace_sm.py`, no npa-tool/OpenSC)
  derives `K_enc`/`K_mac`/SSC itself, so we can issue APDUs that the real client would never issue. Verified
  on the **production cédula** (reserved UID):
  - *Positive control* — PACE established; the SM read of the public EF.CardAccess decrypts to the exact bytes
    read raw (self-validates the SM stack in both directions) → `9000`.
  - *SM MAC tampering* — one byte of the MAC corrupted → `6988`; DO8E removed → `6982`. **MAC enforced.**
  - *PACE downgrade* — MSE:Set AT requesting AES-128, 3DES, and AES-256 over P-256, each **rejected with
    `6A80`** (GENERAL AUTHENTICATE not attempted, so no password counter is touched). **No downgrade.**
  Offline cryptographic self-check: `python3 pace_sm.py --selftest`. Report: `reports/`.

## Tier 3 — Authenticated operations with credentials you legitimately hold (transient state only)
Implemented in `tier3_authenticated.py`. **Requires the PIN held by the user via stdin** (line 2, after the CAN on
line 1); the PIN is cleared and hidden from traces. It changes only the transient security state (reset at power-off);
no persistent change. One VERIFY per reference, never a retry loop, protected by an
explicit `--i-hold-this-pin` confirmation so the tool cannot be used for brute force.

| Test | What it validates | Pass |
|---|---|---|
| `VERIFY` of the held User/SO PIN 🆕 | The credential is correct; the gate opens | `9000`; a subsequent status query shows the counter **full again** (a successful verify resets it) |
| Access control of key operations at Boundary 8 🆕 | Use of key `0x42` is blocked by the DF state | After verifying the User PIN, `MSE:SET`+`INTERNAL AUTHENTICATE` on `0x42` → **denied** (expected `6982`, DF `5015` in init `0x03`); `9000` would be an unexpected capability |
| Chip Authentication replay ✅ | Possession / clone resistance | A fresh CA handshake derives working SM keys (`chip_auth_prove.py`) |

Safety: it is safe to run on the production cédula (read-only/transient). The key-operation probe expects a denial;
its exact `MSE` bytes are best-effort, so the tool reports the raw SW and classifies only
`denied (6xxx)` versus `UNEXPECTED SUCCESS (9000)`.

---

## Tier 4 — Requires issuer secrets/cooperation 🔒 (not implemented here)
- EAC Terminal Authentication with a real CVC chain CVCA→DV→terminal → read DG3.
- GlobalPlatform secure channel with ISD keys.
- 3DES external authentication (key reference `0x21`).
- Full signature enrollment + qualified signature with the delivered signing PIN + certificate.

## Tier 5 — Hardware / physical 🔒⚠️ (out of scope)
Side channel (timing/power), fault injection / glitching, invasive attacks on the chip. Destroys cards;
requires a hardware security laboratory and explicit legal/ethical authorization. Listed to mark the ceiling.

---

## How to run (Tiers 0–3)

```bash
cd active_adaptive

# Tier 0 — offline, no card
python3 tier0_tamper.py                 # dry run (plan)
python3 tier0_tamper.py --execute       # run the offline tamper checks on cached objects/

# Tier 1 — read-only live
python3 tier1_readonly.py                               # dry run
printf '<CAN>' | python3 tier1_readonly.py --can-stdin --execute

# Tier 2 — negative access-control probes
python3 tier2_negative.py                               # dry run
printf '<CAN>' | python3 tier2_negative.py --can-stdin --execute

# Tier 2 (raw) — secure-channel mandatory (no PACE, no credential)
python3 tier2_raw.py --execute

# Tier 2 (SM) — SM MAC tamper + PACE downgrade (from-scratch PACE+SM stack)
python3 pace_sm.py --selftest                          # offline crypto self-check
python3 tier2_sm_tamper.py                             # dry run (plan)
printf '<CAN>' | python3 tier2_sm_tamper.py --can-stdin --execute

# Per-card fingerprint registry
python3 card_registry.py --current --note "<label>"     # register the card on the reader
python3 card_registry.py --list

# Tier 3 — authenticated (held PIN required); CAN on line 1, PIN on line 2
python3 tier3_authenticated.py                          # dry run
printf '<CAN>\n<PIN>' | python3 tier3_authenticated.py --can-stdin --pin-stdin \
    --pin-ref user --i-hold-this-pin --execute
```

The live tools refuse to start without the PC/SC socket and without `--can-stdin`. Session artifacts are
written to `sessions/`, ignored by git; raw card bytes (if any) remain in `objects/`, ignored by git.
Each tool prints a PASS/FAIL summary and a JSON report.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
