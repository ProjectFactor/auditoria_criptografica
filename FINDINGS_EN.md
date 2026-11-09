<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/factor-landscape-reverse.svg"><img src="docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Cédula — The 3 Main Findings and Possible Attacks

- **Status:** Findings report
- **Author:** FACTOR Inc. (commercial arm of Project FACTOR) — Juan Vargas, CEO
- **Scope:** production cédulas issued from early 2026 through September 2026, examined with their holders' permission.
- **Credentials:** CANs and PINs were entered at runtime and never stored.

## How to read the colors

- 🔴 **Confirmed defect**
- 🟠 **Uncertainty or trust gap**
- 🟡 **Conditional:** depends on the verifier
- 🟢 **A specific, named check passed** on the card(s) indicated. It does not mean "secure," "certified" or "trustworthy," and says nothing about cards or attacks not tested.

Four aspects are always kept separate: **signature integrity**, **trust in the issuer**, **algorithm strength** and **development/production provenance**.

**Contents:** [Finding 1: RSA-1024 development signer](#finding-1) · [Finding 2: CSCA trust gap](#finding-2) · [Finding 3: checks passed](#finding-3) · [Recommendation: full audit](#full-audit) · [Attack chains](#attack-chains) · [Summary](#summary)

Each finding has the same parts: what we found, regulatory position, cryptanalytic context and the attacks it may enable.

---

<a id="finding-1"></a>
## Finding 1 — 🔴 RSA-1024 "development" Document Signer (DS) in `EF.CardSecurity`

> **In plain language.** One of the digital signatures inside the cédula's chip uses a key that is too weak by current standards, and it is also a *test* key that the chip manufacturer created for development, not a key made specifically for the JCE. Whoever obtains that key, whether by finding it in vendor material or by breaking it, can produce signatures that the chip's own checks will accept as valid.

Sections: [What we found](#f1-found) · [Regulatory position](#f1-reg) · [Cryptanalytic context](#f1-crypto) · [Attacks it enables](#f1-attacks) · [Assurance gap](#f1-process) · [Scale and reissuance](#f1-reissue) · [Limits](#f1-limits)

<a id="f1-found"></a>
### What we found

**Observed fact.** `EF.CardSecurity` is signed by a Document Signer that uses **RSA-1024** with **`cryptovision/development`** provenance (SHA-256 of the whole object `09b130…`, certificate `4eb279…`), independently verified byte by byte on a production card. The same certificate was present on all the production cards examined, issued from early 2026 through September 2026.

**Why it matters.** Two independent weaknesses accumulate in a single key:
- **Algorithm strength:** RSA-1024 is obsolete and within reach of a well-resourced adversary (state-scale).
- **Provenance:** a *development* signer implies that the private key could ship in the vendor's SDK or sample material; that is, it would be practically public, with no need to factor anything.

<a id="f1-reg"></a>
### Regulatory position

**Regulatory obsolescence — not a disputed or marginal decision.** RSA-1024 was formally declared obsolete by the standards bodies that set cryptographic policy for government systems and critical infrastructure, years before this card was issued:

- **NIST** (US): [SP 800-131A Rev. 2, "Transitioning the Use of Cryptographic Algorithms and Key Lengths"](https://doi.org/10.6028/NIST.SP.800-131Ar2) stopped allowing 1024-bit RSA for generating digital signatures after 2013. [SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management"](https://doi.org/10.6028/NIST.SP.800-57pt1r5) rates 1024-bit RSA at only **80 bits of security strength** —below the 112-bit minimum NIST requires for any current use— and sets 2048 bits as the minimum acceptable RSA modulus.
- **Europe:** [ENISA, "Algorithms, Key Sizes and Parameters Report"](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014) classifies 1024-bit RSA as legacy/insufficient and recommends a minimum of 3072 bits for new systems. Germany's **BSI** (Bundesamt für Sicherheit in der Informationstechnik), [TR-02102-1, "Cryptographic Mechanisms: Recommendations and Key Lengths"](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/BSI-TR-02102.html), sets a minimum RSA modulus of 3000 bits for new deployments and does not consider 1024 bits acceptable for any retention period.
- **Industry/web PKI, as a concrete deadline that has already passed:** the CA/Browser Forum Baseline Requirements prohibited certificate authorities from issuing new 1024-bit RSA TLS certificates **as of January 1, 2014**, more than a decade before this card was issued.
- **The pattern is the same everywhere a national ID program should look:** every body that publishes cryptographic minimums for government-grade credentials set the floor at 2048 bits (NIST) or more (ENISA, BSI) more than ten years ago. No standards body today endorses 1024-bit RSA for the signing key of an identity document.

*(The document identifiers and links above must be independently verified against the current published revisions before relying on this report for a procurement or legal decision; cite the exact section and page in any formal submission.)*

<a id="f1-crypto"></a>
### Cryptanalytic context

**How far this is from the theoretical.** The strength of RSA keys is not an abstract risk; it is eroding publicly, in measurable steps, and the pace has accelerated sharply recently:

- **RSA-240** (795 bits, 240 decimal digits) — factored in **November 2019** by Boudot, Gaudry, Guillevic, Heninger, Thomé and Zimmermann, using the General Number Field Sieve (GNFS); published as "Comparing the Difficulty of Factorization and Discrete Logarithm: a 240-Digit Experiment" (CRYPTO 2020).
- **RSA-250** (829 bits, 250 decimal digits) — factored in **February 2020** by the same team, the next record in the same series.
- **RSA-260** (862 bits, 260 decimal digits) — factored on **September 3, 2026** by Eric Lu (Cognition), using a modified, GPU-accelerated CADO-NFS pipeline; reported cost on the order of 13.5 GPU-years (~4,900 GPU-days), roughly US$400 thousand at market GPU rental prices.
- **RSA-896** (896 bits, 270 decimal digits) — factored on **September 19, 2026**, just 16 days later, by Stephen A. Weis, using a GPU port of CADO-NFS run on up to 2048 GPUs for about 10 days (~30 GPU-years) of *idle, harvested compute capacity*; that is, spare cycles that would otherwise have gone unused, not a dedicated purchase.

**What changed between the 2019–2020 records and those of September 2026 is the pace, not just the size.** Going from RSA-240 to RSA-250 took three months in 2019–2020, and then more than five years passed without another public record. Then, in September 2026 alone, the record jumped twice — RSA-260 and then RSA-896 — just 16 days apart, each with GPU-accelerated tools. RSA-896 was run on idle capacity, not a dedicated budget, which is a substantially lower barrier than "a well-funded team spending money"; it is closer to "the compute a large organization already owns and is not using this week."

**To be precise and not overstate:** no public record establishes that a 1024-bit RSA modulus (309 decimal digits) has been factored; RSA-896, the current public record, is still 128 bits (about 39 decimal digits) short. What the September 2026 records establish is that the *gap closed by more than 100 bits in two and a half weeks*, using only idle compute and an academic- or startup-scale team, not a state budget. Published cost-scaling estimates for the General Number Field Sieve placed a dedicated 1024-bit factoring effort within reach of a well-funded institution or a state well before this acceleration; after it, that estimate should be treated as a ceiling, not a guarantee. Combined with the **development provenance** of this specific key —which removes the need to factor anything if the private key is recoverable from vendor material—, RSA-1024 as the production signing key of an identity document is neither a marginal nor a theoretical weakness; it is an algorithm of a class known to be broken, whose concrete retirement deadline, according to all relevant standards bodies, expired a decade or more ago.

<a id="f1-attacks"></a>
### Attacks this finding can enable

Each attack below requires the attacker to first obtain the signing key (from vendor material or by factoring it) **and** other components, indicated in each item. None was carried out; they are attack models, not demonstrations.

1. **Forging the chip's "I'm genuine" proof (Chip Authentication).** The RSA-1024 signer vouches for the chip's anti-cloning key in `EF.CardSecurity`. With the key, an attacker can sign a replacement that names a key they control.
   *Also requires:* a copy of a card's readable data on a blank card or an emulator, and a verifier that checks Chip Authentication and accepts this signer.
   *Result:* a cloned card passes the check that exists precisely to detect clones.
2. **Edited identity data on a cloned card, if a verifier trusts this signer for identity.** Normally the identity data (`EF.SOD`) is signed by a different production EC key, so this does not work. It does work if a verifier or its trust list accepts this RSA-1024 certificate as a valid signer of identity data.
   *Also requires:* such a verifier (through misconfiguration, or a trust list that includes the development CA), plus the cloned card from attack 1. 🟡 Depends on the verifier.
3. **Forgery that in practice cannot be revoked.** The certificate is valid from 2019 to 2079, and we found no revocation path for it. The JCE's own CRL host does not resolve either (Finding 2). If the key leaks, there may be no effective way to tell verifiers to stop trusting it.
   *Also requires:* the key to leak or be broken; a verifier that checks revocation (or that fails open when it cannot).
4. **Offline, undetectable key compromise.** We did not find the key, and it is not established whether it exists in the vendor's SDK or sample material. If it does, it may already be in other hands. Using it requires no contact with any JCE card or system, so it would leave no trace.
   *Also requires:* only the key and a verifier that accepts the signer.

<a id="f1-process"></a>
### Assurance gap: a development key reached production

A vendor **development** key is signing a national identity credential. An independent cryptographic review would have caught this before issuance. That it reached production indicates a gap in the process's cryptographic assurance, not a single person's mistake.

**Observed**
- The certificate identifies itself with `OU=development`. Its issuer is a development CA.
- It uses RSA-1024, obsolete for more than a decade.
- It is valid until 2079.
- It appears on cards issued from early 2026 through September 2026.
- We found it by reading a public file with a commercial reader and decoding the certificate. That takes minutes and requires no internal access.

**Conclusion** (our inference from the evidence; the JCE's internal records were not seen)
- Whatever acceptance process existed did not include a cryptographic review capable of catching this.
- The defect was present on every card we examined throughout the issuance period, from early 2026 through September 2026.
- Finding 2 is of the same kind: a published trust anchor that does not resolve, undetected.
- Two independent defects of this kind point to an assurance gap in the process, not an isolated error.

**What a cryptographic review would have checked, before a single card was issued**
- Key size and algorithm of each signer against current standards.
- Provenance of each signing key: who generated it, where and under what ceremony.
- That no development, test or sample key or certificate is in production.
- That every published trust anchor and every revocation URL resolves and is pinned.
- That the objects issued on the card verify against the intended production chain, end to end.

**Recommendation**
- Hire qualified **cryptographers**, independent of the card vendor, to audit the key ceremony and the issuance chain.
- Make that audit a **pre-issuance gate**, and repeat it on every change of vendor, firmware or key.
- Treat the signing infrastructure of a national cédula as critical cryptographic infrastructure. It cannot be certified with procurement paperwork alone. It needs people who know how to read the certificate and understand what they see.

<a id="f1-reissue"></a>
### Scale: is it necessary to reissue every cédula?

**How many cards exist**
- **4,009,576** new cédulas delivered, out of **8,730,372** eligible people ([Diario Libre](https://www.diariolibre.com/politica/jce/2026/10/13/jce-supera-los-cuatro-millones-de-cedulas-entregadas/3688288), [Infobae](https://www.infobae.com/republica-dominicana/2026/10/16/junta-central-electoral-dominicana-alcanza-los-4-millones-de-nuevas-cedulas-emitidas-y-pide-renovar-antes-de-abril-de-2027/)). The JCE also reports 196,310 documents delivered abroad.
- The JCE set a mass-issuance period, after which the previous cédula will no longer be accepted.
- Therefore, up to about **4.7 million** cards remain to be issued (8,730,372 − 4,009,576). This is our arithmetic on the JCE's figures, not a JCE figure.
- Our examination covers only cards issued through September 2026, and cannot establish how many of the 4.0 million carry the development signer.

**Short answer: decide after a full audit.** This investigation used only public information. It cannot rule out other flaws, so the reissuance decision must wait for the JCE-backed audit recommended [below](#full-audit). We do not recommend a generalized reissuance of all cards today. We recommend this order:

1. **Stop the line first.** Every card still to be personalized should use a production signer, verified by an independent laboratory. Reissuing cards with the same defect would only repeat it.
2. **Find out how many cards are affected.** Independent sampling by batch, site and date. The object is identical on all the cards we examined, so it is probably a static template, but that is not established.
3. **Find out whether cards already issued can be fixed without replacing them.** Ask the vendor and an independent laboratory whether the issuer can replace `EF.CardSecurity` on a finished card through an authorized update. We did not test it: our reader cannot write, and writes over the public channel are rejected.
   - **If possible:** update the cards at service points or at normal renewal. No reissuance.
   - **If not possible:** reissue only the affected cards, at no cost to citizens, with the vendor bearing the cost where the contract allows.
4. **Protect verifiers in the meantime.** Do not add the development certificate to any trust list. Do not rely solely on Chip Authentication as the anti-cloning check for high-value decisions. Pin the production roots.

**Why a generalized reissuance is not the first response**
- The defect is a signature on an issuer-side object, not the citizens' keys, PINs or identity data. In our tests the identity data is signed by a separate production EC key, and each card's anti-cloning key is distinct.
- Reissuing does not by itself eliminate the weak signer, which is also on cards not yet issued.
- A mass reissuance on top of the ongoing mass renewal would add load on the same offices and the same deadline.

**What would change this to "reissue all"**
- If it is shown that others can recover the development private key, **and**
- the issued cards cannot be updated, **and**
- relying parties depend on Chip Authentication to detect clones.

All three conditions together would justify replacing all affected cards, starting with those used for higher-value decisions.

<a id="f1-limits"></a>
### Limits

**Boundary.** This DS signs `EF.CardSecurity` (Chip Authentication / security objects) — it does **not** sign the identity integrity object (see Finding 3 / `EF.SOD`).

**Caveat.** This finding is confirmed on all the cards examined, issued from early 2026 through September 2026. This report does not claim that every cédula ever issued carries this signer, only that no card examined so far is exempt.

---

<a id="finding-2"></a>
## Finding 2 — 🟠 JCE CSCA trust gap (passive authentication trust cannot be independently validated)

> **In plain language.** The cédula's identity data is correctly signed, but the web address where the JCE's root certificate is supposed to be published does not exist. Therefore, a verifier cannot confirm that the signature chains up to the real JCE. The signature is intact; what is missing is a reachable, pinned root that proves who signed.

Sections: [What we found](#f2-found) · [Regulatory position](#f2-reg) · [Cryptanalytic context](#f2-crypto) · [Attacks it enables](#f2-attacks)

<a id="f2-found"></a>
### What we found

**Observed fact.** `EF.SOD` is signed by **JCE DS 01** (`C=DO, O=Junta Central Electoral - JCE, OU=DOM`, EC with explicit parameters / SHA-384, valid 2026-04 → 2036; certificate `4a31c811…`) — a production-grade identity integrity path. The DS chains to the JCE cédula CSCA (AKI `e8090eb7…`), but the published anchor URI **`https://ca.jce.gob.do/csca` returns NXDOMAIN**. The only CSCA present on disk is the passport CSCA (SKI `d0d9f1ad…`), a different anchor. The NXDOMAIN result for the published anchor URI was independently reconfirmed across the whole sample (it is a check against a public DNS/PKI record, not a property of each card, so it does not depend on which specific card is being verified), and reconfirmed again at the time of publication: a live DNS query for `ca.jce.gob.do` on **2026-11-02 (21:01 AST / 01:01 UTC on 2026-11-03)** still returns NXDOMAIN. The same host also serves the DS's CRL distribution point (`https://ca.jce.gob.do/crl_csca`), so that revocation-checking path is unreachable for the same reason.

**Why it matters.** Verifiers that fetch the CSCA at runtime cannot anchor the chain to a root of trust. Signature integrity is intact; **trust in the issuer cannot be verified** against a reachable authority. This gap was confirmed present on all the cards in the sample.

<a id="f2-reg"></a>
### Regulatory position

ICAO Doc 9303 (Parts 11 and 12) defines Passive Authentication as validating the Document Signer certificate up to a country root of trust (the CSCA), with revocation status checked when available. A root that cannot be obtained makes it impossible to perform that validation from public sources. *The exact part, section and page must be confirmed against the current edition before citing this in a formal submission.*

<a id="f2-crypto"></a>
### Cryptanalytic context

None. This is not a weak-algorithm problem. The `EF.SOD` signature uses EC with SHA-384 and verifies correctly. The gap is the lack of published trust infrastructure, so nothing needs to be broken for it to matter.

<a id="f2-attacks"></a>
### Attacks this finding can enable

1. **Verifiers fail open and accept an unanchored signer.** Software that cannot obtain the root may skip chain verification, or trust any signer the card presents.
   *Also requires:* a verifier written that way. A forged or self-signed signer is then accepted, without compromising any card.
2. **Someone else supplies the "root."** The published address does not resolve, so whoever can make that name resolve (DNS hijacking, or a registration oversight) could serve a root or a revocation list to verifiers that fetch it at runtime.
   *Also requires:* control of that DNS name and verifiers that fetch the root without pinning it. Not tested.
3. **Revocation cannot be delivered.** The signer's revocation list lives on the same nonexistent host. A compromised signer, including the Finding 1 key, could not be revoked in a way verifiers can see.
   *Also requires:* a compromised signer.
4. **Legitimate cards rejected (availability).** Verifiers that fail closed will reject genuine cédulas because they cannot anchor the chain.
   *Also requires:* nothing beyond the unreachable host. This harms citizens and relying parties rather than enabling fraud.

---

<a id="finding-3"></a>
## Finding 3 — 🟢 Named integrity and protocol checks passed on the cards tested

> **In plain language.** We tried several ways of tampering with the card and its secure channel. On the cards we examined in depth, the specific tests listed below did not succeed. This is a record of what we tried, not a guarantee of security.

Regulatory position and cryptanalytic context: not applicable. These are test results, and the algorithms involved (AES-256, NIST P-384, SHA-384) are current. **Attacks this finding enables:** none. It lists the attacks that were attempted and failed, in [Attacks on which our tests did not succeed](#tests-failed).

**Scope note.** Unlike Findings 1 and 2, these checks required a from-scratch PACE/SM session and a full tiered validation run, which was carried out with full evidence capture only on a subset of the cards examined — see `report/mapa_limites_seguridad_cedula_EN.pdf` for what was tested at that level of detail.

**What 🟢 means in this finding.** Each item below is a specific test that passed on the cards examined at this level of detail. Nothing more is claimed.

**Observed facts (on the cards examined at this level of detail).**
- 🟢 **Passive auth, signature integrity only:** `EF.SOD` CMS signature valid; **7/7 readable DGs (1,2,7,11,12,13,14) reconcile** with SHA-256; DG3 protected by EAC/omitted.
- 🟢 **Chip Authentication, only on these cards:** possession proven live; the DG14 CA key is **unique per card** (the anti-cloning key differs between cards).
- 🟢 **Writes rejected over the CAN/PACE channel:** UPDATE BINARY / CREATE FILE → `6982`, PUT DATA → `6A81`, DG3-without-EAC → `6986`.
- 🟢 **Secure Messaging, on our test bench:** the PACE+SM stack built from scratch resists **MAC tampering** (`6988`/`6982`) and **downgrade** (AES-128 / 3DES / weak curve, each rejected with `6A80`, judged at MSE:Set AT without touching any counter).
- 🟢 **PIN retry counters:** present and correctly reported through non-mutating status queries. PINs were not attacked or brute-forced.
- 🟢 Levels 0–3 of the validation plan were passed on these cards.

**What 🟢 does NOT mean here.**
- It does **not** mean trust in the issuer: the `EF.SOD` signature is valid, but the chain could not be anchored to a reachable CSCA (Finding 2).
- It does **not** mean the card is secure in general, nor that other cards, firmware versions or untested commands are secure.
- It does **not** cover `EF.CardSecurity`, whose signer is the Finding 1 defect.
- "Rejected" and "blocked" describe the tests we ran, not proof that no attack exists.

**Why it matters.** On the cards examined at this level of detail, our tests found no way to tamper with the data on the card, break the Secure Messaging session or bypass the PIN retry limits. That narrows where we look next, for those cards, to the provenance of the signing key and the anchoring of the trust chain — the two properties (Findings 1 and 2) that *were* confirmed in the wider sample.

---

<a id="full-audit"></a>
## Recommendation: a full audit, commissioned and backed by the JCE

**We strongly recommend that the JCE commission a full independent cryptographic audit, with its own authority behind it.**

**Why our findings are not enough**
- Everything set out here was found from the outside, using public information and standard card interfaces.
- We had no access to JCE records, key ceremonies, signing hardware, source code, vendor documentation or issuance records.
- Three findings obtained from the outside suggest there may be others we cannot see. The assurance gap in Finding 1 is the strongest reason.
- Our card coverage is limited, and the protocol checks were not run on all cards.
- "Nothing else was found" means only that we could not look further.

**What only the JCE can open**
- Generation and custody records for each signing key, including the history of the development key.
- The approved card profile, the personalization software and the signing configuration.
- Which cards, batches and sites carry each configuration, and how many.
- Whether issued cards can be updated, and through what authorized process.
- Which verifiers consume the card's objects, and how they behave with an untrusted signer.
- Vendor and acceptance-test records.

**What the audit should do**
- Be led by qualified, independent cryptographers, and not only by the card vendor or the system integrator.
- Work under the JCE's authority, with access to the records above and witnessed readings of cards from different batches.
- Report to the JCE's leadership and publish a summary of its findings and of the corrective plan.
- Decide the reissuance question based on its results, not before.

**Independence.** This recommendation holds regardless of who performs the audit and is not conditioned on any engagement of FACTOR Inc. (see the statement of interests). The tools, evidence and reports in this repository are available to whoever performs it as a starting point. Contact details are in [About the author](README_EN.md#about-the-author).

---

<a id="attack-chains"></a>
## Attack chains combining the findings

The attacks of each finding are listed under each one. These chains combine them.

Each is a *conditional* class of attack with explicit preconditions; none is immediate.

### A. Forged `EF.CardSecurity` → defeat of Chip Authentication's anti-cloning guarantee
**Chain:** Finding 1 + Finding 2.
`EF.CardSecurity` (which carries the CA public key) is signed by the RSA-1024 development DS. Preconditions to forge:
- **Recovery of the development key** (the most realistic): private key obtained from the vendor's development material; or
- **Factoring** of RSA-1024 (state-scale effort).

With the DS key, an attacker re-signs a `CardSecurity` that presents a CA key they control and builds a cloned/emulated chip that **passes Chip Authentication** — exactly the guarantee CA exists to provide. It succeeds only if the verifier accepts that DS (see B).

### B. Verifier trust degradation / fail-open acceptance
**Chain:** Finding 2, amplifying A.
Because the CSCA is unreachable, verifiers that fetch it at runtime tend to **fail open**, accepting the DS without anchoring it to a pinned root of trust. A self-signed or forged Document Signer can then be accepted. It requires compromising no card, only a verifier that does not pin the CSCA offline. It is systemic "verification theater."

### C. Acceptance by weak verifiers / downstream credentials
**Chain:** A + B.
Downstream systems (KYC, customer onboarding, kiosks) that trust `CardSecurity`-level data or perform partial passive auth without anchoring could accept a fabricated security object. Severity depends on each verifier's implementation, not on the card.

<a id="tests-failed"></a>
### Attacks on which our tests did not succeed

🟢 here means only: the attack was attempted or analyzed as described and failed. It is not proof of impossibility.
- **Forging `EF.SOD` identity data** (name, photo, DG1/DG2…) by breaking the RSA-1024 key: 🟢 not achieved, because `EF.SOD` is signed by a different, production EC signer. It does **not** cover a verifier that also accepts SODs signed with RSA-1024 (🟡, see the cloning table in `README_EN.md`).
- **Writing false data to a genuine card over the CAN/PACE channel:** 🟢 rejected in our tests (`6982`/`6A81`/`6986`). It does not cover issuer-credential paths (SO PIN, GlobalPlatform), which we did not test.
- **Secure Messaging MAC tampering and algorithm downgrade:** 🟢 rejected on our test bench. A full man-in-the-middle attack was not tested.
- **PIN brute force:** ⚪ not tested (no color claim). Retry counters were observed to be present; we did not attempt to exhaust them.

---

<a id="summary"></a>
## Summary

| Attack | Precondition | Is a block present? |
|---|---|---|
| Clone passes Chip Auth (A) | Recover/factor the RSA-1024 development DS **and** the verifier does not pin the CSCA | Partial — depends on the verifier |
| Trust fail-open (B) | The verifier fetches the CSCA at runtime and fails open | 🔴 CSCA unreachable |
| Acceptance by weak verifier (C) | The downstream system skips full passive auth with anchoring | Depends on the implementation |
| Forge `EF.SOD` data via the RSA-1024 key | — | 🟢 Different signer (EC); not covered if a verifier accepts RSA-1024 SODs |
| Card write / SM tampering / PIN counters | — | 🟢 Named tests passed on the cards tested; not a general security claim |

**Conclusion.** In the tests we ran, the card-side checks passed; the exposure we found is **signing-key provenance (Finding 1) + an unanchored trust chain (Finding 2)**. They must be remediated **together**: fixing one without the other leaves the clone-acceptance path (A/B) open.

**Open item.** Rank A/B/C by real-world likelihood once we know which verifier implementations (JCE app, third-party readers) fail open on the missing CSCA, and gather more production UIDs before any population-level claim.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
