<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Separation of the card's trust domains

| Signed object | Embedded signer | Required issuer/trust input | Result | Must not be substituted by |
|---|---|---|---|---|
| EF.SOD / LDS Security Object | `JCE DS 02` | Authentic `JCE CSCA` whose SKI is `e8090eb7d5c71ffe568f0654a4675af5ea264bb8`, plus the applicable CRL | Valid signature and DG integrity; chain/revocation unresolved | Dominican passport CSCA; Cryptovision development CSCA; CVCA |
| EF.CardSecurity / SecurityInfos | Cryptovision development `DS` | Authentic Cryptovision development `CSCA` whose SKI is `641f978a63ae1b407174e96e3566af347fed3b20` | Valid signature; chain unresolved | JCE CSCA; passport CSCA; CVCA |
| EAC Terminal Authentication | CVC hierarchy CVCA/DV/terminal | Valid and legitimate chain of terminal certificates and the corresponding terminal private key | Not exercised | Any LDS X.509 CSCA/DS certificate |

Passive authentication demonstrates that the stored data was signed with the private key
corresponding to the embedded signer certificate and that the acquired DG bytes match
EF.SOD. It becomes externally trustworthy only when the correct authentic issuer chain
and the applicable revocation evidence are supplied. There is no private key, and none is expected, in EF.SOD,
EF.CardSecurity, the ICAO bulk stores, or any certificate.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
