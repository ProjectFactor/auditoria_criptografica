<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Reconciliación de grupos de datos de EF.SOD

Este análisis es completamente sin conexión. Analiza el contenido de EF.SOD con firma verificada ya
almacenado en el archivo de sesión y calcula el hash de los artefactos DG guardados exactos. No contacta
PC/SC ni usa ninguna credencial.

El SHA-256 del contenido firmado es
`bbbb3c7af8e6565951dadbcff579fef998053ccf396531da80e473332ff08fa9`.
Firma valores SHA-256 para DG1, DG2, DG3, DG7, DG11, DG12, DG13 y DG14.

| DG | Bytes | SHA-256 guardado frente a SHA-256 firmado | Resultado |
|---|---:|---|---|
| DG1 | 95 | `2376b9f48d3f525f4648de4268d3f45289040ef2a64aeb3e6784e9096d279b5f` | coincide |
| DG2 | 8,022 | `38446822652bf68a240ea55d298c7a5afffa93d73bf15953fd49c23bb6db1b74` | coincide |
| DG3 | — | firmado: `1c57c290500e8ea70d0f038b43d4e857c71eaf9779ddb144957b34fb17d54cdd` | no adquirido |
| DG7 | 5,002 | `c38d7b6906f01877afe1d7cc515a76f0e486746840b5995f84a6aaa25bdba999` | coincide |
| DG11 | 47 | `90d5dfea2fa7a41eb24c1e8e8b89463a0269d1a1b4c1f73f700e40f337ec56fe` | coincide |
| DG12 | 45 | `61a6b0c617537d63459b2d041e8b894b09f79c6c39627f5dfb2344804b05f83a` | coincide |
| DG13 | 61 | `a2cc80b6a3c32df81a3c2d0546806556dbc371aea42133824c90fa0a8330eb7b` | coincide |
| DG14 | 531 | `c0dfd53a054c957a2038c4ee6f68a437cf9c9f0730783f962d6e23dfa038ef92` | coincide |

Los siete grupos adquiridos coinciden byte a byte a nivel de hash. DG3 se mantiene deliberadamente
clasificado como `signed_not_acquired`; su SELECT posterior a PACE devolvió `6982`, por lo que su hash
firmado no debe describirse como adquirido ni verificado contra bytes de la tarjeta.

La salida reproducible es `lab/SOD_DG_RECONCILIATION.json`, generada por
`tools/session/reconcile_sod.py`. Esto establece integridad relativa al EF.SOD firmado; la limitación
separada de la cadena CSCA está documentada en `lab/CSCA_TRUST_DISCOVERY.md`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
