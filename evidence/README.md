<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Evidencia

Este directorio contiene únicamente la evidencia técnica que respalda directamente los tres hallazgos de
[`../FINDINGS.md`](../FINDINGS.md). Intencionalmente no incluye el proceso de descubrimiento,
las notas de ingeniería inversa ni la investigación exploratoria que condujo a estos hallazgos; solo los
resultados que los sustentan.

## Hallazgo 1 — Firmante de Documentos RSA-1024 de «desarrollo» en `EF.CardSecurity`

- [`CARDSECURITY_PASSIVE_AUTH_ANALYSIS.md`](CARDSECURITY_PASSIVE_AUTH_ANALYSIS.md) /
  [`CARDSECURITY_PASSIVE_AUTH_REPORT.json`](CARDSECURITY_PASSIVE_AUTH_REPORT.json) — la verificación
  de la firma de `EF.CardSecurity`: el certificado incrustado del Firmante de Documentos RSA-1024
  `cryptovision/development` y la validez de su firma.

## Hallazgo 2 — Brecha de confianza del CSCA de la JCE

- [`CSCA_TRUST_DISCOVERY.md`](CSCA_TRUST_DISCOVERY.md) — la cadena del Firmante de Documentos de la JCE
  hasta su CSCA declarado, y por qué la URI publicada de ese CSCA no resuelve.
- [`ICAO_MASTER_LIST_DO.json`](ICAO_MASTER_LIST_DO.json) — la entrada de la República Dominicana en la
  Lista Maestra pública de la OACI, usada para confirmar que el único CSCA disponible en esa lista
  pública es el CSCA del pasaporte, no el CSCA de la cédula.
- [`TRUST_DOMAIN_SEPARATION.md`](TRUST_DOMAIN_SEPARATION.md) — una tabla concisa que separa qué firmante
  cubre cada objeto firmado y qué ancla de confianza requiere cada uno; es la base para no confundir los
  dominios de confianza de `EF.SOD` (DS de la JCE) y `EF.CardSecurity` (DS de desarrollo).

## Hallazgo 3 — La integridad de la identidad se mantiene (en las tarjetas examinadas en este detalle)

- [`PASSIVE_AUTHENTICATION_RESULT.md`](PASSIVE_AUTHENTICATION_RESULT.md) — la tabla completa de
  reconciliación de hashes por grupo de datos contra el `EF.SOD` firmado (7/7 grupos de datos adquiridos
  coinciden; DG3 correctamente excluido por no haberse adquirido).
- [`PASSIVE_AUTHENTICATION_ANALYSIS.md`](PASSIVE_AUTHENTICATION_ANALYSIS.md) /
  [`PASSIVE_AUTHENTICATION_REPORT.json`](PASSIVE_AUTHENTICATION_REPORT.json) — la verificación
  independiente de la firma CMS/ECDSA de `EF.SOD` que sustenta esa reconciliación.
- [`SOD_DG_RECONCILIATION.json`](SOD_DG_RECONCILIATION.json) — la forma legible por máquina de la misma
  reconciliación, reproducible con `tools/icao/verify_passive_auth.py`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
