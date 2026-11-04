<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Separación de dominios de confianza de la tarjeta

| Objeto firmado | Firmante incrustado | Insumo de emisor/confianza requerido | Resultado | No debe sustituirse por |
|---|---|---|---|---|
| EF.SOD / Objeto de Seguridad LDS | `JCE DS 02` | `JCE CSCA` auténtico cuyo SKI es `e8090eb7d5c71ffe568f0654a4675af5ea264bb8`, más la CRL aplicable | Firma e integridad de DG válidas; cadena/revocación sin resolver | CSCA del pasaporte dominicano; CSCA de desarrollo de Cryptovision; CVCA |
| EF.CardSecurity / SecurityInfos | `DS` de desarrollo de Cryptovision | `CSCA` de desarrollo de Cryptovision auténtico cuyo SKI es `641f978a63ae1b407174e96e3566af347fed3b20` | Firma válida; cadena sin resolver | CSCA de la JCE; CSCA del pasaporte; CVCA |
| Autenticación de Terminal EAC | Jerarquía de CVC CVCA/DV/terminal | Cadena vigente y legítima de certificados de terminal y la clave privada de terminal correspondiente | No ejercida | Cualquier certificado X.509 CSCA/DS del LDS |

La autenticación pasiva demuestra que los datos guardados fueron firmados con la clave privada
correspondiente al certificado del firmante incrustado y que los bytes de DG adquiridos coinciden con
EF.SOD. Solo se vuelve confiable externamente cuando se suministran la cadena de emisor auténtica
correcta y la evidencia de revocación aplicable. No hay ni se espera ninguna clave privada en EF.SOD,
EF.CardSecurity, los almacenes masivos de la OACI ni en ningún certificado.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
