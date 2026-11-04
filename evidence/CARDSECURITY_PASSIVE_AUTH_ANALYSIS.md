<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Análisis de firma sin conexión de EF.CardSecurity

Este análisis usa únicamente el objeto guardado de 1,225 bytes. No establece ni ejerce una sesión con la
tarjeta.

OpenSSL y un verificador local independiente de DER/aritmética modular RSA validan ambos la firma CMS
incrustada y su `messageDigest`. El contenido firmado de 22 bytes coincide exactamente con EF.CardAccess:

- tipo de contenido `0.4.0.127.0.7.3.2.1`;
- `id-PACE-ECDH-GM-AES-CBC-CMAC-256`;
- versión 2;
- identificador de parámetros de dominio estandarizado 15.

El contenido es una declaración de capacidades, no una clave de la tarjeta ni datos personales.

El firmante incrustado es `CN=DS,OU=development,O=cryptovision,C=DE`, emitido por el
`CN=CSCA,OU=development,O=cryptovision,C=DE` no suministrado. Usa RSA-1024, tiene la huella de
certificado `4eb27936eeee488c8409044d8db3ff22210155443b89db7e4b21aee2f95704e2`, y su hora de firma CMS
es 2026-02-04 11:44:47Z. La firma es matemáticamente válida, pero su cadena no está resuelta y la
etiqueta de desarrollo lo hace inadecuado como ancla de confianza externa de producción.

Este es un dominio de confianza distinto de EF.SOD. El CSCA de desarrollo de Cryptovision no puede validar
a `JCE DS 02`, y no se puede asumir que el CSCA de la JCE/OACI valide EF.CardSecurity.

Evidencia legible por máquina: `lab/CARDSECURITY_PASSIVE_AUTH_REPORT.json`.

Reproducción:

```sh
python3 tools/icao/analyze_cardsecurity.py \
  logs/sessions/session_TEST-01_CARDSECURITY_FULL/artifacts/assembled_der_001.bin \
  --json-output lab/CARDSECURITY_PASSIVE_AUTH_REPORT.json
```

Código de salida: `0`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
