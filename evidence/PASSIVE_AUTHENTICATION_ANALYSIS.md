<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Análisis de autenticación pasiva

Alcance: solo bytes guardados; sin PC/SC, comandos a la tarjeta, operaciones de PIN/CAN, solicitudes OCSP ni consultas de red específicas de un número de serie.

## Resultado

El EF.SOD guardado es internamente válido. OpenSSL y un verificador local estricto independiente validan
ambos la firma CMS. Este último analiza el DER por sí mismo y comprueba ECDSA con aritmética de enteros
de campo primo. EF.COM y el Objeto de Seguridad LDS nombran los mismos grupos de datos: `1, 2, 3, 7, 11, 12,
13, 14`. Cada objeto firmado adquirido (`1, 2, 7, 11, 12, 13, 14`) tiene un hash exactamente igual a su
resumen en EF.SOD. DG3 sigue firmado pero no se adquirió porque no se cruzó su límite de acceso.

Esto demuestra integridad y posesión de la clave del firmante para la imagen de tarjeta guardada, pero no
confianza externa. El certificado `JCE DS 02` incrustado aún no puede encadenarse a un `JCE CSCA`
autenticado, y no hay una CRL aplicable. Por lo tanto, el estado correcto con cierre seguro (fail-closed) es:

`internally_valid_external_trust_unresolved`

Evidencia legible por máquina: `lab/PASSIVE_AUTHENTICATION_REPORT.json`.

## Certificado del Firmante de Documentos

| Campo | Resultado exacto |
|---|---|
| Sujeto | `CN=JCE DS 02,OU=DOM,O=Junta Central Electoral - JCE,C=DO` |
| Emisor | `CN=JCE CSCA,O=Junta Central Electoral - JCE,C=DO` |
| Serie | `199686BB721AD7689CB5` |
| Huella SHA-256 | `1412267945fdd2d6d196bcc49acff007dd91f61de761b8ab7e0e16bcf327dfb5` |
| SKI | `f4047b2a821fea2b8c537f474a274f2a97d0460f` |
| AKI | `e8090eb7d5c71ffe568f0654a4675af5ea264bb8` |
| Vigencia del certificado | 2026-04-17 20:35:41Z hasta 2036-08-17 20:35:41Z |
| Período de uso de la clave privada | 2026-04-17 20:35:41Z hasta 2026-08-17 20:35:41Z |
| Clave | EC con parámetros explícitos; los parámetros exactos equivalen a `brainpoolP256r1` |
| SHA-256 del SPKI | `1668370ca5f4a0625159d5334d8202b7b27d4220e4139eb02a4d22c8043beef3` |
| Uso de clave | únicamente `digitalSignature`, crítico |
| Lista de tipos de documento OACI | versión 0; tipo `I` (cédula de identidad) |
| Firma del certificado | ECDSA con SHA-384; el AlgorithmIdentifier tiene parámetros `NULL` inválidos |
| Firma de EF.SOD | ECDSA con SHA-256; el AlgorithmIdentifier tiene parámetros `NULL` inválidos |

La abreviatura anterior `P-256` en el repositorio era ambigua y errónea si se leía como NIST P-256. Los
valores explícitos exactos coinciden con BrainpoolP256r1 y los resúmenes relevantes se corrigieron.

DG12 contiene el emisor `JUNTA CENTRAL ELECTORAL` y la fecha de emisión `20260712`. Esa fecha está dentro
tanto del intervalo de vigencia del certificado como del período de uso de la clave privada. En el momento del análisis
el certificado sigue vigente, mientras que el período de uso de su clave de firma ha terminado. Esto no
invalida un documento demostrablemente producido durante el intervalo de firma permitido.

## Verificaciones de CMS y grupos de datos

- SHA-256 del CMS de EF.SOD: `ea789c1c53bc58a1aff07d2aa83d2e45410768bc94a7b496c13f49f3ab906dcf`.
- SHA-256 del Objeto de Seguridad LDS firmado: `bbbb3c7af8e6565951dadbcff579fef998053ccf396531da80e473332ff08fa9`.
- Los atributos firmados son exactamente `contentType` y `messageDigest`; no hay `signingTime`.
- El `messageDigest` firmado coincide con el contenido encapsulado.
- Los siete resúmenes de DG adquiridos coinciden byte a byte.
- El resumen de DG3 está presente en el objeto firmado, pero no se suministraron bytes de DG3 al verificador.

## Actualización de la confianza externa

Los objetos masivos del PKD de la OACI guardados más recientes son la versión completa `10293` y la
versión `527` de la Lista Maestra de CSCA. La página pública oficial de estado consultada durante el análisis
reporta esas mismas versiones. La página de la Lista Maestra publicada por separado reporta una emisión
del 15 de julio de 2026 y 579 certificados; el conjunto extraído del archivo firmado guardado tiene 581
objetos de certificado. Las dos cifras se registran como una discrepancia entre la página pública y el
archivo, sin suponer su causa.

Solo hay un CSCA `C=DO` en esa Lista Maestra guardada. Es el CSCA del pasaporte dominicano con SHA-256
`74237c758a8f894a9a2932fb370da669563647483dfd2616c5332a4f4671e25d` y SKI
`d0d9f1ad5648a4fb141d24c9f7b77ae72176f033`. No coincide con `JCE DS 02` por DN del emisor ni por
AKI/SKI y no puede sustituirlo.

El certificado DS publica `https://ca.jce.gob.do/csca` y `https://ca.jce.gob.do/crl_csca`. Se intentaron
GET de objetos completos, pero no fue posible ninguna conexión HTTP. Una consulta A de DNS sobre HTTPS de
Google guardada devolvió el estado 3 (NXDOMAIN) con el SOA autoritativo de `jce.gob.do`. En consecuencia,
la cadena y la revocación quedan sin resolver, ni fallidas ni buenas. Las respuestas públicas exactas y los
metadatos de transferencia están en `downloads/passive_auth/`.

## Reproducción

```sh
python3 tools/icao/verify_passive_auth.py \
  --cms logs/sessions/session_TEST-01_EF_SOD_FULL/artifacts/assembled_der_001.tag77-value.der \
  --com logs/sessions/session_TEST-01_EF_COM_FULL/artifacts/decrypted_response_002.bin \
  --dg 1=logs/sessions/session_TEST-01_DG1_FULL/artifacts/assembled_der_001.bin \
  --dg 2=logs/sessions/session_TEST-01_DG2_FULL/artifacts/assembled_der_001.bin \
  --dg 7=logs/sessions/session_TEST-01_DG7_FULL/artifacts/assembled_der_001.bin \
  --dg 11=logs/sessions/session_TEST-01_DG11_FULL/artifacts/assembled_der_001.bin \
  --dg 12=logs/sessions/session_TEST-01_DG12_FULL/artifacts/assembled_der_001.bin \
  --dg 13=logs/sessions/session_TEST-01_DG13_FULL/artifacts/assembled_der_001.bin \
  --dg 14=logs/sessions/session_TEST-01_DG14_FULL/artifacts/assembled_der_001.bin \
  --trust-anchor exports/certificates/dominican-republic-icao-masterlist-csca.pem \
  --validation-time 2026-07-12T00:00:00Z \
  --validation-time 2026-08-17T20:35:41Z \
  --json-output lab/PASSIVE_AUTHENTICATION_REPORT.json
```

Código de salida: `0`. El flujo de diagnóstico exacto está guardado en
`lab/PASSIVE_AUTHENTICATION_VERIFIER.stderr.txt`.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
