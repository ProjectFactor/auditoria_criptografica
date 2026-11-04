<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Resultado del descubrimiento del ancla de confianza CSCA de la JCE

## Alcance y límite de seguridad

Este documento registra el análisis sin conexión del ancla de confianza del Firmante de Documentos de la
JCE incrustado en el EF.SOD de una tarjeta. Usó evidencia guardada de la tarjeta y colecciones del PKD de la
OACI descargadas localmente. No realizó ninguna conexión PC/SC, comando a la tarjeta, acceso a
credenciales, cambio al almacén de confianza del sistema, solicitud directa ni contacto con personal.

## Ancla de confianza de la JCE requerida

El firmante incrustado `exports/certificates/jce-ds-02.pem` requiere un emisor con esta identidad e
identificador de clave:

| Campo | Valor |
|---|---|
| Sujeto del DS | `C=DO, O=Junta Central Electoral - JCE, OU=DOM, CN=JCE DS 02` |
| Emisor del DS | `C=DO, O=Junta Central Electoral - JCE, CN=JCE CSCA` |
| Serie del DS | `199686BB721AD7689CB5` |
| SKI del CSCA requerido / AKI del DS | `e8090eb7d5c71ffe568f0654a4675af5ea264bb8` |
| URI del CSCA incluida en el DS | `https://ca.jce.gob.do/csca` |
| Punto de distribución de la CRL | `https://ca.jce.gob.do/crl_csca` |
| SHA-256 del DS | `1412267945fdd2d6d196bcc49acff007dd91f61de761b8ab7e0e16bcf327dfb5` |

Coincidir solo con el país o el nombre del emisor es insuficiente. Un candidato debe coincidir con el AKI
del DS y verificar la firma del certificado del DS.

## Alcanzabilidad del ancla y del host de la CRL

Tanto la URI del CSCA como el punto de distribución de la CRL anteriores resuelven al mismo host,
`ca.jce.gob.do`. Una consulta DNS de ese host devuelve **NXDOMAIN** (dominio inexistente): no está
simplemente caído o lento, el nombre no resuelve en absoluto. Esto se verificó repetidamente durante esta
investigación y se reconfirmó con una nueva consulta DNS en vivo al momento de la publicación,
con el mismo resultado NXDOMAIN. Un verificador que
dependa de obtener el CSCA o su CRL desde esta ubicación publicada no puede hacerlo, y no puede
distinguir esa falla de una interrupción transitoria sin conocer de forma independiente el ancla correcta
por otra vía.

## Insumos de la OACI e integridad

Las colecciones LDIF completas coinciden con las sumas SHA-1 mostradas por la OACI:

| Insumo local | SHA-1 | SHA-256 |
|---|---|---|
| `icaopkd-001-complete-10293.ldif` | `872256130cdacaf97216fd2aa4fb8876bbe7fa3a` | `af79c202e0b4ce903847a27b67e6a6fc68e243d27ef983c29e392663783f7b67` |
| `icaopkd-002-complete-527.ldif` | `9868cf6f42acb7e79da3a75faf82b81487e9c487` | `91e73a516942f4537000f86dca965ca7a1fa1ecaf452c9d57ac524876bccdeb0` |

Ninguno de los LDIF tiene una entrada `c=DO`. El CMS de la Lista Maestra que los acompaña,
`ICAO_ML_20260721154956.ml`, tiene SHA-256
`412bdd0c0fe1a06bcbe65c18f4f6429ab1ac52f63907bff5e47e572895bc9b94`.
`openssl cms -verify -binary -inform DER -noverify` valida la integridad de su CMS con su firmante
incrustado y extrae el eContent con SHA-256
`f2921558ed1ccceffeb47c0f38eb623f4ff8acb530fdd975d433fb336aa947a9`.
El resultado con `-noverify` no establece confianza externa en el firmante de la Lista Maestra.

## Certificado dominicano encontrado

La Lista Maestra de 581 certificados contiene exactamente un certificado con país del sujeto `DO`:

| Campo | Valor |
|---|---|
| Sujeto y emisor | `CN=CSCA, OU=Certification Authorities, OU=Passport Emitting Entity, O=Government of Dominican Republic, C=DO` |
| Serie | `529B3550C387DDE9E986FFC146DE106A` |
| Vigencia | 2025-11-05 18:33:37Z hasta 2041-06-05 19:03:37Z |
| SKI / AKI | `d0d9f1ad5648a4fb141d24c9f7b77ae72176f033` |
| SHA-256 del certificado | `74237c758a8f894a9a2932fb370da669563647483dfd2616c5332a4f4671e25d` |
| SHA-256 del SPKI público | `31701ebdcac1c18bfe5d6f49925858d70ba25332529349fb93bc1ceb666579c5` |

Se exporta como `exports/certificates/dominican-republic-icao-masterlist-csca.pem`; los metadatos
completos legibles por máquina están en `evidence/ICAO_MASTER_LIST_DO.json`.

Este no es el CSCA de la JCE requerido: su organización, unidades organizativas y sujeto difieren, y su
SKI `d0d9...f033` no coincide con el AKI del DS de la JCE `e809...4bb8`. Por lo tanto, la verificación
estricta de la cadena con OpenSSL falla con `unable to get local issuer certificate`.

## Conclusión de autenticación pasiva

La evidencia respalda tres resultados distintos:

1. La firma CMS de EF.SOD es matemáticamente válida con su clave pública incrustada del DS de la JCE.
2. Los siete grupos de datos LDS adquiridos coinciden con los hashes firmados en EF.SOD.
3. La confianza externa y la revocación siguen sin establecerse: el CSCA dominicano de la OACI disponible
   es una autoridad distinta, y ningún certificado con el SKI del CSCA de la JCE requerido está en estos
   insumos.

El estado correcto es: **firma y hashes de DG adquiridos válidos; cadena del CSCA de la JCE y revocación
no establecidas**. El resultado de la Lista Maestra es una discrepancia estricta de candidato, no una
prueba de que el CSCA de la JCE no exista en otro lugar.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
