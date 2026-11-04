<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/factor-landscape-reverse.svg"><img src="docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Reproducción de estos hallazgos

Los hallazgos de este repositorio se produjeron con las herramientas de [`tools/active_adaptive/`](tools/active_adaptive/)
y [`tools/icao/verify_passive_auth.py`](tools/icao/verify_passive_auth.py), ejecutadas contra una
cédula sin contacto mediante un lector PC/SC. Todo es de solo lectura o reversible de forma no destructiva,
salvo indicación contraria.

## Antes de comenzar

- **Ejecute esto únicamente contra una tarjeta que posea legalmente y esté autorizado a probar**, e idealmente
  primero en una tarjeta que usted posea y esté autorizado a probar, nunca en la cédula de un tercero.
- Todas las herramientas usan por defecto una **ejecución en seco**: imprimen el plan exacto de APDU sin acceder a la tarjeta
  ni a credenciales. Nada toca la tarjeta hasta que se pasa `--execute`.
- Las credenciales (CAN, PIN) se ingresan por stdin en tiempo de ejecución, se mantienen solo en memoria y se limpian
  después de su uso. Nunca se escriben en argv, registros ni archivos versionados; no cambie eso
  al adaptar estos scripts.
- La evidencia que escribe este kit (DER sin procesar, trazas de sesión, datos personales decodificados) va a
  `objects/`, `sessions/` y `live_data/`, que deben mantenerse sin versionar y privados. Si hace un fork de este
  repositorio y continúa la investigación: ningún dato de ciudadanos, imágenes ni credenciales debe estar en una
  copia compartida o pública; mantenga esa regla incluso donde los propios scripts no la hagan cumplir.

## Hardware y software necesarios

- Un lector sin contacto compatible con PC/SC (ISO 14443 / ISO 7816).
- Python 3.9+, `pyscard` (enlaces PC/SC) y la biblioteca criptográfica que importe `pace_sm.py`
  (véase su propio encabezado para la dependencia exacta; implementa PACE/SM desde cero en lugar de
  depender de un controlador del proveedor, precisamente para poder emitir APDU que un cliente conforme nunca enviaría).
- `active_adaptive/npa-ca-v1-generic.inc` + `build-chip-auth-generic.sh` para compilar un asistente de
  Chip Authentication independiente de la tarjeta (fija su propio checkout de OpenSC; trate el directorio del checkout como no confiable,
  como indica el encabezado del propio script).

## Ejecución de los niveles, en orden

El orden completo, la justificación («por qué las pruebas negativas establecen la ausencia de errores mejor que las
positivas») y la organización del almacenamiento de evidencia por tarjeta (`objects/<uid>/`, `sessions/<uid>/<ts>_<label>/`,
indexada por el UID ISO14443 de la tarjeta) están en
[`tools/active_adaptive/VALIDATION_PLAN.md`](tools/active_adaptive/VALIDATION_PLAN.md). Resumen:

| Nivel | Script | Qué verifica | Contacto con la tarjeta |
|---|---|---|---|
| 0 | `tier0_csca.py`, `tier0_tamper.py` | Lógica de cadena/revocación del CSCA; detección de manipulación sin conexión sobre objetos en caché | Ninguno |
| 1 | `tier1_readonly.py` | Reproducibilidad de PACE; consultas de estado de PIN que no modifican nada | Solo lectura, sin enviar credenciales |
| 2 | `tier2_negative.py` | Verificaciones de cierre seguro: escrituras, DG3 sin EAC y otras operaciones que la tarjeta debe rechazar | Solo sondeos negativos, sin credenciales, sin tocar contadores |
| 2 (SM) | `tier2_sm_tamper.py` + `pace_sm.py` | Rechazo de manipulación de MAC de SM y rechazo de degradación de algoritmo PACE, desde una pila PACE+SM construida desde cero | APDU deliberadamente malformados; sin tocar contadores |
| 3 | `tier3_authenticated.py` | VERIFY con un PIN que usted posee legítimamente; confirma un cambio de estado solo transitorio | Requiere su propio CAN + PIN por stdin |

Patrón de invocación típico (primero siempre en seco):

```bash
cd tools/active_adaptive
python3 tier1_readonly.py                               # prints the plan, touches nothing
printf '<your CAN>' | python3 tier1_readonly.py --can-stdin --execute
```

Chip Authentication / huella de la tarjeta y reconciliación del SOD:

```bash
python3 chip_auth_prove.py ...        # proves possession of the DG14 CA private key
python3 reconcile_sod.py --can-stdin --execute   # SHA-256-reconciles every readable DG against EF.SOD
python3 card_registry.py --current    # record this card's UID + crypto fingerprint (non-PII)
```

Batería de aseguramiento de RNG/DRBG (usada para los resultados de aleatoriedad relacionados con los hallazgos):

```bash
cd tools/active_adaptive/assurance
python3 collect_rng_n.py ...
python3 rng_battery.py ...
python3 entropy_study.py ...
```

## Verificación independiente de autenticación pasiva

[`tools/icao/verify_passive_auth.py`](tools/icao/verify_passive_auth.py) es un verificador independiente de
autenticación pasiva según ICAO Doc 9303: dados `EF.SOD` y los grupos de datos que cubre, vuelve a derivar y comprueba
de forma independiente los hashes de cada DG y la firma CMS del SOD, sin depender de ninguno del código de gestión de sesión de
`active_adaptive/`. Úselo para contrastar cualquier afirmación de APROBADO/FALLIDO de los informes con objetos DER
sin procesar que usted mismo capture.

## Informes

Los informes en [`report/`](report/) se publican como documentos PDF finales. No se incluye ni se
mantiene un código fuente de composición tipográfica para ellos en este repositorio.

## Lo que NO debería poder reproducir solo con este repositorio

Por diseño, nada de lo siguiente puede reconstruirse a partir de lo publicado aquí:
datos de identidad de ciudadanos, retratos, firmas, PIN/CAN/PUK de alguna tarjeta específica, ni ninguna
clave privada. Si descubre que *puede* reconstruir alguno de ellos a partir del material publicado,
eso es en sí mismo un hallazgo: repórtelo en lugar de publicarlo más.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
