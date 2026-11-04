<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../../docs/brand/factor-landscape-reverse.svg"><img src="../../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Plan de validación de cumplimiento de seguridad de la cédula

Alcance: validar que las medidas de seguridad de la tarjeta se **cumplen** y que no existen errores de
control de acceso ni de integridad, ordenado de la menos a la más intrusiva. Cubre las tarjetas examinadas, incluida una
cédula de producción independiente (UID reservado). Los hallazgos describen
únicamente las tarjetas observadas y no se generalizan a la población emitida.

> **Por qué pruebas negativas.** Una tarjeta que *acepta* una sesión válida no demuestra nada sobre si
> *rechazaría* una falsificada. «Sin errores / medidas cumplidas» se establece principalmente mediante
> pruebas negativas: confirmar que los bloqueos fallan de forma segura (`6982`/`69xx`) y que las
> verificaciones de integridad realmente rechazan entradas manipuladas. Esas son las comprobaciones más
> baratas y más importantes, y se encuentran en los Niveles 0–2.

Leyenda: ✅ ya realizado · 🆕 nuevo aquí · 🔒 requiere cooperación de la JCE.
Toda herramienta en vivo funciona por defecto como **simulacro** (imprime el plan exacto de APDU; sin acceso a tarjeta ni credenciales) y
realiza la sesión solo con `--execute`. El CAN (y, en el Nivel 3, el PIN) se lee de stdin,
se mantiene en memoria, se borra tras su uso y se oculta de cada traza guardada.

### Organización de la evidencia (por tarjeta, por UID)
El ATR DomIDv1 es idéntico entre tarjetas, por lo que la antigua clave `atr[-8:]` colisionaba y sobrescribía evidencia.
Ahora cada tarjeta se identifica por su **UID ISO14443** (`FF CA 00 00 00`, leído antes de cualquier paso de PACE):

```
objects/<uid>/<name>.der          raw DERs (cardsecurity, dg1, p15_4400, b14_011C, ...)
objects/_registry.json            per-card fingerprint registry (card_registry.py)
sessions/<uid>/<ts>_<label>/      traces, profiles, JSON per run
```

Tarjetas examinadas: producción (UID reservado). (Los CAN se ingresan por stdin en
tiempo de ejecución y deliberadamente no se almacenan en este archivo versionado.)
`card_registry.py` registra el SPKI de autenticación de chip de cada tarjeta, EF.CardSecurity + DS y el DS de SOD, de modo que
se distinguen las tarjetas entre sí y se tabula el patrón del DS de desarrollo RSA-1024. Si la lectura del UID falla, la clave
recurre a `atrunk_<atr8>` para que una captura nunca se archive en silencio bajo otra tarjeta.

---

## Nivel 0 — Sin conexión, sin contacto con la tarjeta (intrusión cero)
Prueba si la *lógica* de verificación detecta manipulación. Implementado en `tier0_tamper.py`
(opera sobre DER en caché en `objects/`, ignorado por git; sin tarjeta, sin CAN).

| Prueba | Qué valida | Aprobación |
|---|---|---|
| Manipulación del hash de DG 🆕 | La autenticación pasiva no es un no-op | Cambiar un byte de un DG → discrepancia de hash → la reconciliación **falla** |
| Manipulación de la firma del SOD 🆕 | La verificación de la firma CMS es real | Mutar un byte de la firma → la verificación CMS **falla** |
| Línea base de autenticación pasiva ✅ | Control positivo de integridad | CMS del SOD válido; todos los DG avalados se reconcilian (`reconcile_sod.py`) |
| Cadena CSCA + revocación 🆕🔒 | Confianza del emisor en la Frontera 4 | DS → CSCA de la cédula de la JCE se valida una vez obtenido el CSCA por un canal externo |
| Revisión de fortaleza de algoritmos ✅ | Primitivas obsoletas | Firmante de Documentos RSA-1024 de procedencia de desarrollo señalado (`fingerprint.py`) |

## Nivel 1 — Lectura en vivo, autenticada, sin cambio de estado, sin uso de contadores
Implementado en `tier1_readonly.py`. Una o más sesiones CAN/PACE; cada APDU es una lectura o una
consulta de estado no mutante. Sin VERIFY, sin escritura, sin consumo de reintentos.

| Prueba | Qué valida | Aprobación |
|---|---|---|
| Reproducibilidad de PACE 🆕 | Lectura autenticada determinista | Releer objetos públicos/permitidos produce bytes idénticos |
| Estado de PIN no mutante 🆕 | Visibilidad del contador sin gastarlo | `00 20 00 <ref>` → `63Cx`, y una repetición devuelve el **mismo** contador (sin decremento) |
| Barrido de fuga de información ✅ | Sin PII legible oculta | El barrido SFI/FID/AID expone solo archivos públicos (`explore_full_sweep.py`, `explore_domrepeid.py`) |

Referencias de PIN esperadas: Usuario `0x83`, SO `0x84`, PIN de firma `0x92`, PUK de firma `0x93`.

## Nivel 2 — Sondeos negativos de control de acceso (cierre seguro), sin enviar secretos
Implementado en `tier2_negative.py`. Una sesión CAN/PACE, `npa-tool` estándar (continúa tras respuestas distintas de 9000).
Cada sondeo **espera una denegación**; una respuesta `9000`/con datos es un **FALLO (posible error)**. No se envía ninguna credencial
y no se toca ningún contador de PIN.

| Sondeo | Esperado (aprobación) | Cómo se vería un error |
|---|---|---|
| Escritura: `UPDATE BINARY` sobre un EF de solo lectura | `6982`/`6985`/`6A82` | `9000` (escritura aceptada) |
| Escritura: `CREATE FILE` | `6982`/`6985` | `9000` |
| Escritura: `PUT DATA` | `6982`/`6985` | `9000` |
| `SELECT` + leer DG3 sin EAC | `6982` | se devuelven datos |
| Leer un DG protegido **sin SM** (texto plano tras PACE) | rechazado / `69xx` | se devuelven datos en texto plano |
| Manipulación de SM (MAC corrupto) ✅ | `6987`/`6988` | el comando se procesa |
| Degradación: suite PACE/CA más débil que la anunciada ✅ | rechazada | aceptada |

**Confirmado:** `npa-tool --translate` *siempre* construye el envoltorio SM (un comando `CLA=00`
en texto plano se envuelve en SM silenciosamente y tiene éxito), por lo que no puede enviar una APDU en texto plano,
con MAC manipulado ni degradada. Por ello, los tres seguimientos se dividen así:
- **`tier2_raw.py` 🆕 — el canal seguro es obligatorio (factible ahora, sin necesidad de PACE).** PC/SC directo, sin
  npa-tool: lee EF.CardAccess (control público → se devuelven datos) pero confirma que EF.COM, DG1 y una escritura
  son todos rechazados sin PACE (observado `6986`/`6986`/`6982`). APROBACIÓN = los datos protegidos son inalcanzables
  sin el canal seguro. Esta es la comprobación de cumplimiento «SM obligatorio» de más bajo nivel.
- **`pace_sm.py` + `tier2_sm_tamper.py` 🆕 — manipulación del MAC de SM y degradación de PACE (HECHO).**
  Un handshake PACE-ECDH-GM-AES-256 desde cero sobre NIST P-384 (`pace_sm.py`, sin npa-tool/OpenSC)
  deriva por sí mismo `K_enc`/`K_mac`/SSC, por lo que podemos emitir APDU que el cliente real nunca emitiría. Verificado
  en la **cédula de producción** (UID reservado):
  - *Control positivo* — PACE establecido; la lectura SM del EF.CardAccess público se descifra a los bytes exactos
    leídos en bruto (auto-valida la pila SM en ambos sentidos) → `9000`.
  - *Manipulación del MAC de SM* — un byte del MAC corrompido → `6988`; DO8E eliminado → `6982`. **MAC exigido.**
  - *Degradación de PACE* — MSE:Set AT solicitando AES-128, 3DES y AES-256 sobre P-256, cada uno **rechazado con
    `6A80`** (sin intentar GENERAL AUTHENTICATE, por lo que no se toca ningún contador de contraseña). **Sin degradación.**
  Autoverificación criptográfica sin conexión: `python3 pace_sm.py --selftest`. Informe: `reports/`.

## Nivel 3 — Operaciones autenticadas con credenciales que usted posee legítimamente (solo estado transitorio)
Implementado en `tier3_authenticated.py`. **Requiere el PIN en poder del usuario por stdin** (línea 2, tras el CAN en
la línea 1); el PIN se borra y se oculta de las trazas. Cambia solo el estado de seguridad transitorio (se reinicia al apagar);
ningún cambio persistente. Un VERIFY por referencia, nunca un bucle de reintentos, protegido por una
confirmación explícita `--i-hold-this-pin` para que la herramienta no pueda usarse para fuerza bruta.

| Prueba | Qué valida | Aprobación |
|---|---|---|
| `VERIFY` del PIN de Usuario/SO en su poder 🆕 | La credencial es correcta; la compuerta se abre | `9000`; una consulta de estado posterior muestra el contador **de nuevo completo** (un verify exitoso lo restablece) |
| Control de acceso de operaciones de clave en la Frontera 8 🆕 | El uso de la clave `0x42` está bloqueado por el estado del DF | Tras verificar el PIN de Usuario, `MSE:SET`+`INTERNAL AUTHENTICATE` sobre `0x42` → **denegado** (esperado `6982`, DF `5015` en init `0x03`); `9000` sería una capacidad inesperada |
| Repetición de Autenticación de Chip ✅ | Posesión / resistencia a clonación | Un handshake CA nuevo deriva claves SM funcionales (`chip_auth_prove.py`) |

Seguridad: es seguro ejecutarlo en la cédula de producción (solo lectura/transitorio). El sondeo de operación de clave espera una denegación;
sus bytes `MSE` exactos son de mejor esfuerzo, por lo que la herramienta reporta el SW en bruto y clasifica solamente
`denegado (6xxx)` frente a `ÉXITO INESPERADO (9000)`.

---

## Nivel 4 — Requiere secretos/cooperación del emisor 🔒 (no implementado aquí)
- Autenticación de Terminal EAC con una cadena CVC real CVCA→DV→terminal → leer DG3.
- Canal seguro GlobalPlatform con claves ISD.
- Autenticación externa 3DES (referencia de clave `0x21`).
- Inscripción completa de firma + firma calificada con el PIN de firma entregado + certificado.

## Nivel 5 — Hardware / físico 🔒⚠️ (fuera de alcance)
Canal lateral (tiempo/consumo), inyección de fallos / glitching, ataques invasivos al chip. Destruye tarjetas;
requiere un laboratorio de seguridad de hardware y autorización legal/ética explícita. Se lista para marcar el techo.

---

## Cómo ejecutar (Niveles 0–3)

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

Las herramientas en vivo se niegan a iniciar sin el socket PC/SC y sin `--can-stdin`. Los artefactos de sesión se
escriben en `sessions/`, ignorado por git; los bytes en bruto de la tarjeta (si los hay) permanecen en `objects/`, ignorado por git.
Cada herramienta imprime un resumen APROBADO/FALLIDO (PASS/FAIL) y un informe JSON.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
