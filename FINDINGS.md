<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/factor-landscape-reverse.svg"><img src="docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Cédula — Los 3 hallazgos principales y posibles ataques

- **Estado:** Informe de hallazgos
- **Autor:** FACTOR Inc. (brazo comercial del Proyecto FACTOR) — Juan Vargas, CEO
- **Alcance:** cédulas de producción emitidas desde principios de 2026 hasta septiembre de 2026, examinadas con el permiso de sus titulares.
- **Credenciales:** los CAN y PIN se ingresaron en tiempo de ejecución y nunca se almacenaron.

## Cómo leer los colores

- 🔴 **Defecto confirmado**
- 🟠 **Incertidumbre o brecha de confianza**
- 🟡 **Condicional:** depende del verificador
- 🟢 **Una verificación específica y nombrada fue superada** en la(s) tarjeta(s) indicada(s). No significa "seguro", "certificado" ni "confiable", y no dice nada sobre tarjetas o ataques no probados.

Siempre se mantienen separados cuatro aspectos: **integridad de la firma**, **confianza en el emisor**, **fortaleza del algoritmo** y **procedencia de desarrollo/producción**.

**Contenido:** [Hallazgo 1: firmante de desarrollo RSA-1024](#finding-1) · [Hallazgo 2: brecha de confianza del CSCA](#finding-2) · [Hallazgo 3: verificaciones superadas](#finding-3) · [Recomendación: auditoría completa](#full-audit) · [Cadenas de ataque](#attack-chains) · [Resumen](#summary)

Cada hallazgo tiene las mismas partes: lo que encontramos, posición regulatoria, contexto criptoanalítico y los ataques que puede habilitar.

---

<a id="finding-1"></a>
## Hallazgo 1 — 🔴 Firmante de Documentos (DS) de "desarrollo" RSA-1024 en `EF.CardSecurity`

> **En lenguaje sencillo.** Una de las firmas digitales dentro del chip de la cédula usa una clave demasiado débil para los estándares actuales, y además es una clave de *prueba* que el fabricante del chip creó para desarrollo, no una clave hecha específicamente para la JCE. Quien obtenga esa clave, ya sea al encontrarla en material del proveedor o al romperla, puede producir firmas que las propias verificaciones del chip darán por válidas.

Secciones: [Lo que encontramos](#f1-found) · [Posición regulatoria](#f1-reg) · [Contexto criptoanalítico](#f1-crypto) · [Ataques que habilita](#f1-attacks) · [Brecha de aseguramiento](#f1-process) · [Escala y reemisión](#f1-reissue) · [Límites](#f1-limits)

<a id="f1-found"></a>
### Lo que encontramos

**Hecho observado.** `EF.CardSecurity` está firmado por un Firmante de Documentos que usa **RSA-1024** con procedencia **`cryptovision/development`** (SHA-256 del objeto completo `09b130…`, certificado `4eb279…`), verificado de forma independiente byte por byte en una tarjeta de producción. El mismo certificado estaba presente en todas las tarjetas de producción examinadas, emitidas desde principios de 2026 hasta septiembre de 2026.

**Por qué importa.** Dos debilidades independientes se acumulan en una sola clave:
- **Fortaleza del algoritmo:** RSA-1024 está obsoleto y al alcance de un adversario con muchos recursos (a escala de un Estado).
- **Procedencia:** un firmante de *desarrollo* implica que la clave privada podría venir incluida en el SDK o material de muestra del proveedor; es decir, sería prácticamente pública, sin necesidad de factorizar nada.

<a id="f1-reg"></a>
### Posición regulatoria

**Obsolescencia regulatoria — no es una decisión discutida ni marginal.** RSA-1024 ha sido declarado formalmente
obsoleto por los organismos de normalización que fijan la política criptográfica de los sistemas gubernamentales y de
infraestructura crítica, años antes de que se emitiera esta tarjeta:

- **NIST** (EE. UU.): [SP 800-131A Rev. 2, "Transitioning the Use of Cryptographic Algorithms and Key
  Lengths"](https://doi.org/10.6028/NIST.SP.800-131Ar2) dejó de permitir RSA de 1024 bits para generar
  firmas digitales después de 2013. [SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management"](https://doi.org/10.6028/NIST.SP.800-57pt1r5)
  califica a RSA de 1024 bits con solo **80 bits de fortaleza de seguridad** —por debajo del mínimo de 112 bits que NIST
  exige para cualquier uso actual— y fija 2048 bits como el módulo RSA mínimo aceptable.
- **Europa:** [ENISA, "Algorithms, Key Sizes and Parameters Report"](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014)
  clasifica RSA de 1024 bits como heredado/insuficiente y recomienda un mínimo de 3072 bits para sistemas nuevos.
  El **BSI** de Alemania (Bundesamt für Sicherheit in der Informationstechnik), [TR-02102-1,
  "Cryptographic Mechanisms: Recommendations and Key Lengths"](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/BSI-TR-02102.html),
  establece un módulo RSA mínimo de 3000 bits para despliegues nuevos y no considera aceptable el de 1024 bits
  en ningún período de retención.
- **Industria/PKI web, como un plazo concreto que ya venció:** los Baseline Requirements del CA/Browser Forum
  prohibieron a las autoridades certificadoras emitir nuevos certificados TLS RSA de 1024 bits
  **a partir del 1 de enero de 2014**, más de una década antes de la emisión de esta tarjeta.
- **El patrón es el mismo en todos los lugares que un programa de cédula nacional debería mirar:** todo organismo
  que publica mínimos criptográficos para credenciales de nivel gubernamental fijó el piso en 2048
  bits (NIST) o más (ENISA, BSI) hace más de diez años. No existe hoy ningún organismo de normalización
  que avale RSA de 1024 bits para la clave de firma de un documento de identidad.

*(Los identificadores de documentos y los enlaces anteriores deben verificarse de forma independiente contra las
revisiones vigentes publicadas antes de basarse en este informe para una decisión de adquisición o legal; cite
la sección y la página exactas en cualquier presentación formal.)*

<a id="f1-crypto"></a>
### Contexto criptoanalítico

**Qué tan lejos está esto de lo teórico.** La fortaleza de las claves RSA no es un
riesgo abstracto; se está erosionando públicamente, en pasos medibles, y el ritmo se ha
acelerado bruscamente en fechas recientes:

- **RSA-240** (795 bits, 240 dígitos decimales) — factorizado en **noviembre de 2019** por Boudot, Gaudry,
  Guillevic, Heninger, Thomé y Zimmermann, usando la Criba General del Cuerpo de Números (GNFS); publicado como
  "Comparing the Difficulty of Factorization and Discrete Logarithm: a 240-Digit Experiment"
  (CRYPTO 2020).
- **RSA-250** (829 bits, 250 dígitos decimales) — factorizado en **febrero de 2020** por el mismo equipo,
  el siguiente récord de la misma serie.
- **RSA-260** (862 bits, 260 dígitos decimales) — factorizado el **3 de septiembre de 2026** por Eric Lu
  (Cognition), usando una canalización CADO-NFS modificada y acelerada por GPU; costo reportado del orden de
  13,5 años-GPU (~4900 días-GPU), aproximadamente US$400 mil a precios de mercado de alquiler de GPU.
- **RSA-896** (896 bits, 270 dígitos decimales) — factorizado el **19 de septiembre de 2026**, apenas 16 días
  después, por Stephen A. Weis, usando un port de CADO-NFS a GPU ejecutado en hasta 2048 GPU durante unos 10
  días (~30 años-GPU) de *capacidad de cómputo ociosa y aprovechada*; es decir, ciclos sobrantes que de otro modo
  no se habrían usado, no una compra dedicada.

**Lo que cambió entre los récords de 2019–2020 y los de septiembre de 2026 es el ritmo, no solo
el tamaño.** Pasar de RSA-240 a RSA-250 tomó tres meses en 2019–2020, y luego pasaron más de cinco
años sin otro récord público. Después, solo en septiembre de 2026, el récord saltó dos veces —
RSA-260 y luego RSA-896— con apenas 16 días de diferencia, cada uno con herramientas aceleradas por GPU. RSA-896 se ejecutó
con capacidad ociosa, no con un presupuesto dedicado, lo cual es una barrera sustancialmente menor que
"un equipo bien financiado gastando dinero"; se acerca más a "el cómputo que una organización grande
ya posee y que no está usando esta semana".

**Para ser precisos y no exagerar:** ningún récord público establece que un módulo RSA de 1024 bits
(309 dígitos decimales) haya sido factorizado; RSA-896, el récord público actual, todavía
está 128 bits (unos 39 dígitos decimales) por debajo. Lo que establecen los récords de septiembre de 2026
es que la *brecha se cerró en más de 100 bits en dos semanas y media*, usando solo cómputo
ocioso y un equipo de escala académica o de startup, no un presupuesto estatal. Las estimaciones publicadas de escalamiento
de costos de la Criba General del Cuerpo de Números ubicaban un esfuerzo dedicado de factorización de 1024 bits al alcance
de una institución bien financiada o de un Estado mucho antes de esta aceleración; después de ella, esa
estimación debe tratarse como un techo, no como una garantía. Combinado con la **procedencia de
desarrollo** de esta clave específica —que elimina la necesidad de factorizar nada si la
clave privada es recuperable a partir del material del proveedor—, RSA-1024 como clave de firma de producción de un documento de identidad
no es una debilidad marginal ni teórica; es un algoritmo de una clase conocida como rota,
cuyo plazo concreto de retiro, según todos los organismos de normalización relevantes, venció hace
una década o más.

<a id="f1-attacks"></a>
### Ataques que este hallazgo puede habilitar

Cada ataque a continuación requiere que el atacante obtenga primero la clave de firma (de material del proveedor o factorizándola) **y** otros componentes, indicados en cada punto. Ninguno se llevó a cabo; son modelos de ataque, no demostraciones.

1. **Falsificar la prueba de "soy genuino" del chip (Chip Authentication).** El firmante RSA-1024 avala la clave anticlonación del chip en `EF.CardSecurity`. Con la clave, un atacante puede firmar un reemplazo que nombre una clave que él controla.
   *También requiere:* una copia de los datos legibles de una tarjeta en una tarjeta en blanco o un emulador, y un verificador que compruebe Chip Authentication y acepte este firmante.
   *Resultado:* una tarjeta clonada supera la verificación que existe precisamente para detectar clones.
2. **Datos de identidad editados en una tarjeta clonada, si un verificador confía en este firmante para identidad.** Normalmente los datos de identidad (`EF.SOD`) están firmados por una clave EC de producción distinta, por lo que esto no funciona. Sí funciona si un verificador o su lista de confianza acepta este certificado RSA-1024 como firmante válido de datos de identidad.
   *También requiere:* un verificador así (por mala configuración, o una lista de confianza que incluya la CA de desarrollo), además de la tarjeta clonada del ataque 1. 🟡 Depende del verificador.
3. **Falsificación que en la práctica no se puede revocar.** El certificado es válido de 2019 a 2079, y no encontramos una vía de revocación para él. El host de CRL de la propia JCE tampoco resuelve (Hallazgo 2). Si la clave se filtra, podría no haber una forma efectiva de indicar a los verificadores que dejen de confiar en ella.
   *También requiere:* que la clave se filtre o sea rota; un verificador que compruebe la revocación (o que falle abierto cuando no puede).
4. **Compromiso de clave sin conexión e indetectable.** No encontramos la clave, y no está establecido si existe en el SDK o material de muestra del proveedor. Si existe, puede estar ya en otras manos. Usarla no requiere contacto con ninguna tarjeta ni sistema de la JCE, por lo que no dejaría rastro.
   *También requiere:* solo la clave y un verificador que acepte el firmante.

<a id="f1-process"></a>
### Brecha de aseguramiento: una clave de desarrollo llegó a producción

Una clave de **desarrollo** de un proveedor está firmando una credencial nacional de identidad. Una revisión criptográfica independiente habría detectado esto antes de la emisión. Que llegara a producción indica una brecha en el aseguramiento criptográfico del proceso, no un error de una sola persona.

**Observado**
- El certificado se identifica a sí mismo con `OU=development`. Su emisor es una CA de desarrollo.
- Usa RSA-1024, obsoleto desde hace más de una década.
- Es válido hasta 2079.
- Aparece en tarjetas emitidas desde principios de 2026 hasta septiembre de 2026.
- Lo encontramos leyendo un archivo público con un lector comercial y decodificando el certificado. Eso toma minutos y no requiere acceso interno.

**Conclusión** (nuestra inferencia a partir de la evidencia; no se vieron los registros internos de la JCE)
- El proceso de aceptación que existiera no incluyó una revisión criptográfica capaz de detectar esto.
- El defecto estuvo presente en todas las tarjetas que examinamos durante todo el período de emisión, desde principios de 2026 hasta septiembre de 2026.
- El Hallazgo 2 es del mismo tipo: un ancla de confianza publicada que no resuelve, sin que se detectara.
- Dos defectos independientes de este tipo apuntan a una brecha de aseguramiento en el proceso, no a un error aislado.

**Lo que una revisión criptográfica habría comprobado, antes de emitir una sola tarjeta**
- Tamaño de clave y algoritmo de cada firmante frente a los estándares vigentes.
- Procedencia de cada clave de firma: quién la generó, dónde y bajo qué ceremonia.
- Que no haya ninguna clave o certificado de desarrollo, prueba o muestra en producción.
- Que cada ancla de confianza publicada y cada URL de revocación resuelva y esté fijada (pinned).
- Que los objetos emitidos en la tarjeta se verifiquen contra la cadena de producción prevista, de extremo a extremo.

**Recomendación**
- Contratar **criptógrafos** calificados, independientes del proveedor de las tarjetas, para auditar la ceremonia de claves y la cadena de emisión.
- Hacer de esa auditoría una **compuerta previa a la emisión**, y repetirla ante cada cambio de proveedor, firmware o clave.
- Tratar la infraestructura de firma de una cédula nacional como infraestructura criptográfica crítica. No puede certificarse solo con papeleo de adquisiciones. Necesita personas que sepan leer el certificado y entender lo que ven.

<a id="f1-reissue"></a>
### Escala: ¿es necesario reemitir todas las cédulas?

**Cuántas tarjetas existen**
- **4,009,576** nuevas cédulas entregadas, de **8,730,372** personas habilitadas ([Diario Libre](https://www.diariolibre.com/politica/jce/2026/10/13/jce-supera-los-cuatro-millones-de-cedulas-entregadas/3688288), [Infobae](https://www.infobae.com/republica-dominicana/2026/10/16/junta-central-electoral-dominicana-alcanza-los-4-millones-de-nuevas-cedulas-emitidas-y-pide-renovar-antes-de-abril-de-2027/)). La JCE reporta además 196,310 documentos entregados en el exterior.
- La JCE fijó un período de cedulación masiva, tras el cual la cédula anterior dejará de ser aceptada.
- Por lo tanto, quedan por emitir hasta unos **4.7 millones** de tarjetas (8,730,372 − 4,009,576). Es nuestra aritmética sobre las cifras de la JCE, no una cifra de la JCE.
- Nuestro examen cubre solo tarjetas emitidas hasta septiembre de 2026, y no puede establecer cuántas de los 4.0 millones llevan el firmante de desarrollo.

**Respuesta corta: decidir después de una auditoría completa.** Esta investigación usó solo información pública. No puede descartar otras fallas, por lo que la decisión de reemisión debe esperar a la auditoría respaldada por la JCE recomendada [más abajo](#full-audit). No recomendamos hoy una reemisión generalizada de todas las tarjetas. Recomendamos este orden:

1. **Detener primero la línea.** Que toda tarjeta aún por personalizar use un firmante de producción, verificado por un laboratorio independiente. Reemitir tarjetas con el mismo defecto solo lo repetiría.
2. **Averiguar cuántas tarjetas están afectadas.** Muestreo independiente por lotes, sitios y fechas. El objeto es idéntico en todas las tarjetas que examinamos, por lo que probablemente sea una plantilla estática, pero eso no está establecido.
3. **Averiguar si las tarjetas ya emitidas se pueden corregir sin reemplazarlas.** Preguntar al proveedor y a un laboratorio independiente si el emisor puede reemplazar `EF.CardSecurity` en una tarjeta terminada mediante una actualización autorizada. No lo probamos: nuestro lector no puede escribir, y las escrituras por el canal público son rechazadas.
   - **Si es posible:** actualizar las tarjetas en puntos de servicio o en la renovación normal. Sin reemisión.
   - **Si no es posible:** reemitir solo las tarjetas afectadas, sin costo para los ciudadanos, con el proveedor asumiendo el costo donde el contrato lo permita.
4. **Proteger a los verificadores mientras tanto.** No agregar el certificado de desarrollo a ninguna lista de confianza. No depender únicamente de Chip Authentication como verificación anticlonación para decisiones de alto valor. Fijar (pin) las raíces de producción.

**Por qué una reemisión generalizada no es la primera respuesta**
- El defecto es una firma sobre un objeto del lado del emisor, no las claves, PIN o datos de identidad de los ciudadanos. En nuestras pruebas los datos de identidad están firmados por una clave EC de producción separada, y la clave anticlonación de cada tarjeta es distinta.
- Reemitir no elimina por sí solo el firmante débil, que también está en tarjetas aún no emitidas.
- Una reemisión masiva junto con la renovación masiva en curso sumaría carga sobre las mismas oficinas y el mismo plazo.

**Qué cambiaría esto a "reemitir todas"**
- Que se demuestre que otros pueden recuperar la clave privada de desarrollo, **y**
- que las tarjetas emitidas no puedan actualizarse, **y**
- que las partes confiantes dependan de Chip Authentication para detectar clones.

Las tres condiciones juntas justificarían reemplazar todas las tarjetas afectadas, comenzando por las usadas para decisiones de mayor valor.

<a id="f1-limits"></a>
### Límites

**Frontera.** Este DS firma `EF.CardSecurity` (Chip Authentication / objetos de seguridad) — **no** el objeto de integridad de identidad (véase Hallazgo 3 / `EF.SOD`).

**Salvedad.** Este hallazgo está confirmado en todas las tarjetas examinadas, emitidas desde principios de 2026 hasta
septiembre de 2026. Este informe no afirma que toda cédula emitida alguna vez lleve este firmante, solo que
ninguna tarjeta examinada hasta ahora está exenta.

---

<a id="finding-2"></a>
## Hallazgo 2 — 🟠 Brecha de confianza del CSCA de la JCE (la confianza de la autenticación pasiva no se puede validar de forma independiente)

> **En lenguaje sencillo.** Los datos de identidad de la cédula están correctamente firmados, pero la dirección web donde se supone que se publica el certificado raíz de la JCE no existe. Por lo tanto, un verificador no puede confirmar que la firma encadena hasta la JCE verdadera. La firma está intacta; lo que falta es una raíz alcanzable y fijada (pinned) que demuestre quién firmó.

Secciones: [Lo que encontramos](#f2-found) · [Posición regulatoria](#f2-reg) · [Contexto criptoanalítico](#f2-crypto) · [Ataques que habilita](#f2-attacks)

<a id="f2-found"></a>
### Lo que encontramos

**Hecho observado.** `EF.SOD` está firmado por **JCE DS 01** (`C=DO, O=Junta Central Electoral - JCE, OU=DOM`, EC con parámetros explícitos / SHA-384, válido 2026-04 → 2036; certificado `4a31c811…`) — una vía de integridad de identidad de nivel de producción. El DS encadena al CSCA de la cédula de la JCE (AKI `e8090eb7…`), pero la URI del ancla publicada **`https://ca.jce.gob.do/csca` devuelve NXDOMAIN**. El único CSCA presente en disco es el CSCA del pasaporte (SKI `d0d9f1ad…`), un ancla distinta. El resultado NXDOMAIN para la URI del ancla publicada fue reconfirmado de forma independiente en toda la muestra (es una verificación contra un registro público de DNS/PKI, no una propiedad de cada tarjeta, por lo que no depende de qué tarjeta específica se esté verificando), y reconfirmado nuevamente al momento de la publicación: una consulta DNS en vivo de `ca.jce.gob.do` el **2026-11-02 (21:01 AST / 01:01 UTC del 2026-11-03)** sigue devolviendo NXDOMAIN. El mismo host sirve además el punto de distribución de CRL del DS (`https://ca.jce.gob.do/crl_csca`), por lo que esa vía de verificación de revocación es inalcanzable por la misma razón.

**Por qué importa.** Los verificadores que obtienen el CSCA en tiempo de ejecución no pueden anclar la cadena a una raíz de confianza. La integridad de la firma está intacta; **la confianza en el emisor no se puede verificar** contra una autoridad alcanzable. Esta brecha se confirmó presente en todas las tarjetas de la muestra.

<a id="f2-reg"></a>
### Posición regulatoria

ICAO Doc 9303 (Partes 11 y 12) define Passive Authentication como la validación del certificado del Firmante de Documentos hasta una raíz de confianza del país (el CSCA), con el estado de revocación comprobado cuando esté disponible. Una raíz que no se puede obtener hace imposible realizar esa validación a partir de fuentes públicas. *La parte, sección y página exactas deben confirmarse contra la edición vigente antes de citar esto en una presentación formal.*

<a id="f2-crypto"></a>
### Contexto criptoanalítico

Ninguno. Este no es un problema de algoritmo débil. La firma de `EF.SOD` usa EC con SHA-384 y se verifica correctamente. La brecha es la falta de infraestructura de confianza publicada, por lo que no hace falta romper nada para que importe.

<a id="f2-attacks"></a>
### Ataques que este hallazgo puede habilitar

1. **Los verificadores fallan abiertos y aceptan un firmante sin ancla.** El software que no puede obtener la raíz puede omitir la verificación de la cadena, o confiar en cualquier firmante que presente la tarjeta.
   *También requiere:* un verificador escrito de esa manera. Un firmante falsificado o autofirmado es entonces aceptado, sin comprometer ninguna tarjeta.
2. **Alguien más suministra la "raíz".** La dirección publicada no resuelve, por lo que quien pueda hacer que ese nombre resuelva (secuestro de DNS, o un descuido en el registro) podría servir una raíz o una lista de revocación a los verificadores que la obtienen en tiempo de ejecución.
   *También requiere:* control de ese nombre DNS y verificadores que obtengan la raíz sin fijarla (pinning). No probado.
3. **La revocación no se puede entregar.** La lista de revocación del firmante vive en el mismo host inexistente. Un firmante comprometido, incluida la clave del Hallazgo 1, no podría revocarse de una forma que los verificadores puedan ver.
   *También requiere:* un firmante comprometido.
4. **Tarjetas legítimas rechazadas (disponibilidad).** Los verificadores que fallan cerrados rechazarán cédulas genuinas porque no pueden anclar la cadena.
   *También requiere:* nada más allá del host inalcanzable. Esto perjudica a ciudadanos y partes confiantes en lugar de habilitar fraude.

---

<a id="finding-3"></a>
## Hallazgo 3 — 🟢 Verificaciones nombradas de integridad y protocolo superadas en las tarjetas probadas

> **En lenguaje sencillo.** Intentamos varias formas de manipular la tarjeta y su canal seguro. En las tarjetas que examinamos en profundidad, las pruebas específicas enumeradas a continuación no tuvieron éxito. Esto es un registro de lo que intentamos, no una garantía de seguridad.

Posición regulatoria y contexto criptoanalítico: no aplican. Son resultados de pruebas, y los algoritmos involucrados (AES-256, NIST P-384, SHA-384) están vigentes. **Ataques que este hallazgo habilita:** ninguno. Enumera los ataques que se intentaron y fallaron, en [Ataques en los que nuestras pruebas no tuvieron éxito](#tests-failed).

**Nota de alcance.** A diferencia de los Hallazgos 1 y 2, estas verificaciones requirieron una sesión PACE/SM desde cero
y una ejecución de validación por niveles completa, que solo se realizó con captura completa de evidencia en un subconjunto
de las tarjetas examinadas — véase `report/mapa_limites_seguridad_cedula.pdf`
para lo que se probó con ese nivel de detalle.

**Qué significa 🟢 en este hallazgo.** Cada punto a continuación es una prueba específica que se superó en las tarjetas examinadas con este nivel de detalle. No se afirma nada más.

**Hechos observados (en las tarjetas examinadas con este nivel de detalle).**
- 🟢 **Passive auth, solo integridad de la firma:** firma CMS de `EF.SOD` válida; **7/7 DG legibles (1,2,7,11,12,13,14) concilian** con SHA-256; DG3 protegido por EAC/omitido.
- 🟢 **Chip Authentication, solo en estas tarjetas:** posesión demostrada en vivo; la clave CA del DG14 es **única por tarjeta** (la clave anticlonación difiere entre tarjetas).
- 🟢 **Escrituras rechazadas por el canal CAN/PACE:** UPDATE BINARY / CREATE FILE → `6982`, PUT DATA → `6A81`, DG3-sin-EAC → `6986`.
- 🟢 **Secure Messaging, en nuestro banco de pruebas:** la pila PACE+SM construida desde cero resiste la **alteración del MAC** (`6988`/`6982`) y la **degradación** (AES-128 / 3DES / curva débil, cada una rechazada con `6A80`, juzgada en MSE:Set AT sin tocar ningún contador).
- 🟢 **Contadores de reintentos de PIN:** presentes y reportados correctamente mediante consultas de estado no mutantes. No se atacaron los PIN ni se intentó fuerza bruta.
- 🟢 Los Niveles 0–3 del plan de validación se superaron en estas tarjetas.

**Qué NO significa 🟢 aquí.**
- **No** significa confianza en el emisor: la firma de `EF.SOD` es válida, pero la cadena no pudo anclarse a un CSCA alcanzable (Hallazgo 2).
- **No** significa que la tarjeta sea segura en general, ni que otras tarjetas, versiones de firmware o comandos no probados sean seguros.
- **No** cubre `EF.CardSecurity`, cuyo firmante es el defecto del Hallazgo 1.
- "Rechazado" y "bloqueado" describen las pruebas que ejecutamos, no una prueba de que no exista ningún ataque.

**Por qué importa.** En las tarjetas examinadas con este nivel de detalle, nuestras pruebas no encontraron una forma de manipular los datos en la tarjeta, romper la sesión de Secure Messaging ni eludir los límites de reintentos de PIN. Eso acota dónde miramos a continuación, para esas tarjetas, a la procedencia de la clave de firma y al anclaje de la cadena de confianza — las dos propiedades (Hallazgos 1 y 2) que *sí* se confirmaron en la muestra más amplia.

---

<a id="full-audit"></a>
## Recomendación: una auditoría completa, encargada y respaldada por la JCE

**Recomendamos enfáticamente que la JCE encargue una auditoría criptográfica independiente completa, con su propia autoridad detrás.**

**Por qué nuestros hallazgos no son suficientes**
- Todo lo aquí expuesto se encontró desde afuera, usando información pública e interfaces de tarjeta estándar.
- No tuvimos acceso a registros de la JCE, ceremonias de claves, hardware de firma, código fuente, documentación del proveedor ni registros de emisión.
- Tres hallazgos obtenidos desde afuera sugieren que puede haber otros que no podemos ver. La brecha de aseguramiento del Hallazgo 1 es la razón más fuerte.
- Nuestra cobertura de tarjetas es limitada, y las verificaciones de protocolo no se ejecutaron en todas las tarjetas.
- "No se encontró nada más" significa solamente que no pudimos mirar más allá.

**Lo que solo la JCE puede abrir**
- Registros de generación y custodia de cada clave de firma, incluido el historial de la clave de desarrollo.
- El perfil de tarjeta aprobado, el software de personalización y la configuración de firma.
- Qué tarjetas, lotes y sitios llevan cada configuración, y cuántas.
- Si las tarjetas emitidas se pueden actualizar, y mediante qué proceso autorizado.
- Qué verificadores consumen los objetos de la tarjeta, y cómo se comportan ante un firmante no confiable.
- Registros del proveedor y de pruebas de aceptación.

**Lo que debería hacer la auditoría**
- Estar liderada por criptógrafos calificados e independientes, y no solo por el proveedor de las tarjetas o el integrador del sistema.
- Trabajar bajo la autoridad de la JCE, con acceso a los registros anteriores y lecturas presenciadas de tarjetas de distintos lotes.
- Reportar a la dirección de la JCE y publicar un resumen de sus hallazgos y del plan correctivo.
- Decidir la cuestión de la reemisión con base en sus resultados, no antes.

**Independencia.** Esta recomendación vale con independencia de quién realice la auditoría y no está condicionada a ninguna contratación de FACTOR Inc. (véase la declaración de intereses). Las herramientas, la evidencia y los informes de este repositorio están a disposición de quien la realice como punto de partida. Los datos de contacto están en [Sobre el autor](README.md#sobre-el-autor).

---

<a id="attack-chains"></a>
## Cadenas de ataque que combinan los hallazgos

Los ataques de cada hallazgo se enumeran bajo cada uno. Estas cadenas los combinan.

Cada una es una clase de ataque *condicional* con precondiciones explícitas; ninguna es inmediata.

### A. `EF.CardSecurity` falsificado → derrota de la garantía anticlonación de Chip Authentication
**Cadena:** Hallazgo 1 + Hallazgo 2.
`EF.CardSecurity` (que porta la clave pública CA) está firmado por el DS de desarrollo RSA-1024. Precondiciones para falsificar:
- **Recuperación de la clave de desarrollo** (lo más realista): clave privada obtenida del material de desarrollo del proveedor; o
- **Factorización** de RSA-1024 (esfuerzo a escala de un Estado).

Con la clave del DS, un atacante vuelve a firmar un `CardSecurity` que presenta una clave CA que él controla y construye un chip clonado/emulado que **supera Chip Authentication** — exactamente la garantía que CA existe para ofrecer. Solo prospera si el verificador acepta ese DS (véase B).

### B. Degradación de confianza del verificador / aceptación con falla abierta
**Cadena:** Hallazgo 2, amplificando A.
Como el CSCA es inalcanzable, los verificadores que lo obtienen en tiempo de ejecución tienden a **fallar abiertos**, aceptando el DS sin anclarlo a una raíz de confianza fijada. Entonces puede aceptarse un Firmante de Documentos autofirmado o falsificado. No requiere comprometer ninguna tarjeta, solo un verificador que no fije el CSCA sin conexión. Es "teatro de verificación" sistémico.

### C. Aceptación por verificadores débiles / credenciales aguas abajo
**Cadena:** A + B.
Los sistemas aguas abajo (KYC, incorporación de clientes, quioscos) que confían en datos a nivel de `CardSecurity` o realizan una passive auth parcial sin anclaje podrían aceptar un objeto de seguridad fabricado. La gravedad depende de la implementación de cada verificador, no de la tarjeta.

<a id="tests-failed"></a>
### Ataques en los que nuestras pruebas no tuvieron éxito

🟢 aquí significa solamente: el ataque se intentó o analizó como se describe y falló. No es prueba de imposibilidad.
- **Falsificar datos de identidad de `EF.SOD`** (nombre, foto, DG1/DG2…) rompiendo la clave RSA-1024: 🟢 no logrado, porque `EF.SOD` está firmado por un firmante EC de producción distinto. **No** cubre a un verificador que también acepte SOD firmados con RSA-1024 (🟡, véase la tabla de clonación en `README.md`).
- **Escribir datos falsos en una tarjeta genuina por el canal CAN/PACE:** 🟢 rechazado en nuestras pruebas (`6982`/`6A81`/`6986`). No cubre las vías con credenciales del emisor (SO PIN, GlobalPlatform), que no probamos.
- **Alteración del MAC de Secure Messaging y degradación de algoritmo:** 🟢 rechazadas en nuestro banco de pruebas. No se probó un ataque de intermediario (man-in-the-middle) completo.
- **Fuerza bruta de PIN:** ⚪ no probado (sin afirmación de color). Se observó que los contadores de reintentos están presentes; no intentamos agotarlos.

---

<a id="summary"></a>
## Resumen

| Ataque | Precondición | ¿Hay un bloqueo presente? |
|---|---|---|
| El clon supera Chip Auth (A) | Recuperar/factorizar el DS de desarrollo RSA-1024 **y** que el verificador no fije el CSCA | Parcial — depende del verificador |
| Falla abierta de confianza (B) | El verificador obtiene el CSCA en tiempo de ejecución y falla abierto | 🔴 CSCA inalcanzable |
| Aceptación por verificador débil (C) | El sistema aguas abajo omite la passive auth completa con anclaje | Depende de la implementación |
| Falsificar datos de `EF.SOD` mediante la clave RSA-1024 | — | 🟢 Firmante distinto (EC); no cubierto si un verificador acepta SOD RSA-1024 |
| Escritura en tarjeta / alteración de SM / contadores de PIN | — | 🟢 Pruebas nombradas superadas en las tarjetas probadas; no es una afirmación de seguridad general |

**Conclusión.** En las pruebas que ejecutamos, las verificaciones del lado de la tarjeta se superaron; la exposición que encontramos es **procedencia de la clave de firma (Hallazgo 1) + una cadena de confianza sin ancla (Hallazgo 2)**. Deben remediarse **juntas**: corregir una sin la otra deja abierta la vía de aceptación de clones (A/B).

**Punto pendiente.** Clasificar A/B/C por probabilidad en el mundo real una vez que sepamos qué implementaciones de verificadores (app de la JCE, lectores de terceros) fallan abiertas ante el CSCA ausente, y reunir más UID de producción antes de cualquier afirmación a nivel de población.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
