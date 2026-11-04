<!-- factor-brand:start -->
**FACTOR Inc.** · [projectfactor.io](https://projectfactor.io)
<!-- factor-brand:end -->

# Cédula Reader 0.1 — versión preliminar portátil para Windows

La interfaz de la aplicación está actualmente solo en inglés; los botones se nombran aquí tal como aparecen en pantalla.

Extraiga `CedulaReader-0.1.0-win-x64.zip` en una carpeta local con permisos de escritura y ejecute `CedulaReader.exe`. No se necesita instalador, instalación de .NET, Python, servicios en la nube ni conexión a internet. Destino: Windows 11 x64. El lector físico igualmente debe ser reconocido por PC/SC de Windows.

## Lector de línea de comandos para Linux

`cedula-reader-0.1.0-linux-x64.tar.gz` contiene un `cedula-reader` autocontenido (requiere `pcscd` y `libpcsclite.so.1`): `cedula-reader readers`; `cedula-reader read [--reader N] [--data DIR] [--export FILE.zip]`. El CAN se toma de `CEDULA_CAN`, de la entrada estándar o de un aviso con entrada oculta. Los escaneos usan el mismo formato `Data/` y la misma exportación ZIP que la aplicación de Windows (se pueden restaurar allí). Validado con lectura en vivo de tarjetas reales.

## Uso

1. Conecte el ACS ACR1552U y haga clic en **Refresh reader** (actualizar lector).
2. Haga clic en **New profile** (nuevo perfil), coloque una tarjeta en el lector, ingrese el **CAN** de seis dígitos y haga clic en **Read cédula** (leer cédula). Las credenciales nunca se reintentan automáticamente.
3. Revise las pestañas de identidad, retrato, firma manuscrita, certificados/claves, inventario y verificación. Al seleccionar un elemento del inventario se muestra su hexadecimal exacto y la estructura ASN.1 disponible.
4. **Export scan ZIP** exporta la adquisición seleccionada. **Export profile history** exporta todos los escaneos asociados a ese perfil. Las exportaciones incluyen las cargas útiles y los fragmentos originales, los archivos JPEG/DER extraídos, los PEM/JSON/PDF derivados y los manifiestos SHA-256.
5. Use **Restore ZIP** para importar un perfil exportado a otra carpeta de datos o a otra máquina. Los identificadores de escaneo existentes nunca se sobrescriben.

La lista de la izquierda muestra las instantáneas de escaneo guardadas. Al seleccionar una se reabre sin necesidad de tarjeta ni CAN. Escanear el mismo documento desde su perfil existente agrega una instantánea. Al iniciar un perfil nuevo, la detección de duplicados ofrece agregar al documento existente; de lo contrario crea un perfil separado. La búsqueda coincide con nombres y números de documento.

`Data/` se encuentra junto al ejecutable y está intencionalmente **sin cifrar**. Los archivos originales se mantienen separados de los informes derivados. Si no se puede crear una carpeta de datos portátil nueva por falta de permisos, la aplicación usa una carpeta por copia en Windows Local AppData y la recuerda. Una carpeta de datos existente e inaccesible produce un error explícito en lugar de cambiar a un almacén de perfiles vacío. Cierre la aplicación antes de mover su carpeta. Abrir dos veces la misma copia portátil trae al frente la ventana existente. Cerrar la ventana principal cierra la aplicación y libera el bloqueo de la carpeta de datos. Solo una instancia puede escribir en una carpeta de datos a la vez. Conserve `Data/` al reemplazar el ejecutable para actualizar. Los perfiles se pueden eliminar con **Delete profile**; las copias ZIP exportadas por separado no se ven afectadas.

## Tamaño de ventana

La aplicación se abre maximizada. Al restaurarla, su tamaño predeterminado es de 1600×1000 con un mínimo de 1200×800 unidades independientes del dispositivo. Todo el espacio de trabajo se escala proporcionalmente cuando la ventana crece o se maximiza: controles, pestañas, texto, espaciado de paneles e imágenes aumentan juntos. El escalado usa dimensiones independientes del dispositivo y respeta el escalado de pantalla de Windows. En tamaños menores conserva el tamaño base del texto, ajusta los controles en varias líneas y mantiene los paneles de datos desplazables. Se conservan las proporciones del retrato y de la firma.

La confirmación de eliminación se abre en una ventana más grande y redimensionable. Su texto y sus botones crecen juntos con la ventana, con texto ajustado y desplazable en tamaños menores. Cancel es la acción predeterminada; Escape o cerrar la ventana también cancela.

Los ZIP de exportación de escaneo y de historial de perfil usan un selector de carpetas redimensionable (1100×800 inicialmente, mínimo 850×650). El texto y los controles se escalan al crecer. Use los accesos directos de carpetas, elija una unidad, haga doble clic en carpetas o ingrese una ruta y presione Go. Los ZIP existentes requieren confirmación explícita para reemplazarse.

Cuando se detecta una clave RSA-1024, Overview muestra una línea de tiempo compacta de estándares debajo de las imágenes, con organización/región, año y alcance. Los enlaces de las organizaciones abren fuentes primarias en el navegador cuando se solicita; la tabla en sí funciona sin conexión. La tabla se oculta para otros tamaños de clave y se borra al iniciar un perfil nuevo.

## Lo que establece esta compilación

- La interfaz nativa WPF funciona bajo Wine 10 con el entorno de ejecución .NET 10 incluido, selección de fuentes disponibles del sistema y fuentes de respaldo incrustadas.
- La evidencia grabada conservada se importa, ambas imágenes se muestran, se analizan tres claves públicas distintas y el firmante de desarrollo RSA-1024 recibe advertencias rojas de inseguro/desarrollo.
- Las dos firmas CMS registradas y los hashes de siete grupos de datos adquiridos se verifican; la confianza en la cadena del emisor sigue sin resolverse y no se comprueba la revocación.
- El almacenamiento local, la exportación/restauración ZIP y el escritor de PDF sin conexión incluido pasan las pruebas de regresión.
- La nueva implementación de CAN/PACE interopera con un oráculo independiente de OpenPACE del lado de la tarjeta, incluida una lectura protegida. Usa primitivas criptográficas de Bouncy Castle/.NET, no implementaciones propias de primitivas.

**La lectura en vivo con el lector y la tarjeta reales se ha validado con estos ejecutables.** Las importaciones registradas y las pruebas automatizadas siempre se identifican como evidencia registrada, no como escaneos en vivo.

## Alcance admitido y límites actuales

El lector en vivo admite el perfil PACE ECDH-GM / AES-256 / NIST P-384 con parámetro 15 observado y las rutas de lectura MF/eMRTD/PKCS#15 conocidas. Los perfiles CardAccess desconocidos fallan antes de intentar el CAN. No usa PIN de firma, no escribe datos en la tarjeta, no firma documentos, no extrae claves privadas, no accede a las huellas del DG3 y no realiza Terminal/Chip Authentication. Las lecturas del directorio de claves privadas se limitan al prefijo de descriptor establecido previamente. Los descriptores de claves no contienen claves privadas.

Esta versión preliminar usa carpetas de escaneo inmutables e instantáneas JSON como repositorio local; el índice de búsqueda SQLite propuesto queda diferido. Expone datos PKCS#15 en bruto/ASN.1; las etiquetas legibles especializadas para cada descriptor aún no están completas. El texto de la interfaz está actualmente en inglés. Se admiten imágenes JPEG; otras codificaciones conservan sus objetos en bruto con un error de decodificación. El PDF usa texto Latin-1 y secuencias de escape `\uXXXX` explícitas para los caracteres no admitidos; el JSON y los archivos originales conservan los valores completos. No hay instalador ni certificado de firma de binarios configurado, por lo que este ejecutable preliminar no está firmado.

Los diarios de adquisición sobreviven a las interrupciones en directorios `.acquiring-*`. Al iniciar, se recuperan las instantáneas de diario legibles como escaneos incompletos. Los últimos fragmentos sin indexar permanecen en el diario para revisión manual. Los manifiestos de escaneos guardados detectan modificaciones accidentales; estos hashes locales no son firmas que prueben la autenticidad del emisor.

## Desarrollo

Proyectos: `Cedula.Core` (procesamiento portátil, almacenamiento, exportaciones y protocolo), `Cedula.Desktop` (WPF) y `Cedula.Tests` (suite ejecutable de regresión). No se incluyen datos de tarjetas en el repositorio ni en el paquete de la aplicación.

Con un SDK de .NET 10 instalado:

```sh
app/scripts/build.sh
app/scripts/test.sh
```

Defina `CEDULA_DOTNET` con un ejecutable explícito del SDK si es necesario. Las compilaciones dirigidas a Windows habilitan `EnableWindowsTargeting`; la restauración de NuGet necesita acceso a la red la primera vez. La aplicación en sí no requiere red. El paquete se genera en `app/artifacts/`.

`prepare-recorded-fixture.py` construye un fixture local ignorado a partir de la evidencia privada existente del repositorio, sin contactar una tarjeta ni acceder a un CAN. El botón **Import recorded scan** acepta el `recorded.json` de ese fixture y copia los originales a un perfil local nuevo.

Una prueba de protocolo independiente opcional usa la biblioteca OpenPACE ya existente en el repositorio:

```sh
gcc app/scripts/openpace-oracle.c -Itools/pace-root/usr/include \
  -Ltools/pace-root/usr/lib/x86_64-linux-gnu \
  -Wl,-rpath,"$PWD/tools/pace-root/usr/lib/x86_64-linux-gnu" \
  -leac -lcrypto -o app/artifacts/openpace-oracle
app/scripts/test.sh "$PWD/app/artifacts/openpace-oracle"
```

El oráculo usa un CAN sintético, nunca abre PC/SC y es un ejecutable de Linux solo para pruebas, no una dependencia de ejecución distribuida.

## Prueba de humo de la interfaz con Wine

Después de instalar/configurar un entorno Wine de 64 bits con fuentes y pantalla:

```sh
wine CedulaReader.exe --smoke 'Z:\path\to\recorded.json' 'Z:\path\to\fresh-output'
```

Antes, elimine cualquier variable de entorno `DOTNET_*` (en particular `DOTNET_BUNDLE_EXTRACT_BASE_DIR` con una ruta de Linux), que desborda la pila del host de archivo único de Windows bajo Wine. `app/scripts/wine-smoke.sh EXE recorded.json OUTDIR` hace esto y comprueba el resultado.

Esto importa el fixture, valida el renderizado de imágenes y las advertencias, captura pantallas de resumen/certificados, exporta un ZIP, comprueba que New profile borra los datos anteriores y reabre el perfil guardado. Escribe `smoke-result.json` y termina. Use un directorio de salida nuevo cada vez. Este modo no contacta el lector.

La enumeración de lectores por sí sola está disponible sin comandos de tarjeta:

```text
CedulaReader.exe --diagnose-readers C:\path\readers.json
```

Consulte `TEST_RESULTS.md` en el árbol de código fuente para ver los resultados reales de las pruebas.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
