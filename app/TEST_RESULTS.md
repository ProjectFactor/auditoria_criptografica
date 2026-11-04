<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Registro de validación — versión preliminar portátil 0.1

Entorno: Ubuntu 26.04 x64; SDK de .NET 10.0.401; Wine 10.0 de Ubuntu desempaquetado localmente; pantalla virtual Xvfb. Todas las pruebas usan evidencia registrada existente registrada o entradas sintéticas. Esta aplicación no realizó ninguna autenticación en vivo con una tarjeta durante estas comprobaciones.

## Completado

- Suite del núcleo en Linux: 47 comprobaciones aprobadas, incluidos los hashes de siete DG adquiridos, ambas firmas CMS, fragmentos exactos de imagen/certificado/clave, dígitos de control del número de documento extendido de la MRZ, almacenamiento, integridad de archivos, colisiones al restaurar, rechazo de recorrido de rutas en ZIP, BER mal formado, reglas de advertencia de algoritmo/entorno, detección de grupos de datos alterados y comportamiento ante fallos de la sesión segura.
- Oráculo independiente OpenPACE: autenticación mutua CAN/PACE exitosa, respuesta cifrada autenticada, comando SELECT cifrado y rechazo de un MAC de respuesta alterado. El oráculo usa un CAN sintético y ningún transporte de tarjeta inteligente.
- Ejecutor del núcleo de Windows bajo Wine: 43 comprobaciones aprobadas (las cuatro comprobaciones del oráculo OpenPACE de Linux se realizan por separado).
- Ejecutable WPF autocontenido de Windows: se inició correctamente bajo Wine, mostró ambas imágenes y tres claves, mostró advertencias rojas de RSA-1024/desarrollo y generó JSON/PDF/ZIP sin instalar .NET en Wine. La ejecución final recorrió todas las pestañas, el borrado de datos con New profile y la reapertura de un perfil guardado. Resultado: `app/artifacts/wine-font-qualified/smoke-result.json`, `Passed: true`.
- Estructura del PDF: validada con `pdfinfo` de Poppler; PDF A4 sin cifrar con flujos JPEG originales incrustados y varias páginas de informe.

Los resultados exactos de la ejecución final están en `app/artifacts/`, que se ignora en el control de versiones. Las capturas de pantalla y los informes exportados contienen información de identidad de una tarjeta y se excluyen de la distribución y del control de código fuente.

## Hallazgos de la configuración de Wine

La extracción local del paquete de Wine requirió los recursos de configuración regional y fuentes de `wine-common` y `zlib1.dll` en el prefijo aislado de Wine. WPF falló inicialmente durante el respaldo por falta de fuentes. Ahora la aplicación selecciona una fuente del sistema realmente enumerada, conserva las fuentes DejaVu incrustadas como respaldo y usa renderizado por software. Un segundo problema de fuentes que afectaba las transiciones de cursor/pestañas se resolvió con una selección explícita de fuente para los controles de texto. El prefijo de Wine configurado también tiene sus fuentes estándar. Estos son requisitos de configuración del anfitrión Wine, no instalaciones adicionales requeridas por la aplicación portátil de Windows.

El uso de CNG de Windows, solo en pruebas, para generar certificados sintéticos expuso una limitación de Wine. Los certificados sintéticos de prueba ahora usan Bouncy Castle, igual que el analizador de certificados de la aplicación. Ningún fallo se ocultó ni se contó como aprobado.

La enumeración de lectores bajo Wine se completó correctamente con una lista de lectores vacía. Por lo tanto, aquí no fue posible probar con una tarjeta real. Resultados finales en Linux: `app/artifacts/linux-release-check/test-result.json`; resultados del núcleo en Windows: `app/artifacts/wine-core-final/test-result.json`.

## Validación en vivo

La adquisición real con el lector y la tarjeta se ha validado con estos ejecutables.

## Verificación del diseño adaptable

La confirmación de eliminación redimensionable pasó la prueba de humo de Wine con datos registrados a 560×360, 760×460, 1200×800 y maximizada. El texto y los botones se escalaron a 1.61× a 1200×800; las capturas compactas y ampliadas se inspeccionaron visualmente. Al cerrar el diálogo se devolvió la cancelación y se conservó el perfil de prueba. Resultados: `app/artifacts/wine-delete-dialog-check/`. La validación nativa en Windows sigue pendiente.

La interfaz actualizada pasó la prueba de humo completa de Wine con datos registrados, más comprobaciones de redimensionado a 1000×700, 1320×900, 1920×1080, 2560×1440 y maximizada en una pantalla virtual de 2560×1440. La escala del espacio de trabajo aumentó de 1.0 a aproximadamente 1.68. El retrato creció de 210 a aproximadamente 354 unidades de pantalla y los controles/texto se escalaron proporcionalmente. Las capturas se inspeccionaron visualmente en tamaños compactos y ampliados. No se enviaron comandos a ninguna tarjeta. Resultados: `app/artifacts/wine-resize-check/resize-results.json` y `smoke-result.json`.

## Ventana de inicio más grande

El inicio maximizado y el diseño adaptable pasaron la prueba de humo de Wine. Un intento de redimensionar a 1000×700 quedó limitado al nuevo mínimo de 1200×800. Los tamaños mayores y la maximización conservaron el escalado proporcional. Resultados: `app/artifacts/wine-large-window-check/`. La verificación nativa en Windows sigue pendiente.

## Tamaño del selector de exportación

El selector de exportación personalizado pasó las pruebas de humo de Wine a 850×650, 1100×800 y 1800×1200. Se inspeccionaron las capturas del tamaño mínimo y del ampliado. Las comprobaciones cubrieron controles visibles y lista de carpetas, escalado proporcional, confirmación de archivo existente, borrado del consentimiento de reemplazo tras renombrar, completado de la extensión ZIP y exportación al destino seleccionado. El archivo de prueba existente permaneció sin cambios. Resultados: `app/artifacts/wine-export-dialog-check/`. Las pruebas nativas en Windows siguen pendientes.

## Línea de tiempo de RSA-1024 en Overview

Las pruebas de humo y de redimensionado de Wine pasaron para la línea de tiempo condicional de cuatro filas. Aparece para la clave RSA-1024 registrada, se oculta para RSA-2048 y se borra con New profile. Se inspeccionaron visualmente el texto ajustado y el contraste de los enlaces a fuentes. Resultados: `app/artifacts/wine-rsa-timeline-final/`. La automatización no abrió los enlaces a fuentes.

## Inicio y reapertura

Una ejecución aislada de Wine abrió la aplicación interactiva, inició un duplicado (que avisó a la instancia existente y terminó), cerró normalmente la original y reabrió correctamente la misma ubicación de datos. Evidencia: `app/artifacts/startup-build/{first,duplicate,reopened}.txt`. Prueba de humo con perfil registrado: `app/artifacts/wine-startup-smoke/`. La validación nativa en Windows y la alternativa a Local AppData cuando se niega el permiso siguen sin verificarse.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
