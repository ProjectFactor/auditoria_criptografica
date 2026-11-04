<!-- factor-brand:start -->
**FACTOR Inc.** · [projectfactor.io](https://projectfactor.io)
<!-- factor-brand:end -->

# Lista de verificación de calificación en Windows

Use la distribución portátil en la laptop con Windows 11 x64 prevista.

1. **Inicio limpio:** extraiga y ejecute sin instalar .NET ni dependencias de la aplicación. Registre la versión de Windows y la versión de la aplicación. Verifique que todas las pestañas y diálogos se muestren correctamente.
2. **Lector:** conecte el ACS ACR1552U USB Tipo-A real. Actualice los lectores y registre el nombre del lector y la versión del controlador. Si Windows no puede enumerarlo, resuelva el requisito del controlador antes de escanear; la aplicación no instala controladores.
3. **Primera adquisición en vivo:** New profile → coloque la cédula de prueba admitida → ingrese su CAN → Read cédula. Se espera una interfaz que responda, una instantánea guardada localmente, retrato/firma y advertencias separadas de certificados/claves. Inspeccione el estado de cada objeto y cualquier error; no trate una adquisición parcial como una lectura completa. La aplicación nunca adivina ni reintenta credenciales automáticamente.
4. **Exactitud:** compare los nuevos archivos en bruto y los resúmenes de certificados/imágenes con la evidencia de prueba establecida. Confirme las siete comprobaciones de hash de DG, ambas comprobaciones CMS y las advertencias de RSA/desarrollo. La confianza en el emisor debe permanecer sin resolverse mientras no haya material de confianza coincidente validado de forma independiente.
5. **Recuperación:** pruebe con el lector desconectado y con la extracción del lector durante la adquisición. Verifique que haya errores claros, estado de incompleto, fragmentos conservados y que no se arrastren datos a un perfil nuevo. Cancele una lectura y luego inicie otra de forma explícita.
6. **Perfiles:** escanee de nuevo en el mismo perfil y luego use New profile para otra tarjeta. Compruebe que una discrepancia de identidad nunca adjunte en silencio el escaneo de otra persona. Cierre y reabra sin conexión y busque en los perfiles guardados.
7. **Exportaciones:** exporte un escaneo y el historial completo. Abra el ZIP con herramientas normales de Windows, inspeccione JPEG/DER/PEM/JSON/PDF y confirme los hashes contra los manifiestos incluidos. Restaure en una carpeta nueva de la aplicación y verifique identidad, historial e imágenes.
8. **Portabilidad:** mueva la aplicación cerrada junto con `Data/` a otra carpeta con permisos de escritura. Repita el inicio sin conexión, la revisión de perfiles y la exportación sin un entorno de ejecución instalado por separado.

Conserve el ZIP y las capturas de pantalla en almacenamiento local de pruebas; contienen los datos originales recopilados. Registre los resultados de cada paso como PASS/FAIL (aprobado/fallido) con el error mostrado y diagnósticos depurados. Una aprobación en Wine no sustituye la realización de estas comprobaciones de hardware y de Windows.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Auditoría criptográfica · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
