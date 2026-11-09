<!-- factor-brand:start -->
**FACTOR Inc.** · [projectfactor.io](https://projectfactor.io)
<!-- factor-brand:end -->

# Windows qualification checklist

Use the portable distribution on the intended Windows 11 x64 laptop.

1. **Clean start:** extract and run without installing .NET or application dependencies. Record the Windows version and the application version. Verify that all tabs and dialogs display correctly.
2. **Reader:** connect the real ACS ACR1552U USB Type-A. Refresh the readers and record the reader name and driver version. If Windows cannot enumerate it, resolve the driver requirement before scanning; the application does not install drivers.
3. **First live acquisition:** New profile → place the supported test cédula → enter its CAN → Read cédula. Expected: a responsive interface, a locally saved snapshot, portrait/signature, and separate certificate/key warnings. Inspect the status of each object and any errors; do not treat a partial acquisition as a complete read. The application never guesses or automatically retries credentials.
4. **Accuracy:** compare the new raw files and the certificate/image summaries against the established test evidence. Confirm the seven DG hash checks, both CMS checks, and the RSA/development warnings. Issuer trust must remain unresolved as long as there is no independently validated matching trust material.
5. **Recovery:** test with the reader disconnected and with the reader removed during acquisition. Verify that there are clear errors, an incomplete status, retained fragments, and that no data carries over into a new profile. Cancel a read and then start another explicitly.
6. **Profiles:** scan again in the same profile and then use New profile for another card. Check that an identity mismatch never silently attaches another person's scan. Close and reopen offline and search the saved profiles.
7. **Exports:** export one scan and the complete history. Open the ZIP with normal Windows tools, inspect JPEG/DER/PEM/JSON/PDF, and confirm the hashes against the included manifests. Restore into a fresh application folder and verify identity, history, and images.
8. **Portability:** move the closed application together with `Data/` to another folder with write permissions. Repeat the offline startup, profile review, and export without a separately installed runtime.

Keep the ZIP and screenshots in local test storage; they contain the original collected data. Record the results of each step as PASS/FAIL with the displayed error and sanitized diagnostics. A pass under Wine does not replace performing these hardware and Windows checks.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
