<!-- factor-brand:start -->
**FACTOR Inc.** · [projectfactor.io](https://projectfactor.io)
<!-- factor-brand:end -->

# Cédula Reader 0.1 — portable preliminary version for Windows

The application interface is currently in English only; buttons are named here exactly as they appear on screen.

Extract `CedulaReader-0.1.0-win-x64.zip` into a local folder with write permissions and run `CedulaReader.exe`. No installer, .NET installation, Python, cloud services, or internet connection is needed. Target: Windows 11 x64. The physical reader must still be recognized by Windows PC/SC.

## Command-line reader for Linux

`cedula-reader-0.1.0-linux-x64.tar.gz` contains a self-contained `cedula-reader` (requires `pcscd` and `libpcsclite.so.1`): `cedula-reader readers`; `cedula-reader read [--reader N] [--data DIR] [--export FILE.zip]`. The CAN is taken from `CEDULA_CAN`, from standard input, or from a hidden-input prompt. Scans use the same `Data/` format and the same ZIP export as the Windows application (they can be restored there). Validated with live reads of real cards.

## Usage

1. Connect the ACS ACR1552U and click **Refresh reader**.
2. Click **New profile**, place a card on the reader, enter the six-digit **CAN**, and click **Read cédula**. Credentials are never retried automatically.
3. Review the identity, portrait, handwritten signature, certificates/keys, inventory, and verification tabs. Selecting an inventory item shows its exact hexadecimal and the available ASN.1 structure.
4. **Export scan ZIP** exports the selected acquisition. **Export profile history** exports all scans associated with that profile. Exports include the original payloads and fragments, the extracted JPEG/DER files, the derived PEM/JSON/PDF files, and the SHA-256 manifests.
5. Use **Restore ZIP** to import an exported profile into another data folder or onto another machine. Existing scan identifiers are never overwritten.

The list on the left shows the saved scan snapshots. Selecting one reopens it without needing a card or CAN. Scanning the same document from its existing profile adds a snapshot. When starting a new profile, duplicate detection offers to add to the existing document; otherwise it creates a separate profile. Search matches names and document numbers.

`Data/` is located next to the executable and is intentionally **unencrypted**. The original files are kept separate from the derived reports. If a new portable data folder cannot be created for lack of permissions, the application uses a per-copy folder in Windows Local AppData and remembers it. An existing but inaccessible data folder produces an explicit error instead of switching to an empty profile store. Close the application before moving its folder. Opening the same portable copy twice brings the existing window to the front. Closing the main window closes the application and releases the data-folder lock. Only one instance can write to a data folder at a time. Keep `Data/` when replacing the executable to update. Profiles can be deleted with **Delete profile**; separately exported ZIP copies are not affected.

## Window size

The application opens maximized. When restored, its default size is 1600×1000 with a minimum of 1200×800 device-independent units. The whole workspace scales proportionally when the window grows or is maximized: controls, tabs, text, panel spacing, and images grow together. Scaling uses device-independent dimensions and respects Windows display scaling. At smaller sizes it keeps the base text size, wraps controls onto multiple lines, and keeps the data panels scrollable. The portrait and signature proportions are preserved.

The delete confirmation opens in a larger, resizable window. Its text and buttons grow together with the window, with wrapped, scrollable text at smaller sizes. Cancel is the default action; Escape or closing the window also cancels.

The scan-export and profile-history ZIPs use a resizable folder picker (initially 1100×800, minimum 850×650). Text and controls scale as it grows. Use the folder shortcuts, choose a drive, double-click folders, or enter a path and press Go. Existing ZIPs require explicit confirmation before being replaced.

When an RSA-1024 key is detected, Overview shows a compact timeline of standards below the images, with organization/region, year, and scope. The organization links open primary sources in the browser on request; the table itself works offline. The table is hidden for other key sizes and cleared when starting a new profile.

## What this build establishes

- The native WPF interface works under Wine 10 with the bundled .NET 10 runtime, selection of available system fonts, and embedded fallback fonts.
- The retained recorded evidence is imported, both images are displayed, three distinct public keys are parsed, and the RSA-1024 development signer receives red insecure/development warnings.
- The two recorded CMS signatures and the hashes of seven acquired data groups are verified; trust in the issuer chain remains unresolved and revocation is not checked.
- Local storage, ZIP export/restore, and the bundled offline PDF writer pass the regression tests.
- The new CAN/PACE implementation interoperates with an independent card-side OpenPACE oracle, including a protected read. It uses Bouncy Castle/.NET cryptographic primitives, not in-house implementations of primitives.

**Live reading with the real reader and card has been validated with these executables.** Recorded imports and automated tests are always identified as recorded evidence, not as live scans.

## Supported scope and current limits

The live reader supports the PACE ECDH-GM / AES-256 / NIST P-384 profile with the observed parameter 15 and the known MF/eMRTD/PKCS#15 read paths. Unknown CardAccess profiles fail before the CAN is attempted. It does not use the signing PIN, does not write data to the card, does not sign documents, does not extract private keys, does not access the DG3 fingerprints, and does not perform Terminal/Chip Authentication. Reads of the private-key directory are limited to the previously established descriptor prefix. The key descriptors do not contain private keys.

This preliminary version uses immutable scan folders and JSON snapshots as the local repository; the proposed SQLite search index is deferred. It exposes raw PKCS#15/ASN.1 data; specialized human-readable labels for each descriptor are not yet complete. The interface text is currently in English. JPEG images are supported; other encodings keep their raw objects with a decoding error. The PDF uses Latin-1 text and explicit `\uXXXX` escape sequences for unsupported characters; the JSON and original files keep the full values. There is no installer or binary signing certificate configured, so this preliminary executable is unsigned.

Acquisition journals survive interruptions in `.acquiring-*` directories. On startup, readable journal snapshots are recovered as incomplete scans. The last unindexed fragments remain in the journal for manual review. The manifests of saved scans detect accidental modification; these local hashes are not signatures proving issuer authenticity.

## Development

Projects: `Cedula.Core` (portable processing, storage, exports, and protocol), `Cedula.Desktop` (WPF), and `Cedula.Tests` (executable regression suite). No card data is included in the repository or in the application package.

With a .NET 10 SDK installed:

```sh
app/scripts/build.sh
app/scripts/test.sh
```

Set `CEDULA_DOTNET` to an explicit SDK executable if needed. Windows-targeting builds enable `EnableWindowsTargeting`; the NuGet restore needs network access the first time. The application itself does not require a network. The package is generated in `app/artifacts/`.

`prepare-recorded-fixture.py` builds an ignored local fixture from the repository's existing private evidence, without contacting a card or accessing a CAN. The **Import recorded scan** button accepts that fixture's `recorded.json` and copies the originals to a new local profile.

An optional independent protocol test uses the OpenPACE library already present in the repository:

```sh
gcc app/scripts/openpace-oracle.c -Itools/pace-root/usr/include \
  -Ltools/pace-root/usr/lib/x86_64-linux-gnu \
  -Wl,-rpath,"$PWD/tools/pace-root/usr/lib/x86_64-linux-gnu" \
  -leac -lcrypto -o app/artifacts/openpace-oracle
app/scripts/test.sh "$PWD/app/artifacts/openpace-oracle"
```

The oracle uses a synthetic CAN, never opens PC/SC, and is a Linux executable for testing only, not a distributed runtime dependency.

## Interface smoke test with Wine

After installing/configuring a 64-bit Wine environment with fonts and a display:

```sh
wine CedulaReader.exe --smoke 'Z:\path\to\recorded.json' 'Z:\path\to\fresh-output'
```

First, remove any `DOTNET_*` environment variable (in particular `DOTNET_BUNDLE_EXTRACT_BASE_DIR` with a Linux path), which overflows the stack of the Windows single-file host under Wine. `app/scripts/wine-smoke.sh EXE recorded.json OUTDIR` does this and checks the result.

This imports the fixture, validates image rendering and warnings, captures overview/certificates screenshots, exports a ZIP, checks that New profile clears the previous data, and reopens the saved profile. It writes `smoke-result.json` and exits. Use a fresh output directory each time. This mode does not contact the reader.

Reader enumeration alone is available without card commands:

```text
CedulaReader.exe --diagnose-readers C:\path\readers.json
```

See `TEST_RESULTS_EN.md` in the source tree for the actual test results.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
