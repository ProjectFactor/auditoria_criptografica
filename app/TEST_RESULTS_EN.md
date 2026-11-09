<!-- factor-brand:start -->
<p align="right"><a href="https://projectfactor.io"><picture><source media="(prefers-color-scheme: dark)" srcset="../docs/brand/factor-landscape-reverse.svg"><img src="../docs/brand/factor-landscape.svg" alt="FACTOR Inc." height="36"></picture></a></p>

<!-- factor-brand:end -->

# Validation log — portable preliminary version 0.1

Environment: Ubuntu 26.04 x64; .NET SDK 10.0.401; Ubuntu's Wine 10.0 unpacked locally; Xvfb virtual display. All tests use existing recorded evidence or synthetic inputs. This application did not perform any live authentication with a card during these checks.

## Completed

- Core suite on Linux: 47 checks passed, including the hashes of seven acquired DGs, both CMS signatures, exact image/certificate/key fragments, check digits of the extended MRZ document number, storage, file integrity, collisions on restore, rejection of path traversal in ZIPs, malformed BER, algorithm/environment warning rules, detection of altered data groups, and secure-session failure behavior.
- Independent OpenPACE oracle: successful mutual CAN/PACE authentication, authenticated encrypted response, encrypted SELECT command, and rejection of a tampered response MAC. The oracle uses a synthetic CAN and no smart-card transport.
- Windows core runner under Wine: 43 checks passed (the four Linux OpenPACE oracle checks are performed separately).
- Self-contained Windows WPF executable: started correctly under Wine, displayed both images and three keys, displayed red RSA-1024/development warnings, and generated JSON/PDF/ZIP without installing .NET in Wine. The final run went through all tabs, data clearing with New profile, and reopening a saved profile. Result: `app/artifacts/wine-font-qualified/smoke-result.json`, `Passed: true`.
- PDF structure: validated with Poppler's `pdfinfo`; unencrypted A4 PDF with embedded original JPEG streams and several report pages.

The exact results of the final run are in `app/artifacts/`, which is ignored by version control. The screenshots and exported reports contain a card's identity information and are excluded from distribution and from source control.

## Wine configuration findings

Local extraction of the Wine package required the locale and font resources from `wine-common` and `zlib1.dll` in the isolated Wine prefix. WPF initially failed during fallback because of missing fonts. The application now selects a system font that is actually enumerated, keeps the embedded DejaVu fonts as a fallback, and uses software rendering. A second font problem affecting cursor/tab transitions was resolved with an explicit font selection for the text controls. The configured Wine prefix also has its standard fonts. These are configuration requirements of the Wine host, not additional installations required by the portable Windows application.

Using Windows CNG, in tests only, to generate synthetic certificates exposed a Wine limitation. The synthetic test certificates now use Bouncy Castle, like the application's certificate parser. No failure was hidden or counted as a pass.

Reader enumeration under Wine completed correctly with an empty reader list. It was therefore not possible to test with a real card here. Final results on Linux: `app/artifacts/linux-release-check/test-result.json`; core results on Windows: `app/artifacts/wine-core-final/test-result.json`.

## Live validation

Real acquisition with the reader and card has been validated with these executables.

## Responsive layout verification

The resizable delete confirmation passed the Wine smoke test with recorded data at 560×360, 760×460, 1200×800, and maximized. The text and buttons scaled to 1.61× at 1200×800; the compact and enlarged screenshots were visually inspected. Closing the dialog returned cancellation and the test profile was preserved. Results: `app/artifacts/wine-delete-dialog-check/`. Native validation on Windows is still pending.

The updated interface passed the full Wine smoke test with recorded data, plus resize checks at 1000×700, 1320×900, 1920×1080, 2560×1440, and maximized on a 2560×1440 virtual display. The workspace scale increased from 1.0 to approximately 1.68. The portrait grew from 210 to approximately 354 screen units and the controls/text scaled proportionally. The screenshots were visually inspected at compact and enlarged sizes. No commands were sent to any card. Results: `app/artifacts/wine-resize-check/resize-results.json` and `smoke-result.json`.

## Larger startup window

The maximized startup and the responsive layout passed the Wine smoke test. An attempt to resize to 1000×700 was clamped to the new minimum of 1200×800. Larger sizes and maximization preserved proportional scaling. Results: `app/artifacts/wine-large-window-check/`. Native verification on Windows is still pending.

## Export picker size

The custom export picker passed the Wine smoke tests at 850×650, 1100×800, and 1800×1200. The screenshots at the minimum and enlarged sizes were inspected. The checks covered visible controls and folder list, proportional scaling, confirmation of an existing file, clearing of the replace consent after renaming, completion of the ZIP extension, and export to the selected destination. The existing test file remained unchanged. Results: `app/artifacts/wine-export-dialog-check/`. Native tests on Windows are still pending.

## RSA-1024 timeline in Overview

The Wine smoke and resize tests passed for the conditional four-row timeline. It appears for the recorded RSA-1024 key, is hidden for RSA-2048, and is cleared with New profile. The wrapped text and the contrast of the source links were visually inspected. Results: `app/artifacts/wine-rsa-timeline-final/`. The automation did not open the source links.

## Startup and reopening

An isolated Wine run opened the interactive application, started a duplicate (which notified the existing instance and exited), closed the original normally, and successfully reopened the same data location. Evidence: `app/artifacts/startup-build/{first,duplicate,reopened}.txt`. Smoke test with recorded profile: `app/artifacts/wine-startup-smoke/`. Native validation on Windows and the fallback to Local AppData when permission is denied remain unverified.

<!-- factor-footer:start -->
---

<p align="center"><sub>© 2026 FACTOR Inc. · Cryptographic audit · <a href="https://projectfactor.io">projectfactor.io</a></sub></p>
<!-- factor-footer:end -->
