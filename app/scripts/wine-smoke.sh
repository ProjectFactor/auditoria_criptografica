#!/usr/bin/env bash
# Run the recorded-data GUI smoke test of the Windows build under Wine.
# usage: wine-smoke.sh CedulaReader.exe recorded.json OUTPUT_DIR   (OUTPUT_DIR must not exist)
set -euo pipefail
exe=$(realpath "$1"); fixture=$(realpath "$2"); out=$(realpath -m "$3")
# A Linux-style DOTNET_BUNDLE_EXTRACT_BASE_DIR makes the Windows single-file host
# overflow the stack under Wine; drop all host-level DOTNET_* overrides.
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^DOTNET_' || true)
cd "$(dirname "$exe")"
WINEDEBUG=${WINEDEBUG:--all} wine "$(basename "$exe")" --smoke "Z:$fixture" "Z:$out"
grep -q '"Passed": *true' "$out/smoke-result.json" && echo "smoke: PASSED ($out)"
