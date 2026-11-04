#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dotnet_cmd="${CEDULA_DOTNET:-dotnet}"
python3 scripts/prepare-recorded-fixture.py
output="artifacts/test-$(date +%Y%m%dT%H%M%S)"
"$dotnet_cmd" run --project Cedula.Tests -- private-fixtures/recorded/recorded.json "$output" "$@"
