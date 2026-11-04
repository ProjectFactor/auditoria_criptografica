#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dotnet_cmd="${CEDULA_DOTNET:-dotnet}"
"$dotnet_cmd" publish Cedula.Desktop/Cedula.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/win-x64
"$dotnet_cmd" publish Cedula.Cli/Cedula.Cli.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/linux-x64
python3 scripts/package.py
