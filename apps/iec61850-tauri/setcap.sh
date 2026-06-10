#!/usr/bin/env bash
# Da CAP_NET_RAW al binario de la app para los monitores/publicadores GOOSE/SV
# (capa 2). Hay que reejecutarlo cada vez que `tauri dev` recompile el core Rust.
# Uso:  sudo ./setcap.sh   [debug|release]
set -euo pipefail
PROFILE="${1:-debug}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/target/$PROFILE/iec61850-tauri"
if [[ ! -x "$BIN" ]]; then
  echo "No existe $BIN — compila primero (pnpm tauri dev / build)." >&2
  exit 1
fi
setcap cap_net_raw,cap_net_admin+ep "$BIN"
echo "OK: capabilities aplicadas a $BIN"
getcap "$BIN"
