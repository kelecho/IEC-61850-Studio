#!/bin/sh
# Post-instalación (.deb/.rpm): da CAP_NET_RAW al binario instalado para que
# los monitores GOOSE/SV (sockets capa 2) funcionen sin root. El resto de la
# app (MMS/TCP) no necesita privilegios. Si setcap falla (p. ej. filesystem
# sin xattrs), la app funciona igual salvo la captura capa 2.
set -e
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw+ep /usr/bin/iec61850-tauri || true
fi
exit 0
