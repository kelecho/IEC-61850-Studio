#!/usr/bin/env bash
# Runner de cargo (ver .cargo/config.toml): tras cada compilación, re-aplica
# CAP_NET_RAW a los binarios que abren sockets capa 2 (GOOSE/SV) y ejecuta.
#
# Requiere una regla sudoers sin contraseña (una sola vez):
#   sudo tee /etc/sudoers.d/iec61850-setcap <<'EOF'
#   kelecho ALL=(root) NOPASSWD: /usr/sbin/setcap cap_net_raw+ep /home/kelecho/apps/iec_61850/target/*
#   EOF
#
# Sin la regla, `sudo -n` falla en silencio y el binario corre sin capacidad
# (los monitores GOOSE/SV darán "permiso denegado", el resto funciona igual).
set -u
bin="$1"
shift
case "$(basename "$bin")" in
  iec61850-tauri | iec61850-sim | iec61850-gui)
    sudo -n /usr/sbin/setcap cap_net_raw+ep "$bin" 2>/dev/null || true
    ;;
esac
exec "$bin" "$@"
