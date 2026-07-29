# IEC 61850 Studio

> Producto de escritorio (crate `iec61850-tauri`, en `apps/iec61850-tauri/`).
> Es la **app principal** del proyecto; sustituye al prototipo egui
> (`apps/iec61850-gui`, obsoleto).

App **Tauri v2** (UI web React + Vite + Mantine) que consume la librería
`iec61850`: cliente de diagnóstico y simulación IEC 61850. El *core* es Rust
(`src-tauri/`, enlaza la librería y expone comandos); el frontend es web y solo
invoca esos comandos — **toda la red MMS/GOOSE/SV ocurre en Rust**.

El **manual de usuario** (tareas guiadas, 14 págs) está en
[`docs/manual/`](../../docs/manual/); este README cubre desarrollo,
ejecución y empaquetado.

## Qué hace

- **Conexión**: MMS (TCP 102), TLS/mTLS (IEC 62351-3), multi-conexión con un
  chip por IED, escáner de red (MMS activo + capa 2 pasivo) y **conexiones
  guardadas** (perfiles con nombre persistidos; import de PEM a la carpeta
  gestionada de la app).
- **Modelo**: árbol LD→LN→DO→DA online o desde SCL, con catálogo semántico
  integrado (clases LN, CDC, FC y nombres traducidos a lenguaje de operador),
  búsqueda, valores inline y panel inspector con valor + calidad + timestamp.
- **Operación**: escritura y control (los 5 ctlModel del 7-2) con **modo
  mando** armable, confirmación por diálogo y barrera reforzada (palabra
  OPERAR) sobre IEDs en servicio; panel de operación drag & drop con
  iconografía unifilar; lista de vigilancia con polling.
- **Grupos de ajuste (SGCB)**: grupo activo/en edición por LD, flujo
  SelectEditSG → escribir FC=SE → ConfirmEditSGValues → SelectActiveSG.
- **Tiempo real**: reportes URCB/BRCB en vivo con edición del RCB y export
  CSV; **logs del IED** (ReadJournal) con fechas decodificadas; **bus de
  estación** GOOSE/SV con estadísticas por publicador, **diff de datos entre
  tramas** GOOSE, forma de onda y **fasores** SV, publicadores de demo (con
  bit de simulación Ed.2) y captura PCAP.
- **Ingeniería**: comparar SCL ↔ online, ficheros del IED (COMTRADE) y
  **auditoría local** append-only de toda operación (también los rechazos).
- **Entorno de pruebas**: sirve cualquier SCL como IED MMS **en vivo** desde
  la propia UI (varios a la vez, visibles en la red), más un simulador
  embebido y un demo mTLS autocontenido con certificados de prueba.

La navegación agrupa las secciones en **tres zonas** (operación / tiempo real /
ingeniería). La UI es **solo tema oscuro** (consola de sala de control, paleta
acero + cobre), tipografías IBM Plex Sans / JetBrains Mono empaquetadas (sin
red). La app arranca **desconectada y en solo lectura**: nada se toca sin
conectar y armar el modo mando.

## Requisitos

- **Rust** (el del workspace) y **Node ≥ 18**.
- **pnpm** como gestor de paquetes. Actívalo con Corepack (incluido en Node):
  `corepack enable` (usará la versión fijada en `package.json` →
  `packageManager`). Alternativa: `npm i -g pnpm`.
- **Tauri CLI**: incluida como devDependency (`@tauri-apps/cli`), se usa vía
  `pnpm tauri …`.
- **Librerías de sistema (Linux/Debian-Ubuntu)** para el webview:
  ```sh
  sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
                   librsvg2-dev build-essential curl wget file pkg-config
  ```
  (En Windows: WebView2, ya presente en Win 11. En macOS: Xcode CLT.)

## Ejecutar

```sh
cd apps/iec61850-tauri
corepack enable                  # habilita pnpm (una vez)
pnpm install                     # instala deps
pnpm tauri dev                   # compila el core Rust + sirve la UI + abre la ventana
```

Para probar sin hardware: **Entorno de pruebas** (icono de matraz) → arranca el
simulador embebido o sirve tu propio SCL como IED en vivo, y conéctate a
`127.0.0.1:10102`. El demo **mTLS** (popover del candado → «Probar TLS con el
simulador») es 100 % autocontenido.

> Tras el primer `pnpm install` se genera `pnpm-lock.yaml`: **commitéalo** y usa
> `pnpm install --frozen-lockfile` para instalaciones reproducibles.

## Capa 2 (GOOSE / SV / PCAP)

Los monitores y publicadores de capa 2 usan `AF_PACKET` (Linux) o **Npcap**
(Windows); en macOS no hay backend (el resto de la app funciona). Requieren
`CAP_NET_RAW`:

```sh
# Dar la capacidad al binario (repetir tras cada recompilación del core Rust):
sudo ./setcap.sh            # equivale a setcap sobre target/debug/iec61850-tauri
```

Prueba 100 % local: interfaz `lo` → **Publicar demo** (GOOSE alterna un
booleano cada 2 s; SV emite una senoide) → **Iniciar** el monitor. Publicar
exige el **modo mando** armado (inyecta tramas reales en el bus). También hay
ejemplos CLI:

```sh
sudo cargo run --example goose_publish -p iec61850-goose --features net -- <iface>
sudo cargo run --example sv_publish    -p iec61850-sv    --features net -- <iface>
```

## Datos persistidos

| Qué | Dónde (Linux) |
|---|---|
| Perfiles de conexión | `~/.config/com.iec61850.studio/connections.json` |
| Certificados importados | `~/.config/com.iec61850.studio/certs/` |
| Auditoría de operaciones | `~/.local/share/com.iec61850.studio/audit.jsonl` (append-only, sin borrado desde la UI) |

## Empaquetar / instaladores

`pnpm tauri build` genera el instalable del SO actual:

- **Linux:** `.deb` y `.rpm`. La post-instalación aplica
  `setcap cap_net_raw+ep` al binario instalado (capa 2 sin root).
- **Windows:** instalador **NSIS** (`.exe`). WebView2 lo instala el propio
  instalador si falta. La capa 2 usa **Npcap** (<https://npcap.com>, modo
  *WinPcap API-compatible*); MMS/TCP funciona sin él.
- **macOS:** `.dmg`. MMS/TCP completo; sin backend de capa 2.

El workflow `.github/workflows/installers.yml` construye los tres en CI al
empujar un tag `v*` y los adjunta a la GitHub Release.

### Firma de código (Windows)

Sin firmar, el `.exe` dispara el aviso SmartScreen. Para firmar en CI con
Authenticode, añade dos secretos de GitHub Actions (el paso se activa solo si
existen): `WINDOWS_PFX_BASE64` (el `.pfx` en base64) y `WINDOWS_PFX_PASSWORD`.
El workflow firma con `signtool` y sella el tiempo; sin secretos, el build
sale sin firmar pero funcional.

### Smoke test (Windows)

Tras instalar el `.exe`, `scripts/smoke-windows.ps1` comprueba binario,
WebView2, Npcap y arranque:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows.ps1
```

## Arquitectura

- `src-tauri/` (Rust): estado en `AppState` (conexiones MMS por id, activa,
  simuladores, monitores L2) tras `tokio::sync::Mutex`; comandos
  `#[tauri::command]` — conexión (`connect`, `connect_tls`, perfiles
  `profiles_list`/`profile_save`/`profile_delete`, `import_cert`), modelo y
  datos (`discover`, `read`, `read_do`, `write`), control (`operate`,
  `select`), reporting (`rcb_read`/`rcb_write`, `enable_report`), settings
  groups (`sgcb_read`, `sg_select_active`/`sg_select_edit`/`sg_confirm_edit`),
  logs (`journal_read`), ficheros, simuladores, capa 2 y auditoría
  (`audit_list`, `audit_path`; el registro lo escriben los propios comandos).
  Reportes y tramas L2 se emiten como eventos (`report`, `goose`, `sv`).
- `src/` (React/TS): `App.tsx` + componentes (`TreeView`, `OperBoard`,
  `DetailPanel`); `invoke` para comandos y `listen` para eventos; el diff
  GOOSE y los fasores SV se calculan en el frontend sobre los eventos.
