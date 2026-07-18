# IEC 61850 Studio

> Producto de escritorio (crate `iec61850-tauri`, en `apps/iec61850-tauri/`).
> Es la **app principal** del proyecto; sustituye al prototipo egui
> (`apps/iec61850-gui`, obsoleto).

App **Tauri v2** (UI web React + Vite) que consume la librería `iec61850`:
cliente MMS para **conectar a un IED, descubrir/leer variables, ver reportes
(RCB) en vivo** y **escribir/operar** (con modo mando y confirmación reforzada),
más SCL, GOOSE/SV, TLS, IED en vivo y panel de operación. El *core* es Rust
(`src-tauri/`, enlaza la librería y expone comandos); el frontend es web y solo
invoca esos comandos — la red MMS ocurre toda en Rust.

## Requisitos

- **Rust** (el del workspace) y **Node ≥ 18**.
- **pnpm** como gestor de paquetes (más estricto/seguro que npm). Actívalo con
  Corepack (incluido en Node): `corepack enable` (usará la versión fijada en
  `package.json` → `packageManager`). Alternativa: `npm i -g pnpm`.
- **Tauri CLI**: se incluye como devDependency (`@tauri-apps/cli`), se usa vía
  `pnpm tauri …`. (Alternativa: `cargo install tauri-cli`.)
- **Librerías de sistema (Linux/Debian-Ubuntu)** para el webview:
  ```sh
  sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
                   librsvg2-dev build-essential curl wget file pkg-config
  ```
  (En Windows: WebView2, ya presente en Win 11. En macOS: Xcode CLT.)

## Ejecutar (una sola terminal)

El **IED simulado va embebido** en la app (servidor MMS in-process, con el modelo
SCL incluido vía `include_str!`): no hace falta lanzar `ied_sim` aparte.

```sh
cd apps/iec61850-tauri
corepack enable                  # habilita pnpm (una vez)
pnpm install                     # instala deps (incluye Mantine; regenera pnpm-lock.yaml)
pnpm tauri dev                   # compila el core Rust + sirve la UI + abre la ventana
```

> La UI usa **Mantine**: tras añadirla, ejecuta `pnpm install` de nuevo antes de
> `pnpm tauri dev`. Incluye un **catálogo semántico IEC 61850** integrado que
> traduce **clases LN** (MMXU→Medida, PTOC→Sobreintensidad…), **CDC**, **FC** y
> nombres de datos a texto legible: el **árbol** muestra el significado en cursiva,
> colorea la FC y pone un **icono por clase de LN** (escudo=protección, medidor=
> medida, ajustes=control, interruptor=maniobra…); al seleccionar un atributo, un
> **panel inspector** detalla
> LD/LN/DO/FC con su significado + tipo/descripción + valor/calidad/timestamp; y la
> pestaña **Resumen** da un panel del IED (nº de LD/LN/atributos y LN por clase).
> Incluye además: **árbol del modelo** (LN→DO→DA) con **búsqueda**,
> **agrupar por FC**, **valor inline** y **auto-lectura** al seleccionar; pestañas
> **Datos / Reportes / Control** con **tablas ordenables**; **tema claro/oscuro**
> (paleta oscura azul-pizarra propia, por defecto; botón para alternar) y
> tipografías **Montserrat** / **JetBrains Mono** (empaquetadas, sin red); confirmación
> para escribir/operar. Al seleccionar un dato muestra **valor + calidad (q) +
> marca de tiempo (t)** del DO. Con **«Vigilar»** (pestaña Datos) añades atributos a
> una **lista de vigilancia curada** (pestaña **Vigilar**) que el **Polling**
> refresca en vivo a intervalo configurable. En **Reportes → Parámetros del RCB**
> puedes leer y
> **editar** DatSet, IntgPd, BufTm, **TrgOps** y **OptFlds** (casillas) antes de
> habilitarlo. Tipografía **Montserrat** (+ JetBrains Mono para datos). Pestañas
> **GOOSE** y **SV** monitorizan tramas de capa 2 (ver abajo).

## Navegación (Modelo / Datasets / Reportes)

El panel izquierdo tiene un selector de **categoría**:

- **Modelo:** árbol de navegación **hasta el DO** (LD→LN→DO; ligero). Al seleccionar
  un DO, el panel derecho (pestaña **Datos**) despliega **todos sus atributos** (DA:
  stVal, q, t, mag, ang…) con su **valor**, en secciones **colapsables**; al pulsar un
  atributo se vuelve el objetivo de leer/escribir.
- **Reportes:** lista de **RCB** deducidos del modelo (hojas con FC RP/BR); al elegir
  uno se carga en la pestaña Reportes.
- **Datasets:** lista de **datasets** del SCL cargado; al elegir uno se muestran sus
  miembros (referencia · FC · tipo).

## Modelo configurado desde SCL

En la barra izquierda (categoría Modelo), el selector **Online / SCL** alterna entre el modelo
descubierto en línea y el **modelo configurado** importado de un archivo SCL
(ICD/CID/SCD): escribe la ruta **o pulsa el icono de carpeta para elegir el archivo
con el diálogo nativo del SO**, y luego el icono de importar. El árbol SCL muestra
**CDC** (por DO), **tipo básico** (por DA) y la **descripción** (`desc` del SCL, en
cursiva) de LN/DO/DA cuando existe; al hacer clic en un atributo se lee su valor en
línea (si hay conexión).

En **Reportes**, el botón **«Nombres (SCL)»** resuelve el dataset del RCB actual
contra el SCL cargado y **etiqueta las entradas de los reportes con el nombre del
miembro** (p. ej. `MMXU1.A.phsA.cVal.mag.f=…`) en vez de su índice posicional.

La pestaña **Comparar** enfrenta el modelo **SCL** (configurado) con el **online**
(descubierto): cuenta **coincidentes / solo SCL / solo online** y lista las
referencias que difieren. «solo SCL» señala posibles discrepancias de
implementación; «solo online» incluye RCB/datasets/control (que el árbol SCL no
modela). Requiere SCL cargado + conexión (para descubrir).

## TLS / mTLS (IEC 62351-3)

El icono de **candado** en la cabecera abre el panel TLS: activa **«Usar TLS»** y
rellena *server name* + rutas a los PEM de **CA**, **certificado de cliente** y
**clave** (mTLS) — cada campo tiene un icono de carpeta para elegir el archivo con
el **diálogo nativo**; luego pulsa **«Conectar TLS»**. No requiere root.

**Demo autocontenido:** en el panel, **«Iniciar sim TLS (demo)»** arranca un IED
TLS embebido en `127.0.0.1:10103` con los certificados de prueba de `test-certs/`
(server name `iec61850-sim`); las rutas de cliente ya vienen precargadas a esos
mismos certs. Activa «Usar TLS» y **Conectar TLS** → asociación mTLS y a explorar.

> `test-certs/` son certificados **de prueba** (CA→servidor+cliente, EC P-256),
> regenerables con OpenSSL. Para un IED real, apunta las rutas a tus propios PEM y
> usa su *server name* (debe estar en el SAN del certificado del servidor).

## Buscar IEDs en la red

El icono de **escáner** en la cabecera abre el buscador, con dos modos:

- **IEDs (MMS, red):** indica la **subred /24** (`a.b.c`) y el **puerto** (102 por
  defecto) y pulsa **Escanear**. Sondea `.1–.254` en paralelo (TCP con timeout
  corto) y, en los que responden, intenta **asociación MMS + Identify** para mostrar
  **fabricante/modelo**. **Conectar** lo añade. (El sim embebido está en **10102**.)
- **Publicadores GOOSE/SV (capa 2):** elige la **interfaz** y los **segundos** a
  escuchar; descubre **pasivamente** los publicadores (gocbRef/goID/dataSet/**APPID**/
  **MAC origen**/confRev para GOOSE, svID/APPID/MAC para SV, con nº de tramas). Requiere `CAP_NET_RAW`; usa «Publicar
  demo» (pestañas GOOSE/SV) o un IED real para tener tráfico.

## Multi-conexión (varios IED a la vez)

«Conectar» **añade** una conexión (no reemplaza): cada IED aparece como un **chip**
en la cabecera. Pulsa un chip para hacerlo **activo** (read/write/discover/reportes
apuntan a él); la **×** del chip lo cierra. Los **reportes** se etiquetan con su IED
de origen (columna *IED*). Para una demo con dos IED: conéctate al sim (`…:10102`) y,
con **«Iniciar sim TLS»** + «Usar TLS», a `…:10103`.

## Exportar a CSV

Cada vista con datos tabulares tiene un botón **«Exportar CSV» / «CSV»** que abre
el **diálogo de guardado nativo** y escribe el archivo: **Lecturas** (Datos),
**Reportes** (con nombres de miembro si se mapearon), **GOOSE** y **SV**. Los
campos se escapan (comillas/comas/saltos) según CSV estándar.

## Monitores GOOSE / SV (capa 2)

Las pestañas **GOOSE** y **SV** abren un socket `AF_PACKET` en la interfaz elegida
y muestran las tramas en vivo (GOOSE: goID/**APPID**/**MAC origen**/stNum/sqNum/
valores; SV: svID/**APPID**/**MAC**/smpCnt/canales 9-2LE). La pestaña **SV** incluye además una **gráfica de forma de onda**
en vivo (canvas) con los 8 canales seleccionables (IA…VN). Ambas muestran un panel
de **estadísticas por stream**: **tasa** (msg/s o smp/s), **jitter** (desviación de
inter-arribo, ms), cambios de estado / retransmisiones / **pérdidas exactas**
(nº de tramas/muestras saltadas, del gap de sqNum/smpCnt), y último stNum·sqNum
(GOOSE) o smpCnt (SV). **Requieren
`CAP_NET_RAW`** (capa 2 cruda):

```sh
# Opción A: dar la capacidad al binario (tras la 1ª compilación de `pnpm tauri dev`):
sudo setcap cap_net_raw+ep ../../target/debug/iec61850-tauri
# (repite tras cada recompilación del core Rust)

# Opción B: ejecutar con privilegios (menos recomendable para una GUI):
sudo -E pnpm tauri dev
```

Para **ver tráfico** tienes dos opciones:

- **Publicador de demo embebido (recomendado, autocontenido):** en cada pestaña,
  botón **«Publicar demo»** → la propia app publica GOOSE (booleano alternando) o
  SV (senoide 9-2LE ~20/s) en la **misma interfaz**. Elige la misma interfaz en el
  monitor y pulsa **Iniciar**. Funciona incluso con la interfaz **`lo`**
  (loopback) para una prueba local sin red ni IED.
- **Publicador externo / IED real:** un IED en la LAN, o los ejemplos del repo:
  ```sh
  sudo cargo run --example goose_publish -p iec61850-goose --features net -- <iface>
  sudo cargo run --example sv_publish    -p iec61850-sv    --features net -- <iface>
  ```

> Prueba rápida 100% local: interfaz **`lo`** → **Publicar demo** (GOOSE y SV) →
> **Iniciar** los monitores. (Igual requiere `CAP_NET_RAW` en el binario.)

> Tras el primer `pnpm install` se genera `pnpm-lock.yaml`: **commitéalo** y usa
> `pnpm install --frozen-lockfile` para instalaciones reproducibles (no muta el
> lockfile). pnpm aísla dependencias (sin *phantom deps*) y verifica integridad.

Al abrir, la app **arranca el simulador IED, conecta, descubre y habilita el RCB**
`IED1LD0/LLN0.rcb1[RP]` automáticamente (en `127.0.0.1:10102`): los **reportes
empiezan a verse solos** en el pie (el simulador varía una corriente cada segundo).
Selecciona una variable y **Leer**; en **Acciones**, **Escribir** la variable
seleccionada u **Operar** un control `[CO]` (ambas piden **confirmación**).

> Para conectar a un **IED real** en vez del simulado: **Desconectar**, **■ Detener
> simulador**, pon su `IP:102` en «IED» y **Conectar**.

⚠ Escribir/Operar modifican el IED: úsalo contra el simulador o equipos fuera de
servicio.

## Empaquetar / instaladores

`pnpm tauri build` genera el instalable del SO actual (los iconos y
`bundle.active = true` ya están en `src-tauri/tauri.conf.json`):

- **Linux:** `.deb` y `.rpm`. La **post-instalación** aplica
  `setcap cap_net_raw+ep` al binario instalado, así los monitores GOOSE/SV
  (capa 2) funcionan **sin root** y sin pasos manuales.
- **Windows:** instalador **NSIS** (`.exe`). WebView2 lo instala el propio
  instalador si falta. La capa 2 (GOOSE/SV/PCAP) usa **Npcap**
  (`wpcap.dll` cargada en tiempo de ejecución): instala Npcap desde
  <https://npcap.com> en modo *WinPcap API-compatible*. MMS/TCP funciona sin él.
- **macOS:** `.dmg`. MMS/TCP completo; sin backend de capa 2.

El workflow **`.github/workflows/installers.yml`** construye los tres en CI
(matriz ubuntu/windows/macos) al empujar un **tag `v*`** y adjunta los
instaladores a la GitHub Release.

### Firma de código (Windows)

Sin firmar, el instalador `.exe` dispara el aviso *SmartScreen* («editor
desconocido»). Para firmarlo en CI con Authenticode, añade al repositorio dos
**secretos** de GitHub Actions (el paso de firma se activa solo si existen):

- `WINDOWS_PFX_BASE64` — el certificado `.pfx` en base64
  (`base64 -w0 cert.pfx` en Linux/macOS, o `certutil -encode`).
- `WINDOWS_PFX_PASSWORD` — su contraseña.

El workflow firma el instalador con `signtool` (SDK de Windows, ya en el
runner) y sella el tiempo. Sin los secretos, el build sale **sin firmar** pero
funcional.

### Smoke test (Windows)

Tras instalar el `.exe`, `scripts/smoke-windows.ps1` comprueba las piezas que
solo dependen del SO (binario, WebView2, Npcap, arranque):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows.ps1
```

## Arquitectura

- `src-tauri/` (Rust): estado con `tokio::sync::Mutex<Option<Arc<MmsClient>>>`;
  comandos `#[tauri::command]` (`connect`, `discover`, `read`, `write`,
  `operate`, `select`, `enable_report`/`disable_report`); los reportes se emiten
  como evento `report` (`AppHandle::emit`).
- `src/` (React/TS): `invoke` (`@tauri-apps/api/core`) para los comandos y
  `listen("report", …)` (`@tauri-apps/api/event`) para los reportes en vivo;
  diálogo de confirmación antes de escribir/operar.
