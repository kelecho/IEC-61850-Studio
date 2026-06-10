# iec61850-gui

App de escritorio de **demostración** (egui/eframe) que consume la librería
`iec61850`: cliente MMS para **conectar a un IED, descubrir y leer variables, ver
reportes (RCB) en vivo** y **escribir / operar** (con diálogo de confirmación,
porque modifican el IED).

No se publica en crates.io (`publish = false`); es un ejemplo de integración.

## Ejecutar (demo con el IED simulado)

```sh
# Terminal 1 — IED simulado (servidor MMS en 0.0.0.0:10102):
cargo run --example ied_sim -p iec61850-mms --features server

# Terminal 2 — la app:
cargo run -p iec61850-gui
```

En la app: **Conectar** a `127.0.0.1:10102` → **Descubrir** → selecciona
`IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]` y pulsa **Leer**. En "Reportes en vivo",
**Habilitar** `IED1LD0/LLN0.rcb1[RP]`; los reportes aparecen cuando cambia un
miembro del dataset (p. ej. el `ied_sim` varía una corriente periódicamente).

En el panel **Acciones** (derecha) puedes **Escribir** la variable seleccionada
(elige tipo + valor) y, para un control `[CO]` (p. ej. `IED1LD0/GGIO1.SPCSO1[CO]`),
**Seleccionar** y **Operar**. Escribir/Operar piden **confirmación** porque
modifican el IED. ⚠ Úsalo solo contra simulador o equipos fuera de servicio.

## Requisitos de compilación (Linux)

eframe necesita librerías del sistema para enlazar/ejecutar la GUI; en Debian/Ubuntu:

```sh
sudo apt install libxkbcommon-dev libwayland-dev libgl1-mesa-dev libxcb1-dev pkg-config
```

## Arquitectura

- Hilo principal: `eframe`/egui (UI inmediata).
- Hilo de fondo: runtime `tokio` con `iec61850::mms::MmsClient`.
- Puente: comandos UI→backend (`tokio::sync::mpsc`) y eventos backend→UI
  (`std::sync::mpsc`, sondeados cada frame); el backend despierta la UI con
  `egui::Context::request_repaint`.
