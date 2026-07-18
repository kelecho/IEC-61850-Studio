//! App de escritorio (egui) de demostración: cliente MMS que conecta a un IED,
//! descubre y lee variables, y muestra los reportes (RCB) en vivo. Solo
//! lectura/monitoreo. Consume la librería `iec61850` (feature `mms`).
//!
//! Demo: levanta el IED simulado y luego esta app:
//!   cargo run --example ied_sim -p iec61850-mms --features server
//!   cargo run -p iec61850-gui

mod app;
mod backend;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "IEC 61850 (cliente egui — OBSOLETO, usa IEC 61850 Studio)",
        options,
        Box::new(|cc| {
            let (evt_tx, evt_rx) = std::sync::mpsc::channel();
            let cmd_tx = backend::spawn(evt_tx, cc.egui_ctx.clone());
            Ok(Box::new(app::GuiApp::new(cmd_tx, evt_rx)))
        }),
    )
}
