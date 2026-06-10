// Evita una consola extra en Windows en modo release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    iec61850_tauri_lib::run();
}
