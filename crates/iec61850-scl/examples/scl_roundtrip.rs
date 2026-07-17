//! Round-trip de escritura SCL: parsea uno o varios ficheros, los serializa de
//! vuelta a XML, re-parsea el resultado y comprueba que el modelo resuelto es
//! equivalente (mismo nº de IED/LD y sin nuevos errores de resolución).
//!
//! Uso: cargo run -p iec61850-scl --example scl_roundtrip -- f1.icd [f2.cid ...]

use iec61850_scl::{Severity, parse_scl_file, parse_scl_str, write_scl_str};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("uso: scl_roundtrip <fichero.scl> [más...]");
        std::process::exit(2);
    }
    let mut ok = 0usize;
    let mut fail = 0usize;
    for path in &paths {
        match round_trip(path) {
            Ok(msg) => {
                ok += 1;
                println!("OK   {path}: {msg}");
            }
            Err(e) => {
                fail += 1;
                println!("FAIL {path}: {e}");
            }
        }
    }
    println!(
        "\n== {} ficheros, {ok} round-trip OK, {fail} fallan ==",
        paths.len()
    );
}

fn round_trip(path: &str) -> Result<String, String> {
    let doc = parse_scl_file(path).map_err(|e| format!("parse original: {e}"))?;
    let (m1, _) = doc.clone().resolve_lenient();
    let n_ld1: usize = m1.ieds.values().map(|s| s.logical_devices.len()).sum();

    let xml = write_scl_str(&doc).map_err(|e| format!("serializar: {e}"))?;
    let doc2 = parse_scl_str(&xml).map_err(|e| format!("re-parsear el XML generado: {e}"))?;
    let (m2, diags) = doc2.resolve_lenient();
    let n_ld2: usize = m2.ieds.values().map(|s| s.logical_devices.len()).sum();
    let errs = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();

    if m1.ieds.len() != m2.ieds.len() || n_ld1 != n_ld2 {
        return Err(format!(
            "modelo distinto: {} IED/{n_ld1} LD → {} IED/{n_ld2} LD",
            m1.ieds.len(),
            m2.ieds.len()
        ));
    }
    if errs > 0 {
        return Err(format!("{errs} errores de resolución tras round-trip"));
    }
    Ok(format!("{} IED, {n_ld1} LD conservados", m1.ieds.len()))
}
