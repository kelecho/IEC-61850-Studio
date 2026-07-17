//! Audita uno o varios ficheros SCL con el parser en modo *lenient*: reporta si
//! parsea, cuántos IED/LD resuelve y los diagnósticos (warnings/errores) por
//! fichero. Útil para validar interoperabilidad contra SCL de terceros.
//!
//! Uso:
//!   cargo run -p iec61850-scl --example scl_audit -- fichero1.icd [fichero2.cid ...]
//!   cargo run -p iec61850-scl --example scl_audit -- $(find /ruta -name '*.icd')

use iec61850_scl::{Severity, parse_scl_file};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("uso: scl_audit <fichero.scl> [más ficheros...]");
        std::process::exit(2);
    }

    let mut ok = 0usize;
    let mut parse_fail = 0usize;
    let mut with_errors = 0usize;

    for path in &paths {
        match parse_scl_file(path) {
            Ok(doc) => {
                let (model, diags) = doc.resolve_lenient();
                let n_ied = model.ieds.len();
                let n_ld: usize = model.ieds.values().map(|s| s.logical_devices.len()).sum();
                let errs = diags
                    .iter()
                    .filter(|d| d.severity == Severity::Error)
                    .count();
                let warns = diags.len() - errs;
                if errs > 0 {
                    with_errors += 1;
                }
                ok += 1;
                println!(
                    "OK   {path}\n     {n_ied} IED, {n_ld} LD, {errs} errores, {warns} warnings",
                );
                for d in diags
                    .iter()
                    .filter(|d| d.severity == Severity::Error)
                    .take(5)
                {
                    println!("       error @ {}: {}", d.location, d.message);
                }
            }
            Err(e) => {
                parse_fail += 1;
                println!("FAIL {path}\n     no parsea: {e}");
            }
        }
    }

    println!(
        "\n== resumen: {} ficheros, {ok} parsean, {parse_fail} fallan, {with_errors} con errores de resolución ==",
        paths.len()
    );
}
