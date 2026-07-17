//! Regresión de interoperabilidad contra un corpus **externo** de ficheros SCL
//! reales (p. ej. un checkout de libiec61850, ejemplos de fabricantes, etc.).
//!
//! No se vendorizan ficheros de terceros en el repo (evita problemas de licencia
//! como el GPL de libiec61850). En su lugar, apunta la variable de entorno a un
//! directorio con ficheros `.icd/.cid/.scd` y el test los recorre:
//!
//! ```sh
//! IEC61850_SCL_CORPUS=/ruta/a/libiec61850 \
//!   cargo test -p iec61850-scl --test external_corpus -- --nocapture
//! ```
//!
//! Sin la variable, el test se salta (no rompe el CI de quien no tenga el corpus).
//!
//! Criterio: **ningún fichero debe provocar un panic**. Se permite que un
//! fichero no parsee (algunos son inválidos a propósito), pero se reporta el
//! recuento para vigilar regresiones.

use std::path::PathBuf;

fn collect_scl(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_scl(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_ascii_lowercase();
            if matches!(ext.as_str(), "icd" | "cid" | "scd" | "iid" | "ssd") {
                out.push(path);
            }
        }
    }
}

#[test]
fn external_scl_corpus_never_panics() {
    let Ok(root) = std::env::var("IEC61850_SCL_CORPUS") else {
        eprintln!("IEC61850_SCL_CORPUS no definida: test omitido");
        return;
    };
    let mut files = Vec::new();
    collect_scl(std::path::Path::new(&root), &mut files);
    assert!(!files.is_empty(), "no se hallaron ficheros SCL en {root}");

    let mut parsed = 0usize;
    let mut failed = 0usize;
    for path in &files {
        // parse_scl_file no debe entrar en pánico para NINGUNA entrada; un Err
        // controlado es aceptable (fichero inválido), un panic no.
        match iec61850_scl::parse_scl_file(path) {
            Ok(doc) => {
                // La resolución lenient tampoco debe entrar en pánico.
                let _ = doc.resolve_lenient();
                parsed += 1;
            }
            Err(e) => {
                failed += 1;
                eprintln!("no parsea {}: {e}", path.display());
            }
        }
    }
    eprintln!(
        "corpus externo: {} ficheros, {parsed} parsean, {failed} fallan",
        files.len()
    );
}
