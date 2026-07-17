#![no_main]
//! Fuzz del parser SCL + resolución de plantillas. Un fichero ICD/CID/SCD es
//! entrada de terceros (lo entrega el integrador); debe digerir cualquier XML
//! sin panic. Se prueba el modo lenient (el de la herramienta) end-to-end.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(doc) = iec61850_scl::parse_scl_str(text) {
            let _ = doc.resolve_lenient();
        }
    }
});
