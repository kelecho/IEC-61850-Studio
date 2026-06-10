//! Lectura de documentos SCL desde texto o disco.

use std::path::Path;

use crate::error::SclError;
use crate::model::SclDocument;

/// Parsea un documento SCL desde una cadena XML.
pub fn parse_scl_str(xml: &str) -> Result<SclDocument, SclError> {
    let doc: SclDocument = quick_xml::de::from_str(xml)?;
    Ok(doc)
}

/// Parsea un documento SCL desde un archivo (`.icd`, `.cid`, `.scd`, `.ssd`).
pub fn parse_scl_file<P: AsRef<Path>>(path: P) -> Result<SclDocument, SclError> {
    let path = path.as_ref();
    let xml = std::fs::read_to_string(path).map_err(|source| SclError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_scl_str(&xml)
}
