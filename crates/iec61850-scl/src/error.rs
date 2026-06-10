//! Errores y diagnósticos del parseo y resolución de SCL.

use std::path::PathBuf;

/// Error fatal al parsear o resolver un documento SCL.
#[derive(Debug, thiserror::Error)]
pub enum SclError {
    #[error("error de E/S leyendo '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("error de deserialización XML: {0}")]
    Xml(#[from] quick_xml::DeError),

    #[error("referencia de tipo sin resolver '{type_id}' (en {context})")]
    UnresolvedTypeRef { type_id: String, context: String },

    #[error("error de resolución en {location}: {message}")]
    Resolution { message: String, location: String },
}

/// Severidad de un diagnóstico no fatal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    Warning,
    Error,
}

/// Diagnóstico no fatal acumulado durante la resolución laxa
/// ([`crate::SclDocument::resolve_lenient`]).
///
/// Permite que una herramienta de diagnóstico cargue archivos SCL imperfectos
/// (referencias colgantes, tipos faltantes) reportando los problemas en lugar
/// de abortar.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    /// Ruta/contexto donde se detectó (p. ej. `IED1/LD0/MMXU1`).
    pub location: String,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            location: location.into(),
        }
    }

    pub fn warning(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            location: location.into(),
        }
    }
}
