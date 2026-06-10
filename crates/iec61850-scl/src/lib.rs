//! # iec61850-scl
//!
//! Parser de **SCL** (Substation Configuration Language, IEC 61850-6) y
//! resolución de plantillas al modelo de datos de [`iec61850_model`].
//!
//! El flujo típico:
//!
//! 1. [`parse_scl_file`] / [`parse_scl_str`] → [`SclDocument`] (AST fiel al XML).
//! 2. [`SclDocument::resolve`] → [`iec61850_model::Model`] (árbol instanciado,
//!    con plantillas resueltas y valores de `DAI` aplicados).
//!
//! Para cargar archivos imperfectos sin abortar, use
//! [`SclDocument::resolve_lenient`], que devuelve los [`Diagnostic`]
//! encontrados.
//!
//! ```no_run
//! let doc = iec61850_scl::parse_scl_file("subestacion.scd")?;
//! let model = doc.resolve()?;
//! if let Some(node) = model.find("IED1LD0/LLN0.Mod.stVal") {
//!     println!("{node:?}");
//! }
//! # Ok::<(), iec61850_scl::SclError>(())
//! ```

pub mod error;
pub mod model;
pub mod parse;
pub mod resolve;

pub use error::{Diagnostic, SclError, Severity};
pub use model::{Header, SclDocument};
pub use parse::{parse_scl_file, parse_scl_str};

/// Conveniencia: parsea un archivo SCL y lo resuelve a un [`Model`] en un paso.
///
/// [`Model`]: iec61850_model::Model
pub fn load_model<P: AsRef<std::path::Path>>(path: P) -> Result<iec61850_model::Model, SclError> {
    parse_scl_file(path)?.resolve()
}
