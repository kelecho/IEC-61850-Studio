//! # iec61850
//!
//! Fachada de la librería IEC 61850 en Rust. Re-exporta los crates por
//! componente bajo *feature flags*, de modo que los consumidores usen un único
//! `iec61850 = { features = [...] }` estable a medida que se añadan las capas
//! de comunicación (MMS, GOOSE, Sampled Values).
//!
//! - [`model`]: modelo de datos (siempre disponible).
//! - [`scl`]: parser SCL (feature `scl`, activa por defecto).
//!
//! ```no_run
//! # #[cfg(feature = "scl")]
//! # fn main() -> Result<(), iec61850::scl::SclError> {
//! let model = iec61850::scl::load_model("subestacion.scd")?;
//! for (reference, _da) in model.iter_data_attributes() {
//!     println!("{reference}");
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "scl"))]
//! # fn main() {}
//! ```

/// Modelo de datos IEC 61850 (jerarquía Server/LD/LN/DO/DA, referencias).
pub use iec61850_model as model;

/// Parser SCL (IEC 61850-6) y resolución al modelo de datos.
#[cfg(feature = "scl")]
pub use iec61850_scl as scl;

/// MMS (IEC 61850-8-1): cliente y/o servidor asíncronos.
#[cfg(any(feature = "mms", feature = "mms-server"))]
pub use iec61850_mms as mms;

/// GOOSE (IEC 61850-8-1): codec y, con `goose-net`, publicador/suscriptor.
#[cfg(feature = "goose")]
pub use iec61850_goose as goose;

/// Sampled Values (IEC 61850-9-2): codec y, con `sv-net`, publicador/suscriptor.
#[cfg(feature = "sv")]
pub use iec61850_sv as sv;

/// Integración SCL → configuración de GOOSE/SV (feature `config`).
#[cfg(feature = "config")]
pub mod config;

// Re-exports de conveniencia de los tipos más usados.
pub use iec61850_model::{Model, NodeRef, ObjectReference};
