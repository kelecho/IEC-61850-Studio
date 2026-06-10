//! # iec61850-model
//!
//! Modelo de datos IEC 61850 (parte 7-x) en tipos de Rust: la jerarquía
//! `Server → LogicalDevice → LogicalNode → DataObject → DataAttribute`, junto
//! con las primitivas del estándar (restricciones funcionales, clases de datos
//! comunes, tipos básicos) y la [`ObjectReference`] para direccionar nodos.
//!
//! Este crate **no** depende de SCL ni de ninguna pila de comunicación: es el
//! núcleo común que reutilizan el parser SCL y las futuras capas MMS/GOOSE/SV.
//!
//! ## Ejemplo
//!
//! ```
//! use iec61850_model::{Model, ObjectReference};
//!
//! let r: ObjectReference = "IED1LD0/LLN0.Mod.stVal".parse().unwrap();
//! assert_eq!(r.ln, "LLN0");
//! assert_eq!(r.path, vec!["Mod", "stVal"]);
//! ```
//!
//! La función `serde` (opcional) habilita `Serialize`/`Deserialize` en todos
//! los tipos del modelo, útil para volcados de diagnóstico.

pub mod basic_type;
pub mod cdc;
pub mod fc;
pub mod model;
pub mod quality;
pub mod reference;
pub mod tree;
pub mod value;

pub use basic_type::BasicType;
pub use cdc::CommonDataClass;
pub use fc::FunctionalConstraint;
pub use model::{DatasetMember, Model, NodeRef};
pub use quality::{Quality, Source, TimeQuality, Timestamp, Validity};
pub use reference::{ObjectReference, ParseReferenceError};
pub use tree::{
    DataAttribute, DataObject, DataSet, Fcda, LogicalDevice, LogicalNode, ReportControl, Server,
    TriggerOptions,
};
pub use value::Value;
