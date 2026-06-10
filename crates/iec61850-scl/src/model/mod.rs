//! AST de SCL (IEC 61850-6): estructuras serde fieles al XML, sin resolver.

pub mod communication;
pub mod control;
pub mod ied;
pub mod instance;
pub mod scl;
pub mod substation;
pub mod templates;

pub use communication::Communication;
pub use ied::{AccessPoint, Ied, LDevice, Ln, Server};
pub use scl::{Header, SclDocument};
pub use substation::Substation;
pub use templates::DataTypeTemplates;
