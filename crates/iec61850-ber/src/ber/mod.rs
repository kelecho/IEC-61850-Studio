//! Codec BER (ASN.1 Basic Encoding Rules) escrito a mano, acotado a lo que MMS
//! necesita. No depende de tokio ni de ningún crate de terceros.

pub mod length;
pub mod prim;
pub mod reader;
pub mod tag;
pub mod writer;

pub use prim::BitString;
pub use reader::{BerReader, Tlv};
pub use tag::{Tag, TagClass};
pub use writer::BerWriter;
