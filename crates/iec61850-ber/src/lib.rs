//! # iec61850-ber
//!
//! Codec **BER** (ASN.1 Basic Encoding Rules) escrito a mano y el tipo `Data`
//! de MMS ([`MmsData`]), compartidos por las capas MMS y GOOSE de la librería
//! IEC 61850. Sin dependencias de red ni del modelo: sólo `thiserror`.

pub mod ber;
pub mod data;
pub mod error;

pub use ber::{BerReader, BerWriter, BitString, Tag, TagClass, Tlv};
pub use data::{MmsData, UtcTime};
pub use error::BerError;
