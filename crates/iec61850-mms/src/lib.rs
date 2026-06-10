//! # iec61850-mms
//!
//! Cliente **MMS** (Manufacturing Message Specification, ISO 9506) con el mapeo
//! **IEC 61850-8-1**, sobre la pila ISO/OSI en TCP/102
//! (`MMS → ACSE → Presentation → Session → COTP → TPKT → TCP`).
//!
//! El codec **BER** ([`ber`]) y el ensamblado de PDUs están escritos a mano y se
//! compilan/testean sin red. El cliente asíncrono ([`client`], sobre `tokio`) se
//! activa con la feature `client`.

/// Codec BER compartido, re-exportado desde [`iec61850_ber`].
pub use iec61850_ber::ber;

pub mod control;
pub mod error;
pub mod mapping;
pub mod mms;
pub mod transport;
pub mod upper;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub use control::{ControlParameters, OrCat};
pub use error::{BerError, DataAccessError, MmsError};
pub use mapping::{MappingError, mms_to_object_reference, object_reference_to_mms};
pub use mms::{
    CommandTermination, FileAttributes, FileChunk, FileDirectory, FileEntry, FileOpen,
    IdentifyResponse, MmsData, Report, ReportConfig, ReportEntry, StructComponent, TypeSpec,
    VariableAttributes, WriteResult,
};

#[cfg(feature = "client")]
pub use client::MmsClient;

#[cfg(feature = "server")]
pub use server::{MmsServer, ServerHandle, ServerModel, Store};

#[cfg(all(feature = "tls", any(feature = "client", feature = "server")))]
pub use tokio_rustls::{TlsAcceptor, TlsConnector};
/// Configuración TLS de transporte (mTLS, IEC 62351-3).
#[cfg(all(feature = "tls", any(feature = "client", feature = "server")))]
pub use transport::tls::{TlsClientOptions, TlsServerOptions, certs_from_pem, key_from_pem};
