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

pub use control::{ControlParameters, OrCat, add_cause};
pub use error::{BerError, DataAccessError, MmsError};
pub use mapping::{MappingError, mms_to_object_reference, object_reference_to_mms};
pub use mms::{
    CommandTermination, FileAttributes, FileChunk, FileDirectory, FileEntry, FileOpen,
    IdentifyResponse, LastApplError, MmsData, Report, ReportConfig, ReportEntry, StructComponent,
    TypeSpec, VariableAttributes, WriteResult,
};

#[cfg(feature = "client")]
pub use client::MmsClient;

#[cfg(feature = "server")]
pub use server::{
    AuthPolicy, MmsServer, Permissions, Role, ServerHandle, ServerLimits, ServerModel, Store,
};

/// Access tokens firmados (RBAC, IEC 62351-8) y las primitivas de firma
/// (re-exportadas de [`iec61850_l2`], la criptografía compartida del proyecto).
#[cfg(feature = "tokens")]
pub use iec61850_l2::{EcdsaSigner, EcdsaVerifier, HmacKey, Signer, Verifier};
#[cfg(feature = "tokens")]
pub use mms::{AccessToken, TokenError, token};

#[cfg(all(feature = "tls", any(feature = "client", feature = "server")))]
pub use tokio_rustls::{TlsAcceptor, TlsConnector};
/// Configuración TLS de transporte (mTLS, IEC 62351-3).
#[cfg(all(feature = "tls", any(feature = "client", feature = "server")))]
pub use transport::tls::{
    CertStatus, CrlInfo, OcspResponse, OcspSingleResponse, PkiError, RevocationSource,
    TlsClientOptions, TlsServerOptions, cert_common_name, cert_serial_number, cert_validity,
    certs_from_pem, key_from_pem, parse_crl, parse_ocsp_response, validate_certificate,
};
