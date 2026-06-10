//! Error de la capa 2.

/// Error de codificación/parseo de cabecera o de transporte de capa 2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum L2Error {
    #[error("trama truncada")]
    Truncated,
    #[error("trama malformada: {0}")]
    Malformed(String),
    #[error("EtherType inesperado: {0:#06X}")]
    WrongEthertype(u16),

    #[cfg(feature = "net")]
    #[error("error de E/S de socket: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "net")]
    #[error("permiso denegado (se requiere CAP_NET_RAW o root)")]
    Permission,
}
