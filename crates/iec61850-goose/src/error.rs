//! Errores de GOOSE.

/// Error de codificación/decodificación o transporte GOOSE.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GooseError {
    #[error("trama GOOSE truncada o malformada: {0}")]
    Malformed(String),
    #[error("error de codec BER: {0}")]
    Ber(#[from] iec61850_ber::BerError),
    #[error("error de capa 2: {0}")]
    L2(#[from] iec61850_l2::L2Error),
}
