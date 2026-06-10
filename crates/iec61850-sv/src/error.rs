//! Errores de Sampled Values.

/// Error de codificación/decodificación o transporte SV.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SvError {
    #[error("PDU/ASDU SV malformado: {0}")]
    Malformed(String),
    #[error("error de codec BER: {0}")]
    Ber(#[from] iec61850_ber::BerError),
    #[error("error de capa 2: {0}")]
    L2(#[from] iec61850_l2::L2Error),
}
