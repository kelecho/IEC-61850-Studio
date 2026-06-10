//! Errores del cliente MMS, organizados por capa.

/// Error del codec BER, re-exportado desde el crate compartido [`iec61850_ber`].
pub use iec61850_ber::BerError;

/// Código de error de acceso a dato (`DataAccessError`, ISO 9506-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DataAccessError {
    #[error("objeto invalidado")]
    ObjectInvalidated,
    #[error("hardware con fallo")]
    HardwareFault,
    #[error("acceso temporalmente no disponible")]
    TemporarilyUnavailable,
    #[error("acceso denegado por el objeto")]
    ObjectAccessDenied,
    #[error("conflicto de acceso al objeto")]
    ObjectAccessUnsupported,
    #[error("objeto inexistente")]
    ObjectNonExistent,
    #[error("tipo de objeto inconsistente")]
    ObjectAttributeInconsistent,
    #[error("tipo de dato no soportado")]
    TypeUnsupported,
    #[error("inconsistencia de tipo")]
    TypeInconsistent,
    #[error("conflicto de estado del objeto")]
    ObjectValueInvalid,
    #[error("error de acceso a dato no reconocido ({0})")]
    Other(i64),
}

impl DataAccessError {
    /// Mapea el código entero del protocolo a la variante.
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => DataAccessError::ObjectInvalidated,
            1 => DataAccessError::HardwareFault,
            2 => DataAccessError::TemporarilyUnavailable,
            3 => DataAccessError::ObjectAccessDenied,
            4 => DataAccessError::ObjectAccessUnsupported,
            5 => DataAccessError::ObjectNonExistent,
            6 => DataAccessError::ObjectAttributeInconsistent,
            7 => DataAccessError::TypeUnsupported,
            8 => DataAccessError::TypeInconsistent,
            10 => DataAccessError::ObjectValueInvalid,
            other => DataAccessError::Other(other),
        }
    }

    /// Código entero del protocolo para esta variante (inverso de [`from_code`]).
    ///
    /// [`from_code`]: DataAccessError::from_code
    pub fn to_code(self) -> i64 {
        match self {
            DataAccessError::ObjectInvalidated => 0,
            DataAccessError::HardwareFault => 1,
            DataAccessError::TemporarilyUnavailable => 2,
            DataAccessError::ObjectAccessDenied => 3,
            DataAccessError::ObjectAccessUnsupported => 4,
            DataAccessError::ObjectNonExistent => 5,
            DataAccessError::ObjectAttributeInconsistent => 6,
            DataAccessError::TypeUnsupported => 7,
            DataAccessError::TypeInconsistent => 8,
            DataAccessError::ObjectValueInvalid => 10,
            DataAccessError::Other(c) => c,
        }
    }
}

/// Error de alto nivel del cliente MMS.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MmsError {
    #[cfg(any(feature = "client", feature = "server"))]
    #[error("error de E/S de transporte: {0}")]
    Io(#[from] std::io::Error),

    #[error("trama TPKT/COTP inválida: {0}")]
    Transport(String),

    #[error("error de codificación BER: {0}")]
    Ber(#[from] BerError),

    #[error("asociación rechazada: {0}")]
    AssociateRejected(String),

    #[error("servicio MMS rechazado: {0}")]
    ServiceReject(String),

    #[error("error de acceso a dato: {0}")]
    DataAccess(#[from] DataAccessError),

    #[error("invokeID inesperado: esperado {expected}, recibido {got}")]
    InvokeIdMismatch { expected: u32, got: u32 },

    #[error("PDU MMS inesperado")]
    UnexpectedPdu,

    #[error("la conexión se cerró")]
    ConnectionClosed,

    #[error("tiempo de espera agotado")]
    Timeout,

    #[error("control terminado negativamente (AddCause {add_cause})")]
    ControlTerminated { add_cause: i64 },

    #[error("sin CommandTermination dentro del plazo")]
    ControlTimeout,

    #[error("error TLS: {0}")]
    Tls(String),

    #[error("error de mapeo IEC 61850-8-1: {0}")]
    Mapping(#[from] crate::mapping::MappingError),
}
