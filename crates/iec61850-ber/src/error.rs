//! Error del codec BER.

/// Error del codec BER (codificación/decodificación ASN.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    #[error("fin de datos inesperado leyendo BER")]
    UnexpectedEof,
    #[error("longitud en forma indefinida no soportada")]
    IndefiniteLength,
    #[error("longitud BER excede el tamaño representable")]
    LengthOverflow,
    #[error("tag inesperado: esperado {expected}, encontrado {found}")]
    UnexpectedTag { expected: String, found: String },
    #[error("entero BER inválido")]
    BadInteger,
    #[error("booleano BER inválido")]
    BadBool,
    #[error("OID BER inválido")]
    BadOid,
    #[error("cadena BER inválida (no es UTF-8/ASCII válido)")]
    BadString,
    #[error("bit string BER inválido")]
    BadBitString,
    #[error("datos sobrantes tras el valor BER")]
    TrailingData,
    #[error("estructura BER inesperada: {0}")]
    Structure(String),
    #[error("anidamiento BER excede el máximo permitido")]
    DepthExceeded,
}
