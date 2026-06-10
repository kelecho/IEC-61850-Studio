//! Tipos básicos de atributos de datos (`bType` en SCL) — IEC 61850-7-2 / 7-3.
//!
//! Son los tipos "hoja" que toma un `DataAttribute`. Los compuestos
//! (`Struct`) se modelan con sub-atributos en el árbol.

use std::fmt;
use std::str::FromStr;

/// Tipo básico de un atributo de datos.
///
/// Los tipos con longitud máxima (cadenas/octetos) llevan `max_len` cuando se
/// conoce desde la plantilla SCL (`VisString255` → 255, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum BasicType {
    Boolean,
    Int8,
    Int16,
    Int32,
    Int64,
    Int8u,
    Int16u,
    Int32u,
    Float32,
    Float64,
    /// Enumerado; el `EnumType` referenciado se resuelve aparte.
    Enum,
    /// Double point position (estado de doble bit).
    Dbpos,
    /// Tap command.
    Tcmd,
    Quality,
    Timestamp,
    /// Visible string. `max_len` desde el tipo (p. ej. 255).
    VisString {
        max_len: Option<u32>,
    },
    /// Unicode string.
    Unicode {
        max_len: Option<u32>,
    },
    OctetString {
        max_len: Option<u32>,
    },
    /// Referencia a objeto (cadena con una ObjectReference).
    ObjRef,
    Currency,
    EntryTime,
    Check,
    /// Compuesto: el atributo tiene sub-atributos (hijos).
    Struct,
    /// Tipo no reconocido (robustez ante SCL propietarios/futuros);
    /// conserva el texto original del `bType`.
    Other(String),
}

impl BasicType {
    /// `true` si el tipo es compuesto (tiene sub-atributos).
    pub fn is_struct(&self) -> bool {
        matches!(self, BasicType::Struct)
    }

    /// Construye desde el `bType` de SCL. Nunca falla: tipos desconocidos
    /// caen en [`BasicType::Other`].
    ///
    /// Las longitudes máximas embebidas en el nombre (p. ej. `VisString255`)
    /// se extraen automáticamente.
    pub fn from_btype(s: &str) -> Self {
        use BasicType::*;
        match s {
            "BOOLEAN" => Boolean,
            "INT8" => Int8,
            "INT16" => Int16,
            "INT32" => Int32,
            "INT64" => Int64,
            "INT8U" => Int8u,
            "INT16U" => Int16u,
            "INT32U" => Int32u,
            "FLOAT32" => Float32,
            "FLOAT64" => Float64,
            "Enum" => Enum,
            "Dbpos" => Dbpos,
            "Tcmd" => Tcmd,
            "Quality" => Quality,
            "Timestamp" => Timestamp,
            "ObjRef" => ObjRef,
            "Currency" => Currency,
            "EntryTime" => EntryTime,
            "Check" => Check,
            "Struct" => Struct,
            _ => {
                if let Some(len) = s.strip_prefix("VisString") {
                    VisString {
                        max_len: len.parse().ok(),
                    }
                } else if let Some(len) = s.strip_prefix("Unicode") {
                    Unicode {
                        max_len: len.parse().ok(),
                    }
                } else if let Some(len) = s.strip_prefix("Octet") {
                    // "Octet64" / "OctetString64" → extrae dígitos finales
                    let digits: String = len.chars().filter(|c| c.is_ascii_digit()).collect();
                    OctetString {
                        max_len: digits.parse().ok(),
                    }
                } else {
                    Other(s.to_string())
                }
            }
        }
    }

    /// Representación textual canónica del `bType` (sin la longitud).
    pub fn as_str(&self) -> &str {
        use BasicType::*;
        match self {
            Boolean => "BOOLEAN",
            Int8 => "INT8",
            Int16 => "INT16",
            Int32 => "INT32",
            Int64 => "INT64",
            Int8u => "INT8U",
            Int16u => "INT16U",
            Int32u => "INT32U",
            Float32 => "FLOAT32",
            Float64 => "FLOAT64",
            Enum => "Enum",
            Dbpos => "Dbpos",
            Tcmd => "Tcmd",
            Quality => "Quality",
            Timestamp => "Timestamp",
            VisString { .. } => "VisString",
            Unicode { .. } => "Unicode",
            OctetString { .. } => "OctetString",
            ObjRef => "ObjRef",
            Currency => "Currency",
            EntryTime => "EntryTime",
            Check => "Check",
            Struct => "Struct",
            Other(s) => s,
        }
    }
}

impl FromStr for BasicType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(BasicType::from_btype(s))
    }
}

impl fmt::Display for BasicType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types() {
        assert_eq!(BasicType::from_btype("BOOLEAN"), BasicType::Boolean);
        assert_eq!(BasicType::from_btype("FLOAT32"), BasicType::Float32);
        assert!(BasicType::from_btype("Struct").is_struct());
    }

    #[test]
    fn string_lengths() {
        assert_eq!(
            BasicType::from_btype("VisString255"),
            BasicType::VisString { max_len: Some(255) }
        );
        assert_eq!(
            BasicType::from_btype("Unicode255"),
            BasicType::Unicode { max_len: Some(255) }
        );
        assert_eq!(
            BasicType::from_btype("VisString"),
            BasicType::VisString { max_len: None }
        );
    }

    #[test]
    fn unknown_is_other() {
        assert_eq!(
            BasicType::from_btype("FooBar"),
            BasicType::Other("FooBar".into())
        );
    }
}
