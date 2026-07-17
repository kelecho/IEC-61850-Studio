//! Servicio MMS `GetVariableAccessAttributes` (ISO 9506-2, servicio `[6]`).
//!
//! Devuelve la **especificación de tipo** (`TypeSpecification`) de una variable:
//! booleano, entero/sin signo (con su anchura de bits), flotante, bit-string,
//! octet-string, timestamps, y los compuestos `array`/`structure` (recursivos).
//!
//! Es la pieza que permite **explorar el tipo de un IED sin tener su SCL** — el
//! caso de campo donde no se dispone del archivo de ingeniería. Antes el
//! explorador dependía del SCL o de heurística sobre los nombres.

use std::fmt;

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::data::MmsData;
use crate::mms::pdu::{self, service};

/// Especificación de tipo MMS (`TypeSpecification`, ISO 9506-2). Recursiva para
/// `array` y `structure`.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeSpec {
    Boolean,
    /// Entero con signo de `n` bits.
    Integer(u8),
    /// Entero sin signo de `n` bits.
    Unsigned(u8),
    /// Flotante: anchura total y anchura de exponente, en bits.
    FloatingPoint {
        format_width: u8,
        exponent_width: u8,
    },
    /// Bit-string de tamaño dado (negativo = tamaño fijo).
    BitString(i32),
    OctetString(i32),
    VisibleString(i32),
    MmsString(i32),
    /// Hora binaria: `true` = 6 octetos (con fecha), `false` = 4 octetos.
    BinaryTime(bool),
    GeneralizedTime,
    UtcTime,
    /// BCD de `n` dígitos.
    Bcd(u8),
    ObjId,
    Array {
        elements: u32,
        element: Box<TypeSpec>,
    },
    Structure(Vec<StructComponent>),
    /// Referencia a un tipo con nombre (`typeName`, poco habitual en 61850).
    TypeName(String),
    /// Alternativa de `TypeSpecification` no reconocida (número de tag de contexto).
    Other(u32),
}

/// Componente de una `structure`.
#[derive(Debug, Clone, PartialEq)]
pub struct StructComponent {
    pub name: Option<String>,
    pub ty: TypeSpec,
}

/// Respuesta de `GetVariableAccessAttributes`.
#[derive(Debug, Clone, PartialEq)]
pub struct VariableAttributes {
    /// `true` si la variable puede borrarse vía MMS (informativo).
    pub mms_deletable: bool,
    pub type_spec: TypeSpec,
}

// --- Tags de las alternativas de TypeSpecification ---
const TS_TYPE_NAME: Tag = Tag::context(0, true);
const TS_ARRAY: Tag = Tag::context(1, true);
const TS_STRUCTURE: Tag = Tag::context(2, true);
const TS_BOOLEAN: Tag = Tag::context(3, false);
const TS_BIT_STRING: Tag = Tag::context(4, false);
const TS_INTEGER: Tag = Tag::context(5, false);
const TS_UNSIGNED: Tag = Tag::context(6, false);
const TS_FLOAT: Tag = Tag::context(7, true);
const TS_OCTET_STRING: Tag = Tag::context(9, false);
const TS_VISIBLE_STRING: Tag = Tag::context(10, false);
const TS_GENERALIZED_TIME: Tag = Tag::context(11, false);
const TS_BINARY_TIME: Tag = Tag::context(12, false);
const TS_BCD: Tag = Tag::context(13, false);
const TS_OBJ_ID: Tag = Tag::context(15, false);
const TS_MMS_STRING: Tag = Tag::context(16, false);
const TS_UTC_TIME: Tag = Tag::context(17, false);

// --- Cliente: petición ---

/// Escribe el servicio `getVariableAccessAttributes [6] { name [0] { domain-specific } }`.
pub fn write_request(w: &mut BerWriter, domain_id: &str, item_id: &str) {
    w.tlv(service::GET_VARIABLE_ACCESS_ATTRIBUTES, |w| {
        // GetVariableAccessAttributes-Request CHOICE → name [0] ObjectName
        w.tlv(Tag::context(0, true), |w| {
            // ObjectName: domain-specific [1] IMPLICIT SEQUENCE { domainId, itemId }
            w.tlv(Tag::context(1, true), |w| {
                w.visible_string(universal::VISIBLE_STRING, domain_id);
                w.visible_string(universal::VISIBLE_STRING, item_id);
            });
        });
    });
}

// --- Cliente: respuesta ---

/// Decodifica la respuesta `GetVariableAccessAttributes`.
pub fn decode_response(service_tlv: &Tlv<'_>) -> Result<VariableAttributes, MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_VARIABLE_ACCESS_ATTRIBUTES)?;
    let mut r = BerReader::new(content);
    // mmsDeletable [0] IMPLICIT BOOLEAN (mandatorio, pero toleramos su ausencia).
    let mms_deletable = match r.read_if(Tag::context(0, false))? {
        Some(c) => crate::ber::prim::decode_bool(c)?,
        None => false,
    };
    // typeSpecification (CHOICE: lleva su propio tag).
    let ts_tlv = r.read_tlv()?;
    let type_spec = decode_type_spec(&ts_tlv)?;
    Ok(VariableAttributes {
        mms_deletable,
        type_spec,
    })
}

/// Profundidad máxima de una `TypeSpecification` anidada (arrays/structures).
/// Corta el desbordamiento de pila ante una respuesta hostil o corrupta.
const MAX_TYPE_SPEC_DEPTH: usize = 16;

/// Decodifica recursivamente una `TypeSpecification`.
pub fn decode_type_spec(tlv: &Tlv<'_>) -> Result<TypeSpec, MmsError> {
    decode_type_spec_at(tlv, 0)
}

fn decode_type_spec_at(tlv: &Tlv<'_>, depth: usize) -> Result<TypeSpec, MmsError> {
    if depth >= MAX_TYPE_SPEC_DEPTH {
        return Err(MmsError::Ber(crate::error::BerError::DepthExceeded));
    }
    Ok(match tlv.tag {
        TS_BOOLEAN => TypeSpec::Boolean,
        TS_INTEGER => TypeSpec::Integer(small_u8(tlv.content)?),
        TS_UNSIGNED => TypeSpec::Unsigned(small_u8(tlv.content)?),
        TS_BIT_STRING => TypeSpec::BitString(small_i32(tlv.content)?),
        TS_OCTET_STRING => TypeSpec::OctetString(small_i32(tlv.content)?),
        TS_VISIBLE_STRING => TypeSpec::VisibleString(small_i32(tlv.content)?),
        TS_MMS_STRING => TypeSpec::MmsString(small_i32(tlv.content)?),
        TS_BCD => TypeSpec::Bcd(small_u8(tlv.content)?),
        TS_BINARY_TIME => TypeSpec::BinaryTime(crate::ber::prim::decode_bool(tlv.content)?),
        TS_GENERALIZED_TIME => TypeSpec::GeneralizedTime,
        TS_UTC_TIME => TypeSpec::UtcTime,
        TS_OBJ_ID => TypeSpec::ObjId,
        TS_FLOAT => decode_float_spec(tlv.content)?,
        TS_ARRAY => decode_array_spec(tlv.content, depth)?,
        TS_STRUCTURE => TypeSpec::Structure(decode_structure(tlv.content, depth)?),
        TS_TYPE_NAME => {
            // name [0] ObjectName → mejor esfuerzo: último VisibleString.
            TypeSpec::TypeName(last_visible_string(tlv.content).unwrap_or_default())
        }
        other => TypeSpec::Other(other.number),
    })
}

fn decode_float_spec(content: &[u8]) -> Result<TypeSpec, MmsError> {
    // floating-point [7] SEQUENCE { format-width Unsigned8, exponent-width Unsigned8 }
    let mut r = BerReader::new(content);
    let format_width = small_u8(r.expect(universal::INTEGER)?)?;
    let exponent_width = small_u8(r.expect(universal::INTEGER)?)?;
    Ok(TypeSpec::FloatingPoint {
        format_width,
        exponent_width,
    })
}

fn decode_array_spec(content: &[u8], depth: usize) -> Result<TypeSpec, MmsError> {
    // array [1] SEQUENCE { packed [0] BOOLEAN OPT, numberOfElements [1] Unsigned32,
    //                      elementType [2] TypeSpecification }
    let mut r = BerReader::new(content);
    let _ = r.read_if(Tag::context(0, false))?; // packed
    let elements = crate::ber::prim::decode_unsigned(r.expect(Tag::context(1, false))?)? as u32;
    let element_explicit = r.expect(Tag::context(2, true))?; // EXPLICIT (CHOICE)
    let mut er = BerReader::new(element_explicit);
    let inner = er.read_tlv()?;
    Ok(TypeSpec::Array {
        elements,
        element: Box::new(decode_type_spec_at(&inner, depth + 1)?),
    })
}

fn decode_structure(content: &[u8], depth: usize) -> Result<Vec<StructComponent>, MmsError> {
    let mut r = BerReader::new(content);
    let _ = r.read_if(Tag::context(0, false))?; // packed [0] BOOLEAN OPT
    let comps = r.expect(Tag::context(1, true))?; // components [1] SEQUENCE OF
    let mut cr = BerReader::new(comps);
    let mut out = Vec::new();
    while !cr.is_empty() {
        let comp_seq = cr.read_tlv()?; // SEQUENCE { componentName [0]?, componentType [1] }
        let mut csr = BerReader::new(comp_seq.content);
        let name = match csr.read_if(Tag::context(0, false))? {
            Some(c) => Some(crate::ber::prim::decode_visible_string(c)?.to_string()),
            None => None,
        };
        let ct = csr.expect(Tag::context(1, true))?; // componentType [1] EXPLICIT
        let mut ctr = BerReader::new(ct);
        let ty_tlv = ctr.read_tlv()?;
        out.push(StructComponent {
            name,
            ty: decode_type_spec_at(&ty_tlv, depth + 1)?,
        });
    }
    Ok(out)
}

// --- Servidor: petición + respuesta ---

/// Decodifica una petición `GetVariableAccessAttributes` (lado servidor) →
/// `(domainId, itemId)`.
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<(String, String), MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_VARIABLE_ACCESS_ATTRIBUTES)?;
    let mut r = BerReader::new(content);
    let name = r.expect(Tag::context(0, true))?; // name [0]
    let mut nr = BerReader::new(name);
    let ds = nr.expect(Tag::context(1, true))?; // domain-specific [1]
    let mut dr = BerReader::new(ds);
    let domain =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    let item =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    Ok((domain, item))
}

/// Codifica una respuesta `GetVariableAccessAttributes` (lado servidor).
pub fn encode_response(w: &mut BerWriter, attrs: &VariableAttributes) {
    w.tlv(service::GET_VARIABLE_ACCESS_ATTRIBUTES, |w| {
        w.boolean(Tag::context(0, false), attrs.mms_deletable);
        encode_type_spec(w, &attrs.type_spec);
    });
}

/// Codifica una `TypeSpecification`.
pub fn encode_type_spec(w: &mut BerWriter, ts: &TypeSpec) {
    match ts {
        TypeSpec::Boolean => w.null(TS_BOOLEAN),
        TypeSpec::Integer(n) => w.integer(TS_INTEGER, *n as i64),
        TypeSpec::Unsigned(n) => w.integer(TS_UNSIGNED, *n as i64),
        TypeSpec::BitString(n) => w.integer(TS_BIT_STRING, *n as i64),
        TypeSpec::OctetString(n) => w.integer(TS_OCTET_STRING, *n as i64),
        TypeSpec::VisibleString(n) => w.integer(TS_VISIBLE_STRING, *n as i64),
        TypeSpec::MmsString(n) => w.integer(TS_MMS_STRING, *n as i64),
        TypeSpec::Bcd(n) => w.integer(TS_BCD, *n as i64),
        TypeSpec::BinaryTime(b) => w.boolean(TS_BINARY_TIME, *b),
        TypeSpec::GeneralizedTime => w.null(TS_GENERALIZED_TIME),
        TypeSpec::UtcTime => w.null(TS_UTC_TIME),
        TypeSpec::ObjId => w.null(TS_OBJ_ID),
        TypeSpec::FloatingPoint {
            format_width,
            exponent_width,
        } => w.tlv(TS_FLOAT, |w| {
            w.integer(universal::INTEGER, *format_width as i64);
            w.integer(universal::INTEGER, *exponent_width as i64);
        }),
        TypeSpec::Array { elements, element } => w.tlv(TS_ARRAY, |w| {
            w.unsigned(Tag::context(1, false), *elements as u64);
            w.tlv(Tag::context(2, true), |w| encode_type_spec(w, element));
        }),
        TypeSpec::Structure(comps) => w.tlv(TS_STRUCTURE, |w| {
            w.tlv(Tag::context(1, true), |w| {
                for c in comps {
                    w.sequence(|w| {
                        if let Some(name) = &c.name {
                            w.visible_string(Tag::context(0, false), name);
                        }
                        w.tlv(Tag::context(1, true), |w| encode_type_spec(w, &c.ty));
                    });
                }
            });
        }),
        TypeSpec::TypeName(name) => w.tlv(TS_TYPE_NAME, |w| {
            w.visible_string(universal::VISIBLE_STRING, name)
        }),
        // Sin información suficiente para reconstruir una alternativa desconocida:
        // emitimos un boolean como marcador inocuo.
        TypeSpec::Other(_) => w.null(TS_BOOLEAN),
    }
}

impl TypeSpec {
    /// Sintetiza una `TypeSpecification` a partir de un valor `MmsData`. La usa el
    /// IED simulado para responder `GetVariableAccessAttributes` desde su almacén
    /// (sin nombres de componente, que el valor no conserva).
    pub fn from_mms_data(value: &MmsData) -> TypeSpec {
        match value {
            MmsData::Bool(_) => TypeSpec::Boolean,
            MmsData::Int(_) => TypeSpec::Integer(32),
            MmsData::Uint(_) => TypeSpec::Unsigned(32),
            MmsData::Float(_) => TypeSpec::FloatingPoint {
                format_width: 32,
                exponent_width: 8,
            },
            MmsData::BitString(b) => TypeSpec::BitString(b.len_bits() as i32),
            MmsData::Octets(v) => TypeSpec::OctetString(v.len() as i32),
            MmsData::Visible(s) => TypeSpec::VisibleString(s.len() as i32),
            MmsData::MmsString(s) => TypeSpec::MmsString(s.len() as i32),
            MmsData::Utc(_) => TypeSpec::UtcTime,
            MmsData::BinaryTime(v) => TypeSpec::BinaryTime(v.len() == 6),
            MmsData::Structure(items) => TypeSpec::Structure(
                items
                    .iter()
                    .map(|v| StructComponent {
                        name: None,
                        ty: TypeSpec::from_mms_data(v),
                    })
                    .collect(),
            ),
            MmsData::Array(items) => TypeSpec::Array {
                elements: items.len() as u32,
                element: Box::new(
                    items
                        .first()
                        .map(TypeSpec::from_mms_data)
                        .unwrap_or(TypeSpec::Boolean),
                ),
            },
            // MmsData es `#[non_exhaustive]`: cualquier variante futura.
            _ => TypeSpec::Other(0),
        }
    }
}

/// Resumen legible de un `TypeSpec` (para el explorador/UI).
impl fmt::Display for TypeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeSpec::Boolean => write!(f, "bool"),
            TypeSpec::Integer(n) => write!(f, "int{n}"),
            TypeSpec::Unsigned(n) => write!(f, "uint{n}"),
            TypeSpec::FloatingPoint { format_width, .. } => write!(f, "float{format_width}"),
            TypeSpec::BitString(n) => write!(f, "bitstring({n})"),
            TypeSpec::OctetString(n) => write!(f, "octets({n})"),
            TypeSpec::VisibleString(n) => write!(f, "vstring({n})"),
            TypeSpec::MmsString(n) => write!(f, "mmsstring({n})"),
            TypeSpec::BinaryTime(_) => write!(f, "binary-time"),
            TypeSpec::GeneralizedTime => write!(f, "generalized-time"),
            TypeSpec::UtcTime => write!(f, "utc-time"),
            TypeSpec::Bcd(n) => write!(f, "bcd({n})"),
            TypeSpec::ObjId => write!(f, "objid"),
            TypeSpec::Array { elements, element } => write!(f, "{element}[{elements}]"),
            TypeSpec::Structure(comps) => {
                write!(f, "struct{{")?;
                for (i, c) in comps.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    if let Some(name) = &c.name {
                        write!(f, "{name}: ")?;
                    }
                    write!(f, "{}", c.ty)?;
                }
                write!(f, "}}")
            }
            TypeSpec::TypeName(name) => write!(f, "@{name}"),
            TypeSpec::Other(n) => write!(f, "other({n})"),
        }
    }
}

fn small_u8(content: &[u8]) -> Result<u8, MmsError> {
    Ok(crate::ber::prim::decode_integer(content)?.clamp(0, u8::MAX as i64) as u8)
}

fn small_i32(content: &[u8]) -> Result<i32, MmsError> {
    Ok(crate::ber::prim::decode_integer(content)?.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
}

/// Último `VisibleString` dentro de un contenido (para `typeName`).
fn last_visible_string(content: &[u8]) -> Option<String> {
    let mut r = BerReader::new(content);
    let mut found = None;
    while !r.is_empty() {
        let tlv = r.read_tlv().ok()?;
        if tlv.tag == universal::VISIBLE_STRING {
            found = crate::ber::prim::decode_visible_string(tlv.content)
                .ok()
                .map(|s| s.to_string());
        } else if tlv.tag.constructed {
            if let Some(s) = last_visible_string(tlv.content) {
                found = Some(s);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape() {
        let mut w = BerWriter::new();
        write_request(&mut w, "IED1LD0", "MMXU1$MX$A$phsA");
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0xA6); // getVariableAccessAttributes [6]
        assert!(bytes.windows(7).any(|c| c == b"IED1LD0"));
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(svc.tag, service::GET_VARIABLE_ACCESS_ATTRIBUTES);
        let (d, i) = decode_request(&svc).unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "MMXU1$MX$A$phsA");
    }

    fn round_trip(ts: TypeSpec) -> TypeSpec {
        let attrs = VariableAttributes {
            mms_deletable: false,
            type_spec: ts,
        };
        let mut w = BerWriter::new();
        encode_response(&mut w, &attrs);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        decode_response(&svc).unwrap().type_spec
    }

    #[test]
    fn primitive_round_trips() {
        for ts in [
            TypeSpec::Boolean,
            TypeSpec::Integer(32),
            TypeSpec::Unsigned(16),
            TypeSpec::BitString(13),
            TypeSpec::OctetString(8),
            TypeSpec::VisibleString(20),
            TypeSpec::UtcTime,
            TypeSpec::FloatingPoint {
                format_width: 32,
                exponent_width: 8,
            },
        ] {
            assert_eq!(round_trip(ts.clone()), ts, "round-trip de {ts}");
        }
    }

    #[test]
    fn structure_and_array_round_trip() {
        // struct { mag: struct { f: float32 }, q: bitstring(13), t: utc-time }
        let mag = TypeSpec::Structure(vec![StructComponent {
            name: Some("f".into()),
            ty: TypeSpec::FloatingPoint {
                format_width: 32,
                exponent_width: 8,
            },
        }]);
        let ts = TypeSpec::Structure(vec![
            StructComponent {
                name: Some("mag".into()),
                ty: mag,
            },
            StructComponent {
                name: Some("q".into()),
                ty: TypeSpec::BitString(13),
            },
            StructComponent {
                name: Some("t".into()),
                ty: TypeSpec::UtcTime,
            },
        ]);
        assert_eq!(round_trip(ts.clone()), ts);

        let arr = TypeSpec::Array {
            elements: 3,
            element: Box::new(TypeSpec::Integer(32)),
        };
        assert_eq!(round_trip(arr.clone()), arr);
        assert_eq!(arr.to_string(), "int32[3]");
    }

    #[test]
    fn from_mms_data_derives_shape() {
        let v = MmsData::Structure(vec![MmsData::Float(1.0), MmsData::Bool(true)]);
        let ts = TypeSpec::from_mms_data(&v);
        assert_eq!(
            ts,
            TypeSpec::Structure(vec![
                StructComponent {
                    name: None,
                    ty: TypeSpec::FloatingPoint {
                        format_width: 32,
                        exponent_width: 8
                    }
                },
                StructComponent {
                    name: None,
                    ty: TypeSpec::Boolean
                },
            ])
        );
    }
}
