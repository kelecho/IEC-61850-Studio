//! El tipo `Data` de MMS (ISO 9506) y su codec BER.
//!
//! `Data` es un CHOICE etiquetado con tags de **clase contexto**. Los valores
//! leídos de un servidor se decodifican a [`MmsData`]; el árbol soporta tipos
//! compuestos (`structure`, `array`).

use crate::ber::prim::{self, BitString};
use crate::ber::reader::{BerReader, Tlv};
use crate::ber::writer::BerWriter;
use crate::error::BerError;

/// Tags de contexto del CHOICE `Data`.
pub mod tags {
    use crate::ber::tag::Tag;
    pub const ARRAY: Tag = Tag::context(1, true);
    pub const STRUCTURE: Tag = Tag::context(2, true);
    pub const BOOLEAN: Tag = Tag::context(3, false);
    pub const BIT_STRING: Tag = Tag::context(4, false);
    pub const INTEGER: Tag = Tag::context(5, false);
    pub const UNSIGNED: Tag = Tag::context(6, false);
    pub const FLOATING_POINT: Tag = Tag::context(7, false);
    pub const OCTET_STRING: Tag = Tag::context(9, false);
    pub const VISIBLE_STRING: Tag = Tag::context(10, false);
    pub const BINARY_TIME: Tag = Tag::context(12, false);
    pub const BOOLEAN_ARRAY: Tag = Tag::context(14, false);
    pub const MMS_STRING: Tag = Tag::context(16, false);
    pub const UTC_TIME: Tag = Tag::context(17, false);
}

/// Marca de tiempo UTC de MMS: 8 octetos (4 segundos epoch + 3 fracción + 1 calidad).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTime {
    pub raw: [u8; 8],
}

impl UtcTime {
    /// Segundos desde el epoch (1970-01-01).
    pub fn seconds(&self) -> u32 {
        u32::from_be_bytes([self.raw[0], self.raw[1], self.raw[2], self.raw[3]])
    }
    /// Fracción de segundo (3 octetos).
    pub fn fraction(&self) -> u32 {
        u32::from_be_bytes([0, self.raw[4], self.raw[5], self.raw[6]])
    }
    /// Octeto de calidad del tiempo.
    pub fn quality(&self) -> u8 {
        self.raw[7]
    }
}

/// Valor de datos MMS decodificado.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MmsData {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    BitString(BitString),
    Octets(Vec<u8>),
    Visible(String),
    MmsString(String),
    Utc(UtcTime),
    BinaryTime(Vec<u8>),
    Structure(Vec<MmsData>),
    Array(Vec<MmsData>),
}

impl MmsData {
    /// Decodifica un `Data` desde un TLV ya leído.
    pub fn decode(tlv: &Tlv<'_>) -> Result<MmsData, BerError> {
        let c = tlv.content;
        let t = tlv.tag;
        let unexpected = || BerError::Structure(format!("tag Data inesperado: {t}"));

        match (t.number, t.constructed) {
            (3, false) => Ok(MmsData::Bool(prim::decode_bool(c)?)),
            (5, false) => Ok(MmsData::Int(prim::decode_integer(c)?)),
            (6, false) => Ok(MmsData::Uint(prim::decode_unsigned(c)?)),
            (7, false) => Ok(MmsData::Float(decode_float(c)?)),
            (9, false) => Ok(MmsData::Octets(c.to_vec())),
            (10, false) => Ok(MmsData::Visible(
                prim::decode_visible_string(c)?.to_string(),
            )),
            (16, false) => Ok(MmsData::MmsString(
                std::str::from_utf8(c)
                    .map_err(|_| BerError::BadString)?
                    .to_string(),
            )),
            (4, false) => Ok(MmsData::BitString(decode_bit_string(c)?)),
            (14, false) => Ok(MmsData::BitString(decode_bit_string(c)?)),
            (12, false) => Ok(MmsData::BinaryTime(c.to_vec())),
            (17, false) => {
                let raw: [u8; 8] = c
                    .try_into()
                    .map_err(|_| BerError::Structure("utc-time debe tener 8 octetos".into()))?;
                Ok(MmsData::Utc(UtcTime { raw }))
            }
            (2, true) => Ok(MmsData::Structure(decode_list(c)?)),
            (1, true) => Ok(MmsData::Array(decode_list(c)?)),
            _ => Err(unexpected()),
        }
    }

    /// Codifica el `Data` (necesario para Write, fase futura; aquí para tests).
    pub fn encode(&self, w: &mut BerWriter) {
        match self {
            MmsData::Bool(v) => w.boolean(tags::BOOLEAN, *v),
            MmsData::Int(v) => w.integer(tags::INTEGER, *v),
            MmsData::Uint(v) => w.unsigned(tags::UNSIGNED, *v),
            MmsData::Float(v) => w.primitive(tags::FLOATING_POINT, &encode_float(*v)),
            MmsData::BitString(bs) => w.bit_string(tags::BIT_STRING, bs),
            MmsData::Octets(b) => w.octet_string(tags::OCTET_STRING, b),
            MmsData::Visible(s) => w.visible_string(tags::VISIBLE_STRING, s),
            MmsData::MmsString(s) => w.primitive(tags::MMS_STRING, s.as_bytes()),
            MmsData::Utc(u) => w.primitive(tags::UTC_TIME, &u.raw),
            MmsData::BinaryTime(b) => w.primitive(tags::BINARY_TIME, b),
            MmsData::Structure(items) => w.tlv(tags::STRUCTURE, |w| {
                for it in items {
                    it.encode(w);
                }
            }),
            MmsData::Array(items) => w.tlv(tags::ARRAY, |w| {
                for it in items {
                    it.encode(w);
                }
            }),
        }
    }

    // --- accesores de conveniencia ---

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            MmsData::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            MmsData::Int(v) => Some(*v),
            MmsData::Uint(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            MmsData::Float(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MmsData::Visible(s) | MmsData::MmsString(s) => Some(s),
            _ => None,
        }
    }
}

fn decode_list(content: &[u8]) -> Result<Vec<MmsData>, BerError> {
    let mut r = BerReader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        out.push(MmsData::decode(&tlv)?);
    }
    Ok(out)
}

fn decode_bit_string(content: &[u8]) -> Result<BitString, BerError> {
    let (&unused, bytes) = content.split_first().ok_or(BerError::BadBitString)?;
    if unused > 7 {
        return Err(BerError::BadBitString);
    }
    Ok(BitString {
        unused_bits: unused,
        bytes: bytes.to_vec(),
    })
}

/// Decodifica un FloatingPoint de MMS: 1er octeto = nº bits de exponente, resto
/// = IEEE-754.
fn decode_float(content: &[u8]) -> Result<f64, BerError> {
    let (_exp_width, ieee) = content
        .split_first()
        .ok_or_else(|| BerError::Structure("floating-point vacío".into()))?;
    match ieee.len() {
        4 => Ok(f32::from_be_bytes(ieee.try_into().unwrap()) as f64),
        8 => Ok(f64::from_be_bytes(ieee.try_into().unwrap())),
        _ => Err(BerError::Structure(
            "floating-point con tamaño IEEE inválido".into(),
        )),
    }
}

fn encode_float(value: f64) -> Vec<u8> {
    let as32 = value as f32;
    if as32 as f64 == value {
        let mut v = Vec::with_capacity(5);
        v.push(8); // exponente de 8 bits (float32)
        v.extend_from_slice(&as32.to_be_bytes());
        v
    } else {
        let mut v = Vec::with_capacity(9);
        v.push(11); // exponente de 11 bits (float64)
        v.extend_from_slice(&value.to_be_bytes());
        v
    }
}

/// Lee un único `Data` desde el inicio de un buffer (helper para tests/decode).
pub fn decode_data(bytes: &[u8]) -> Result<MmsData, BerError> {
    let mut r = BerReader::new(bytes);
    let tlv = r.read_tlv()?;
    MmsData::decode(&tlv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(data: MmsData) {
        let mut w = BerWriter::new();
        data.encode(&mut w);
        let bytes = w.into_bytes();
        let back = decode_data(&bytes).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn scalar_round_trips() {
        round(MmsData::Bool(true));
        round(MmsData::Int(-42));
        round(MmsData::Uint(65000));
        round(MmsData::Visible("hello".into()));
        round(MmsData::Octets(vec![0xDE, 0xAD]));
        round(MmsData::Float(1.5));
        round(MmsData::Float(1234.5678)); // no representable en f32 → fuerza float64
    }

    #[test]
    fn float32_vector() {
        // 1.5f32 = 0x3FC00000 ; FloatingPoint = [width=8, 3F C0 00 00]
        // Data context tag 7 primitivo (0x87), len 5
        let bytes = [0x87, 0x05, 0x08, 0x3F, 0xC0, 0x00, 0x00];
        let d = decode_data(&bytes).unwrap();
        assert_eq!(d, MmsData::Float(1.5));
    }

    #[test]
    fn structure_round_trip() {
        let s = MmsData::Structure(vec![
            MmsData::Int(1),
            MmsData::Bool(false),
            MmsData::Structure(vec![MmsData::Visible("x".into())]),
        ]);
        round(s);
    }

    #[test]
    fn decode_visible_vector() {
        // visible-string [10] "AB" → 0x8A 0x02 0x41 0x42
        let d = decode_data(&[0x8A, 0x02, 0x41, 0x42]).unwrap();
        assert_eq!(d.as_str(), Some("AB"));
    }
}
