//! Codificación/decodificación de los tipos primitivos BER que usa MMS.
//!
//! Las funciones de codificación devuelven el **contenido** (sin tag ni
//! longitud); el [`super::writer::BerWriter`] añade el envoltorio TLV.

use crate::error::BerError;

/// Cadena de bits BER: número de bits no usados en el último octeto + octetos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    pub unused_bits: u8,
    pub bytes: Vec<u8>,
}

impl BitString {
    /// Construye una cadena de bits a partir de bits individuales (MSB-first).
    pub fn from_bits(bits: &[bool]) -> Self {
        let nbytes = bits.len().div_ceil(8);
        let mut bytes = vec![0u8; nbytes];
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                bytes[i / 8] |= 0x80 >> (i % 8);
            }
        }
        let unused_bits = (nbytes * 8 - bits.len()) as u8;
        BitString { unused_bits, bytes }
    }

    /// Devuelve el valor del bit `i` (MSB-first).
    pub fn bit(&self, i: usize) -> bool {
        self.bytes
            .get(i / 8)
            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
    }

    /// Número total de bits significativos.
    pub fn len_bits(&self) -> usize {
        self.bytes.len() * 8 - self.unused_bits as usize
    }
}

// --- INTEGER (con signo) ---

pub fn encode_integer(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let first = bytes[0];
        let second = bytes[1];
        // octeto redundante si es 0x00 con MSB siguiente a 0, o 0xFF con MSB a 1
        if (first == 0x00 && second & 0x80 == 0) || (first == 0xFF && second & 0x80 != 0) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    bytes
}

pub fn decode_integer(content: &[u8]) -> Result<i64, BerError> {
    if content.is_empty() || content.len() > 8 {
        return Err(BerError::BadInteger);
    }
    // extensión de signo a partir del primer octeto
    let mut acc = (content[0] as i8) as i64;
    for &b in &content[1..] {
        acc = (acc << 8) | b as i64;
    }
    Ok(acc)
}

// --- INTEGER no negativo (Unsigned de MMS) ---

pub fn encode_unsigned(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    // si el MSB está a 1, anteponer 0x00 para que no se interprete negativo
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

pub fn decode_unsigned(content: &[u8]) -> Result<u64, BerError> {
    if content.is_empty() {
        return Err(BerError::BadInteger);
    }
    // ignora un eventual 0x00 de signo inicial
    let trimmed = if content[0] == 0 && content.len() > 1 {
        &content[1..]
    } else {
        content
    };
    if trimmed.len() > 8 {
        return Err(BerError::LengthOverflow);
    }
    let mut acc: u64 = 0;
    for &b in trimmed {
        acc = (acc << 8) | b as u64;
    }
    Ok(acc)
}

// --- BOOLEAN ---

pub fn encode_bool(v: bool) -> [u8; 1] {
    [if v { 0xFF } else { 0x00 }]
}

pub fn decode_bool(content: &[u8]) -> Result<bool, BerError> {
    match content {
        [b] => Ok(*b != 0),
        _ => Err(BerError::BadBool),
    }
}

// --- VisibleString ---

pub fn decode_visible_string(content: &[u8]) -> Result<&str, BerError> {
    std::str::from_utf8(content).map_err(|_| BerError::BadString)
}

// --- OBJECT IDENTIFIER ---

fn push_base128(out: &mut Vec<u8>, mut v: u32) {
    let mut stack = [0u8; 5];
    let mut n = 0;
    loop {
        stack[n] = (v & 0x7F) as u8;
        v >>= 7;
        n += 1;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        let mut byte = stack[i];
        if i != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

pub fn encode_oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "un OID necesita al menos dos arcos");
    let mut out = Vec::new();
    push_base128(&mut out, arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push_base128(&mut out, arc);
    }
    out
}

pub fn decode_oid(content: &[u8]) -> Result<Vec<u32>, BerError> {
    if content.is_empty() {
        return Err(BerError::BadOid);
    }
    let mut subids = Vec::new();
    let mut acc: u32 = 0;
    let mut started = false;
    for &b in content {
        acc = acc.checked_shl(7).ok_or(BerError::BadOid)? | (b & 0x7F) as u32;
        started = true;
        if b & 0x80 == 0 {
            subids.push(acc);
            acc = 0;
            started = false;
        }
    }
    if started {
        return Err(BerError::BadOid); // terminó con bit de continuación
    }

    let first = subids[0];
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut arcs = Vec::with_capacity(subids.len() + 1);
    arcs.push(a);
    arcs.push(b);
    arcs.extend_from_slice(&subids[1..]);
    Ok(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_canonical_x690() {
        assert_eq!(encode_integer(0), vec![0x00]);
        assert_eq!(encode_integer(127), vec![0x7F]);
        assert_eq!(encode_integer(128), vec![0x00, 0x80]);
        assert_eq!(encode_integer(-128), vec![0x80]);
        assert_eq!(encode_integer(300), vec![0x01, 0x2C]);
        assert_eq!(encode_integer(-1), vec![0xFF]);
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            255,
            256,
            300,
            -300,
            i32::MAX as i64,
            i32::MIN as i64,
        ] {
            assert_eq!(decode_integer(&encode_integer(v)).unwrap(), v, "int {v}");
        }
    }

    #[test]
    fn unsigned_roundtrip() {
        assert_eq!(encode_unsigned(0), vec![0x00]);
        assert_eq!(encode_unsigned(127), vec![0x7F]);
        assert_eq!(encode_unsigned(128), vec![0x00, 0x80]);
        assert_eq!(encode_unsigned(255), vec![0x00, 0xFF]);
        assert_eq!(encode_unsigned(256), vec![0x01, 0x00]);
        for v in [0u64, 1, 127, 128, 255, 256, 65000, u32::MAX as u64] {
            assert_eq!(decode_unsigned(&encode_unsigned(v)).unwrap(), v, "uint {v}");
        }
    }

    #[test]
    fn bool_codec() {
        assert_eq!(encode_bool(true), [0xFF]);
        assert_eq!(encode_bool(false), [0x00]);
        assert!(decode_bool(&[0xFF]).unwrap());
        assert!(!decode_bool(&[0x00]).unwrap());
        assert!(decode_bool(&[0x01]).unwrap());
        assert!(decode_bool(&[]).is_err());
    }

    #[test]
    fn oid_codec() {
        // BER transfer syntax 2.1.1 → 51 01
        assert_eq!(encode_oid(&[2, 1, 1]), vec![0x51, 0x01]);
        assert_eq!(decode_oid(&[0x51, 0x01]).unwrap(), vec![2, 1, 1]);
        // MMS abstract syntax 1.0.9506.2.1 ; 9506 = base128 CA 22
        let mms = encode_oid(&[1, 0, 9506, 2, 1]);
        assert_eq!(mms, vec![0x28, 0xCA, 0x22, 0x02, 0x01]);
        assert_eq!(decode_oid(&mms).unwrap(), vec![1, 0, 9506, 2, 1]);
    }

    #[test]
    fn bit_string_bits() {
        let bs = BitString::from_bits(&[true, false, true]);
        assert_eq!(bs.unused_bits, 5);
        assert_eq!(bs.bytes, vec![0b1010_0000]);
        assert!(bs.bit(0) && !bs.bit(1) && bs.bit(2));
        assert_eq!(bs.len_bits(), 3);
    }
}
