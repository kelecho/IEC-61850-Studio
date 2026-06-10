//! Identificadores (tags) BER: clase, constructed/primitivo y número.

use std::fmt;

use crate::error::BerError;

/// Clase del tag BER (bits 8-7 del primer octeto del identificador).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    Context,
    Private,
}

impl TagClass {
    const fn bits(self) -> u8 {
        match self {
            TagClass::Universal => 0b00,
            TagClass::Application => 0b01,
            TagClass::Context => 0b10,
            TagClass::Private => 0b11,
        }
    }

    fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0b00 => TagClass::Universal,
            0b01 => TagClass::Application,
            0b10 => TagClass::Context,
            _ => TagClass::Private,
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            TagClass::Universal => "U",
            TagClass::Application => "A",
            TagClass::Context => "C",
            TagClass::Private => "P",
        }
    }
}

/// Tag BER: clase + indicador constructed + número.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const fn new(class: TagClass, constructed: bool, number: u32) -> Self {
        Self {
            class,
            constructed,
            number,
        }
    }

    pub const fn universal(number: u32, constructed: bool) -> Self {
        Self::new(TagClass::Universal, constructed, number)
    }

    pub const fn application(number: u32, constructed: bool) -> Self {
        Self::new(TagClass::Application, constructed, number)
    }

    pub const fn context(number: u32, constructed: bool) -> Self {
        Self::new(TagClass::Context, constructed, number)
    }

    /// Codifica el identificador en `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        let mut first = (self.class.bits() << 6) | if self.constructed { 0x20 } else { 0 };
        if self.number < 0x1F {
            first |= self.number as u8;
            out.push(first);
        } else {
            first |= 0x1F;
            out.push(first);
            // forma multi-byte, base-128 big-endian, bit 8 = continuación
            let mut stack = [0u8; 5];
            let mut n = 0;
            let mut v = self.number;
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
    }

    /// Decodifica un identificador desde el inicio de `data`.
    /// Devuelve el tag y el número de octetos consumidos.
    pub fn decode(data: &[u8]) -> Result<(Tag, usize), BerError> {
        let first = *data.first().ok_or(BerError::UnexpectedEof)?;
        let class = TagClass::from_bits(first >> 6);
        let constructed = first & 0x20 != 0;
        let low = first & 0x1F;
        if low != 0x1F {
            return Ok((Tag::new(class, constructed, low as u32), 1));
        }
        // forma multi-byte
        let mut number: u32 = 0;
        let mut i = 1;
        loop {
            let b = *data.get(i).ok_or(BerError::UnexpectedEof)?;
            number = number.checked_shl(7).ok_or(BerError::LengthOverflow)? | (b & 0x7F) as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        Ok((Tag::new(class, constructed, number), i))
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}{}{}]",
            self.class.prefix(),
            if self.constructed { "c" } else { "p" },
            self.number
        )
    }
}

/// Tags universales usados por el codec.
pub mod universal {
    use super::Tag;

    pub const BOOLEAN: Tag = Tag::universal(0x01, false);
    pub const INTEGER: Tag = Tag::universal(0x02, false);
    pub const BIT_STRING: Tag = Tag::universal(0x03, false);
    pub const OCTET_STRING: Tag = Tag::universal(0x04, false);
    pub const NULL: Tag = Tag::universal(0x05, false);
    pub const OID: Tag = Tag::universal(0x06, false);
    pub const VISIBLE_STRING: Tag = Tag::universal(0x1A, false);
    pub const SEQUENCE: Tag = Tag::universal(0x10, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(tag: Tag, expected: &[u8]) {
        let mut out = Vec::new();
        tag.encode(&mut out);
        assert_eq!(out, expected, "encode {tag}");
        let (decoded, n) = Tag::decode(&out).unwrap();
        assert_eq!(decoded, tag);
        assert_eq!(n, out.len());
    }

    #[test]
    fn single_byte_tags() {
        round(universal::INTEGER, &[0x02]);
        round(universal::SEQUENCE, &[0x30]);
        round(Tag::context(0, true), &[0xA0]);
        round(Tag::context(2, false), &[0x82]);
        round(Tag::application(8, true), &[0x68]);
        round(Tag::context(30, false), &[0x9E]);
    }

    #[test]
    fn multi_byte_tag() {
        // contexto número 31 → 0x9F 0x1F
        round(Tag::context(31, false), &[0x9F, 0x1F]);
        // aplicación 82 → 0x5F 0x52 (constructed=false)
        round(Tag::application(82, false), &[0x5F, 0x52]);
    }
}
