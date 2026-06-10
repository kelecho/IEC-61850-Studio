//! Lector BER zero-copy: tokeniza TLVs sobre un `&[u8]` sin copiar.

use super::length::decode_len;
use super::tag::Tag;
use crate::error::BerError;

/// Un TLV decodificado: su tag y una vista a su contenido.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Crea un lector sobre el contenido (para descender en un constructed).
    pub fn reader(&self) -> BerReader<'a> {
        BerReader::new(self.content)
    }
}

/// Cursor de lectura sobre una secuencia de TLVs en el mismo nivel.
#[derive(Debug, Clone)]
pub struct BerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Mira el tag del siguiente TLV sin consumirlo.
    pub fn peek_tag(&self) -> Result<Tag, BerError> {
        let (tag, _) = Tag::decode(&self.data[self.pos..])?;
        Ok(tag)
    }

    /// Lee el siguiente TLV del nivel actual.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, BerError> {
        let rest = &self.data[self.pos..];
        let (tag, tn) = Tag::decode(rest)?;
        let (len, ln) = decode_len(&rest[tn..])?;
        let start = self.pos + tn + ln;
        let end = start.checked_add(len).ok_or(BerError::LengthOverflow)?;
        if end > self.data.len() {
            return Err(BerError::UnexpectedEof);
        }
        let content = &self.data[start..end];
        self.pos = end;
        Ok(Tlv { tag, content })
    }

    /// Lee el siguiente TLV exigiendo un tag concreto; devuelve su contenido.
    pub fn expect(&mut self, tag: Tag) -> Result<&'a [u8], BerError> {
        let tlv = self.read_tlv()?;
        if tlv.tag != tag {
            return Err(BerError::UnexpectedTag {
                expected: tag.to_string(),
                found: tlv.tag.to_string(),
            });
        }
        Ok(tlv.content)
    }

    /// Lee el siguiente TLV si su tag coincide; si no, no consume nada.
    pub fn read_if(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, BerError> {
        if self.is_empty() {
            return Ok(None);
        }
        if self.peek_tag()? == tag {
            Ok(Some(self.expect(tag)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::universal;
    use crate::ber::writer::BerWriter;

    #[test]
    fn read_nested() {
        let mut w = BerWriter::new();
        w.sequence(|w| {
            w.integer_u(300);
            w.visible_string(universal::VISIBLE_STRING, "hi");
        });
        let bytes = w.into_bytes();

        let mut top = BerReader::new(&bytes);
        let seq = top.read_tlv().unwrap();
        assert_eq!(seq.tag, universal::SEQUENCE);
        assert!(top.is_empty());

        let mut inner = seq.reader();
        let int = inner.expect(universal::INTEGER).unwrap();
        assert_eq!(crate::ber::prim::decode_integer(int).unwrap(), 300);
        let s = inner.expect(universal::VISIBLE_STRING).unwrap();
        assert_eq!(crate::ber::prim::decode_visible_string(s).unwrap(), "hi");
        assert!(inner.is_empty());
    }

    #[test]
    fn unexpected_tag_errors() {
        let bytes = [0x02, 0x01, 0x05]; // INTEGER 5
        let mut r = BerReader::new(&bytes);
        assert!(r.expect(universal::BOOLEAN).is_err());
    }

    #[test]
    fn truncated_errors() {
        let bytes = [0x04, 0x05, 0x01, 0x02]; // dice 5 bytes, hay 2
        let mut r = BerReader::new(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), BerError::UnexpectedEof);
    }
}
