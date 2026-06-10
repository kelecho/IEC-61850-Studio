//! Escritor BER con back-patching de longitud.
//!
//! El patrón central es [`BerWriter::tlv`]: escribe el tag, ejecuta un cierre
//! que produce el contenido (posiblemente anidando más `tlv`), y luego inserta
//! la longitud real. Como el cierre recibe `&mut BerWriter` de forma anidada y
//! secuencial, no hay dos préstamos vivos a la vez.

use super::length::encode_len;
use super::prim::{self, BitString};
use super::tag::{Tag, universal};

#[derive(Debug, Default)]
pub struct BerWriter {
    buf: Vec<u8>,
}

impl BerWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Escribe un TLV constructed/primitivo cuyo contenido lo produce `body`.
    pub fn tlv(&mut self, tag: Tag, body: impl FnOnce(&mut BerWriter)) {
        tag.encode(&mut self.buf);
        let content_start = self.buf.len();
        body(self);
        let content_len = self.buf.len() - content_start;

        let mut len_bytes = Vec::with_capacity(2);
        encode_len(&mut len_bytes, content_len);
        // inserta los octetos de longitud justo antes del contenido
        self.buf.splice(content_start..content_start, len_bytes);
    }

    /// Escribe un TLV primitivo con contenido ya calculado.
    pub fn primitive(&mut self, tag: Tag, content: &[u8]) {
        tag.encode(&mut self.buf);
        encode_len(&mut self.buf, content.len());
        self.buf.extend_from_slice(content);
    }

    /// Incrusta bytes ya serializados (p. ej. un sub-PDU completo).
    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    // --- helpers de primitivos (con tag explícito para permitir tags de contexto) ---

    pub fn boolean(&mut self, tag: Tag, v: bool) {
        self.primitive(tag, &prim::encode_bool(v));
    }

    pub fn integer(&mut self, tag: Tag, v: i64) {
        self.primitive(tag, &prim::encode_integer(v));
    }

    pub fn unsigned(&mut self, tag: Tag, v: u64) {
        self.primitive(tag, &prim::encode_unsigned(v));
    }

    pub fn octet_string(&mut self, tag: Tag, bytes: &[u8]) {
        self.primitive(tag, bytes);
    }

    pub fn visible_string(&mut self, tag: Tag, s: &str) {
        self.primitive(tag, s.as_bytes());
    }

    pub fn null(&mut self, tag: Tag) {
        self.primitive(tag, &[]);
    }

    pub fn object_identifier(&mut self, tag: Tag, arcs: &[u32]) {
        self.primitive(tag, &prim::encode_oid(arcs));
    }

    pub fn bit_string(&mut self, tag: Tag, bits: &BitString) {
        let mut content = Vec::with_capacity(bits.bytes.len() + 1);
        content.push(bits.unused_bits);
        content.extend_from_slice(&bits.bytes);
        self.primitive(tag, &content);
    }

    // --- atajos con tag universal ---

    pub fn integer_u(&mut self, v: i64) {
        self.integer(universal::INTEGER, v);
    }

    pub fn sequence(&mut self, body: impl FnOnce(&mut BerWriter)) {
        self.tlv(universal::SEQUENCE, body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::universal;

    #[test]
    fn nested_sequence() {
        let mut w = BerWriter::new();
        w.sequence(|w| {
            w.integer_u(1);
            w.boolean(universal::BOOLEAN, true);
        });
        // SEQUENCE { INTEGER 1, BOOLEAN true }
        assert_eq!(
            w.into_bytes(),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF]
        );
    }

    #[test]
    fn long_length_backpatch() {
        // contenido de 200 bytes dentro de un OCTET STRING → prefijo 04 81 C8
        let payload = vec![0xAAu8; 200];
        let mut w = BerWriter::new();
        w.octet_string(universal::OCTET_STRING, &payload);
        let out = w.into_bytes();
        assert_eq!(&out[..3], &[0x04, 0x81, 0xC8]);
        assert_eq!(out.len(), 3 + 200);

        // y el back-patching dentro de un constructed que envuelve los 200 bytes
        let mut w = BerWriter::new();
        w.sequence(|w| w.octet_string(universal::OCTET_STRING, &payload));
        let out = w.into_bytes();
        // SEQUENCE len = 203 (3 de cabecera del octet string + 200) → 30 81 CB ...
        assert_eq!(&out[..2], &[0x30, 0x81]);
        assert_eq!(out[2], 203);
    }
}
