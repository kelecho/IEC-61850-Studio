//! Servicio MMS `Identify`: devuelve fabricante, modelo y revisión del servidor.

use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::pdu::{self, service};

/// Respuesta al servicio `Identify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyResponse {
    pub vendor: String,
    pub model: String,
    pub revision: String,
}

/// Escribe el servicio `identify` (sin parámetros) en una Confirmed-Request.
pub fn write_request(w: &mut BerWriter) {
    w.null(service::IDENTIFY_REQUEST);
}

/// Codifica la respuesta `Identify` (lado servidor).
pub fn encode_response(w: &mut BerWriter, resp: &IdentifyResponse) {
    w.tlv(service::IDENTIFY_RESPONSE, |w| {
        w.visible_string(Tag::context(0, false), &resp.vendor);
        w.visible_string(Tag::context(1, false), &resp.model);
        w.visible_string(Tag::context(2, false), &resp.revision);
    });
}

/// Decodifica la respuesta `Identify` desde el TLV de servicio.
pub fn decode_response(
    service_tlv: &crate::ber::reader::Tlv<'_>,
) -> Result<IdentifyResponse, MmsError> {
    let content = pdu::expect_service(service_tlv, service::IDENTIFY_RESPONSE)?;
    let mut r = BerReader::new(content);

    let vendor = read_visible(&mut r, Tag::context(0, false))?;
    let model = read_visible(&mut r, Tag::context(1, false))?;
    let revision = read_visible(&mut r, Tag::context(2, false))?;

    Ok(IdentifyResponse {
        vendor,
        model,
        revision,
    })
}

fn read_visible(r: &mut BerReader<'_>, tag: Tag) -> Result<String, MmsError> {
    let content = r.expect(tag)?;
    Ok(crate::ber::prim::decode_visible_string(content)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::reader::BerReader;

    #[test]
    fn request_encoding() {
        let mut w = BerWriter::new();
        write_request(&mut w);
        // identify [2] primitivo, longitud 0
        assert_eq!(w.into_bytes(), vec![0x82, 0x00]);
    }

    #[test]
    fn response_decoding() {
        // identify [2] { [0]"ACME" [1]"IED-X" [2]"1.0" }
        let bytes = [
            0xA2, 0x12, 0x80, 0x04, b'A', b'C', b'M', b'E', 0x81, 0x05, b'I', b'E', b'D', b'-',
            b'X', 0x82, 0x03, b'1', b'.', b'0',
        ];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let resp = decode_response(&tlv).unwrap();
        assert_eq!(
            resp,
            IdentifyResponse {
                vendor: "ACME".into(),
                model: "IED-X".into(),
                revision: "1.0".into()
            }
        );
    }
}
