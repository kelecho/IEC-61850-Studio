//! PDUs de inicio de asociación MMS: `Initiate-Request` / `Initiate-Response`.

use crate::ber::prim::BitString;
use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::pdu::mmspdu;

/// Parámetros propuestos por el cliente al iniciar la asociación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateRequest {
    pub local_detail: i32,
    pub max_serv_out_calling: u16,
    pub max_serv_out_called: u16,
    pub nesting_level: u8,
}

impl Default for InitiateRequest {
    fn default() -> Self {
        Self {
            local_detail: 65000,
            max_serv_out_calling: 10,
            max_serv_out_called: 10,
            nesting_level: 10,
        }
    }
}

impl InitiateRequest {
    /// Codifica el `Initiate-RequestPDU` completo (`MMSpdu` `[8]`).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(mmspdu::INITIATE_REQUEST, |w| {
            w.integer(Tag::context(0, false), self.local_detail as i64);
            w.integer(Tag::context(1, false), self.max_serv_out_calling as i64);
            w.integer(Tag::context(2, false), self.max_serv_out_called as i64);
            w.integer(Tag::context(3, false), self.nesting_level as i64);
            // mmsInitRequestDetail [4] IMPLICIT InitRequestDetail
            w.tlv(Tag::context(4, true), |w| {
                w.integer(Tag::context(0, false), PROPOSED_VERSION);
                w.bit_string(Tag::context(1, false), &proposed_parameter_cbb());
                w.bit_string(Tag::context(2, false), &services_supported_calling());
            });
        });
        w.into_bytes()
    }

    /// Decodifica un `Initiate-RequestPDU` (`MMSpdu` `[8]`) entrante (lado servidor).
    pub fn decode(pdu: &[u8]) -> Result<InitiateRequest, MmsError> {
        let mut top = BerReader::new(pdu);
        let outer = top.read_tlv()?;
        if outer.tag != mmspdu::INITIATE_REQUEST {
            return Err(MmsError::UnexpectedPdu);
        }
        let mut r = outer.reader();
        let local_detail = read_opt_int(&mut r, Tag::context(0, false))?.unwrap_or(0) as i32;
        let max_serv_out_calling = read_int(&mut r, Tag::context(1, false))? as u16;
        let max_serv_out_called = read_int(&mut r, Tag::context(2, false))? as u16;
        let nesting_level = read_opt_int(&mut r, Tag::context(3, false))?.unwrap_or(0) as u8;
        // mmsInitRequestDetail [4] se ignora en el hito.
        Ok(InitiateRequest {
            local_detail,
            max_serv_out_calling,
            max_serv_out_called,
            nesting_level,
        })
    }
}

const PROPOSED_VERSION: i64 = 1;

/// `proposedParameterCBB`: capacidades de parámetros que ofrece el cliente.
/// Bits: str1(0), str2(1), vnam(2), valt(3), vadr(4), vlis(7).
fn proposed_parameter_cbb() -> BitString {
    let mut bits = [false; 11];
    for i in [0, 1, 2, 3, 4, 7] {
        bits[i] = true;
    }
    BitString::from_bits(&bits)
}

/// `servicesSupportedCalling`: servicios soportados por el cliente. Conjunto
/// mínimo para este hito: getNameList(1), identify(2), read(4).
fn services_supported_calling() -> BitString {
    let mut bits = [false; 85];
    for i in [1, 2, 4] {
        bits[i] = true;
    }
    BitString::from_bits(&bits)
}

/// Parámetros negociados que devuelve el servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateResponse {
    pub local_detail_called: Option<i32>,
    pub max_serv_out_calling: u16,
    pub max_serv_out_called: u16,
    pub nesting_level: Option<u8>,
    pub version: i64,
}

impl InitiateResponse {
    /// Construye una respuesta negociando los parámetros propuestos por el
    /// cliente contra la capacidad del servidor (lado servidor).
    pub fn accept(req: &InitiateRequest) -> InitiateResponse {
        InitiateResponse {
            local_detail_called: Some(65000),
            max_serv_out_calling: req.max_serv_out_calling.min(10),
            max_serv_out_called: req.max_serv_out_called.min(10),
            nesting_level: Some(req.nesting_level.min(10)),
            version: PROPOSED_VERSION,
        }
    }

    /// Codifica un `Initiate-ResponsePDU` (`MMSpdu` `[9]`) (lado servidor).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(mmspdu::INITIATE_RESPONSE, |w| {
            if let Some(ld) = self.local_detail_called {
                w.integer(Tag::context(0, false), ld as i64);
            }
            w.integer(Tag::context(1, false), self.max_serv_out_calling as i64);
            w.integer(Tag::context(2, false), self.max_serv_out_called as i64);
            if let Some(n) = self.nesting_level {
                w.integer(Tag::context(3, false), n as i64);
            }
            w.tlv(Tag::context(4, true), |w| {
                w.integer(Tag::context(0, false), self.version);
                w.bit_string(Tag::context(1, false), &proposed_parameter_cbb());
                w.bit_string(Tag::context(2, false), &services_supported_calling());
            });
        });
        w.into_bytes()
    }

    /// Decodifica un `Initiate-ResponsePDU` (`MMSpdu` `[9]`). Un
    /// `Initiate-ErrorPDU` `[10]` se traduce a `AssociateRejected`.
    pub fn decode(pdu: &[u8]) -> Result<Self, MmsError> {
        let mut top = BerReader::new(pdu);
        let outer = top.read_tlv()?;
        if outer.tag == mmspdu::INITIATE_ERROR {
            return Err(MmsError::AssociateRejected(format!(
                "initiate-error: {:02X?}",
                outer.content
            )));
        }
        if outer.tag != mmspdu::INITIATE_RESPONSE {
            return Err(MmsError::UnexpectedPdu);
        }

        let mut r = outer.reader();
        let local_detail_called = read_opt_int(&mut r, Tag::context(0, false))?.map(|v| v as i32);
        let max_serv_out_calling = read_int(&mut r, Tag::context(1, false))? as u16;
        let max_serv_out_called = read_int(&mut r, Tag::context(2, false))? as u16;
        let nesting_level = read_opt_int(&mut r, Tag::context(3, false))?.map(|v| v as u8);

        // mmsInitResponseDetail [4] { negotiatedVersionNumber [0], ... }
        let detail = r.expect(Tag::context(4, true))?;
        let mut dr = BerReader::new(detail);
        let version = read_int(&mut dr, Tag::context(0, false))?;

        Ok(InitiateResponse {
            local_detail_called,
            max_serv_out_calling,
            max_serv_out_called,
            nesting_level,
            version,
        })
    }
}

fn read_int(r: &mut BerReader<'_>, tag: Tag) -> Result<i64, MmsError> {
    let c = r.expect(tag)?;
    Ok(crate::ber::prim::decode_integer(c)?)
}

fn read_opt_int(r: &mut BerReader<'_>, tag: Tag) -> Result<Option<i64>, MmsError> {
    match r.read_if(tag)? {
        Some(c) => Ok(Some(crate::ber::prim::decode_integer(c)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_fields() {
        let req = InitiateRequest::default();
        let bytes = req.encode();
        // empieza por initiate-RequestPDU [8] constructed
        assert_eq!(bytes[0], 0xA8);

        // Comprobamos sub-campos navegando el BER (golden self-derivado).
        let mut top = BerReader::new(&bytes);
        let outer = top.read_tlv().unwrap();
        assert_eq!(outer.tag, mmspdu::INITIATE_REQUEST);
        let mut r = outer.reader();
        assert_eq!(read_int(&mut r, Tag::context(0, false)).unwrap(), 65000);
        assert_eq!(read_int(&mut r, Tag::context(1, false)).unwrap(), 10);
        assert_eq!(read_int(&mut r, Tag::context(2, false)).unwrap(), 10);
        assert_eq!(read_int(&mut r, Tag::context(3, false)).unwrap(), 10);
        let detail = r.expect(Tag::context(4, true)).unwrap();
        let mut dr = BerReader::new(detail);
        assert_eq!(read_int(&mut dr, Tag::context(0, false)).unwrap(), 1);
    }

    #[test]
    fn response_decoding() {
        // initiate-Response [9] {
        //   [0] localDetailCalled 65000 ; [1] 5 ; [2] 5 ; [3] 10 ;
        //   [4] { [0] version 1 , [1] cbb , [2] servicesSupported }
        // }
        let req = InitiateRequest::default();
        // construimos una respuesta a mano reutilizando el writer
        let mut w = BerWriter::new();
        w.tlv(mmspdu::INITIATE_RESPONSE, |w| {
            w.integer(Tag::context(0, false), 65000);
            w.integer(Tag::context(1, false), 5);
            w.integer(Tag::context(2, false), 5);
            w.integer(Tag::context(3, false), 10);
            w.tlv(Tag::context(4, true), |w| {
                w.integer(Tag::context(0, false), 1);
                w.bit_string(Tag::context(1, false), &proposed_parameter_cbb());
                w.bit_string(Tag::context(2, false), &services_supported_calling());
            });
        });
        let _ = req; // (solo para mostrar simetría)

        let resp = InitiateResponse::decode(&w.into_bytes()).unwrap();
        assert_eq!(resp.local_detail_called, Some(65000));
        assert_eq!(resp.max_serv_out_calling, 5);
        assert_eq!(resp.max_serv_out_called, 5);
        assert_eq!(resp.nesting_level, Some(10));
        assert_eq!(resp.version, 1);
    }

    #[test]
    fn initiate_error_is_rejected() {
        let mut w = BerWriter::new();
        w.tlv(mmspdu::INITIATE_ERROR, |w| {
            w.integer(Tag::context(0, false), 1)
        });
        assert!(matches!(
            InitiateResponse::decode(&w.into_bytes()),
            Err(MmsError::AssociateRejected(_))
        ));
    }
}
