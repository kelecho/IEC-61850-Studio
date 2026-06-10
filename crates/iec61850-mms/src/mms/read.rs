//! Servicio MMS `Read`: lee variables. Para el hito, lectura de una variable
//! *domain-specific* (`domainId` / `itemId`).

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::{DataAccessError, MmsError};
use crate::mms::data::MmsData;
use crate::mms::pdu::{self, service};

/// Resultado de acceso a una variable.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult {
    Success(MmsData),
    Failure(DataAccessError),
}

impl AccessResult {
    /// Devuelve el dato o convierte el fallo en error.
    pub fn into_data(self) -> Result<MmsData, MmsError> {
        match self {
            AccessResult::Success(d) => Ok(d),
            AccessResult::Failure(e) => Err(MmsError::DataAccess(e)),
        }
    }
}

/// Escribe el servicio `read` de una variable domain-specific.
pub fn write_request(w: &mut BerWriter, domain_id: &str, item_id: &str) {
    w.tlv(service::READ, |w| {
        // (specificationWithResult [0] omitido → FALSE por defecto)
        // variableAccessSpecification: listOfVariable [0] SEQUENCE OF
        w.tlv(Tag::context(0, true), |w| {
            w.sequence(|w| {
                // variableSpecification: name [0] EXPLICIT ObjectName
                w.tlv(Tag::context(0, true), |w| {
                    // ObjectName: domain-specific [1] IMPLICIT SEQUENCE { domainId, itemId }
                    w.tlv(Tag::context(1, true), |w| {
                        w.visible_string(universal::VISIBLE_STRING, domain_id);
                        w.visible_string(universal::VISIBLE_STRING, item_id);
                    });
                });
            });
        });
    });
}

/// Decodifica una petición `read` (lado servidor) → lista de (domainId, itemId).
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<Vec<(String, String)>, MmsError> {
    let content = pdu::expect_service(service_tlv, service::READ)?;
    let mut r = BerReader::new(content);
    // specificationWithResult [0] BOOLEAN (primitivo) OPTIONAL → ignorar si está
    let _ = r.read_if(Tag::context(0, false))?;
    // variableAccessSpecification: listOfVariable [0] (constructed)
    let lov = r.expect(Tag::context(0, true))?;
    pdu::parse_list_of_variable(lov)
}

/// Codifica una respuesta `read` (lado servidor).
pub fn encode_response(w: &mut BerWriter, results: &[AccessResult]) {
    w.tlv(service::READ, |w| {
        w.tlv(Tag::context(1, true), |w| {
            for r in results {
                match r {
                    AccessResult::Success(data) => data.encode(w),
                    AccessResult::Failure(e) => w.integer(Tag::context(0, false), e.to_code()),
                }
            }
        });
    });
}

/// Decodifica `listOfAccessResult` de la respuesta `Read`.
pub fn decode_response(service_tlv: &Tlv<'_>) -> Result<Vec<AccessResult>, MmsError> {
    let content = pdu::expect_service(service_tlv, service::READ)?;
    let mut r = BerReader::new(content);

    // variableAccessSpecification [0] OPTIONAL → ignorar si está
    let _ = r.read_if(Tag::context(0, true))?;

    // listOfAccessResult [1] IMPLICIT SEQUENCE OF AccessResult
    let list = r.expect(Tag::context(1, true))?;
    let mut lr = BerReader::new(list);
    let mut results = Vec::new();
    while !lr.is_empty() {
        let tlv = lr.read_tlv()?;
        if tlv.tag == Tag::context(0, false) {
            // failure [0] IMPLICIT DataAccessError (INTEGER)
            let code = crate::ber::prim::decode_integer(tlv.content)?;
            results.push(AccessResult::Failure(DataAccessError::from_code(code)));
        } else {
            // success: Data (CHOICE con sus propios tags)
            results.push(AccessResult::Success(MmsData::decode(&tlv)?));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_single_variable() {
        let mut w = BerWriter::new();
        write_request(&mut w, "IED1LD0", "LLN0$ST$Mod$stVal");
        let bytes = w.into_bytes();
        // estructura: A4 { A0 { 30 { A0 { A1 { 1A "IED1LD0", 1A "LLN0$ST$Mod$stVal" } } } } }
        assert_eq!(bytes[0], 0xA4);
        // contiene domainId e itemId como VisibleString
        assert!(bytes.windows(7).any(|c| c == b"IED1LD0"));
        assert!(bytes.windows(17).any(|c| c == b"LLN0$ST$Mod$stVal"));
        // verifica el anidamiento de tags al principio del cuerpo
        let mut r = BerReader::new(&bytes);
        let read = r.read_tlv().unwrap();
        assert_eq!(read.tag, service::READ);
        let mut rr = read.reader();
        let lov = rr.read_tlv().unwrap();
        assert_eq!(lov.tag, Tag::context(0, true));
    }

    #[test]
    fn response_success_integer() {
        // read [4] { listOfAccessResult [1] { success Data integer 5 } }
        // Data integer [5] = 85 01 05
        let bytes = [0xA4, 0x05, 0xA1, 0x03, 0x85, 0x01, 0x05];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let results = decode_response(&tlv).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], AccessResult::Success(MmsData::Int(5)));
    }

    #[test]
    fn response_failure() {
        // listOfAccessResult [1] { failure [0] INTEGER 10 (objectValueInvalid) }
        let bytes = [0xA4, 0x05, 0xA1, 0x03, 0x80, 0x01, 0x0A];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let results = decode_response(&tlv).unwrap();
        assert_eq!(
            results[0],
            AccessResult::Failure(DataAccessError::ObjectValueInvalid)
        );
    }
}
