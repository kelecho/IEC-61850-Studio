//! Servicio MMS `Write`: escribe una variable *domain-specific*.

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::{DataAccessError, MmsError};
use crate::mms::data::MmsData;
use crate::mms::pdu::{self, service};

/// Resultado de escribir una variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteResult {
    Success,
    Failure(DataAccessError),
}

impl WriteResult {
    /// Convierte un fallo en error.
    pub fn into_result(self) -> Result<(), MmsError> {
        match self {
            WriteResult::Success => Ok(()),
            WriteResult::Failure(e) => Err(MmsError::DataAccess(e)),
        }
    }
}

/// Escribe el servicio `write` de una variable domain-specific con su valor.
///
/// NOTA de conformidad (verificada contra libiec61850): a diferencia de
/// `ReadRequest`, en `WriteRequest` el `variableAccessSpecification` **no lleva
/// tag envolvente** (`[1]`): el CHOICE `listOfVariable [0]` va directamente, y
/// `listOfData [0]` le sigue (se desambiguan por orden). No "corregir" a `[1]`.
pub fn write_request(w: &mut BerWriter, domain_id: &str, item_id: &str, value: &MmsData) {
    w.tlv(service::WRITE, |w| {
        // variableAccessSpecification → listOfVariable [0] SEQUENCE OF (sin wrapper)
        w.tlv(Tag::context(0, true), |w| {
            w.sequence(|w| {
                // variableSpecification: name [0] EXPLICIT ObjectName
                w.tlv(Tag::context(0, true), |w| {
                    // ObjectName: domain-specific [1] { domainId, itemId }
                    w.tlv(Tag::context(1, true), |w| {
                        w.visible_string(universal::VISIBLE_STRING, domain_id);
                        w.visible_string(universal::VISIBLE_STRING, item_id);
                    });
                });
            });
        });
        // listOfData [0] SEQUENCE OF Data
        w.tlv(Tag::context(0, true), |w| value.encode(w));
    });
}

/// Variables (domainId, itemId) y sus datos asociados de una petición Write.
pub type WriteItems = (Vec<(String, String)>, Vec<MmsData>);

/// Decodifica una petición `write` (lado servidor): variables + datos.
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<WriteItems, MmsError> {
    let content = pdu::expect_service(service_tlv, service::WRITE)?;
    let mut r = BerReader::new(content);
    // variableAccessSpecification: listOfVariable [0]
    let lov = r.expect(Tag::context(0, true))?;
    let names = pdu::parse_list_of_variable(lov)?;
    // listOfData [0] (mismo tag, desambiguado por posición)
    let lod = r.expect(Tag::context(0, true))?;
    let mut dr = BerReader::new(lod);
    let mut data = Vec::new();
    while !dr.is_empty() {
        data.push(MmsData::decode(&dr.read_tlv()?)?);
    }
    Ok((names, data))
}

/// Codifica una respuesta `write` (lado servidor).
pub fn encode_response(w: &mut BerWriter, results: &[WriteResult]) {
    w.tlv(service::WRITE, |w| {
        for r in results {
            match r {
                WriteResult::Success => w.null(Tag::context(1, false)),
                WriteResult::Failure(e) => w.integer(Tag::context(0, false), e.to_code()),
            }
        }
    });
}

/// Decodifica la respuesta `Write` (un resultado por variable escrita).
pub fn decode_response(service_tlv: &Tlv<'_>) -> Result<Vec<WriteResult>, MmsError> {
    let content = pdu::expect_service(service_tlv, service::WRITE)?;
    let mut r = BerReader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        match tlv.tag {
            // failure [0] IMPLICIT DataAccessError (INTEGER)
            t if t == Tag::context(0, false) => {
                let code = crate::ber::prim::decode_integer(tlv.content)?;
                out.push(WriteResult::Failure(DataAccessError::from_code(code)));
            }
            // success [1] IMPLICIT NULL
            t if t == Tag::context(1, false) => out.push(WriteResult::Success),
            _ => return Err(MmsError::UnexpectedPdu),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_structure() {
        let mut w = BerWriter::new();
        write_request(
            &mut w,
            "IED1LD0",
            "LLN0$CF$Mod$ctlVal",
            &MmsData::Bool(true),
        );
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0xA5); // write [5]
        assert!(bytes.windows(7).any(|c| c == b"IED1LD0"));
        // tras el access-spec [0] y el valor, ambos campos comparten tag [0]
        let mut r = BerReader::new(&bytes);
        let write = r.read_tlv().unwrap();
        assert_eq!(write.tag, service::WRITE);
        let mut wr = write.reader();
        assert_eq!(wr.read_tlv().unwrap().tag, Tag::context(0, true)); // access-spec
        assert_eq!(wr.read_tlv().unwrap().tag, Tag::context(0, true)); // listOfData
    }

    #[test]
    fn response_success() {
        // write [5] { success [1] NULL }
        let bytes = [0xA5, 0x02, 0x81, 0x00];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(decode_response(&tlv).unwrap(), vec![WriteResult::Success]);
    }

    #[test]
    fn response_failure() {
        // write [5] { failure [0] INTEGER 3 (objectAccessDenied) }
        let bytes = [0xA5, 0x03, 0x80, 0x01, 0x03];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(
            decode_response(&tlv).unwrap(),
            vec![WriteResult::Failure(DataAccessError::ObjectAccessDenied)]
        );
    }
}
