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
///
/// Estructura conforme a ISO 9506 (verificada contra libiec61850):
/// `ReadRequest { specificationWithResult [0] OPT, variableAccessSpecification [1] }`,
/// donde el CHOICE es `listOfVariable [0] SEQUENCE OF ListOfVariableSeq`.
pub fn write_request(w: &mut BerWriter, domain_id: &str, item_id: &str) {
    w.tlv(service::READ, |w| {
        // (specificationWithResult [0] omitido → FALSE por defecto)
        // variableAccessSpecification [1]
        w.tlv(Tag::context(1, true), |w| {
            // listOfVariable [0] IMPLICIT SEQUENCE OF
            w.tlv(Tag::context(0, true), |w| {
                // ListOfVariableSeq: SEQUENCE { variableSpecification, ... }
                w.sequence(|w| {
                    // variableSpecification → name [0] EXPLICIT ObjectName
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
    });
}

/// Escribe un `read` de un **dataset por nombre** (`variableListName`), la forma
/// que usan los clientes para `readDataSetValues`.
pub fn write_data_set_request(w: &mut BerWriter, domain_id: &str, list_name: &str) {
    w.tlv(service::READ, |w| {
        // variableAccessSpecification [1] → variableListName [1] → domain-specific [1]
        w.tlv(Tag::context(1, true), |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.tlv(Tag::context(1, true), |w| {
                    w.visible_string(universal::VISIBLE_STRING, domain_id);
                    w.visible_string(universal::VISIBLE_STRING, list_name);
                });
            });
        });
    });
}

/// Lo que una petición `read` quiere leer (el CHOICE `VariableAccessSpecification`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadTarget {
    /// `listOfVariable [0]`: lista explícita de `(domainId, itemId)`.
    Variables(Vec<(String, String)>),
    /// `variableListName [1]`: un dataset nombrado `(domainId, listName)`.
    NamedList(String, String),
}

/// Decodifica una petición `read` (lado servidor).
///
/// Soporta las dos alternativas de `VariableAccessSpecification`: `listOfVariable`
/// (lectura de variables sueltas) y `variableListName` (lectura de un dataset por
/// nombre, que usan clientes como libiec61850 en `readDataSetValues`).
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<ReadTarget, MmsError> {
    let content = pdu::expect_service(service_tlv, service::READ)?;
    let mut r = BerReader::new(content);
    // specificationWithResult [0] BOOLEAN (primitivo) OPTIONAL → ignorar si está
    let _ = r.read_if(Tag::context(0, false))?;
    // variableAccessSpecification [1] → CHOICE { listOfVariable [0], variableListName [1] }
    let vas = r.expect(Tag::context(1, true))?;
    let mut vr = BerReader::new(vas);
    let choice = vr.read_tlv()?;
    match choice.tag {
        t if t == Tag::context(0, true) => Ok(ReadTarget::Variables(pdu::parse_list_of_variable(
            choice.content,
        )?)),
        t if t == Tag::context(1, true) => {
            // variableListName [1] ObjectName → domain-specific [1] { domainId, itemId }
            let mut nr = BerReader::new(choice.content);
            let ds = nr.expect(Tag::context(1, true))?;
            let mut dr = BerReader::new(ds);
            let domain =
                crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?
                    .to_string();
            let name =
                crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?
                    .to_string();
            Ok(ReadTarget::NamedList(domain, name))
        }
        _ => Err(MmsError::UnexpectedPdu),
    }
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
        // Estructura CONFORME (verificada contra libiec61850):
        // A4 read { A1 varAccessSpec { A0 listOfVariable { 30 seq {
        //   A0 name { A1 domainSpecific { 1A "IED1LD0", 1A "LLN0$ST$Mod$stVal" }}}}}}
        assert_eq!(bytes[0], 0xA4);
        assert!(bytes.windows(7).any(|c| c == b"IED1LD0"));
        assert!(bytes.windows(17).any(|c| c == b"LLN0$ST$Mod$stVal"));

        // Guardián de regresión del bug de interop: el variableAccessSpecification
        // DEBE ir envuelto en [1] antes del listOfVariable [0]. Sin este wrapper,
        // un stack conforme (libiec61850) rechaza el Read con reject-PDU.
        let mut r = BerReader::new(&bytes);
        let read = r.read_tlv().unwrap();
        assert_eq!(read.tag, service::READ);
        let mut rr = read.reader();
        let vas = rr.read_tlv().unwrap();
        assert_eq!(
            vas.tag,
            Tag::context(1, true),
            "variableAccessSpecification debe ser [1]"
        );
        let mut vr = vas.reader();
        let lov = vr.read_tlv().unwrap();
        assert_eq!(
            lov.tag,
            Tag::context(0, true),
            "listOfVariable debe ser [0] dentro de [1]"
        );

        // Y round-trip con nuestro propio decodificador de servidor.
        let service = Tlv {
            tag: service::READ,
            content: &bytes[read_header_len(&bytes)..],
        };
        let target = decode_request(&service).unwrap();
        assert_eq!(
            target,
            ReadTarget::Variables(vec![(
                "IED1LD0".to_string(),
                "LLN0$ST$Mod$stVal".to_string()
            )])
        );
    }

    #[test]
    fn request_named_list_dataset() {
        // variableAccessSpecification [1] { variableListName [1] { domain-specific } }
        // como envía readDataSetValues de libiec61850.
        let mut w = BerWriter::new();
        w.tlv(service::READ, |w| {
            w.boolean(Tag::context(0, false), true); // specificationWithResult
            w.tlv(Tag::context(1, true), |w| {
                w.tlv(Tag::context(1, true), |w| {
                    w.tlv(Tag::context(1, true), |w| {
                        w.visible_string(universal::VISIBLE_STRING, "IED1LD0");
                        w.visible_string(universal::VISIBLE_STRING, "LLN0$Events");
                    });
                });
            });
        });
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(
            decode_request(&svc).unwrap(),
            ReadTarget::NamedList("IED1LD0".to_string(), "LLN0$Events".to_string())
        );
    }

    /// Longitud de la cabecera TLV (tag + length) del Read para localizar su
    /// contenido en el test anterior.
    fn read_header_len(bytes: &[u8]) -> usize {
        let mut r = BerReader::new(bytes);
        let tlv = r.read_tlv().unwrap();
        bytes.len() - tlv.content.len()
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
