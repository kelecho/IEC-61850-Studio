//! Datasets **dinámicos** (MMS *named variable lists*, IEC 61850-8-1 Ed.2):
//! `DefineNamedVariableList` `[11]`, `DeleteNamedVariableList` `[12]` y
//! `GetNamedVariableListAttributes` `[13]`.
//!
//! Permiten a un cliente crear/borrar/introspeccionar datasets en tiempo de
//! ejecución (además de los definidos estáticamente en el SCL). El nombre de la
//! lista es un `ObjectName` domain-specific (`domainId` / `itemId`), y sus
//! miembros son `VariableSpecification` (igual que en Read/Write).

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::pdu::{self, service};

/// Escribe un `ObjectName` domain-specific `[1] { domainId, itemId }`.
fn write_object_name(w: &mut BerWriter, domain: &str, item: &str) {
    w.tlv(Tag::context(1, true), |w| {
        w.visible_string(universal::VISIBLE_STRING, domain);
        w.visible_string(universal::VISIBLE_STRING, item);
    });
}

/// Escribe un `VariableSpecification` `name [0] { domain-specific [1] {...} }`.
fn write_variable_spec(w: &mut BerWriter, domain: &str, item: &str) {
    w.tlv(Tag::context(0, true), |w| {
        write_object_name(w, domain, item)
    });
}

/// Lee un `ObjectName` domain-specific → `(domainId, itemId)`.
fn read_object_name(content: &[u8]) -> Result<(String, String), MmsError> {
    let mut r = BerReader::new(content);
    let ds = r.expect(Tag::context(1, true))?;
    let mut dr = BerReader::new(ds);
    let domain =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    let item =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    Ok((domain, item))
}

// --- DefineNamedVariableList [11] ---

/// Escribe una petición `DefineNamedVariableList`:
/// `{ variableListName ObjectName, listOfVariable SEQUENCE OF { name [0] } }`.
pub fn write_define_request(
    w: &mut BerWriter,
    domain: &str,
    name: &str,
    members: &[(String, String)],
) {
    w.tlv(service::DEFINE_NAMED_VARIABLE_LIST, |w| {
        // variableListName ObjectName (domain-specific [1]).
        write_object_name(w, domain, name);
        // listOfVariable [0] SEQUENCE OF SEQUENCE { variableSpecification }.
        // (verificado contra libiec61850: lleva tag de contexto [0], no 0x30).
        w.tlv(Tag::context(0, true), |w| {
            for (md, mi) in members {
                w.sequence(|w| write_variable_spec(w, md, mi));
            }
        });
    });
}

/// Decodifica una petición `DefineNamedVariableList` (lado servidor) →
/// `((domain, name), miembros)`.
#[allow(clippy::type_complexity)]
pub fn decode_define_request(
    service_tlv: &Tlv<'_>,
) -> Result<((String, String), Vec<(String, String)>), MmsError> {
    let content = pdu::expect_service(service_tlv, service::DEFINE_NAMED_VARIABLE_LIST)?;
    let mut r = BerReader::new(content);
    // variableListName ObjectName.
    let name_tlv = r.expect(Tag::context(1, true))?;
    let (domain, name) = read_object_name_inner(name_tlv)?;
    // listOfVariable [0] SEQUENCE OF.
    let list = r.expect(Tag::context(0, true))?;
    let members = parse_list_of_variable_spec(list)?;
    Ok(((domain, name), members))
}

/// Codifica la respuesta `DefineNamedVariableList` (éxito → NULL, tag primitivo).
pub fn encode_define_response(w: &mut BerWriter) {
    w.tlv(service::DEFINE_NAMED_VARIABLE_LIST_RESPONSE, |_| {});
}

// --- DeleteNamedVariableList [12] ---

/// Escribe una petición `DeleteNamedVariableList` para una lista concreta:
/// `{ scopeOfDelete [0] specific(0), listOfVariableListName [1] { ObjectName } }`.
pub fn write_delete_request(w: &mut BerWriter, domain: &str, name: &str) {
    w.tlv(service::DELETE_NAMED_VARIABLE_LIST, |w| {
        // scopeOfDelete [0] IMPLICIT INTEGER specific(0).
        w.integer(Tag::context(0, false), 0);
        // listOfVariableListName [1] IMPLICIT SEQUENCE OF ObjectName.
        w.tlv(Tag::context(1, true), |w| {
            write_object_name(w, domain, name)
        });
    });
}

/// Resultado de `DeleteNamedVariableList`: `(numberMatched, numberDeleted)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteResult {
    pub matched: u32,
    pub deleted: u32,
}

/// Decodifica una petición `DeleteNamedVariableList` (lado servidor) → las listas
/// a borrar `(domain, name)`.
pub fn decode_delete_request(service_tlv: &Tlv<'_>) -> Result<Vec<(String, String)>, MmsError> {
    let content = pdu::expect_service(service_tlv, service::DELETE_NAMED_VARIABLE_LIST)?;
    let mut r = BerReader::new(content);
    // scopeOfDelete [0] OPTIONAL → ignorar.
    let _ = r.read_if(Tag::context(0, false))?;
    let mut out = Vec::new();
    // listOfVariableListName [1] SEQUENCE OF ObjectName.
    if let Some(list) = r.read_if(Tag::context(1, true))? {
        let mut lr = BerReader::new(list);
        while !lr.is_empty() {
            let name = lr.expect(Tag::context(1, true))?; // ObjectName domain-specific
            out.push(read_object_name_inner_from_ds(name)?);
        }
    }
    Ok(out)
}

/// Codifica la respuesta `DeleteNamedVariableList`.
pub fn encode_delete_response(w: &mut BerWriter, result: DeleteResult) {
    w.tlv(service::DELETE_NAMED_VARIABLE_LIST, |w| {
        w.unsigned(Tag::context(0, false), result.matched as u64);
        w.unsigned(Tag::context(1, false), result.deleted as u64);
    });
}

/// Decodifica la respuesta `DeleteNamedVariableList`.
pub fn decode_delete_response(service_tlv: &Tlv<'_>) -> Result<DeleteResult, MmsError> {
    let content = pdu::expect_service(service_tlv, service::DELETE_NAMED_VARIABLE_LIST)?;
    let mut r = BerReader::new(content);
    let matched = crate::ber::prim::decode_unsigned(r.expect(Tag::context(0, false))?)? as u32;
    let deleted = crate::ber::prim::decode_unsigned(r.expect(Tag::context(1, false))?)? as u32;
    Ok(DeleteResult { matched, deleted })
}

// --- GetNamedVariableListAttributes [13] ---

/// Escribe una petición `GetNamedVariableListAttributes` (= `ObjectName`).
pub fn write_get_attributes_request(w: &mut BerWriter, domain: &str, name: &str) {
    w.tlv(service::GET_NAMED_VARIABLE_LIST_ATTRIBUTES, |w| {
        write_object_name(w, domain, name);
    });
}

/// Atributos de una named variable list: si es borrable y sus miembros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListAttributes {
    pub deletable: bool,
    pub members: Vec<(String, String)>,
}

/// Decodifica una petición `GetNamedVariableListAttributes` → `(domain, name)`.
pub fn decode_get_attributes_request(service_tlv: &Tlv<'_>) -> Result<(String, String), MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_NAMED_VARIABLE_LIST_ATTRIBUTES)?;
    read_object_name(content)
}

/// Codifica la respuesta `GetNamedVariableListAttributes`.
pub fn encode_get_attributes_response(
    w: &mut BerWriter,
    deletable: bool,
    members: &[(String, String)],
) {
    w.tlv(service::GET_NAMED_VARIABLE_LIST_ATTRIBUTES, |w| {
        // mmsDeletable [0] IMPLICIT BOOLEAN.
        w.boolean(Tag::context(0, false), deletable);
        // listOfVariable [1] IMPLICIT SEQUENCE OF SEQUENCE { name [0] }.
        w.tlv(Tag::context(1, true), |w| {
            for (md, mi) in members {
                w.sequence(|w| write_variable_spec(w, md, mi));
            }
        });
    });
}

/// Decodifica la respuesta `GetNamedVariableListAttributes`.
pub fn decode_get_attributes_response(service_tlv: &Tlv<'_>) -> Result<ListAttributes, MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_NAMED_VARIABLE_LIST_ATTRIBUTES)?;
    let mut r = BerReader::new(content);
    let deletable = crate::ber::prim::decode_bool(r.expect(Tag::context(0, false))?)?;
    let list = r.expect(Tag::context(1, true))?;
    let members = parse_list_of_variable_spec(list)?;
    Ok(ListAttributes { deletable, members })
}

// --- Helpers compartidos ---

/// Lee el contenido de un `ObjectName` que ya viene como domain-specific `[1]`.
fn read_object_name_inner(name_tlv: &[u8]) -> Result<(String, String), MmsError> {
    read_object_name_inner_from_ds(name_tlv)
}

/// El TLV ya es el contenido del domain-specific `[1]` (SEQUENCE { domainId, itemId }).
fn read_object_name_inner_from_ds(ds_content: &[u8]) -> Result<(String, String), MmsError> {
    let mut dr = BerReader::new(ds_content);
    let domain =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    let item =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    Ok((domain, item))
}

/// Parsea un `SEQUENCE OF { variableSpecification: name [0] { domain-specific } }`.
fn parse_list_of_variable_spec(content: &[u8]) -> Result<Vec<(String, String)>, MmsError> {
    let mut lr = BerReader::new(content);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let seq = lr.read_tlv()?; // SEQUENCE { variableSpecification, alternateAccess? }
        let mut sr = BerReader::new(seq.content);
        let name = sr.expect(Tag::context(0, true))?; // name [0] EXPLICIT ObjectName
        out.push(read_object_name(name)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_service<F: FnOnce(&mut BerWriter)>(f: F) -> Vec<u8> {
        let mut w = BerWriter::new();
        f(&mut w);
        w.into_bytes()
    }

    #[test]
    fn define_request_round_trip() {
        let members = vec![
            ("LD0".to_string(), "GGIO1$ST$Ind1$stVal".to_string()),
            ("LD0".to_string(), "GGIO1$ST$Ind2$stVal".to_string()),
        ];
        let bytes = round_service(|w| write_define_request(w, "LD0", "myDS", &members));
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        let ((d, n), got) = decode_define_request(&svc).unwrap();
        assert_eq!((d.as_str(), n.as_str()), ("LD0", "myDS"));
        assert_eq!(got, members);
    }

    #[test]
    fn delete_request_and_response_round_trip() {
        let bytes = round_service(|w| write_delete_request(w, "LD0", "myDS"));
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(
            decode_delete_request(&svc).unwrap(),
            vec![("LD0".to_string(), "myDS".to_string())]
        );

        let resp = round_service(|w| {
            encode_delete_response(
                w,
                DeleteResult {
                    matched: 1,
                    deleted: 1,
                },
            )
        });
        let mut r = BerReader::new(&resp);
        let svc = r.read_tlv().unwrap();
        assert_eq!(
            decode_delete_response(&svc).unwrap(),
            DeleteResult {
                matched: 1,
                deleted: 1
            }
        );
    }

    #[test]
    fn get_attributes_round_trip() {
        let members = vec![("LD0".to_string(), "GGIO1$ST$Ind1$stVal".to_string())];
        let req = round_service(|w| write_get_attributes_request(w, "LD0", "myDS"));
        let mut r = BerReader::new(&req);
        let svc = r.read_tlv().unwrap();
        assert_eq!(
            decode_get_attributes_request(&svc).unwrap(),
            ("LD0".to_string(), "myDS".to_string())
        );

        let resp = round_service(|w| encode_get_attributes_response(w, true, &members));
        let mut r = BerReader::new(&resp);
        let svc = r.read_tlv().unwrap();
        let attrs = decode_get_attributes_response(&svc).unwrap();
        assert!(attrs.deletable);
        assert_eq!(attrs.members, members);
    }
}
