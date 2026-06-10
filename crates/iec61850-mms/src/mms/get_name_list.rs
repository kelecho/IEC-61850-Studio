//! Servicio MMS `GetNameList`: enumera objetos (dominios = LDs, o variables de
//! un dominio). Soporta paginación vía `continueAfter`/`moreFollows`.

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::pdu::{self, service};

/// Clase de objeto a enumerar (subconjunto usado por el cliente).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClass {
    NamedVariable,
    Domain,
}

impl ObjectClass {
    fn code(self) -> i64 {
        match self {
            ObjectClass::NamedVariable => 0,
            ObjectClass::Domain => 9,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(ObjectClass::NamedVariable),
            9 => Some(ObjectClass::Domain),
            _ => None,
        }
    }
}

/// Petición `GetNameList` decodificada (lado servidor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListRequest {
    pub class: ObjectClass,
    pub scope: ObjectScope,
    pub continue_after: Option<String>,
}

/// Ámbito de la enumeración.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectScope {
    VmdSpecific,
    DomainSpecific(String),
}

/// Respuesta de `GetNameList` (una página).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListResponse {
    pub identifiers: Vec<String>,
    pub more_follows: bool,
}

/// Escribe el servicio `getNameList` en una Confirmed-Request.
pub fn write_request(
    w: &mut BerWriter,
    class: ObjectClass,
    scope: &ObjectScope,
    continue_after: Option<&str>,
) {
    w.tlv(service::GET_NAME_LIST, |w| {
        // objectClass [0] EXPLICIT { basicObjectClass [0] IMPLICIT INTEGER }
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), class.code());
        });
        // objectScope [1] EXPLICIT CHOICE
        w.tlv(Tag::context(1, true), |w| match scope {
            ObjectScope::VmdSpecific => w.null(Tag::context(0, false)),
            ObjectScope::DomainSpecific(d) => w.visible_string(Tag::context(1, false), d),
        });
        // continueAfter [2] IMPLICIT Identifier OPTIONAL
        if let Some(ca) = continue_after {
            w.visible_string(Tag::context(2, false), ca);
        }
    });
}

/// Decodifica una petición `getNameList` (lado servidor).
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<GetNameListRequest, MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_NAME_LIST)?;
    let mut r = BerReader::new(content);

    // objectClass [0] EXPLICIT { basicObjectClass [0] INTEGER }
    let class_outer = r.expect(Tag::context(0, true))?;
    let mut cr = BerReader::new(class_outer);
    let class_code = crate::ber::prim::decode_integer(cr.expect(Tag::context(0, false))?)?;
    let class = ObjectClass::from_code(class_code)
        .ok_or_else(|| MmsError::ServiceReject(format!("objectClass {class_code} no soportada")))?;

    // objectScope [1] EXPLICIT CHOICE
    let scope_outer = r.expect(Tag::context(1, true))?;
    let mut sr = BerReader::new(scope_outer);
    let scope_tlv = sr.read_tlv()?;
    let scope = match scope_tlv.tag {
        t if t == Tag::context(0, false) => ObjectScope::VmdSpecific,
        t if t == Tag::context(1, false) => ObjectScope::DomainSpecific(
            crate::ber::prim::decode_visible_string(scope_tlv.content)?.to_string(),
        ),
        _ => return Err(MmsError::UnexpectedPdu),
    };

    // continueAfter [2] IMPLICIT Identifier OPTIONAL
    let continue_after = match r.read_if(Tag::context(2, false))? {
        Some(c) => Some(crate::ber::prim::decode_visible_string(c)?.to_string()),
        None => None,
    };

    Ok(GetNameListRequest {
        class,
        scope,
        continue_after,
    })
}

/// Codifica una página de respuesta `getNameList` (lado servidor).
pub fn encode_response(w: &mut BerWriter, resp: &GetNameListResponse) {
    w.tlv(service::GET_NAME_LIST, |w| {
        w.tlv(Tag::context(0, true), |w| {
            for id in &resp.identifiers {
                w.visible_string(universal::VISIBLE_STRING, id);
            }
        });
        w.boolean(Tag::context(1, false), resp.more_follows);
    });
}

/// Decodifica una página de respuesta desde el TLV de servicio.
pub fn decode_response(service_tlv: &Tlv<'_>) -> Result<GetNameListResponse, MmsError> {
    let content = pdu::expect_service(service_tlv, service::GET_NAME_LIST)?;
    let mut r = BerReader::new(content);

    // listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier
    let list = r.expect(Tag::context(0, true))?;
    let mut lr = BerReader::new(list);
    let mut identifiers = Vec::new();
    while !lr.is_empty() {
        let id = lr.expect(universal::VISIBLE_STRING)?;
        identifiers.push(crate::ber::prim::decode_visible_string(id)?.to_string());
    }

    // moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE
    let more_follows = match r.read_if(Tag::context(1, false))? {
        Some(c) => crate::ber::prim::decode_bool(c)?,
        None => true,
    };

    Ok(GetNameListResponse {
        identifiers,
        more_follows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_domains() {
        let mut w = BerWriter::new();
        write_request(&mut w, ObjectClass::Domain, &ObjectScope::VmdSpecific, None);
        // A1 { A0{80 01 09} A1{80 00} }
        assert_eq!(
            w.into_bytes(),
            vec![
                0xA1, 0x09, 0xA0, 0x03, 0x80, 0x01, 0x09, 0xA1, 0x02, 0x80, 0x00
            ]
        );
    }

    #[test]
    fn request_domain_variables_with_continue() {
        let mut w = BerWriter::new();
        write_request(
            &mut w,
            ObjectClass::NamedVariable,
            &ObjectScope::DomainSpecific("LD0".into()),
            Some("LLN0$ST$Mod"),
        );
        let bytes = w.into_bytes();
        // empieza por getNameList [1], objectClass namedVariable(0), scope domainSpecific "LD0"
        assert_eq!(&bytes[..7], &[0xA1, bytes[1], 0xA0, 0x03, 0x80, 0x01, 0x00]);
        // contiene "LD0" y el continueAfter "LLN0$ST$Mod"
        assert!(bytes.windows(3).any(|w| w == b"LD0"));
        assert!(bytes.windows(11).any(|w| w == b"LLN0$ST$Mod"));
    }

    #[test]
    fn response_with_more_follows() {
        // A1 { A0 { 1A 02 "AB" , 1A 02 "CD" } , 81 01 FF }
        let bytes = [
            0xA1, 0x11, 0xA0, 0x0C, 0x1A, 0x02, b'A', b'B', 0x1A, 0x02, b'C', b'D', 0x1A, 0x02,
            b'E', b'F', 0x81, 0x01, 0xFF,
        ];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let resp = decode_response(&tlv).unwrap();
        assert_eq!(resp.identifiers, vec!["AB", "CD", "EF"]);
        assert!(resp.more_follows);
    }

    #[test]
    fn response_default_more_follows_false_when_absent() {
        // sin el campo moreFollows → DEFAULT TRUE
        let bytes = [0xA1, 0x06, 0xA0, 0x04, 0x1A, 0x02, b'X', b'Y'];
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let resp = decode_response(&tlv).unwrap();
        assert_eq!(resp.identifiers, vec!["XY"]);
        assert!(resp.more_follows); // ausente ⇒ true
    }
}
