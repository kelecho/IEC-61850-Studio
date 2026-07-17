//! ACSE (ISO 8650): AARQ/AARE para establecer la asociación de aplicación.
//!
//! El `user-information` transporta el `Initiate-RequestPDU`/`ResponsePDU` de MMS
//! dentro de un EXTERNAL.

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, TagClass, universal};
use crate::ber::writer::BerWriter;
use crate::error::{BerError, MmsError};

/// OID del contexto de aplicación MMS (`1.0.9506.2.3`).
pub const MMS_APP_CONTEXT: [u32; 5] = [1, 0, 9506, 2, 3];

/// `[APPLICATION 0]` AARQ.
const AARQ: Tag = Tag::application(0, true);
/// `[APPLICATION 1]` AARE.
const AARE: Tag = Tag::application(1, true);
/// EXTERNAL `[UNIVERSAL 8]` constructed.
const EXTERNAL: Tag = Tag::new(TagClass::Universal, true, 8);
/// `user-information [30]`.
const USER_INFORMATION: Tag = Tag::context(30, true);
/// `single-ASN1-type [0]`.
const SINGLE_ASN1: Tag = Tag::context(0, true);
/// Identificador de contexto de presentación del abstract-syntax MMS.
const MMS_PRES_CONTEXT_ID: i64 = 3;

/// OID del mecanismo de autenticación por **password** (IEC 62351-4), codificado
/// como valor de OID sin el tag universal: `2.2.3.1` → `52 03 01`.
const AUTH_MECH_PASSWORD_OID: [u8; 3] = [0x52, 0x03, 0x01];

/// Construye un AARQ que envuelve el `Initiate-RequestPDU` de MMS, sin autenticación.
pub fn aarq(initiate_pdu: &[u8]) -> Vec<u8> {
    aarq_auth(initiate_pdu, None)
}

/// Construye un AARQ con **autenticación** opcional (IEC 62351-4/-8). El
/// `auth_value` son los octetos que viajan en `authentication-value [AC]
/// { charstring [0] }`: un password (bytes UTF-8) o un **access token firmado**
/// (BER) del RBAC 62351-8. Con `Some(..)` añade además `sender-acse-requirements
/// [10]` y `mechanism-name [11]`.
pub fn aarq_auth(initiate_pdu: &[u8], auth_value: Option<&[u8]>) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(AARQ, |w| {
        // application-context-name [1] EXPLICIT OBJECT IDENTIFIER
        w.tlv(Tag::context(1, true), |w| {
            w.object_identifier(universal::OID, &MMS_APP_CONTEXT);
        });
        if let Some(av) = auth_value {
            // sender-acse-requirements [10] IMPLICIT BIT STRING: bit authentication.
            w.primitive(Tag::context(10, false), &[0x04, 0x80]);
            // mechanism-name [11] IMPLICIT OID (password).
            w.primitive(Tag::context(11, false), &AUTH_MECH_PASSWORD_OID);
            // authentication-value [AC] CHOICE → charstring [0] IMPLICIT.
            w.tlv(Tag::context(12, true), |w| {
                w.primitive(Tag::context(0, false), av);
            });
        }
        // user-information [30] { EXTERNAL { indirect-ref, single-ASN1-type } }
        w.tlv(USER_INFORMATION, |w| {
            w.tlv(EXTERNAL, |w| {
                w.integer(universal::INTEGER, MMS_PRES_CONTEXT_ID); // indirect-reference
                w.tlv(SINGLE_ASN1, |w| w.raw(initiate_pdu));
            });
        });
    });
    w.into_bytes()
}

/// Extrae el **password** de autenticación (IEC 62351-4) de un AARQ, si lo lleva.
/// Devuelve `None` si el AARQ no incluye `authentication-value`.
pub fn extract_auth_password(data: &[u8]) -> Option<Vec<u8>> {
    let mut r = BerReader::new(data);
    let outer = r.read_tlv().ok()?;
    if outer.tag != AARQ {
        return None;
    }
    // authentication-value [AC] { charstring [0] }.
    let av = find_child(outer.content, Tag::context(12, true)).ok()??;
    let mut ar = BerReader::new(av.content);
    let charstring = ar.read_tlv().ok()?;
    Some(charstring.content.to_vec())
}

/// Construye un AARE que envuelve el `Initiate-ResponsePDU` de MMS (lado servidor).
pub fn aare(initiate_response: &[u8]) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(AARE, |w| {
        // application-context-name [1] EXPLICIT.
        w.tlv(Tag::context(1, true), |w| {
            w.object_identifier(universal::OID, &MMS_APP_CONTEXT);
        });
        // result [2] EXPLICIT INTEGER 0 (accepted). En ACSE (X.227) los tags son
        // EXPLICIT: un cliente estricto (libiec61850) rechaza la forma IMPLICIT.
        w.tlv(Tag::context(2, true), |w| {
            w.integer(universal::INTEGER, 0);
        });
        // result-source-diagnostic [3] EXPLICIT: acse-service-user [1] { INTEGER 0 }
        // (obligatorio en el AARE; su ausencia hace que peers estrictos no asocien).
        w.tlv(Tag::context(3, true), |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.integer(universal::INTEGER, 0);
            });
        });
        w.tlv(USER_INFORMATION, |w| {
            w.tlv(EXTERNAL, |w| {
                w.integer(universal::INTEGER, MMS_PRES_CONTEXT_ID);
                w.tlv(SINGLE_ASN1, |w| w.raw(initiate_response));
            });
        });
    });
    w.into_bytes()
}

/// Construye un AARE de **rechazo** de la asociación (p. ej. autenticación
/// fallida, IEC 62351-4). `result` = 1 (rejected-permanent); el
/// `result-source-diagnostic` indica `authentication-failure` (acse-service-user
/// = 6). No lleva `user-information` (no hay Initiate response).
pub fn aare_reject() -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(AARE, |w| {
        w.tlv(Tag::context(1, true), |w| {
            w.object_identifier(universal::OID, &MMS_APP_CONTEXT);
        });
        // result [2] EXPLICIT INTEGER 1 (rejected-permanent).
        w.tlv(Tag::context(2, true), |w| {
            w.integer(universal::INTEGER, 1);
        });
        // result-source-diagnostic [3]: acse-service-user [1] { 6 = authentication-failure }.
        w.tlv(Tag::context(3, true), |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.integer(universal::INTEGER, 6);
            });
        });
    });
    w.into_bytes()
}

/// Extrae el `Initiate-ResponsePDU` de un AARE, **validando antes el resultado de
/// la asociación**.
///
/// Un IED real puede rechazar la asociación (credenciales, contextos, límites de
/// conexiones). En ese caso el AARE lleva `result [2]` distinto de `accepted(0)` y,
/// a menudo, **sin** `user-information`. Antes este parser ignoraba el resultado y
/// fallaba más tarde con un error confuso (o se colgaba). Ahora se devuelve un
/// [`MmsError::AssociateRejected`] explicando el motivo (incluyendo el
/// `result-source-diagnostic [3]` cuando está presente).
pub fn parse_aare(data: &[u8]) -> Result<&[u8], MmsError> {
    let mut r = BerReader::new(data);
    let outer = r.read_tlv()?;
    if outer.tag != AARE {
        return Err(MmsError::AssociateRejected(format!(
            "se esperaba {AARE}, tag {}",
            outer.tag
        )));
    }

    // result [2] Associate-result (INTEGER: accepted(0), rejected-permanent(1),
    // rejected-transient(2)). En ACSE va EXPLICIT (constructed, [2] { INTEGER }),
    // pero toleramos la forma IMPLICIT (primitiva) por compatibilidad.
    let result_value = match find_child(outer.content, Tag::context(2, true))? {
        Some(explicit) => {
            let mut rr = BerReader::new(explicit.content);
            Some(crate::ber::prim::decode_integer(
                rr.expect(universal::INTEGER)?,
            )?)
        }
        None => find_child(outer.content, Tag::context(2, false))?
            .map(|t| crate::ber::prim::decode_integer(t.content))
            .transpose()?,
    };
    if let Some(result) = result_value {
        if result != 0 {
            let detail = find_child(outer.content, Tag::context(3, true))?
                .and_then(|t| diagnostic_text(t.content))
                .unwrap_or_else(|| associate_result_name(result).to_string());
            return Err(MmsError::AssociateRejected(format!(
                "result={result} ({detail})"
            )));
        }
    }

    let user_info = find_child(outer.content, USER_INFORMATION)?
        .ok_or_else(|| MmsError::AssociateRejected("asociación sin user-information".into()))?;
    extract_external_value(user_info.content)
}

/// Extrae el `Initiate-RequestPDU` de un AARQ entrante (lado servidor).
pub fn parse_aarq(data: &[u8]) -> Result<&[u8], MmsError> {
    parse_associate(data, AARQ)
}

/// Nombre del código de `Associate-result` para mensajes de error.
fn associate_result_name(code: i64) -> &'static str {
    match code {
        1 => "rejected-permanent",
        2 => "rejected-transient",
        _ => "rejected",
    }
}

/// Interpreta, en lo posible, el `result-source-diagnostic [3]` del AARE: una
/// CHOICE entre `acse-service-user [1] INTEGER` y `acse-service-provider [2]
/// INTEGER`. Es best-effort: si no se reconoce la forma, se devuelve `None` y el
/// llamador recurre al nombre del código de resultado.
fn diagnostic_text(content: &[u8]) -> Option<String> {
    let mut r = BerReader::new(content);
    let inner = r.read_tlv().ok()?;
    let code = crate::ber::prim::decode_integer(inner.content).ok()?;
    let src = if inner.tag == Tag::context(1, false) || inner.tag == Tag::context(1, true) {
        "service-user"
    } else if inner.tag == Tag::context(2, false) || inner.tag == Tag::context(2, true) {
        "service-provider"
    } else {
        "diagnostic"
    };
    Some(format!("{src} {code}"))
}

/// Lógica común de AARQ/AARE: localiza el `user-information` y extrae el PDU MMS.
fn parse_associate(data: &[u8], expected: Tag) -> Result<&[u8], MmsError> {
    let mut r = BerReader::new(data);
    let outer = r.read_tlv()?;
    if outer.tag != expected {
        return Err(MmsError::AssociateRejected(format!(
            "se esperaba {expected}, tag {}",
            outer.tag
        )));
    }
    let user_info = find_child(outer.content, USER_INFORMATION)?
        .ok_or_else(|| MmsError::AssociateRejected("asociación sin user-information".into()))?;
    extract_external_value(user_info.content)
}

/// Dado el contenido de un `user-information [30]` (EXTERNAL), devuelve el PDU
/// MMS que transporta (single-ASN1-type o octet-aligned).
pub fn extract_external_value(user_info: &[u8]) -> Result<&[u8], MmsError> {
    let mut r = BerReader::new(user_info);
    let external = r.expect(EXTERNAL)?;
    let mut er = BerReader::new(external);
    while !er.is_empty() {
        let tlv = er.read_tlv()?;
        match tlv.tag {
            t if t == SINGLE_ASN1 => return Ok(tlv.content),
            // octet-aligned [1] IMPLICIT OCTET STRING
            t if t == Tag::context(1, false) => return Ok(tlv.content),
            _ => {} // direct-reference / indirect-reference / descriptor → ignorar
        }
    }
    Err(MmsError::Ber(BerError::Structure(
        "EXTERNAL sin valor de codificación".into(),
    )))
}

/// Busca el primer hijo con un tag dado dentro de un contenido constructed.
fn find_child(content: &[u8], tag: Tag) -> Result<Option<Tlv<'_>>, BerError> {
    let mut r = BerReader::new(content);
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        if tlv.tag == tag {
            return Ok(Some(tlv));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aarq_wraps_initiate() {
        let initiate = [0xA8, 0x02, 0x80, 0x00]; // initiate-request ficticio
        let bytes = aarq(&initiate);
        assert_eq!(bytes[0], 0x60); // AARQ
        // contiene el OID del contexto MMS y el initiate incrustado
        let oid = crate::ber::prim::encode_oid(&MMS_APP_CONTEXT);
        assert!(bytes.windows(oid.len()).any(|w| w == oid));
        assert!(bytes.windows(initiate.len()).any(|w| w == initiate));
    }

    #[test]
    fn aarq_round_trip() {
        // el servidor extrae el Initiate-Request que el cliente metió en el AARQ
        let initiate = [0xA8, 0x02, 0x80, 0x00];
        let bytes = aarq(&initiate);
        assert_eq!(parse_aarq(&bytes).unwrap(), initiate);
    }

    #[test]
    fn aare_builder_round_trip() {
        // el AARE construido por el servidor lo decodifica el cliente
        let initiate_resp = [0xA9, 0x03, 0x81, 0x01, 0x05];
        let bytes = aare(&initiate_resp);
        assert_eq!(bytes[0], 0x61); // AARE
        assert_eq!(parse_aare(&bytes).unwrap(), initiate_resp);
    }

    #[test]
    fn aare_rejected_permanent_is_error() {
        // AARE con result [2] = 1 (rejected-permanent) y diagnóstico service-user 1.
        let mut w = BerWriter::new();
        w.tlv(AARE, |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.object_identifier(universal::OID, &MMS_APP_CONTEXT)
            });
            w.integer(Tag::context(2, false), 1); // rejected-permanent
            // result-source-diagnostic [3] { acse-service-user [1] INTEGER 1 }
            w.tlv(Tag::context(3, true), |w| {
                w.integer(Tag::context(1, false), 1);
            });
            // sin user-information, como hace un IED que rechaza
        });
        let bytes = w.into_bytes();
        let err = parse_aare(&bytes).unwrap_err();
        match err {
            MmsError::AssociateRejected(msg) => {
                assert!(msg.contains("result=1"), "msg={msg}");
                assert!(msg.contains("service-user"), "msg={msg}");
            }
            other => panic!("se esperaba AssociateRejected, fue {other:?}"),
        }
    }

    #[test]
    fn aare_rejected_without_diagnostic_falls_back_to_name() {
        let mut w = BerWriter::new();
        w.tlv(AARE, |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.object_identifier(universal::OID, &MMS_APP_CONTEXT)
            });
            w.integer(Tag::context(2, false), 2); // rejected-transient
        });
        let bytes = w.into_bytes();
        let err = parse_aare(&bytes).unwrap_err();
        match err {
            MmsError::AssociateRejected(msg) => {
                assert!(msg.contains("rejected-transient"), "msg={msg}");
            }
            other => panic!("se esperaba AssociateRejected, fue {other:?}"),
        }
    }

    #[test]
    fn aare_round_trip() {
        // construimos un AARE con un initiate-response ficticio y lo extraemos
        let initiate_resp = [0xA9, 0x03, 0x81, 0x01, 0x05];
        let mut w = BerWriter::new();
        w.tlv(AARE, |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.object_identifier(universal::OID, &MMS_APP_CONTEXT)
            });
            // result [2] accepted(0)
            w.integer(Tag::context(2, false), 0);
            w.tlv(USER_INFORMATION, |w| {
                w.tlv(EXTERNAL, |w| {
                    w.integer(universal::INTEGER, MMS_PRES_CONTEXT_ID);
                    w.tlv(SINGLE_ASN1, |w| w.raw(&initiate_resp));
                });
            });
        });
        let bytes = w.into_bytes();
        let extracted = parse_aare(&bytes).unwrap();
        assert_eq!(extracted, initiate_resp);
    }
}
