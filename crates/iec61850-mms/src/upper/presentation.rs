//! ISO Presentation (ISO 8823): CP/CPA y `fully-encoded-data`.
//!
//! En el envío construimos un CP con dos contextos (ACSE=1, MMS=3). En la
//! recepción no parseamos la capa de sesión: localizamos directamente el
//! `fully-encoded-data` y extraemos el PDU interno (AARE en la asociación, o el
//! PDU MMS en la fase de datos). Es un enfoque tolerante; las constantes del CP
//! deberían validarse contra una captura real de un IED.

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::MmsError;

/// OID del abstract-syntax de ACSE (`2.2.1.0.1`).
const ACSE_AS: [u32; 5] = [2, 2, 1, 0, 1];
/// OID del abstract-syntax de MMS (`1.0.9506.2.1`).
const MMS_AS: [u32; 5] = [1, 0, 9506, 2, 1];
/// OID del transfer-syntax BER (`2.1.1`).
const BER_TS: [u32; 3] = [2, 1, 1];

pub const ACSE_CONTEXT_ID: i64 = 1;
pub const MMS_CONTEXT_ID: i64 = 3;

const SET: Tag = Tag::universal(17, true); // 0x31
const FULLY_ENCODED: Tag = Tag::application(1, true); // 0x61
const SINGLE_ASN1: Tag = Tag::context(0, true);

/// Construye un CP (Connect Presentation) que transporta el AARQ bajo el
/// contexto ACSE.
pub fn connect_cp(aarq: &[u8]) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(SET, |w| {
        // mode-selector [0] { [0] normal-mode(1) }
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), 1);
        });
        // normal-mode-parameters [2]
        w.tlv(Tag::context(2, true), |w| {
            // calling/called presentation-selector [1]/[2] IMPLICIT OCTET STRING
            w.octet_string(Tag::context(1, false), &[0, 0, 0, 1]);
            w.octet_string(Tag::context(2, false), &[0, 0, 0, 1]);
            // presentation-context-definition-list [4]
            w.tlv(Tag::context(4, true), |w| {
                context_list_item(w, ACSE_CONTEXT_ID, &ACSE_AS);
                context_list_item(w, MMS_CONTEXT_ID, &MMS_AS);
            });
            // user-data: fully-encoded-data con el AARQ bajo el contexto ACSE
            w.raw(&user_data(aarq, ACSE_CONTEXT_ID));
        });
    });
    w.into_bytes()
}

/// Construye un CPA (Connect Presentation Accept) que transporta el AARE bajo el
/// contexto ACSE. Gemelo de [`connect_cp`]; el cliente lo desenvuelve con
/// [`extract_inner_pdu`], así que la forma exacta de la lista de contextos es
/// indiferente para la interoperación con este crate.
pub fn connect_cpa(aare: &[u8]) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(SET, |w| {
        // mode-selector [0] { [0] normal-mode(1) }
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), 1);
        });
        // normal-mode-parameters [2]
        w.tlv(Tag::context(2, true), |w| {
            w.octet_string(Tag::context(1, false), &[0, 0, 0, 1]); // responding-selector
            // presentation-context-definition-result-list [5]: aceptación por contexto
            w.tlv(Tag::context(5, true), |w| {
                result_list_item(w);
                result_list_item(w);
            });
            // user-data: fully-encoded-data con el AARE bajo el contexto ACSE
            w.raw(&user_data(aare, ACSE_CONTEXT_ID));
        });
    });
    w.into_bytes()
}

/// Un resultado de contexto: result [0] = acceptance(0) + transfer-syntax [1].
fn result_list_item(w: &mut BerWriter) {
    w.sequence(|w| {
        w.integer(Tag::context(0, false), 0); // acceptance
        w.object_identifier(Tag::context(1, false), &BER_TS);
    });
}

fn context_list_item(w: &mut BerWriter, id: i64, abstract_syntax: &[u32]) {
    w.sequence(|w| {
        w.integer(universal::INTEGER, id);
        w.object_identifier(universal::OID, abstract_syntax);
        w.sequence(|w| w.object_identifier(universal::OID, &BER_TS));
    });
}

/// Construye un `fully-encoded-data` que transporta `pdu` bajo el contexto dado.
pub fn user_data(pdu: &[u8], context_id: i64) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(FULLY_ENCODED, |w| {
        // PDV-list
        w.sequence(|w| {
            w.integer(universal::INTEGER, context_id); // presentation-context-identifier
            w.tlv(SINGLE_ASN1, |w| w.raw(pdu)); // single-ASN1-type [0]
        });
    });
    w.into_bytes()
}

/// Localiza el `fully-encoded-data` en un buffer recibido y extrae el PDU
/// interno (contenido del `single-ASN1-type`).
///
/// Funciona tanto para el CPA de la asociación (devuelve el AARE) como para las
/// respuestas de datos (devuelve el PDU MMS), sin parsear la capa de sesión.
pub fn extract_inner_pdu(buf: &[u8]) -> Result<&[u8], MmsError> {
    for start in 0..buf.len() {
        if buf[start] != 0x61 {
            continue;
        }
        let mut r = BerReader::new(&buf[start..]);
        let Ok(fed) = r.read_tlv() else { continue };
        if fed.tag != FULLY_ENCODED {
            continue;
        }
        if let Ok(inner) = drill_pdv(fed.content) {
            return Ok(inner);
        }
    }
    Err(MmsError::Transport(
        "no se encontró fully-encoded-data en la respuesta".into(),
    ))
}

fn drill_pdv(content: &[u8]) -> Result<&[u8], MmsError> {
    let mut r = BerReader::new(content);
    let pdv = r.expect(universal::SEQUENCE)?;
    let mut pr = BerReader::new(pdv);
    while !pr.is_empty() {
        let tlv = pr.read_tlv()?;
        match tlv.tag {
            t if t == SINGLE_ASN1 => return Ok(tlv.content),
            t if t == Tag::context(1, false) => return Ok(tlv.content), // octet-aligned
            _ => {}
        }
    }
    Err(MmsError::Transport("PDV-list sin valor de datos".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_round_trip() {
        let pdu = [0xA0, 0x03, 0x02, 0x01, 0x2A];
        let ud = user_data(&pdu, MMS_CONTEXT_ID);
        assert_eq!(ud[0], 0x61);
        let extracted = extract_inner_pdu(&ud).unwrap();
        assert_eq!(extracted, pdu);
    }

    #[test]
    fn extract_from_cpa() {
        // un AARE en un CPA del servidor debe poder extraerse igual que del CP
        let aare = [0x61u8, 0x02, 0x80, 0x00];
        let cpa = connect_cpa(&aare);
        assert_eq!(cpa[0], 0x31); // SET
        assert_eq!(extract_inner_pdu(&cpa).unwrap(), aare);
    }

    #[test]
    fn extract_from_cp() {
        // un AARQ ficticio embebido en un CP debe poder extraerse del 0x61 interno
        let aarq = [0xA8, 0x02, 0x80, 0x00];
        let cp = connect_cp(&aarq);
        assert_eq!(cp[0], 0x31); // SET
        let extracted = extract_inner_pdu(&cp).unwrap();
        assert_eq!(extracted, aarq);
    }

    #[test]
    fn extract_ignores_session_prefix() {
        // simula bytes de sesión por delante del fully-encoded-data
        let pdu = [0x84u8, 0x01, 0xFF];
        let ud = user_data(&pdu, MMS_CONTEXT_ID);
        let mut framed = vec![0x01, 0x00, 0x01, 0x00];
        framed.extend_from_slice(&ud);
        assert_eq!(extract_inner_pdu(&framed).unwrap(), pdu);
    }
}
