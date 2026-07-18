//! ISO Presentation (ISO 8823): CP/CPA, negociación de contextos y
//! `fully-encoded-data`.
//!
//! Cliente: construye un CP con dos contextos (ACSE=1, MMS=3) y valida en el
//! CPA que el servidor aceptó el contexto MMS ([`check_cpa_results`]).
//! Servidor: **negociación real** — [`parse_cp`] parsea la lista de contextos
//! propuesta, [`negotiate`] acepta ACSE/MMS con transfer-syntax BER y rechaza
//! el resto con su razón, y [`connect_cpa_negotiated`] responde a CADA contexto
//! en orden; la fase de datos usa el context-id MMS que propuso el cliente.
//! [`extract_inner_pdu`] sigue disponible como camino tolerante (escaneo) para
//! peers cuya trama no parsea.

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

/// Un contexto de presentación propuesto en el CP entrante.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedContext {
    pub id: i64,
    /// Contenido crudo del OID del abstract-syntax (sin tag/longitud).
    pub abstract_syntax: Vec<u8>,
    /// Contenidos crudos de los OID de transfer-syntax propuestos.
    pub transfer_syntaxes: Vec<Vec<u8>>,
}

/// CP entrante parseado (lado servidor).
#[derive(Debug, PartialEq)]
pub struct ParsedCp<'a> {
    pub contexts: Vec<ProposedContext>,
    /// called-presentation-selector `[2]`, si vino (se refleja en el CPA).
    pub called_selector: Option<&'a [u8]>,
    /// PDU interno del user-data del CP (el AARQ, ya extraído del PDV-list).
    pub inner_pdu: &'a [u8],
}

/// Veredicto por contexto propuesto (ISO 8823 `Result-list`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContextVerdict {
    /// acceptance(0) con transfer-syntax BER.
    Acceptance,
    /// provider-rejection(2), abstract-syntax-not-supported(1).
    AbstractSyntaxNotSupported,
    /// provider-rejection(2), proposed-transfer-syntaxes-not-supported(2).
    TransferSyntaxesNotSupported,
}

/// Resultado de la negociación de un CP.
#[derive(Debug, PartialEq)]
pub struct Negotiated {
    /// Id del contexto ACSE aceptado (el primero cuyo abstract-syntax es ACSE).
    pub acse_id: Option<i64>,
    /// Id del contexto MMS aceptado.
    pub mms_id: Option<i64>,
    /// Veredicto por contexto, en el MISMO orden en que se propusieron.
    pub verdicts: Vec<ContextVerdict>,
}

/// Parsea el CP (`SET` de ISO 8823): mode-selector, lista de contextos
/// propuestos, called-selector y user-data. Falla si no es normal-mode.
pub fn parse_cp(buf: &[u8]) -> Result<ParsedCp<'_>, MmsError> {
    let err = |m: &str| MmsError::Transport(format!("CP de presentación: {m}"));
    let mut r = BerReader::new(buf);
    let set = r.read_tlv().map_err(|_| err("no es un SET"))?;
    if set.tag != SET {
        return Err(err("no es un SET"));
    }

    let mut contexts = Vec::new();
    let mut called_selector = None;
    let mut inner_pdu: Option<&[u8]> = None;

    let mut sr = BerReader::new(set.content);
    while !sr.is_empty() {
        let item = sr.read_tlv().map_err(|_| err("elemento truncado"))?;
        if item.tag == Tag::context(0, true) {
            // mode-selector [0] { [0] INTEGER }: solo normal-mode (1).
            let mut mr = BerReader::new(item.content);
            if let Ok(m) = mr.read_tlv() {
                if crate::ber::prim::decode_integer(m.content) != Ok(1) {
                    return Err(err("mode-selector distinto de normal-mode"));
                }
            }
        } else if item.tag == Tag::context(2, true) {
            // normal-mode-parameters [2]
            let mut pr = BerReader::new(item.content);
            while !pr.is_empty() {
                let p = pr.read_tlv().map_err(|_| err("parámetro truncado"))?;
                if p.tag == Tag::context(2, false) {
                    called_selector = Some(p.content);
                } else if p.tag == Tag::context(4, true) {
                    contexts = parse_context_list(p.content)?;
                } else if p.tag == FULLY_ENCODED {
                    inner_pdu = Some(drill_pdv(p.content)?);
                }
            }
        }
    }
    if contexts.is_empty() {
        return Err(err("sin presentation-context-definition-list"));
    }
    let inner_pdu = inner_pdu.ok_or_else(|| err("sin user-data"))?;
    Ok(ParsedCp {
        contexts,
        called_selector,
        inner_pdu,
    })
}

/// Parsea la `presentation-context-definition-list [4]`.
fn parse_context_list(content: &[u8]) -> Result<Vec<ProposedContext>, MmsError> {
    let err = |m: &str| MmsError::Transport(format!("context-definition-list: {m}"));
    let mut out = Vec::new();
    let mut r = BerReader::new(content);
    while !r.is_empty() {
        let item = r.read_tlv().map_err(|_| err("contexto truncado"))?;
        if item.tag != universal::SEQUENCE {
            continue; // tolerante con elementos desconocidos
        }
        let mut ir = BerReader::new(item.content);
        let id_tlv = ir.expect(universal::INTEGER).map_err(|_| err("sin id"))?;
        let id = crate::ber::prim::decode_integer(id_tlv).map_err(|_| err("id inválido"))?;
        let abs = ir
            .expect(universal::OID)
            .map_err(|_| err("sin abstract-syntax"))?;
        let mut transfer_syntaxes = Vec::new();
        if let Ok(ts_list) = ir.expect(universal::SEQUENCE) {
            let mut tr = BerReader::new(ts_list);
            while !tr.is_empty() {
                if let Ok(ts) = tr.expect(universal::OID) {
                    transfer_syntaxes.push(ts.to_vec());
                } else {
                    break;
                }
            }
        }
        out.push(ProposedContext {
            id,
            abstract_syntax: abs.to_vec(),
            transfer_syntaxes,
        });
    }
    Ok(out)
}

/// Negocia los contextos propuestos: acepta ACSE y MMS con transfer-syntax BER;
/// rechaza (con la razón adecuada) cualquier otro. El orden de los veredictos
/// es el de la propuesta (obligatorio en el Result-list de ISO 8823).
pub fn negotiate(contexts: &[ProposedContext]) -> Negotiated {
    let acse_oid = crate::ber::prim::encode_oid(&ACSE_AS);
    let mms_oid = crate::ber::prim::encode_oid(&MMS_AS);
    let ber_oid = crate::ber::prim::encode_oid(&BER_TS);

    let mut neg = Negotiated {
        acse_id: None,
        mms_id: None,
        verdicts: Vec::with_capacity(contexts.len()),
    };
    for c in contexts {
        let known = c.abstract_syntax == acse_oid || c.abstract_syntax == mms_oid;
        let verdict = if !known {
            ContextVerdict::AbstractSyntaxNotSupported
        } else if !c.transfer_syntaxes.contains(&ber_oid) {
            ContextVerdict::TransferSyntaxesNotSupported
        } else {
            if c.abstract_syntax == acse_oid && neg.acse_id.is_none() {
                neg.acse_id = Some(c.id);
            }
            if c.abstract_syntax == mms_oid && neg.mms_id.is_none() {
                neg.mms_id = Some(c.id);
            }
            ContextVerdict::Acceptance
        };
        neg.verdicts.push(verdict);
    }
    neg
}

/// CPA **negociado**: el Result-list responde a CADA contexto propuesto en su
/// orden (acceptance con BER o provider-rejection con razón), el
/// responding-selector refleja el called-selector del CP y el AARE viaja bajo
/// el context-id ACSE que propuso el cliente.
pub fn connect_cpa_negotiated(
    aare: &[u8],
    neg: &Negotiated,
    called_selector: Option<&[u8]>,
    acse_context_id: i64,
) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(SET, |w| {
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), 1);
        });
        w.tlv(Tag::context(2, true), |w| {
            // responding-presentation-selector [3]: eco del called-selector.
            w.octet_string(
                Tag::context(3, false),
                called_selector.unwrap_or(&[0, 0, 0, 1]),
            );
            // presentation-context-definition-result-list [5], MISMO orden.
            w.tlv(Tag::context(5, true), |w| {
                for v in &neg.verdicts {
                    match v {
                        ContextVerdict::Acceptance => result_list_item(w),
                        ContextVerdict::AbstractSyntaxNotSupported => {
                            rejection_item(w, 1);
                        }
                        ContextVerdict::TransferSyntaxesNotSupported => {
                            rejection_item(w, 2);
                        }
                    }
                }
            });
            w.raw(&user_data(aare, acse_context_id));
        });
    });
    w.into_bytes()
}

/// Un resultado de rechazo: provider-rejection(2) + provider-reason `[2]`.
fn rejection_item(w: &mut BerWriter, reason: i64) {
    w.sequence(|w| {
        w.integer(Tag::context(0, false), 2); // provider-rejection
        w.integer(Tag::context(2, false), reason);
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

/// Valida el Result-list del CPA recibido (lado cliente): nuestro CP propone
/// `[ACSE(id 1), MMS(id 3)]`, así que la SEGUNDA entrada del
/// `presentation-context-definition-result-list [5]` es el contexto MMS; si el
/// servidor la rechazó, la asociación no sirve y se falla con un error claro
/// en vez de morir después con PDUs indescifrables. Best-effort: si el CPA no
/// trae la estructura esperada (servidores de plantilla), no se bloquea.
pub fn check_cpa_results(buf: &[u8]) -> Result<(), MmsError> {
    fn find_in(content: &[u8], tag: Tag) -> Option<&[u8]> {
        let mut r = BerReader::new(content);
        while !r.is_empty() {
            let tlv = r.read_tlv().ok()?;
            if tlv.tag == tag {
                return Some(tlv.content);
            }
        }
        None
    }
    for start in 0..buf.len() {
        if buf[start] != 0x31 {
            continue;
        }
        let mut r = BerReader::new(&buf[start..]);
        let Ok(set) = r.read_tlv() else { continue };
        if set.tag != SET {
            continue;
        }
        let Some(params) = find_in(set.content, Tag::context(2, true)) else {
            continue;
        };
        let Some(results) = find_in(params, Tag::context(5, true)) else {
            return Ok(()); // CPA sin result-list: tolerado
        };
        let mut idx = 0usize;
        let mut rr = BerReader::new(results);
        while !rr.is_empty() {
            let Ok(item) = rr.read_tlv() else { break };
            if item.tag != universal::SEQUENCE {
                continue;
            }
            let mut ir = BerReader::new(item.content);
            if let Ok(res) = ir.read_tlv() {
                if res.tag == Tag::context(0, false) {
                    let code = crate::ber::prim::decode_integer(res.content).unwrap_or(0);
                    if code != 0 && idx == 1 {
                        return Err(MmsError::AssociateRejected(format!(
                            "el servidor rechazó el contexto de presentación MMS (result={code})"
                        )));
                    }
                }
            }
            idx += 1;
        }
        return Ok(());
    }
    Ok(())
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

    #[test]
    fn parse_cp_of_our_connect() {
        // Nuestro propio CP debe parsearse: 2 contextos (ACSE=1, MMS=3) con
        // transfer BER, y el AARQ recuperable como inner_pdu.
        let aarq = [0x60u8, 0x02, 0x80, 0x00];
        let cp_bytes = connect_cp(&aarq);
        let cp = parse_cp(&cp_bytes).expect("CP propio parseable");
        assert_eq!(cp.contexts.len(), 2);
        assert_eq!(cp.contexts[0].id, ACSE_CONTEXT_ID);
        assert_eq!(cp.contexts[1].id, MMS_CONTEXT_ID);
        assert_eq!(
            cp.contexts[1].abstract_syntax,
            crate::ber::prim::encode_oid(&MMS_AS)
        );
        assert_eq!(cp.contexts[1].transfer_syntaxes.len(), 1);
        assert_eq!(cp.called_selector, Some(&[0u8, 0, 0, 1][..]));
        assert_eq!(cp.inner_pdu, aarq);
    }

    #[test]
    fn negotiate_accepts_acse_and_mms_rejects_unknown() {
        let ber = crate::ber::prim::encode_oid(&BER_TS);
        let contexts = vec![
            ProposedContext {
                id: 5,
                abstract_syntax: crate::ber::prim::encode_oid(&ACSE_AS),
                transfer_syntaxes: vec![ber.clone()],
            },
            ProposedContext {
                id: 7,
                abstract_syntax: crate::ber::prim::encode_oid(&MMS_AS),
                transfer_syntaxes: vec![ber.clone()],
            },
            // abstract-syntax desconocido
            ProposedContext {
                id: 9,
                abstract_syntax: crate::ber::prim::encode_oid(&[1, 2, 3, 4]),
                transfer_syntaxes: vec![ber],
            },
            // MMS sin BER entre los transfer propuestos
            ProposedContext {
                id: 11,
                abstract_syntax: crate::ber::prim::encode_oid(&MMS_AS),
                transfer_syntaxes: vec![crate::ber::prim::encode_oid(&[1, 2, 840])],
            },
        ];
        let neg = negotiate(&contexts);
        assert_eq!(neg.acse_id, Some(5));
        assert_eq!(neg.mms_id, Some(7));
        assert_eq!(
            neg.verdicts,
            vec![
                ContextVerdict::Acceptance,
                ContextVerdict::Acceptance,
                ContextVerdict::AbstractSyntaxNotSupported,
                ContextVerdict::TransferSyntaxesNotSupported,
            ]
        );
    }

    #[test]
    fn negotiated_cpa_round_trip_and_client_check() {
        // CPA negociado con un contexto rechazado: el AARE se extrae igual y
        // el result-list refleja los 3 veredictos en orden.
        let aare = [0x61u8, 0x02, 0x80, 0x00];
        let neg = Negotiated {
            acse_id: Some(1),
            mms_id: Some(3),
            verdicts: vec![
                ContextVerdict::Acceptance,
                ContextVerdict::Acceptance,
                ContextVerdict::AbstractSyntaxNotSupported,
            ],
        };
        let cpa = connect_cpa_negotiated(&aare, &neg, Some(&[0, 0, 0, 2]), 1);
        assert_eq!(extract_inner_pdu(&cpa).unwrap(), aare);
        // La entrada MMS (índice 1) es aceptación → el cliente no protesta.
        check_cpa_results(&cpa).expect("MMS aceptado");
    }

    #[test]
    fn client_detects_rejected_mms_context() {
        // CPA cuyo result-list rechaza el contexto MMS (2ª entrada).
        let aare = [0x61u8, 0x02, 0x80, 0x00];
        let neg = Negotiated {
            acse_id: Some(1),
            mms_id: None,
            verdicts: vec![
                ContextVerdict::Acceptance,
                ContextVerdict::TransferSyntaxesNotSupported,
            ],
        };
        let cpa = connect_cpa_negotiated(&aare, &neg, None, 1);
        let err = check_cpa_results(&cpa).unwrap_err();
        assert!(
            err.to_string().contains("contexto de presentación MMS"),
            "err={err}"
        );
    }
}
