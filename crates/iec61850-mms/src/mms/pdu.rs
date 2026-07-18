//! Envoltura de PDUs MMS (`MMSpdu` CHOICE) y utilidades comunes de
//! petición/respuesta confirmadas.

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::{BerError, MmsError};

/// Tags de contexto del CHOICE `MMSpdu`.
pub mod mmspdu {
    use crate::ber::tag::Tag;
    pub const CONFIRMED_REQUEST: Tag = Tag::context(0, true);
    pub const CONFIRMED_RESPONSE: Tag = Tag::context(1, true);
    pub const CONFIRMED_ERROR: Tag = Tag::context(2, true);
    pub const UNCONFIRMED: Tag = Tag::context(3, true);
    pub const REJECT: Tag = Tag::context(4, true);
    pub const INITIATE_REQUEST: Tag = Tag::context(8, true);
    pub const INITIATE_RESPONSE: Tag = Tag::context(9, true);
    pub const INITIATE_ERROR: Tag = Tag::context(10, true);
    pub const CONCLUDE_REQUEST: Tag = Tag::context(11, true);
    pub const CONCLUDE_RESPONSE: Tag = Tag::context(12, true);
}

/// Tags de contexto del CHOICE `ConfirmedServiceRequest`/`Response`.
pub mod service {
    use crate::ber::tag::Tag;
    pub const GET_NAME_LIST: Tag = Tag::context(1, true);
    /// Identify: la **petición** es primitiva (NULL implícito); la **respuesta**
    /// es constructed (SEQUENCE).
    pub const IDENTIFY_REQUEST: Tag = Tag::context(2, false);
    pub const IDENTIFY_RESPONSE: Tag = Tag::context(2, true);
    pub const READ: Tag = Tag::context(4, true);
    pub const WRITE: Tag = Tag::context(5, true);
    pub const GET_VARIABLE_ACCESS_ATTRIBUTES: Tag = Tag::context(6, true);
    // Datasets dinámicos (MMS named variable lists, IEC 61850-8-1 Ed.2).
    pub const DEFINE_NAMED_VARIABLE_LIST: Tag = Tag::context(11, true);
    /// La **respuesta** de DefineNamedVariableList es `NULL` → tag `[11]` primitivo.
    pub const DEFINE_NAMED_VARIABLE_LIST_RESPONSE: Tag = Tag::context(11, false);
    pub const DELETE_NAMED_VARIABLE_LIST: Tag = Tag::context(12, true);
    pub const GET_NAMED_VARIABLE_LIST_ATTRIBUTES: Tag = Tag::context(13, true);
    /// ReadJournal (logs, ISO 9506): tag `[65]` constructed (multi-byte `bf 41`).
    pub const READ_JOURNAL: Tag = Tag::context(65, true);
    // Servicios de transferencia de ficheros (tags altos, multi-byte).
    pub const FILE_OPEN: Tag = Tag::context(72, true);
    /// fileRead: la **petición** es primitiva (Integer32 = frsmID); la
    /// **respuesta** es constructed (`SEQUENCE { fileData, moreFollows }`).
    pub const FILE_READ: Tag = Tag::context(73, false);
    pub const FILE_READ_RESPONSE: Tag = Tag::context(73, true);
    pub const FILE_CLOSE: Tag = Tag::context(74, false);
    pub const FILE_DIRECTORY: Tag = Tag::context(77, true);
}

/// Tags de contexto del CHOICE `Unconfirmed-Service`.
pub mod unconfirmed_service {
    use crate::ber::tag::Tag;
    pub const INFORMATION_REPORT: Tag = Tag::context(0, true);
}

/// Codifica una `Confirmed-RequestPDU` completa: `[0] { invokeID, <servicio> }`.
///
/// `service` escribe el TLV del servicio (p. ej. `read [4] { ... }`).
pub fn encode_confirmed_request(invoke_id: u32, service: impl FnOnce(&mut BerWriter)) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::CONFIRMED_REQUEST, |w| {
        w.integer(universal::INTEGER, invoke_id as i64);
        service(w);
    });
    w.into_bytes()
}

/// Codifica una `Confirmed-ResponsePDU` completa: `[1] { invokeID, <servicio> }`.
pub fn encode_confirmed_response(invoke_id: u32, service: impl FnOnce(&mut BerWriter)) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::CONFIRMED_RESPONSE, |w| {
        w.integer(universal::INTEGER, invoke_id as i64);
        service(w);
    });
    w.into_bytes()
}

/// Codifica una `Confirmed-ErrorPDU` `[2] { invokeID, <serviceError> }`.
pub fn encode_confirmed_error(
    invoke_id: u32,
    service_error: impl FnOnce(&mut BerWriter),
) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::CONFIRMED_ERROR, |w| {
        w.integer(universal::INTEGER, invoke_id as i64);
        service_error(w);
    });
    w.into_bytes()
}

/// Desenvuelve una `Confirmed-RequestPDU` entrante (inverso de
/// [`parse_confirmed_response`]): devuelve `(invokeID, TLV del servicio)`.
pub fn parse_confirmed_request(pdu: &[u8]) -> Result<(u32, Tlv<'_>), MmsError> {
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv()?;
    if outer.tag != mmspdu::CONFIRMED_REQUEST {
        return Err(MmsError::UnexpectedPdu);
    }
    let mut inner = outer.reader();
    let invoke_id = read_unsigned_integer(&mut inner)?;
    let service = inner.read_tlv()?;
    Ok((invoke_id, service))
}

/// Resultado de desenvolver una respuesta confirmada.
pub struct ConfirmedResponse<'a> {
    pub invoke_id: u32,
    /// TLV del servicio (su tag identifica de qué servicio se trata).
    pub service: Tlv<'a>,
}

/// Desenvuelve un MMS PDU de respuesta. Convierte `confirmed-Error` y `reject`
/// en `Err(MmsError::ServiceReject)`.
pub fn parse_confirmed_response(pdu: &[u8]) -> Result<ConfirmedResponse<'_>, MmsError> {
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv()?;
    match outer.tag {
        t if t == mmspdu::CONFIRMED_RESPONSE => {
            let mut inner = outer.reader();
            let invoke_id = read_unsigned_integer(&mut inner)?;
            let service = inner.read_tlv()?;
            Ok(ConfirmedResponse { invoke_id, service })
        }
        t if t == mmspdu::CONFIRMED_ERROR => Err(MmsError::ServiceReject(format!(
            "confirmed-error: {:02X?}",
            outer.content
        ))),
        t if t == mmspdu::REJECT => Err(MmsError::ServiceReject(format!(
            "reject-PDU: {:02X?}",
            outer.content
        ))),
        _ => Err(MmsError::UnexpectedPdu),
    }
}

/// Clasificación del PDU MMS exterior, para el demultiplexor del cliente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduKind {
    ConfirmedRequest,
    ConfirmedResponse,
    ConfirmedError,
    Reject,
    Unconfirmed,
    InitiateRequest,
    ConcludeRequest,
    Other,
}

/// Clasifica el tag exterior de un PDU MMS entrante en el servidor.
pub fn peek_request_kind(pdu: &[u8]) -> Result<PduKind, MmsError> {
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv()?;
    Ok(match outer.tag {
        t if t == mmspdu::CONFIRMED_REQUEST => PduKind::ConfirmedRequest,
        t if t == mmspdu::INITIATE_REQUEST => PduKind::InitiateRequest,
        t if t == mmspdu::CONCLUDE_REQUEST => PduKind::ConcludeRequest,
        _ => PduKind::Other,
    })
}

/// Inspecciona el tag exterior de un PDU MMS y, cuando aplica, su invokeID.
///
/// La tarea lectora lo usa para enrutar respuestas confirmadas (incluso de
/// error) por invokeID y separar los PDU no solicitados (reportes).
pub fn peek_invoke_and_kind(pdu: &[u8]) -> Result<(PduKind, Option<u32>), MmsError> {
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv()?;
    let kind = match outer.tag {
        t if t == mmspdu::CONFIRMED_RESPONSE => PduKind::ConfirmedResponse,
        t if t == mmspdu::CONFIRMED_ERROR => PduKind::ConfirmedError,
        t if t == mmspdu::REJECT => PduKind::Reject,
        t if t == mmspdu::UNCONFIRMED => return Ok((PduKind::Unconfirmed, None)),
        _ => return Ok((PduKind::Other, None)),
    };
    let mut inner = outer.reader();
    let invoke = match kind {
        // RejectPDU: originalInvokeID [0] IMPLICIT Unsigned32 OPTIONAL.
        PduKind::Reject => match inner.read_if(Tag::context(0, false))? {
            Some(c) => crate::ber::prim::decode_integer(c)
                .ok()
                .and_then(|v| u32::try_from(v).ok()),
            None => None,
        },
        // confirmed-response / confirmed-error: invokeID Unsigned32 (INTEGER universal).
        _ => read_unsigned_integer(&mut inner).ok(),
    };
    Ok((kind, invoke))
}

/// Desenvuelve un `Unconfirmed-PDU` y devuelve el TLV del servicio
/// (p. ej. `informationReport [0]`). Tolera modificadores previos.
pub fn parse_unconfirmed(pdu: &[u8]) -> Result<Tlv<'_>, MmsError> {
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv()?;
    if outer.tag != mmspdu::UNCONFIRMED {
        return Err(MmsError::UnexpectedPdu);
    }
    let mut inner = outer.reader();
    // El primer TLV es el servicio no confirmado (sin modificadores en 8-1).
    inner.read_tlv().map_err(MmsError::from)
}

/// Lee un INTEGER universal y lo interpreta como `u32` (invokeID).
pub fn read_unsigned_integer(r: &mut BerReader<'_>) -> Result<u32, MmsError> {
    let content = r.expect(universal::INTEGER)?;
    let v = crate::ber::prim::decode_integer(content)?;
    u32::try_from(v).map_err(|_| MmsError::Ber(BerError::BadInteger))
}

/// Comprueba que el invokeID de la respuesta coincide con el esperado.
pub fn check_invoke_id(expected: u32, got: u32) -> Result<(), MmsError> {
    if expected == got {
        Ok(())
    } else {
        Err(MmsError::InvokeIdMismatch { expected, got })
    }
}

/// Parsea un `listOfVariable [0]` (SEQUENCE OF VariableSpecification) a la lista
/// de `(domainId, itemId)` domain-specific. Compartido por Read y Write.
pub fn parse_list_of_variable(content: &[u8]) -> Result<Vec<(String, String)>, MmsError> {
    let mut lr = BerReader::new(content);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let seq = lr.read_tlv()?; // SEQUENCE (VariableSpecification wrapper)
        let mut sr = BerReader::new(seq.content);
        let name = sr.expect(Tag::context(0, true))?; // name [0] EXPLICIT
        let mut nr = BerReader::new(name);
        let ds = nr.expect(Tag::context(1, true))?; // domain-specific [1] { domainId, itemId }
        let mut dr = BerReader::new(ds);
        let domain =
            crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?
                .to_string();
        let item = crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?
            .to_string();
        out.push((domain, item));
    }
    Ok(out)
}

/// Verifica que un TLV de servicio tiene el tag esperado.
pub fn expect_service<'a>(service: &Tlv<'a>, tag: Tag) -> Result<&'a [u8], MmsError> {
    if service.tag != tag {
        return Err(MmsError::UnexpectedPdu);
    }
    Ok(service.content)
}
