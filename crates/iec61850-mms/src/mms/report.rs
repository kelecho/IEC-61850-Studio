//! Reportes IEC 61850 (InformationReport no solicitado) y configuración de RCB.
//!
//! La decodificación está **guiada por OptFlds** y es de mejor esfuerzo: el
//! orden de los campos opcionales sigue IEC 61850-8-1, pero sin conocer la
//! composición del dataset no se puede mapear cada valor a su referencia
//! (`ReportEntry::reference` queda `None`). El campo `raw` conserva todos los
//! `AccessResult` por si hace falta reinterpretar.

use iec61850_model::ObjectReference;

use crate::ber::prim::BitString;
use crate::ber::reader::{BerReader, Tlv};
use crate::error::MmsError;
use crate::mms::data::MmsData;

/// Bits de `OptFlds` (IEC 61850-8-1) que indican qué campos opcionales trae el
/// reporte.
pub mod opt_flds {
    pub const SEQUENCE_NUMBER: usize = 1;
    pub const REPORT_TIMESTAMP: usize = 2;
    pub const REASON_FOR_INCLUSION: usize = 3;
    pub const DATA_SET_NAME: usize = 4;
    pub const DATA_REFERENCE: usize = 5;
    pub const BUFFER_OVERFLOW: usize = 6;
    pub const ENTRY_ID: usize = 7;
    pub const CONF_REVISION: usize = 8;
    pub const SEGMENTATION: usize = 9;
}

/// Configuración a aplicar a un RCB antes de habilitarlo. Cada campo `Some`
/// se escribe como atributo del RCB; los `None` se dejan como estén.
#[derive(Debug, Clone, Default)]
pub struct ReportConfig {
    pub dataset: Option<String>,
    pub trg_ops: Option<BitString>,
    pub opt_flds: Option<BitString>,
    pub integrity_period: Option<u32>,
    pub buf_time: Option<u32>,
    /// Si `true`, solicita una interrogación general (`GI`) tras habilitar.
    pub general_interrogation: bool,
}

/// Un miembro incluido en el reporte.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportEntry {
    /// Índice del miembro dentro del dataset (según el bit puesto en `inclusion`).
    pub member_index: usize,
    pub value: MmsData,
    /// Motivo de inclusión (si `OptFlds.reason-for-inclusion`).
    pub reason: Option<BitString>,
    /// Referencia del dato (best-effort, normalmente `None`).
    pub reference: Option<ObjectReference>,
}

/// Un reporte decodificado de un InformationReport.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub rpt_id: String,
    pub opt_flds: BitString,
    pub seq_num: Option<u64>,
    pub time_of_entry: Option<MmsData>,
    pub dataset: Option<String>,
    pub buffer_overflow: Option<bool>,
    pub entry_id: Option<Vec<u8>>,
    pub conf_rev: Option<u64>,
    pub sub_seq_num: Option<u64>,
    pub more_segments: Option<bool>,
    pub inclusion: Option<BitString>,
    pub entries: Vec<ReportEntry>,
    /// Todos los `AccessResult` crudos, en orden, por si la heurística no encaja.
    pub raw: Vec<MmsData>,
}

/// Datos para codificar un InformationReport (lado servidor).
pub struct ReportData<'a> {
    pub rpt_id: &'a str,
    pub opt_flds: &'a BitString,
    pub seq_num: u32,
    pub dataset: Option<&'a str>,
    pub conf_rev: u32,
    pub time_of_entry: Option<crate::mms::data::UtcTime>,
    /// Indicador de desbordamiento del buffer (BRCB, `OptFlds.buffer-overflow`).
    pub buf_ovfl: bool,
    /// EntryID del reporte (BRCB, `OptFlds.entry-id`); 8 octetos big-endian.
    pub entry_id: Option<&'a [u8]>,
    /// Bit por cada miembro del dataset incluido en este reporte.
    pub inclusion: &'a BitString,
    /// Valores de los miembros incluidos (en el orden de los bits a 1).
    pub values: &'a [MmsData],
    /// Motivo de inclusión por miembro (si `OptFlds.reason-for-inclusion`).
    pub reasons: Option<&'a [BitString]>,
}

/// Codifica un `unconfirmed-PDU [3] { informationReport [0] { ... } }`
/// byte-consistente con [`decode_information_report`]. Sólo emite los campos
/// cuyos bits están activos en `opt_flds` (el orden sigue IEC 61850-8-1).
pub fn encode_information_report(data: &ReportData<'_>) -> Vec<u8> {
    use crate::ber::tag::Tag;
    use crate::ber::writer::BerWriter;
    use crate::mms::pdu::mmspdu::UNCONFIRMED;
    use crate::mms::pdu::unconfirmed_service::INFORMATION_REPORT;

    let o = data.opt_flds;
    let mut w = BerWriter::new();
    w.tlv(UNCONFIRMED, |w| {
        w.tlv(INFORMATION_REPORT, |w| {
            // listOfAccessResult [0] SEQUENCE OF AccessResult (Data success)
            w.tlv(Tag::context(0, true), |w| {
                MmsData::Visible(data.rpt_id.to_string()).encode(w);
                MmsData::BitString(o.clone()).encode(w);
                if o.bit(opt_flds::SEQUENCE_NUMBER) {
                    MmsData::Uint(data.seq_num as u64).encode(w);
                }
                if o.bit(opt_flds::REPORT_TIMESTAMP) {
                    MmsData::Utc(
                        data.time_of_entry
                            .unwrap_or(crate::mms::data::UtcTime { raw: [0; 8] }),
                    )
                    .encode(w);
                }
                if o.bit(opt_flds::DATA_SET_NAME) {
                    MmsData::Visible(data.dataset.unwrap_or("").to_string()).encode(w);
                }
                if o.bit(opt_flds::BUFFER_OVERFLOW) {
                    MmsData::Bool(data.buf_ovfl).encode(w);
                }
                if o.bit(opt_flds::ENTRY_ID) {
                    MmsData::Octets(data.entry_id.unwrap_or(&[]).to_vec()).encode(w);
                }
                if o.bit(opt_flds::CONF_REVISION) {
                    MmsData::Uint(data.conf_rev as u64).encode(w);
                }
                // inclusion-bitstring (siempre)
                MmsData::BitString(data.inclusion.clone()).encode(w);
                // valores de los miembros incluidos
                for v in data.values {
                    v.encode(w);
                }
                // reason-for-inclusion (uno por miembro) si procede
                if o.bit(opt_flds::REASON_FOR_INCLUSION) {
                    if let Some(reasons) = data.reasons {
                        for r in reasons {
                            MmsData::BitString(r.clone()).encode(w);
                        }
                    }
                }
            });
        });
    });
    w.into_bytes()
}

/// CommandTermination (control de seguridad reforzada, IEC 61850-7-2): mensaje
/// no solicitado que confirma el resultado final de un `Oper`/`Cancel`.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandTermination {
    pub domain: String,
    /// itemId del objeto de control, p. ej. `"GGIO1$CO$SPCSO2$Oper"`.
    pub object_item: String,
    /// `true` = positiva (comando completado), `false` = negativa.
    pub positive: bool,
    /// AddCause (sólo en la negativa).
    pub add_cause: Option<i64>,
}

/// Codifica una CommandTermination como `unconfirmed-PDU [3] { informationReport
/// [0] { variableAccessSpecification(listOfVariable con el Oper), listOfAccessResult } }`.
/// La positiva lleva la estructura `oper` reflejada; la negativa, el AddCause.
pub fn encode_command_termination(
    domain: &str,
    object_item: &str,
    oper: &MmsData,
    positive: bool,
    add_cause: i64,
) -> Vec<u8> {
    use crate::ber::tag::{Tag, universal};
    use crate::ber::writer::BerWriter;
    use crate::mms::pdu::mmspdu::UNCONFIRMED;
    use crate::mms::pdu::unconfirmed_service::INFORMATION_REPORT;

    let mut w = BerWriter::new();
    w.tlv(UNCONFIRMED, |w| {
        w.tlv(INFORMATION_REPORT, |w| {
            // variableAccessSpecification: listOfVariable [0] → name [0] → domain-specific [1]
            w.tlv(Tag::context(0, true), |w| {
                w.sequence(|w| {
                    w.tlv(Tag::context(0, true), |w| {
                        w.tlv(Tag::context(1, true), |w| {
                            w.visible_string(universal::VISIBLE_STRING, domain);
                            w.visible_string(universal::VISIBLE_STRING, object_item);
                        });
                    });
                });
            });
            // listOfAccessResult [0]
            w.tlv(Tag::context(0, true), |w| {
                if positive {
                    oper.encode(w);
                } else {
                    // failure [0] = AddCause
                    w.integer(Tag::context(0, false), add_cause);
                }
            });
        });
    });
    w.into_bytes()
}

/// Intenta interpretar un `informationReport [0]` como CommandTermination.
/// Devuelve `None` si es un reporte RCB normal (sin variableAccessSpecification
/// o cuyo objeto no es un control `$Oper`/`$Cancel`).
pub fn parse_command_termination(service_tlv: &Tlv<'_>) -> Option<CommandTermination> {
    use crate::ber::tag::Tag;
    use crate::mms::pdu::unconfirmed_service::INFORMATION_REPORT;
    if service_tlv.tag != INFORMATION_REPORT {
        return None;
    }
    let mut r = BerReader::new(service_tlv.content);
    let first = r.read_tlv().ok()?;
    if r.is_empty() {
        return None; // reporte RCB (sólo listOfAccessResult)
    }
    let results = r.read_tlv().ok()?;
    let (domain, object_item) = crate::mms::pdu::parse_list_of_variable(first.content)
        .ok()?
        .into_iter()
        .next()?;
    if !(object_item.ends_with("$Oper") || object_item.ends_with("$Cancel")) {
        return None;
    }
    let mut ar = BerReader::new(results.content);
    let res = ar.read_tlv().ok()?;
    let (positive, add_cause) = if res.tag == Tag::context(0, false) {
        (false, crate::ber::prim::decode_integer(res.content).ok())
    } else {
        (true, None)
    };
    Some(CommandTermination {
        domain,
        object_item,
        positive,
        add_cause,
    })
}

/// Decodifica un `Information-Report` desde el TLV del servicio
/// (`informationReport [0]`).
pub fn decode_information_report(service_tlv: &Tlv<'_>) -> Result<Report, MmsError> {
    use crate::mms::pdu::unconfirmed_service::INFORMATION_REPORT;
    if service_tlv.tag != INFORMATION_REPORT {
        return Err(MmsError::UnexpectedPdu);
    }

    // Information-Report ::= SEQUENCE { variableAccessSpecification, listOfAccessResult [0] }
    let mut r = BerReader::new(service_tlv.content);
    let first = r.read_tlv()?;
    let (access_spec, results) = if r.is_empty() {
        (None, first)
    } else {
        (Some(first), r.read_tlv()?)
    };

    let dataset = access_spec.and_then(dataset_from_access_spec);

    // listOfAccessResult: secuencia de AccessResult.
    let mut ar = BerReader::new(results.content);
    let mut values = Vec::new();
    while !ar.is_empty() {
        let tlv = ar.read_tlv()?;
        if tlv.tag == crate::ber::tag::Tag::context(0, false) {
            // failure → lo representamos como un dato vacío para no desalinear.
            continue;
        }
        values.push(MmsData::decode(&tlv)?);
    }

    interpret(values, dataset)
}

/// Extrae el nombre del dataset/RCB de `variableListName [1]` si está presente.
fn dataset_from_access_spec(tlv: Tlv<'_>) -> Option<String> {
    use crate::ber::tag::{Tag, universal};
    // variableListName [1] → ObjectName CHOICE
    if tlv.tag != Tag::context(1, true) {
        return None;
    }
    let mut r = BerReader::new(tlv.content);
    let name = r.read_tlv().ok()?;
    match name.tag {
        // domain-specific [1] { domainId, itemId }
        t if t == Tag::context(1, true) => {
            let mut dr = BerReader::new(name.content);
            let domain = dr.expect(universal::VISIBLE_STRING).ok()?;
            let item = dr.expect(universal::VISIBLE_STRING).ok()?;
            Some(format!(
                "{}/{}",
                std::str::from_utf8(domain).ok()?,
                std::str::from_utf8(item).ok()?
            ))
        }
        // vmd-specific [0] / aa-specific [2]
        _ => std::str::from_utf8(name.content).ok().map(str::to_string),
    }
}

fn take(values: &[MmsData], idx: &mut usize) -> Option<MmsData> {
    let v = values.get(*idx).cloned();
    *idx += 1;
    v
}

/// Toma el siguiente valor sólo si `present`; si no, no avanza.
fn opt_take(values: &[MmsData], idx: &mut usize, present: bool) -> Option<MmsData> {
    if present { take(values, idx) } else { None }
}

fn interpret(values: Vec<MmsData>, dataset_from_spec: Option<String>) -> Result<Report, MmsError> {
    let mut idx = 0usize;

    let rpt_id = match take(&values, &mut idx) {
        Some(MmsData::Visible(s)) | Some(MmsData::MmsString(s)) => s,
        _ => return Err(MmsError::UnexpectedPdu),
    };
    let opt_flds = match take(&values, &mut idx) {
        Some(MmsData::BitString(b)) => b,
        _ => return Err(MmsError::UnexpectedPdu),
    };
    let data_reference = opt_flds.bit(opt_flds::DATA_REFERENCE);
    let reason_for_inclusion = opt_flds.bit(opt_flds::REASON_FOR_INCLUSION);

    let seq_num =
        opt_take(&values, &mut idx, opt_flds.bit(opt_flds::SEQUENCE_NUMBER)).and_then(as_u64);
    let time_of_entry = opt_take(&values, &mut idx, opt_flds.bit(opt_flds::REPORT_TIMESTAMP));
    let dataset = if opt_flds.bit(opt_flds::DATA_SET_NAME) {
        take(&values, &mut idx).and_then(as_string)
    } else {
        dataset_from_spec
    };
    let buffer_overflow =
        opt_take(&values, &mut idx, opt_flds.bit(opt_flds::BUFFER_OVERFLOW)).and_then(as_bool);
    let entry_id =
        opt_take(&values, &mut idx, opt_flds.bit(opt_flds::ENTRY_ID)).and_then(as_octets);
    let conf_rev =
        opt_take(&values, &mut idx, opt_flds.bit(opt_flds::CONF_REVISION)).and_then(as_u64);
    let (sub_seq_num, more_segments) = if opt_flds.bit(opt_flds::SEGMENTATION) {
        (
            take(&values, &mut idx).and_then(as_u64),
            take(&values, &mut idx).and_then(as_bool),
        )
    } else {
        (None, None)
    };

    let inclusion = match take(&values, &mut idx) {
        Some(MmsData::BitString(b)) => b,
        _ => {
            // sin inclusion-bitstring no podemos mapear miembros; devolvemos lo crudo.
            return Ok(Report {
                rpt_id,
                opt_flds,
                seq_num,
                time_of_entry,
                dataset,
                buffer_overflow,
                entry_id,
                conf_rev,
                sub_seq_num,
                more_segments,
                inclusion: None,
                entries: Vec::new(),
                raw: values,
            });
        }
    };

    let included: Vec<usize> = (0..inclusion.len_bits())
        .filter(|&i| inclusion.bit(i))
        .collect();
    let n = included.len();

    // data-reference (best-effort): N referencias antes de los valores.
    let mut references: Vec<Option<ObjectReference>> = vec![None; n];
    if data_reference {
        for slot in references.iter_mut() {
            *slot = take(&values, &mut idx)
                .and_then(as_string)
                .and_then(|s| s.parse().ok());
        }
    }

    // N valores.
    let mut entry_values = Vec::with_capacity(n);
    for _ in 0..n {
        match take(&values, &mut idx) {
            Some(v) => entry_values.push(v),
            None => break,
        }
    }

    // reason-for-inclusion (opcional): N bitstrings.
    let mut reasons: Vec<Option<BitString>> = vec![None; n];
    if reason_for_inclusion {
        for slot in reasons.iter_mut() {
            if let Some(MmsData::BitString(b)) = take(&values, &mut idx) {
                *slot = Some(b);
            }
        }
    }

    let entries = included
        .iter()
        .enumerate()
        .take(entry_values.len())
        .map(|(k, &member_index)| ReportEntry {
            member_index,
            value: entry_values[k].clone(),
            reason: reasons.get(k).cloned().flatten(),
            reference: references.get(k).cloned().flatten(),
        })
        .collect();

    Ok(Report {
        rpt_id,
        opt_flds,
        seq_num,
        time_of_entry,
        dataset,
        buffer_overflow,
        entry_id,
        conf_rev,
        sub_seq_num,
        more_segments,
        inclusion: Some(inclusion),
        entries,
        raw: values,
    })
}

fn as_u64(v: MmsData) -> Option<u64> {
    match v {
        MmsData::Uint(u) => Some(u),
        MmsData::Int(i) => u64::try_from(i).ok(),
        _ => None,
    }
}
fn as_bool(v: MmsData) -> Option<bool> {
    match v {
        MmsData::Bool(b) => Some(b),
        _ => None,
    }
}
fn as_string(v: MmsData) -> Option<String> {
    match v {
        MmsData::Visible(s) | MmsData::MmsString(s) => Some(s),
        _ => None,
    }
}
fn as_octets(v: MmsData) -> Option<Vec<u8>> {
    match v {
        MmsData::Octets(o) => Some(o),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::Tag;
    use crate::ber::writer::BerWriter;

    /// Construye un informationReport [0] con RptID, OptFlds, inclusion y valores.
    fn build_report(
        rpt_id: &str,
        opt_bits: &[usize],
        inclusion: &[bool],
        values: &[MmsData],
    ) -> Vec<u8> {
        let mut opt = [false; 10];
        for &b in opt_bits {
            opt[b] = true;
        }
        let mut w = BerWriter::new();
        w.tlv(Tag::context(0, true), |w| {
            // listOfAccessResult [0]
            w.tlv(Tag::context(0, true), |w| {
                MmsData::Visible(rpt_id.into()).encode(w);
                MmsData::BitString(BitString::from_bits(&opt)).encode(w);
                MmsData::BitString(BitString::from_bits(inclusion)).encode(w);
                for v in values {
                    v.encode(w);
                }
            });
        });
        w.into_bytes()
    }

    #[test]
    fn encoder_round_trip() {
        // El reporte que emite el servidor debe decodificarlo el cliente.
        let opt = {
            let mut b = [false; 10];
            b[opt_flds::SEQUENCE_NUMBER] = true;
            b[opt_flds::DATA_SET_NAME] = true;
            b[opt_flds::CONF_REVISION] = true;
            BitString::from_bits(&b)
        };
        let inclusion = BitString::from_bits(&[true, false, true]);
        let values = [MmsData::Float(1.5), MmsData::Bool(true)];
        let bytes = encode_information_report(&ReportData {
            rpt_id: "IED1LD0/LLN0.rcb1",
            opt_flds: &opt,
            seq_num: 7,
            dataset: Some("ds1"),
            conf_rev: 1,
            time_of_entry: None,
            buf_ovfl: false,
            entry_id: None,
            inclusion: &inclusion,
            values: &values,
            reasons: None,
        });

        let svc = crate::mms::pdu::parse_unconfirmed(&bytes).unwrap();
        let report = decode_information_report(&svc).unwrap();
        assert_eq!(report.rpt_id, "IED1LD0/LLN0.rcb1");
        assert_eq!(report.seq_num, Some(7));
        assert_eq!(report.dataset.as_deref(), Some("ds1"));
        assert_eq!(report.conf_rev, Some(1));
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].member_index, 0);
        assert_eq!(report.entries[0].value, MmsData::Float(1.5));
        assert_eq!(report.entries[1].member_index, 2);
        assert_eq!(report.entries[1].value, MmsData::Bool(true));
    }

    #[test]
    fn encoder_buffered_round_trip() {
        // Reporte de un BRCB: lleva entryID y buffer-overflow.
        let opt = {
            let mut b = [false; 10];
            b[opt_flds::SEQUENCE_NUMBER] = true;
            b[opt_flds::DATA_SET_NAME] = true;
            b[opt_flds::BUFFER_OVERFLOW] = true;
            b[opt_flds::ENTRY_ID] = true;
            BitString::from_bits(&b)
        };
        let inclusion = BitString::from_bits(&[true]);
        let values = [MmsData::Int(42)];
        let entry_id = 5u64.to_be_bytes();
        let bytes = encode_information_report(&ReportData {
            rpt_id: "IED1LD0/LLN0.brcb1",
            opt_flds: &opt,
            seq_num: 3,
            dataset: Some("ds1"),
            conf_rev: 1,
            time_of_entry: None,
            buf_ovfl: true,
            entry_id: Some(&entry_id),
            inclusion: &inclusion,
            values: &values,
            reasons: None,
        });

        let svc = crate::mms::pdu::parse_unconfirmed(&bytes).unwrap();
        let report = decode_information_report(&svc).unwrap();
        assert_eq!(report.seq_num, Some(3));
        assert_eq!(report.buffer_overflow, Some(true));
        assert_eq!(report.entry_id.as_deref(), Some(&5u64.to_be_bytes()[..]));
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].value, MmsData::Int(42));
    }

    #[test]
    fn command_termination_round_trip() {
        let oper = MmsData::Structure(vec![MmsData::Bool(true), MmsData::Uint(1)]);
        // Positiva.
        let bytes = encode_command_termination("IED1LD0", "GGIO1$CO$SPCSO2$Oper", &oper, true, 0);
        let svc = crate::mms::pdu::parse_unconfirmed(&bytes).unwrap();
        let ct = parse_command_termination(&svc).expect("es CommandTermination");
        assert_eq!(ct.domain, "IED1LD0");
        assert_eq!(ct.object_item, "GGIO1$CO$SPCSO2$Oper");
        assert!(ct.positive);
        assert_eq!(ct.add_cause, None);

        // Negativa con AddCause.
        let bytes = encode_command_termination("IED1LD0", "GGIO1$CO$SPCSO2$Oper", &oper, false, 1);
        let svc = crate::mms::pdu::parse_unconfirmed(&bytes).unwrap();
        let ct = parse_command_termination(&svc).unwrap();
        assert!(!ct.positive);
        assert_eq!(ct.add_cause, Some(1));

        // Un reporte RCB normal NO es CommandTermination.
        let opt = BitString::from_bits(&[false; 10]);
        let inclusion = BitString::from_bits(&[true]);
        let rcb_bytes = encode_information_report(&ReportData {
            rpt_id: "x",
            opt_flds: &opt,
            seq_num: 0,
            dataset: None,
            conf_rev: 0,
            time_of_entry: None,
            buf_ovfl: false,
            entry_id: None,
            inclusion: &inclusion,
            values: &[MmsData::Int(1)],
            reasons: None,
        });
        let svc = crate::mms::pdu::parse_unconfirmed(&rcb_bytes).unwrap();
        assert!(parse_command_termination(&svc).is_none());
    }

    #[test]
    fn minimal_report() {
        let bytes = build_report(
            "rpt1",
            &[],
            &[true, false, true],
            &[MmsData::Int(7), MmsData::Bool(true)],
        );
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let report = decode_information_report(&tlv).unwrap();
        assert_eq!(report.rpt_id, "rpt1");
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].member_index, 0);
        assert_eq!(report.entries[0].value, MmsData::Int(7));
        assert_eq!(report.entries[1].member_index, 2); // tercer bit
        assert_eq!(report.entries[1].value, MmsData::Bool(true));
    }

    #[test]
    fn report_with_seq_num() {
        // OptFlds con sequence-number → un SqNum entre OptFlds e inclusion
        let mut w = BerWriter::new();
        let mut opt = [false; 10];
        opt[opt_flds::SEQUENCE_NUMBER] = true;
        w.tlv(Tag::context(0, true), |w| {
            w.tlv(Tag::context(0, true), |w| {
                MmsData::Visible("r".into()).encode(w);
                MmsData::BitString(BitString::from_bits(&opt)).encode(w);
                MmsData::Uint(42).encode(w); // SqNum
                MmsData::BitString(BitString::from_bits(&[true])).encode(w);
                MmsData::Int(9).encode(w);
            });
        });
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let tlv = r.read_tlv().unwrap();
        let report = decode_information_report(&tlv).unwrap();
        assert_eq!(report.seq_num, Some(42));
        assert_eq!(report.entries[0].value, MmsData::Int(9));
    }
}
