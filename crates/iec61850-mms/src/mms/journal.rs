//! Servicio MMS `ReadJournal` `[65]` (logs, ISO 9506 / IEC 61850-8-1): lee las
//! entradas persistidas de un `Log`.
//!
//! Cada entrada del journal lleva un `entryID` (octetos), su instante de
//! ocurrencia (`BinaryTime`) y, opcionalmente, los valores registrados. El
//! nombre del journal es un `ObjectName` domain-specific (`domainId`/`itemId`,
//! p. ej. `simpleIOGenericIO` / `LLN0$EventLog`).

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::{Tag, universal};
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::data::MmsData;
use crate::mms::pdu::{self, service};

/// Una entrada de un journal (log) de IEC 61850.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalEntry {
    /// Identificador de la entrada (octetos monótonos).
    pub entry_id: Vec<u8>,
    /// Instante de ocurrencia (`BinaryTime`, 6 octetos).
    pub occurrence_time: Vec<u8>,
    /// Valores registrados en la entrada (vacío si solo es un marcador).
    pub values: Vec<MmsData>,
}

/// Escribe una petición `ReadJournal` de todas las entradas de un journal desde
/// el inicio del tiempo (`rangeStartSpecification` con instante cero).
///
/// Un `rangeStartSpecification` es obligatorio en la práctica: libiec61850
/// rechaza (`invalid-argument`) un ReadJournal que solo lleva el `journalName`.
pub fn write_request(w: &mut BerWriter, domain: &str, item: &str) {
    w.tlv(service::READ_JOURNAL, |w| {
        // journalName [0] → domain-specific [1] { domainId, itemId }
        w.tlv(Tag::context(0, true), |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.visible_string(universal::VISIBLE_STRING, domain);
                w.visible_string(universal::VISIBLE_STRING, item);
            });
        });
        // El servidor exige un rango completo: rangeStart [1] + rangeStop [2]
        // (o entryToStartAfter). Usamos [0, máx] → todas las entradas.
        // timeSpecification [0] IMPLICIT BinaryTime (6 octetos).
        w.tlv(Tag::context(1, true), |w| {
            w.octet_string(Tag::context(0, false), &[0u8; 6]);
        });
        w.tlv(Tag::context(2, true), |w| {
            w.octet_string(Tag::context(0, false), &[0xffu8; 6]);
        });
    });
}

/// Decodifica una petición `ReadJournal` (lado servidor) → `(domain, item)` del
/// journal. Ignora las especificaciones de rango (start/stop) si están presentes.
pub fn decode_request(service_tlv: &Tlv<'_>) -> Result<(String, String), MmsError> {
    let content = pdu::expect_service(service_tlv, service::READ_JOURNAL)?;
    let mut r = BerReader::new(content);
    let name = r.expect(Tag::context(0, true))?; // journalName [0]
    let mut nr = BerReader::new(name);
    let ds = nr.expect(Tag::context(1, true))?; // domain-specific [1]
    let mut dr = BerReader::new(ds);
    let domain =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    let item =
        crate::ber::prim::decode_visible_string(dr.expect(universal::VISIBLE_STRING)?)?.to_string();
    Ok((domain, item))
}

/// Codifica la respuesta `ReadJournal` con la lista de entradas.
///
/// Estructura (verificada contra libiec61850): `listOfJournalEntry [0]` con una
/// `SEQUENCE` por entrada `{ entryID [0], entryContent [2] { occurenceTime [0],
/// journalVariables [2]? } }`, y `moreFollows [1]`.
pub fn encode_response(w: &mut BerWriter, entries: &[JournalEntry], more_follows: bool) {
    w.tlv(service::READ_JOURNAL, |w| {
        w.tlv(Tag::context(0, true), |w| {
            for e in entries {
                w.sequence(|w| {
                    // entryID [0] IMPLICIT OCTET STRING
                    w.octet_string(Tag::context(0, false), &e.entry_id);
                    // entryContent [2]
                    w.tlv(Tag::context(2, true), |w| {
                        // occurenceTime [0] IMPLICIT BinaryTime
                        w.octet_string(Tag::context(0, false), &e.occurrence_time);
                        // journalVariables [2] SEQUENCE OF { variableTag, valueSpec }
                        if !e.values.is_empty() {
                            w.tlv(Tag::context(2, true), |w| {
                                for v in &e.values {
                                    w.sequence(|w| {
                                        // variableTag [0] VisibleString
                                        w.visible_string(Tag::context(0, false), "");
                                        // valueSpecification [1] { Data }
                                        w.tlv(Tag::context(1, true), |w| v.encode(w));
                                    });
                                }
                            });
                        }
                    });
                });
            }
        });
        // moreFollows [1] IMPLICIT BOOLEAN
        w.boolean(Tag::context(1, false), more_follows);
    });
}

/// Decodifica la respuesta `ReadJournal` → `(entradas, moreFollows)`.
pub fn decode_response(service_tlv: &Tlv<'_>) -> Result<(Vec<JournalEntry>, bool), MmsError> {
    let content = pdu::expect_service(service_tlv, service::READ_JOURNAL)?;
    let mut r = BerReader::new(content);
    let list = r.expect(Tag::context(0, true))?; // listOfJournalEntry [0]
    let mut lr = BerReader::new(list);
    let mut entries = Vec::new();
    while !lr.is_empty() {
        let je = lr.read_tlv()?; // JournalEntry SEQUENCE
        entries.push(decode_entry(je.content)?);
    }
    let more_follows = match r.read_if(Tag::context(1, false))? {
        Some(c) => crate::ber::prim::decode_bool(c)?,
        None => false,
    };
    Ok((entries, more_follows))
}

fn decode_entry(content: &[u8]) -> Result<JournalEntry, MmsError> {
    let mut r = BerReader::new(content);
    let entry_id = r.expect(Tag::context(0, false))?.to_vec(); // entryID [0]
    let mut occurrence_time = Vec::new();
    let mut values = Vec::new();
    // entryContent [2] (originatingApplication [1] opcional, ignorado).
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        if tlv.tag == Tag::context(2, true) {
            let mut cr = BerReader::new(tlv.content);
            while !cr.is_empty() {
                let inner = cr.read_tlv()?;
                if inner.tag == Tag::context(0, false) {
                    occurrence_time = inner.content.to_vec(); // occurenceTime [0]
                } else if inner.tag == Tag::context(2, true) {
                    // journalVariables [2]: SEQUENCE OF { variableTag, valueSpec }
                    let mut vr = BerReader::new(inner.content);
                    while !vr.is_empty() {
                        let vseq = vr.read_tlv()?;
                        let mut sr = BerReader::new(vseq.content);
                        // variableTag [0] (ignorado), valueSpecification [1] { Data }
                        while !sr.is_empty() {
                            let f = sr.read_tlv()?;
                            if f.tag == Tag::context(1, true) {
                                let mut dr = BerReader::new(f.content);
                                if let Ok(d) = dr.read_tlv() {
                                    if let Ok(v) = MmsData::decode(&d) {
                                        values.push(v);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(JournalEntry {
        entry_id,
        occurrence_time,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trip() {
        let entries = vec![
            JournalEntry {
                entry_id: vec![0, 0, 0, 0, 0, 0, 0, 1],
                occurrence_time: vec![0, 0x8c, 0xb5, 0x02, 0x3c, 0xb1],
                values: vec![MmsData::Bool(true)],
            },
            JournalEntry {
                entry_id: vec![0, 0, 0, 0, 0, 0, 0, 2],
                occurrence_time: vec![0, 0x8c, 0xb5, 0x02, 0x3c, 0xb2],
                values: vec![],
            },
        ];
        let mut w = BerWriter::new();
        encode_response(&mut w, &entries, false);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        let (got, more) = decode_response(&svc).unwrap();
        assert!(!more);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].entry_id, vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(got[0].occurrence_time.len(), 6);
        assert_eq!(got[0].values, vec![MmsData::Bool(true)]);
        assert_eq!(got[1].entry_id, vec![0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(got[1].values.is_empty());
    }

    #[test]
    fn request_round_trip() {
        let mut w = BerWriter::new();
        write_request(&mut w, "simpleIOGenericIO", "LLN0$EventLog");
        let bytes = w.into_bytes();
        // El tag de servicio es [65] constructed (multi-byte bf 41).
        assert_eq!(&bytes[..2], &[0xbf, 0x41]);
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(
            decode_request(&svc).unwrap(),
            ("simpleIOGenericIO".to_string(), "LLN0$EventLog".to_string())
        );
    }
}
