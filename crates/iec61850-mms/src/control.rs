//! Modelo de control IEC 61850-7-2 sobre MMS: construcción de la estructura
//! `Oper`/`SBOw` y categorías de origen.
//!
//! Soporta **direct-with-normal-security** (escribir `Oper`) y
//! **sbo-with-normal-security** (leer `SBO` para seleccionar, luego escribir
//! `Oper`). Los métodos asíncronos del cliente están en
//! [`crate::client::MmsClient`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ber::prim::BitString;
use crate::mms::data::{MmsData, UtcTime};

/// Categoría del originador del control (`orCat`, IEC 61850-7-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrCat {
    NotSupported = 0,
    BayControl = 1,
    StationControl = 2,
    RemoteControl = 3,
    AutomaticBay = 4,
    AutomaticStation = 5,
    AutomaticRemote = 6,
    Maintenance = 7,
    Process = 8,
}

/// Parámetros del servicio de control (origen, número de control, test, checks).
#[derive(Debug, Clone)]
pub struct ControlParameters {
    pub orig_category: OrCat,
    pub orig_ident: Vec<u8>,
    pub ctl_num: u8,
    pub test: bool,
    /// `[interlock-check, synchro-check]`.
    pub check: [bool; 2],
    /// Tiempo máximo de espera entre `select` y `operate`.
    pub select_timeout: Duration,
}

impl Default for ControlParameters {
    fn default() -> Self {
        Self {
            orig_category: OrCat::BayControl,
            orig_ident: b"iec61850-rs".to_vec(),
            ctl_num: 0,
            test: false,
            check: [false, false],
            select_timeout: Duration::from_secs(5),
        }
    }
}

/// Marca de tiempo UTC actual en formato MMS (4 s epoch + 3 fracción + 1 calidad).
pub fn now_utc() -> UtcTime {
    let mut raw = [0u8; 8];
    if let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) {
        raw[0..4].copy_from_slice(&(d.as_secs() as u32).to_be_bytes());
        // fracción de segundo en 24 bits (frac * 2^24)
        let frac = ((d.subsec_nanos() as u64) << 24) / 1_000_000_000;
        let fb = (frac as u32).to_be_bytes();
        raw[4..7].copy_from_slice(&fb[1..4]);
    }
    raw[7] = 0x0A; // calidad: 10 bits de precisión de fracción
    UtcTime { raw }
}

/// Construye la estructura `Oper`/`SBOw` (orden de campos CRÍTICO):
/// `{ ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }`.
pub fn build_oper(ctl_val: MmsData, params: &ControlParameters, t: UtcTime) -> MmsData {
    MmsData::Structure(vec![
        ctl_val,
        MmsData::Structure(vec![
            MmsData::Int(params.orig_category as i64),
            MmsData::Octets(params.orig_ident.clone()),
        ]),
        MmsData::Uint(params.ctl_num as u64),
        MmsData::Utc(t),
        MmsData::Bool(params.test),
        MmsData::BitString(BitString::from_bits(&params.check)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oper_field_order() {
        let t = UtcTime { raw: [0; 8] };
        let oper = build_oper(MmsData::Bool(true), &ControlParameters::default(), t);
        let MmsData::Structure(fields) = &oper else {
            panic!("Oper debe ser Structure")
        };
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], MmsData::Bool(true)); // ctlVal
        // origin = Structure { orCat, orIdent }
        let MmsData::Structure(origin) = &fields[1] else {
            panic!("origin Structure")
        };
        assert_eq!(origin[0], MmsData::Int(OrCat::BayControl as i64));
        assert_eq!(origin[1], MmsData::Octets(b"iec61850-rs".to_vec()));
        assert_eq!(fields[2], MmsData::Uint(0)); // ctlNum
        assert_eq!(fields[3], MmsData::Utc(t)); // T
        assert_eq!(fields[4], MmsData::Bool(false)); // Test
        assert!(matches!(fields[5], MmsData::BitString(_))); // Check
    }

    #[test]
    fn oper_encodes_as_structure_tag() {
        let oper = build_oper(MmsData::Int(1), &ControlParameters::default(), now_utc());
        let mut w = crate::ber::writer::BerWriter::new();
        oper.encode(&mut w);
        // tag de estructura Data = [contexto 2 constructed] = 0xA2
        assert_eq!(w.into_bytes()[0], 0xA2);
    }
}
