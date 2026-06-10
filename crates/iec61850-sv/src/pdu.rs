//! El `savPdu` y los `ASDU` de Sampled Values (IEC 61850-9-2), reutilizando el
//! codec BER de [`iec61850_ber`].
//!
//! Nota byte-exacta: `smpCnt`/`confRev`/`smpRate`/`smpMod` se codifican como
//! **OCTET STRING de ancho fijo** (no INTEGER), igual que `refrTm` (8 octetos) y
//! `smpSynch` (1 octeto).

use iec61850_ber::ber::prim;
use iec61850_ber::{BerReader, BerWriter, Tag, UtcTime};

use crate::error::SvError;
use crate::nine_two_le::NineTwoLe;

/// `savPdu [APPLICATION 0]` IMPLICIT SEQUENCE → tag `0x60`.
const SAV_PDU: Tag = Tag::application(0, true);

mod sv_tags {
    use iec61850_ber::Tag;
    pub const NO_ASDU: Tag = Tag::context(0, false);
    pub const SECURITY: Tag = Tag::context(1, true);
    pub const SEQ_ASDU: Tag = Tag::context(2, true);
}

mod asdu_tags {
    use iec61850_ber::Tag;
    pub const SV_ID: Tag = Tag::context(0, false);
    pub const DAT_SET: Tag = Tag::context(1, false);
    pub const SMP_CNT: Tag = Tag::context(2, false);
    pub const CONF_REV: Tag = Tag::context(3, false);
    pub const REFR_TM: Tag = Tag::context(4, false);
    pub const SMP_SYNCH: Tag = Tag::context(5, false);
    pub const SMP_RATE: Tag = Tag::context(6, false);
    pub const SAMPLE: Tag = Tag::context(7, false);
    pub const SMP_MOD: Tag = Tag::context(8, false);
}

/// PDU de Sampled Values: una o varias ASDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvPdu {
    pub no_asdu: u32,
    pub asdus: Vec<Asdu>,
}

/// Una unidad de datos de aplicación (una muestra de un control block SV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asdu {
    pub sv_id: String,
    pub dat_set: Option<String>,
    pub smp_cnt: u16,
    pub conf_rev: u32,
    pub refr_tm: Option<UtcTime>,
    pub smp_synch: u8,
    pub smp_rate: Option<u16>,
    pub sample: Vec<u8>,
    pub smp_mod: Option<u16>,
}

impl Asdu {
    /// Empaqueta un dataset 9-2LE en el campo `sample`.
    pub fn set_9_2le(&mut self, n: &NineTwoLe) {
        self.sample = n.to_bytes().to_vec();
    }
    /// Interpreta `sample` como 9-2LE (si tiene 64 octetos).
    pub fn as_9_2le(&self) -> Option<NineTwoLe> {
        NineTwoLe::from_bytes(&self.sample).ok()
    }
}

impl SvPdu {
    /// Codifica el `savPdu` completo (tag `0x60` + longitud + contenido).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(SAV_PDU, |w| {
            w.unsigned(sv_tags::NO_ASDU, self.no_asdu as u64);
            // security [1] omitido
            w.tlv(sv_tags::SEQ_ASDU, |w| {
                for a in &self.asdus {
                    w.sequence(|w| {
                        w.visible_string(asdu_tags::SV_ID, &a.sv_id);
                        if let Some(ds) = &a.dat_set {
                            w.visible_string(asdu_tags::DAT_SET, ds);
                        }
                        w.octet_string(asdu_tags::SMP_CNT, &a.smp_cnt.to_be_bytes());
                        w.octet_string(asdu_tags::CONF_REV, &a.conf_rev.to_be_bytes());
                        if let Some(t) = &a.refr_tm {
                            w.octet_string(asdu_tags::REFR_TM, &t.raw);
                        }
                        w.octet_string(asdu_tags::SMP_SYNCH, &[a.smp_synch]);
                        if let Some(r) = a.smp_rate {
                            w.octet_string(asdu_tags::SMP_RATE, &r.to_be_bytes());
                        }
                        w.octet_string(asdu_tags::SAMPLE, &a.sample);
                        if let Some(m) = a.smp_mod {
                            w.octet_string(asdu_tags::SMP_MOD, &m.to_be_bytes());
                        }
                    });
                }
            });
        });
        w.into_bytes()
    }

    /// Decodifica un `savPdu` desde sus bytes (empezando por el tag `0x60`).
    pub fn decode(bytes: &[u8]) -> Result<SvPdu, SvError> {
        let mut top = BerReader::new(bytes);
        let apdu = top.read_tlv()?;
        if apdu.tag != SAV_PDU {
            return Err(SvError::Malformed(format!("savPdu con tag {}", apdu.tag)));
        }
        let mut r = apdu.reader();

        let no_asdu = u32::try_from(prim::decode_integer(r.expect(sv_tags::NO_ASDU)?)?)
            .map_err(|_| SvError::Malformed("noASDU fuera de rango".into()))?;
        let _ = r.read_if(sv_tags::SECURITY)?; // security opcional → descartar
        let seq = r.expect(sv_tags::SEQ_ASDU)?;

        let mut ar = BerReader::new(seq);
        let mut asdus = Vec::new();
        while !ar.is_empty() {
            asdus.push(decode_asdu(ar.read_tlv()?.content)?);
        }
        Ok(SvPdu { no_asdu, asdus })
    }
}

fn decode_asdu(content: &[u8]) -> Result<Asdu, SvError> {
    let mut f = BerReader::new(content);
    let sv_id = prim::decode_visible_string(f.expect(asdu_tags::SV_ID)?)?.to_string();
    let dat_set = match f.read_if(asdu_tags::DAT_SET)? {
        Some(c) => Some(prim::decode_visible_string(c)?.to_string()),
        None => None,
    };
    let smp_cnt = octets_u16(f.expect(asdu_tags::SMP_CNT)?)?;
    let conf_rev = octets_u32(f.expect(asdu_tags::CONF_REV)?)?;
    let refr_tm = match f.read_if(asdu_tags::REFR_TM)? {
        Some(c) => Some(UtcTime {
            raw: c
                .try_into()
                .map_err(|_| SvError::Malformed("refrTm != 8 octetos".into()))?,
        }),
        None => None,
    };
    let smp_synch = {
        let c = f.expect(asdu_tags::SMP_SYNCH)?;
        *c.first()
            .ok_or_else(|| SvError::Malformed("smpSynch vacío".into()))?
    };
    let smp_rate = match f.read_if(asdu_tags::SMP_RATE)? {
        Some(c) => Some(octets_u16(c)?),
        None => None,
    };
    let sample = f.expect(asdu_tags::SAMPLE)?.to_vec();
    let smp_mod = match f.read_if(asdu_tags::SMP_MOD)? {
        Some(c) => Some(octets_u16(c)?),
        None => None,
    };
    Ok(Asdu {
        sv_id,
        dat_set,
        smp_cnt,
        conf_rev,
        refr_tm,
        smp_synch,
        smp_rate,
        sample,
        smp_mod,
    })
}

fn octets_u16(c: &[u8]) -> Result<u16, SvError> {
    let a: [u8; 2] = c
        .try_into()
        .map_err(|_| SvError::Malformed("se esperaban 2 octetos".into()))?;
    Ok(u16::from_be_bytes(a))
}
fn octets_u32(c: &[u8]) -> Result<u32, SvError> {
    let a: [u8; 4] = c
        .try_into()
        .map_err(|_| SvError::Malformed("se esperaban 4 octetos".into()))?;
    Ok(u32::from_be_bytes(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asdu() -> Asdu {
        let mut a = Asdu {
            sv_id: "MU01".into(),
            dat_set: Some("MU01$ds".into()),
            smp_cnt: 5,
            conf_rev: 1,
            refr_tm: Some(UtcTime {
                raw: [1, 2, 3, 4, 5, 6, 7, 8],
            }),
            smp_synch: 2,
            smp_rate: Some(4000),
            sample: Vec::new(),
            smp_mod: None,
        };
        a.set_9_2le(&NineTwoLe::default());
        a
    }

    #[test]
    fn pdu_round_trip() {
        let pdu = SvPdu {
            no_asdu: 1,
            asdus: vec![asdu()],
        };
        let bytes = pdu.encode();
        assert_eq!(bytes[0], 0x60);
        assert_eq!(SvPdu::decode(&bytes).unwrap(), pdu);
    }

    #[test]
    fn fixed_width_fields() {
        // localiza el ASDU y comprueba que smpCnt es 0x82 0x02 .. y confRev 0x83 0x04 ..
        let bytes = SvPdu {
            no_asdu: 1,
            asdus: vec![asdu()],
        }
        .encode();
        // smpCnt=5 → 82 02 00 05
        assert!(bytes.windows(4).any(|w| w == [0x82, 0x02, 0x00, 0x05]));
        // confRev=1 → 83 04 00 00 00 01
        assert!(
            bytes
                .windows(6)
                .any(|w| w == [0x83, 0x04, 0x00, 0x00, 0x00, 0x01])
        );
    }

    #[test]
    fn multiple_asdus() {
        let mut a2 = asdu();
        a2.smp_cnt = 6;
        let pdu = SvPdu {
            no_asdu: 2,
            asdus: vec![asdu(), a2],
        };
        let bytes = pdu.encode();
        assert_eq!(SvPdu::decode(&bytes).unwrap(), pdu);
    }

    #[test]
    fn minimal_asdu() {
        let a = Asdu {
            sv_id: "MU".into(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 0,
            refr_tm: None,
            smp_synch: 0,
            smp_rate: None,
            sample: vec![0xAA, 0xBB],
            smp_mod: None,
        };
        let pdu = SvPdu {
            no_asdu: 1,
            asdus: vec![a],
        };
        let bytes = pdu.encode();
        assert_eq!(SvPdu::decode(&bytes).unwrap(), pdu);
    }
}
