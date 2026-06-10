//! El `goosePdu` (IEC 61850-8-1): `[APPLICATION 1]` IMPLICIT SEQUENCE con campos
//! de contexto, reutilizando el codec BER y `MmsData` de [`iec61850_ber`].

use iec61850_ber::ber::prim;
use iec61850_ber::{BerReader, BerWriter, MmsData, Tag, Tlv, UtcTime};

use crate::error::GooseError;

/// `[APPLICATION 1]` IMPLICIT SEQUENCE → tag `0x61`.
const GOOSE_APDU: Tag = Tag::application(1, true);

mod tags {
    use iec61850_ber::Tag;
    pub const GOCB_REF: Tag = Tag::context(0, false);
    pub const TIME_ALLOWED: Tag = Tag::context(1, false);
    pub const DAT_SET: Tag = Tag::context(2, false);
    pub const GO_ID: Tag = Tag::context(3, false);
    pub const T: Tag = Tag::context(4, false);
    pub const ST_NUM: Tag = Tag::context(5, false);
    pub const SQ_NUM: Tag = Tag::context(6, false);
    pub const TEST: Tag = Tag::context(7, false);
    pub const CONF_REV: Tag = Tag::context(8, false);
    pub const NDS_COM: Tag = Tag::context(9, false);
    pub const NUM_ENTRIES: Tag = Tag::context(10, false);
    pub const ALL_DATA: Tag = Tag::context(11, true);
}

/// Unidad de datos GOOSE.
#[derive(Debug, Clone, PartialEq)]
pub struct GoosePdu {
    pub gocb_ref: String,
    pub time_allowed_to_live: u32,
    pub dat_set: String,
    pub go_id: String,
    pub t: UtcTime,
    pub st_num: u32,
    pub sq_num: u32,
    pub test: bool,
    pub conf_rev: u32,
    pub nds_com: bool,
    pub num_dat_set_entries: u32,
    pub all_data: Vec<MmsData>,
}

impl GoosePdu {
    /// Codifica el `goosePdu` completo (tag `0x61` + longitud + contenido).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(GOOSE_APDU, |w| {
            w.visible_string(tags::GOCB_REF, &self.gocb_ref);
            w.unsigned(tags::TIME_ALLOWED, self.time_allowed_to_live as u64);
            w.visible_string(tags::DAT_SET, &self.dat_set);
            w.visible_string(tags::GO_ID, &self.go_id);
            w.primitive(tags::T, &self.t.raw);
            w.unsigned(tags::ST_NUM, self.st_num as u64);
            w.unsigned(tags::SQ_NUM, self.sq_num as u64);
            w.boolean(tags::TEST, self.test);
            w.unsigned(tags::CONF_REV, self.conf_rev as u64);
            w.boolean(tags::NDS_COM, self.nds_com);
            w.unsigned(tags::NUM_ENTRIES, self.num_dat_set_entries as u64);
            w.tlv(tags::ALL_DATA, |w| {
                for d in &self.all_data {
                    d.encode(w);
                }
            });
        });
        w.into_bytes()
    }

    /// Decodifica un `goosePdu` desde sus bytes (empezando por el tag `0x61`).
    pub fn decode(bytes: &[u8]) -> Result<GoosePdu, GooseError> {
        let mut top = BerReader::new(bytes);
        let apdu = top.read_tlv()?;
        if apdu.tag != GOOSE_APDU {
            return Err(GooseError::Malformed(format!(
                "APDU GOOSE con tag {}",
                apdu.tag
            )));
        }
        let mut r = apdu.reader();

        let gocb_ref = read_visible(&mut r, tags::GOCB_REF)?;
        let time_allowed_to_live = read_u32(&mut r, tags::TIME_ALLOWED)?;
        let dat_set = read_visible(&mut r, tags::DAT_SET)?;
        let go_id = read_visible(&mut r, tags::GO_ID)?;
        let t = read_utc(&mut r, tags::T)?;
        let st_num = read_u32(&mut r, tags::ST_NUM)?;
        let sq_num = read_u32(&mut r, tags::SQ_NUM)?;
        let test = read_bool(&mut r, tags::TEST)?;
        let conf_rev = read_u32(&mut r, tags::CONF_REV)?;
        let nds_com = read_bool(&mut r, tags::NDS_COM)?;
        let num_dat_set_entries = read_u32(&mut r, tags::NUM_ENTRIES)?;

        let all_data_content = r.expect(tags::ALL_DATA)?;
        let mut ar = BerReader::new(all_data_content);
        let mut all_data = Vec::new();
        while !ar.is_empty() {
            all_data.push(MmsData::decode(&ar.read_tlv()?)?);
        }

        Ok(GoosePdu {
            gocb_ref,
            time_allowed_to_live,
            dat_set,
            go_id,
            t,
            st_num,
            sq_num,
            test,
            conf_rev,
            nds_com,
            num_dat_set_entries,
            all_data,
        })
    }
}

fn read_visible(r: &mut BerReader<'_>, tag: Tag) -> Result<String, GooseError> {
    Ok(prim::decode_visible_string(r.expect(tag)?)?.to_string())
}
fn read_u32(r: &mut BerReader<'_>, tag: Tag) -> Result<u32, GooseError> {
    let v = prim::decode_unsigned(r.expect(tag)?)?;
    u32::try_from(v).map_err(|_| GooseError::Malformed("entero GOOSE fuera de rango u32".into()))
}
fn read_bool(r: &mut BerReader<'_>, tag: Tag) -> Result<bool, GooseError> {
    Ok(prim::decode_bool(r.expect(tag)?)?)
}
fn read_utc(r: &mut BerReader<'_>, tag: Tag) -> Result<UtcTime, GooseError> {
    let raw: [u8; 8] = r
        .expect(tag)?
        .try_into()
        .map_err(|_| GooseError::Malformed("campo t debe tener 8 octetos".into()))?;
    Ok(UtcTime { raw })
}

/// Reexpuesto para tests/usuarios que quieran el `Tlv` ya leído.
pub use iec61850_ber::ber::tag::Tag as BerTag;
pub type GooseTlv<'a> = Tlv<'a>;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GoosePdu {
        GoosePdu {
            gocb_ref: "IED1LD0/LLN0.GO$gcb01".into(),
            time_allowed_to_live: 2000,
            dat_set: "IED1LD0/LLN0$ds1".into(),
            go_id: "gcb01".into(),
            t: UtcTime {
                raw: [0x66, 0x00, 0x00, 0x00, 0x10, 0x20, 0x30, 0x0A],
            },
            st_num: 7,
            sq_num: 3,
            test: false,
            conf_rev: 1,
            nds_com: false,
            num_dat_set_entries: 2,
            all_data: vec![MmsData::Bool(true), MmsData::Int(42)],
        }
    }

    #[test]
    fn pdu_round_trip() {
        let pdu = sample();
        let bytes = pdu.encode();
        assert_eq!(bytes[0], 0x61); // [APPLICATION 1]
        assert_eq!(GoosePdu::decode(&bytes).unwrap(), pdu);
    }

    #[test]
    fn pdu_field_tags() {
        let bytes = sample().encode();
        // tras 0x61 <len>, el primer campo es gocbRef [0] → 0x80
        let mut r = BerReader::new(&bytes);
        let apdu = r.read_tlv().unwrap();
        let mut fr = apdu.reader();
        assert_eq!(fr.read_tlv().unwrap().tag, tags::GOCB_REF);
    }
}
