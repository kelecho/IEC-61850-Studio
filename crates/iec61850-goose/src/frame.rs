//! Trama GOOSE: cabecera Ethernet (capa 2 compartida) + `goosePdu`.

use iec61850_l2::{EthHeader, finish_l2_frame, parse_eth_appid, write_eth_appid};

use crate::error::GooseError;
use crate::pdu::GoosePdu;

pub use iec61850_l2::{MacAddr, VlanTag};

pub const ETHERTYPE_GOOSE: u16 = 0x88B8;

/// Trama GOOSE completa.
#[derive(Debug, Clone, PartialEq)]
pub struct GooseFrame {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<VlanTag>,
    pub appid: u16,
    /// Bit "Simulated" de Ed.2 (Reserved1): trama simulada/de prueba.
    pub simulation: bool,
    pub pdu: GoosePdu,
}

impl GooseFrame {
    /// Codifica la trama completa (con padding a 60 octetos).
    pub fn encode(&self) -> Vec<u8> {
        let hdr = EthHeader {
            dst: self.dst,
            src: self.src,
            vlan: self.vlan,
            ethertype: ETHERTYPE_GOOSE,
            simulation: self.simulation,
        };
        let mut out = Vec::with_capacity(128);
        let len_pos = write_eth_appid(&mut out, &hdr, self.appid);
        let apdu = self.pdu.encode();
        out.extend_from_slice(&apdu);
        finish_l2_frame(&mut out, len_pos, apdu.len());
        out
    }

    /// Decodifica una trama recibida.
    pub fn decode(bytes: &[u8]) -> Result<GooseFrame, GooseError> {
        let (hdr, appid, apdu) = parse_eth_appid(bytes, ETHERTYPE_GOOSE)?;
        Ok(GooseFrame {
            dst: hdr.dst,
            src: hdr.src,
            vlan: hdr.vlan,
            appid,
            simulation: hdr.simulation,
            pdu: GoosePdu::decode(apdu)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_ber::{MmsData, UtcTime};

    fn sample_pdu() -> GoosePdu {
        GoosePdu {
            gocb_ref: "IED1LD0/LLN0.GO$gcb01".into(),
            time_allowed_to_live: 2000,
            dat_set: "IED1LD0/LLN0$ds1".into(),
            go_id: "gcb01".into(),
            t: UtcTime {
                raw: [1, 2, 3, 4, 5, 6, 7, 8],
            },
            st_num: 1,
            sq_num: 0,
            test: false,
            conf_rev: 1,
            nds_com: false,
            num_dat_set_entries: 2,
            all_data: vec![MmsData::Bool(true), MmsData::Int(42)],
        }
    }

    fn frame(vlan: Option<VlanTag>) -> GooseFrame {
        GooseFrame {
            dst: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            vlan,
            appid: 0x0001,
            simulation: false,
            pdu: sample_pdu(),
        }
    }

    #[test]
    fn round_trip_simulation_bit() {
        let mut f = frame(None);
        f.simulation = true;
        let bytes = f.encode();
        let decoded = GooseFrame::decode(&bytes).unwrap();
        assert!(decoded.simulation);
        assert_eq!(decoded, f);
    }

    #[test]
    fn round_trip_no_vlan() {
        let f = frame(None);
        let bytes = f.encode();
        assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), ETHERTYPE_GOOSE);
        assert!(bytes.len() >= 60);
        assert_eq!(GooseFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_vlan() {
        let f = frame(Some(VlanTag::new(100)));
        let bytes = f.encode();
        assert_eq!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            iec61850_l2::TPID_8021Q
        );
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), ETHERTYPE_GOOSE);
        assert_eq!(GooseFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn length_excludes_ethernet_and_padding() {
        let f = frame(None);
        let bytes = f.encode();
        let apdu = f.pdu.encode();
        let length = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        assert_eq!(length, 8 + apdu.len());
    }

    #[test]
    fn rejects_non_goose() {
        let mut bytes = frame(None).encode();
        bytes[12] = 0x08;
        bytes[13] = 0x00; // IPv4
        assert!(GooseFrame::decode(&bytes).is_err());
    }
}
