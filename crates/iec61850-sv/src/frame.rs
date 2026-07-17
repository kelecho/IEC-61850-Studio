//! Trama SV: cabecera Ethernet (capa 2 compartida) + `savPdu`.

use iec61850_l2::{
    EthHeader, FrameSigner, FrameVerifier, finish_l2_frame, finish_l2_frame_signed,
    parse_eth_appid, parse_eth_appid_auth, write_eth_appid,
};

use crate::error::SvError;
use crate::pdu::SvPdu;

pub use iec61850_l2::{
    AuthStatus, HmacKey, KeyEntry, KeyRing, MacAddr, Signer, SignerRing, Verifier, VerifierRing,
    VlanTag,
};
#[cfg(feature = "ecdsa")]
pub use iec61850_l2::{EcdsaSigner, EcdsaVerifier};

pub const ETHERTYPE_SV: u16 = 0x88BA;

/// Trama SV completa.
#[derive(Debug, Clone, PartialEq)]
pub struct SvFrame {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<VlanTag>,
    pub appid: u16,
    /// Bit "Simulated" de Ed.2 (Reserved1): trama simulada/de prueba.
    pub simulation: bool,
    pub pdu: SvPdu,
}

impl SvFrame {
    pub fn encode(&self) -> Vec<u8> {
        let hdr = EthHeader {
            dst: self.dst,
            src: self.src,
            vlan: self.vlan,
            ethertype: ETHERTYPE_SV,
            simulation: self.simulation,
        };
        let mut out = Vec::with_capacity(128);
        let len_pos = write_eth_appid(&mut out, &hdr, self.appid);
        let apdu = self.pdu.encode();
        out.extend_from_slice(&apdu);
        finish_l2_frame(&mut out, len_pos, apdu.len());
        out
    }

    /// Codifica la trama firmándola (IEC 62351-6): anexa el tag de autenticación
    /// tras el `savPdu`. Genérico sobre el firmante: HMAC-SHA256 ([`HmacKey`]) o
    /// ECDSA P-256 (`EcdsaSigner`, feature `ecdsa`).
    pub fn encode_signed<S: FrameSigner>(&self, signer: &S) -> Vec<u8> {
        let hdr = EthHeader {
            dst: self.dst,
            src: self.src,
            vlan: self.vlan,
            ethertype: ETHERTYPE_SV,
            simulation: self.simulation,
        };
        let mut out = Vec::with_capacity(160);
        let len_pos = write_eth_appid(&mut out, &hdr, self.appid);
        let apdu = self.pdu.encode();
        out.extend_from_slice(&apdu);
        finish_l2_frame_signed(&mut out, len_pos, apdu.len(), signer);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SvFrame, SvError> {
        let (hdr, appid, apdu) = parse_eth_appid(bytes, ETHERTYPE_SV)?;
        Ok(SvFrame {
            dst: hdr.dst,
            src: hdr.src,
            vlan: hdr.vlan,
            appid,
            simulation: hdr.simulation,
            pdu: SvPdu::decode(apdu)?,
        })
    }

    /// Decodifica y verifica la autenticación (IEC 62351-6) con el verificador
    /// dado (HMAC-SHA256 o ECDSA P-256). Devuelve la trama y el estado de la
    /// firma (`Unsigned`/`Valid`/`Invalid`).
    pub fn decode_verified<V: FrameVerifier>(
        bytes: &[u8],
        verifier: &V,
    ) -> Result<(SvFrame, AuthStatus), SvError> {
        let p = parse_eth_appid_auth(bytes, ETHERTYPE_SV)?;
        let status = if p.auth_tag.is_empty() {
            AuthStatus::Unsigned
        } else if verifier.verify_tag(p.signed_data, p.auth_tag) {
            AuthStatus::Valid
        } else {
            AuthStatus::Invalid
        };
        let frame = SvFrame {
            dst: p.hdr.dst,
            src: p.hdr.src,
            vlan: p.hdr.vlan,
            appid: p.appid,
            simulation: p.hdr.simulation,
            pdu: SvPdu::decode(p.apdu)?,
        };
        Ok((frame, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nine_two_le::NineTwoLe;
    use crate::pdu::Asdu;
    use iec61850_ber::UtcTime;

    fn frame(vlan: Option<VlanTag>) -> SvFrame {
        let mut a = Asdu {
            sv_id: "MU01".into(),
            dat_set: None,
            smp_cnt: 1,
            conf_rev: 1,
            refr_tm: Some(UtcTime { raw: [0; 8] }),
            smp_synch: 2,
            smp_rate: Some(4000),
            sample: Vec::new(),
            smp_mod: None,
        };
        a.set_9_2le(&NineTwoLe::default());
        SvFrame {
            dst: [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01],
            src: [0, 1, 2, 3, 4, 5],
            vlan,
            appid: 0x4000,
            simulation: false,
            pdu: SvPdu {
                no_asdu: 1,
                asdus: vec![a],
            },
        }
    }

    #[test]
    fn round_trip_simulation_bit() {
        let mut f = frame(None);
        f.simulation = true;
        let decoded = SvFrame::decode(&f.encode()).unwrap();
        assert!(decoded.simulation);
        assert_eq!(decoded, f);
    }

    #[test]
    fn round_trip_no_vlan() {
        let f = frame(None);
        let bytes = f.encode();
        assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), ETHERTYPE_SV);
        assert_eq!(SvFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_vlan() {
        let f = frame(Some(VlanTag::new(50)));
        let bytes = f.encode();
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), ETHERTYPE_SV);
        assert_eq!(SvFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn signed_round_trip_and_tamper() {
        let key = HmacKey::new(b"clave-sv");
        let f = frame(Some(VlanTag::new(50)));
        let bytes = f.encode_signed(&key);

        let (decoded, status) = SvFrame::decode_verified(&bytes, &key).unwrap();
        assert_eq!(status, AuthStatus::Valid);
        assert_eq!(decoded, f);
        assert_eq!(SvFrame::decode(&bytes).unwrap(), f);

        let (_, status) = SvFrame::decode_verified(&bytes, &HmacKey::new(b"otra")).unwrap();
        assert_eq!(status, AuthStatus::Invalid);
        let (_, status) = SvFrame::decode_verified(&f.encode(), &key).unwrap();
        assert_eq!(status, AuthStatus::Unsigned);
    }
}
