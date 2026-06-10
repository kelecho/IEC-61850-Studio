//! Cabecera Ethernet + 802.1Q opcional + cabecera de aplicación de 8 octetos
//! (APPID/Length/Reserved), común a GOOSE y SV. Solo cambia el EtherType.

use crate::error::L2Error;

pub type MacAddr = [u8; 6];

pub const TPID_8021Q: u16 = 0x8100;
const MIN_ETH_FRAME: usize = 60;

/// Etiqueta 802.1Q (VLAN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    pub pcp: u8,
    pub dei: bool,
    pub vid: u16,
}

impl VlanTag {
    /// VLAN con prioridad por defecto 4 (recomendada para GOOSE/SV).
    pub fn new(vid: u16) -> Self {
        Self {
            pcp: 4,
            dei: false,
            vid: vid & 0x0FFF,
        }
    }
    fn tci(&self) -> u16 {
        ((self.pcp as u16 & 0x7) << 13) | ((self.dei as u16) << 12) | (self.vid & 0x0FFF)
    }
}

/// Bit "Simulated" (S) de IEC 61850-8-1 Ed.2: bit más significativo del campo
/// Reserved1 de la cabecera de aplicación. Indica una trama simulada/de prueba
/// que un IED en modo simulación (`LPHD.Sim`) acepta en lugar de la real.
pub const RESERVED1_SIMULATED: u16 = 0x8000;

/// Cabecera Ethernet (con VLAN opcional), EtherType y bit de simulación (Ed.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<VlanTag>,
    pub ethertype: u16,
    /// Bit "Simulated" de Ed.2 (Reserved1, bit 15).
    pub simulation: bool,
}

/// Escribe la cabecera Ethernet + APPID + placeholders de Length/Reserved.
/// Devuelve la posición del campo Length (para parchearlo con
/// [`finish_l2_frame`] tras añadir el APDU). El bit de simulación (Ed.2) se
/// codifica en el MSB de Reserved1.
pub fn write_eth_appid(out: &mut Vec<u8>, hdr: &EthHeader, appid: u16) -> usize {
    out.extend_from_slice(&hdr.dst);
    out.extend_from_slice(&hdr.src);
    if let Some(vlan) = hdr.vlan {
        out.extend_from_slice(&TPID_8021Q.to_be_bytes());
        out.extend_from_slice(&vlan.tci().to_be_bytes());
    }
    out.extend_from_slice(&hdr.ethertype.to_be_bytes());
    out.extend_from_slice(&appid.to_be_bytes());
    let len_pos = out.len();
    out.extend_from_slice(&[0, 0]); // Length (placeholder)
    let reserved1: u16 = if hdr.simulation {
        RESERVED1_SIMULATED
    } else {
        0
    };
    out.extend_from_slice(&reserved1.to_be_bytes()); // Reserved1 (bit15 = Simulated)
    out.extend_from_slice(&[0, 0]); // Reserved2
    len_pos
}

/// Parchea el campo Length (= 8 + `apdu_len`) y rellena hasta 60 octetos. Debe
/// llamarse después de haber añadido el APDU al buffer.
pub fn finish_l2_frame(out: &mut Vec<u8>, len_pos: usize, apdu_len: usize) {
    let length = (8 + apdu_len) as u16;
    out[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());
    if out.len() < MIN_ETH_FRAME {
        out.resize(MIN_ETH_FRAME, 0);
    }
}

/// Parsea la cabecera Ethernet/APPID y devuelve `(cabecera, appid, slice del APDU)`.
/// Falla con `WrongEthertype` si el EtherType no es el esperado.
pub fn parse_eth_appid(
    bytes: &[u8],
    expected_ethertype: u16,
) -> Result<(EthHeader, u16, &[u8]), L2Error> {
    if bytes.len() < 14 {
        return Err(L2Error::Truncated);
    }
    let dst: MacAddr = bytes[0..6].try_into().unwrap();
    let src: MacAddr = bytes[6..12].try_into().unwrap();

    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    let (vlan, off, ethertype) = if ethertype == TPID_8021Q {
        if bytes.len() < 18 {
            return Err(L2Error::Truncated);
        }
        let tci = u16::from_be_bytes([bytes[14], bytes[15]]);
        let vlan = VlanTag {
            pcp: (tci >> 13) as u8 & 0x7,
            dei: (tci >> 12) & 1 == 1,
            vid: tci & 0x0FFF,
        };
        (Some(vlan), 18, u16::from_be_bytes([bytes[16], bytes[17]]))
    } else {
        (None, 14, ethertype)
    };

    if ethertype != expected_ethertype {
        return Err(L2Error::WrongEthertype(ethertype));
    }

    let hdr = bytes
        .get(off..off + 8)
        .ok_or_else(|| L2Error::Malformed("cabecera de aplicación truncada".into()))?;
    let appid = u16::from_be_bytes([hdr[0], hdr[1]]);
    let length = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    // Reserved1 (hdr[4..6]): bit 15 = Simulated (Ed.2).
    let simulation = u16::from_be_bytes([hdr[4], hdr[5]]) & RESERVED1_SIMULATED != 0;
    if length < 8 {
        return Err(L2Error::Malformed("Length < 8".into()));
    }
    let apdu = bytes
        .get(off + 8..off + length)
        .ok_or_else(|| L2Error::Malformed("Length excede la trama".into()))?;

    Ok((
        EthHeader {
            dst,
            src,
            vlan,
            ethertype,
            simulation,
        },
        appid,
        apdu,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(ethertype: u16, vlan: Option<VlanTag>, simulation: bool) {
        let hdr = EthHeader {
            dst: [1, 2, 3, 4, 5, 6],
            src: [7, 8, 9, 10, 11, 12],
            vlan,
            ethertype,
            simulation,
        };
        let apdu = [0xAAu8, 0xBB, 0xCC];
        let mut out = Vec::new();
        let len_pos = write_eth_appid(&mut out, &hdr, 0x1234);
        out.extend_from_slice(&apdu);
        finish_l2_frame(&mut out, len_pos, apdu.len());

        assert!(out.len() >= MIN_ETH_FRAME);
        let (h, appid, parsed) = parse_eth_appid(&out, ethertype).unwrap();
        assert_eq!(h, hdr);
        assert_eq!(appid, 0x1234);
        assert_eq!(parsed, apdu);
    }

    #[test]
    fn header_round_trip() {
        round(0x88B8, None, false);
        round(0x88BA, Some(VlanTag::new(100)), false);
        // Bit de simulación (Ed.2).
        round(0x88B8, None, true);
        round(0x88BA, Some(VlanTag::new(100)), true);
    }

    #[test]
    fn simulation_bit_is_reserved1_msb() {
        let hdr = EthHeader {
            dst: [0; 6],
            src: [0; 6],
            vlan: None,
            ethertype: 0x88B8,
            simulation: true,
        };
        let mut out = Vec::new();
        let len_pos = write_eth_appid(&mut out, &hdr, 1);
        finish_l2_frame(&mut out, len_pos, 0);
        // Reserved1 está justo tras APPID(2)+Length(2) = offset 14+2+2 = 18.
        assert_eq!(out[18], 0x80); // MSB de Reserved1
        assert_eq!(out[19], 0x00);
    }

    #[test]
    fn wrong_ethertype() {
        let hdr = EthHeader {
            dst: [0; 6],
            src: [0; 6],
            vlan: None,
            ethertype: 0x88B8,
            simulation: false,
        };
        let mut out = Vec::new();
        let len_pos = write_eth_appid(&mut out, &hdr, 1);
        finish_l2_frame(&mut out, len_pos, 0);
        assert!(matches!(
            parse_eth_appid(&out, 0x88BA),
            Err(L2Error::WrongEthertype(0x88B8))
        ));
    }
}
