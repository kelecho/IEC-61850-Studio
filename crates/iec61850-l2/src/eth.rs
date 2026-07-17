//! Cabecera Ethernet + 802.1Q opcional + cabecera de aplicación de 8 octetos
//! (APPID/Length/Reserved), común a GOOSE y SV. Solo cambia el EtherType.

use crate::auth::FrameSigner;
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

/// Como [`finish_l2_frame`], pero **firma la trama** (IEC 62351-6): anexa el tag
/// de autenticación tras el APDU, ajusta `Length` para abarcarlo y codifica su
/// longitud en `Reserved2`. El tag cubre desde `APPID` hasta el final del APDU
/// (los 8 octetos de cabecera de aplicación —con `Length`/`Reserved2` ya
/// fijados— más el APDU), por lo que la verificación es autoconsistente. Es
/// genérico sobre el [`FrameSigner`]: HMAC-SHA256 o ECDSA P-256.
pub fn finish_l2_frame_signed<S: FrameSigner>(
    out: &mut Vec<u8>,
    len_pos: usize,
    apdu_len: usize,
    signer: &S,
) {
    let tag_len = signer.tag_len();
    let length = (8 + apdu_len + tag_len) as u16;
    out[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());
    // Reserved2 (offset len_pos+4) = longitud del tag de autenticación.
    out[len_pos + 4..len_pos + 6].copy_from_slice(&(tag_len as u16).to_be_bytes());
    let start = len_pos - 2; // inicio de APPID (cabecera de aplicación)
    let end = len_pos + 6 + apdu_len; // fin del APDU
    let tag = signer.sign_tag(&out[start..end]);
    debug_assert_eq!(tag.len(), tag_len);
    out.extend_from_slice(&tag);
    if out.len() < MIN_ETH_FRAME {
        out.resize(MIN_ETH_FRAME, 0);
    }
}

/// Cabecera de aplicación parseada, con separación del tag de autenticación
/// (IEC 62351-6) cuando `Reserved2 != 0`.
#[derive(Debug, Clone)]
pub struct ParsedAppFrame<'a> {
    pub hdr: EthHeader,
    pub appid: u16,
    /// APDU sin el tag de autenticación (listo para decodificar el PDU).
    pub apdu: &'a [u8],
    /// Octetos cubiertos por el MAC (`APPID`..fin del APDU); vacío si no firmada.
    pub signed_data: &'a [u8],
    /// Tag de autenticación anexado; vacío si la trama no está firmada.
    pub auth_tag: &'a [u8],
}

/// Parsea la cabecera Ethernet/APPID y devuelve `(cabecera, appid, slice del APDU)`.
/// Falla con `WrongEthertype` si el EtherType no es el esperado. Si la trama está
/// firmada (IEC 62351-6), el tag anexado se **descuenta** del APDU (véase
/// [`parse_eth_appid_auth`] para obtenerlo).
pub fn parse_eth_appid(
    bytes: &[u8],
    expected_ethertype: u16,
) -> Result<(EthHeader, u16, &[u8]), L2Error> {
    let p = parse_eth_appid_auth(bytes, expected_ethertype)?;
    Ok((p.hdr, p.appid, p.apdu))
}

/// Igual que [`parse_eth_appid`] pero además separa los octetos firmados y el tag
/// de autenticación (IEC 62351-6). `Reserved2` indica la longitud del tag; si es
/// 0, `signed_data` y `auth_tag` quedan vacíos.
pub fn parse_eth_appid_auth(
    bytes: &[u8],
    expected_ethertype: u16,
) -> Result<ParsedAppFrame<'_>, L2Error> {
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
    // Reserved2 (hdr[6..8]): longitud del tag de autenticación (IEC 62351-6).
    let auth_len = u16::from_be_bytes([hdr[6], hdr[7]]) as usize;
    if length < 8 + auth_len {
        return Err(L2Error::Malformed(
            "Length < 8 + tag de autenticación".into(),
        ));
    }
    let end = off + length;
    if end > bytes.len() {
        return Err(L2Error::Malformed("Length excede la trama".into()));
    }
    let apdu = &bytes[off + 8..end - auth_len];
    let (signed_data, auth_tag) = if auth_len == 0 {
        (&bytes[0..0], &bytes[0..0])
    } else {
        (&bytes[off..end - auth_len], &bytes[end - auth_len..end])
    };

    Ok(ParsedAppFrame {
        hdr: EthHeader {
            dst,
            src,
            vlan,
            ethertype,
            simulation,
        },
        appid,
        apdu,
        signed_data,
        auth_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{HMAC_SHA256_TAG_LEN, HmacKey};

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
    fn signed_frame_round_trip_and_tamper() {
        let hdr = EthHeader {
            dst: [1, 2, 3, 4, 5, 6],
            src: [7, 8, 9, 10, 11, 12],
            vlan: Some(VlanTag::new(100)),
            ethertype: 0x88B8,
            simulation: false,
        };
        let apdu = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let key = HmacKey::new(b"clave-de-flujo");

        let mut out = Vec::new();
        let len_pos = write_eth_appid(&mut out, &hdr, 0x1234);
        out.extend_from_slice(&apdu);
        finish_l2_frame_signed(&mut out, len_pos, apdu.len(), &key);

        // El APDU se recupera limpio (sin el tag) y el tag verifica.
        let p = parse_eth_appid_auth(&out, 0x88B8).unwrap();
        assert_eq!(p.appid, 0x1234);
        assert_eq!(p.apdu, apdu);
        assert_eq!(p.auth_tag.len(), HMAC_SHA256_TAG_LEN);
        assert!(key.verify(p.signed_data, p.auth_tag));
        // parse_eth_appid (compat) también da el APDU sin el tag.
        let (_, _, apdu2) = parse_eth_appid(&out, 0x88B8).unwrap();
        assert_eq!(apdu2, apdu);

        // Manipular un octeto del APDU invalida el tag.
        let mut tampered = out.clone();
        tampered[len_pos + 6] ^= 0x01;
        let pt = parse_eth_appid_auth(&tampered, 0x88B8).unwrap();
        assert!(!key.verify(pt.signed_data, pt.auth_tag));
    }

    #[test]
    fn unsigned_frame_has_empty_auth() {
        let hdr = EthHeader {
            dst: [0; 6],
            src: [0; 6],
            vlan: None,
            ethertype: 0x88B8,
            simulation: false,
        };
        let mut out = Vec::new();
        let len_pos = write_eth_appid(&mut out, &hdr, 1);
        out.extend_from_slice(&[9, 9, 9]);
        finish_l2_frame(&mut out, len_pos, 3);
        let p = parse_eth_appid_auth(&out, 0x88B8).unwrap();
        assert!(p.auth_tag.is_empty());
        assert!(p.signed_data.is_empty());
        assert_eq!(p.apdu, [9, 9, 9]);
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
