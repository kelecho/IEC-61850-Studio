//! ISO Session (ISO 8327), kernel mínimo para MMS.
//!
//! Envío: SPDU CONNECT (envuelve el CP de presentación) y, en fase de datos, el
//! prefijo constante GIVE-TOKENS + DATA-TRANSFER. En recepción el servidor
//! parsea la SPDU CONNECT ([`parse_connect`]) para negociar la versión y
//! localizar el user-data por estructura (no por escaneo); el cliente sigue
//! usando [`crate::upper::presentation::extract_inner_pdu`].

use crate::error::MmsError;

const SI_CONNECT: u8 = 0x0D;
const SI_ACCEPT: u8 = 0x0E;

/// PI Session User Requirements.
const PI_REQUIREMENTS: u8 = 0x14;
/// PI Version Number (dentro del Connect/Accept Item).
const PI_VERSION: u8 = 0x16;
/// PI Protocol Options (dentro del Connect/Accept Item).
const PI_PROTOCOL_OPTIONS: u8 = 0x13;
/// PGI Connect/Accept Item.
const PGI_CONNECT_ACCEPT: u8 = 0x05;
/// PI Calling Session Selector.
const PI_CALLING_SELECTOR: u8 = 0x33;
/// PI Called Session Selector.
const PI_CALLED_SELECTOR: u8 = 0x34;
/// PGI User Data.
const PGI_USER_DATA: u8 = 0xC1;

/// Prefijo de la fase de datos: GIVE-TOKENS (`01 00`) + DATA-TRANSFER (`01 00`).
pub const DATA_PREFIX: [u8; 4] = [0x01, 0x00, 0x01, 0x00];

/// Construye una SPDU CONNECT que transporta el CP de presentación.
pub fn connect(presentation_cp: &[u8]) -> Vec<u8> {
    let mut after_li = Vec::new();
    // Connect Accept Item (PI 0x05): Protocol Options (13 01 00) + Version (16 01 02)
    after_li.extend_from_slice(&[0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02]);
    // Session User Requirements (PI 0x14): duplex (0x0002)
    after_li.extend_from_slice(&[0x14, 0x02, 0x00, 0x02]);
    // User Data (PGI 0xC1) con el CP de presentación
    after_li.push(0xC1);
    push_li(&mut after_li, presentation_cp.len());
    after_li.extend_from_slice(presentation_cp);

    let mut out = Vec::with_capacity(2 + after_li.len());
    out.push(SI_CONNECT);
    push_li(&mut out, after_li.len());
    out.extend_from_slice(&after_li);
    out
}

/// Construye una SPDU ACCEPT que transporta el CPA de presentación (lado servidor).
pub fn accept(presentation_cpa: &[u8]) -> Vec<u8> {
    accept_with_version(presentation_cpa, 0x02)
}

/// SPDU ACCEPT con el **bitmask de versión negociado** (PI 0x16): se responde la
/// mejor versión común con el CONNECT del cliente (v2 si la ofrece, v1 si no).
pub fn accept_with_version(presentation_cpa: &[u8], version: u8) -> Vec<u8> {
    let mut after_li = Vec::new();
    after_li.extend_from_slice(&[
        PGI_CONNECT_ACCEPT,
        0x06,
        PI_PROTOCOL_OPTIONS,
        0x01,
        0x00,
        PI_VERSION,
        0x01,
        version,
    ]);
    after_li.extend_from_slice(&[PI_REQUIREMENTS, 0x02, 0x00, 0x02]);
    after_li.push(PGI_USER_DATA);
    push_li(&mut after_li, presentation_cpa.len());
    after_li.extend_from_slice(presentation_cpa);

    let mut out = Vec::with_capacity(2 + after_li.len());
    out.push(SI_ACCEPT);
    push_li(&mut out, after_li.len());
    out.extend_from_slice(&after_li);
    out
}

/// Parámetros relevantes de una SPDU CONNECT entrante.
#[derive(Debug, PartialEq)]
pub struct ConnectSpdu<'a> {
    /// Bitmask del PI Version Number (bit0 = v1, bit1 = v2); 0x02 si no vino.
    pub version: u8,
    /// Session User Requirements (2 octetos), si vinieron.
    pub requirements: Option<[u8; 2]>,
    /// Calling / Called Session Selector, si vinieron.
    pub calling_selector: Option<&'a [u8]>,
    pub called_selector: Option<&'a [u8]>,
    /// User-data (PGI 0xC1): el CP de presentación.
    pub user_data: &'a [u8],
}

impl ConnectSpdu<'_> {
    /// Mejor versión común: v2 si el cliente la ofrece, si no v1.
    pub fn negotiated_version(&self) -> u8 {
        if self.version & 0x02 != 0 { 0x02 } else { 0x01 }
    }
}

/// Lee un indicador de longitud de sesión en `buf[i..]`; devuelve (len, octetos).
fn read_li(buf: &[u8], i: usize) -> Option<(usize, usize)> {
    match *buf.get(i)? {
        0xFF => {
            let hi = *buf.get(i + 1)? as usize;
            let lo = *buf.get(i + 2)? as usize;
            Some(((hi << 8) | lo, 3))
        }
        n => Some((n as usize, 1)),
    }
}

/// Parsea una SPDU CONNECT (SI 0x0D): recorre los parámetros PI/PGI por
/// estructura y devuelve versión, requirements, selectores y el user-data.
pub fn parse_connect(buf: &[u8]) -> Result<ConnectSpdu<'_>, MmsError> {
    let err = |m: &str| MmsError::Transport(format!("SPDU CONNECT: {m}"));
    if buf.first() != Some(&SI_CONNECT) {
        return Err(err("no es CONNECT (SI 0x0D)"));
    }
    let (total, li_len) = read_li(buf, 1).ok_or_else(|| err("LI truncada"))?;
    let mut i = 1 + li_len;
    let end = (i + total).min(buf.len());

    let mut out = ConnectSpdu {
        version: 0x02,
        requirements: None,
        calling_selector: None,
        called_selector: None,
        user_data: &[],
    };
    while i < end {
        let code = buf[i];
        let (len, li) = read_li(buf, i + 1).ok_or_else(|| err("parámetro truncado"))?;
        let start = i + 1 + li;
        let value = buf
            .get(start..start + len)
            .ok_or_else(|| err("valor de parámetro truncado"))?;
        match code {
            PGI_CONNECT_ACCEPT => {
                // Sub-parámetros: protocol options / version.
                let mut j = 0;
                while j < value.len() {
                    let sub = value[j];
                    let (slen, sli) =
                        read_li(value, j + 1).ok_or_else(|| err("sub-parámetro truncado"))?;
                    let sstart = j + 1 + sli;
                    let sval = value
                        .get(sstart..sstart + slen)
                        .ok_or_else(|| err("sub-valor truncado"))?;
                    if sub == PI_VERSION {
                        out.version = sval.first().copied().unwrap_or(0x02);
                    }
                    j = sstart + slen;
                }
            }
            PI_REQUIREMENTS if len == 2 => out.requirements = Some([value[0], value[1]]),
            PI_CALLING_SELECTOR => out.calling_selector = Some(value),
            PI_CALLED_SELECTOR => out.called_selector = Some(value),
            PGI_USER_DATA => out.user_data = value,
            _ => {} // parámetro no relevante para el kernel MMS: se ignora
        }
        i = start + len;
    }
    if out.user_data.is_empty() {
        return Err(err("sin user-data (PGI 0xC1)"));
    }
    Ok(out)
}

/// Antepone el prefijo de datos a los datos de usuario de presentación.
pub fn data(presentation_user_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_PREFIX.len() + presentation_user_data.len());
    out.extend_from_slice(&DATA_PREFIX);
    out.extend_from_slice(presentation_user_data);
    out
}

/// Codifica un indicador de longitud de sesión (forma corta, o `FF hi lo` si ≥255).
fn push_li(out: &mut Vec<u8>, len: usize) {
    if len < 0xFF {
        out.push(len as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_short_li() {
        let cp = [0xAAu8; 10];
        let cn = connect(&cp);
        assert_eq!(cn[0], SI_CONNECT);
        // LI corta = longitud del resto
        assert_eq!(cn[1] as usize, cn.len() - 2);
        // termina con el CP tras el PGI 0xC1
        assert!(cn.windows(10).any(|w| w == cp));
    }

    #[test]
    fn connect_long_li() {
        let cp = vec![0x55u8; 300];
        let cn = connect(&cp);
        // el PGI de user-data usa forma extendida FF hi lo
        assert!(cn.windows(3).any(|w| w == [0xFF, 0x01, 0x2C])); // 300 = 0x012C
    }

    #[test]
    fn data_prefix() {
        let ud = [0x61, 0x02, 0x00, 0x00];
        let d = data(&ud);
        assert_eq!(&d[..4], &DATA_PREFIX);
        assert_eq!(&d[4..], &ud);
    }

    #[test]
    fn parse_connect_round_trip() {
        let cp = [0x31u8, 0x03, 0xA0, 0x01, 0x00];
        let spdu = connect(&cp);
        let parsed = parse_connect(&spdu).expect("CONNECT propio parseable");
        assert_eq!(parsed.version, 0x02);
        assert_eq!(parsed.negotiated_version(), 0x02);
        assert_eq!(parsed.requirements, Some([0x00, 0x02]));
        assert_eq!(parsed.user_data, cp);
    }

    #[test]
    fn parse_connect_long_user_data() {
        // user-data ≥255 fuerza la LI extendida FF hi lo también al parsear.
        let cp = vec![0x42u8; 300];
        let spdu = connect(&cp);
        let parsed = parse_connect(&spdu).unwrap();
        assert_eq!(parsed.user_data, &cp[..]);
    }

    #[test]
    fn parse_connect_with_selectors_and_v1() {
        // CONNECT artesanal: versión solo v1 + selectores de sesión.
        let cp = [0x31u8, 0x00];
        let mut body = Vec::new();
        body.extend_from_slice(&[PGI_CONNECT_ACCEPT, 0x03, PI_VERSION, 0x01, 0x01]);
        body.extend_from_slice(&[PI_CALLING_SELECTOR, 0x02, 0xAA, 0xBB]);
        body.extend_from_slice(&[PI_CALLED_SELECTOR, 0x02, 0xCC, 0xDD]);
        body.push(PGI_USER_DATA);
        body.push(cp.len() as u8);
        body.extend_from_slice(&cp);
        let mut spdu = vec![SI_CONNECT, body.len() as u8];
        spdu.extend_from_slice(&body);

        let parsed = parse_connect(&spdu).unwrap();
        assert_eq!(parsed.version, 0x01);
        assert_eq!(parsed.negotiated_version(), 0x01);
        assert_eq!(parsed.calling_selector, Some(&[0xAA, 0xBB][..]));
        assert_eq!(parsed.called_selector, Some(&[0xCC, 0xDD][..]));
        assert_eq!(parsed.user_data, cp);
    }

    #[test]
    fn parse_connect_rejects_non_connect() {
        assert!(parse_connect(&[SI_ACCEPT, 0x00]).is_err());
        assert!(parse_connect(&[]).is_err());
    }
}
