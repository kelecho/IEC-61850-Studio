//! ISO Session (ISO 8327), kernel mínimo para MMS.
//!
//! Envío: SPDU CONNECT (envuelve el CP de presentación) y, en fase de datos, el
//! prefijo constante GIVE-TOKENS + DATA-TRANSFER. La recepción no se parsea
//! aquí: el cliente localiza el `fully-encoded-data` con
//! [`crate::upper::presentation::extract_inner_pdu`].

const SI_CONNECT: u8 = 0x0D;
const SI_ACCEPT: u8 = 0x0E;

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
    let mut after_li = Vec::new();
    after_li.extend_from_slice(&[0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02]);
    after_li.extend_from_slice(&[0x14, 0x02, 0x00, 0x02]);
    after_li.push(0xC1);
    push_li(&mut after_li, presentation_cpa.len());
    after_li.extend_from_slice(presentation_cpa);

    let mut out = Vec::with_capacity(2 + after_li.len());
    out.push(SI_ACCEPT);
    push_li(&mut out, after_li.len());
    out.extend_from_slice(&after_li);
    out
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
}
