//! TPKT (RFC 1006): encapsula las TPDU de COTP sobre TCP.
//!
//! Cabecera de 4 octetos: `03 00 len_hi len_lo`, donde `len` es la longitud
//! **total** del paquete incluyendo la propia cabecera.

use crate::error::MmsError;

pub const HEADER_LEN: usize = 4;
pub const VERSION: u8 = 0x03;

/// Cota superior del payload TPKT que aceptamos. El campo de longitud es de 16
/// bits (máx. 65535), así que el límite teórico es pequeño, pero lo acotamos
/// explícitamente para no asignar a ciegas ante una cabecera corrupta de un peer
/// hostil o con errores.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize - HEADER_LEN;

/// Envuelve un payload (TPDU COTP) en una trama TPKT.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let total = HEADER_LEN + payload.len();
    let mut out = Vec::with_capacity(total);
    out.push(VERSION);
    out.push(0x00);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Dada la cabecera TPKT, devuelve cuántos octetos de payload faltan por leer.
pub fn payload_len(header: &[u8; HEADER_LEN]) -> Result<usize, MmsError> {
    if header[0] != VERSION {
        return Err(MmsError::Transport(format!(
            "versión TPKT inesperada: {:#04X}",
            header[0]
        )));
    }
    let total = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total < HEADER_LEN {
        return Err(MmsError::Transport(format!(
            "longitud TPKT inválida: {total}"
        )));
    }
    let payload = total - HEADER_LEN;
    if payload > MAX_PAYLOAD_LEN {
        return Err(MmsError::Transport(format!(
            "payload TPKT excede el máximo ({payload} > {MAX_PAYLOAD_LEN})"
        )));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_and_length() {
        let framed = frame(&[0xAA, 0xBB]);
        assert_eq!(framed, vec![0x03, 0x00, 0x00, 0x06, 0xAA, 0xBB]);
        let header: [u8; 4] = framed[..4].try_into().unwrap();
        assert_eq!(payload_len(&header).unwrap(), 2);
    }

    #[test]
    fn rejects_bad_version() {
        assert!(payload_len(&[0x04, 0x00, 0x00, 0x04]).is_err());
        assert!(payload_len(&[0x03, 0x00, 0x00, 0x02]).is_err()); // total < 4
    }
}
