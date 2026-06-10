//! Codificación de longitud BER (forma corta y larga definida).

use crate::error::BerError;

/// Codifica una longitud en `out` (forma corta si <128, larga definida si no).
pub fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first_nonzero..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Número de octetos que ocupará la longitud `len` codificada.
pub fn len_encoded_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        let bytes = len.to_be_bytes();
        let first_nonzero = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        1 + (bytes.len() - first_nonzero)
    }
}

/// Decodifica una longitud desde el inicio de `data`.
/// Devuelve `(longitud, octetos consumidos)`. Rechaza la forma indefinida.
pub fn decode_len(data: &[u8]) -> Result<(usize, usize), BerError> {
    let first = *data.first().ok_or(BerError::UnexpectedEof)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    if first == 0x80 {
        return Err(BerError::IndefiniteLength);
    }
    let n = (first & 0x7F) as usize;
    if n > std::mem::size_of::<usize>() {
        return Err(BerError::LengthOverflow);
    }
    let mut len: usize = 0;
    for i in 0..n {
        let b = *data.get(1 + i).ok_or(BerError::UnexpectedEof)?;
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(len: usize, expected: &[u8]) {
        let mut out = Vec::new();
        encode_len(&mut out, len);
        assert_eq!(out, expected, "encode len {len}");
        assert_eq!(len_encoded_size(len), out.len());
        let (decoded, n) = decode_len(&out).unwrap();
        assert_eq!(decoded, len);
        assert_eq!(n, out.len());
    }

    #[test]
    fn short_form() {
        round(0, &[0x00]);
        round(1, &[0x01]);
        round(127, &[0x7F]);
    }

    #[test]
    fn long_form() {
        round(128, &[0x81, 0x80]);
        round(200, &[0x81, 0xC8]);
        round(255, &[0x81, 0xFF]);
        round(256, &[0x82, 0x01, 0x00]);
        round(65535, &[0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn indefinite_rejected() {
        assert_eq!(decode_len(&[0x80]), Err(BerError::IndefiniteLength));
    }
}
