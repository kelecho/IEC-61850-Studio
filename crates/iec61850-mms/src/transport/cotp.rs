//! COTP (ISO 8073 / RFC 905), clase 0: las TPDU mínimas que MMS necesita —
//! Connection Request (CR), Connection Confirm (CC) y Data (DT).

use crate::error::MmsError;

const CR_CODE: u8 = 0xE0;
const CC_CODE: u8 = 0xD0;
const DT_CODE: u8 = 0xF0;
const DR_CODE: u8 = 0x80; // Disconnect Request (rechazo de conexión COTP)

const PARAM_TPDU_SIZE: u8 = 0xC0;
const PARAM_SRC_TSAP: u8 = 0xC1;
const PARAM_DST_TSAP: u8 = 0xC2;

/// T-selector por defecto (calling/called). Valor habitual en clientes MMS.
const DEFAULT_TSEL: [u8; 2] = [0x00, 0x01];
/// Tamaño máximo de TPDU propuesto: `0x0A` = 1024 octetos.
const TPDU_SIZE_CODE: u8 = 0x0A;
/// TPDU-size asumido cuando el peer no incluye el parámetro en la CC.
pub const DEFAULT_TPDU_SIZE: usize = 1024;
/// Códigos de TPDU-size válidos (X.224 §13.3.4): 2^code octetos, de 128 a 8192.
const MIN_TPDU_SIZE_CODE: u8 = 7;
const MAX_TPDU_SIZE_CODE: u8 = 13;

/// Construye una Connection Request (CR) COTP (sin la cabecera TPKT).
pub fn connection_request(src_ref: u16) -> Vec<u8> {
    let src = src_ref.to_be_bytes();
    // parte variable: TPDU-size + TSAP llamante + TSAP llamado
    let params: [u8; 11] = [
        PARAM_TPDU_SIZE,
        0x01,
        TPDU_SIZE_CODE,
        PARAM_SRC_TSAP,
        0x02,
        DEFAULT_TSEL[0],
        DEFAULT_TSEL[1],
        PARAM_DST_TSAP,
        0x02,
        DEFAULT_TSEL[0],
        DEFAULT_TSEL[1],
    ];
    // cabecera fija tras LI: code(1) + dst-ref(2) + src-ref(2) + class(1)
    let li = 6 + params.len() as u8;
    let mut out = Vec::with_capacity(1 + li as usize);
    out.push(li);
    out.push(CR_CODE);
    out.extend_from_slice(&[0x00, 0x00]); // dst-ref
    out.extend_from_slice(&src); // src-ref
    out.push(0x00); // class 0, opciones
    out.extend_from_slice(&params);
    out
}

/// Parsea una Connection Request (CR) entrante y devuelve el `src-ref` del
/// cliente (que el servidor usará como `dst-ref` en la CC).
pub fn parse_connection_request(data: &[u8]) -> Result<u16, MmsError> {
    let li = *data.first().ok_or_else(|| transport("CR vacía"))? as usize;
    let code = *data.get(1).ok_or_else(|| transport("CR truncada"))?;
    if code & 0xF0 != CR_CODE {
        return Err(transport(&format!("se esperaba CR, código {code:#04X}")));
    }
    if 1 + li > data.len() {
        return Err(transport("LI de CR inconsistente"));
    }
    let src = data.get(4..6).ok_or_else(|| transport("CR sin src-ref"))?;
    Ok(u16::from_be_bytes([src[0], src[1]]))
}

/// Construye una Connection Confirm (CC): `dst-ref` = src-ref del cliente,
/// `src-ref` = el del servidor.
pub fn connection_confirm(client_src_ref: u16, our_src_ref: u16) -> Vec<u8> {
    let dst = client_src_ref.to_be_bytes();
    let src = our_src_ref.to_be_bytes();
    let params: [u8; 11] = [
        PARAM_TPDU_SIZE,
        0x01,
        TPDU_SIZE_CODE,
        PARAM_SRC_TSAP,
        0x02,
        DEFAULT_TSEL[0],
        DEFAULT_TSEL[1],
        PARAM_DST_TSAP,
        0x02,
        DEFAULT_TSEL[0],
        DEFAULT_TSEL[1],
    ];
    let li = 6 + params.len() as u8;
    let mut out = Vec::with_capacity(1 + li as usize);
    out.push(li);
    out.push(CC_CODE);
    out.extend_from_slice(&dst); // dst-ref = src-ref del cliente
    out.extend_from_slice(&src); // src-ref propio
    out.push(0x00); // class 0
    out.extend_from_slice(&params);
    out
}

/// Valida una Connection Confirm (CC) recibida y devuelve el **TPDU-size
/// negociado** (en octetos). Si la CC no incluye el parámetro, se asume
/// [`DEFAULT_TPDU_SIZE`].
///
/// Antes esta función solo comprobaba el código; un peer que respondiera una
/// Disconnect Request (DR) o que negociara un tamaño distinto pasaba inadvertido.
/// Ahora se distingue una DR explícita y se extrae el tamaño acordado.
pub fn parse_connection_confirm(data: &[u8]) -> Result<usize, MmsError> {
    let li = *data.first().ok_or_else(|| transport("CC vacía"))? as usize;
    let code = *data.get(1).ok_or_else(|| transport("CC truncada"))?;
    if code & 0xF0 == DR_CODE {
        return Err(MmsError::AssociateRejected(
            "el peer respondió Disconnect Request (DR) a la conexión COTP".into(),
        ));
    }
    if code & 0xF0 != CC_CODE {
        return Err(transport(&format!("se esperaba CC, código {code:#04X}")));
    }
    if 1 + li > data.len() {
        return Err(transport("LI de CC inconsistente"));
    }
    // Parte variable: empieza tras LI(1) + cabecera fija(6) = offset 7, y termina
    // en 1 + li.
    let params = data.get(7..1 + li).unwrap_or(&[]);
    Ok(tpdu_size_from_params(params))
}

/// Recorre los parámetros de la parte variable de una CR/CC buscando el
/// TPDU-size (`0xC0`). Devuelve el tamaño en octetos, o [`DEFAULT_TPDU_SIZE`] si
/// no aparece o es inválido.
fn tpdu_size_from_params(mut params: &[u8]) -> usize {
    while params.len() >= 2 {
        let ptype = params[0];
        let plen = params[1] as usize;
        let Some(value) = params.get(2..2 + plen) else {
            break;
        };
        if ptype == PARAM_TPDU_SIZE && plen == 1 {
            let code = value[0];
            if (MIN_TPDU_SIZE_CODE..=MAX_TPDU_SIZE_CODE).contains(&code) {
                return 1usize << code;
            }
        }
        params = &params[2 + plen..];
    }
    DEFAULT_TPDU_SIZE
}

/// Antepone la cabecera de una TPDU de datos (DT) a `payload`.
///
/// OJO: no fragmenta. Para TSDUs que pueden superar el TPDU size negociado,
/// usa [`data_tpdus`] (un peer conforme aborta ante una DT sobredimensionada).
pub fn data_tpdu(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(0x02); // LI
    out.push(DT_CODE); // DT
    out.push(0x80); // EOT=1, TPDU-NR=0
    out.extend_from_slice(payload);
    out
}

/// Trocea un TSDU en las DT TPDUs necesarias para respetar `max_tpdu` (tamaño
/// máximo de TPDU en octetos, cabecera COTP incluida), marcando **EOT solo en
/// la última** (ISO 8073 clase 0). Interop: libiec61850 aborta la conexión si
/// recibe una DT mayor que el TPDU size negociado (p. ej. al servirle un bloque
/// de fichero de 8 KiB con TPDU de 1024).
pub fn data_tpdus(payload: &[u8], max_tpdu: usize) -> Vec<Vec<u8>> {
    let chunk = max_tpdu.saturating_sub(3).max(1);
    if payload.len() <= chunk {
        return vec![data_tpdu(payload)];
    }
    let mut out = Vec::with_capacity(payload.len().div_ceil(chunk));
    let mut it = payload.chunks(chunk).peekable();
    while let Some(c) = it.next() {
        let eot = it.peek().is_none();
        let mut t = Vec::with_capacity(3 + c.len());
        t.push(0x02); // LI
        t.push(DT_CODE);
        t.push(if eot { 0x80 } else { 0x00 });
        t.extend_from_slice(c);
        out.push(t);
    }
    out
}

/// Extrae el payload (datos de usuario) de una TPDU de datos (DT).
pub fn parse_data_tpdu(data: &[u8]) -> Result<&[u8], MmsError> {
    Ok(parse_data_tpdu_eot(data)?.0)
}

/// Como [`parse_data_tpdu`] pero devuelve también el bit **EOT** (End Of TSDU).
///
/// COTP clase 0 fragmenta los TSDU grandes en varias DT TPDUs; solo la última
/// lleva EOT=1. El reensamblado en la capa de conexión usa este bit para saber
/// cuándo el mensaje (p.ej. una respuesta GetNameList grande) está completo. Sin
/// esto, una respuesta fragmentada de un IED real se truncaba al primer
/// fragmento.
pub fn parse_data_tpdu_eot(data: &[u8]) -> Result<(&[u8], bool), MmsError> {
    let li = *data.first().ok_or_else(|| transport("DT vacía"))? as usize;
    let code = *data.get(1).ok_or_else(|| transport("DT truncada"))?;
    if code != DT_CODE {
        return Err(transport(&format!("se esperaba DT, código {code:#04X}")));
    }
    // Octeto EOT/TPDU-NR (justo tras el código). EOT = bit 0x80.
    let eot = data.get(2).map(|b| b & 0x80 != 0).unwrap_or(true);
    let start = 1 + li;
    let payload = data
        .get(start..)
        .ok_or_else(|| transport("LI de DT inconsistente"))?;
    Ok((payload, eot))
}

fn transport(msg: &str) -> MmsError {
    MmsError::Transport(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_structure() {
        let cr = connection_request(0x1234);
        assert_eq!(cr[0], 17); // LI = 6 + 11
        assert_eq!(cr[1], CR_CODE);
        assert_eq!(&cr[2..4], &[0x00, 0x00]); // dst-ref
        assert_eq!(&cr[4..6], &[0x12, 0x34]); // src-ref
        assert_eq!(cr[6], 0x00); // class
        assert_eq!(&cr[7..10], &[PARAM_TPDU_SIZE, 0x01, TPDU_SIZE_CODE]);
        assert_eq!(cr.len(), 18);
    }

    #[test]
    fn cr_server_round_trip() {
        // el servidor parsea la CR del cliente y responde una CC coherente
        let cr = connection_request(0x1234);
        let client_ref = parse_connection_request(&cr).unwrap();
        assert_eq!(client_ref, 0x1234);
        let cc = connection_confirm(client_ref, 0x0002);
        assert_eq!(cc[1], CC_CODE);
        assert_eq!(&cc[2..4], &[0x12, 0x34]); // dst-ref = src del cliente
        assert_eq!(&cc[4..6], &[0x00, 0x02]); // src-ref del servidor
        parse_connection_confirm(&cc).unwrap(); // el cliente la acepta
    }

    #[test]
    fn cc_validation() {
        // CC mínima: LI=6, code=0xD0, dst, src, class → sin parámetro de tamaño
        // se asume el valor por defecto.
        let cc = [0x06, 0xD0, 0x00, 0x01, 0x12, 0x34, 0x00];
        assert_eq!(parse_connection_confirm(&cc).unwrap(), DEFAULT_TPDU_SIZE);
        // un CR no es CC
        assert!(parse_connection_confirm(&[0x06, 0xE0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn cc_negotiated_tpdu_size() {
        // El servidor negocia 0x0B = 2048 octetos en la CC.
        let cc = connection_confirm(0x1234, 0x0002);
        // connection_confirm propone 0x0A (1024) por defecto.
        assert_eq!(parse_connection_confirm(&cc).unwrap(), 1024);

        // CC fabricada con TPDU-size 0x0B (2048).
        let cc2 = [
            0x09,
            CC_CODE,
            0x12,
            0x34,
            0x00,
            0x02,
            0x00, // hasta class
            PARAM_TPDU_SIZE,
            0x01,
            0x0B, // 2^11 = 2048
        ];
        assert_eq!(parse_connection_confirm(&cc2).unwrap(), 2048);
    }

    #[test]
    fn cc_disconnect_request_is_rejected() {
        // Un peer que rechaza la conexión COTP responde DR (0x80).
        let dr = [0x06, DR_CODE, 0x00, 0x01, 0x12, 0x34, 0x00];
        match parse_connection_confirm(&dr) {
            Err(MmsError::AssociateRejected(_)) => {}
            other => panic!("se esperaba AssociateRejected, fue {other:?}"),
        }
    }

    #[test]
    fn dt_eot_bit() {
        // EOT=1 (0x80) → fragmento final.
        let final_frag = data_tpdu(&[0xAA, 0xBB]);
        let (payload, eot) = parse_data_tpdu_eot(&final_frag).unwrap();
        assert_eq!(payload, &[0xAA, 0xBB]);
        assert!(eot);

        // EOT=0 → fragmento intermedio (NR=0, sin bit 0x80).
        let mid = [0x02u8, DT_CODE, 0x00, 0xCC, 0xDD];
        let (payload, eot) = parse_data_tpdu_eot(&mid).unwrap();
        assert_eq!(payload, &[0xCC, 0xDD]);
        assert!(!eot);
    }

    #[test]
    fn dt_round_trip() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let dt = data_tpdu(&payload);
        assert_eq!(&dt[..3], &[0x02, 0xF0, 0x80]);
        assert_eq!(parse_data_tpdu(&dt).unwrap(), &payload);
    }
}

#[cfg(test)]
mod frag_tests {
    use super::*;

    #[test]
    fn data_tpdus_fragments_and_reassembles() {
        // TSDU de 2500 octetos con TPDU de 1024 ⇒ 3 fragmentos, EOT solo al final.
        let tsdu: Vec<u8> = (0..2500u32).map(|i| (i % 256) as u8).collect();
        let frags = data_tpdus(&tsdu, DEFAULT_TPDU_SIZE);
        assert_eq!(frags.len(), 3);
        for (i, f) in frags.iter().enumerate() {
            assert!(
                f.len() <= DEFAULT_TPDU_SIZE,
                "fragmento {i} excede el TPDU size"
            );
            let (payload, eot) = parse_data_tpdu_eot(f).unwrap();
            assert_eq!(eot, i == frags.len() - 1, "EOT solo en el último");
            assert!(!payload.is_empty());
        }
        // Reensamblado == original.
        let rebuilt: Vec<u8> = frags
            .iter()
            .flat_map(|f| parse_data_tpdu_eot(f).unwrap().0.to_vec())
            .collect();
        assert_eq!(rebuilt, tsdu);
    }

    #[test]
    fn data_tpdus_small_single_fragment() {
        let frags = data_tpdus(b"abc", DEFAULT_TPDU_SIZE);
        assert_eq!(frags.len(), 1);
        let (p, eot) = parse_data_tpdu_eot(&frags[0]).unwrap();
        assert_eq!(p, b"abc");
        assert!(eot);
    }
}
