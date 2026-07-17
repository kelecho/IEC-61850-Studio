#![no_main]
//! Fuzz de la pila de transporte entrante: longitud TPKT (RFC 1006) y TPDUs
//! COTP (X.224). Primer eslabón que toca un byte del socket.
use iec61850_mms::transport::{cotp, tpkt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= tpkt::HEADER_LEN {
        let header: [u8; tpkt::HEADER_LEN] = data[..tpkt::HEADER_LEN].try_into().unwrap();
        let _ = tpkt::payload_len(&header);
    }
    // El resto del buffer, como si fuera una TPDU COTP cruda.
    let _ = cotp::parse_connection_request(data);
    let _ = cotp::parse_connection_confirm(data);
    let _ = cotp::parse_data_tpdu(data);
    let _ = cotp::parse_data_tpdu_eot(data);
});
