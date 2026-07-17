#![no_main]
//! Fuzz del decodificador de PDU GOOSE. Las tramas GOOSE llegan por multicast
//! de capa 2 sin autenticación: cualquiera en el segmento puede inyectarlas.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iec61850_goose::GoosePdu::decode(data);
});
