#![no_main]
//! Fuzz del decodificador de PDU Sampled Values. Igual que GOOSE: multicast L2
//! no autenticado, entrada plenamente hostil.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iec61850_sv::SvPdu::decode(data);
});
