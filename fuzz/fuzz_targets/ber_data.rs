#![no_main]
//! Fuzz del decodificador de `Data` de MMS (BER). Es la superficie que procesa
//! los valores que llegan de un servidor/publicador no confiable. El objetivo:
//! ningún panic, OOM ni desbordamiento de pila para NINGUNA entrada.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iec61850_ber::data::decode_data(data);
});
