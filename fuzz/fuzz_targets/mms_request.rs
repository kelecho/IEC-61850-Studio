#![no_main]
//! Fuzz del lado servidor de MMS: parseo de PDUs entrantes (Initiate + peticiones
//! confirmadas). Modela a un cliente hostil enviando PDUs arbitrarias tras el
//! handshake de transporte.
use iec61850_mms::mms::{initiate, pdu};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = initiate::InitiateRequest::decode(data);
    let _ = pdu::peek_request_kind(data);
    let _ = pdu::peek_invoke_and_kind(data);
    if let Ok((_invoke, service_tlv)) = pdu::parse_confirmed_request(data) {
        // Ejercita los decodificadores de servicio sobre el TLV extraído.
        let _ = iec61850_mms::mms::read::decode_request(&service_tlv);
        let _ = iec61850_mms::mms::read::decode_response(&service_tlv);
        let _ = iec61850_mms::mms::get_name_list::decode_request(&service_tlv);
        let _ = iec61850_mms::mms::write::decode_request(&service_tlv);
        let _ = iec61850_mms::mms::type_attr::decode_request(&service_tlv);
    }
    let _ = pdu::parse_unconfirmed(data);
});
