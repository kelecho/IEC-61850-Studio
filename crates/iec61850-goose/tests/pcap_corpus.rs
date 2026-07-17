//! Corpus PCAP de regresión para el codec GOOSE.
//!
//! `fixtures/pcap/goose.pcap` es una captura **congelada** (generada por
//! `regenerate_corpus`, un test `#[ignore]`) con tramas GOOSE deterministas:
//! sin VLAN, con VLAN y firmada (IEC 62351-6). El test `corpus_matches_and_decodes`
//! comprueba que el codec sigue produciendo exactamente esos bytes y que los
//! decodifica a los campos esperados: cualquier cambio incompatible del formato de
//! trama rompe el test.
//!
//! Para regenerar tras un cambio de formato *intencionado*:
//! `cargo test -p iec61850-goose --features net --test pcap_corpus regenerate -- --ignored`
#![cfg(feature = "net")]

use std::path::PathBuf;

use iec61850_goose::frame::{GooseFrame, MacAddr};
use iec61850_goose::pdu::GoosePdu;
use iec61850_goose::{
    AuthStatus, HmacKey, LINKTYPE_ETHERNET, MmsData, PcapReader, PcapWriter, UtcTime, VlanTag,
};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
const SRC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// Clave HMAC del corpus (fija; solo para reproducir la trama firmada).
const CORPUS_KEY: &[u8] = b"corpus-goose-62351-6";

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap/goose.pcap")
}

fn sample_pdu(st_num: u32, values: Vec<MmsData>) -> GoosePdu {
    GoosePdu {
        gocb_ref: "IED1LD0/LLN0.GO$gcb01".into(),
        time_allowed_to_live: 2000,
        dat_set: "IED1LD0/LLN0$ds1".into(),
        go_id: "gcb01".into(),
        t: UtcTime {
            raw: [0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A],
        },
        st_num,
        sq_num: 0,
        test: false,
        conf_rev: 1,
        nds_com: false,
        num_dat_set_entries: values.len() as u32,
        all_data: values,
    }
}

/// Las tramas del corpus, con su marca de tiempo determinista.
/// Devuelve `(ts_sec, ts_usec, bytes)`.
fn corpus_packets() -> Vec<(u32, u32, Vec<u8>)> {
    let base = GooseFrame {
        dst: DST,
        src: SRC,
        vlan: None,
        appid: 0x0001,
        simulation: false,
        pdu: sample_pdu(1, vec![MmsData::Bool(true), MmsData::Int(42)]),
    };
    // (1) GOOSE sin VLAN.
    let plain = base.clone();
    // (2) GOOSE con VLAN (prioridad 4).
    let vlan = GooseFrame {
        vlan: Some(VlanTag::new(100)),
        pdu: sample_pdu(2, vec![MmsData::Bool(false)]),
        ..base.clone()
    };
    // (3) GOOSE firmada (IEC 62351-6, HMAC-SHA256).
    let signed = GooseFrame {
        pdu: sample_pdu(3, vec![MmsData::Int(-7)]),
        ..base.clone()
    };
    let key = HmacKey::new(CORPUS_KEY);

    vec![
        (1_700_000_000, 0, plain.encode()),
        (1_700_000_000, 100, vlan.encode()),
        (1_700_000_001, 0, signed.encode_signed(&key)),
    ]
}

#[test]
#[ignore = "regenera el fixture congelado; correr a mano tras un cambio de formato"]
fn regenerate_corpus() {
    let mut w = PcapWriter::new(Vec::new()).unwrap();
    for (sec, usec, data) in corpus_packets() {
        w.write_packet(sec, usec, &data).unwrap();
    }
    std::fs::create_dir_all(corpus_path().parent().unwrap()).unwrap();
    std::fs::write(corpus_path(), w.into_inner()).unwrap();
}

#[test]
fn corpus_matches_and_decodes() {
    let bytes = std::fs::read(corpus_path()).expect("fixtures/pcap/goose.pcap presente");
    let reader = PcapReader::new(bytes).expect("pcap válido");
    assert_eq!(reader.linktype, LINKTYPE_ETHERNET);
    let packets: Vec<_> = reader.collect();
    let expected = corpus_packets();

    assert_eq!(
        packets.len(),
        expected.len(),
        "el corpus debe tener {} tramas",
        expected.len()
    );

    // Byte-exacto contra las tramas deterministas: congela el ENCODER.
    for (pkt, (sec, _usec, data)) in packets.iter().zip(&expected) {
        assert_eq!(pkt.ts_sec, *sec);
        assert_eq!(&pkt.data, data, "bytes de trama divergen del corpus");
    }

    // Decodificación: congela el DECODER y los campos esperados.
    let plain = GooseFrame::decode(&packets[0].data).expect("decodifica sin VLAN");
    assert_eq!(plain.vlan, None);
    assert_eq!(plain.pdu.st_num, 1);
    assert_eq!(
        plain.pdu.all_data,
        vec![MmsData::Bool(true), MmsData::Int(42)]
    );

    let vlan = GooseFrame::decode(&packets[1].data).expect("decodifica con VLAN");
    assert_eq!(vlan.vlan, Some(VlanTag::new(100)));
    assert_eq!(vlan.pdu.st_num, 2);

    // La trama firmada verifica con la clave del corpus y falla con otra.
    let key = HmacKey::new(CORPUS_KEY);
    let (signed, status) =
        GooseFrame::decode_verified(&packets[2].data, &key).expect("decodifica firmada");
    assert_eq!(status, AuthStatus::Valid);
    assert_eq!(signed.pdu.st_num, 3);
    assert_eq!(signed.pdu.all_data, vec![MmsData::Int(-7)]);
    let (_, bad) = GooseFrame::decode_verified(&packets[2].data, &HmacKey::new(b"otra")).unwrap();
    assert_eq!(bad, AuthStatus::Invalid);
}
