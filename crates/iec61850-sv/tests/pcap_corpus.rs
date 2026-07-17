//! Corpus PCAP de regresión para el codec Sampled Values (9-2 / 9-2LE).
//!
//! `fixtures/pcap/sv.pcap` es una captura **congelada** con ASDUs SV
//! deterministas: sin VLAN, con VLAN y firmada (IEC 62351-6). `corpus_matches_and_decodes`
//! comprueba que el codec produce exactamente esos bytes y los decodifica a los
//! campos esperados (incl. el dataset 9-2LE).
//!
//! Regenerar tras un cambio de formato *intencionado*:
//! `cargo test -p iec61850-sv --features net --test pcap_corpus regenerate -- --ignored`
#![cfg(feature = "net")]

use std::path::PathBuf;

use iec61850_ber::UtcTime;
use iec61850_sv::frame::SvFrame;
use iec61850_sv::pdu::{Asdu, SvPdu};
use iec61850_sv::{
    AuthStatus, HmacKey, LINKTYPE_ETHERNET, MacAddr, NineTwoLe, PcapReader, PcapWriter, SvChannel,
    VlanTag,
};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
const SRC: MacAddr = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
const CORPUS_KEY: &[u8] = b"corpus-sv-62351-6";

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap/sv.pcap")
}

fn nine_two_le() -> NineTwoLe {
    let mut n = NineTwoLe::default();
    n.channels[0] = SvChannel {
        value: 1234,
        quality: 0,
    };
    n.channels[4] = SvChannel {
        value: -5678,
        quality: 0,
    };
    n
}

fn asdu(smp_cnt: u16) -> Asdu {
    let mut a = Asdu {
        sv_id: "MU01".into(),
        dat_set: None,
        smp_cnt,
        conf_rev: 1,
        refr_tm: Some(UtcTime {
            raw: [0x66, 0, 0, 0, 0, 0, 0, 0x0A],
        }),
        smp_synch: 2,
        smp_rate: Some(4000),
        sample: Vec::new(),
        smp_mod: None,
    };
    a.set_9_2le(&nine_two_le());
    a
}

fn frame(vlan: Option<VlanTag>, smp_cnt: u16) -> SvFrame {
    SvFrame {
        dst: DST,
        src: SRC,
        vlan,
        appid: 0x4000,
        simulation: false,
        pdu: SvPdu {
            no_asdu: 1,
            asdus: vec![asdu(smp_cnt)],
        },
    }
}

fn corpus_packets() -> Vec<(u32, u32, Vec<u8>)> {
    let key = HmacKey::new(CORPUS_KEY);
    vec![
        (1_700_000_000, 0, frame(None, 0).encode()),
        (
            1_700_000_000,
            250,
            frame(Some(VlanTag::new(50)), 1).encode(),
        ),
        (1_700_000_000, 500, frame(None, 2).encode_signed(&key)),
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
    let bytes = std::fs::read(corpus_path()).expect("fixtures/pcap/sv.pcap presente");
    let reader = PcapReader::new(bytes).expect("pcap válido");
    assert_eq!(reader.linktype, LINKTYPE_ETHERNET);
    let packets: Vec<_> = reader.collect();
    let expected = corpus_packets();
    assert_eq!(packets.len(), expected.len());

    for (pkt, (sec, _usec, data)) in packets.iter().zip(&expected) {
        assert_eq!(pkt.ts_sec, *sec);
        assert_eq!(&pkt.data, data, "bytes de trama SV divergen del corpus");
    }

    // Decodificación + campos esperados (incl. 9-2LE).
    let plain = SvFrame::decode(&packets[0].data).expect("decodifica SV");
    assert_eq!(plain.vlan, None);
    let a = &plain.pdu.asdus[0];
    assert_eq!(a.sv_id, "MU01");
    assert_eq!(a.smp_cnt, 0);
    let dec = a.as_9_2le().expect("dataset 9-2LE");
    assert_eq!(dec.channels[0].value, 1234);
    assert_eq!(dec.channels[4].value, -5678);

    let vlan = SvFrame::decode(&packets[1].data).expect("decodifica SV VLAN");
    assert_eq!(vlan.vlan, Some(VlanTag::new(50)));
    assert_eq!(vlan.pdu.asdus[0].smp_cnt, 1);

    // Firmada (IEC 62351-6).
    let key = HmacKey::new(CORPUS_KEY);
    let (signed, status) =
        SvFrame::decode_verified(&packets[2].data, &key).expect("decodifica SV firmada");
    assert_eq!(status, AuthStatus::Valid);
    assert_eq!(signed.pdu.asdus[0].smp_cnt, 2);
    let (_, bad) = SvFrame::decode_verified(&packets[2].data, &HmacKey::new(b"otra")).unwrap();
    assert_eq!(bad, AuthStatus::Invalid);
}
