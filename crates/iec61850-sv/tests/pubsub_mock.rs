//! Publicador ↔ suscriptor SV sobre `MockLink`, con el reloj de tokio pausado.
#![cfg(feature = "net")]

use std::time::Duration;

use iec61850_sv::frame::SvFrame;
use iec61850_sv::pdu::{Asdu, SvPdu};
use iec61850_sv::{
    AuthStatus, HmacKey, L2Link, MacAddr, MockBus, NineTwoLe, SvChannel, SvConfig, SvEventKind,
    SvFilter, SvPublisher, SvSubscriber,
};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
const SRC: MacAddr = [0, 1, 2, 3, 4, 5];

fn config() -> SvConfig {
    let mut c = SvConfig::new(DST, SRC, 0x4000, "MU01");
    c.sample_period = Duration::from_micros(250);
    c.smp_cnt_wrap = 4;
    c
}

#[tokio::test(start_paused = true)]
async fn publish_and_track() {
    let bus = MockBus::new();
    let publisher = SvPublisher::new(bus.link(), config());
    let mut sub = SvSubscriber::new(bus.link(), SvFilter::default()).start();
    let handle = publisher.start();

    let mut n = NineTwoLe::default();
    n.channels[0] = SvChannel {
        value: 1234,
        quality: 0,
    };
    handle.set_9_2le(&n);

    // Primer tick → smpCnt=0.
    tokio::time::advance(Duration::from_micros(250)).await;
    let ev = sub.recv_sample().await.unwrap();
    assert_eq!(ev.smp_cnt, 0);
    assert_eq!(ev.kind, SvEventKind::Sample);
    assert_eq!(ev.decoded_9_2le.unwrap().channels[0].value, 1234);

    // Siguientes muestras incrementan smpCnt.
    for expected in 1..=3 {
        tokio::time::advance(Duration::from_micros(250)).await;
        let ev = sub.recv_sample().await.unwrap();
        assert_eq!(ev.smp_cnt, expected);
        assert_eq!(ev.kind, SvEventKind::Sample);
    }

    // El quinto tick envuelve smpCnt a 0 (wrap=4).
    tokio::time::advance(Duration::from_micros(250)).await;
    let ev = sub.recv_sample().await.unwrap();
    assert_eq!(ev.smp_cnt, 0);
    assert_eq!(ev.kind, SvEventKind::Wrap);

    handle.stop().await;
    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn detects_loss() {
    let bus = MockBus::new();
    let injector = bus.link();
    let mut sub = SvSubscriber::new(bus.link(), SvFilter::default()).start();

    injector.send(&frame(0)).await.unwrap();
    assert_eq!(sub.recv_sample().await.unwrap().kind, SvEventKind::Sample);

    // smpCnt salta 0 → 5 → pérdida.
    injector.send(&frame(5)).await.unwrap();
    assert_eq!(
        sub.recv_sample().await.unwrap().kind,
        SvEventKind::SampleLoss {
            expected: 1,
            got: 5
        }
    );

    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn signed_publisher_verified_by_subscriber() {
    // IEC 62351-6: publicador SV firmado con HMAC-SHA256; el suscriptor legítimo
    // (misma clave) procesa las muestras, el de clave errónea las marca AuthFailed.
    let bus = MockBus::new();
    let key = HmacKey::new(b"clave-sv-subestacion");
    let publisher = SvPublisher::new(bus.link(), config().with_security(key.clone()));

    let mut good = SvSubscriber::new(bus.link(), SvFilter::default())
        .security(key)
        .start();
    let mut bad = SvSubscriber::new(bus.link(), SvFilter::default())
        .security(HmacKey::new(b"clave-erronea"))
        .start();

    let handle = publisher.start();
    let mut n = NineTwoLe::default();
    n.channels[0] = SvChannel {
        value: 4321,
        quality: 0,
    };
    handle.set_9_2le(&n);

    tokio::time::advance(Duration::from_micros(250)).await;
    let ev = good.recv_sample().await.unwrap();
    assert_eq!(ev.kind, SvEventKind::Sample);
    assert_eq!(ev.decoded_9_2le.unwrap().channels[0].value, 4321);

    let ev = bad.recv_sample().await.unwrap();
    assert_eq!(
        ev.kind,
        SvEventKind::AuthFailed {
            status: AuthStatus::Invalid
        }
    );

    handle.stop().await;
    good.stop().await;
    bad.stop().await;
}

#[cfg(feature = "ecdsa")]
#[tokio::test(start_paused = true)]
async fn ecdsa_signed_publisher_verified_by_subscriber() {
    use iec61850_sv::EcdsaSigner;

    // IEC 62351-6:2020: publicador SV firmado con ECDSA P-256; el suscriptor con
    // la clave pública correcta procesa; con otra, AuthFailed.
    let bus = MockBus::new();
    let signer = EcdsaSigner::from_scalar(&[0x2A; 32]).unwrap();
    let verifier = signer.verifier();
    let publisher = SvPublisher::new(bus.link(), config().with_security(signer));

    let mut good = SvSubscriber::new(bus.link(), SvFilter::default())
        .security(verifier)
        .start();
    let other = EcdsaSigner::from_scalar(&[0x3B; 32]).unwrap().verifier();
    let mut bad = SvSubscriber::new(bus.link(), SvFilter::default())
        .security(other)
        .start();

    let handle = publisher.start();
    let mut n = NineTwoLe::default();
    n.channels[0] = SvChannel {
        value: 777,
        quality: 0,
    };
    handle.set_9_2le(&n);

    tokio::time::advance(Duration::from_micros(250)).await;
    let ev = good.recv_sample().await.unwrap();
    assert_eq!(ev.kind, SvEventKind::Sample);
    assert_eq!(ev.decoded_9_2le.unwrap().channels[0].value, 777);

    let ev = bad.recv_sample().await.unwrap();
    assert_eq!(
        ev.kind,
        SvEventKind::AuthFailed {
            status: AuthStatus::Invalid
        }
    );

    handle.stop().await;
    good.stop().await;
    bad.stop().await;
}

fn frame(smp_cnt: u16) -> Vec<u8> {
    let mut a = Asdu {
        sv_id: "MU01".into(),
        dat_set: None,
        smp_cnt,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: 2,
        smp_rate: Some(4000),
        sample: Vec::new(),
        smp_mod: None,
    };
    a.set_9_2le(&NineTwoLe::default());
    SvFrame {
        dst: DST,
        src: SRC,
        vlan: None,
        appid: 0x4000,
        simulation: false,
        pdu: SvPdu {
            no_asdu: 1,
            asdus: vec![a],
        },
    }
    .encode()
}
