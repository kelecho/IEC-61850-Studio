//! Publicador ↔ suscriptor GOOSE sobre `MockLink`, con el reloj de tokio
//! pausado para verificar la retransmisión sin esperas reales.
#![cfg(feature = "net")]

use std::time::Duration;

use iec61850_goose::GooseFilter;
use iec61850_goose::frame::{GooseFrame, MacAddr};
use iec61850_goose::pdu::GoosePdu;
use iec61850_goose::{
    AuthStatus, GooseConfig, GooseEventKind, GoosePublisher, GooseSubscriber, HmacKey, KeyRing,
    MmsData, MockBus,
};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
const SRC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn config() -> GooseConfig {
    let mut c = GooseConfig::new(DST, SRC, 0x0001, "IED1LD0/LLN0.GO$gcb01");
    c.dat_set = "IED1LD0/LLN0$ds1".into();
    c.go_id = "gcb01".into();
    c.t_min = Duration::from_millis(4);
    c.t_max = Duration::from_millis(64);
    c
}

#[tokio::test(start_paused = true)]
async fn simulation_bit_propagates() {
    // Un publicador con el bit de simulación (Ed.2) → el suscriptor en modo
    // simulación lo ve. (Sin modo Sim, las tramas simuladas se descartan: ese
    // comportamiento se prueba en `simulation_mode_gates_frames`.)
    let bus = MockBus::new();
    let mut cfg = config();
    cfg.simulation = true;
    let publisher = GoosePublisher::new(bus.link(), cfg);
    let mut sub = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .simulation_mode(true)
        .start();
    let handle = publisher.start();

    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();
    let ev = sub.recv_event().await.unwrap();
    assert!(ev.simulation, "el evento debe marcar simulación");
    handle.stop().await;
    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn simulation_mode_gates_frames() {
    // En modo normal (sim off), un publicador SIMULADO no debe entregar eventos.
    let bus = MockBus::new();
    let mut cfg = config();
    cfg.simulation = true;
    let publisher = GoosePublisher::new(bus.link(), cfg);
    let mut sub = GooseSubscriber::new(bus.link(), GooseFilter::default()).start(); // sim off
    let handle = publisher.start();

    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();
    // Damos tiempo (lógico) a varias retransmisiones; ninguna debe llegar.
    tokio::time::advance(Duration::from_millis(50)).await;
    // El canal no debe tener eventos: usamos un timeout corto para no colgar.
    let got = tokio::time::timeout(Duration::from_millis(10), sub.recv_event()).await;
    assert!(
        got.is_err(),
        "las tramas simuladas deben descartarse sin modo Sim"
    );
    handle.stop().await;
    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn state_change_and_retransmission() {
    let bus = MockBus::new();
    let publisher = GoosePublisher::new(bus.link(), config());
    let mut sub = GooseSubscriber::new(bus.link(), GooseFilter::default()).start();
    let handle = publisher.start();

    // Primer publish → cambio de estado st=1, sq=0.
    handle.publish(vec![MmsData::Bool(false)]).await.unwrap();
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);
    assert_eq!((ev.st_num, ev.sq_num), (1, 0));
    assert_eq!(ev.values, vec![MmsData::Bool(false)]);

    // Retransmisión tras t_min → misma st, sq=1.
    tokio::time::advance(Duration::from_millis(4)).await;
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::Retransmission);
    assert_eq!((ev.st_num, ev.sq_num), (1, 1));

    // Siguiente retransmisión: el intervalo se duplica (8 ms).
    tokio::time::advance(Duration::from_millis(8)).await;
    let ev = sub.recv_event().await.unwrap();
    assert_eq!((ev.st_num, ev.sq_num), (1, 2));

    // Cambio de valor → nuevo estado st=2, sq=0.
    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);
    assert_eq!((ev.st_num, ev.sq_num), (2, 0));
    assert_eq!(ev.values, vec![MmsData::Bool(true)]);

    handle.stop().await;
    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn loss_and_expiry() {
    let bus = MockBus::new();
    let injector = bus.link();
    let mut sub = GooseSubscriber::new(bus.link(), GooseFilter::default()).start();

    use iec61850_goose::link::GooseLink;

    // Trama inicial st=5, sq=0, TTL corto.
    injector.send(&frame(5, 0, 20)).await.unwrap();
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);

    // Salto de sqNum (0 → 3) → pérdida sospechada.
    injector.send(&frame(5, 3, 20)).await.unwrap();
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(
        ev.kind,
        GooseEventKind::LossSuspected {
            expected_sq: 1,
            got_sq: 3
        }
    );

    // Sin más tramas, vence el TTL (20 ms) → Expired.
    tokio::time::advance(Duration::from_millis(25)).await;
    let ev = sub.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::Expired);

    sub.stop().await;
}

#[tokio::test(start_paused = true)]
async fn signed_publisher_verified_by_subscriber() {
    // IEC 62351-6: el publicador firma con HMAC-SHA256; el suscriptor con la misma
    // clave acepta las tramas (Valid); con una clave distinta las marca AuthFailed.
    let bus = MockBus::new();
    let key = HmacKey::new(b"clave-de-la-subestacion");
    let publisher = GoosePublisher::new(bus.link(), config().with_security(key.clone()));

    // Suscriptor legítimo (misma clave): procesa normalmente.
    let mut good = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(key)
        .start();
    // Suscriptor con clave equivocada: ve las tramas como AuthFailed.
    let mut bad = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(HmacKey::new(b"clave-incorrecta"))
        .start();

    let handle = publisher.start();
    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();

    let ev = good.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);
    assert_eq!(ev.values, vec![MmsData::Bool(true)]);

    let ev = bad.recv_event().await.unwrap();
    assert_eq!(
        ev.kind,
        GooseEventKind::AuthFailed {
            status: AuthStatus::Invalid
        },
        "una clave distinta debe fallar la verificación"
    );

    handle.stop().await;
    good.stop().await;
    bad.stop().await;
}

#[tokio::test(start_paused = true)]
async fn unsigned_frame_rejected_when_security_required() {
    // Un publicador SIN firma contra un suscriptor que EXIGE firma: las tramas se
    // entregan como AuthFailed(Unsigned), no como eventos normales.
    let bus = MockBus::new();
    let publisher = GoosePublisher::new(bus.link(), config()); // sin security
    let mut sub = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(HmacKey::new(b"clave"))
        .start();

    let handle = publisher.start();
    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();

    let ev = sub.recv_event().await.unwrap();
    assert_eq!(
        ev.kind,
        GooseEventKind::AuthFailed {
            status: AuthStatus::Unsigned
        }
    );
    handle.stop().await;
    sub.stop().await;
}

#[cfg(feature = "ecdsa")]
#[tokio::test(start_paused = true)]
async fn ecdsa_signed_publisher_verified_by_subscriber() {
    use iec61850_goose::EcdsaSigner;

    // IEC 62351-6:2020: el publicador firma con ECDSA P-256 (clave privada); el
    // suscriptor verifica con la pública. Otra clave pública → AuthFailed.
    let bus = MockBus::new();
    let signer = EcdsaSigner::from_scalar(&[0x2A; 32]).unwrap();
    let verifier = signer.verifier();
    let publisher = GoosePublisher::new(bus.link(), config().with_security(signer));

    let mut good = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(verifier)
        .start();
    let other = EcdsaSigner::from_scalar(&[0x3B; 32]).unwrap().verifier();
    let mut bad = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(other)
        .start();

    let handle = publisher.start();
    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();

    let ev = good.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);
    assert_eq!(ev.values, vec![MmsData::Bool(true)]);

    let ev = bad.recv_event().await.unwrap();
    assert_eq!(
        ev.kind,
        GooseEventKind::AuthFailed {
            status: AuthStatus::Invalid
        }
    );

    handle.stop().await;
    good.stop().await;
    bad.stop().await;
}

#[tokio::test(start_paused = true)]
async fn key_rotation_with_overlap() {
    // IEC 62351-9: el publicador firma con la clave de grupo activa (mayor key_id).
    // Durante una rotación, el suscriptor tiene ambas claves en su anillo, así que
    // acepta las tramas sin cortes; un suscriptor que solo tiene la clave vieja
    // deja de validar (AuthFailed) al rotar.
    let bus = MockBus::new();
    let k1 = HmacKey::new(b"grupo-clave-1");
    let k2 = HmacKey::new(b"grupo-clave-2");

    // Publicador: anillo con la clave 2 como activa (mayor key_id).
    let mut sign_ring = KeyRing::new();
    sign_ring.insert_permanent(1, k1.clone().into());
    sign_ring.insert_permanent(2, k2.clone().into());
    let publisher = GoosePublisher::new(bus.link(), config().with_security(sign_ring));

    // Suscriptor al día: anillo con ambas claves (cubre el solapamiento).
    let up_to_date = KeyRing::new()
        .with_permanent(1, k1.clone().into())
        .with_permanent(2, k2.into());
    let mut good = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(up_to_date)
        .start();
    // Suscriptor rezagado: solo tiene la clave vieja.
    let stale = KeyRing::new().with_permanent(1, k1.into());
    let mut lagging = GooseSubscriber::new(bus.link(), GooseFilter::default())
        .security(stale)
        .start();

    let handle = publisher.start();
    handle.publish(vec![MmsData::Bool(true)]).await.unwrap();

    // El suscriptor al día valida (tiene la clave 2, con la que se firmó).
    let ev = good.recv_event().await.unwrap();
    assert_eq!(ev.kind, GooseEventKind::StateChange);
    // El rezagado no valida la trama firmada con la clave nueva.
    let ev = lagging.recv_event().await.unwrap();
    assert_eq!(
        ev.kind,
        GooseEventKind::AuthFailed {
            status: AuthStatus::Invalid
        }
    );

    handle.stop().await;
    good.stop().await;
    lagging.stop().await;
}

fn frame(st: u32, sq: u32, ttl_ms: u32) -> Vec<u8> {
    GooseFrame {
        dst: DST,
        src: SRC,
        vlan: None,
        appid: 0x0001,
        simulation: false,
        pdu: GoosePdu {
            gocb_ref: "IED1LD0/LLN0.GO$gcb01".into(),
            time_allowed_to_live: ttl_ms,
            dat_set: "ds1".into(),
            go_id: "gcb01".into(),
            t: iec61850_goose::UtcTime { raw: [0; 8] },
            st_num: st,
            sq_num: sq,
            test: false,
            conf_rev: 1,
            nds_com: false,
            num_dat_set_entries: 1,
            all_data: vec![MmsData::Bool(true)],
        },
    }
    .encode()
}
