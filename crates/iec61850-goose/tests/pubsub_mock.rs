//! Publicador ↔ suscriptor GOOSE sobre `MockLink`, con el reloj de tokio
//! pausado para verificar la retransmisión sin esperas reales.
#![cfg(feature = "net")]

use std::time::Duration;

use iec61850_goose::GooseFilter;
use iec61850_goose::frame::{GooseFrame, MacAddr};
use iec61850_goose::pdu::GoosePdu;
use iec61850_goose::{
    GooseConfig, GooseEventKind, GoosePublisher, GooseSubscriber, MmsData, MockBus,
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
