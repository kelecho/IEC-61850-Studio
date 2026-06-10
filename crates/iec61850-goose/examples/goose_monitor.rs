//! Monitoriza **todos** los GOOSE de una interfaz e imprime los eventos (cambios
//! de estado, retransmisiones, pérdidas, expiraciones). Modo promiscuo: captura
//! los GOOSE de cualquier publicador, no solo los de un grupo multicast concreto.
//!
//! Uso (requiere root o CAP_NET_RAW):
//!   sudo -E cargo run -p iec61850-goose --features net --example goose_monitor -- <iface>

use iec61850_goose::socket::RawSocket;
use iec61850_goose::{ETHERTYPE_GOOSE, GooseFilter, GooseSubscriber};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    let socket = RawSocket::open_promiscuous(&iface, ETHERTYPE_GOOSE)?;

    let mut sub = GooseSubscriber::new(socket, GooseFilter::default()).start();
    println!("Escuchando GOOSE en {iface} (Ctrl-C para parar)…");

    while let Some(ev) = sub.recv_event().await {
        println!(
            "[{:?}] {} st={} sq={} test={} valores={:?}",
            ev.kind, ev.gocb_ref, ev.st_num, ev.sq_num, ev.test, ev.values
        );
    }
    Ok(())
}
