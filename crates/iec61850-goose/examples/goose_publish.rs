//! Publica GOOSE en una interfaz, alternando un booleano cada 5 s (cada cambio
//! dispara un nuevo estado con su ráfaga de retransmisión).
//!
//! Uso (requiere root o CAP_NET_RAW):
//!   sudo -E cargo run -p iec61850-goose --features net --example goose_publish -- <iface>

use std::time::Duration;

use iec61850_goose::socket::RawSocket;
use iec61850_goose::{ETHERTYPE_GOOSE, GooseConfig, GoosePublisher, MacAddr, MmsData};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
const SRC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    let socket = RawSocket::open(&iface, ETHERTYPE_GOOSE, DST)?;

    let mut cfg = GooseConfig::new(DST, SRC, 0x0001, "IED1LD0/LLN0.GO$gcb01");
    cfg.dat_set = "IED1LD0/LLN0$ds1".into();
    cfg.go_id = "gcb01".into();

    let publisher = GoosePublisher::new(socket, cfg).start();
    println!("Publicando GOOSE en {iface} (Ctrl-C para parar)…");

    let mut on = false;
    loop {
        publisher.publish(vec![MmsData::Bool(on)]).await?;
        println!("estado: {on}");
        on = !on;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
