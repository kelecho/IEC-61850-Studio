//! Monitoriza **todos** los flujos SV de la interfaz e imprime cada muestra
//! (svID, smpCnt, canales 9-2LE). Usa modo promiscuo, así que captura los SV de
//! cualquier publicador, no solo los dirigidos a un grupo multicast concreto.
//!
//! Uso (requiere root o CAP_NET_RAW):
//!   sudo -E cargo run -p iec61850-sv --features net --example sv_monitor -- <iface>

use iec61850_sv::{ETHERTYPE_SV, RawSocket, SvFilter, SvSubscriber};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    let socket = RawSocket::open_promiscuous(&iface, ETHERTYPE_SV)?;

    let mut sub = SvSubscriber::new(socket, SvFilter::default()).start();
    println!("Escuchando SV en {iface} (Ctrl-C para parar)…");

    while let Some(ev) = sub.recv_sample().await {
        match ev.decoded_9_2le {
            Some(n) => println!(
                "[{:?}] {} smpCnt={} IA={} VA={}",
                ev.kind, ev.sv_id, ev.smp_cnt, n.channels[0].value, n.channels[4].value
            ),
            None => println!(
                "[{:?}] {} smpCnt={} sample={}B",
                ev.kind,
                ev.sv_id,
                ev.smp_cnt,
                ev.sample.len()
            ),
        }
    }
    Ok(())
}
