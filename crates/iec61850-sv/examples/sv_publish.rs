//! Publica un flujo SV 9-2LE a 4000 muestras/s, generando una senoide de 50 Hz
//! en las tres corrientes/tensiones.
//!
//! Uso (requiere root o CAP_NET_RAW):
//!   sudo -E cargo run -p iec61850-sv --features net --example sv_publish -- <iface>

use std::time::Duration;

use iec61850_sv::nine_two_le::idx;
use iec61850_sv::{ETHERTYPE_SV, MacAddr, NineTwoLe, RawSocket, SvChannel, SvConfig, SvPublisher};

const DST: MacAddr = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
const SRC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    let socket = RawSocket::open(&iface, ETHERTYPE_SV, DST)?;

    let cfg = SvConfig::new(DST, SRC, 0x4000, "MU01");
    let smp_rate = cfg.smp_rate as f64;
    let publisher = SvPublisher::new(socket, cfg).start();
    println!("Publicando SV 9-2LE en {iface} a 4000/s (Ctrl-C para parar)…");

    // La app actualiza la muestra; el publicador la emite a tasa fija.
    let mut k: f64 = 0.0;
    let mut ticker = tokio::time::interval(Duration::from_micros(250));
    loop {
        ticker.tick().await;
        let phase = 2.0 * std::f64::consts::PI * 50.0 * (k / smp_rate);
        let amp = 1000.0;
        let mut n = NineTwoLe::default();
        n.channels[idx::IA] = SvChannel {
            value: (amp * phase.sin()) as i32,
            quality: 0,
        };
        n.channels[idx::VA] = SvChannel {
            value: (amp * phase.cos()) as i32,
            quality: 0,
        };
        publisher.set_9_2le(&n);
        k += 1.0;
    }
}
