//! Captura pasiva del tráfico de una interfaz a un archivo **pcap** (legible en
//! Wireshark). Modo promiscuo `ETH_P_ALL`: GOOSE, SV, MMS/C-S, ARP…
//!
//! Uso (requiere root o CAP_NET_RAW):
//!   sudo -E cargo run -p iec61850-l2 --features net --example pcap_capture -- <iface> <salida.pcap> [n_tramas]
//!
//! Detiene tras capturar `n_tramas` (por defecto 200) y escribe el archivo.

use std::fs::File;
use std::io::BufWriter;

use iec61850_l2::socket::RawSocket;
use iec61850_l2::{L2Link, PcapWriter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "eth0".into());
    let out_path = args.next().unwrap_or_else(|| "captura.pcap".into());
    let count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);

    let socket = RawSocket::open_all(&iface)?;
    let mut pcap = PcapWriter::new(BufWriter::new(File::create(&out_path)?))?;

    println!("Capturando {count} tramas en {iface} → {out_path} …");
    for i in 0..count {
        let frame = socket.recv().await?;
        pcap.write_packet_now(&frame)?;
        if (i + 1) % 50 == 0 {
            println!("  {} tramas", i + 1);
        }
    }
    pcap.flush()?;
    println!("Listo: {count} tramas escritas en {out_path}");
    Ok(())
}
