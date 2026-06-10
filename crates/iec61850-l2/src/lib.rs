//! # iec61850-l2
//!
//! Capa 2 común de IEC 61850-8-1 / 9-2: cabecera Ethernet (+ 802.1Q) y de
//! aplicación (APPID/Length/Reserved), el trait de enlace [`L2Link`] y el socket
//! `AF_PACKET` [`RawSocket`], compartidos por GOOSE (EtherType 0x88B8) y SV
//! (0x88BA). El codec de cabecera ([`eth`]) compila sin red; el transporte está
//! tras la feature `net`.

pub mod error;
pub mod eth;
pub mod pcap;

#[cfg(feature = "net")]
pub mod link;
#[cfg(all(feature = "net", target_os = "linux"))]
pub mod socket;

pub use error::L2Error;
pub use eth::{
    EthHeader, MacAddr, RESERVED1_SIMULATED, TPID_8021Q, VlanTag, finish_l2_frame, parse_eth_appid,
    write_eth_appid,
};
pub use pcap::{LINKTYPE_ETHERNET, PcapWriter};

#[cfg(feature = "net")]
pub use link::{L2Link, MockBus, MockLink};
#[cfg(all(feature = "net", target_os = "linux"))]
pub use socket::RawSocket;
