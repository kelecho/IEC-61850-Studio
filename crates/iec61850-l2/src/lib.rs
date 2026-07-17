//! # iec61850-l2
//!
//! Capa 2 común de IEC 61850-8-1 / 9-2: cabecera Ethernet (+ 802.1Q) y de
//! aplicación (APPID/Length/Reserved), el trait de enlace [`L2Link`] y el socket
//! `AF_PACKET` [`RawSocket`], compartidos por GOOSE (EtherType 0x88B8) y SV
//! (0x88BA). El codec de cabecera ([`eth`]) compila sin red; el transporte está
//! tras la feature `net`.

pub mod auth;
pub mod error;
pub mod eth;
pub mod keystore;
pub mod pcap;
#[cfg(feature = "ecdsa")]
pub mod sign;

#[cfg(feature = "net")]
pub mod link;
#[cfg(all(feature = "net", target_os = "linux"))]
pub mod socket;

pub use auth::{
    AuthStatus, FrameSigner, FrameVerifier, HMAC_SHA256_TAG_LEN, HmacKey, Signer, Verifier, sha256,
};
pub use error::L2Error;
pub use eth::{
    EthHeader, MacAddr, ParsedAppFrame, RESERVED1_SIMULATED, TPID_8021Q, VlanTag, finish_l2_frame,
    finish_l2_frame_signed, parse_eth_appid, parse_eth_appid_auth, write_eth_appid,
};
pub use keystore::{KeyEntry, KeyRing, SignerRing, VerifierRing};
pub use pcap::{LINKTYPE_ETHERNET, PcapPacket, PcapReader, PcapWriter};
#[cfg(feature = "ecdsa")]
pub use sign::{ECDSA_P256_TAG_LEN, EcdsaError, EcdsaSigner, EcdsaVerifier};

#[cfg(feature = "net")]
pub use link::{L2Link, MockBus, MockLink};
#[cfg(all(feature = "net", target_os = "linux"))]
pub use socket::RawSocket;
