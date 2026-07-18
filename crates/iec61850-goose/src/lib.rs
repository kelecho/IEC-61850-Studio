//! # iec61850-goose
//!
//! GOOSE (Generic Object Oriented Substation Events, IEC 61850-8-1):
//! publicación/suscripción de eventos por multicast Ethernet de capa 2
//! (EtherType `0x88B8`).
//!
//! El **codec** ([`frame`], [`pdu`]) reutiliza el BER y `MmsData` de
//! [`iec61850_ber`] y la cabecera Ethernet de [`iec61850_l2`], y se compila/testea
//! sin red. El publicador, suscriptor y el socket AF_PACKET (vía `iec61850-l2`)
//! se activan con la feature `net`.

pub mod config;
pub mod error;
pub mod frame;
pub mod pdu;

#[cfg(feature = "net")]
pub mod publisher;
#[cfg(feature = "net")]
pub mod subscriber;

/// Compatibilidad: el enlace y los mocks viven ahora en [`iec61850_l2`].
#[cfg(feature = "net")]
pub mod link {
    pub use iec61850_l2::{L2Link as GooseLink, MockBus, MockLink};
}

/// Compatibilidad: el socket de capa 2 vive ahora en [`iec61850_l2`]
/// (AF_PACKET en Linux, Npcap en Windows).
#[cfg(all(feature = "net", any(target_os = "linux", windows)))]
pub mod socket {
    pub use iec61850_l2::{RawSocket, interfaces};
}

pub use config::GooseConfig;
pub use error::GooseError;
pub use frame::{
    AuthStatus, ETHERTYPE_GOOSE, GooseFrame, HmacKey, KeyEntry, KeyRing, MacAddr, Signer,
    SignerRing, Verifier, VerifierRing, VlanTag,
};
#[cfg(feature = "ecdsa")]
pub use frame::{EcdsaSigner, EcdsaVerifier};
pub use pdu::GoosePdu;

/// Conveniencia: el escritor PCAP de [`iec61850_l2`], para volcar capturas a
/// disco desde apps que ya dependen de GOOSE.
pub use iec61850_l2::{LINKTYPE_ETHERNET, PcapPacket, PcapReader, PcapWriter};

#[cfg(feature = "net")]
pub use iec61850_l2::{L2Link as GooseLink, MockBus, MockLink};
#[cfg(feature = "net")]
pub use publisher::{GoosePublisher, PublisherHandle};
#[cfg(feature = "net")]
pub use subscriber::{GooseEvent, GooseEventKind, GooseFilter, GooseSubscriber, SubscriberHandle};

// Re-export de los tipos de datos reutilizados, por conveniencia.
pub use iec61850_ber::{MmsData, UtcTime};
