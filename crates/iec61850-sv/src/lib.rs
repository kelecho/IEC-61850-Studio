//! # iec61850-sv
//!
//! Sampled Values (IEC 61850-9-2): muestras de medida por multicast Ethernet de
//! capa 2 (EtherType `0x88BA`). El **codec** ([`frame`], [`pdu`], [`nine_two_le`])
//! reutiliza el BER de [`iec61850_ber`] y la cabecera de [`iec61850_l2`], y se
//! testea sin red. El publicador/suscriptor (feature `net`) están sobre `tokio`.

pub mod config;
pub mod error;
pub mod frame;
pub mod nine_two_le;
pub mod pdu;

#[cfg(feature = "net")]
pub mod publisher;
#[cfg(feature = "net")]
pub mod subscriber;

pub use config::SvConfig;
pub use error::SvError;
pub use frame::{ETHERTYPE_SV, SvFrame};
pub use nine_two_le::{NineTwoLe, SvChannel};
pub use pdu::{Asdu, SvPdu};

pub use iec61850_l2::{MacAddr, VlanTag};

#[cfg(feature = "net")]
pub use iec61850_l2::{L2Link, MockBus, MockLink};
#[cfg(feature = "net")]
pub use publisher::{SvPublisher, SvPublisherHandle};
#[cfg(feature = "net")]
pub use subscriber::{SvEvent, SvEventKind, SvFilter, SvSubscriber, SvSubscriberHandle};

#[cfg(all(feature = "net", target_os = "linux"))]
pub use iec61850_l2::RawSocket;
