//! Capa de transporte: TPKT (RFC 1006) y COTP clase 0 (ISO 8073).
//!
//! `connection` (que usa tokio) se compila con las features `client` o `server`.

pub mod cotp;
pub mod tpkt;

#[cfg(any(feature = "client", feature = "server"))]
pub mod connection;

#[cfg(all(feature = "tls", any(feature = "client", feature = "server")))]
pub mod tls;
