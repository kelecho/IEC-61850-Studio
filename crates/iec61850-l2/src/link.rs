//! Abstracción del enlace de capa 2, con una implementación en memoria
//! ([`MockLink`]) para pruebas sin privilegios.

use std::future::Future;

use tokio::sync::{Mutex, broadcast};

use crate::error::L2Error;

/// Enlace por el que se envían y reciben tramas Ethernet crudas.
pub trait L2Link: Send + Sync + 'static {
    fn send(&self, frame: &[u8]) -> impl Future<Output = Result<(), L2Error>> + Send;
    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, L2Error>> + Send;
}

/// Bus en memoria que modela el dominio multicast: todas las tramas enviadas
/// las reciben los demás enlaces del bus.
#[derive(Clone)]
pub struct MockBus {
    tx: broadcast::Sender<Vec<u8>>,
}

impl MockBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { tx }
    }
    /// Crea un enlace conectado a este bus (con su propio receptor).
    pub fn link(&self) -> MockLink {
        MockLink {
            tx: self.tx.clone(),
            rx: Mutex::new(self.tx.subscribe()),
        }
    }
}

impl Default for MockBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Enlace en memoria conectado a un [`MockBus`].
pub struct MockLink {
    tx: broadcast::Sender<Vec<u8>>,
    rx: Mutex<broadcast::Receiver<Vec<u8>>>,
}

impl L2Link for MockLink {
    async fn send(&self, frame: &[u8]) -> Result<(), L2Error> {
        let _ = self.tx.send(frame.to_vec());
        Ok(())
    }
    async fn recv(&self) -> Result<Vec<u8>, L2Error> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(frame) => return Ok(frame),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(L2Error::Malformed("bus de capa 2 cerrado".into()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_bus_delivers() {
        let bus = MockBus::new();
        let a = bus.link();
        let b = bus.link();
        a.send(&[1, 2, 3]).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), vec![1, 2, 3]);
    }
}
