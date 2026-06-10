//! Conexión ISO sobre TCP (opcionalmente TLS): enmarca/desenmarca TPKT alrededor
//! de un stream. El stream subyacente puede ir en claro (`TcpStream`) o cifrado
//! (`tokio_rustls::TlsStream`, feature `tls`), abstraído por [`MaybeTlsStream`]
//! para no propagar genéricos al cliente/servidor.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};

use super::{cotp, tpkt};
use crate::error::MmsError;

/// Puerto estándar de MMS (ISO sobre TCP / RFC 1006).
pub const MMS_PORT: u16 = 102;

/// Cota del TSDU reensamblado a partir de fragmentos DT, para no acumular sin
/// límite ante un peer que nunca marque EOT. 16 MiB cubre con holgura cualquier
/// respuesta MMS legítima (modelos grandes, file transfer por bloques).
const MAX_TSDU_LEN: usize = 16 * 1024 * 1024;

/// Stream subyacente: en claro o cifrado con TLS.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Conexión de transporte ISO: TPKT sobre TCP (o TLS).
pub struct IsoConnection {
    stream: MaybeTlsStream,
}

impl IsoConnection {
    /// Abre una conexión TCP en claro al servidor.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, MmsError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream: MaybeTlsStream::Plain(stream),
        })
    }

    /// Envuelve un `TcpStream` ya aceptado, en claro (lado servidor).
    pub fn from_stream(stream: TcpStream) -> Self {
        stream.set_nodelay(true).ok();
        Self {
            stream: MaybeTlsStream::Plain(stream),
        }
    }

    /// Abre una conexión TLS al servidor (cliente). Requiere la feature `tls`.
    #[cfg(feature = "tls")]
    pub async fn connect_tls<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        connector: &tokio_rustls::TlsConnector,
    ) -> Result<Self, MmsError> {
        use tokio_rustls::rustls::pki_types::ServerName;
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true).ok();
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|e| MmsError::Tls(format!("nombre de servidor inválido: {e}")))?;
        let tls = connector.connect(name, tcp).await?;
        Ok(Self {
            stream: MaybeTlsStream::Tls(Box::new(tokio_rustls::TlsStream::Client(tls))),
        })
    }

    /// Acepta TLS sobre un `TcpStream` ya aceptado (lado servidor). Feature `tls`.
    #[cfg(feature = "tls")]
    pub async fn from_stream_tls(
        stream: TcpStream,
        acceptor: &tokio_rustls::TlsAcceptor,
    ) -> Result<Self, MmsError> {
        stream.set_nodelay(true).ok();
        let tls = acceptor.accept(stream).await?;
        Ok(Self {
            stream: MaybeTlsStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls))),
        })
    }

    /// Envía un payload (TPDU COTP) enmarcado en TPKT.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MmsError> {
        let frame = tpkt::frame(payload);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Recibe un paquete TPKT completo y devuelve su payload (TPDU COTP).
    pub async fn recv(&mut self) -> Result<Vec<u8>, MmsError> {
        let mut header = [0u8; tpkt::HEADER_LEN];
        self.stream.read_exact(&mut header).await?;
        let len = tpkt::payload_len(&header)?;
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(payload)
    }

    /// Recibe un TSDU completo de la fase de datos, **reensamblando** los
    /// fragmentos DT (COTP clase 0) hasta el que lleva EOT. Devuelve los datos de
    /// usuario concatenados (capa de sesión/presentación).
    pub async fn recv_data(&mut self) -> Result<Vec<u8>, MmsError> {
        let mut out = Vec::new();
        loop {
            let tpdu = self.recv().await?;
            if reassemble_into(&mut out, &tpdu)? {
                return Ok(out);
            }
        }
    }

    /// Separa la conexión en mitades independientes de lectura y escritura,
    /// para que una tarea de fondo lea mientras otras envían peticiones.
    pub fn split(self) -> (IsoReader, IsoWriter) {
        let (r, w) = tokio::io::split(self.stream);
        (IsoReader { half: r }, IsoWriter { half: w })
    }
}

/// Mitad de lectura: entrega paquetes TPKT (payload COTP).
pub struct IsoReader {
    half: ReadHalf<MaybeTlsStream>,
}

impl IsoReader {
    /// Recibe un paquete TPKT completo y devuelve su payload (TPDU COTP).
    pub async fn recv(&mut self) -> Result<Vec<u8>, MmsError> {
        let mut header = [0u8; tpkt::HEADER_LEN];
        self.half.read_exact(&mut header).await?;
        let len = tpkt::payload_len(&header)?;
        let mut payload = vec![0u8; len];
        self.half.read_exact(&mut payload).await?;
        Ok(payload)
    }

    /// Recibe un TSDU completo de la fase de datos, reensamblando los fragmentos
    /// DT hasta EOT (ver [`IsoConnection::recv_data`]).
    pub async fn recv_data(&mut self) -> Result<Vec<u8>, MmsError> {
        let mut out = Vec::new();
        loop {
            let tpdu = self.recv().await?;
            if reassemble_into(&mut out, &tpdu)? {
                return Ok(out);
            }
        }
    }
}

/// Añade el payload del DT `tpdu` a `out` y devuelve `true` si es el último
/// fragmento (EOT). Acota el TSDU acumulado a [`MAX_TSDU_LEN`].
fn reassemble_into(out: &mut Vec<u8>, tpdu: &[u8]) -> Result<bool, MmsError> {
    let (payload, eot) = cotp::parse_data_tpdu_eot(tpdu)?;
    if out.len() + payload.len() > MAX_TSDU_LEN {
        return Err(MmsError::Transport(format!(
            "TSDU reensamblado excede el máximo ({MAX_TSDU_LEN} octetos)"
        )));
    }
    out.extend_from_slice(payload);
    Ok(eot)
}

/// Mitad de escritura: enmarca payloads COTP en TPKT.
pub struct IsoWriter {
    half: WriteHalf<MaybeTlsStream>,
}

impl IsoWriter {
    /// Envía un payload (TPDU COTP) enmarcado en TPKT.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MmsError> {
        let frame = tpkt::frame(payload);
        self.half.write_all(&frame).await?;
        self.half.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_two_dt_fragments() {
        // Fragmento intermedio (EOT=0) + fragmento final (EOT=1).
        let mid = [0x02u8, 0xF0, 0x00, b'A', b'B'];
        let last = [0x02u8, 0xF0, 0x80, b'C'];
        let mut out = Vec::new();
        assert!(!reassemble_into(&mut out, &mid).unwrap());
        assert!(reassemble_into(&mut out, &last).unwrap());
        assert_eq!(out, b"ABC");
    }

    #[test]
    fn single_dt_is_complete() {
        let only = [0x02u8, 0xF0, 0x80, b'X', b'Y'];
        let mut out = Vec::new();
        assert!(reassemble_into(&mut out, &only).unwrap());
        assert_eq!(out, b"XY");
    }
}
