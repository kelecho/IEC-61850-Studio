//! Configuración TLS (IEC 62351-3) con autenticación **mutua** (mTLS) sobre
//! rustls. Construye un [`TlsConnector`] (cliente) / [`TlsAcceptor`] (servidor)
//! a partir de certificados y claves en DER. Sólo con la feature `tls`.

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::MmsError;

pub use tokio_rustls::{TlsAcceptor as Acceptor, TlsConnector as Connector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots(certs: &[CertificateDer<'static>]) -> Result<RootCertStore, MmsError> {
    let mut store = RootCertStore::empty();
    for c in certs {
        store
            .add(c.clone())
            .map_err(|e| MmsError::Tls(format!("certificado raíz inválido: {e}")))?;
    }
    Ok(store)
}

/// Material TLS del **cliente** para mTLS.
pub struct TlsClientOptions {
    /// Certificado(s) raíz de confianza para verificar al servidor.
    pub ca: Vec<CertificateDer<'static>>,
    /// Cadena de certificado del propio cliente (la presenta al servidor).
    pub client_cert: Vec<CertificateDer<'static>>,
    /// Clave privada del cliente.
    pub client_key: PrivateKeyDer<'static>,
}

impl TlsClientOptions {
    /// Construye un [`TlsConnector`] con verificación del servidor y cert de cliente.
    pub fn connector(self) -> Result<TlsConnector, MmsError> {
        let roots = roots(&self.ca)?;
        let cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| MmsError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(self.client_cert, self.client_key)
            .map_err(|e| MmsError::Tls(e.to_string()))?;
        Ok(TlsConnector::from(Arc::new(cfg)))
    }

    /// Construye las opciones desde PEM: CA(s) de confianza, cadena del cliente
    /// (leaf + intermedios) y su clave privada.
    pub fn from_pem(
        ca_pem: &[u8],
        client_chain_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, MmsError> {
        Ok(Self {
            ca: certs_from_pem(ca_pem)?,
            client_cert: certs_from_pem(client_chain_pem)?,
            client_key: key_from_pem(key_pem)?,
        })
    }

    /// Igual que [`from_pem`](Self::from_pem) pero leyendo de archivos.
    pub fn from_pem_files(
        ca: impl AsRef<Path>,
        client_chain: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Self, MmsError> {
        Self::from_pem(
            &std::fs::read(ca)?,
            &std::fs::read(client_chain)?,
            &std::fs::read(key)?,
        )
    }
}

/// Material TLS del **servidor** para mTLS.
pub struct TlsServerOptions {
    /// Cadena de certificado del servidor.
    pub server_cert: Vec<CertificateDer<'static>>,
    /// Clave privada del servidor.
    pub server_key: PrivateKeyDer<'static>,
    /// Certificado(s) raíz que firman los certificados de cliente aceptados.
    pub client_ca: Vec<CertificateDer<'static>>,
}

impl TlsServerOptions {
    /// Construye un [`TlsAcceptor`] que exige y verifica el certificado de cliente.
    pub fn acceptor(self) -> Result<TlsAcceptor, MmsError> {
        let roots = roots(&self.client_ca)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider(),
        )
        .build()
        .map_err(|e| MmsError::Tls(e.to_string()))?;
        let cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| MmsError::Tls(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.server_cert, self.server_key)
            .map_err(|e| MmsError::Tls(e.to_string()))?;
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }

    /// Construye las opciones desde PEM: cadena del servidor (leaf + intermedios),
    /// su clave privada y la(s) CA que firman los certificados de cliente.
    pub fn from_pem(
        server_chain_pem: &[u8],
        key_pem: &[u8],
        client_ca_pem: &[u8],
    ) -> Result<Self, MmsError> {
        Ok(Self {
            server_cert: certs_from_pem(server_chain_pem)?,
            server_key: key_from_pem(key_pem)?,
            client_ca: certs_from_pem(client_ca_pem)?,
        })
    }

    /// Igual que [`from_pem`](Self::from_pem) pero leyendo de archivos.
    pub fn from_pem_files(
        server_chain: impl AsRef<Path>,
        key: impl AsRef<Path>,
        client_ca: impl AsRef<Path>,
    ) -> Result<Self, MmsError> {
        Self::from_pem(
            &std::fs::read(server_chain)?,
            &std::fs::read(key)?,
            &std::fs::read(client_ca)?,
        )
    }
}

// --- Parseo PEM (a mano: framing BEGIN/END + base64 propio) ---

/// Carga todos los bloques `CERTIFICATE` de un PEM como cadena/bundle DER.
pub fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, MmsError> {
    let certs: Vec<CertificateDer<'static>> = pem_blocks(pem)?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| CertificateDer::from(der))
        .collect();
    if certs.is_empty() {
        return Err(MmsError::Tls("PEM sin certificados".into()));
    }
    Ok(certs)
}

/// Carga la primera clave privada de un PEM (PKCS#8 / PKCS#1 / SEC1).
pub fn key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, MmsError> {
    for (label, der) in pem_blocks(pem)? {
        let key = match label.as_str() {
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            _ => continue,
        };
        return Ok(key);
    }
    Err(MmsError::Tls("PEM sin clave privada".into()))
}

/// Extrae los bloques `-----BEGIN <label>----- … -----END <label>-----` con su
/// cuerpo base64 decodificado a DER. Tolera varios bloques y texto intercalado.
fn pem_blocks(pem: &[u8]) -> Result<Vec<(String, Vec<u8>)>, MmsError> {
    let text = std::str::from_utf8(pem).map_err(|_| MmsError::Tls("PEM no es UTF-8".into()))?;
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line
            .trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        for l in lines.by_ref() {
            if l.trim() == end {
                closed = true;
                break;
            }
            body.push_str(l.trim());
        }
        if !closed {
            return Err(MmsError::Tls(format!("bloque PEM '{label}' sin END")));
        }
        blocks.push((label.to_string(), b64_decode(&body)?));
    }
    Ok(blocks)
}

/// Decodifica base64 estándar (`A–Za–z0–9+/`, padding `=`), ignorando espacios.
fn b64_decode(s: &str) -> Result<Vec<u8>, MmsError> {
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut quad = [0u8; 4];
    let mut n = 0;
    let mut pad = 0u32;
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            quad[n] = 0;
        } else {
            if pad > 0 {
                return Err(MmsError::Tls("base64: dato tras padding".into()));
            }
            quad[n] = val(c).ok_or_else(|| MmsError::Tls("base64: carácter inválido".into()))?;
        }
        n += 1;
        if n == 4 {
            out.push((quad[0] << 2) | (quad[1] >> 4));
            out.push((quad[1] << 4) | (quad[2] >> 2));
            out.push((quad[2] << 6) | quad[3]);
            n = 0;
        }
    }
    if n != 0 || pad > 2 {
        return Err(MmsError::Tls("base64: longitud inválida".into()));
    }
    out.truncate(out.len() - pad as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_vectors() {
        // RFC 4648 vectores.
        assert_eq!(b64_decode("").unwrap(), b"");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // Ignora espacios/saltos.
        assert_eq!(b64_decode("Zm9v\n YmFy").unwrap(), b"foobar");
        // Inválidos.
        assert!(b64_decode("Zg=A").is_err()); // dato tras padding
        assert!(b64_decode("Zm9").is_err()); // longitud no múltiplo de 4
        assert!(b64_decode("$$$$").is_err()); // carácter inválido
    }

    #[test]
    fn pem_multiple_certs_as_chain() {
        // Dos bloques CERTIFICATE concatenados → cadena de 2.
        let pem = b"\
-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n\
junk intercalado\n\
-----BEGIN CERTIFICATE-----\nYmFy\n-----END CERTIFICATE-----\n";
        let certs = certs_from_pem(pem).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), b"foo");
        assert_eq!(certs[1].as_ref(), b"bar");
    }

    #[test]
    fn key_label_to_variant() {
        let p8 = b"-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n";
        assert!(matches!(key_from_pem(p8).unwrap(), PrivateKeyDer::Pkcs8(_)));
        let p1 = b"-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n";
        assert!(matches!(key_from_pem(p1).unwrap(), PrivateKeyDer::Pkcs1(_)));
        let ec = b"-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n";
        assert!(matches!(key_from_pem(ec).unwrap(), PrivateKeyDer::Sec1(_)));
        // Sin clave / sin END.
        assert!(
            key_from_pem(b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")
                .is_err()
        );
        assert!(certs_from_pem(b"-----BEGIN CERTIFICATE-----\nZm9v\n").is_err());
    }
}
