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

/// Extrae el **CommonName (CN)** del *subject* de un certificado X.509 (DER).
///
/// Navega `Certificate → tbsCertificate → subject (Name)` y busca el atributo con
/// OID `2.5.4.3` (`55 04 03`). Usado para autenticación por certificado
/// (IEC 62351-4/8): el CN del cliente mTLS identifica su rol. Devuelve `None` si
/// el DER no es un certificado válido o no tiene CN.
pub fn cert_common_name(der: &[u8]) -> Option<String> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let mut top = BerReader::new(der);
    let cert = top.read_tlv().ok()?;
    if cert.tag != universal::SEQUENCE {
        return None;
    }
    // tbsCertificate ::= SEQUENCE { [0] version?, serial, signature, issuer,
    //                               validity, subject, ... }
    let mut tbs_reader = BerReader::new(cert.content);
    let tbs = tbs_reader.read_tlv().ok()?;
    let mut r = BerReader::new(tbs.content);

    // Salta version [0] EXPLICIT si está presente.
    if r.peek_tag().ok()? == Tag::context(0, true) {
        r.read_tlv().ok()?;
    }
    r.read_tlv().ok()?; // serialNumber INTEGER
    r.read_tlv().ok()?; // signature AlgorithmIdentifier (SEQUENCE)
    r.read_tlv().ok()?; // issuer Name (SEQUENCE)
    r.read_tlv().ok()?; // validity (SEQUENCE)
    let subject = r.read_tlv().ok()?; // subject Name (SEQUENCE OF RDN)

    // Busca el AttributeTypeAndValue con OID de CN (2.5.4.3).
    const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
    let mut rdns = BerReader::new(subject.content);
    while !rdns.is_empty() {
        let rdn = rdns.read_tlv().ok()?; // RelativeDistinguishedName (SET OF)
        let mut atvs = BerReader::new(rdn.content);
        while !atvs.is_empty() {
            let atv = atvs.read_tlv().ok()?; // SEQUENCE { type OID, value }
            let mut av = BerReader::new(atv.content);
            let oid = av.read_tlv().ok()?; // type OID
            let value = av.read_tlv().ok()?; // value (string)
            if oid.content == CN_OID {
                return Some(String::from_utf8_lossy(value.content).into_owned());
            }
        }
    }
    None
}

// --- PKI: validez y revocación de certificados (IEC 62351-9) ------------------

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, universal};

const UTC_TIME: Tag = Tag::universal(0x17, false);
const GENERALIZED_TIME: Tag = Tag::universal(0x18, false);

/// Sitúa un lector en el contenido del `tbsCertificate` de un certificado DER.
fn tbs_reader(der: &[u8]) -> Option<BerReader<'_>> {
    let mut top = BerReader::new(der);
    let cert = top.read_tlv().ok()?;
    if cert.tag != universal::SEQUENCE {
        return None;
    }
    let mut tr = BerReader::new(cert.content);
    let tbs = tr.read_tlv().ok()?;
    Some(BerReader::new(tbs.content))
}

/// Número de días desde el epoch Unix para una fecha civil (Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parsea un `Time` de X.509 (`UTCTime` o `GeneralizedTime`, en UTC/`Z`) a
/// segundos epoch. Devuelve `None` si el formato no es reconocible.
fn parse_asn1_time(tag: Tag, content: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(content).ok()?;
    let (year, rest) = if tag == UTC_TIME {
        // "YYMMDDHHMMSSZ": 00–49 ⇒ 20YY, 50–99 ⇒ 19YY (RFC 5280).
        if s.len() < 13 {
            return None;
        }
        let yy: i64 = s[0..2].parse().ok()?;
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (year, &s[2..])
    } else if tag == GENERALIZED_TIME {
        // "YYYYMMDDHHMMSSZ".
        if s.len() < 15 {
            return None;
        }
        let year: i64 = s[0..4].parse().ok()?;
        (year, &s[4..])
    } else {
        return None;
    };
    let month: i64 = rest[0..2].parse().ok()?;
    let day: i64 = rest[2..4].parse().ok()?;
    let hour: i64 = rest[4..6].parse().ok()?;
    let min: i64 = rest[6..8].parse().ok()?;
    let sec: i64 = rest[8..10].parse().ok()?;
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + min * 60 + sec;
    u64::try_from(secs).ok()
}

/// Normaliza el número de serie (quita ceros de relleno a la izquierda) para
/// comparar seriales entre el certificado y la CRL de forma robusta.
fn normalize_serial(bytes: &[u8]) -> Vec<u8> {
    let mut s = bytes;
    while s.len() > 1 && s[0] == 0 {
        s = &s[1..];
    }
    s.to_vec()
}

/// Número de serie del certificado (DER), normalizado.
pub fn cert_serial_number(der: &[u8]) -> Option<Vec<u8>> {
    let mut r = tbs_reader(der)?;
    if r.peek_tag().ok()? == Tag::context(0, true) {
        r.read_tlv().ok()?; // version [0] EXPLICIT
    }
    let serial = r.read_tlv().ok()?; // serialNumber INTEGER
    Some(normalize_serial(serial.content))
}

/// Ventana de validez del certificado `(notBefore, notAfter)` en segundos epoch.
pub fn cert_validity(der: &[u8]) -> Option<(u64, u64)> {
    let mut r = tbs_reader(der)?;
    if r.peek_tag().ok()? == Tag::context(0, true) {
        r.read_tlv().ok()?; // version [0]
    }
    r.read_tlv().ok()?; // serialNumber
    r.read_tlv().ok()?; // signature AlgorithmIdentifier
    r.read_tlv().ok()?; // issuer Name
    let validity = r.read_tlv().ok()?; // validity SEQUENCE
    let mut vr = BerReader::new(validity.content);
    let nb = vr.read_tlv().ok()?;
    let na = vr.read_tlv().ok()?;
    Some((
        parse_asn1_time(nb.tag, nb.content)?,
        parse_asn1_time(na.tag, na.content)?,
    ))
}

/// Lista de revocación de certificados (CRL X.509, RFC 5280) ya parseada.
#[derive(Debug, Clone)]
pub struct CrlInfo {
    /// Emisión de la CRL (epoch s).
    pub this_update: u64,
    /// Próxima actualización, si la CRL la declara (epoch s). Pasada esa fecha la
    /// CRL se considera caducada.
    pub next_update: Option<u64>,
    /// Números de serie revocados (normalizados).
    pub revoked: Vec<Vec<u8>>,
}

impl CrlInfo {
    /// ¿Está revocado el certificado con este número de serie?
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        let s = normalize_serial(serial);
        self.revoked.contains(&s)
    }
}

/// Parsea una CRL en DER (`CertificateList`). No verifica la **firma** de la CRL:
/// se asume que procede de una fuente de confianza (fichero del operador); su
/// autenticación con la clave de la CA es un refuerzo pendiente.
pub fn parse_crl(der: &[u8]) -> Option<CrlInfo> {
    let mut top = BerReader::new(der);
    let cl = top.read_tlv().ok()?;
    if cl.tag != universal::SEQUENCE {
        return None;
    }
    let mut clr = BerReader::new(cl.content);
    let tbs = clr.read_tlv().ok()?; // tbsCertList
    let mut r = BerReader::new(tbs.content);

    // version INTEGER OPTIONAL.
    if r.peek_tag().ok()? == universal::INTEGER {
        r.read_tlv().ok()?;
    }
    r.read_tlv().ok()?; // signature AlgorithmIdentifier
    r.read_tlv().ok()?; // issuer Name
    let tu = r.read_tlv().ok()?; // thisUpdate Time
    let this_update = parse_asn1_time(tu.tag, tu.content)?;

    let mut next_update = None;
    let mut revoked = Vec::new();
    while !r.is_empty() {
        let tag = r.peek_tag().ok()?;
        if tag == UTC_TIME || tag == GENERALIZED_TIME {
            let nu = r.read_tlv().ok()?; // nextUpdate Time
            next_update = Some(parse_asn1_time(nu.tag, nu.content)?);
        } else if tag == universal::SEQUENCE {
            // revokedCertificates ::= SEQUENCE OF SEQUENCE { serial, revDate, ... }
            let list = r.read_tlv().ok()?;
            let mut lr = BerReader::new(list.content);
            while !lr.is_empty() {
                let entry = lr.read_tlv().ok()?;
                let mut er = BerReader::new(entry.content);
                let serial = er.read_tlv().ok()?; // userCertificate INTEGER
                revoked.push(normalize_serial(serial.content));
            }
        } else {
            // crlExtensions [0] u otros: se ignoran.
            r.read_tlv().ok()?;
        }
    }
    Some(CrlInfo {
        this_update,
        next_update,
        revoked,
    })
}

// --- OCSP (RFC 6960): estado de revocación en línea, pre-obtenido/grapado -------

const ENUMERATED: Tag = Tag::universal(0x0A, false);

/// Estado de un certificado según una respuesta OCSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// El certificado es válido (no revocado).
    Good,
    /// El certificado está revocado.
    Revoked,
    /// El emisor no conoce el estado del certificado.
    Unknown,
}

/// Estado de un certificado concreto dentro de una respuesta OCSP.
#[derive(Debug, Clone)]
pub struct OcspSingleResponse {
    /// Número de serie del certificado (normalizado).
    pub serial: Vec<u8>,
    /// Estado reportado.
    pub status: CertStatus,
    /// Emisión de esta información (epoch s).
    pub this_update: u64,
    /// Próxima actualización (epoch s); pasada esa fecha la respuesta es obsoleta.
    pub next_update: Option<u64>,
}

/// Respuesta OCSP (RFC 6960) parseada: estados por certificado. No se verifica la
/// **firma** de la respuesta (se asume grapada/obtenida de fuente de confianza,
/// como la CRL); su autenticación con la clave del respondedor es un refuerzo
/// pendiente.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Respuestas individuales (una por certificado consultado).
    pub responses: Vec<OcspSingleResponse>,
}

impl OcspResponse {
    /// Estado del certificado con este número de serie, si la respuesta lo cubre.
    pub fn status_of(&self, serial: &[u8]) -> Option<&OcspSingleResponse> {
        let s = normalize_serial(serial);
        self.responses.iter().find(|r| r.serial == s)
    }
}

/// Parsea una respuesta OCSP en DER (`OCSPResponse` → `BasicOCSPResponse`).
/// Devuelve `None` si el estado global no es `successful` o el DER no es válido.
pub fn parse_ocsp_response(der: &[u8]) -> Option<OcspResponse> {
    let mut top = BerReader::new(der);
    let outer = top.read_tlv().ok()?; // OCSPResponse SEQUENCE
    if outer.tag != universal::SEQUENCE {
        return None;
    }
    let mut r = BerReader::new(outer.content);
    let status = r.read_tlv().ok()?; // responseStatus ENUMERATED
    if status.tag != ENUMERATED || status.content.first().copied() != Some(0) {
        return None; // no 'successful'
    }
    let rb = r.read_tlv().ok()?; // responseBytes [0] EXPLICIT
    if rb.tag != Tag::context(0, true) {
        return None;
    }
    let mut rbr = BerReader::new(rb.content);
    let rbytes = rbr.read_tlv().ok()?; // ResponseBytes SEQUENCE
    let mut rbs = BerReader::new(rbytes.content);
    rbs.read_tlv().ok()?; // responseType OID (se asume id-pkix-ocsp-basic)
    let resp = rbs.read_tlv().ok()?; // response OCTET STRING = BasicOCSPResponse
    parse_basic_ocsp(resp.content)
}

fn parse_basic_ocsp(der: &[u8]) -> Option<OcspResponse> {
    let mut top = BerReader::new(der);
    let basic = top.read_tlv().ok()?; // BasicOCSPResponse SEQUENCE
    let mut r = BerReader::new(basic.content);
    let tbs = r.read_tlv().ok()?; // tbsResponseData (ResponseData)
    let mut rd = BerReader::new(tbs.content);
    // version [0] EXPLICIT DEFAULT v1 (opcional).
    if rd.peek_tag().ok()? == Tag::context(0, true) {
        rd.read_tlv().ok()?;
    }
    rd.read_tlv().ok()?; // responderID ([1] byName / [2] byKey)
    rd.read_tlv().ok()?; // producedAt GeneralizedTime
    let responses = rd.read_tlv().ok()?; // responses SEQUENCE OF SingleResponse
    let mut lr = BerReader::new(responses.content);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let sr = lr.read_tlv().ok()?;
        out.push(parse_single_response(sr.content)?);
    }
    Some(OcspResponse { responses: out })
}

fn parse_single_response(der: &[u8]) -> Option<OcspSingleResponse> {
    let mut r = BerReader::new(der);
    let cert_id = r.read_tlv().ok()?; // CertID SEQUENCE
    let mut cr = BerReader::new(cert_id.content);
    cr.read_tlv().ok()?; // hashAlgorithm
    cr.read_tlv().ok()?; // issuerNameHash OCTET STRING
    cr.read_tlv().ok()?; // issuerKeyHash OCTET STRING
    let serial = cr.read_tlv().ok()?; // serialNumber INTEGER
    let serial = normalize_serial(serial.content);

    // certStatus CHOICE: good [0] NULL, revoked [1] RevokedInfo, unknown [2] NULL.
    let cs = r.read_tlv().ok()?;
    let status = if cs.tag == Tag::context(0, false) {
        CertStatus::Good
    } else if cs.tag == Tag::context(1, true) {
        CertStatus::Revoked
    } else {
        CertStatus::Unknown
    };

    let tu = r.read_tlv().ok()?; // thisUpdate GeneralizedTime
    let this_update = parse_asn1_time(tu.tag, tu.content)?;
    // nextUpdate [0] EXPLICIT GeneralizedTime (opcional); singleExtensions [1].
    let mut next_update = None;
    while !r.is_empty() {
        let tag = r.peek_tag().ok()?;
        if tag == Tag::context(0, true) {
            let nu = r.read_tlv().ok()?;
            let mut nur = BerReader::new(nu.content);
            let g = nur.read_tlv().ok()?;
            next_update = parse_asn1_time(g.tag, g.content);
        } else {
            r.read_tlv().ok()?;
        }
    }
    Some(OcspSingleResponse {
        serial,
        status,
        this_update,
        next_update,
    })
}

/// Fuente de estado de revocación para IEC 62351-9: una **CRL** (lista) o una
/// **respuesta OCSP** (en línea, pre-obtenida/grapada).
#[derive(Debug, Clone)]
pub enum RevocationSource {
    /// Lista de revocación (RFC 5280).
    Crl(CrlInfo),
    /// Respuesta OCSP (RFC 6960).
    Ocsp(OcspResponse),
}

impl From<CrlInfo> for RevocationSource {
    fn from(c: CrlInfo) -> Self {
        RevocationSource::Crl(c)
    }
}

impl From<OcspResponse> for RevocationSource {
    fn from(o: OcspResponse) -> Self {
        RevocationSource::Ocsp(o)
    }
}

impl RevocationSource {
    /// Comprueba el estado de revocación del `serial` en `now`.
    fn check(&self, serial: &[u8], now: u64) -> Result<(), PkiError> {
        match self {
            RevocationSource::Crl(crl) => {
                if let Some(nu) = crl.next_update {
                    if now >= nu {
                        return Err(PkiError::CrlExpired);
                    }
                }
                if crl.is_revoked(serial) {
                    return Err(PkiError::Revoked);
                }
                Ok(())
            }
            RevocationSource::Ocsp(ocsp) => match ocsp.status_of(serial) {
                Some(sr) => {
                    if let Some(nu) = sr.next_update {
                        if now >= nu {
                            return Err(PkiError::OcspExpired);
                        }
                    }
                    match sr.status {
                        CertStatus::Good => Ok(()),
                        CertStatus::Revoked => Err(PkiError::Revoked),
                        CertStatus::Unknown => Err(PkiError::OcspUnknown),
                    }
                }
                // Sin estado para este certificado: se trata como desconocido.
                None => Err(PkiError::OcspUnknown),
            },
        }
    }
}

/// Resultado negativo de la validación PKI de un certificado (IEC 62351-9).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PkiError {
    /// El certificado no se pudo parsear.
    #[error("certificado malformado")]
    Malformed,
    /// El instante actual es anterior a `notBefore`.
    #[error("certificado aún no válido")]
    NotYetValid,
    /// El instante actual es igual o posterior a `notAfter`.
    #[error("certificado expirado")]
    Expired,
    /// El número de serie figura como revocado (CRL u OCSP).
    #[error("certificado revocado")]
    Revoked,
    /// La CRL sobrepasó su `nextUpdate` (información de revocación obsoleta).
    #[error("CRL caducada")]
    CrlExpired,
    /// La respuesta OCSP sobrepasó su `nextUpdate`.
    #[error("respuesta OCSP caducada")]
    OcspExpired,
    /// La OCSP no reporta el estado del certificado (o lo marca `unknown`).
    #[error("estado OCSP desconocido")]
    OcspUnknown,
}

/// Valida un certificado (DER) según IEC 62351-9: comprueba su **ventana de
/// validez** en `now` (epoch s) y, si se aporta una fuente de revocación
/// ([`RevocationSource`]: CRL u OCSP), que **no esté revocado**. No revalida la
/// cadena de confianza (de eso se encarga el verificador TLS/rustls en el
/// handshake).
pub fn validate_certificate(
    cert_der: &[u8],
    revocation: Option<&RevocationSource>,
    now: u64,
) -> Result<(), PkiError> {
    let (not_before, not_after) = cert_validity(cert_der).ok_or(PkiError::Malformed)?;
    if now < not_before {
        return Err(PkiError::NotYetValid);
    }
    if now >= not_after {
        return Err(PkiError::Expired);
    }
    if let Some(rev) = revocation {
        let serial = cert_serial_number(cert_der).ok_or(PkiError::Malformed)?;
        rev.check(&serial, now)?;
    }
    Ok(())
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

    // --- PKI / CRL (62351-9) ---

    use crate::ber::writer::BerWriter;

    /// Construye un certificado DER mínimo (versión, serial, validez, subject).
    fn build_cert(serial: &[u8], not_before: &str, not_after: &str) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(universal::SEQUENCE, |w| {
            w.tlv(universal::SEQUENCE, |w| {
                // version [0] EXPLICIT INTEGER 2 (v3)
                w.tlv(Tag::context(0, true), |w| w.integer(universal::INTEGER, 2));
                w.primitive(universal::INTEGER, serial); // serialNumber
                w.tlv(universal::SEQUENCE, |_| {}); // signature AlgorithmIdentifier
                w.tlv(universal::SEQUENCE, |_| {}); // issuer Name
                w.tlv(universal::SEQUENCE, |w| {
                    w.primitive(UTC_TIME, not_before.as_bytes());
                    w.primitive(UTC_TIME, not_after.as_bytes());
                });
                w.tlv(universal::SEQUENCE, |_| {}); // subject Name
            });
            w.tlv(universal::SEQUENCE, |_| {}); // signatureAlgorithm
            w.primitive(Tag::universal(0x03, false), &[0x00]); // signatureValue
        });
        w.into_bytes()
    }

    /// Construye una CRL DER con los seriales revocados dados.
    fn build_crl(this: &str, next: Option<&str>, revoked: &[&[u8]]) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.tlv(universal::SEQUENCE, |w| {
            w.tlv(universal::SEQUENCE, |w| {
                w.tlv(universal::SEQUENCE, |_| {}); // signature AlgorithmIdentifier
                w.tlv(universal::SEQUENCE, |_| {}); // issuer Name
                w.primitive(UTC_TIME, this.as_bytes()); // thisUpdate
                if let Some(n) = next {
                    w.primitive(UTC_TIME, n.as_bytes()); // nextUpdate
                }
                if !revoked.is_empty() {
                    w.tlv(universal::SEQUENCE, |w| {
                        for s in revoked {
                            w.tlv(universal::SEQUENCE, |w| {
                                w.primitive(universal::INTEGER, s); // userCertificate
                                w.primitive(UTC_TIME, this.as_bytes()); // revocationDate
                            });
                        }
                    });
                }
            });
            w.tlv(universal::SEQUENCE, |_| {}); // signatureAlgorithm
            w.primitive(Tag::universal(0x03, false), &[0x00]); // signatureValue
        });
        w.into_bytes()
    }

    #[test]
    fn parses_cert_validity_and_serial() {
        let der = build_cert(&[0x12, 0x34], "230101000000Z", "330101000000Z");
        assert_eq!(cert_serial_number(&der).unwrap(), vec![0x12, 0x34]);
        let (nb, na) = cert_validity(&der).unwrap();
        assert_eq!(nb, 1_672_531_200); // 2023-01-01T00:00:00Z
        assert!(nb < na);
    }

    #[test]
    fn parses_crl_and_detects_revocation() {
        let crl = parse_crl(&build_crl(
            "230101000000Z",
            Some("330101000000Z"),
            &[&[0x12, 0x34], &[0xAB]],
        ))
        .unwrap();
        assert_eq!(crl.revoked.len(), 2);
        assert!(crl.is_revoked(&[0x12, 0x34]));
        assert!(crl.is_revoked(&[0x00, 0xAB])); // normaliza el relleno
        assert!(!crl.is_revoked(&[0x99]));
        assert!(crl.next_update.is_some());
    }

    #[test]
    fn validate_certificate_flow() {
        let now = 1_700_000_000; // 2023-11-14
        let good = build_cert(&[0x01], "230101000000Z", "330101000000Z");
        assert!(validate_certificate(&good, None, now).is_ok());

        let expired = build_cert(&[0x02], "200101000000Z", "210101000000Z");
        assert_eq!(
            validate_certificate(&expired, None, now),
            Err(PkiError::Expired)
        );
        let future = build_cert(&[0x03], "300101000000Z", "330101000000Z");
        assert_eq!(
            validate_certificate(&future, None, now),
            Err(PkiError::NotYetValid)
        );

        // Revocado por la CRL.
        let crl: RevocationSource = parse_crl(&build_crl(
            "230101000000Z",
            Some("330101000000Z"),
            &[&[0x01]],
        ))
        .unwrap()
        .into();
        assert_eq!(
            validate_certificate(&good, Some(&crl), now),
            Err(PkiError::Revoked)
        );
        // CRL caducada (nextUpdate en el pasado).
        let stale: RevocationSource =
            parse_crl(&build_crl("200101000000Z", Some("210101000000Z"), &[]))
                .unwrap()
                .into();
        assert_eq!(
            validate_certificate(&good, Some(&stale), now),
            Err(PkiError::CrlExpired)
        );
    }

    /// Construye una respuesta OCSP DER con el estado dado para un serial.
    fn build_ocsp(serial: &[u8], revoked: bool, this: &str, next: Option<&str>) -> Vec<u8> {
        // SingleResponse.
        let mut sr = BerWriter::new();
        sr.tlv(universal::SEQUENCE, |w| {
            // certID SEQUENCE { hashAlg, nameHash, keyHash, serial }
            w.tlv(universal::SEQUENCE, |w| {
                w.tlv(universal::SEQUENCE, |_| {}); // hashAlgorithm
                w.primitive(universal::OCTET_STRING, &[0u8; 4]); // issuerNameHash
                w.primitive(universal::OCTET_STRING, &[0u8; 4]); // issuerKeyHash
                w.primitive(universal::INTEGER, serial); // serialNumber
            });
            // certStatus CHOICE.
            if revoked {
                w.tlv(Tag::context(1, true), |w| {
                    w.primitive(GENERALIZED_TIME, this.as_bytes()); // revocationTime
                });
            } else {
                w.primitive(Tag::context(0, false), &[]); // good [0] NULL
            }
            w.primitive(GENERALIZED_TIME, this.as_bytes()); // thisUpdate
            if let Some(n) = next {
                w.tlv(Tag::context(0, true), |w| {
                    w.primitive(GENERALIZED_TIME, n.as_bytes()); // nextUpdate [0] EXPLICIT
                });
            }
        });
        let single = sr.into_bytes();

        // BasicOCSPResponse.
        let mut basic = BerWriter::new();
        basic.tlv(universal::SEQUENCE, |w| {
            w.tlv(universal::SEQUENCE, |w| {
                // ResponseData
                w.tlv(Tag::context(1, true), |w| {
                    w.tlv(universal::SEQUENCE, |_| {})
                }); // responderID byName
                w.primitive(GENERALIZED_TIME, this.as_bytes()); // producedAt
                w.tlv(universal::SEQUENCE, |w| w.raw(&single)); // responses
            });
            w.tlv(universal::SEQUENCE, |_| {}); // signatureAlgorithm
            w.primitive(Tag::universal(0x03, false), &[0x00]); // signature
        });
        let basic = basic.into_bytes();

        // OCSPResponse.
        let mut w = BerWriter::new();
        w.tlv(universal::SEQUENCE, |w| {
            w.primitive(ENUMERATED, &[0x00]); // responseStatus = successful
            w.tlv(Tag::context(0, true), |w| {
                w.tlv(universal::SEQUENCE, |w| {
                    w.primitive(
                        universal::OID,
                        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
                    );
                    w.primitive(universal::OCTET_STRING, &basic);
                });
            });
        });
        w.into_bytes()
    }

    #[test]
    fn parses_ocsp_and_reports_status() {
        let ocsp = parse_ocsp_response(&build_ocsp(
            &[0x12, 0x34],
            false,
            "20230101000000Z",
            Some("20330101000000Z"),
        ))
        .expect("OCSP válida");
        assert_eq!(ocsp.responses.len(), 1);
        let sr = ocsp.status_of(&[0x12, 0x34]).unwrap();
        assert_eq!(sr.status, CertStatus::Good);
        assert!(sr.next_update.is_some());
        assert!(ocsp.status_of(&[0x99]).is_none());
    }

    #[test]
    fn validate_certificate_with_ocsp() {
        let now = 1_700_000_000; // 2023-11-14
        let cert = build_cert(&[0x0A], "230101000000Z", "330101000000Z");

        // OCSP 'good' → válido.
        let good: RevocationSource = parse_ocsp_response(&build_ocsp(
            &[0x0A],
            false,
            "20230101000000Z",
            Some("20330101000000Z"),
        ))
        .unwrap()
        .into();
        assert!(validate_certificate(&cert, Some(&good), now).is_ok());

        // OCSP 'revoked' → revocado.
        let revoked: RevocationSource = parse_ocsp_response(&build_ocsp(
            &[0x0A],
            true,
            "20230101000000Z",
            Some("20330101000000Z"),
        ))
        .unwrap()
        .into();
        assert_eq!(
            validate_certificate(&cert, Some(&revoked), now),
            Err(PkiError::Revoked)
        );

        // Serial no cubierto por la OCSP → estado desconocido.
        let other: RevocationSource = parse_ocsp_response(&build_ocsp(
            &[0xFF],
            false,
            "20230101000000Z",
            Some("20330101000000Z"),
        ))
        .unwrap()
        .into();
        assert_eq!(
            validate_certificate(&cert, Some(&other), now),
            Err(PkiError::OcspUnknown)
        );

        // OCSP caducada (nextUpdate en el pasado).
        let stale: RevocationSource = parse_ocsp_response(&build_ocsp(
            &[0x0A],
            false,
            "20200101000000Z",
            Some("20210101000000Z"),
        ))
        .unwrap()
        .into();
        assert_eq!(
            validate_certificate(&cert, Some(&stale), now),
            Err(PkiError::OcspExpired)
        );
    }
}
