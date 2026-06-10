//! Test de integración TLS/mTLS (IEC 62351-3): cliente real ↔ servidor real
//! sobre una conexión cifrada con autenticación mutua. Los certificados se
//! generan al vuelo con `rcgen` (sin material de claves en el repo).
#![cfg(all(feature = "client", feature = "server", feature = "tls"))]

use std::path::PathBuf;
use std::sync::Arc;

use iec61850_mms::{
    IdentifyResponse, MmsClient, MmsData, MmsServer, ServerModel, TlsAcceptor, TlsClientOptions,
    TlsServerOptions,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/icd/simple.icd")
}

fn ident() -> IdentifyResponse {
    IdentifyResponse {
        vendor: "ACME".into(),
        model: "IED-SIM".into(),
        revision: "1.0".into(),
    }
}

/// Genera un par certificado autofirmado (SAN `localhost`) + clave en DER.
fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (cert, key)
}

async fn start_tls_server(
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client_ca: CertificateDer<'static>,
) -> std::net::SocketAddr {
    let acceptor = TlsServerOptions {
        server_cert: vec![server_cert],
        server_key,
        client_ca: vec![client_ca],
    }
    .acceptor()
    .unwrap();
    start_with_acceptor(acceptor).await
}

async fn start_with_acceptor(acceptor: TlsAcceptor) -> std::net::SocketAddr {
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind_tls("127.0.0.1:0", Arc::new(sm), store, acceptor)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

/// Genera un par certificado autofirmado (SAN `localhost`) en formato PEM.
fn gen_cert_pem() -> (String, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (ck.cert.pem(), ck.key_pair.serialize_pem())
}

/// Genera una CA y un certificado de hoja firmado por ella. Devuelve
/// `(ca_pem, leaf_pem, leaf_key_pem)`.
fn gen_ca_and_leaf() -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    (ca.pem(), leaf.pem(), leaf_key.serialize_pem())
}

#[tokio::test]
async fn mtls_from_pem() {
    let (server_pem, server_key_pem) = gen_cert_pem();
    let (client_pem, client_key_pem) = gen_cert_pem();

    // Servidor: cadena + clave en PEM; confía en el cert de cliente (PEM).
    let acceptor = TlsServerOptions::from_pem(
        server_pem.as_bytes(),
        server_key_pem.as_bytes(),
        client_pem.as_bytes(),
    )
    .unwrap()
    .acceptor()
    .unwrap();
    let addr = start_with_acceptor(acceptor).await;

    // Cliente: confía en el cert del servidor (PEM) y presenta el suyo (PEM).
    let connector = TlsClientOptions::from_pem(
        server_pem.as_bytes(),
        client_pem.as_bytes(),
        client_key_pem.as_bytes(),
    )
    .unwrap()
    .connector()
    .unwrap();

    let client = MmsClient::connect_tls(addr, "localhost", connector)
        .await
        .expect("conecta sobre TLS con material PEM");
    assert_eq!(client.identify().await.unwrap().vendor, "ACME");
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    assert_eq!(client.read(&f_ref).await.unwrap(), MmsData::Float(1.5));
}

#[tokio::test]
async fn mtls_ca_signed_chain() {
    // Certs de servidor y cliente firmados por sendas CA; cada lado confía en la
    // CA del otro (ancla de confianza ≠ leaf), validando la verificación de cadena.
    let (server_ca, server_leaf, server_key) = gen_ca_and_leaf();
    let (client_ca, client_leaf, client_key) = gen_ca_and_leaf();

    let acceptor = TlsServerOptions::from_pem(
        server_leaf.as_bytes(),
        server_key.as_bytes(),
        client_ca.as_bytes(), // verifica al cliente contra SU CA
    )
    .unwrap()
    .acceptor()
    .unwrap();
    let addr = start_with_acceptor(acceptor).await;

    let connector = TlsClientOptions::from_pem(
        server_ca.as_bytes(), // confía en la CA del servidor, no en el leaf
        client_leaf.as_bytes(),
        client_key.as_bytes(),
    )
    .unwrap()
    .connector()
    .unwrap();

    let client = MmsClient::connect_tls(addr, "localhost", connector)
        .await
        .expect("handshake con cadena firmada por CA");
    assert_eq!(client.identify().await.unwrap().vendor, "ACME");
}

#[tokio::test]
async fn mtls_client_against_server() {
    let (server_cert, server_key) = gen_cert();
    let (client_cert, client_key) = gen_cert();

    let addr = start_tls_server(server_cert.clone(), server_key, client_cert.clone()).await;

    // Cliente que confía en el cert del servidor y presenta el suyo (mTLS).
    let connector = TlsClientOptions {
        ca: vec![server_cert],
        client_cert: vec![client_cert],
        client_key,
    }
    .connector()
    .unwrap();

    let client = MmsClient::connect_tls(addr, "localhost", connector)
        .await
        .expect("conecta y asocia sobre TLS");

    // La pila MMS completa funciona cifrada.
    let id = client.identify().await.unwrap();
    assert_eq!(id.vendor, "ACME");
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    assert_eq!(client.read(&f_ref).await.unwrap(), MmsData::Float(1.5));
}

#[tokio::test]
async fn mtls_handshake_fails_with_untrusted_server() {
    let (server_cert, server_key) = gen_cert();
    let (client_cert, client_key) = gen_cert();
    let addr = start_tls_server(server_cert, server_key, client_cert.clone()).await;

    // El cliente NO confía en el cert del servidor (CA distinta) → handshake falla.
    let (other_ca, _) = gen_cert();
    let connector = TlsClientOptions {
        ca: vec![other_ca],
        client_cert: vec![client_cert],
        client_key,
    }
    .connector()
    .unwrap();

    assert!(
        MmsClient::connect_tls(addr, "localhost", connector)
            .await
            .is_err()
    );
}
