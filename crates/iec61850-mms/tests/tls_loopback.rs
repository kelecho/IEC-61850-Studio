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

/// Genera una CA reutilizable (objeto + clave) para firmar varios leaf.
fn gen_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    (ca, ca_key)
}

/// Genera un cert de hoja (SAN `localhost`) con el `CommonName` dado, firmado por
/// la CA. Devuelve `(cert_der, key_der)`.
fn gen_leaf_with_cn(
    ca: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    cn: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let leaf = params.signed_by(&key, ca, ca_key).unwrap();
    let der = leaf.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

#[tokio::test]
async fn mtls_certificate_authentication_by_cn() {
    use iec61850_mms::{AuthPolicy, MmsError, Role};

    // Una CA firma el cert del servidor y los de los clientes: todos son
    // criptográficamente válidos; el CN decide el ROL (o el rechazo).
    let (ca, ca_key) = gen_ca();
    let ca_der = ca.der().clone();
    let (server_cert, server_key) = gen_leaf_with_cn(&ca, &ca_key, "ied-server");
    let (eng_cert, eng_key) = gen_leaf_with_cn(&ca, &ca_key, "engineer@ied");
    let (view_cert, view_key) = gen_leaf_with_cn(&ca, &ca_key, "viewer@ied");
    let (intruder_cert, intruder_key) = gen_leaf_with_cn(&ca, &ca_key, "intruso@ied");

    // Servidor mTLS: confía en la CA para verificar clientes; autoriza por CN.
    let acceptor = TlsServerOptions {
        server_cert: vec![server_cert],
        server_key,
        client_ca: vec![ca_der.clone()],
    }
    .acceptor()
    .unwrap();
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind_tls("127.0.0.1:0", Arc::new(sm), store, acceptor)
        .await
        .unwrap()
        .with_auth(AuthPolicy::Certificates(vec![
            ("engineer@ied".into(), Role::Engineer),
            ("viewer@ied".into(), Role::Viewer),
        ]));
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let f_ref: iec61850_model::ObjectReference =
        "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();

    let connector = |cert, key| {
        TlsClientOptions {
            ca: vec![ca_der.clone()],
            client_cert: vec![cert],
            client_key: key,
        }
        .connector()
        .unwrap()
    };

    // Engineer: asocia por su CN y puede escribir.
    let eng = MmsClient::connect_tls(addr, "localhost", connector(eng_cert, eng_key))
        .await
        .expect("engineer asocia por certificado");
    eng.write(&f_ref, MmsData::Float(5.0))
        .await
        .expect("engineer escribe");
    assert_eq!(eng.read(&f_ref).await.unwrap(), MmsData::Float(5.0));

    // Viewer: asocia pero NO puede escribir (RBAC por CN).
    let viewer = MmsClient::connect_tls(addr, "localhost", connector(view_cert, view_key))
        .await
        .expect("viewer asocia por certificado");
    assert!(viewer.read(&f_ref).await.is_ok());
    assert!(matches!(
        viewer.write(&f_ref, MmsData::Float(9.0)).await,
        Err(MmsError::DataAccess(_))
    ));

    // Intruso: cert válido (firmado por la CA) pero CN no autorizado → rechazo
    // de la asociación aunque el handshake TLS tenga éxito.
    assert!(
        MmsClient::connect_tls(addr, "localhost", connector(intruder_cert, intruder_key))
            .await
            .is_err(),
        "un CN no autorizado debe rechazarse en la asociación"
    );
}

/// Construye una CRL DER (RFC 5280) que revoca `revoked_serial`.
fn build_crl(revoked_serial: &[u8]) -> Vec<u8> {
    use iec61850_mms::ber::tag::{Tag, universal};
    use iec61850_mms::ber::writer::BerWriter;
    const UTC: Tag = Tag::universal(0x17, false);
    let mut w = BerWriter::new();
    w.tlv(universal::SEQUENCE, |w| {
        w.tlv(universal::SEQUENCE, |w| {
            w.tlv(universal::SEQUENCE, |_| {}); // signature AlgorithmIdentifier
            w.tlv(universal::SEQUENCE, |_| {}); // issuer Name
            w.primitive(UTC, b"200101000000Z"); // thisUpdate
            w.primitive(UTC, b"350101000000Z"); // nextUpdate (lejano)
            w.tlv(universal::SEQUENCE, |w| {
                w.tlv(universal::SEQUENCE, |w| {
                    w.primitive(universal::INTEGER, revoked_serial);
                    w.primitive(UTC, b"200101000000Z");
                });
            });
        });
        w.tlv(universal::SEQUENCE, |_| {}); // signatureAlgorithm
        w.primitive(Tag::universal(0x03, false), &[0x00]); // signatureValue
    });
    w.into_bytes()
}

/// Construye una respuesta OCSP DER (RFC 6960) con el estado de cada `(serial,
/// revocado)`.
fn build_ocsp(entries: &[(&[u8], bool)]) -> Vec<u8> {
    use iec61850_mms::ber::tag::{Tag, universal};
    use iec61850_mms::ber::writer::BerWriter;
    const GT: Tag = Tag::universal(0x18, false);
    const ENUM: Tag = Tag::universal(0x0A, false);
    const THIS: &[u8] = b"20200101000000Z";
    const NEXT: &[u8] = b"20350101000000Z";

    let mut responses = BerWriter::new();
    for (serial, revoked) in entries {
        responses.tlv(universal::SEQUENCE, |w| {
            w.tlv(universal::SEQUENCE, |w| {
                w.tlv(universal::SEQUENCE, |_| {}); // hashAlgorithm
                w.primitive(universal::OCTET_STRING, &[0u8; 4]);
                w.primitive(universal::OCTET_STRING, &[0u8; 4]);
                w.primitive(universal::INTEGER, serial);
            });
            if *revoked {
                w.tlv(Tag::context(1, true), |w| w.primitive(GT, THIS));
            } else {
                w.primitive(Tag::context(0, false), &[]);
            }
            w.primitive(GT, THIS);
            w.tlv(Tag::context(0, true), |w| w.primitive(GT, NEXT));
        });
    }
    let responses = responses.into_bytes();

    let mut basic = BerWriter::new();
    basic.tlv(universal::SEQUENCE, |w| {
        w.tlv(universal::SEQUENCE, |w| {
            w.tlv(Tag::context(1, true), |w| {
                w.tlv(universal::SEQUENCE, |_| {})
            });
            w.primitive(GT, THIS);
            w.tlv(universal::SEQUENCE, |w| w.raw(&responses));
        });
        w.tlv(universal::SEQUENCE, |_| {});
        w.primitive(Tag::universal(0x03, false), &[0x00]);
    });
    let basic = basic.into_bytes();

    let mut w = BerWriter::new();
    w.tlv(universal::SEQUENCE, |w| {
        w.primitive(ENUM, &[0x00]);
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

#[tokio::test]
async fn mtls_ocsp_revoked_cert_rejected() {
    use iec61850_mms::{AuthPolicy, Role, cert_serial_number, parse_ocsp_response};

    let (ca, ca_key) = gen_ca();
    let ca_der = ca.der().clone();
    let (server_cert, server_key) = gen_leaf_with_cn(&ca, &ca_key, "ied-server");
    let (good_cert, good_key) = gen_leaf_with_cn(&ca, &ca_key, "engineer@ied");
    let (revoked_cert, revoked_key) = gen_leaf_with_cn(&ca, &ca_key, "engineer@ied");

    let good_serial = cert_serial_number(good_cert.as_ref()).unwrap();
    let revoked_serial = cert_serial_number(revoked_cert.as_ref()).unwrap();
    // OCSP: el bueno 'good', el otro 'revoked'.
    let ocsp = parse_ocsp_response(&build_ocsp(&[
        (&good_serial, false),
        (&revoked_serial, true),
    ]))
    .expect("OCSP válida");

    let acceptor = TlsServerOptions {
        server_cert: vec![server_cert],
        server_key,
        client_ca: vec![ca_der.clone()],
    }
    .acceptor()
    .unwrap();
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind_tls("127.0.0.1:0", Arc::new(sm), store, acceptor)
        .await
        .unwrap()
        .with_auth(AuthPolicy::Certificates(vec![(
            "engineer@ied".into(),
            Role::Engineer,
        )]))
        .with_ocsp(ocsp);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let connector = |cert, key| {
        TlsClientOptions {
            ca: vec![ca_der.clone()],
            client_cert: vec![cert],
            client_key: key,
        }
        .connector()
        .unwrap()
    };

    // OCSP 'good' → asocia.
    assert!(
        MmsClient::connect_tls(addr, "localhost", connector(good_cert, good_key))
            .await
            .is_ok(),
        "un certificado con OCSP 'good' debe asociar"
    );
    // OCSP 'revoked' → rechazado.
    assert!(
        MmsClient::connect_tls(addr, "localhost", connector(revoked_cert, revoked_key))
            .await
            .is_err(),
        "un certificado con OCSP 'revoked' debe rechazarse"
    );
}

#[tokio::test]
async fn mtls_revoked_cert_rejected() {
    use iec61850_mms::{AuthPolicy, Role, cert_serial_number, parse_crl};

    // Dos clientes con el MISMO CN autorizado (engineer@ied): solo la revocación
    // por CRL (IEC 62351-9) los diferencia.
    let (ca, ca_key) = gen_ca();
    let ca_der = ca.der().clone();
    let (server_cert, server_key) = gen_leaf_with_cn(&ca, &ca_key, "ied-server");
    let (good_cert, good_key) = gen_leaf_with_cn(&ca, &ca_key, "engineer@ied");
    let (revoked_cert, revoked_key) = gen_leaf_with_cn(&ca, &ca_key, "engineer@ied");

    // CRL que revoca el número de serie del cert 'revoked'.
    let revoked_serial = cert_serial_number(revoked_cert.as_ref()).unwrap();
    let crl = parse_crl(&build_crl(&revoked_serial)).expect("CRL válida");

    let acceptor = TlsServerOptions {
        server_cert: vec![server_cert],
        server_key,
        client_ca: vec![ca_der.clone()],
    }
    .acceptor()
    .unwrap();
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind_tls("127.0.0.1:0", Arc::new(sm), store, acceptor)
        .await
        .unwrap()
        .with_auth(AuthPolicy::Certificates(vec![(
            "engineer@ied".into(),
            Role::Engineer,
        )]))
        .with_crl(crl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let connector = |cert, key| {
        TlsClientOptions {
            ca: vec![ca_der.clone()],
            client_cert: vec![cert],
            client_key: key,
        }
        .connector()
        .unwrap()
    };

    // Cert vigente y NO revocado → asocia.
    assert!(
        MmsClient::connect_tls(addr, "localhost", connector(good_cert, good_key))
            .await
            .is_ok(),
        "un certificado vigente y no revocado debe asociar"
    );
    // Cert revocado → asociación rechazada aunque el TLS y el CN sean válidos.
    assert!(
        MmsClient::connect_tls(addr, "localhost", connector(revoked_cert, revoked_key))
            .await
            .is_err(),
        "un certificado revocado (CRL) debe rechazarse"
    );
}
