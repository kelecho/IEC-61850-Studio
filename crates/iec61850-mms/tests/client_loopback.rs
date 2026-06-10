//! Test de integración del cliente MMS contra un servidor simulado en proceso.
//!
//! No requiere hardware: un `TcpListener` local responde la secuencia
//! COTP/asociación/servicios usando los propios codificadores del crate. Cubre
//! connect → identify → read → write → operate (control) → InformationReport, y
//! el cierre de conexión.
#![cfg(feature = "client")]

use iec61850_mms::MmsClient;
use iec61850_mms::ber::prim::BitString;
use iec61850_mms::ber::reader::BerReader;
use iec61850_mms::ber::tag::{Tag, TagClass, universal};
use iec61850_mms::ber::writer::BerWriter;
use iec61850_mms::mms::data::MmsData;
use iec61850_mms::mms::pdu::{mmspdu, service, unconfirmed_service};
use iec61850_mms::transport::{cotp, tpkt};
use iec61850_mms::upper::{acse, presentation, session};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ACSE_CTX: i64 = presentation::ACSE_CONTEXT_ID;
const EXTERNAL: Tag = Tag::new(TagClass::Universal, true, 8);

async fn read_tpkt(sock: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    sock.read_exact(&mut header).await.unwrap();
    let len = tpkt::payload_len(&header).unwrap();
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).await.unwrap();
    payload
}

async fn write_tpkt(sock: &mut TcpStream, payload: &[u8]) {
    sock.write_all(&tpkt::frame(payload)).await.unwrap();
}

async fn send_mms(sock: &mut TcpStream, pdu: &[u8]) {
    let ud = presentation::user_data(pdu, ACSE_CTX);
    write_tpkt(sock, &cotp::data_tpdu(&session::data(&ud))).await;
}

/// Lee un request MMS del socket y devuelve (invokeID, tag de servicio, pdu).
async fn read_request(sock: &mut TcpStream) -> (u32, Tag) {
    let req = read_tpkt(sock).await;
    let pdu = presentation::extract_inner_pdu(cotp::parse_data_tpdu(&req).unwrap()).unwrap();
    let mut r = BerReader::new(pdu);
    let outer = r.read_tlv().unwrap();
    assert_eq!(outer.tag, mmspdu::CONFIRMED_REQUEST);
    let mut inner = outer.reader();
    let invoke = iec61850_mms::ber::prim::decode_integer(inner.expect(universal::INTEGER).unwrap())
        .unwrap() as u32;
    (invoke, inner.read_tlv().unwrap().tag)
}

fn initiate_response() -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::INITIATE_RESPONSE, |w| {
        w.integer(Tag::context(0, false), 65000);
        w.integer(Tag::context(1, false), 5);
        w.integer(Tag::context(2, false), 5);
        w.integer(Tag::context(3, false), 10);
        w.tlv(Tag::context(4, true), |w| {
            w.integer(Tag::context(0, false), 1)
        });
    });
    w.into_bytes()
}

fn aare(initiate_resp: &[u8]) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(Tag::application(1, true), |w| {
        w.tlv(Tag::context(1, true), |w| {
            w.object_identifier(universal::OID, &acse::MMS_APP_CONTEXT)
        });
        w.integer(Tag::context(2, false), 0);
        w.tlv(Tag::context(30, true), |w| {
            w.tlv(EXTERNAL, |w| {
                w.integer(universal::INTEGER, 3);
                w.tlv(Tag::context(0, true), |w| w.raw(initiate_resp));
            });
        });
    });
    w.into_bytes()
}

fn confirmed_response(invoke: u32, service: impl FnOnce(&mut BerWriter)) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::CONFIRMED_RESPONSE, |w| {
        w.integer(universal::INTEGER, invoke as i64);
        service(w);
    });
    w.into_bytes()
}

fn identify_response(invoke: u32) -> Vec<u8> {
    confirmed_response(invoke, |w| {
        w.tlv(service::IDENTIFY_RESPONSE, |w| {
            w.visible_string(Tag::context(0, false), "ACME");
            w.visible_string(Tag::context(1, false), "IED-X");
            w.visible_string(Tag::context(2, false), "1.0");
        });
    })
}

fn read_response(invoke: u32, value: &MmsData) -> Vec<u8> {
    confirmed_response(invoke, |w| {
        w.tlv(service::READ, |w| {
            w.tlv(Tag::context(1, true), |w| value.encode(w));
        });
    })
}

fn write_response_ok(invoke: u32) -> Vec<u8> {
    confirmed_response(invoke, |w| {
        w.tlv(service::WRITE, |w| w.null(Tag::context(1, false))); // success [1] NULL
    })
}

/// InformationReport no solicitado con un RptID y un valor incluido.
fn information_report(rpt_id: &str, value: &MmsData) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(mmspdu::UNCONFIRMED, |w| {
        w.tlv(unconfirmed_service::INFORMATION_REPORT, |w| {
            // listOfAccessResult [0] (sin variableAccessSpecification)
            w.tlv(Tag::context(0, true), |w| {
                MmsData::Visible(rpt_id.into()).encode(w);
                MmsData::BitString(BitString::from_bits(&[false; 10])).encode(w); // OptFlds
                MmsData::BitString(BitString::from_bits(&[true])).encode(w); // inclusion
                value.encode(w);
            });
        });
    });
    w.into_bytes()
}

async fn accept_and_associate(listener: &TcpListener) -> TcpStream {
    let (mut sock, _) = listener.accept().await.unwrap();
    let _cr = read_tpkt(&mut sock).await;
    write_tpkt(&mut sock, &[0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00]).await; // CC
    let _assoc = read_tpkt(&mut sock).await;
    send_mms(&mut sock, &aare(&initiate_response())).await;
    sock
}

#[tokio::test]
async fn full_service_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let mut sock = accept_and_associate(&listener).await;

        // Identify
        let (inv, tag) = read_request(&mut sock).await;
        assert_eq!(tag, service::IDENTIFY_REQUEST);
        send_mms(&mut sock, &identify_response(inv)).await;

        // Read
        let (inv, tag) = read_request(&mut sock).await;
        assert_eq!(tag, service::READ);
        send_mms(&mut sock, &read_response(inv, &MmsData::Float(1.5))).await;

        // Write
        let (inv, tag) = read_request(&mut sock).await;
        assert_eq!(tag, service::WRITE);
        send_mms(&mut sock, &write_response_ok(inv)).await;

        // Operate (control = write de Oper)
        let (inv, tag) = read_request(&mut sock).await;
        assert_eq!(tag, service::WRITE);
        send_mms(&mut sock, &write_response_ok(inv)).await;

        // Reporte no solicitado
        send_mms(&mut sock, &information_report("rcb01", &MmsData::Int(99))).await;

        // mantener el socket vivo un instante para que el cliente reciba el reporte
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let mut client = MmsClient::connect(addr).await.expect("conecta");
    let mut reports = client.take_report_rx().unwrap();
    assert_eq!(client.negotiated().version, 1);

    let id = client.identify().await.unwrap();
    assert_eq!(id.vendor, "ACME");

    let value = client
        .read(&"IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(value, MmsData::Float(1.5));

    client
        .write(
            &"IED1LD0/GGIO1.SPCSO1.stVal[CF]".parse().unwrap(),
            MmsData::Bool(true),
        )
        .await
        .unwrap();

    // operate sobre un DO de control (FC se fuerza a CO; se añade $Oper)
    client
        .operate(
            &"IED1LD0/CSWI1.Pos[CO]".parse().unwrap(),
            MmsData::Bool(true),
        )
        .await
        .unwrap();

    let report = reports.recv().await.expect("reporte");
    assert_eq!(report.rpt_id, "rcb01");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].value, MmsData::Int(99));

    server.await.unwrap();
}

#[tokio::test]
async fn connection_close_propagates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let sock = accept_and_associate(&listener).await;
        // cerrar el socket inmediatamente tras asociar
        drop(sock);
    });

    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();
    server.await.unwrap();

    // una petición tras el cierre debe fallar (cerrado), no colgarse.
    let res = client.identify().await;
    assert!(res.is_err(), "se esperaba error tras el cierre: {res:?}");
    // el canal de reportes se cierra.
    assert!(reports.recv().await.is_none());
}
