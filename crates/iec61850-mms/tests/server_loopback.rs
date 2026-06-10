//! Test de integración: el `MmsClient` real contra el `MmsServer` real, en
//! proceso. Valida AMBOS lados de la pila ISO entre sí (cierra la deuda
//! "best-effort sin hardware") y los servicios GetNameList/Read/Write.
#![cfg(all(feature = "client", feature = "server"))]

use std::path::PathBuf;
use std::sync::Arc;

use iec61850_mms::{
    ControlParameters, IdentifyResponse, MmsClient, MmsData, MmsError, MmsServer, ServerModel,
};

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

async fn start_server(page_size: usize) -> (std::net::SocketAddr, iec61850_mms::ServerHandle) {
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident()).with_page_size(page_size);
    let store = sm.init_store(&model);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.handle();
    tokio::spawn(server.serve());
    (addr, handle)
}

#[tokio::test]
async fn client_against_server_end_to_end() {
    let (addr, handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.expect("conecta y asocia");

    // Asociación e Identify.
    assert_eq!(client.negotiated().version, 1);
    let id = client.identify().await.unwrap();
    assert_eq!(id.vendor, "ACME");
    assert_eq!(id.model, "IED-SIM");

    // Descubrimiento.
    let lds = client.get_server_directory().await.unwrap();
    assert_eq!(lds, vec!["IED1LD0".to_string()]);
    let vars = client
        .get_logical_device_directory("IED1LD0")
        .await
        .unwrap();
    assert!(
        vars.iter()
            .any(|r| r.to_string().starts_with("IED1LD0/MMXU1.A.phsA.cVal.mag.f")),
        "debe descubrir el measurand: {vars:?}"
    );

    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();

    // Read del valor por defecto del SCL.
    assert_eq!(client.read(&f_ref).await.unwrap(), MmsData::Float(1.5));

    // Write y relectura.
    client.write(&f_ref, MmsData::Float(9.0)).await.unwrap();
    assert_eq!(client.read(&f_ref).await.unwrap(), MmsData::Float(9.0));

    // Inyección por el handle de la app, observada por el cliente.
    handle.set_value(&f_ref, MmsData::Float(2.5)).await.unwrap();
    assert_eq!(client.read(&f_ref).await.unwrap(), MmsData::Float(2.5));

    // Variable inexistente → fallo de acceso.
    let bad = "IED1LD0/MMXU1.NoExiste.x[MX]".parse().unwrap();
    assert!(client.read(&bad).await.is_err());
}

#[tokio::test]
async fn get_name_list_pagination() {
    // página de tamaño 1 → el cliente debe reconstruir la lista completa
    // iterando continueAfter/moreFollows.
    let (addr, _handle) = start_server(1).await;
    let client = MmsClient::connect(addr).await.unwrap();

    let vars = client
        .get_logical_device_directory("IED1LD0")
        .await
        .unwrap();
    // simple.icd tiene varios DA en LD0; con página=1 forzamos varias rondas.
    assert!(
        vars.len() >= 5,
        "esperados varios items, got {}",
        vars.len()
    );
    // sin duplicados ni huecos: el conteo coincide con una página grande.
    let (addr2, _h2) = start_server(1000).await;
    let client2 = MmsClient::connect(addr2).await.unwrap();
    let vars_full = client2
        .get_logical_device_directory("IED1LD0")
        .await
        .unwrap();
    assert_eq!(vars.len(), vars_full.len());
}

#[tokio::test]
async fn reporting_dchg_and_gi() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    // Habilitar el URCB rcb1 (config por defecto → usa DatSet/OptFlds sembrados).
    let rcb = "IED1LD0/LLN0.rcb1[RP]".parse().unwrap();
    client
        .enable_report(&rcb, &Default::default())
        .await
        .unwrap();

    // Cambiar un miembro del dataset por el handle → reporte por dchg.
    let member = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    handle
        .set_value(&member, MmsData::Float(7.5))
        .await
        .unwrap();

    let report = reports.recv().await.expect("reporte dchg");
    assert_eq!(report.rpt_id, "IED1LD0/LLN0.rcb1");
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.value == MmsData::Float(7.5)),
        "el reporte debe incluir el valor nuevo: {report:?}"
    );

    // Interrogación general → reporte con (todos) los miembros del dataset.
    client.general_interrogation(&rcb).await.unwrap();
    let gi = reports.recv().await.expect("reporte GI");
    assert_eq!(gi.rpt_id, "IED1LD0/LLN0.rcb1");
    assert!(!gi.entries.is_empty());
}

#[tokio::test]
async fn control_operate_and_select() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();

    let do_ctrl = "IED1LD0/GGIO1.SPCSO1[CO]".parse().unwrap();
    let stval = "IED1LD0/GGIO1.SPCSO1.stVal[ST]".parse().unwrap();

    // Estado inicial false; operate(true) lo cambia (control directo).
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(false));
    client.operate(&do_ctrl, MmsData::Bool(true)).await.unwrap();
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(true));

    // Select-before-operate: el servidor concede la selección.
    assert!(client.select(&do_ctrl).await.unwrap());
}

fn entry_id_of(report: &iec61850_mms::Report) -> u64 {
    let bytes = report.entry_id.clone().expect("el BRCB debe traer EntryID");
    u64::from_be_bytes(bytes.try_into().expect("EntryID de 8 octetos"))
}

#[tokio::test]
async fn buffered_reporting_entry_id() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    // Habilitar el BRCB brcb1 (FC BR).
    let brcb = "IED1LD0/LLN0.brcb1[BR]".parse().unwrap();
    client
        .enable_report(&brcb, &Default::default())
        .await
        .unwrap();

    let member = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    for v in [1.0, 2.0, 3.0] {
        handle.set_value(&member, MmsData::Float(v)).await.unwrap();
    }

    // Tres reportes bufferados con EntryID monótono 1,2,3.
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(entry_id_of(&reports.recv().await.expect("reporte BRCB")));
    }
    assert_eq!(ids, vec![1, 2, 3]);
}

#[tokio::test]
async fn buffered_resync_from_entry_id() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    let brcb = "IED1LD0/LLN0.brcb1[BR]".parse().unwrap();
    client
        .enable_report(&brcb, &Default::default())
        .await
        .unwrap();

    let member = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    for v in [1.0, 2.0, 3.0] {
        handle.set_value(&member, MmsData::Float(v)).await.unwrap();
    }
    for _ in 0..3 {
        let _ = reports.recv().await.unwrap();
    }

    // Resync: pedir desde EntryID=1 → replay de 2 y 3.
    let entry_id_ref = "IED1LD0/LLN0.brcb1.EntryID[BR]".parse().unwrap();
    client
        .write(&entry_id_ref, MmsData::Octets(1u64.to_be_bytes().to_vec()))
        .await
        .unwrap();

    assert_eq!(entry_id_of(&reports.recv().await.unwrap()), 2);
    assert_eq!(entry_id_of(&reports.recv().await.unwrap()), 3);
}

#[tokio::test]
async fn buffered_purge() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    let brcb = "IED1LD0/LLN0.brcb1[BR]".parse().unwrap();
    client
        .enable_report(&brcb, &Default::default())
        .await
        .unwrap();

    let member = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    handle
        .set_value(&member, MmsData::Float(1.0))
        .await
        .unwrap();
    assert_eq!(entry_id_of(&reports.recv().await.unwrap()), 1);

    // Vaciar el buffer; un evento posterior genera EntryID 2.
    let purge_ref = "IED1LD0/LLN0.brcb1.PurgeBuf[BR]".parse().unwrap();
    client.write(&purge_ref, MmsData::Bool(true)).await.unwrap();
    handle
        .set_value(&member, MmsData::Float(2.0))
        .await
        .unwrap();
    assert_eq!(entry_id_of(&reports.recv().await.unwrap()), 2);

    // Resync desde 0: el buffer purgado solo conserva el evento 2 (no el 1).
    let entry_id_ref = "IED1LD0/LLN0.brcb1.EntryID[BR]".parse().unwrap();
    client
        .write(&entry_id_ref, MmsData::Octets(0u64.to_be_bytes().to_vec()))
        .await
        .unwrap();
    assert_eq!(entry_id_of(&reports.recv().await.unwrap()), 2);
}

// --- Control de seguridad reforzada (SPCSO2 = sbo-with-enhanced-security) ---

#[tokio::test]
async fn enhanced_operate_ok() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();
    let do2 = "IED1LD0/GGIO1.SPCSO2[CO]".parse().unwrap();
    let stval = "IED1LD0/GGIO1.SPCSO2.stVal[ST]".parse().unwrap();
    let p = ControlParameters::default();

    // sbo-enhanced: seleccionar (SBOw) y luego operar; llega CommandTermination+.
    client
        .select_with_value(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap();
    client
        .operate_enhanced(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap();
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(true));
}

#[tokio::test]
async fn enhanced_operate_interlock_blocked() {
    let (addr, handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();
    let do2 = "IED1LD0/GGIO1.SPCSO2[CO]".parse().unwrap();
    let stval = "IED1LD0/GGIO1.SPCSO2.stVal[ST]".parse().unwrap();

    // El interlock del punto está bloqueado.
    handle
        .set_raw("IED1LD0", "GGIO1$CF$SPCSO2$intlckBlk", MmsData::Bool(true))
        .await;

    // Oper con interlock-check ⇒ CommandTermination− (AddCause 1), sin cambio.
    let p = ControlParameters {
        check: [true, false],
        ..Default::default()
    };
    client
        .select_with_value(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap();
    let err = client
        .operate_enhanced(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap_err();
    assert!(matches!(err, MmsError::ControlTerminated { add_cause: 1 }));
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(false));
}

#[tokio::test]
async fn enhanced_cancel_deselects() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();
    let do2 = "IED1LD0/GGIO1.SPCSO2[CO]".parse().unwrap();
    let p = ControlParameters::default();

    client
        .select_with_value(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap();
    client.cancel(&do2, &p).await.unwrap();

    // Tras Cancel ya no hay selección: operar (sbo) ⇒ acceso denegado.
    let err = client
        .operate_enhanced(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap_err();
    assert!(matches!(err, MmsError::DataAccess(_)));
}

#[tokio::test]
async fn get_variable_access_attributes_reveals_type() {
    use iec61850_mms::TypeSpec;
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();

    // El measurand flotante: el tipo se descubre sin SCL.
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    let attrs = client.type_attributes(&f_ref).await.unwrap();
    assert!(
        matches!(attrs.type_spec, TypeSpec::FloatingPoint { .. }),
        "se esperaba flotante, fue {}",
        attrs.type_spec
    );

    // Un atributo de estado booleano (stVal de un SPC).
    let st_ref = "IED1LD0/GGIO1.SPCSO1.stVal[ST]".parse().unwrap();
    let attrs = client.type_attributes(&st_ref).await.unwrap();
    assert_eq!(attrs.type_spec, TypeSpec::Boolean);

    // Variable inexistente → error de servicio.
    let bad = "IED1LD0/MMXU1.NoExiste.x[MX]".parse().unwrap();
    assert!(client.type_attributes(&bad).await.is_err());
}

#[tokio::test]
async fn file_transfer_directory_and_download() {
    // Directorio temporal con un "registro" de prueba (multi-bloque).
    let dir = std::env::temp_dir().join(format!("iec61850_ft_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let content: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("rec001.cfg"), b"COMTRADE config").unwrap();
    std::fs::write(dir.join("rec001.dat"), &content).unwrap();

    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident()).with_file_root(&dir);
    let store = sm.init_store(&model);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let client = MmsClient::connect(addr).await.unwrap();

    // fileDirectory: lista los dos ficheros con su tamaño.
    let listing = client.file_directory(None, None).await.unwrap();
    assert!(
        listing
            .entries
            .iter()
            .any(|e| e.name == "rec001.dat" && e.size == 20_000),
        "directorio: {:?}",
        listing.entries
    );

    // download_file: open + varias fileRead (20000 > 8192) + close.
    let data = client.download_file("rec001.dat").await.unwrap();
    assert_eq!(data, content);

    // Fichero inexistente → error.
    assert!(client.download_file("noexiste.dat").await.is_err());

    std::fs::remove_dir_all(&dir).ok();
}
