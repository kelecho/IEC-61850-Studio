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

    // Fidelidad de enum (3.4): el SCL da Mod.stVal = "on" (literal); el servidor
    // debe servirlo como el ORDINAL correspondiente (INTEGER 1), no como string.
    let mod_stval = "IED1LD0/LLN0.Mod.stVal[ST]".parse().unwrap();
    assert_eq!(client.read(&mod_stval).await.unwrap(), MmsData::Int(1));
}

#[tokio::test]
async fn dynamic_dataset_lifecycle() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.expect("conecta");

    let member = (
        "IED1LD0".to_string(),
        "MMXU1$MX$A$phsA$cVal$mag$f".to_string(),
    );

    // Crear un dataset dinámico con un miembro.
    client
        .create_data_set("IED1LD0", "myDS", std::slice::from_ref(&member))
        .await
        .expect("DefineNamedVariableList");

    // GetNamedVariableListAttributes: debe ser borrable y traer el miembro.
    let attrs = client
        .get_data_set_directory("IED1LD0", "myDS")
        .await
        .expect("GetNamedVariableListAttributes");
    assert!(attrs.deletable, "un dataset dinámico es borrable");
    assert_eq!(attrs.members, vec![member.clone()]);

    // Leer el dataset por nombre debe devolver el valor del miembro.
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    client.write(&f_ref, MmsData::Float(7.0)).await.unwrap();
    let values = client
        .read_data_set("IED1LD0", "myDS")
        .await
        .expect("read del dataset dinámico");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], MmsData::Float(7.0));

    // Borrar el dataset: 1 coincidencia, 1 borrado.
    let del = client
        .delete_data_set("IED1LD0", "myDS")
        .await
        .expect("DeleteNamedVariableList");
    assert_eq!((del.matched, del.deleted), (1, 1));

    // Tras borrar, sus atributos ya no existen.
    assert!(
        client
            .get_data_set_directory("IED1LD0", "myDS")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn setting_group_control_block() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.expect("conecta");

    // El fixture declara un SGCB con numOfSGs=3, actSG=1.
    let sgcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.SGCB[SP]".parse().unwrap();

    // Leer el SGCB completo devuelve una estructura con sus componentes.
    let s = client.read(&sgcb).await.expect("read del SGCB");
    let MmsData::Structure(comps) = s else {
        panic!("el SGCB debe leerse como estructura, fue {s:?}");
    };
    // NumOfSG, ActSG, EditSG, CnfEdit, LActTm (5 componentes).
    assert_eq!(comps.len(), 5, "SGCB: {comps:?}");
    assert_eq!(comps[0], MmsData::Uint(3), "NumOfSG=3");
    assert_eq!(comps[1], MmsData::Uint(1), "ActSG=1 inicial");

    // Leer NumOfSG suelto.
    let num: iec61850_model::ObjectReference = "IED1LD0/LLN0.SGCB.NumOfSG[SP]".parse().unwrap();
    assert_eq!(client.read(&num).await.unwrap(), MmsData::Uint(3));

    // SelectActiveSG(2): activa el grupo 2.
    client
        .select_active_sg(&sgcb, 2)
        .await
        .expect("SelectActiveSG");
    let act: iec61850_model::ObjectReference = "IED1LD0/LLN0.SGCB.ActSG[SP]".parse().unwrap();
    assert_eq!(client.read(&act).await.unwrap(), MmsData::Uint(2));

    // SelectEditSG(3): selecciona el grupo 3 en edición.
    client.select_edit_sg(&sgcb, 3).await.expect("SelectEditSG");
    let edit: iec61850_model::ObjectReference = "IED1LD0/LLN0.SGCB.EditSG[SP]".parse().unwrap();
    assert_eq!(client.read(&edit).await.unwrap(), MmsData::Uint(3));
}

#[tokio::test]
async fn setting_group_values_per_group() {
    // El fixture declara PTOC1.StrVal.setVal (FC=SG, valor inicial 10) bajo un LD
    // con SGCB de 3 grupos. Se comprueba que cada grupo mantiene su propio valor.
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.expect("conecta");

    let sgcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.SGCB[SP]".parse().unwrap();
    let sg: iec61850_model::ObjectReference = "IED1LD0/PTOC1.StrVal.setVal[SG]".parse().unwrap();
    let se: iec61850_model::ObjectReference = "IED1LD0/PTOC1.StrVal.setVal[SE]".parse().unwrap();

    // El grupo activo inicial (1) refleja el valor del SCL.
    assert_eq!(client.read(&sg).await.unwrap(), MmsData::Int(10));

    // Editar el grupo 2: SelectEditSG(2) → escribir FC=SE → aún sin confirmar.
    client.select_edit_sg(&sgcb, 2).await.expect("SelectEditSG");
    client.write(&se, MmsData::Int(99)).await.expect("write SE");
    // La vista FC=SE ya muestra el valor pendiente...
    assert_eq!(client.read(&se).await.unwrap(), MmsData::Int(99));
    // ...pero el grupo activo (1) NO cambia hasta confirmar.
    assert_eq!(client.read(&sg).await.unwrap(), MmsData::Int(10));

    // ConfirmEditSGValues: los cambios se guardan en el grupo 2.
    client
        .confirm_edit_sg(&sgcb)
        .await
        .expect("ConfirmEditSGValues");

    // Activar el grupo 2 → la vista FC=SG devuelve el valor editado.
    client
        .select_active_sg(&sgcb, 2)
        .await
        .expect("SelectActiveSG");
    assert_eq!(client.read(&sg).await.unwrap(), MmsData::Int(99));

    // Volver al grupo 1 → conserva su valor original (aislamiento por grupo).
    client
        .select_active_sg(&sgcb, 1)
        .await
        .expect("SelectActiveSG");
    assert_eq!(client.read(&sg).await.unwrap(), MmsData::Int(10));

    // Un grupo fuera de rango se rechaza (1..=NumOfSG).
    assert!(client.select_active_sg(&sgcb, 9).await.is_err());
}

#[cfg(feature = "tokens")]
#[tokio::test]
async fn rbac_with_signed_token() {
    use iec61850_mms::token::{self, AccessToken};
    use iec61850_mms::{AuthPolicy, HmacKey, Role, Signer, Verifier};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // Autoridad emisora (clave HMAC compartida con el servidor). El servidor
    // confía en cualquier token que verifique con ella.
    let authority = HmacKey::new(b"autoridad-de-la-subestacion");
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_auth(AuthPolicy::Token(Verifier::from(authority.clone())));
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let now = now_secs();
    let mk_token = |role, signer: &Signer| {
        token::issue(
            &AccessToken {
                subject: "user@sub".into(),
                role,
                issuer: "AA".into(),
                not_before: now - 60,
                not_after: now + 3600,
            },
            signer,
        )
    };

    // (1) Token válido para Operator → asocia, y el rol se aplica (RBAC): puede
    // definir datasets pero no escribir valores de proceso.
    let op_token = mk_token(Role::Operator, &Signer::from(authority.clone()));
    let op = MmsClient::connect_with_token(addr, &op_token)
        .await
        .expect("token válido asocia");
    let member = (
        "IED1LD0".to_string(),
        "MMXU1$MX$A$phsA$cVal$mag$f".to_string(),
    );
    op.create_data_set("IED1LD0", "tkDS", std::slice::from_ref(&member))
        .await
        .expect("operator define dataset");
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    assert!(
        matches!(
            op.write(&f_ref, MmsData::Float(1.0)).await,
            Err(MmsError::DataAccess(_))
        ),
        "operator no escribe valores de proceso"
    );

    // (2) Token firmado por un impostor → asociación rechazada.
    let fake = mk_token(Role::Engineer, &Signer::from(HmacKey::new(b"impostor")));
    assert!(
        MmsClient::connect_with_token(addr, &fake).await.is_err(),
        "un token de otra autoridad debe rechazarse"
    );

    // (3) Token expirado → rechazado.
    let expired = token::issue(
        &AccessToken {
            subject: "user@sub".into(),
            role: Role::Engineer,
            issuer: "AA".into(),
            not_before: now - 3600,
            not_after: now - 60,
        },
        &Signer::from(authority),
    );
    assert!(
        MmsClient::connect_with_token(addr, &expired).await.is_err(),
        "un token expirado debe rechazarse"
    );

    // (4) Sin credencial → rechazado.
    assert!(MmsClient::connect(addr).await.is_err());
}

#[tokio::test]
async fn rbac_custom_role() {
    use iec61850_mms::{AuthPolicy, Permissions, Role};

    // Rol personalizado (IEC 62351-8): lee datos y opera reporting, pero NO
    // controla, NO escribe valores y NO define datasets.
    let custom = Role::Custom(Permissions::DATA_READ | Permissions::REPORTING);
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_auth(AuthPolicy::Passwords(vec![("monitor".into(), custom)]));
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let client = MmsClient::connect_with_password(addr, "monitor")
        .await
        .expect("rol personalizado asocia");
    let f_ref = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();

    // Puede leer (tiene DATA_READ).
    assert!(client.read(&f_ref).await.is_ok(), "el rol lee datos");
    // No puede escribir valores (sin DATA_WRITE).
    assert!(
        matches!(
            client.write(&f_ref, MmsData::Float(1.0)).await,
            Err(MmsError::DataAccess(_))
        ),
        "el rol personalizado no debe escribir valores"
    );
    // No puede definir datasets (sin DATASET_DEFINE).
    let member = (
        "IED1LD0".to_string(),
        "MMXU1$MX$A$phsA$cVal$mag$f".to_string(),
    );
    assert!(
        client
            .create_data_set("IED1LD0", "cDS", std::slice::from_ref(&member))
            .await
            .is_err(),
        "el rol personalizado no debe definir datasets"
    );
}

#[tokio::test]
async fn rbac_read_and_datasets() {
    use iec61850_mms::{AuthPolicy, Role};

    // Servidor con tres roles por password.
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let auth = AuthPolicy::Passwords(vec![
        ("viewpw".into(), Role::Viewer),
        ("oppw".into(), Role::Operator),
        ("engpw".into(), Role::Engineer),
    ]);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_auth(auth);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let proc_ref: iec61850_model::ObjectReference =
        "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    // Buffer de edición de settings (FC=SE): lectura reservada a Engineer.
    let se_ref: iec61850_model::ObjectReference =
        "IED1LD0/PTOC1.StrVal.setVal[SE]".parse().unwrap();
    let member = (
        "IED1LD0".to_string(),
        "MMXU1$MX$A$phsA$cVal$mag$f".to_string(),
    );

    // (1) Viewer: lee datos de proceso, pero no el buffer de edición de settings
    // (FC=SE) ni puede definir datasets.
    let viewer = MmsClient::connect_with_password(addr, "viewpw")
        .await
        .unwrap();
    assert!(viewer.read(&proc_ref).await.is_ok(), "viewer lee proceso");
    match viewer.read(&se_ref).await {
        Err(MmsError::DataAccess(_)) => {}
        other => panic!("viewer no debe leer FC=SE: {other:?}"),
    }
    assert!(
        viewer
            .create_data_set("IED1LD0", "vwDS", std::slice::from_ref(&member))
            .await
            .is_err(),
        "viewer no debe definir datasets"
    );

    // (2) Operator: define datasets (monitoreo) pero tampoco lee FC=SE.
    let op = MmsClient::connect_with_password(addr, "oppw")
        .await
        .unwrap();
    op.create_data_set("IED1LD0", "opDS", std::slice::from_ref(&member))
        .await
        .expect("operator define dataset");
    assert!(
        matches!(op.read(&se_ref).await, Err(MmsError::DataAccess(_))),
        "operator no debe leer FC=SE"
    );

    // (3) Engineer: lee el buffer de edición de settings y define datasets.
    let eng = MmsClient::connect_with_password(addr, "engpw")
        .await
        .unwrap();
    assert!(eng.read(&se_ref).await.is_ok(), "engineer lee FC=SE");
    eng.create_data_set("IED1LD0", "engDS", std::slice::from_ref(&member))
        .await
        .expect("engineer define dataset");
}

#[tokio::test]
async fn log_control_block_and_read_journal() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.expect("conecta");

    // El fixture declara un LCB EventLog con logEna=true.
    let lcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.EventLog[LG]".parse().unwrap();
    let s = client.read(&lcb).await.expect("read del LCB");
    let MmsData::Structure(comps) = s else {
        panic!("el LCB debe leerse como estructura, fue {s:?}");
    };
    // 9 componentes: LogEna, LogRef, DatSet, OldEntrTm, NewEntrTm, OldEntr,
    // NewEntr, TrgOps, IntgPd.
    assert_eq!(comps.len(), 9, "LCB: {comps:?}");
    assert_eq!(comps[0], MmsData::Bool(true), "LogEna=true");

    // ReadJournal del log EventLog: el servidor devuelve entradas del journal.
    let (entries, more) = client
        .read_journal("IED1LD0", "LLN0$EventLog")
        .await
        .expect("ReadJournal");
    assert!(!more);
    assert_eq!(entries.len(), 2, "el journal de ejemplo tiene 2 entradas");
    assert_eq!(entries[0].entry_id.len(), 8, "entryID de 8 octetos");
    assert_eq!(
        entries[0].occurrence_time.len(),
        6,
        "BinaryTime de 6 octetos"
    );
}

#[tokio::test]
async fn acse_authentication_and_rbac() {
    use iec61850_mms::{AuthPolicy, Role};

    // Servidor con dos passwords: uno de solo lectura, otro de ingeniería.
    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let auth = AuthPolicy::Passwords(vec![
        ("viewpw".into(), Role::Viewer),
        ("engpw".into(), Role::Engineer),
    ]);
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_auth(auth);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let f_ref: iec61850_model::ObjectReference =
        "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();

    // (1) Sin password → la asociación se rechaza (62351-4).
    assert!(
        MmsClient::connect(addr).await.is_err(),
        "sin password la asociación debe rechazarse"
    );

    // (2) Password incorrecto → rechazado.
    assert!(
        MmsClient::connect_with_password(addr, "malo")
            .await
            .is_err()
    );

    // (3) Viewer: asocia y lee, pero NO puede escribir (RBAC 62351-8).
    let viewer = MmsClient::connect_with_password(addr, "viewpw")
        .await
        .expect("viewer asocia");
    assert!(viewer.read(&f_ref).await.is_ok(), "viewer puede leer");
    match viewer.write(&f_ref, MmsData::Float(3.0)).await {
        Err(MmsError::DataAccess(_)) => {} // acceso denegado, correcto
        other => panic!("viewer no debe poder escribir: {other:?}"),
    }

    // (4) Engineer: asocia, lee y escribe.
    let eng = MmsClient::connect_with_password(addr, "engpw")
        .await
        .expect("engineer asocia");
    eng.write(&f_ref, MmsData::Float(5.0))
        .await
        .expect("engineer puede escribir");
    assert_eq!(eng.read(&f_ref).await.unwrap(), MmsData::Float(5.0));
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

    // Select sobre un objeto direct-normal ⇒ denegado (no es modelo SBO).
    assert!(!client.select(&do_ctrl).await.unwrap());
}

#[tokio::test]
async fn control_sbo_normal_flow() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();

    // SPCSO3 = sbo-with-normal-security (ctlModel=2).
    let do3 = "IED1LD0/GGIO1.SPCSO3[CO]".parse().unwrap();
    let stval = "IED1LD0/GGIO1.SPCSO3.stVal[ST]".parse().unwrap();

    // Operar sin seleccionar ⇒ rechazo con AddCause 18 (object-not-selected).
    let err = client.operate(&do3, MmsData::Bool(true)).await.unwrap_err();
    assert!(matches!(
        err,
        MmsError::ControlTerminated {
            add_cause: iec61850_mms::add_cause::OBJECT_NOT_SELECTED
        }
    ));

    // Select (lectura de SBO) concedido; después el operate pasa.
    assert!(client.select(&do3).await.unwrap());
    client.operate(&do3, MmsData::Bool(true)).await.unwrap();
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(true));

    // La selección es one-shot: un segundo operate vuelve a denegarse.
    let err = client
        .operate(&do3, MmsData::Bool(false))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        MmsError::ControlTerminated {
            add_cause: iec61850_mms::add_cause::OBJECT_NOT_SELECTED
        }
    ));
}

#[tokio::test]
async fn control_sbo_selection_expires() {
    let (addr, handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();
    let do3 = "IED1LD0/GGIO1.SPCSO3[CO]".parse().unwrap();

    // sboTimeout de 50 ms en el CF del objeto.
    handle
        .set_raw("IED1LD0", "GGIO1$CF$SPCSO3$sboTimeout", MmsData::Uint(50))
        .await;

    assert!(client.select(&do3).await.unwrap());
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // La selección expiró (AddCause 16 = time-limit-over en el LastApplError).
    let err = client.operate(&do3, MmsData::Bool(true)).await.unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::ControlTerminated {
                add_cause: iec61850_mms::add_cause::TIME_LIMIT_OVER
            }
        ),
        "se esperaba time-limit-over, fue {err:?}"
    );
}

#[tokio::test]
async fn control_status_only_rejects_operate() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();

    // SPCSO4 = status-only (ctlModel=0): no operable.
    let do4 = "IED1LD0/GGIO1.SPCSO4[CO]".parse().unwrap();
    let stval = "IED1LD0/GGIO1.SPCSO4.stVal[ST]".parse().unwrap();

    let err = client.operate(&do4, MmsData::Bool(true)).await.unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::ControlTerminated {
                add_cause: iec61850_mms::add_cause::NOT_SUPPORTED
            }
        ),
        "se esperaba not-supported, fue {err:?}"
    );
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(false));

    // Tampoco se puede seleccionar.
    assert!(!client.select(&do4).await.unwrap());
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

    // Oper con interlock-check ⇒ LastApplError + CommandTermination−
    // (AddCause 10 = blocked-by-interlocking, IEC 61850-7-2), sin cambio.
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
    assert!(
        matches!(
            err,
            MmsError::ControlTerminated {
                add_cause: iec61850_mms::add_cause::BLOCKED_BY_INTERLOCKING
            }
        ),
        "se esperaba blocked-by-interlocking, fue {err:?}"
    );
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(false));
}

#[tokio::test]
async fn enhanced_operate_without_select_rejected() {
    let (addr, _handle) = start_server(100).await;
    let client = MmsClient::connect(addr).await.unwrap();
    let do2 = "IED1LD0/GGIO1.SPCSO2[CO]".parse().unwrap();
    let p = ControlParameters::default();

    // sbo-enhanced sin selección previa ⇒ Write− precedido de LastApplError
    // con AddCause 18 (object-not-selected).
    let err = client
        .operate_enhanced(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::ControlTerminated {
                add_cause: iec61850_mms::add_cause::OBJECT_NOT_SELECTED
            }
        ),
        "se esperaba object-not-selected, fue {err:?}"
    );
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

    // Tras Cancel ya no hay selección: operar (sbo) ⇒ rechazo con AddCause 18.
    let err = client
        .operate_enhanced(&do2, MmsData::Bool(true), &p)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::ControlTerminated {
                add_cause: iec61850_mms::add_cause::OBJECT_NOT_SELECTED
            }
        ),
        "se esperaba object-not-selected, fue {err:?}"
    );
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

#[tokio::test]
async fn handshake_timeout_closes_idle_socket() {
    use iec61850_mms::ServerLimits;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let limits = ServerLimits {
        handshake_timeout: Duration::from_millis(200),
        ..Default::default()
    };
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_limits(limits);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    // Cliente que abre el socket y NO envía el CR de COTP: el servidor debe
    // cerrarlo al vencer el timeout de handshake (defensa slow-loris).
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    // read() retorna Ok(0) cuando el peer cierra: debe ocurrir antes de ~2 s.
    let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .expect("el servidor debe cerrar el socket por timeout de handshake")
        .unwrap();
    assert_eq!(n, 0, "se esperaba cierre limpio del servidor");
}

#[tokio::test]
async fn respects_max_connections() {
    use iec61850_mms::ServerLimits;

    let model = iec61850_scl::load_model(fixture()).unwrap();
    let sm = ServerModel::from_model(&model, ident());
    let store = sm.init_store(&model);
    let limits = ServerLimits {
        max_connections: 2,
        ..Default::default()
    };
    let server = MmsServer::bind("127.0.0.1:0", Arc::new(sm), store)
        .await
        .unwrap()
        .with_limits(limits);
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    // Dos asociaciones completas caben dentro del límite y funcionan.
    let c1 = MmsClient::connect(addr).await.expect("1ª conexión");
    let c2 = MmsClient::connect(addr).await.expect("2ª conexión");
    assert_eq!(c1.identify().await.unwrap().vendor, "ACME");
    assert_eq!(c2.identify().await.unwrap().vendor, "ACME");
    // Al cerrar una, se libera el permiso y una tercera puede asociarse.
    drop(c1);
    let c3 = MmsClient::connect(addr).await.expect("3ª tras liberar");
    assert_eq!(c3.identify().await.unwrap().vendor, "ACME");
}

// --- Negociación real de Sesión/Presentación (ISO 8327/8823) ----------------

/// Cliente "extraño pero conforme": propone los contextos de presentación en
/// IDs NO estándar (ACSE=5, MMS=7) más un contexto desconocido (id 9). Un
/// servidor de plantilla (pre-negociación) contestaría la fase de datos con el
/// context-id 3 cacheado y un result-list de 2 entradas fijas; el negociado
/// debe responder a los 3 contextos EN ORDEN (aceptar/rechazar) y usar el id 7
/// del cliente en la fase de datos.
#[tokio::test]
async fn association_negotiates_nonstandard_context_ids() {
    use iec61850_mms::ber::reader::BerReader;
    use iec61850_mms::ber::tag::{Tag, universal};
    use iec61850_mms::ber::writer::BerWriter;
    use iec61850_mms::mms::{InitiateRequest, pdu};
    use iec61850_mms::transport::{cotp, tpkt};
    use iec61850_mms::upper::{acse, presentation, session};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ACSE_ID: i64 = 5;
    const MMS_ID: i64 = 7;

    let (addr, _handle) = start_server(100).await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();

    async fn send(sock: &mut tokio::net::TcpStream, tpdu: &[u8]) {
        sock.write_all(&tpkt::frame(tpdu)).await.unwrap();
    }
    /// Lee un TPKT y devuelve el TSDU (payload del DT sin cabecera COTP).
    async fn recv(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut hdr = [0u8; tpkt::HEADER_LEN];
        sock.read_exact(&mut hdr).await.unwrap();
        let len = tpkt::payload_len(&hdr).unwrap();
        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload).await.unwrap();
        cotp::parse_data_tpdu(&payload).map(<[u8]>::to_vec).unwrap()
    }

    // COTP CR → CC.
    sock.write_all(&tpkt::frame(&cotp::connection_request(0x0007)))
        .await
        .unwrap();
    let mut hdr = [0u8; tpkt::HEADER_LEN];
    sock.read_exact(&mut hdr).await.unwrap();
    let mut cc = vec![0u8; tpkt::payload_len(&hdr).unwrap()];
    sock.read_exact(&mut cc).await.unwrap();
    cotp::parse_connection_confirm(&cc).unwrap();

    // CP artesanal con IDs 5/7 y un contexto extra desconocido (id 9).
    let aarq = acse::aarq(&InitiateRequest::default().encode());
    let ber_ts: [u32; 3] = [2, 1, 1];
    let mut w = BerWriter::new();
    w.tlv(Tag::universal(17, true), |w| {
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), 1); // normal-mode
        });
        w.tlv(Tag::context(2, true), |w| {
            w.octet_string(Tag::context(1, false), &[0, 0, 0, 9]); // calling
            w.octet_string(Tag::context(2, false), &[0, 0, 0, 9]); // called
            w.tlv(Tag::context(4, true), |w| {
                for (id, oid) in [
                    (ACSE_ID, &[2u32, 2, 1, 0, 1][..]),
                    (MMS_ID, &[1, 0, 9506, 2, 1][..]),
                    (9, &[1, 3, 6, 1, 4][..]), // abstract-syntax desconocido
                ] {
                    w.sequence(|w| {
                        w.integer(universal::INTEGER, id);
                        w.object_identifier(universal::OID, oid);
                        w.sequence(|w| w.object_identifier(universal::OID, &ber_ts));
                    });
                }
            });
            w.raw(&presentation::user_data(&aarq, ACSE_ID));
        });
    });
    let cp = w.into_bytes();
    send(&mut sock, &cotp::data_tpdu(&session::connect(&cp))).await;

    // Respuesta: el result-list debe traer TRES entradas (2 aceptaciones + 1
    // provider-rejection por abstract-syntax) y el AARE debe decodificar.
    let resp = recv(&mut sock).await;
    let aare = presentation::extract_inner_pdu(&resp).unwrap();
    acse::parse_aare(aare).expect("AARE aceptado");
    let set_start = resp.iter().position(|b| *b == 0x31).unwrap();
    let mut r = BerReader::new(&resp[set_start..]);
    let set = r.read_tlv().unwrap();
    let mut results = Vec::new();
    let mut sr = BerReader::new(set.content);
    while !sr.is_empty() {
        let item = sr.read_tlv().unwrap();
        if item.tag != Tag::context(2, true) {
            continue;
        }
        let mut pr = BerReader::new(item.content);
        while !pr.is_empty() {
            let p = pr.read_tlv().unwrap();
            if p.tag != Tag::context(5, true) {
                continue;
            }
            let mut rr = BerReader::new(p.content);
            while !rr.is_empty() {
                let e = rr.read_tlv().unwrap();
                let mut er = BerReader::new(e.content);
                let res = er.read_tlv().unwrap();
                results.push(iec61850_mms::ber::prim::decode_integer(res.content).unwrap());
            }
        }
    }
    assert_eq!(
        results,
        vec![0, 0, 2],
        "result-list debe responder a los 3 contextos en orden (acc, acc, provider-rejection)"
    );

    // Fase de datos: Identify bajo el ctx MMS=7 del cliente; la respuesta debe
    // volver TAMBIÉN bajo el ctx 7 (no el 3 de plantilla).
    let ident_req = pdu::encode_confirmed_request(1, |w| {
        w.tlv(Tag::context(2, false), |_| {}); // identify (tag [2], vacío)
    });
    let ud = presentation::user_data(&ident_req, MMS_ID);
    send(&mut sock, &cotp::data_tpdu(&session::data(&ud))).await;

    let resp = recv(&mut sock).await;
    // El fully-encoded-data de la respuesta lleva el presentation-context-id 7.
    let fed_start = resp.iter().position(|b| *b == 0x61).unwrap();
    let mut r = BerReader::new(&resp[fed_start..]);
    let fed = r.read_tlv().unwrap();
    let mut fr = BerReader::new(fed.content);
    let pdv = fr.expect(universal::SEQUENCE).unwrap();
    let mut pr = BerReader::new(pdv);
    let ctx = pr.expect(universal::INTEGER).unwrap();
    assert_eq!(
        iec61850_mms::ber::prim::decode_integer(ctx).unwrap(),
        MMS_ID,
        "la fase de datos debe usar el context-id MMS propuesto por el cliente"
    );
    // Y el PDU interno es la respuesta Identify correcta.
    let inner = presentation::extract_inner_pdu(&resp).unwrap();
    let cr = pdu::parse_confirmed_response(inner).unwrap();
    let id = iec61850_mms::mms::identify::decode_response(&cr.service).unwrap();
    assert_eq!(id.vendor, "ACME");
}

/// Un CP cuyos contextos no incluyen MMS con BER debe rechazarse (el servidor
/// cierra sin asociar en vez de aceptar a ciegas como la plantilla anterior).
#[tokio::test]
async fn association_rejects_cp_without_usable_contexts() {
    use iec61850_mms::ber::tag::{Tag, universal};
    use iec61850_mms::ber::writer::BerWriter;
    use iec61850_mms::mms::InitiateRequest;
    use iec61850_mms::transport::{cotp, tpkt};
    use iec61850_mms::upper::{acse, presentation, session};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (addr, _handle) = start_server(100).await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();

    sock.write_all(&tpkt::frame(&cotp::connection_request(0x0008)))
        .await
        .unwrap();
    let mut hdr = [0u8; tpkt::HEADER_LEN];
    sock.read_exact(&mut hdr).await.unwrap();
    let mut cc = vec![0u8; tpkt::payload_len(&hdr).unwrap()];
    sock.read_exact(&mut cc).await.unwrap();

    // CP con un único contexto de abstract-syntax desconocido.
    let aarq = acse::aarq(&InitiateRequest::default().encode());
    let mut w = BerWriter::new();
    w.tlv(Tag::universal(17, true), |w| {
        w.tlv(Tag::context(0, true), |w| {
            w.integer(Tag::context(0, false), 1);
        });
        w.tlv(Tag::context(2, true), |w| {
            w.tlv(Tag::context(4, true), |w| {
                w.sequence(|w| {
                    w.integer(universal::INTEGER, 1);
                    w.object_identifier(universal::OID, &[1, 3, 6, 1, 4]);
                    w.sequence(|w| w.object_identifier(universal::OID, &[2, 1, 1]));
                });
            });
            w.raw(&presentation::user_data(&aarq, 1));
        });
    });
    let cp = w.into_bytes();
    sock.write_all(&tpkt::frame(&cotp::data_tpdu(&session::connect(&cp))))
        .await
        .unwrap();

    // El servidor no asocia: cierra la conexión (0 bytes) en vez de aceptar.
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("el servidor debe cerrar, no colgarse")
        .unwrap_or(0);
    assert_eq!(n, 0, "se esperaba cierre de conexión sin AARE");
}

// --- Reporting completo: overflow, reservas y decodificación guiada ---------

/// Desbordar el buffer del BRCB (capacidad 64) antes de habilitar: el primer
/// reporte drenado debe señalizar `BufOvfl=true` y conservar las ÚLTIMAS 64
/// entradas (las más antiguas se descartan).
#[tokio::test]
async fn buffered_overflow_signaled() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    let member = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    // 70 eventos sin cliente: 64 de capacidad ⇒ 6 descartados, overflow.
    for i in 0..70 {
        handle
            .set_value(&member, MmsData::Float(i as f64))
            .await
            .unwrap();
    }

    let brcb = "IED1LD0/LLN0.brcb1[BR]".parse().unwrap();
    client
        .enable_report(&brcb, &Default::default())
        .await
        .unwrap();
    // Resync desde el principio (EntryID=0): pide todo lo bufferado.
    let entry_id_ref = "IED1LD0/LLN0.brcb1.EntryID[BR]".parse().unwrap();
    client
        .write(&entry_id_ref, MmsData::Octets(0u64.to_be_bytes().to_vec()))
        .await
        .unwrap();

    // Primer reporte del replay: EntryID 7 (1..=6 descartados) y BufOvfl.
    let first = reports.recv().await.expect("primer reporte drenado");
    assert_eq!(
        first.buffer_overflow,
        Some(true),
        "el desbordamiento debe señalizarse: {first:?}"
    );
    assert_eq!(
        entry_id_of(&first),
        7,
        "las 6 entradas más viejas se descartan"
    );
    // El resto llega sin overflow y termina en el EntryID 70.
    let mut last = entry_id_of(&first);
    for _ in 0..63 {
        let r = reports.recv().await.expect("resto del drenado");
        last = entry_id_of(&r);
    }
    assert_eq!(last, 70);
}

/// Reserva de URCB con `Resv`: mientras una conexión lo tiene reservado, otra
/// no puede escribir sus atributos ni habilitarlo; al soltarlo (Resv=false) sí.
#[tokio::test]
async fn urcb_reservation_excludes_other_clients() {
    let (addr, _handle) = start_server(100).await;
    let c1 = MmsClient::connect(addr).await.unwrap();
    let c2 = MmsClient::connect(addr).await.unwrap();

    let resv: iec61850_model::ObjectReference = "IED1LD0/LLN0.rcb1.Resv[RP]".parse().unwrap();
    let rcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.rcb1[RP]".parse().unwrap();

    // c1 reserva el URCB.
    c1.write(&resv, MmsData::Bool(true)).await.unwrap();

    // c2 no puede habilitarlo ni escribir atributos.
    let err = c2
        .enable_report(&rcb, &Default::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::DataAccess(iec61850_mms::DataAccessError::TemporarilyUnavailable)
        ),
        "RCB reservado ⇒ temporarily-unavailable, fue {err:?}"
    );

    // c1 libera; ahora c2 puede habilitar.
    c1.write(&resv, MmsData::Bool(false)).await.unwrap();
    c2.enable_report(&rcb, &Default::default()).await.unwrap();
}

/// Habilitar un RCB toma la reserva implícita: la conexión que lo habilitó lo
/// posee; al desconectar (sin ResvTms) la reserva se libera sola.
#[tokio::test]
async fn rcb_implicit_reservation_released_on_disconnect() {
    let (addr, _handle) = start_server(100).await;
    let rcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.rcb1[RP]".parse().unwrap();

    let c1 = MmsClient::connect(addr).await.unwrap();
    c1.enable_report(&rcb, &Default::default()).await.unwrap();

    // Mientras c1 vive, c2 no puede tomar el RCB.
    let c2 = MmsClient::connect(addr).await.unwrap();
    assert!(c2.enable_report(&rcb, &Default::default()).await.is_err());

    // c1 se desconecta ⇒ la reserva implícita (sin ResvTms) se libera.
    drop(c1);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    c2.enable_report(&rcb, &Default::default()).await.unwrap();
}

/// `ResvTms` (BRCB): la reserva sobrevive a la desconexión durante su ventana
/// y expira después.
#[tokio::test]
async fn brcb_resv_tms_survives_disconnect_until_window() {
    let (addr, _handle) = start_server(100).await;
    let resv_tms: iec61850_model::ObjectReference =
        "IED1LD0/LLN0.brcb1.ResvTms[BR]".parse().unwrap();
    let brcb: iec61850_model::ObjectReference = "IED1LD0/LLN0.brcb1[BR]".parse().unwrap();

    let c1 = MmsClient::connect(addr).await.unwrap();
    c1.write(&resv_tms, MmsData::Int(1)).await.unwrap(); // 1 s de ventana
    drop(c1);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Dentro de la ventana: el BRCB sigue reservado.
    let c2 = MmsClient::connect(addr).await.unwrap();
    let err = c2
        .enable_report(&brcb, &Default::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MmsError::DataAccess(iec61850_mms::DataAccessError::TemporarilyUnavailable)
        ),
        "dentro de ResvTms ⇒ reservado, fue {err:?}"
    );

    // Pasada la ventana: libre.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    c2.enable_report(&brcb, &Default::default()).await.unwrap();
}

/// Decodificación guiada por el dataset: `enable_report` resuelve los miembros
/// del dataset del RCB y las entradas llegan con su `reference` poblada.
#[tokio::test]
async fn report_entries_carry_dataset_references() {
    let (addr, handle) = start_server(100).await;
    let mut client = MmsClient::connect(addr).await.unwrap();
    let mut reports = client.take_report_rx().unwrap();

    let rcb = "IED1LD0/LLN0.rcb1[RP]".parse().unwrap();
    client
        .enable_report(&rcb, &Default::default())
        .await
        .unwrap();

    let member: iec61850_model::ObjectReference =
        "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
    handle
        .set_value(&member, MmsData::Float(3.25))
        .await
        .unwrap();

    let report = reports.recv().await.expect("reporte dchg");
    assert_eq!(report.entries.len(), 1);
    let entry = &report.entries[0];
    assert_eq!(entry.value, MmsData::Float(3.25));
    assert_eq!(
        entry.reference.as_ref().map(ToString::to_string).as_deref(),
        Some("IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]"),
        "la referencia debe salir del dataset resuelto: {report:?}"
    );
}
