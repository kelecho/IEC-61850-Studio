//! Interoperabilidad en vivo: **nuestro `MmsClient` contra un servidor MMS de
//! terceros** (por defecto, el `server_example_basic_io` de libiec61850).
//!
//! Es el complemento del test de loopback (que valida nuestro cliente contra
//! nuestro servidor): aquí probamos contra una implementación independiente, que
//! es la verdadera medida de interoperabilidad IEC 61850-8-1.
//!
//! No se ejecuta por defecto: requiere un servidor externo escuchando. Arráncalo
//! (ver `interop/README.md`) y define la dirección:
//!
//! ```sh
//! IEC61850_INTEROP_ADDR=127.0.0.1:102 \
//!   cargo test -p iec61850-mms --features client --test interop_client \
//!     -- --nocapture --test-threads=1
//! ```
//!
//! Usa **`--test-threads=1`**: los servidores de ejemplo (p. ej.
//! server_example_basic_io) aceptan pocas conexiones concurrentes, y varios
//! tests abriendo asociaciones a la vez saturan el servidor.
//!
//! Sin la variable, cada test se salta (no rompe el CI de quien no lo levante).
#![cfg(feature = "client")]

use iec61850_mms::MmsClient;
use iec61850_model::ObjectReference;

fn interop_addr() -> Option<String> {
    std::env::var("IEC61850_INTEROP_ADDR").ok()
}

macro_rules! addr_or_skip {
    () => {
        match interop_addr() {
            Some(a) => a,
            None => {
                eprintln!("IEC61850_INTEROP_ADDR no definida: test de interop omitido");
                return;
            }
        }
    };
}

#[tokio::test]
async fn interop_associate_and_identify() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr)
        .await
        .expect("asociación MMS con el servidor de terceros");
    // El handshake negoció una versión válida.
    assert!(client.negotiated().version >= 1);
    // Identify es opcional en el estándar: registramos el resultado sin exigirlo.
    match client.identify().await {
        Ok(id) => eprintln!(
            "Identify: vendor={} model={} rev={}",
            id.vendor, id.model, id.revision
        ),
        Err(e) => eprintln!("Identify no soportado o rechazado: {e}"),
    }
}

#[tokio::test]
async fn interop_browse_and_read() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");

    // Descubrimiento de dispositivos lógicos.
    let lds = client
        .get_server_directory()
        .await
        .expect("GetServerDirectory");
    eprintln!("LDs descubiertos: {lds:?}");
    assert!(!lds.is_empty(), "el servidor debe exponer al menos un LD");

    // Descubrimiento de variables del primer LD y lectura de la primera.
    let vars = client
        .get_logical_device_directory(&lds[0])
        .await
        .expect("GetLogicalDeviceDirectory");
    eprintln!("{} variables en {}", vars.len(), lds[0]);
    assert!(!vars.is_empty(), "el LD debe exponer variables");

    // Lee la primera variable descubierta: no debe entrar en pánico ni colgar.
    if let Some(first) = vars.first() {
        match client.read(first).await {
            Ok(v) => eprintln!("read {} = {v:?}", first),
            Err(e) => eprintln!("read {} rechazado: {e}", first),
        }
    }
}

/// Mide la tasa de éxito de Read sobre variables **hoja** concretas (las que
/// terminan en un atributo de datos típico: stVal, mag, q, t, ctlNum...). Leer
/// un LN entero con una FC puede rechazarse legítimamente; esto aísla las
/// lecturas que sí deben funcionar y sirve de métrica de interop de Read.
#[tokio::test]
async fn interop_read_leaf_variables() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let lds = client.get_server_directory().await.expect("dirs");

    let mut ok = 0usize;
    let mut rejected = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        // Heurística de "hoja": la referencia contiene un atributo de dato común.
        let leaves = vars.iter().filter(|r| {
            let s = r.to_string();
            [
                "stVal", ".mag", ".q[", ".t[", "ctlModel", "ctlNum", "General",
            ]
            .iter()
            .any(|needle| s.contains(needle))
        });
        for r in leaves.take(40) {
            match client.read(r).await {
                Ok(v) => {
                    ok += 1;
                    if samples.len() < 8 {
                        samples.push(format!("{r} = {v:?}"));
                    }
                }
                Err(_) => rejected += 1,
            }
        }
    }

    eprintln!("Read de hojas: {ok} ok, {rejected} rechazadas");
    for s in &samples {
        eprintln!("  {s}");
    }
    // Al menos alguna lectura hoja debe funcionar contra un stack conforme; si
    // no, es un bug de interop de nuestro Read (no un simple 'variable no existe').
    assert!(
        ok > 0,
        "ninguna lectura hoja funcionó contra el servidor de terceros \
         (posible bug de codificación del Read request)"
    );
}

/// Verifica que la **estructura** de nuestro Write request la acepta un stack
/// conforme: escribimos un valor de control y comprobamos que la respuesta es un
/// resultado de Write (éxito o `DataAccess` por permisos/rango), NO un
/// `reject-PDU` (que indicaría PDU malformada). Distingue "estructura correcta,
/// escritura denegada" de "PDU no conforme".
#[tokio::test]
async fn interop_write_structure_accepted() {
    use iec61850_mms::MmsData;
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let lds = client.get_server_directory().await.expect("dirs");

    // Busca una variable de control escribible (ctlVal/SPCSO/Oper) o un stVal.
    let mut target = None;
    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        if let Some(r) = vars.iter().find(|r| {
            let s = r.to_string();
            s.contains("SPCSO") && s.contains("ctlVal")
        }) {
            target = Some(r.clone());
            break;
        }
    }
    let Some(target) = target else {
        eprintln!("sin variable de control adecuada: subtest de Write omitido");
        return;
    };

    eprintln!("Write a {target}");
    match client.write(&target, MmsData::Bool(true)).await {
        Ok(()) => eprintln!("Write aceptado (éxito)"),
        Err(iec61850_mms::MmsError::DataAccess(e)) => {
            // Estructura entendida, escritura denegada: interop de Write OK.
            eprintln!("Write entendido, DataAccessError esperado: {e:?}");
        }
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("Write produjo reject-PDU (estructura no conforme): {r}");
        }
        Err(e) => eprintln!("Write: otro error (aceptable): {e}"),
    }
}

/// **Control directo** (direct-with-normal-security) contra libiec61850. El
/// modelo simpleIO expone GGIO1.SPCSO1..4 como SPC con control directo. Operamos
/// y verificamos que el `stVal` refleja el valor mandado. Es la prueba real de
/// que nuestra codificación de `Oper` (estructura de control del 7-2) es conforme.
#[tokio::test]
async fn interop_direct_control() {
    use iec61850_mms::MmsData;
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");

    let ctl: ObjectReference = "simpleIOGenericIO/GGIO1.SPCSO1"
        .parse()
        .expect("ref control");
    let stval: ObjectReference = "simpleIOGenericIO/GGIO1.SPCSO1.stVal[ST]"
        .parse()
        .expect("ref stVal");

    // Lee el estado inicial (puede ser false).
    let before = client.read(&stval).await;
    eprintln!("stVal antes: {before:?}");

    // Aserción dura: el `operate` (Oper[CO]) debe ser ACEPTADO por el servidor
    // sin reject-PDU. Es la prueba de que nuestra estructura de control (7-2) es
    // conforme, independientemente de la lógica de aplicación del servidor.
    match client.operate(&ctl, MmsData::Bool(true)).await {
        Ok(()) => {}
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("operate produjo reject-PDU (estructura de control no conforme): {r}")
        }
        Err(e) => panic!("operate rechazado: {e}"),
    }

    // Comprobación adicional (depende del servidor): si implementa el feedback de
    // control, el stVal reflejará el mando. Algunos ejemplos (server_example_files)
    // aceptan el control pero no instalan handler que actualice el stVal.
    let after = client.read(&stval).await.expect("read stVal tras operar");
    eprintln!("stVal después: {after:?}");
    if after == MmsData::Bool(true) {
        eprintln!("control con feedback: stVal reflejó el mando");
        let _ = client.operate(&ctl, MmsData::Bool(false)).await;
    } else {
        eprintln!("el servidor aceptó el control pero no refleja stVal (sin handler)");
    }
}

/// **Select-Before-Operate**: aunque SPCSO1 es direct, ejercitamos la ruta SBO
/// para comprobar que la estructura de la petición Select la acepta el servidor
/// (una negativa de acceso es válida; un reject-PDU sería bug de conformidad).
#[tokio::test]
async fn interop_select_structure_accepted() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let ctl: ObjectReference = "simpleIOGenericIO/GGIO1.SPCSO1"
        .parse()
        .expect("ref control");
    match client.select(&ctl).await {
        Ok(granted) => eprintln!("Select respondido (concedido={granted})"),
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("Select produjo reject-PDU (estructura no conforme): {r}")
        }
        Err(e) => eprintln!("Select: error de acceso (aceptable para un DO direct): {e}"),
    }
}

/// **Reporting (URCB)** contra libiec61850: descubre un RCB no bufferado,
/// lo habilita con interrogación general y espera recibir un `InformationReport`.
/// Prueba la ruta completa write RCB (RptEna/GI) + decodificación del reporte
/// entrante contra un generador de reportes independiente.
#[tokio::test]
async fn interop_reporting_urcb() {
    use iec61850_mms::ReportConfig;
    use std::time::Duration;

    let addr = addr_or_skip!();
    let mut client = MmsClient::connect(&addr).await.expect("asocia");
    let mut reports = client.take_report_rx().expect("canal de reportes");

    let lds = client.get_server_directory().await.expect("dirs");

    // Descubre el RCB no bufferado: una variable con FC=RP cuyo último segmento
    // sea 'RptEna'. El RCB base es esa referencia sin el atributo final.
    let mut rcb: Option<ObjectReference> = None;
    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        if let Some(r) = vars.iter().find(|r| {
            r.fc == Some(iec61850_model::FunctionalConstraint::RP)
                && r.path.last().map(|s| s.as_str()) == Some("RptEna")
        }) {
            let mut base = r.clone();
            base.path.pop(); // quita 'RptEna' → referencia del RCB
            rcb = Some(base);
            break;
        }
    }
    let Some(rcb) = rcb else {
        eprintln!("no se halló URCB (variable RP/RptEna): subtest omitido");
        return;
    };
    eprintln!("URCB descubierto: {rcb}");

    // Habilita con interrogación general para forzar un reporte inmediato.
    let cfg = ReportConfig {
        general_interrogation: true,
        ..Default::default()
    };
    client
        .enable_report(&rcb, &cfg)
        .await
        .expect("habilitar el RCB (RptEna/GI) aceptado por libiec61850");

    // Espera un InformationReport. El EventsRCB tiene disparo periódico + GI.
    let got = tokio::time::timeout(Duration::from_secs(6), reports.recv()).await;
    match got {
        Ok(Some(report)) => {
            eprintln!(
                "Reporte recibido: rptID={:?} dataset={:?} {} entradas",
                report.rpt_id,
                report.dataset,
                report.entries.len()
            );
        }
        Ok(None) => panic!("el canal de reportes se cerró sin recibir ninguno"),
        Err(_) => panic!(
            "no llegó ningún InformationReport en 6 s tras habilitar el RCB \
             (posible bug de interop en el reporting)"
        ),
    }

    let _ = client.disable_report(&rcb).await;
}

/// **Reporting bufferado (BRCB)** contra libiec61850: descubre un RCB bufferado
/// (FC=BR), lo habilita y recibe un `InformationReport` que debe traer `EntryID`
/// (característica distintiva del bufferado, con `OptFlds.entry-id`). Valida el
/// camino de reporting persistente y la decodificación del EntryID.
#[tokio::test]
async fn interop_reporting_brcb() {
    use iec61850_mms::ReportConfig;
    use std::time::Duration;

    let addr = addr_or_skip!();
    let mut client = MmsClient::connect(&addr).await.expect("asocia");
    let mut reports = client.take_report_rx().expect("canal de reportes");
    let lds = client.get_server_directory().await.expect("dirs");

    // BRCB: variable con FC=BR cuyo último segmento sea 'RptEna'. Preferimos uno
    // cuyo dataset lleve EntryID en su OptFlds — el 'Measurements' del modelo
    // simpleIO — para poder validar la decodificación del EntryID; si no, uno
    // cualquiera (el EntryID depende de la config del BRCB, no de ser bufferado).
    let mut candidates: Vec<ObjectReference> = Vec::new();
    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        for r in vars.iter().filter(|r| {
            r.fc == Some(iec61850_model::FunctionalConstraint::BR)
                && r.path.last().map(|s| s.as_str()) == Some("RptEna")
        }) {
            let mut base = r.clone();
            base.path.pop();
            candidates.push(base);
        }
    }
    if candidates.is_empty() {
        eprintln!("no se halló BRCB (variable BR/RptEna): subtest omitido");
        return;
    }
    // Prioriza el BRCB de medidas (tiene entryID en OptFlds).
    let brcb = candidates
        .iter()
        .find(|r| r.path.iter().any(|s| s.contains("Measurement")))
        .cloned()
        .unwrap_or_else(|| candidates[0].clone());
    eprintln!("BRCB elegido: {brcb} (de {} candidatos)", candidates.len());

    // Habilita con GI. El dataset Measurements tiene mag.f con dchg → dispara.
    let cfg = ReportConfig {
        general_interrogation: true,
        ..Default::default()
    };
    client
        .enable_report(&brcb, &cfg)
        .await
        .expect("habilitar el BRCB aceptado por libiec61850");

    let got = tokio::time::timeout(Duration::from_secs(8), reports.recv()).await;
    match got {
        Ok(Some(report)) => {
            eprintln!(
                "Reporte BUFFERADO: rptID={:?} entryID={:?} confRev={:?} \
                 bufOvfl={:?} {} entradas",
                report.rpt_id,
                report.entry_id.as_ref().map(|e| e.len()),
                report.conf_rev,
                report.buffer_overflow,
                report.entries.len()
            );
            // Si el BRCB es el de medidas, su OptFlds activa entry-id: debe
            // decodificarse. (Otros BRCB pueden no llevarlo, y es correcto.)
            let is_measurements = brcb.path.iter().any(|s| s.contains("Measurement"));
            if is_measurements {
                assert!(
                    report.entry_id.is_some(),
                    "el BRCB de medidas activa entry-id en OptFlds: {report:?}"
                );
            }
            assert!(!report.entries.is_empty(), "el reporte debe traer entradas");
        }
        Ok(None) => panic!("canal de reportes cerrado sin recibir del BRCB"),
        Err(_) => panic!(
            "no llegó InformationReport del BRCB en 8 s \
             (posible bug de interop en el reporting bufferado)"
        ),
    }

    let _ = client.disable_report(&brcb).await;
}

/// **File transfer** (ISO 9506-2) contra libiec61850: lista el directorio de
/// ficheros del servidor y descarga uno, verificando el contenido byte a byte.
/// Ejercita fileDirectory + fileOpen/fileRead/fileClose contra una implementación
/// independiente. Requiere un servidor con file service habilitado (p. ej.
/// `server_example_files`); si el directorio viene vacío, el subtest se omite.
#[tokio::test]
async fn interop_file_transfer() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");

    // Lista el directorio raíz del filestore. Un reject-PDU aquí es
    // "unrecognized-service": libiec61850 compilado SIN file services (p. ej.
    // server_example_basic_io); la conformidad estructural de fileDirectory se
    // verificó contra server_example_files y queda cubierta por los guardianes
    // de bytes de `mms/file.rs`.
    let dir = match client.file_directory(None, None).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("file service no disponible ({e}): subtest omitido");
            return;
        }
    };
    eprintln!("Directorio del filestore: {} entradas", dir.entries.len());
    for e in &dir.entries {
        eprintln!("  {} ({} bytes)", e.name, e.size);
    }
    if dir.entries.is_empty() {
        eprintln!("filestore vacío: subtest de descarga omitido");
        return;
    }

    // Descarga un fichero pequeño (evita el binario grande IEDSERVER.BIN).
    let small = dir
        .entries
        .iter()
        .filter(|e| e.size > 0 && e.size < 100_000)
        .min_by_key(|e| e.size)
        .expect("algún fichero pequeño");
    eprintln!("Descargando {} ({} bytes)", small.name, small.size);

    let data = client
        .download_file(&small.name)
        .await
        .expect("descarga por bloques (open/read/close)");
    assert_eq!(
        data.len() as u64,
        small.size as u64,
        "el tamaño descargado debe coincidir con el del directorio"
    );

    // Si es nuestro fichero de prueba, verifica el contenido exacto.
    if small.name.contains("prueba") {
        assert_eq!(
            data, b"CONTENIDO-DE-PRUEBA-INTEROP-1234567890",
            "el contenido descargado debe ser idéntico"
        );
        eprintln!("Contenido verificado byte a byte");
    }
}

/// **Datasets dinámicos** contra libiec61850: crea un dataset con
/// `DefineNamedVariableList`, comprueba sus atributos, lo lee y lo borra.
#[tokio::test]
async fn interop_dynamic_dataset() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let lds = client.get_server_directory().await.expect("dirs");
    let ld = lds.first().cloned().unwrap_or_default();

    // Descubre 2 variables leíbles para el dataset (hojas de tipo escalar).
    let vars = client
        .get_logical_device_directory(&ld)
        .await
        .unwrap_or_default();
    let members: Vec<(String, String)> = vars
        .iter()
        .filter(|r| r.to_string().contains("stVal") || r.to_string().contains(".mag"))
        .take(2)
        .filter_map(|r| {
            let s = r.to_string();
            let (_, item) = iec61850_mms::object_reference_to_mms(r).ok()?;
            let _ = s;
            Some((ld.clone(), item))
        })
        .collect();
    if members.is_empty() {
        eprintln!("sin miembros adecuados: subtest omitido");
        return;
    }

    match client.create_data_set(&ld, "InteropDS", &members).await {
        Ok(()) => eprintln!("dataset dinámico creado con {} miembros", members.len()),
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("DefineNamedVariableList produjo reject-PDU: {r}")
        }
        Err(e) => {
            eprintln!("createDataSet no soportado por el servidor ({e}): subtest omitido");
            return;
        }
    }

    // Atributos: debe ser borrable y traer los miembros que pusimos.
    let attrs = client
        .get_data_set_directory(&ld, "InteropDS")
        .await
        .expect("GetNamedVariableListAttributes");
    assert!(attrs.deletable);
    assert_eq!(attrs.members.len(), members.len());

    // Leer el dataset dinámico no debe fallar.
    let values = client
        .read_data_set(&ld, "InteropDS")
        .await
        .expect("read del dataset dinámico");
    eprintln!("leídos {} valores del dataset dinámico", values.len());

    // Borrar: 1 coincidencia, 1 borrado.
    let del = client
        .delete_data_set(&ld, "InteropDS")
        .await
        .expect("DeleteNamedVariableList");
    assert_eq!((del.matched, del.deleted), (1, 1));
}

/// **Log Control Block (LCB)** contra libiec61850: descubre un LCB (FC=LG), lo
/// lee como estructura y comprueba sus componentes (`LogEna`, `LogRef`...).
#[tokio::test]
async fn interop_log_control_block() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let lds = client.get_server_directory().await.expect("dirs");

    // Descubre el LCB: variable con FC=LG cuyo último segmento sea 'LogEna'.
    let mut lcb: Option<ObjectReference> = None;
    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        if let Some(r) = vars.iter().find(|r| {
            r.fc == Some(iec61850_model::FunctionalConstraint::LG)
                && r.path.last().map(|s| s.as_str()) == Some("LogEna")
        }) {
            let mut base = r.clone();
            base.path.pop();
            lcb = Some(base);
            break;
        }
    }
    let Some(lcb) = lcb else {
        eprintln!("sin LCB (FC=LG): subtest omitido");
        return;
    };
    eprintln!("LCB descubierto: {lcb}");

    // Leer el LCB completo debe devolver una estructura (LogEna, LogRef, ...).
    match client.read(&lcb).await {
        Ok(iec61850_mms::MmsData::Structure(comps)) => {
            eprintln!("LCB estructura con {} componentes", comps.len());
            assert!(comps.len() >= 7, "el LCB tiene al menos 7 componentes");
        }
        Ok(other) => panic!("el LCB debe leerse como estructura, fue {other:?}"),
        Err(e) => panic!("no se pudo leer el LCB: {e}"),
    }

    // ReadJournal del log asociado: el journalName es "<LN>$<LogName>" en el
    // mismo LD. La respuesta debe decodificarse sin error (aunque venga vacía).
    let domain = &lcb.ld;
    let log_item = format!(
        "{}${}",
        lcb.ln,
        lcb.path.last().cloned().unwrap_or_default()
    );
    match client.read_journal(domain, &log_item).await {
        Ok((entries, more)) => {
            eprintln!(
                "ReadJournal {log_item}: {} entradas, more={more}",
                entries.len()
            );
        }
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("ReadJournal produjo reject-PDU (estructura no conforme): {r}")
        }
        Err(e) => eprintln!("ReadJournal rechazado (aceptable si el log no existe): {e}"),
    }
}

/// **Autenticación ACSE por password** (IEC 62351-4) contra libiec61850: el
/// `server_example_password_auth` exige uno de dos passwords. Sin él la
/// asociación se rechaza; con él, se acepta. Requiere que `IEC61850_INTEROP_PW`
/// contenga un password válido del servidor (p. ej. `user1@testpw`).
#[tokio::test]
async fn interop_acse_password_auth() {
    let addr = addr_or_skip!();
    let Ok(pw) = std::env::var("IEC61850_INTEROP_PW") else {
        eprintln!("IEC61850_INTEROP_PW no definida: subtest de auth omitido");
        return;
    };

    // Con el password correcto: asocia.
    let client = MmsClient::connect_with_password(&addr, &pw)
        .await
        .expect("asociación autenticada (62351-4)");
    assert!(client.negotiated().version >= 1);
    eprintln!("asociación autenticada OK con password");

    // Con un password incorrecto: la asociación debe rechazarse.
    match MmsClient::connect_with_password(&addr, "password-invalido").await {
        Err(_) => eprintln!("password inválido rechazado, correcto"),
        Ok(_) => panic!("el servidor aceptó un password inválido"),
    }
}

/// **Grupos de ajustes (SGCB)** contra libiec61850: descubre el SGCB, lo lee como
/// estructura (`NumOfSG`, `ActSG`...) y selecciona un grupo activo.
#[tokio::test]
async fn interop_setting_groups() {
    let addr = addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let lds = client.get_server_directory().await.expect("dirs");

    // Descubre el SGCB: una variable con FC=SP cuyo penúltimo/último segmento
    // sea 'SGCB' (p. ej. 'LLN0$SP$SGCB$NumOfSG').
    let mut sgcb: Option<ObjectReference> = None;
    for ld in &lds {
        let vars = client
            .get_logical_device_directory(ld)
            .await
            .unwrap_or_default();
        if let Some(r) = vars.iter().find(|r| {
            r.fc == Some(iec61850_model::FunctionalConstraint::SP)
                && r.path.iter().any(|s| s == "SGCB")
                && r.path.last().map(|s| s.as_str()) == Some("NumOfSG")
        }) {
            // Referencia de la base del SGCB: quita el atributo final.
            let mut base = r.clone();
            base.path.pop();
            sgcb = Some(base);
            break;
        }
    }
    let Some(sgcb) = sgcb else {
        eprintln!("sin SGCB (FC=SP): subtest omitido");
        return;
    };
    eprintln!("SGCB descubierto: {sgcb}");

    // Lee NumOfSG y ActSG.
    let mut num_ref = sgcb.clone();
    num_ref.path.push("NumOfSG".to_string());
    let num = client.read(&num_ref).await.expect("read NumOfSG");
    eprintln!("NumOfSG = {num:?}");
    let num_groups = match num {
        iec61850_mms::MmsData::Uint(n) => n as u32,
        iec61850_mms::MmsData::Int(n) => n as u32,
        other => panic!("NumOfSG debe ser numérico, fue {other:?}"),
    };
    assert!(num_groups >= 1, "debe haber al menos un grupo de ajustes");

    // Selecciona el grupo activo 1 (SelectActiveSG). No debe dar reject-PDU.
    match client.select_active_sg(&sgcb, 1).await {
        Ok(()) => eprintln!("SelectActiveSG(1) aceptado"),
        Err(iec61850_mms::MmsError::ServiceReject(r)) => {
            panic!("SelectActiveSG produjo reject-PDU: {r}")
        }
        Err(e) => eprintln!("SelectActiveSG rechazado (aceptable según permisos): {e}"),
    }
}

// --- Modelos de control del 7-2 contra `server_example_control` -------------
//
// El servidor de control de libiec61850 expone GGIO1.SPCSO1..4 con los cuatro
// modelos operables: 1 = direct-normal, 2 = sbo-normal, 3 = direct-enhanced,
// 4 = sbo-enhanced. Se levanta con el servicio `libiec61850-control` del
// docker-compose del banco y se apunta con IEC61850_INTEROP_CONTROL_ADDR
// (p. ej. 127.0.0.1:10103).

fn control_addr() -> Option<String> {
    std::env::var("IEC61850_INTEROP_CONTROL_ADDR").ok()
}

macro_rules! control_addr_or_skip {
    () => {
        match control_addr() {
            Some(a) => a,
            None => {
                eprintln!("IEC61850_INTEROP_CONTROL_ADDR no definida: test omitido");
                return;
            }
        }
    };
}

/// Lee el `ctlModel` (CF) de un SPCSO del servidor de control.
async fn read_ctl_model(client: &MmsClient, spcso: &str) -> i64 {
    let r: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}.ctlModel[CF]")
        .parse()
        .expect("ref ctlModel");
    match client.read(&r).await.expect("read ctlModel") {
        iec61850_mms::MmsData::Int(n) => n,
        iec61850_mms::MmsData::Uint(n) => n as i64,
        other => panic!("ctlModel debe ser entero, fue {other:?}"),
    }
}

/// Los cuatro SPCSO del servidor de control cubren los cuatro modelos operables.
#[tokio::test]
async fn interop_control_models_advertised() {
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let mut models = Vec::new();
    for spcso in ["SPCSO1", "SPCSO2", "SPCSO3", "SPCSO4"] {
        models.push(read_ctl_model(&client, spcso).await);
    }
    eprintln!("ctlModel SPCSO1..4 = {models:?}");
    // El ejemplo de libiec61850 los define como 1..4; toleramos otro orden pero
    // exigimos que los cuatro modelos operables estén presentes.
    let mut sorted = models.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![1, 2, 3, 4],
        "faltan modelos de control: {models:?}"
    );
}

/// direct-with-normal-security: Oper aceptado y stVal refleja el mando.
#[tokio::test]
async fn interop_control_direct_normal() {
    use iec61850_mms::MmsData;
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let spcso = "SPCSO1";
    assert_eq!(
        read_ctl_model(&client, spcso).await,
        1,
        "SPCSO1 debe ser direct-normal"
    );

    let ctl: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}").parse().unwrap();
    let stval: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}.stVal[ST]")
        .parse()
        .unwrap();
    client
        .operate(&ctl, MmsData::Bool(true))
        .await
        .expect("operate direct");
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(true));
    client
        .operate(&ctl, MmsData::Bool(false))
        .await
        .expect("operate off");
}

/// sbo-with-normal-security: select (lectura de SBO) y operate.
#[tokio::test]
async fn interop_control_sbo_normal() {
    use iec61850_mms::MmsData;
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let spcso = "SPCSO2";
    assert_eq!(
        read_ctl_model(&client, spcso).await,
        2,
        "SPCSO2 debe ser sbo-normal"
    );

    let ctl: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}").parse().unwrap();
    let stval: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}.stVal[ST]")
        .parse()
        .unwrap();
    assert!(
        client.select(&ctl).await.expect("select"),
        "el select debe concederse"
    );
    client
        .operate(&ctl, MmsData::Bool(true))
        .await
        .expect("operate tras select");
    assert_eq!(client.read(&stval).await.unwrap(), MmsData::Bool(true));
}

/// direct-with-enhanced-security: Oper + CommandTermination positiva.
#[tokio::test]
async fn interop_control_direct_enhanced() {
    use iec61850_mms::{ControlParameters, MmsData};
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let spcso = "SPCSO3";
    assert_eq!(
        read_ctl_model(&client, spcso).await,
        3,
        "SPCSO3 debe ser direct-enhanced"
    );

    let ctl: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}").parse().unwrap();
    client
        .operate_enhanced(&ctl, MmsData::Bool(true), &ControlParameters::default())
        .await
        .expect("operate enhanced con CommandTermination+");
    eprintln!("CommandTermination+ recibida y decodificada");
}

/// sbo-with-enhanced-security: SBOw + Oper + CommandTermination positiva.
#[tokio::test]
async fn interop_control_sbo_enhanced() {
    use iec61850_mms::{ControlParameters, MmsData};
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let spcso = "SPCSO4";
    assert_eq!(
        read_ctl_model(&client, spcso).await,
        4,
        "SPCSO4 debe ser sbo-enhanced"
    );

    let ctl: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}").parse().unwrap();
    let p = ControlParameters::default();
    client
        .select_with_value(&ctl, MmsData::Bool(true), &p)
        .await
        .expect("SBOw aceptado");
    client
        .operate_enhanced(&ctl, MmsData::Bool(true), &p)
        .await
        .expect("operate enhanced tras SBOw");
    eprintln!("flujo sbo-enhanced completo (SBOw + Oper + CommandTermination+)");
}

/// Operar un sbo-enhanced SIN seleccionar: el rechazo debe llegar con el
/// `LastApplError` de libiec61850 (AddCause 18 = object-not-selected u otro
/// AddCause distinto de 0). Verifica nuestro parser de LastApplError contra
/// el emisor real.
#[tokio::test]
async fn interop_control_not_selected_lastapplerror() {
    use iec61850_mms::{ControlParameters, MmsData, MmsError};
    let addr = control_addr_or_skip!();
    let client = MmsClient::connect(&addr).await.expect("asocia");
    let spcso = "SPCSO4";
    assert_eq!(read_ctl_model(&client, spcso).await, 4);

    let ctl: ObjectReference = format!("simpleIOGenericIO/GGIO1.{spcso}").parse().unwrap();
    let err = client
        .operate_enhanced(&ctl, MmsData::Bool(true), &ControlParameters::default())
        .await
        .expect_err("operate sin select debe rechazarse");
    eprintln!("rechazo recibido: {err}");
    match err {
        MmsError::ControlTerminated { add_cause } => {
            eprintln!("AddCause del LastApplError: {add_cause}");
            assert_eq!(
                add_cause,
                iec61850_mms::add_cause::OBJECT_NOT_SELECTED,
                "se esperaba object-not-selected"
            );
        }
        // Sin LastApplError correlacionado sería un DataAccess pelado: también
        // conforme, pero registramos que no vimos la causa detallada.
        MmsError::DataAccess(e) => {
            panic!("Write− sin LastApplError correlacionado (esperábamos AddCause 18): {e}")
        }
        other => panic!("error inesperado: {other}"),
    }
}
