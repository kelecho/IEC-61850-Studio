//! Core Rust de la app Tauri: expone el cliente MMS de `iec61850` como comandos
//! invocables desde el frontend web, y emite los reportes (RCB) como eventos
//! `report`. Solo MMS (TCP); refleja la app egui (lectura + escritura/control).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use iec61850::Model;
use iec61850::ObjectReference;
#[cfg(any(target_os = "linux", windows))]
use iec61850::goose::socket::RawSocket;
#[cfg(any(target_os = "linux", windows))]
use iec61850::goose::{
    ETHERTYPE_GOOSE, GooseConfig, GooseEventKind, GooseFilter, GooseLink, GoosePublisher,
    GooseSubscriber, PcapWriter,
};
use iec61850::mms::ber::prim::BitString;
use iec61850::mms::{
    IdentifyResponse, MmsClient, MmsData, MmsServer, Report, ServerModel, TlsClientOptions,
    TlsServerOptions,
};
use iec61850::model::{BasicType, DataAttribute, DataObject, FunctionalConstraint};
#[cfg(any(target_os = "linux", windows))]
use iec61850::sv::{
    ETHERTYPE_SV, NineTwoLe, SvChannel, SvConfig, SvEventKind, SvFilter, SvPublisher, SvSubscriber,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Modelo SCL embebido para el IED simulado (sin archivos externos).
const SIMPLE_ICD: &str = include_str!("../../../../fixtures/icd/simple.icd");
/// Dirección donde escucha el simulador embebido.
const SIM_ADDR: &str = "127.0.0.1:10102";
/// Dirección del simulador TLS embebido (demo mTLS).
const SIM_TLS_ADDR: &str = "127.0.0.1:10103";
/// Certificados de PRUEBA embebidos para el simulador TLS (ver `test-certs/`).
const TLS_CA: &[u8] = include_bytes!("../../test-certs/ca.crt.pem");
const TLS_SERVER_CRT: &[u8] = include_bytes!("../../test-certs/server.crt.pem");
const TLS_SERVER_KEY: &[u8] = include_bytes!("../../test-certs/server.key.pem");
/// Certificado/clave de CLIENTE de prueba embebidos: permiten el demo mTLS
/// (`connect_tls_demo`) 100 % autocontenido, sin rutas a ficheros en disco.
const TLS_CLIENT_CRT: &[u8] = include_bytes!("../../test-certs/client.crt.pem");
const TLS_CLIENT_KEY: &[u8] = include_bytes!("../../test-certs/client.key.pem");
/// Server name del certificado del simulador TLS embebido.
const SIM_TLS_SERVER_NAME: &str = "iec61850-sim";

/// Mensaje de los stubs sin backend de capa 2. GOOSE/SV/PCAP usan AF_PACKET
/// (Linux) o Npcap (Windows); en otros SO (p. ej. macOS) no hay backend. El
/// resto de la app (MMS/TCP, SCL, IED en vivo) funciona en cualquier SO.
#[cfg(not(any(target_os = "linux", windows)))]
const L2_UNSUPPORTED: &str =
    "captura capa 2 (GOOSE/SV/PCAP) no disponible en este sistema operativo: requiere Linux o Windows (con Npcap)";

/// Tareas del simulador IED en marcha (servidor + variación de medida).
struct SimHandle {
    addr: String,
    serve: JoinHandle<()>,
    vary: JoinHandle<()>,
}

/// IED **en vivo**: servidor MMS sirviendo un SCL del usuario, arrancado desde
/// la UI. Puede haber varios a la vez (banco de subestación), cada uno en su
/// dirección.
struct LiveSim {
    /// Ruta del SCL servido (para mostrarla en la UI).
    scl: String,
    /// Directorio temporal expuesto por file transfer (contiene copia del SCL);
    /// se borra al detener el IED.
    files: std::path::PathBuf,
    serve: JoinHandle<()>,
    vary: JoinHandle<()>,
}

/// IED en vivo serializado para el frontend.
#[derive(Serialize)]
struct LiveSimInfo {
    addr: String,
    scl: String,
}

/// Una conexión MMS abierta (a un IED).
struct Conn {
    client: Arc<MmsClient>,
    tls: bool,
}

/// Conexión serializada para el frontend.
#[derive(Serialize)]
struct ConnInfo {
    id: String,
    tls: bool,
    active: bool,
}

/// Estado compartido: las conexiones MMS abiertas (multi-IED), cuál está activa,
/// y opcionalmente los simuladores IED embebidos.
#[derive(Default)]
struct AppState {
    /// Conexiones abiertas, indexadas por su id (la dirección `ip:puerto`).
    clients: Mutex<HashMap<String, Conn>>,
    /// Id de la conexión activa (a la que apuntan read/write/etc.).
    active: Mutex<Option<String>>,
    sim: Mutex<Option<SimHandle>>,
    /// Simulador TLS embebido (demo mTLS), si está en marcha.
    sim_tls: Mutex<Option<SimHandle>>,
    /// Tarea del monitor GOOSE (capa 2), si está en marcha.
    goose_mon: Mutex<Option<JoinHandle<()>>>,
    /// Tarea del monitor SV (capa 2), si está en marcha.
    sv_mon: Mutex<Option<JoinHandle<()>>>,
    /// Tarea del publicador GOOSE de demo, si está en marcha.
    goose_pub: Mutex<Option<JoinHandle<()>>>,
    /// Tarea del publicador SV de demo, si está en marcha.
    sv_pub: Mutex<Option<JoinHandle<()>>>,
    /// Modelo cargado desde un SCL (para el árbol configurado y los datasets).
    scl_model: Mutex<Option<Model>>,
    /// IEDs en vivo (servidores MMS desde un SCL del usuario), por dirección.
    sims_live: Mutex<HashMap<String, LiveSim>>,
}

fn sim_ident() -> IdentifyResponse {
    IdentifyResponse {
        vendor: "ACME".into(),
        model: "IED-SIM (embebido)".into(),
        revision: "1.0".into(),
    }
}

/// Una entrada de reporte: índice de miembro en el dataset + valor.
#[derive(Serialize, Clone)]
struct EntryP {
    index: usize,
    value: String,
}

/// Reporte serializado que se emite al frontend.
#[derive(Serialize, Clone)]
struct ReportPayload {
    /// IED de origen (id de la conexión).
    source: String,
    rpt_id: String,
    seq_num: Option<u64>,
    dataset: Option<String>,
    entry_id: Option<String>,
    entries: Vec<EntryP>,
}

impl ReportPayload {
    fn from(r: &Report, source: &str) -> Self {
        ReportPayload {
            source: source.to_string(),
            rpt_id: r.rpt_id.clone(),
            seq_num: r.seq_num,
            dataset: r.dataset.clone(),
            entry_id: r.entry_id.as_ref().map(|b| hex(b)),
            entries: r
                .entries
                .iter()
                .map(|e| EntryP {
                    index: e.member_index,
                    value: fmt_value(&e.value),
                })
                .collect(),
        }
    }
}

/// Items (variables/RCB) de un dominio (LD), para el árbol del frontend.
#[derive(Serialize)]
struct DomainItems {
    domain: String,
    items: Vec<String>,
}

/// Lectura de un dato con su calidad y marca de tiempo (estilo IEDScout),
/// decodificadas con los tipos `Quality`/`Timestamp` de `iec61850-model`.
#[derive(Serialize)]
struct DoReading {
    value: String,
    /// Resumen de calidad (validez + flags), p. ej. "invalid+overflow+test".
    quality: Option<String>,
    /// Validez: good/invalid/reserved/questionable.
    validity: Option<String>,
    /// `true` si la validez es buena y no hay ninguna bandera de detección activa.
    good: Option<bool>,
    /// Marca de tiempo en segundos epoch (con fracción), si se pidió.
    time_epoch: Option<f64>,
    /// El reloj que selló la marca de tiempo reportó fallo.
    clock_failure: Option<bool>,
    /// El reloj no estaba sincronizado al sellar la marca de tiempo.
    clock_not_synced: Option<bool>,
}

/// Obtiene una referencia clonada al cliente de la conexión **activa**, o error.
async fn current(state: &State<'_, AppState>) -> Result<Arc<MmsClient>, String> {
    let id = state
        .active
        .lock()
        .await
        .clone()
        .ok_or_else(|| "no hay conexión activa".to_string())?;
    state
        .clients
        .lock()
        .await
        .get(&id)
        .map(|c| c.client.clone())
        .ok_or_else(|| "la conexión activa ya no existe".to_string())
}

fn parse_ref(s: &str) -> Result<ObjectReference, String> {
    s.parse::<ObjectReference>()
        .map_err(|_| format!("referencia inválida: {s}"))
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    addr: String,
) -> Result<String, String> {
    let mut c = MmsClient::connect(&addr).await.map_err(|e| e.to_string())?;
    let neg = format!("asociado (MMS v{})", c.negotiated().version);
    let id = addr.clone();
    // Reenvía los reportes no solicitados al frontend como eventos (etiquetados con su IED).
    if let Some(mut rx) = c.take_report_rx() {
        let app = app.clone();
        let source = id.clone();
        tokio::spawn(async move {
            while let Some(r) = rx.recv().await {
                let _ = app.emit("report", ReportPayload::from(&r, &source));
            }
        });
    }
    state.clients.lock().await.insert(
        id.clone(),
        Conn {
            client: Arc::new(c),
            tls: false,
        },
    );
    *state.active.lock().await = Some(id);
    Ok(neg)
}

/// Conecta sobre **TLS/mTLS** (IEC 62351-3). `server_name` se verifica contra el
/// certificado del servidor; `ca`/`cert`/`key` son rutas a PEM.
#[tauri::command]
async fn connect_tls(
    app: AppHandle,
    state: State<'_, AppState>,
    addr: String,
    server_name: String,
    ca: String,
    cert: String,
    key: String,
) -> Result<String, String> {
    let connector = TlsClientOptions::from_pem_files(&ca, &cert, &key)
        .map_err(|e| e.to_string())?
        .connector()
        .map_err(|e| e.to_string())?;
    let mut c = MmsClient::connect_tls(&addr, &server_name, connector)
        .await
        .map_err(|e| e.to_string())?;
    let neg = format!("asociado TLS (MMS v{})", c.negotiated().version);
    let id = addr.clone();
    if let Some(mut rx) = c.take_report_rx() {
        let app = app.clone();
        let source = id.clone();
        tokio::spawn(async move {
            while let Some(r) = rx.recv().await {
                let _ = app.emit("report", ReportPayload::from(&r, &source));
            }
        });
    }
    state.clients.lock().await.insert(
        id.clone(),
        Conn {
            client: Arc::new(c),
            tls: true,
        },
    );
    *state.active.lock().await = Some(id);
    Ok(neg)
}

/// Conecta por **TLS/mTLS al simulador embebido** usando los certificados de
/// prueba embebidos (CA + cliente): demo 100 % autocontenido, sin pedir rutas
/// a ficheros. Arranca el simulador TLS si no estaba en marcha.
#[tauri::command]
async fn connect_tls_demo(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let addr = sim_start_tls(state.clone()).await?;
    let connector = TlsClientOptions::from_pem(TLS_CA, TLS_CLIENT_CRT, TLS_CLIENT_KEY)
        .map_err(|e| e.to_string())?
        .connector()
        .map_err(|e| e.to_string())?;
    let mut c = MmsClient::connect_tls(&addr, SIM_TLS_SERVER_NAME, connector)
        .await
        .map_err(|e| e.to_string())?;
    let neg = format!("asociado TLS (MMS v{})", c.negotiated().version);
    let id = addr.clone();
    if let Some(mut rx) = c.take_report_rx() {
        let app = app.clone();
        let source = id.clone();
        tokio::spawn(async move {
            while let Some(r) = rx.recv().await {
                let _ = app.emit("report", ReportPayload::from(&r, &source));
            }
        });
    }
    state.clients.lock().await.insert(
        id.clone(),
        Conn {
            client: Arc::new(c),
            tls: true,
        },
    );
    *state.active.lock().await = Some(id);
    Ok(neg)
}

/// Lista las conexiones abiertas y cuál está activa.
#[tauri::command]
async fn connections(state: State<'_, AppState>) -> Result<Vec<ConnInfo>, String> {
    let active = state.active.lock().await.clone();
    let clients = state.clients.lock().await;
    let mut out: Vec<ConnInfo> = clients
        .iter()
        .map(|(id, c)| ConnInfo {
            id: id.clone(),
            tls: c.tls,
            active: active.as_deref() == Some(id.as_str()),
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Cambia la conexión activa (a la que apuntan read/write/discover/etc.).
#[tauri::command]
async fn set_active(state: State<'_, AppState>, id: String) -> Result<(), String> {
    if !state.clients.lock().await.contains_key(&id) {
        return Err(format!("conexión '{id}' no encontrada"));
    }
    *state.active.lock().await = Some(id);
    Ok(())
}

/// Cierra la conexión activa y activa otra si queda alguna.
#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let id = state.active.lock().await.clone();
    let mut clients = state.clients.lock().await;
    if let Some(id) = &id {
        clients.remove(id); // Drop aborta la tarea lectora.
    }
    let next = clients.keys().next().cloned();
    drop(clients);
    *state.active.lock().await = next;
    Ok(())
}

/// Cierra una conexión concreta por su id.
#[tauri::command]
async fn disconnect_id(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut clients = state.clients.lock().await;
    clients.remove(&id);
    let next = clients.keys().next().cloned();
    drop(clients);
    let mut active = state.active.lock().await;
    if active.as_deref() == Some(id.as_str()) {
        *active = next;
    }
    Ok(())
}

/// Escribe texto (CSV) en una ruta elegida por el usuario (diálogo de guardado).
#[tauri::command]
async fn save_text(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| format!("guardar {path}: {e}"))
}

/// Captura a un archivo **PCAP** (abrible en Wireshark) todo el tráfico de la
/// interfaz en modo promiscuo (ETH_P_ALL): GOOSE, SV, MMS/C-S, ARP… Se detiene
/// al llegar a `frames` tramas o tras `secs` segundos sin más tráfico. Devuelve
/// el nº de tramas capturadas. Requiere CAP_NET_RAW/root.
#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn capture_pcap(
    iface: String,
    path: String,
    frames: usize,
    secs: u64,
) -> Result<usize, String> {
    let sock = RawSocket::open_all(&iface)
        .map_err(|e| format!("captura en {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let file = std::fs::File::create(&path).map_err(|e| format!("crear {path}: {e}"))?;
    let mut pcap = PcapWriter::new(std::io::BufWriter::new(file))
        .map_err(|e| format!("cabecera pcap: {e}"))?;
    let frames = if frames == 0 {
        500
    } else {
        frames.min(100_000)
    };
    let secs = if secs == 0 { 15 } else { secs.min(300) };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut n = 0usize;
    while n < frames {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sock.recv()).await {
            Ok(Ok(frame)) => {
                pcap.write_packet_now(&frame)
                    .map_err(|e| format!("escribir pcap: {e}"))?;
                n += 1;
            }
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Err(_) => break, // sin más tráfico dentro del plazo
        }
    }
    pcap.flush().map_err(|e| format!("flush pcap: {e}"))?;
    Ok(n)
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn capture_pcap(
    iface: String,
    path: String,
    frames: usize,
    secs: u64,
) -> Result<usize, String> {
    let _ = (iface, path, frames, secs);
    Err(L2_UNSUPPORTED.into())
}

/// Entrada de fichero del IED, para el frontend.
#[derive(Serialize)]
struct FileEntryP {
    name: String,
    size: u32,
    last_modified: Option<String>,
}

/// Lista los ficheros del IED de la conexión activa (registros, COMTRADE, logs).
#[tauri::command]
async fn file_directory(state: State<'_, AppState>) -> Result<Vec<FileEntryP>, String> {
    let client = current(&state).await?;
    let dir = client
        .file_directory(None, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(dir
        .entries
        .into_iter()
        .map(|e| FileEntryP {
            name: e.name,
            size: e.size,
            last_modified: e.last_modified,
        })
        .collect())
}

/// Descarga un fichero del IED (open + read por bloques + close) y lo guarda en
/// `dest`. Devuelve el nº de octetos escritos.
#[tauri::command]
async fn download_file(
    state: State<'_, AppState>,
    name: String,
    dest: String,
) -> Result<usize, String> {
    let client = current(&state).await?;
    let data = client
        .download_file(&name)
        .await
        .map_err(|e| e.to_string())?;
    let len = data.len();
    std::fs::write(&dest, &data).map_err(|e| format!("guardar {dest}: {e}"))?;
    Ok(len)
}

/// IED descubierto en el escaneo de red.
#[derive(Serialize)]
struct FoundIed {
    addr: String,
    vendor: Option<String>,
    model: Option<String>,
    revision: Option<String>,
}

/// Escanea un /24 (`base` = `a.b.c`) buscando IEDs: sondea el puerto (102 por
/// defecto) y, si responde, intenta asociar MMS + Identify (vendor/model/rev).
#[tauri::command]
async fn scan_network(base: String, port: u16) -> Result<Vec<FoundIed>, String> {
    let octets: Vec<&str> = base.split(['.', '/']).filter(|s| !s.is_empty()).collect();
    if octets.len() < 3 {
        return Err("prefijo inválido; usa a.b.c (p. ej. 192.168.1)".into());
    }
    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    let port = if port == 0 { 102 } else { port };
    let sem = Arc::new(tokio::sync::Semaphore::new(64));
    let mut handles = Vec::new();
    for h in 1..=254u16 {
        let addr = format!("{prefix}.{h}:{port}");
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            // Sondea el puerto con timeout corto.
            let probe = tokio::time::timeout(
                Duration::from_millis(700),
                tokio::net::TcpStream::connect(&addr),
            )
            .await;
            match probe {
                Ok(Ok(stream)) => drop(stream),
                _ => return None, // cerrado / filtrado / sin respuesta
            }
            // Asocia MMS e Identify (puede fallar si no es un IED MMS).
            let (vendor, model, revision) =
                match tokio::time::timeout(Duration::from_secs(3), MmsClient::connect(&addr)).await
                {
                    Ok(Ok(c)) => {
                        match tokio::time::timeout(Duration::from_secs(2), c.identify()).await {
                            Ok(Ok(id)) => (Some(id.vendor), Some(id.model), Some(id.revision)),
                            _ => (None, None, None),
                        }
                    }
                    _ => (None, None, None),
                };
            Some(FoundIed {
                addr,
                vendor,
                model,
                revision,
            })
        }));
    }
    let mut found = Vec::new();
    for handle in handles {
        if let Ok(Some(f)) = handle.await {
            found.push(f);
        }
    }
    found.sort_by_key(|f| {
        f.addr
            .rsplit_once(':')
            .and_then(|(ip, _)| ip.rsplit_once('.'))
            .and_then(|(_, h)| h.parse::<u16>().ok())
            .unwrap_or(0)
    });
    Ok(found)
}

/// Publicador GOOSE/SV descubierto pasivamente en capa 2.
#[derive(Serialize, Clone)]
struct PubInfo {
    kind: String,
    id: String,
    label: String,
    dat_set: String,
    appid: u16,
    src: String,
    conf_rev: u32,
    count: u32,
}

/// Escucha `secs` segundos en `iface` y lista los publicadores GOOSE/SV únicos
/// (capa 2; requiere CAP_NET_RAW/root).
#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn discover_l2(iface: String, secs: u64) -> Result<Vec<PubInfo>, String> {
    let secs = if secs == 0 { 4 } else { secs.min(30) };
    // Modo promiscuo: descubre publicadores GOOSE/SV de cualquier MAC, no solo
    // de un grupo multicast.
    let g_sock = RawSocket::open_promiscuous(&iface, ETHERTYPE_GOOSE)
        .map_err(|e| format!("GOOSE {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let s_sock = RawSocket::open_promiscuous(&iface, ETHERTYPE_SV)
        .map_err(|e| format!("SV {iface}: {e} (¿CAP_NET_RAW/root?)"))?;

    let found: Arc<Mutex<HashMap<String, PubInfo>>> = Arc::new(Mutex::new(HashMap::new()));

    let fg = found.clone();
    let g_task = tokio::spawn(async move {
        let mut sub = GooseSubscriber::new(g_sock, GooseFilter::default()).start();
        while let Some(ev) = sub.recv_event().await {
            let key = format!("GOOSE:{}", ev.gocb_ref);
            fg.lock()
                .await
                .entry(key)
                .and_modify(|e| e.count += 1)
                .or_insert(PubInfo {
                    kind: "GOOSE".into(),
                    id: ev.gocb_ref,
                    label: ev.go_id,
                    dat_set: ev.dat_set,
                    appid: ev.appid,
                    src: mac(&ev.src),
                    conf_rev: ev.conf_rev,
                    count: 1,
                });
        }
    });
    let fs = found.clone();
    let s_task = tokio::spawn(async move {
        let mut sub = SvSubscriber::new(s_sock, SvFilter::default()).start();
        while let Some(ev) = sub.recv_sample().await {
            let key = format!("SV:{}", ev.sv_id);
            fs.lock()
                .await
                .entry(key)
                .and_modify(|e| e.count += 1)
                .or_insert(PubInfo {
                    kind: "SV".into(),
                    id: ev.sv_id,
                    label: String::new(),
                    dat_set: String::new(),
                    appid: ev.appid,
                    src: mac(&ev.src),
                    conf_rev: ev.conf_rev,
                    count: 1,
                });
        }
    });

    tokio::time::sleep(Duration::from_secs(secs)).await;
    g_task.abort();
    s_task.abort();

    let mut out: Vec<PubInfo> = found.lock().await.values().cloned().collect();
    out.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    Ok(out)
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn discover_l2(iface: String, secs: u64) -> Result<Vec<PubInfo>, String> {
    let _ = (iface, secs);
    Err(L2_UNSUPPORTED.into())
}

#[tauri::command]
async fn discover(state: State<'_, AppState>) -> Result<Vec<DomainItems>, String> {
    let c = current(&state).await?;
    let domains = c.get_server_directory().await.map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(domains.len());
    for domain in domains {
        let items = c
            .get_logical_device_directory(&domain)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|r| r.to_string())
            .collect();
        out.push(DomainItems { domain, items });
    }
    Ok(out)
}

#[tauri::command]
async fn read(state: State<'_, AppState>, reference: String) -> Result<String, String> {
    let c = current(&state).await?;
    let obj = parse_ref(&reference)?;
    let value = c.read(&obj).await.map_err(|e| e.to_string())?;
    Ok(fmt_value(&value))
}

/// Lee un dato y, opcionalmente, su calidad (`q`) y su marca de tiempo (`t`),
/// decodificadas. El frontend calcula las referencias de `q`/`t` del DO.
#[tauri::command]
async fn read_do(
    state: State<'_, AppState>,
    value: String,
    q: Option<String>,
    t: Option<String>,
) -> Result<DoReading, String> {
    let c = current(&state).await?;
    let val = c
        .read(&parse_ref(&value)?)
        .await
        .map_err(|e| e.to_string())?;

    let mut reading = DoReading {
        value: fmt_value(&val),
        quality: None,
        validity: None,
        good: None,
        time_epoch: None,
        clock_failure: None,
        clock_not_synced: None,
    };

    if let Some(r) = q {
        let v = c.read(&parse_ref(&r)?).await.map_err(|e| e.to_string())?;
        if let MmsData::BitString(b) = &v {
            // Calidad tipada (IEC 61850-7-3) vía iec61850-model.
            let bits: Vec<bool> = (0..b.len_bits()).map(|i| b.bit(i)).collect();
            let quality = iec61850::model::Quality::from_bits(&bits);
            reading.quality = Some(quality.to_string());
            reading.validity = Some(quality.validity.to_string());
            reading.good = Some(quality.is_good());
        } else {
            reading.quality = Some(fmt_value(&v));
        }
    }

    if let Some(r) = t {
        let v = c.read(&parse_ref(&r)?).await.map_err(|e| e.to_string())?;
        if let MmsData::Utc(utc) = &v {
            // Marca de tiempo tipada (segundos + fracción + calidad del reloj).
            let ts = iec61850::model::Timestamp::from_bytes(utc.raw);
            reading.time_epoch = Some(ts.epoch_seconds());
            reading.clock_failure = Some(ts.quality.clock_failure);
            reading.clock_not_synced = Some(ts.quality.clock_not_synchronized);
        }
    }

    Ok(reading)
}

/// Parámetros de un RCB (para leer/editar antes de habilitarlo).
#[derive(Serialize)]
struct RcbParams {
    rpt_id: String,
    dat_set: String,
    conf_rev: u64,
    intg_pd: u64,
    buf_tm: u64,
    trg_ops: Vec<bool>,
    opt_flds: Vec<bool>,
}

/// Construye la referencia de un atributo del RCB: "<rcb sin [FC]>.<attr>[FC]".
fn rcb_attr(rcb: &str, attr: &str) -> String {
    match rcb.rfind('[') {
        Some(i) => format!("{}.{attr}{}", &rcb[..i], &rcb[i..]),
        None => format!("{rcb}.{attr}"),
    }
}

async fn read_attr(c: &MmsClient, rcb: &str, attr: &str) -> Option<MmsData> {
    let r = parse_ref(&rcb_attr(rcb, attr)).ok()?;
    c.read(&r).await.ok()
}

async fn write_attr(c: &MmsClient, rcb: &str, attr: &str, v: MmsData) -> Result<(), String> {
    let r = parse_ref(&rcb_attr(rcb, attr))?;
    c.write(&r, v).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn rcb_read(state: State<'_, AppState>, rcb: String) -> Result<RcbParams, String> {
    let c = current(&state).await?;
    let to_str = |m: Option<MmsData>| match m {
        Some(MmsData::Visible(s)) | Some(MmsData::MmsString(s)) => s,
        _ => String::new(),
    };
    let to_u64 = |m: Option<MmsData>| match m {
        Some(MmsData::Uint(u)) => u,
        Some(MmsData::Int(i)) => i.max(0) as u64,
        _ => 0,
    };
    let to_bools = |m: Option<MmsData>| -> Vec<bool> {
        match m {
            Some(MmsData::BitString(b)) => (0..b.len_bits()).map(|i| b.bit(i)).collect(),
            _ => Vec::new(),
        }
    };
    Ok(RcbParams {
        rpt_id: to_str(read_attr(&c, &rcb, "RptID").await),
        dat_set: to_str(read_attr(&c, &rcb, "DatSet").await),
        conf_rev: to_u64(read_attr(&c, &rcb, "ConfRev").await),
        intg_pd: to_u64(read_attr(&c, &rcb, "IntgPd").await),
        buf_tm: to_u64(read_attr(&c, &rcb, "BufTm").await),
        trg_ops: to_bools(read_attr(&c, &rcb, "TrgOps").await),
        opt_flds: to_bools(read_attr(&c, &rcb, "OptFlds").await),
    })
}

#[tauri::command]
async fn rcb_write(
    state: State<'_, AppState>,
    rcb: String,
    dat_set: Option<String>,
    intg_pd: Option<u64>,
    buf_tm: Option<u64>,
    trg_ops: Option<Vec<bool>>,
    opt_flds: Option<Vec<bool>>,
) -> Result<(), String> {
    let c = current(&state).await?;
    if let Some(s) = dat_set {
        write_attr(&c, &rcb, "DatSet", MmsData::Visible(s)).await?;
    }
    if let Some(p) = intg_pd {
        write_attr(&c, &rcb, "IntgPd", MmsData::Uint(p)).await?;
    }
    if let Some(b) = buf_tm {
        write_attr(&c, &rcb, "BufTm", MmsData::Uint(b)).await?;
    }
    if let Some(bits) = trg_ops {
        write_attr(
            &c,
            &rcb,
            "TrgOps",
            MmsData::BitString(BitString::from_bits(&bits)),
        )
        .await?;
    }
    if let Some(bits) = opt_flds {
        write_attr(
            &c,
            &rcb,
            "OptFlds",
            MmsData::BitString(BitString::from_bits(&bits)),
        )
        .await?;
    }
    Ok(())
}

#[tauri::command]
async fn enable_report(state: State<'_, AppState>, rcb: String) -> Result<(), String> {
    let c = current(&state).await?;
    let obj = parse_ref(&rcb)?;
    c.enable_report(&obj, &Default::default())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn disable_report(state: State<'_, AppState>, rcb: String) -> Result<(), String> {
    let c = current(&state).await?;
    let obj = parse_ref(&rcb)?;
    c.disable_report(&obj).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn write(
    state: State<'_, AppState>,
    reference: String,
    kind: String,
    value: String,
) -> Result<(), String> {
    let c = current(&state).await?;
    let obj = parse_ref(&reference)?;
    let val = parse_value(&kind, &value)?;
    c.write(&obj, val).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn operate(
    state: State<'_, AppState>,
    reference: String,
    kind: String,
    value: String,
) -> Result<(), String> {
    let c = current(&state).await?;
    let obj = parse_ref(&reference)?;
    let val = parse_value(&kind, &value)?;
    c.operate(&obj, val).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn select(state: State<'_, AppState>, reference: String) -> Result<String, String> {
    let c = current(&state).await?;
    let obj = parse_ref(&reference)?;
    let granted = c.select(&obj).await.map_err(|e| e.to_string())?;
    Ok(if granted { "concedido" } else { "denegado" }.to_string())
}

/// Primer measurand flotante (FC=MX) del modelo: candidato a variar en vivo.
fn first_measurand(model: &Model) -> Option<ObjectReference> {
    model.iter_data_attributes().find_map(|(reference, da)| {
        if da.fc == FunctionalConstraint::MX
            && matches!(da.basic_type, BasicType::Float32 | BasicType::Float64)
        {
            Some(reference)
        } else {
            None
        }
    })
}

/// Arranca el IED simulado (servidor MMS) dentro de la propia app y varía un
/// measurand para que los reportes tengan actividad. Devuelve su dirección.
///
/// - `scl_path`: SCL a servir (`.cid`/`.icd`/`.scd`); vacío → el ICD embebido.
/// - `bind`: dirección de escucha (`0.0.0.0:10102` la hace visible en la LAN);
///   vacío → `127.0.0.1:10102`.
#[tauri::command]
async fn sim_start(
    state: State<'_, AppState>,
    scl_path: Option<String>,
    bind: Option<String>,
) -> Result<String, String> {
    let mut guard = state.sim.lock().await;
    if let Some(h) = guard.as_ref() {
        return Ok(h.addr.clone());
    }
    let model = match scl_path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(path) => iec61850::scl::load_model(path).map_err(|e| format!("cargar {path}: {e}"))?,
        None => iec61850::scl::parse_scl_str(SIMPLE_ICD)
            .map_err(|e| e.to_string())?
            .resolve()
            .map_err(|e| e.to_string())?,
    };
    let bind_addr = bind
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| SIM_ADDR.to_string());
    let sm = ServerModel::from_model(&model, sim_ident());
    let store = sm.init_store(&model);
    let server = MmsServer::bind(&bind_addr, Arc::new(sm), store)
        .await
        .map_err(|e| format!("bind {bind_addr}: {e}"))?;
    let addr = server
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind_addr.clone());
    let app_handle = server.handle();
    let serve = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    // Varía el primer measurand MX flotante del modelo (para ver datos vivos).
    let member = first_measurand(&model);
    let vary = tokio::spawn(async move {
        let Some(member) = member else { return };
        let mut t = 0.0f64;
        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            t += 0.25;
            let value = MmsData::Float(100.0 + 10.0 * t.sin());
            let _ = app_handle.set_value(&member, value).await;
        }
    });
    *guard = Some(SimHandle {
        addr: addr.clone(),
        serve,
        vary,
    });
    Ok(addr)
}

/// Arranca un simulador IED **TLS** (mTLS) con los certificados de prueba embebidos.
/// Devuelve su dirección; conéctate con `server_name = "iec61850-sim"`.
#[tauri::command]
async fn sim_start_tls(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.sim_tls.lock().await;
    if let Some(h) = guard.as_ref() {
        return Ok(h.addr.clone());
    }
    let doc = iec61850::scl::parse_scl_str(SIMPLE_ICD).map_err(|e| e.to_string())?;
    let model = doc.resolve().map_err(|e| e.to_string())?;
    let sm = ServerModel::from_model(&model, sim_ident());
    let store = sm.init_store(&model);
    let acceptor = TlsServerOptions::from_pem(TLS_SERVER_CRT, TLS_SERVER_KEY, TLS_CA)
        .map_err(|e| e.to_string())?
        .acceptor()
        .map_err(|e| e.to_string())?;
    let server = MmsServer::bind_tls(SIM_TLS_ADDR, Arc::new(sm), store, acceptor)
        .await
        .map_err(|e| format!("bind_tls {SIM_TLS_ADDR}: {e}"))?;
    let addr = server
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| SIM_TLS_ADDR.to_string());
    let app_handle = server.handle();
    let serve = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    let vary = tokio::spawn(async move {
        let member: ObjectReference = match "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse() {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut t = 0.0f64;
        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            t += 0.25;
            let _ = app_handle
                .set_value(&member, MmsData::Float(100.0 + 10.0 * t.sin()))
                .await;
        }
    });
    *guard = Some(SimHandle {
        addr: addr.clone(),
        serve,
        vary,
    });
    Ok(addr)
}

/// Arranca un **IED en vivo** desde un SCL del usuario, en la dirección pedida.
/// Convive con otros: cada llamada añade un servidor (banco de subestación).
#[tauri::command]
async fn sim_live_start(
    state: State<'_, AppState>,
    scl_path: String,
    bind: String,
) -> Result<String, String> {
    let scl_path = scl_path.trim().to_string();
    let bind = bind.trim().to_string();
    if scl_path.is_empty() {
        return Err("indica el fichero SCL a servir".into());
    }
    let model =
        iec61850::scl::load_model(&scl_path).map_err(|e| format!("cargar {scl_path}: {e}"))?;
    // Expone el propio SCL por file transfer: cualquier cliente conectado puede
    // descargar el CID exacto que sirve este IED (pestaña «Ficheros»). Se copia
    // a un directorio temporal propio para no exponer el directorio del usuario.
    let file_root = std::env::temp_dir().join(format!(
        "iec61850-live-{}",
        bind.replace([':', '/', '\\'], "_")
    ));
    std::fs::create_dir_all(&file_root)
        .map_err(|e| format!("crear {}: {e}", file_root.display()))?;
    let scl_name = std::path::Path::new(&scl_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ied.cid".into());
    std::fs::copy(&scl_path, file_root.join(&scl_name))
        .map_err(|e| format!("copiar el SCL a {}: {e}", file_root.display()))?;
    let sm = ServerModel::from_model(&model, sim_ident()).with_file_root(file_root.clone());
    let store = sm.init_store(&model);
    let server = MmsServer::bind(&bind, Arc::new(sm), store)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = server
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.clone());
    let mut guard = state.sims_live.lock().await;
    if guard.contains_key(&addr) {
        return Err(format!("ya hay un IED en vivo en {addr}"));
    }
    let app_handle = server.handle();
    let serve = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    let member = first_measurand(&model);
    let vary = tokio::spawn(async move {
        let Some(member) = member else { return };
        let mut t = 0.0f64;
        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            t += 0.25;
            let _ = app_handle
                .set_value(&member, MmsData::Float(100.0 + 10.0 * t.sin()))
                .await;
        }
    });
    guard.insert(
        addr.clone(),
        LiveSim {
            scl: scl_path,
            files: file_root,
            serve,
            vary,
        },
    );
    Ok(addr)
}

/// Lista los IEDs en vivo (dirección + SCL servido).
#[tauri::command]
async fn sim_live_list(state: State<'_, AppState>) -> Result<Vec<LiveSimInfo>, String> {
    let guard = state.sims_live.lock().await;
    let mut v: Vec<LiveSimInfo> = guard
        .iter()
        .map(|(addr, s)| LiveSimInfo {
            addr: addr.clone(),
            scl: s.scl.clone(),
        })
        .collect();
    v.sort_by(|a, b| a.addr.cmp(&b.addr));
    Ok(v)
}

/// Detiene el IED en vivo que escucha en `addr`.
#[tauri::command]
async fn sim_live_stop(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    match state.sims_live.lock().await.remove(&addr) {
        Some(s) => {
            s.serve.abort();
            s.vary.abort();
            let _ = std::fs::remove_dir_all(&s.files);
            Ok(())
        }
        None => Err(format!("no hay IED en vivo en {addr}")),
    }
}

/// Detiene los IED simulados embebidos (plano y TLS).
#[tauri::command]
async fn sim_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(h) = state.sim.lock().await.take() {
        h.serve.abort();
        h.vary.abort();
    }
    if let Some(h) = state.sim_tls.lock().await.take() {
        h.serve.abort();
        h.vary.abort();
    }
    Ok(())
}

// --- Monitores GOOSE / SV (capa 2; requieren CAP_NET_RAW/root) ---

/// Lista las interfaces de captura disponibles: `/sys/class/net` en Linux, los
/// dispositivos Npcap en Windows. Vacía en otros SO (o si falta Npcap).
#[tauri::command]
fn list_interfaces() -> Vec<String> {
    #[cfg(any(target_os = "linux", windows))]
    {
        iec61850::goose::socket::interfaces()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Vec::new()
    }
}

/// Formatea una MAC (`[u8; 6]`) como `aa:bb:cc:dd:ee:ff`.
#[cfg(any(target_os = "linux", windows))]
fn mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Evento GOOSE serializado para el frontend.
#[cfg(any(target_os = "linux", windows))]
#[derive(Serialize, Clone)]
struct GoosePayload {
    gocb_ref: String,
    go_id: String,
    dat_set: String,
    appid: u16,
    src: String,
    st_num: u32,
    sq_num: u32,
    conf_rev: u32,
    test: bool,
    /// Bit "Simulated" de Ed.2 (la trama es simulada/de prueba).
    simulation: bool,
    ttl: u32,
    kind: String,
    /// Nº exacto de tramas perdidas (salto de sqNum), 0 si no hubo pérdida.
    lost: u32,
    values: Vec<String>,
}

/// Nº de tramas perdidas según el tipo de evento (salto de sqNum).
#[cfg(any(target_os = "linux", windows))]
fn goose_lost(k: &GooseEventKind) -> u32 {
    match k {
        GooseEventKind::LossSuspected {
            expected_sq,
            got_sq,
        } => got_sq.saturating_sub(*expected_sq),
        _ => 0,
    }
}

#[cfg(any(target_os = "linux", windows))]
fn goose_kind(k: &GooseEventKind) -> String {
    match k {
        GooseEventKind::StateChange => "stChange".into(),
        GooseEventKind::Retransmission => "retx".into(),
        GooseEventKind::LossSuspected {
            expected_sq,
            got_sq,
        } => {
            format!("loss(esp {expected_sq}, recibido {got_sq})")
        }
        GooseEventKind::Expired => "expirado".into(),
        GooseEventKind::AuthFailed { .. } => "auth-fallida".into(),
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn goose_start(
    app: AppHandle,
    state: State<'_, AppState>,
    iface: String,
    sim_mode: bool,
) -> Result<(), String> {
    let sock = RawSocket::open_promiscuous(&iface, ETHERTYPE_GOOSE)
        .map_err(|e| format!("abrir socket GOOSE en {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let mut sub = GooseSubscriber::new(sock, GooseFilter::default())
        .simulation_mode(sim_mode)
        .start();
    let task = tokio::spawn(async move {
        while let Some(ev) = sub.recv_event().await {
            let _ = app.emit(
                "goose",
                GoosePayload {
                    gocb_ref: ev.gocb_ref,
                    go_id: ev.go_id,
                    dat_set: ev.dat_set,
                    appid: ev.appid,
                    src: mac(&ev.src),
                    st_num: ev.st_num,
                    sq_num: ev.sq_num,
                    conf_rev: ev.conf_rev,
                    test: ev.test,
                    simulation: ev.simulation,
                    ttl: ev.time_allowed_to_live,
                    lost: goose_lost(&ev.kind),
                    kind: goose_kind(&ev.kind),
                    values: ev.values.iter().map(fmt_value).collect(),
                },
            );
        }
    });
    if let Some(old) = state.goose_mon.lock().await.replace(task) {
        old.abort();
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn goose_start(iface: String, sim_mode: bool) -> Result<(), String> {
    let _ = (iface, sim_mode);
    Err(L2_UNSUPPORTED.into())
}

#[tauri::command]
async fn goose_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(t) = state.goose_mon.lock().await.take() {
        t.abort();
    }
    Ok(())
}

/// Un canal del perfil 9-2LE.
#[cfg(any(target_os = "linux", windows))]
#[derive(Serialize, Clone)]
struct SvChan {
    value: i32,
    quality: u32,
}

/// Evento SV serializado para el frontend.
#[cfg(any(target_os = "linux", windows))]
#[derive(Serialize, Clone)]
struct SvPayload {
    sv_id: String,
    appid: u16,
    src: String,
    /// Bit "Simulated" de Ed.2 (la trama es simulada/de prueba).
    simulation: bool,
    smp_cnt: u16,
    conf_rev: u32,
    kind: String,
    /// Nº exacto de muestras perdidas (salto de smpCnt), 0 si no hubo pérdida.
    lost: u32,
    channels: Option<Vec<SvChan>>,
}

/// Nº de muestras perdidas según el tipo de evento (salto de smpCnt).
#[cfg(any(target_os = "linux", windows))]
fn sv_lost(k: &SvEventKind) -> u32 {
    match k {
        SvEventKind::SampleLoss { expected, got } => got.wrapping_sub(*expected) as u32,
        _ => 0,
    }
}

#[cfg(any(target_os = "linux", windows))]
fn sv_kind(k: &SvEventKind) -> String {
    match k {
        SvEventKind::Sample => "sample".into(),
        SvEventKind::SampleLoss { expected, got } => {
            format!("loss(esp {expected}, recibido {got})")
        }
        SvEventKind::Wrap => "wrap".into(),
        SvEventKind::AuthFailed { .. } => "auth-fallida".into(),
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn sv_start(
    app: AppHandle,
    state: State<'_, AppState>,
    iface: String,
    sim_mode: bool,
) -> Result<(), String> {
    let sock = RawSocket::open_promiscuous(&iface, ETHERTYPE_SV)
        .map_err(|e| format!("abrir socket SV en {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let mut sub = SvSubscriber::new(sock, SvFilter::default())
        .simulation_mode(sim_mode)
        .start();
    let task = tokio::spawn(async move {
        while let Some(ev) = sub.recv_sample().await {
            let channels = ev.decoded_9_2le.map(|n| {
                n.channels
                    .iter()
                    .map(|c| SvChan {
                        value: c.value,
                        quality: c.quality,
                    })
                    .collect()
            });
            let _ = app.emit(
                "sv",
                SvPayload {
                    sv_id: ev.sv_id,
                    appid: ev.appid,
                    src: mac(&ev.src),
                    simulation: ev.simulation,
                    smp_cnt: ev.smp_cnt,
                    conf_rev: ev.conf_rev,
                    lost: sv_lost(&ev.kind),
                    kind: sv_kind(&ev.kind),
                    channels,
                },
            );
        }
    });
    if let Some(old) = state.sv_mon.lock().await.replace(task) {
        old.abort();
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn sv_start(iface: String, sim_mode: bool) -> Result<(), String> {
    let _ = (iface, sim_mode);
    Err(L2_UNSUPPORTED.into())
}

#[tauri::command]
async fn sv_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(t) = state.sv_mon.lock().await.take() {
        t.abort();
    }
    Ok(())
}

// --- Publicadores GOOSE / SV de demo (para probar los monitores sin IED real) ---

#[cfg(any(target_os = "linux", windows))]
const DEMO_SRC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Publica GOOSE de demo en `iface` (alterna un booleano cada 2 s).
#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn goose_pub_start(
    state: State<'_, AppState>,
    iface: String,
    simulation: bool,
) -> Result<(), String> {
    let dst: [u8; 6] = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00];
    let sock = RawSocket::open(&iface, ETHERTYPE_GOOSE, dst)
        .map_err(|e| format!("abrir socket GOOSE en {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let mut cfg = GooseConfig::new(dst, DEMO_SRC, 0x0001, "DEMO/LLN0$GO$gcbDemo");
    cfg.dat_set = "DEMO/LLN0$dsDemo".into();
    cfg.go_id = "DEMO_GOOSE".into();
    cfg.simulation = simulation; // bit de simulación Ed.2 (pruebas de esquemas)
    let pubh = GoosePublisher::new(sock, cfg).start();
    let task = tokio::spawn(async move {
        let mut on = false;
        loop {
            on = !on;
            let _ = pubh
                .publish(vec![
                    MmsData::Bool(on),
                    MmsData::Int(if on { 1 } else { 0 }),
                ])
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    if let Some(old) = state.goose_pub.lock().await.replace(task) {
        old.abort();
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn goose_pub_start(iface: String, simulation: bool) -> Result<(), String> {
    let _ = (iface, simulation);
    Err(L2_UNSUPPORTED.into())
}

#[tauri::command]
async fn goose_pub_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(t) = state.goose_pub.lock().await.take() {
        t.abort();
    }
    Ok(())
}

/// Publica SV de demo en `iface` (~20 muestras/s, senoide en el canal IA).
#[cfg(any(target_os = "linux", windows))]
#[tauri::command]
async fn sv_pub_start(
    state: State<'_, AppState>,
    iface: String,
    simulation: bool,
) -> Result<(), String> {
    let dst: [u8; 6] = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00];
    let sock = RawSocket::open(&iface, ETHERTYPE_SV, dst)
        .map_err(|e| format!("abrir socket SV en {iface}: {e} (¿CAP_NET_RAW/root?)"))?;
    let mut cfg = SvConfig::new(dst, DEMO_SRC, 0x4000, "DEMO_SV");
    cfg.dat_set = Some("DEMO/LLN0$dsSv".into());
    cfg.sample_period = Duration::from_millis(50); // 20/s (en vez de 4000/s) para la demo
    cfg.simulation = simulation; // bit de simulación Ed.2
    let pubh = SvPublisher::new(sock, cfg).start();
    let task = tokio::spawn(async move {
        let mut t = 0.0f64;
        loop {
            t += 0.1;
            let mut n = NineTwoLe::default();
            n.channels[0] = SvChannel {
                value: (1000.0 * t.sin()) as i32,
                quality: 0,
            };
            n.channels[3] = SvChannel {
                value: (1000.0 * (t + 2.094).sin()) as i32,
                quality: 0,
            };
            pubh.set_9_2le(&n);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    if let Some(old) = state.sv_pub.lock().await.replace(task) {
        old.abort();
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
#[tauri::command]
async fn sv_pub_start(iface: String, simulation: bool) -> Result<(), String> {
    let _ = (iface, simulation);
    Err(L2_UNSUPPORTED.into())
}

#[tauri::command]
async fn sv_pub_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(t) = state.sv_pub.lock().await.take() {
        t.abort();
    }
    Ok(())
}

// --- Modelo configurado desde SCL (importar .icd/.cid/.scd) ---

/// Nodo del árbol del modelo configurado (LD→LN→DO/SDO→DA).
#[derive(Serialize)]
struct SclNode {
    id: String,
    label: String,
    /// Descripción legible (`desc` en SCL), si la hay.
    desc: Option<String>,
    /// Clase de datos común (sólo en DO).
    cdc: Option<String>,
    /// Restricción funcional (sólo en DA hoja).
    fc: Option<String>,
    /// Tipo básico (sólo en DA hoja).
    ty: Option<String>,
    /// Referencia legible (sólo en DA hoja).
    reference: Option<String>,
    children: Vec<SclNode>,
}

/// Miembro de un dataset resuelto desde el SCL.
#[derive(Serialize)]
struct MemberInfo {
    index: usize,
    reference: String,
    fc: String,
    ty: Option<String>,
}

fn da_node(ld: &str, ln: &str, mut path: Vec<String>, da: &DataAttribute) -> SclNode {
    path.push(da.name.clone());
    let joined = path.join(".");
    let leaf = da.children.is_empty();
    SclNode {
        id: format!("{ld}/{ln}.{joined}"),
        label: da.name.clone(),
        desc: da.desc.clone(),
        cdc: None,
        fc: Some(format!("{}", da.fc)),
        ty: Some(format!("{:?}", da.basic_type)),
        reference: leaf.then(|| format!("{ld}/{ln}.{joined}[{}]", da.fc)),
        children: da
            .children
            .iter()
            .map(|c| da_node(ld, ln, path.clone(), c))
            .collect(),
    }
}

fn do_node(ld: &str, ln: &str, mut path: Vec<String>, dobj: &DataObject) -> SclNode {
    path.push(dobj.name.clone());
    let mut children: Vec<SclNode> = dobj
        .attributes
        .iter()
        .map(|a| da_node(ld, ln, path.clone(), a))
        .collect();
    children.extend(
        dobj.sub_objects
            .iter()
            .map(|s| do_node(ld, ln, path.clone(), s)),
    );
    SclNode {
        id: format!("{ld}/{ln}.{}", path.join(".")),
        label: dobj.name.clone(),
        desc: dobj.desc.clone(),
        cdc: Some(format!("{}", dobj.cdc)),
        fc: None,
        ty: None,
        reference: None,
        children,
    }
}

fn build_scl_tree(model: &Model) -> Vec<SclNode> {
    let mut roots = Vec::new();
    for (ied, server) in &model.ieds {
        for ld in &server.logical_devices {
            let domain = ld
                .ld_name
                .clone()
                .unwrap_or_else(|| format!("{ied}{}", ld.inst));
            let lns: Vec<SclNode> = ld
                .logical_nodes
                .iter()
                .map(|ln| {
                    let name = ln.name();
                    SclNode {
                        id: format!("{domain}/{name}"),
                        label: name.clone(),
                        desc: ln.desc.clone(),
                        cdc: None,
                        fc: None,
                        ty: None,
                        reference: None,
                        children: ln
                            .data_objects
                            .iter()
                            .map(|d| do_node(&domain, &name, Vec::new(), d))
                            .collect(),
                    }
                })
                .collect();
            roots.push(SclNode {
                id: format!("LD:{domain}"),
                label: domain.clone(),
                desc: None,
                cdc: None,
                fc: None,
                ty: None,
                reference: None,
                children: lns,
            });
        }
    }
    roots
}

/// Carga un SCL (ICD/CID/SCD), lo guarda y devuelve el árbol del modelo configurado.
#[tauri::command]
async fn scl_load(state: State<'_, AppState>, path: String) -> Result<Vec<SclNode>, String> {
    let doc = iec61850::scl::parse_scl_file(&path).map_err(|e| e.to_string())?;
    let (model, _diags) = doc.resolve_lenient();
    let tree = build_scl_tree(&model);
    *state.scl_model.lock().await = Some(model);
    Ok(tree)
}

/// Un dataset del SCL cargado (para el navegador de datasets).
#[derive(Serialize)]
struct DsInfo {
    domain: String,
    name: String,
    count: usize,
}

/// Lista los datasets definidos en el SCL cargado.
#[tauri::command]
async fn scl_datasets(state: State<'_, AppState>) -> Result<Vec<DsInfo>, String> {
    let guard = state.scl_model.lock().await;
    let model = guard.as_ref().ok_or("no hay SCL cargado")?;
    let mut out = Vec::new();
    for (ied, server) in &model.ieds {
        for ld in &server.logical_devices {
            let domain = ld
                .ld_name
                .clone()
                .unwrap_or_else(|| format!("{ied}{}", ld.inst));
            for ln in &ld.logical_nodes {
                for ds in &ln.data_sets {
                    out.push(DsInfo {
                        domain: domain.clone(),
                        name: ds.name.clone(),
                        count: ds.entries.len(),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.domain, &a.name).cmp(&(&b.domain, &b.name)));
    Ok(out)
}

/// Resuelve los miembros (ordenados) de un dataset del SCL cargado.
#[tauri::command]
async fn scl_dataset(
    state: State<'_, AppState>,
    domain: String,
    name: String,
) -> Result<Vec<MemberInfo>, String> {
    let guard = state.scl_model.lock().await;
    let model = guard.as_ref().ok_or("no hay SCL cargado")?;
    let members = model
        .resolve_dataset(&domain, &name)
        .ok_or_else(|| format!("dataset {name} no encontrado en {domain}"))?;
    Ok(members
        .iter()
        .enumerate()
        .map(|(i, m)| MemberInfo {
            index: i,
            reference: m.reference.to_string(),
            fc: format!("{}", m.fc),
            ty: m.basic_type.as_ref().map(|b| format!("{b:?}")),
        })
        .collect())
}

/// Punto de entrada (compartido por `main.rs` y, en su caso, móvil).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            connect,
            connect_tls,
            connect_tls_demo,
            disconnect,
            disconnect_id,
            connections,
            set_active,
            save_text,
            capture_pcap,
            file_directory,
            download_file,
            scan_network,
            discover_l2,
            discover,
            read,
            read_do,
            rcb_read,
            rcb_write,
            enable_report,
            disable_report,
            write,
            operate,
            select,
            sim_start,
            sim_start_tls,
            sim_stop,
            sim_live_start,
            sim_live_list,
            sim_live_stop,
            list_interfaces,
            goose_start,
            goose_stop,
            sv_start,
            sv_stop,
            goose_pub_start,
            goose_pub_stop,
            sv_pub_start,
            sv_pub_stop,
            scl_load,
            scl_dataset,
            scl_datasets
        ])
        .run(tauri::generate_context!())
        .expect("error al ejecutar la aplicación Tauri");
}

// --- Helpers de valor (portados de la app egui) ---

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Construye un `MmsData` a partir del tipo y el texto introducidos.
fn parse_value(kind: &str, text: &str) -> Result<MmsData, String> {
    let t = text.trim();
    match kind {
        "Bool" => match t.to_ascii_lowercase().as_str() {
            "true" | "1" | "on" => Ok(MmsData::Bool(true)),
            "false" | "0" | "off" => Ok(MmsData::Bool(false)),
            _ => Err("bool: usa true/false".into()),
        },
        "Int" => t
            .parse::<i64>()
            .map(MmsData::Int)
            .map_err(|e| e.to_string()),
        "Uint" => t
            .parse::<u64>()
            .map(MmsData::Uint)
            .map_err(|e| e.to_string()),
        "Float" => t
            .parse::<f64>()
            .map(MmsData::Float)
            .map_err(|e| e.to_string()),
        "Text" => Ok(MmsData::Visible(text.to_string())),
        other => Err(format!("tipo desconocido: {other}")),
    }
}

/// Decodifica una calidad (Quality, IEC 61850-7-3): validez + flags de detalle.

/// Convierte un `UtcTime` (4 s epoch + 3 fracción) a segundos epoch con fracción.

/// Formatea un `MmsData` para mostrarlo en el frontend.
fn fmt_value(v: &MmsData) -> String {
    match v {
        MmsData::Bool(b) => b.to_string(),
        MmsData::Int(i) => i.to_string(),
        MmsData::Uint(u) => u.to_string(),
        MmsData::Float(f) => format!("{f}"),
        MmsData::Visible(s) | MmsData::MmsString(s) => format!("\"{s}\""),
        MmsData::Octets(o) | MmsData::BinaryTime(o) => format!("0x{}", hex(o)),
        MmsData::BitString(b) => format!("{b:?}"),
        MmsData::Utc(t) => format!("utc:0x{}", hex(&t.raw)),
        MmsData::Structure(items) | MmsData::Array(items) => {
            let inner: Vec<String> = items.iter().map(fmt_value).collect();
            format!("{{{}}}", inner.join(", "))
        }
        _ => "<?>".to_string(),
    }
}
