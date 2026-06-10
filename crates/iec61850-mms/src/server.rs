//! Servidor MMS / IED simulado (IEC 61850-8-1). Sólo con la feature `server`.
//!
//! Carga el namespace desde un [`Model`] (parser SCL), sirve descubrimiento
//! (GetNameList), lectura, escritura, **reporting** (InformationReport por RCB) y
//! **control** (Oper/Select) sobre un almacén de valores compartido. Cada
//! conexión usa un modelo demultiplexor: una tarea por cliente que atiende
//! peticiones y, en paralelo, empuja reportes ante cambios de valor.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_model::{BasicType, FunctionalConstraint, Model, ObjectReference, Value};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Instant, sleep_until};

use crate::ber::prim::BitString;
use crate::ber::reader::Tlv;
use crate::ber::writer::BerWriter;
use crate::error::{DataAccessError, MmsError};
use crate::mapping::object_reference_to_mms;
use crate::mms::data::{MmsData, UtcTime};
use crate::mms::file::{
    self, DirFileProvider, FileAttributes, FileChunk, FileDirectory, FileOpen, FileProvider,
};
use crate::mms::get_name_list::{
    self, GetNameListRequest, GetNameListResponse, ObjectClass, ObjectScope,
};
use crate::mms::identify::{self, IdentifyResponse};
use crate::mms::initiate::{InitiateRequest, InitiateResponse};
use crate::mms::pdu::{self, PduKind};
use crate::mms::read::{self, AccessResult};
use crate::mms::report::{self, ReportData, opt_flds};
use crate::mms::type_attr::{self, TypeSpec, VariableAttributes};
use crate::mms::write::{self, WriteResult};
use crate::transport::connection::{IsoConnection, IsoWriter};
use crate::transport::cotp;
use crate::upper::{acse, presentation, session};

const OUR_SRC_REF: u16 = 0x0002;
/// Máximo de identificadores por página de GetNameList.
pub const MAX_PAGE_ITEMS: usize = 100;

/// Almacén de valores en vivo: `(domainId, itemId) -> MmsData`.
pub type Store = Arc<RwLock<HashMap<(String, String), MmsData>>>;

/// Notificación de cambio de un valor del almacén (alimenta el reporting).
#[derive(Debug, Clone)]
pub struct ValueChange {
    pub domain: String,
    pub item: String,
    pub value: MmsData,
}

/// Atributos comunes de un RCB que se siembran en el namespace/almacén.
const RCB_ATTRS: &[&str] = &[
    "RptID", "RptEna", "DatSet", "ConfRev", "OptFlds", "TrgOps", "IntgPd", "GI", "BufTm",
];
/// Atributos adicionales de un BRCB (bufferado).
const BRCB_ATTRS: &[&str] = &["EntryID", "PurgeBuf"];
/// Capacidad por defecto del buffer de un BRCB (nº de entradas).
const BRCB_CAPACITY: usize = 64;

/// Definición de un Report Control Block extraída del SCL.
#[derive(Debug, Clone)]
struct RcbDef {
    domain: String,
    base: String, // p. ej. "LLN0$RP$rcb1" o "LLN0$BR$brcb1"
    rpt_id: String,
    dataset: Option<String>,
    conf_rev: u32,
    buffered: bool,
}

/// Buffer de un BRCB: cola de entradas con EntryID monótono.
struct BrcbBuffer {
    entries: VecDeque<BufEntry>,
    next_id: u64,
    overflow: bool,
    capacity: usize,
}

impl BrcbBuffer {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            next_id: 1,
            overflow: false,
            capacity: BRCB_CAPACITY,
        }
    }
    fn max_id(&self) -> u64 {
        self.entries.back().map(|e| e.entry_id).unwrap_or(0)
    }
}

/// Una entrada bufferada (un miembro cambiado, con su EntryID).
#[derive(Clone)]
struct BufEntry {
    entry_id: u64,
    member_idx: usize,
    value: MmsData,
}

/// Buffers de todos los BRCB del servidor, indexados por `(domain, base)`.
type Buffers = Arc<Mutex<HashMap<(String, String), BrcbBuffer>>>;
/// Para cada BRCB: su clave `(domain, base)` y los miembros `(domain, item)`.
type BrcbMembers = Vec<((String, String), Vec<(String, String)>)>;

/// `OptFlds` por defecto: sequence-number + data-set-name (10 bits). Para un
/// BRCB se añaden buffer-overflow y entry-id.
fn default_opt_flds(buffered: bool) -> BitString {
    let mut b = [false; 10];
    b[opt_flds::SEQUENCE_NUMBER] = true;
    b[opt_flds::DATA_SET_NAME] = true;
    if buffered {
        b[opt_flds::BUFFER_OVERFLOW] = true;
        b[opt_flds::ENTRY_ID] = true;
    }
    BitString::from_bits(&b)
}

/// Namespace MMS precomputado desde un [`Model`].
pub struct ServerModel {
    domains: Vec<String>,
    items: BTreeMap<String, Vec<String>>,
    datasets: HashMap<(String, String), Vec<(String, String)>>,
    rcbs: Vec<RcbDef>,
    ident: IdentifyResponse,
    page_size: usize,
    file_provider: Option<Arc<dyn FileProvider>>,
}

impl ServerModel {
    /// Construye el namespace (variables, datasets y RCBs) desde el modelo.
    pub fn from_model(model: &Model, ident: IdentifyResponse) -> Self {
        let mut items: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (obj, _da) in model.iter_data_attributes() {
            if let Ok((domain, item)) = object_reference_to_mms(&obj) {
                items.entry(domain).or_default().push(item);
            }
        }

        // Datasets y RCBs por nodo lógico.
        let mut datasets: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
        let mut rcbs: Vec<RcbDef> = Vec::new();
        for (objref, ln) in model.iter_logical_nodes() {
            let domain = objref.ld.clone();
            let ln_name = objref.ln.clone();
            for ds in &ln.data_sets {
                let members: Vec<(String, String)> = ds
                    .entries
                    .iter()
                    .filter_map(|f| fcda_item(f).map(|i| (domain.clone(), i)))
                    .collect();
                datasets.insert((domain.clone(), ds.name.clone()), members);
            }
            for rc in &ln.report_controls {
                let fc = if rc.buffered { "BR" } else { "RP" };
                let base = format!("{ln_name}${fc}${}", rc.name);
                let rpt_id = rc
                    .rpt_id
                    .clone()
                    .unwrap_or_else(|| format!("{domain}/{ln_name}.{}", rc.name));
                // sembrar atributos del RCB en el namespace
                let dom_items = items.entry(domain.clone()).or_default();
                for attr in RCB_ATTRS {
                    dom_items.push(format!("{base}${attr}"));
                }
                if rc.buffered {
                    for attr in BRCB_ATTRS {
                        dom_items.push(format!("{base}${attr}"));
                    }
                }
                rcbs.push(RcbDef {
                    domain: domain.clone(),
                    base,
                    rpt_id,
                    dataset: rc.dataset.clone(),
                    conf_rev: rc.conf_rev.unwrap_or(1),
                    buffered: rc.buffered,
                });
            }
        }

        for v in items.values_mut() {
            v.sort();
            v.dedup();
        }
        let domains: Vec<String> = items.keys().cloned().collect();
        ServerModel {
            domains,
            items,
            datasets,
            rcbs,
            ident,
            page_size: MAX_PAGE_ITEMS,
            file_provider: None,
        }
    }

    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page_size = n.max(1);
        self
    }

    /// Expone los ficheros de un directorio del disco vía los servicios MMS de
    /// transferencia (fileDirectory/Open/Read/Close). Útil para que el IED
    /// simulado sirva registros COMTRADE/oscilografías de prueba.
    pub fn with_file_root(self, root: impl Into<std::path::PathBuf>) -> Self {
        self.with_file_provider(Arc::new(DirFileProvider::new(root)))
    }

    /// Expone ficheros desde un proveedor arbitrario.
    pub fn with_file_provider(mut self, provider: Arc<dyn FileProvider>) -> Self {
        self.file_provider = Some(provider);
        self
    }

    fn file_provider(&self) -> Option<&dyn FileProvider> {
        self.file_provider.as_deref()
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
    pub fn items_of(&self, domain: &str) -> Option<&[String]> {
        self.items.get(domain).map(Vec::as_slice)
    }
    pub fn contains(&self, domain: &str, item: &str) -> bool {
        self.items
            .get(domain)
            .is_some_and(|v| v.binary_search(&item.to_string()).is_ok())
    }
    pub fn ident(&self) -> &IdentifyResponse {
        &self.ident
    }

    fn rcb_def(&self, domain: &str, base: &str) -> Option<&RcbDef> {
        self.rcbs
            .iter()
            .find(|r| r.domain == domain && r.base == base)
    }
    fn dataset_members(&self, domain: &str, name: &str) -> Option<&[(String, String)]> {
        self.datasets
            .get(&(domain.to_string(), name.to_string()))
            .map(Vec::as_slice)
    }

    /// Para cada BRCB: su clave `(domain, base)` y los miembros de su dataset.
    fn buffered_rcb_members(&self) -> BrcbMembers {
        self.rcbs
            .iter()
            .filter(|r| r.buffered)
            .map(|r| {
                let members = r
                    .dataset
                    .as_deref()
                    .and_then(|n| self.dataset_members(&r.domain, n))
                    .map(|m| m.to_vec())
                    .unwrap_or_default();
                ((r.domain.clone(), r.base.clone()), members)
            })
            .collect()
    }

    /// Inicializa el almacén: valores por defecto de datos del SCL + atributos RCB.
    pub fn init_store(&self, model: &Model) -> Store {
        let mut map: HashMap<(String, String), MmsData> = HashMap::new();
        for (obj, da) in model.iter_data_attributes() {
            if let Ok((domain, item)) = object_reference_to_mms(&obj) {
                let value = da
                    .value
                    .as_ref()
                    .and_then(|v| value_to_mms(&da.basic_type, v))
                    .unwrap_or_else(|| default_for(&da.basic_type));
                map.insert((domain, item), value);
            }
        }
        // Sembrar atributos de cada RCB.
        for rcb in &self.rcbs {
            let d = rcb.domain.clone();
            let put = |map: &mut HashMap<(String, String), MmsData>, attr: &str, v: MmsData| {
                map.insert((d.clone(), format!("{}${attr}", rcb.base)), v);
            };
            put(&mut map, "RptID", MmsData::Visible(rcb.rpt_id.clone()));
            put(&mut map, "RptEna", MmsData::Bool(false));
            put(
                &mut map,
                "DatSet",
                MmsData::Visible(rcb.dataset.clone().unwrap_or_default()),
            );
            put(&mut map, "ConfRev", MmsData::Uint(rcb.conf_rev as u64));
            put(
                &mut map,
                "OptFlds",
                MmsData::BitString(default_opt_flds(rcb.buffered)),
            );
            put(
                &mut map,
                "TrgOps",
                MmsData::BitString(BitString::from_bits(&[false, true])),
            ); // dchg
            put(&mut map, "IntgPd", MmsData::Uint(0));
            put(&mut map, "GI", MmsData::Bool(false));
            put(&mut map, "BufTm", MmsData::Uint(0));
            if rcb.buffered {
                put(&mut map, "EntryID", MmsData::Octets(Vec::new()));
                put(&mut map, "PurgeBuf", MmsData::Bool(false));
            }
        }
        Arc::new(RwLock::new(map))
    }
}

/// Construye el itemId de un FCDA (`LN$FC$DO$...$DA`).
fn fcda_item(f: &iec61850_model::Fcda) -> Option<String> {
    let fc: FunctionalConstraint = f.fc?;
    let ln = format!("{}{}{}", f.prefix, f.ln_class, f.ln_inst);
    let mut item = format!("{ln}${}", fc.as_str());
    for seg in f.do_name.split('.') {
        item.push('$');
        item.push_str(seg);
    }
    if !f.da_name.is_empty() {
        item.push('$');
        item.push_str(&f.da_name);
    }
    Some(item)
}

fn value_to_mms(bt: &BasicType, v: &Value) -> Option<MmsData> {
    use BasicType::*;
    Some(match bt {
        Boolean => MmsData::Bool(v.as_bool()?),
        Int8 | Int16 | Int32 | Int64 => MmsData::Int(v.as_i64()?),
        Int8u | Int16u | Int32u => MmsData::Uint(v.as_i64()? as u64),
        Float32 | Float64 => MmsData::Float(v.as_f64()?),
        Enum | Dbpos | Tcmd => v
            .as_i64()
            .map(MmsData::Int)
            .unwrap_or_else(|| MmsData::Visible(v.raw.clone())),
        VisString { .. } | Unicode { .. } | ObjRef => MmsData::Visible(v.raw.clone()),
        _ => return None,
    })
}

fn default_for(bt: &BasicType) -> MmsData {
    use BasicType::*;
    match bt {
        Boolean | Check => MmsData::Bool(false),
        Int8 | Int16 | Int32 | Int64 | Enum | Dbpos | Tcmd => MmsData::Int(0),
        Int8u | Int16u | Int32u => MmsData::Uint(0),
        Float32 | Float64 => MmsData::Float(0.0),
        VisString { .. } | Unicode { .. } | ObjRef => MmsData::Visible(String::new()),
        Quality => MmsData::BitString(BitString::from_bits(&[false; 13])),
        Timestamp | EntryTime => MmsData::Utc(UtcTime { raw: [0; 8] }),
        OctetString { .. } => MmsData::Octets(Vec::new()),
        _ => MmsData::Int(0),
    }
}

/// Muta el almacén y publica el cambio (para disparar reportes).
async fn apply_value(
    store: &Store,
    change_tx: &broadcast::Sender<ValueChange>,
    domain: String,
    item: String,
    value: MmsData,
) {
    store
        .write()
        .await
        .insert((domain.clone(), item.clone()), value.clone());
    let _ = change_tx.send(ValueChange {
        domain,
        item,
        value,
    });
}

/// Handle compartido para que la app inyecte/lea valores en vivo.
#[derive(Clone)]
pub struct ServerHandle {
    store: Store,
    change_tx: broadcast::Sender<ValueChange>,
}

impl ServerHandle {
    pub async fn set_value(&self, obj: &ObjectReference, value: MmsData) -> Result<(), MmsError> {
        let (d, i) = object_reference_to_mms(obj)?;
        apply_value(&self.store, &self.change_tx, d, i, value).await;
        Ok(())
    }
    pub async fn get_value(&self, obj: &ObjectReference) -> Option<MmsData> {
        let (d, i) = object_reference_to_mms(obj).ok()?;
        self.store.read().await.get(&(d, i)).cloned()
    }
    pub async fn set_raw(&self, domain: &str, item: &str, value: MmsData) {
        apply_value(
            &self.store,
            &self.change_tx,
            domain.to_string(),
            item.to_string(),
            value,
        )
        .await;
    }
    pub async fn get_raw(&self, domain: &str, item: &str) -> Option<MmsData> {
        self.store
            .read()
            .await
            .get(&(domain.to_string(), item.to_string()))
            .cloned()
    }
}

/// Servidor MMS escuchando conexiones de clientes.
pub struct MmsServer {
    listener: TcpListener,
    model: Arc<ServerModel>,
    store: Store,
    change_tx: broadcast::Sender<ValueChange>,
    buffers: Buffers,
    buffer_tx: broadcast::Sender<(String, String)>,
    #[cfg(feature = "tls")]
    acceptor: Option<tokio_rustls::TlsAcceptor>,
}

impl MmsServer {
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        model: Arc<ServerModel>,
        store: Store,
    ) -> Result<Self, MmsError> {
        let listener = TcpListener::bind(addr).await?;
        let (change_tx, _) = broadcast::channel(1024);
        let (buffer_tx, _) = broadcast::channel(1024);
        Ok(Self {
            listener,
            model,
            store,
            change_tx,
            buffers: Arc::new(Mutex::new(HashMap::new())),
            buffer_tx,
            #[cfg(feature = "tls")]
            acceptor: None,
        })
    }

    /// Vincula el servidor sirviendo sobre **TLS** (mTLS, IEC 62351-3): cada
    /// conexión completa el handshake TLS antes de hablar MMS. Requiere `tls`.
    #[cfg(feature = "tls")]
    pub async fn bind_tls<A: ToSocketAddrs>(
        addr: A,
        model: Arc<ServerModel>,
        store: Store,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> Result<Self, MmsError> {
        let mut s = Self::bind(addr, model, store).await?;
        s.acceptor = Some(acceptor);
        Ok(s)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            store: self.store.clone(),
            change_tx: self.change_tx.clone(),
        }
    }

    pub async fn serve(self) -> Result<(), MmsError> {
        // Tarea de buffering: alimenta los buffers de los BRCB con cada cambio.
        let brcbs = self.model.buffered_rcb_members();
        if !brcbs.is_empty() {
            tokio::spawn(buffering_task(
                self.change_tx.subscribe(),
                self.buffers.clone(),
                self.buffer_tx.clone(),
                brcbs,
            ));
        }
        loop {
            let (sock, _) = self.listener.accept().await?;
            let model = self.model.clone();
            let store = self.store.clone();
            let change_tx = self.change_tx.clone();
            let buffers = self.buffers.clone();
            let buffer_rx = self.buffer_tx.subscribe();
            #[cfg(feature = "tls")]
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                // Establece el transporte (en claro o TLS) antes del handshake MMS.
                #[cfg(feature = "tls")]
                let conn = match acceptor {
                    Some(acc) => match IsoConnection::from_stream_tls(sock, &acc).await {
                        Ok(c) => c,
                        Err(_) => return, // handshake TLS fallido
                    },
                    None => IsoConnection::from_stream(sock),
                };
                #[cfg(not(feature = "tls"))]
                let conn = IsoConnection::from_stream(sock);

                let _ = handle_connection(conn, model, store, change_tx, buffers, buffer_rx).await;
            });
        }
    }
}

/// Tarea de buffering por servidor: por cada cambio de valor, añade una entrada
/// (con EntryID) a los BRCB cuyo dataset contenga ese miembro, y notifica.
async fn buffering_task(
    mut change_rx: broadcast::Receiver<ValueChange>,
    buffers: Buffers,
    buffer_tx: broadcast::Sender<(String, String)>,
    brcbs: BrcbMembers,
) {
    loop {
        match change_rx.recv().await {
            Ok(change) => {
                let member = (change.domain.clone(), change.item.clone());
                for (key, members) in &brcbs {
                    let Some(idx) = members.iter().position(|m| *m == member) else {
                        continue;
                    };
                    {
                        let mut guard = buffers.lock().unwrap();
                        let buf = guard.entry(key.clone()).or_insert_with(BrcbBuffer::new);
                        let entry_id = buf.next_id;
                        buf.next_id += 1;
                        buf.entries.push_back(BufEntry {
                            entry_id,
                            member_idx: idx,
                            value: change.value.clone(),
                        });
                        while buf.entries.len() > buf.capacity {
                            buf.entries.pop_front();
                            buf.overflow = true;
                        }
                    }
                    let _ = buffer_tx.send(key.clone());
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Estado por RCB habilitado en una conexión.
struct RcbRuntime {
    enabled: bool,
    buffered: bool,
    rpt_id: String,
    dataset_name: Option<String>,
    members: Vec<(String, String)>,
    opt_flds: BitString,
    conf_rev: u32,
    intg_pd: u32,
    seq_num: u32,
    next_integrity: Option<Instant>,
    last_values: HashMap<(String, String), MmsData>,
    /// BRCB: último EntryID enviado por esta conexión.
    cursor: u64,
}

/// Estado de un fichero abierto para lectura (por `frsmID`).
struct FileReadState {
    data: Vec<u8>,
    pos: usize,
}

/// Tamaño de bloque que devuelve cada `fileRead`.
const FILE_READ_CHUNK: usize = 8192;

/// Estado de una conexión: RCBs habilitados, selecciones de control y ficheros
/// abiertos.
#[derive(Default)]
struct ConnState {
    rcbs: HashMap<(String, String), RcbRuntime>, // (domain, base)
    selections: HashMap<(String, String), MmsData>,
    files: HashMap<i32, FileReadState>,
    next_frsm: i32,
}

async fn handle_connection(
    mut conn: IsoConnection,
    model: Arc<ServerModel>,
    store: Store,
    change_tx: broadcast::Sender<ValueChange>,
    buffers: Buffers,
    mut buffer_rx: broadcast::Receiver<(String, String)>,
) -> Result<(), MmsError> {
    // COTP: CR → CC.
    let cr = conn.recv().await?;
    let client_ref = cotp::parse_connection_request(&cr)?;
    conn.send(&cotp::connection_confirm(client_ref, OUR_SRC_REF))
        .await?;

    // Asociación.
    let assoc = conn.recv_data().await?;
    let aarq = presentation::extract_inner_pdu(&assoc)?;
    let req = InitiateRequest::decode(acse::parse_aarq(aarq)?)?;
    let resp = InitiateResponse::accept(&req);
    let accept = session::accept(&presentation::connect_cpa(&acse::aare(&resp.encode())));
    conn.send(&cotp::data_tpdu(&accept)).await?;

    // Separar para poder leer peticiones y empujar reportes a la vez.
    let (mut reader, mut writer) = conn.split();
    let mut change_rx = change_tx.subscribe();
    let mut state = ConnState::default();

    loop {
        let next_int = state.next_integrity_deadline();
        tokio::select! {
            biased;

            r = reader.recv_data() => {
                let payload = match r { Ok(p) => p, Err(_) => break };
                let pdu = presentation::extract_inner_pdu(&payload)?;
                match pdu::peek_request_kind(pdu)? {
                    PduKind::ConfirmedRequest => {
                        let (invoke, service) = pdu::parse_confirmed_request(pdu)?;
                        let (resp, reports) = state
                            .handle_request(invoke, &service, &model, &store, &change_tx, &buffers)
                            .await;
                        send_report(&mut writer, &resp).await?;
                        for rep in reports {
                            send_report(&mut writer, &rep).await?;
                        }
                    }
                    PduKind::ConcludeRequest => {
                        let mut w = BerWriter::new();
                        w.tlv(pdu::mmspdu::CONCLUDE_RESPONSE, |_| {});
                        send_report(&mut writer, &w.into_bytes()).await?;
                        break;
                    }
                    _ => break,
                }
            }

            ch = change_rx.recv() => {
                match ch {
                    Ok(change) => {
                        for rep in state.on_value_change(&change) {
                            send_report(&mut writer, &rep).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            key = buffer_rx.recv() => {
                match key {
                    Ok(key) => {
                        for rep in state.on_buffer(&key, &buffers) {
                            send_report(&mut writer, &rep).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            _ = async { match next_int { Some(t) => sleep_until(t).await, None => std::future::pending().await } } => {
                for rep in state.on_integrity(&store).await {
                    send_report(&mut writer, &rep).await?;
                }
            }
        }
    }
    Ok(())
}

impl ConnState {
    fn next_integrity_deadline(&self) -> Option<Instant> {
        self.rcbs.values().filter_map(|r| r.next_integrity).min()
    }

    /// Atiende una petición confirmada; devuelve la respuesta y, opcionalmente,
    /// reportes a enviar inmediatamente (p. ej. tras una GI).
    async fn handle_request(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
        buffers: &Buffers,
    ) -> (Vec<u8>, Vec<Vec<u8>>) {
        let tag = service.tag;
        let no_reports = Vec::new();
        if tag == pdu::service::IDENTIFY_REQUEST {
            (
                pdu::encode_confirmed_response(invoke, |w| {
                    identify::encode_response(w, model.ident())
                }),
                no_reports,
            )
        } else if tag == pdu::service::GET_NAME_LIST {
            let resp = match get_name_list::decode_request(service) {
                Ok(req) => {
                    let page = build_name_list(model, &req);
                    pdu::encode_confirmed_response(invoke, |w| {
                        get_name_list::encode_response(w, &page)
                    })
                }
                Err(_) => encode_error(invoke),
            };
            (resp, no_reports)
        } else if tag == pdu::service::READ {
            (
                self.handle_read(invoke, service, model, store).await,
                no_reports,
            )
        } else if tag == pdu::service::GET_VARIABLE_ACCESS_ATTRIBUTES {
            (
                handle_get_var_attr(invoke, service, model, store).await,
                no_reports,
            )
        } else if tag == pdu::service::FILE_DIRECTORY {
            (handle_file_directory(invoke, service, model), no_reports)
        } else if tag == pdu::service::FILE_OPEN {
            (self.handle_file_open(invoke, service, model), no_reports)
        } else if tag == pdu::service::FILE_READ {
            (self.handle_file_read(invoke, service), no_reports)
        } else if tag == pdu::service::FILE_CLOSE {
            (self.handle_file_close(invoke, service), no_reports)
        } else if tag == pdu::service::WRITE {
            self.handle_write(invoke, service, model, store, change_tx, buffers)
                .await
        } else {
            (encode_error(invoke), no_reports)
        }
    }

    /// `fileOpen`: lee el fichero del proveedor a memoria y asigna un frsmID.
    fn handle_file_open(&mut self, invoke: u32, service: &Tlv<'_>, model: &ServerModel) -> Vec<u8> {
        let Some(provider) = model.file_provider() else {
            return encode_error(invoke);
        };
        let Ok((name, pos)) = file::decode_open_request(service) else {
            return encode_error(invoke);
        };
        let Ok(data) = provider.read(&name) else {
            return encode_error(invoke);
        };
        let size = data.len() as u32;
        let start = (pos as usize).min(data.len());
        self.next_frsm = self.next_frsm.max(0) + 1;
        let frsm_id = self.next_frsm;
        self.files
            .insert(frsm_id, FileReadState { data, pos: start });
        pdu::encode_confirmed_response(invoke, |w| {
            file::encode_open_response(
                w,
                &FileOpen {
                    frsm_id,
                    attributes: FileAttributes {
                        size,
                        last_modified: None,
                    },
                },
            )
        })
    }

    /// `fileRead`: devuelve el siguiente bloque del fichero abierto.
    fn handle_file_read(&mut self, invoke: u32, service: &Tlv<'_>) -> Vec<u8> {
        let Ok(frsm) = file::decode_read_request(service) else {
            return encode_error(invoke);
        };
        let Some(st) = self.files.get_mut(&frsm) else {
            return encode_error(invoke);
        };
        let end = (st.pos + FILE_READ_CHUNK).min(st.data.len());
        let data = st.data[st.pos..end].to_vec();
        st.pos = end;
        let more_follows = st.pos < st.data.len();
        pdu::encode_confirmed_response(invoke, |w| {
            file::encode_read_response(w, &FileChunk { data, more_follows })
        })
    }

    /// `fileClose`: libera el frsmID.
    fn handle_file_close(&mut self, invoke: u32, service: &Tlv<'_>) -> Vec<u8> {
        let Ok(frsm) = file::decode_close_request(service) else {
            return encode_error(invoke);
        };
        self.files.remove(&frsm);
        pdu::encode_confirmed_response(invoke, file::encode_close_response)
    }

    async fn handle_read(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
        store: &Store,
    ) -> Vec<u8> {
        let Ok(vars) = read::decode_request(service) else {
            return encode_error(invoke);
        };
        let guard = store.read().await;
        let results: Vec<AccessResult> = vars
            .iter()
            .map(|(d, i)| {
                // Select-before-operate: leer $SBO concede el control.
                if let Some(base) = i.strip_suffix("$SBO") {
                    self.selections
                        .insert((d.clone(), base.to_string()), MmsData::Visible(i.clone()));
                    return AccessResult::Success(MmsData::Visible(i.clone()));
                }
                if !model.contains(d, i) {
                    AccessResult::Failure(DataAccessError::ObjectNonExistent)
                } else {
                    match guard.get(&(d.clone(), i.clone())) {
                        Some(v) => AccessResult::Success(v.clone()),
                        None => AccessResult::Failure(DataAccessError::TemporarilyUnavailable),
                    }
                }
            })
            .collect();
        pdu::encode_confirmed_response(invoke, |w| read::encode_response(w, &results))
    }

    async fn handle_write(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
        buffers: &Buffers,
    ) -> (Vec<u8>, Vec<Vec<u8>>) {
        let Ok((vars, data)) = write::decode_request(service) else {
            return (encode_error(invoke), Vec::new());
        };
        let mut results = Vec::with_capacity(vars.len());
        let mut reports = Vec::new();

        for (k, (domain, item)) in vars.iter().enumerate() {
            let Some(value) = data.get(k).cloned() else {
                results.push(WriteResult::Failure(
                    DataAccessError::ObjectAttributeInconsistent,
                ));
                continue;
            };

            let result = if let Some(base) = item.strip_suffix("$RptEna") {
                let r = self
                    .set_rpt_ena(domain, base, &value, model, store, change_tx, buffers)
                    .await;
                // Al habilitar un BRCB, reenvía lo bufferado posterior al cursor.
                if matches!(value, MmsData::Bool(true)) {
                    let key = (domain.clone(), base.to_string());
                    reports.extend(self.drain_buffer(&key, buffers));
                }
                r
            } else if let Some(base) = item.strip_suffix("$GI") {
                if let Some(rep) = self
                    .general_interrogation(domain, base, &value, store)
                    .await
                {
                    reports.push(rep);
                }
                store_write(store, change_tx, domain, item, value).await
            } else if let Some(base) = item.strip_suffix("$EntryID") {
                // Resync: fija el cursor y reenvía lo posterior si está habilitado.
                reports.extend(self.set_entry_id(domain, base, &value, buffers));
                store_write(store, change_tx, domain, item, value).await
            } else if let Some(base) = item.strip_suffix("$PurgeBuf") {
                if matches!(value, MmsData::Bool(true)) {
                    self.purge_buf(domain, base, buffers);
                }
                store_write(store, change_tx, domain, item, value).await
            } else if item.contains("$CO$") && item.ends_with("$Oper") {
                let (r, term) = self
                    .operate(domain, item, &value, model, store, change_tx)
                    .await;
                if let Some(t) = term {
                    reports.push(t);
                }
                r
            } else if item.contains("$CO$") && item.ends_with("$Cancel") {
                if let Some(base) = item.strip_suffix("$Cancel") {
                    self.selections.remove(&(domain.clone(), base.to_string()));
                }
                WriteResult::Success
            } else if let Some(base) = item.strip_suffix("$SBOw") {
                self.selections
                    .insert((domain.clone(), base.to_string()), value);
                WriteResult::Success
            } else if model.contains(domain, item) {
                store_write(store, change_tx, domain, item, value).await
            } else {
                WriteResult::Failure(DataAccessError::ObjectNonExistent)
            };
            results.push(result);
        }
        (
            pdu::encode_confirmed_response(invoke, |w| write::encode_response(w, &results)),
            reports,
        )
    }

    /// Habilita/deshabilita un RCB al escribir `RptEna`.
    #[allow(clippy::too_many_arguments)]
    async fn set_rpt_ena(
        &mut self,
        domain: &str,
        base: &str,
        value: &MmsData,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
        buffers: &Buffers,
    ) -> WriteResult {
        let Some(rcbdef) = model.rcb_def(domain, base) else {
            return WriteResult::Failure(DataAccessError::ObjectNonExistent);
        };
        let buffered = rcbdef.buffered;
        let enable = matches!(value, MmsData::Bool(true));
        // refleja RptEna en el almacén
        store_write(
            store,
            change_tx,
            domain,
            &format!("{base}$RptEna"),
            value.clone(),
        )
        .await;

        let key = (domain.to_string(), base.to_string());
        if !enable {
            self.rcbs.remove(&key);
            return WriteResult::Success;
        }

        let guard = store.read().await;
        let get = |attr: &str| guard.get(&(domain.to_string(), format!("{base}${attr}")));
        let dataset_name = match get("DatSet") {
            Some(MmsData::Visible(s)) if !s.is_empty() => Some(s.clone()),
            _ => rcbdef.dataset.clone(),
        };
        let opt_flds = match get("OptFlds") {
            Some(MmsData::BitString(b)) => b.clone(),
            _ => default_opt_flds(buffered),
        };
        let intg_pd = match get("IntgPd") {
            Some(MmsData::Uint(u)) => *u as u32,
            _ => 0,
        };
        // BRCB: cursor de resync desde EntryID (o desde el final del buffer).
        let resume = get("EntryID").map(decode_entry_id).unwrap_or(0);
        let members: Vec<(String, String)> = dataset_name
            .as_deref()
            .and_then(|n| model.dataset_members(domain, n))
            .map(|m| m.to_vec())
            .unwrap_or_default();
        let last_values = members
            .iter()
            .map(|m| {
                (
                    m.clone(),
                    guard.get(m).cloned().unwrap_or(MmsData::Bool(false)),
                )
            })
            .collect();
        drop(guard);

        let cursor = if !buffered {
            0
        } else if resume > 0 {
            resume
        } else {
            // sólo eventos nuevos: arranca en el final actual del buffer.
            buffers
                .lock()
                .unwrap()
                .get(&key)
                .map(|b| b.max_id())
                .unwrap_or(0)
        };

        let next_integrity = (!buffered && intg_pd > 0)
            .then(|| Instant::now() + Duration::from_millis(intg_pd as u64));
        self.rcbs.insert(
            key,
            RcbRuntime {
                enabled: true,
                buffered,
                rpt_id: rcbdef.rpt_id.clone(),
                dataset_name,
                members,
                opt_flds,
                conf_rev: rcbdef.conf_rev,
                intg_pd,
                seq_num: 0,
                next_integrity,
                last_values,
                cursor,
            },
        );
        WriteResult::Success
    }

    /// Resync por EntryID: ajusta el cursor del BRCB; el replay lo hace el
    /// llamador con [`Self::drain_buffer`].
    fn set_entry_id(
        &mut self,
        domain: &str,
        base: &str,
        value: &MmsData,
        buffers: &Buffers,
    ) -> Vec<Vec<u8>> {
        let key = (domain.to_string(), base.to_string());
        let Some(rcb) = self.rcbs.get_mut(&key) else {
            return Vec::new();
        };
        if !rcb.enabled || !rcb.buffered {
            return Vec::new();
        }
        rcb.cursor = decode_entry_id(value);
        self.drain_buffer(&key, buffers)
    }

    /// Vacía el buffer de un BRCB (PurgeBuf) y reinicia su cursor.
    fn purge_buf(&mut self, domain: &str, base: &str, buffers: &Buffers) {
        let key = (domain.to_string(), base.to_string());
        if let Some(buf) = buffers.lock().unwrap().get_mut(&key) {
            buf.entries.clear();
            buf.overflow = false;
        }
        if let Some(rcb) = self.rcbs.get_mut(&key) {
            rcb.cursor = 0;
        }
    }

    /// Drena del buffer compartido las entradas con `entry_id > cursor` del BRCB
    /// `key` (si esta conexión lo tiene habilitado) y produce un reporte por cada.
    fn drain_buffer(&mut self, key: &(String, String), buffers: &Buffers) -> Vec<Vec<u8>> {
        let Some(rcb) = self.rcbs.get_mut(key) else {
            return Vec::new();
        };
        if !rcb.enabled || !rcb.buffered {
            return Vec::new();
        }
        let mut guard = buffers.lock().unwrap();
        let Some(buf) = guard.get_mut(key) else {
            return Vec::new();
        };
        let pending: Vec<BufEntry> = buf
            .entries
            .iter()
            .filter(|e| e.entry_id > rcb.cursor)
            .cloned()
            .collect();
        let overflow = buf.overflow;
        if !pending.is_empty() {
            buf.overflow = false;
        }
        drop(guard);

        let mut out = Vec::with_capacity(pending.len());
        for e in pending {
            rcb.seq_num += 1;
            rcb.cursor = e.entry_id;
            let inclusion = single_included(rcb.members.len(), e.member_idx);
            let entry_id = e.entry_id.to_be_bytes();
            out.push(make_buffered_report(
                rcb,
                &inclusion,
                &[e.value],
                overflow,
                &entry_id,
            ));
        }
        out
    }

    /// Reportes a emitir cuando crece el buffer de un BRCB.
    fn on_buffer(&mut self, key: &(String, String), buffers: &Buffers) -> Vec<Vec<u8>> {
        self.drain_buffer(key, buffers)
    }

    /// Emite un reporte de interrogación general (todos los miembros) si el RCB
    /// está habilitado y `GI=true`.
    async fn general_interrogation(
        &mut self,
        domain: &str,
        base: &str,
        value: &MmsData,
        store: &Store,
    ) -> Option<Vec<u8>> {
        if !matches!(value, MmsData::Bool(true)) {
            return None;
        }
        let rcb = self.rcbs.get_mut(&(domain.to_string(), base.to_string()))?;
        if !rcb.enabled {
            return None;
        }
        let guard = store.read().await;
        let values: Vec<MmsData> = rcb
            .members
            .iter()
            .map(|m| guard.get(m).cloned().unwrap_or(MmsData::Bool(false)))
            .collect();
        drop(guard);
        rcb.seq_num += 1;
        Some(make_report(rcb, &all_included(rcb.members.len()), &values))
    }

    /// Ejecuta un control directo: aplica `ctlVal` al estado `stVal`.
    /// Ejecuta un `Oper`. Devuelve la respuesta Write y, en seguridad reforzada,
    /// la CommandTermination a enviar tras ella.
    async fn operate(
        &mut self,
        domain: &str,
        oper_item: &str,
        value: &MmsData,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
    ) -> (WriteResult, Option<Vec<u8>>) {
        // Oper es una estructura { ctlVal, origin, ctlNum, T, Test, Check }.
        let (ctl_val, interlock_check) = match value {
            MmsData::Structure(fields) if !fields.is_empty() => {
                let chk = fields.get(5).and_then(|f| match f {
                    MmsData::BitString(b) => Some(b.bit(0)), // interlock-check
                    _ => None,
                });
                (fields[0].clone(), chk.unwrap_or(false))
            }
            other => (other.clone(), false),
        };
        // Mapeo heurístico CO→ST: "LN$CO$<do>$Oper" → "LN$ST$<do>$stVal".
        let status_item = oper_item
            .replacen("$CO$", "$ST$", 1)
            .replace("$Oper", "$stVal");
        if !model.contains(domain, &status_item) {
            return (
                WriteResult::Failure(DataAccessError::ObjectNonExistent),
                None,
            );
        }

        // Modelo de control (ctlModel en CF): 3 = direct-enhanced, 4 = sbo-enhanced.
        let parts: Vec<&str> = oper_item.split('$').collect();
        let (ln, doi) = (parts[0], parts.get(2).copied().unwrap_or(""));
        let cf = |attr: &str| format!("{ln}$CF${doi}${attr}");
        let co_base = oper_item.trim_end_matches("$Oper").to_string();
        let model_kind = {
            let g = store.read().await;
            match g.get(&(domain.to_string(), cf("ctlModel"))) {
                Some(MmsData::Int(n)) => *n,
                Some(MmsData::Uint(n)) => *n as i64,
                _ => 0,
            }
        };
        let enhanced = model_kind == 3 || model_kind == 4;
        let sbo = model_kind == 2 || model_kind == 4;

        // SBO: exige selección previa.
        if sbo
            && !self
                .selections
                .contains_key(&(domain.to_string(), co_base.clone()))
        {
            return (
                WriteResult::Failure(DataAccessError::ObjectAccessDenied),
                None,
            );
        }
        // El comando consume la selección (one-shot).
        self.selections.remove(&(domain.to_string(), co_base));

        if !enhanced {
            apply_value(store, change_tx, domain.to_string(), status_item, ctl_val).await;
            return (WriteResult::Success, None);
        }

        // Enhanced: responder Write+ y enviar CommandTermination (positiva/negativa).
        let blocked = interlock_check && {
            let g = store.read().await;
            matches!(
                g.get(&(domain.to_string(), cf("intlckBlk"))),
                Some(MmsData::Bool(true))
            )
        };
        if blocked {
            // AddCause 1 = blocked-by-interlocking. No cambia el estado.
            let term = report::encode_command_termination(domain, oper_item, value, false, 1);
            return (WriteResult::Success, Some(term));
        }
        apply_value(store, change_tx, domain.to_string(), status_item, ctl_val).await;
        let term = report::encode_command_termination(domain, oper_item, value, true, 0);
        (WriteResult::Success, Some(term))
    }

    /// Reportes a emitir ante un cambio de valor (disparo por dchg).
    fn on_value_change(&mut self, change: &ValueChange) -> Vec<Vec<u8>> {
        let member = (change.domain.clone(), change.item.clone());
        let mut out = Vec::new();
        for rcb in self.rcbs.values_mut() {
            if !rcb.enabled || rcb.buffered {
                continue; // los BRCB se sirven por el buffer
            }
            if let Some(idx) = rcb.members.iter().position(|m| *m == member) {
                if rcb.last_values.get(&member) != Some(&change.value) {
                    rcb.last_values.insert(member.clone(), change.value.clone());
                    rcb.seq_num += 1;
                    let inclusion = single_included(rcb.members.len(), idx);
                    out.push(make_report(
                        rcb,
                        &inclusion,
                        std::slice::from_ref(&change.value),
                    ));
                }
            }
        }
        out
    }

    /// Reportes de integridad periódica vencidos.
    async fn on_integrity(&mut self, store: &Store) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        let guard = store.read().await;
        for rcb in self.rcbs.values_mut() {
            let Some(deadline) = rcb.next_integrity else {
                continue;
            };
            if deadline > now {
                continue;
            }
            let values: Vec<MmsData> = rcb
                .members
                .iter()
                .map(|m| guard.get(m).cloned().unwrap_or(MmsData::Bool(false)))
                .collect();
            rcb.seq_num += 1;
            out.push(make_report(rcb, &all_included(rcb.members.len()), &values));
            rcb.next_integrity = Some(now + Duration::from_millis(rcb.intg_pd as u64));
        }
        out
    }
}

fn all_included(n: usize) -> BitString {
    BitString::from_bits(&vec![true; n])
}
fn single_included(n: usize, idx: usize) -> BitString {
    let bits: Vec<bool> = (0..n).map(|i| i == idx).collect();
    BitString::from_bits(&bits)
}

fn make_report(rcb: &RcbRuntime, inclusion: &BitString, values: &[MmsData]) -> Vec<u8> {
    report::encode_information_report(&ReportData {
        rpt_id: &rcb.rpt_id,
        opt_flds: &rcb.opt_flds,
        seq_num: rcb.seq_num,
        dataset: rcb.dataset_name.as_deref(),
        conf_rev: rcb.conf_rev,
        time_of_entry: None,
        buf_ovfl: false,
        entry_id: None,
        inclusion,
        values,
        reasons: None,
    })
}

/// Reporte de un BRCB: incluye EntryID y el indicador de desbordamiento.
fn make_buffered_report(
    rcb: &RcbRuntime,
    inclusion: &BitString,
    values: &[MmsData],
    buf_ovfl: bool,
    entry_id: &[u8],
) -> Vec<u8> {
    report::encode_information_report(&ReportData {
        rpt_id: &rcb.rpt_id,
        opt_flds: &rcb.opt_flds,
        seq_num: rcb.seq_num,
        dataset: rcb.dataset_name.as_deref(),
        conf_rev: rcb.conf_rev,
        time_of_entry: None,
        buf_ovfl,
        entry_id: Some(entry_id),
        inclusion,
        values,
        reasons: None,
    })
}

/// Decodifica un EntryID (octetos big-endian) a `u64`. Vacío/otro → 0.
fn decode_entry_id(v: &MmsData) -> u64 {
    match v {
        MmsData::Octets(o) if !o.is_empty() => {
            let mut buf = [0u8; 8];
            let n = o.len().min(8);
            buf[8 - n..].copy_from_slice(&o[o.len() - n..]);
            u64::from_be_bytes(buf)
        }
        _ => 0,
    }
}

/// Escribe en el almacén y notifica (write genérico de cliente y control).
async fn store_write(
    store: &Store,
    change_tx: &broadcast::Sender<ValueChange>,
    domain: &str,
    item: &str,
    value: MmsData,
) -> WriteResult {
    apply_value(
        store,
        change_tx,
        domain.to_string(),
        item.to_string(),
        value,
    )
    .await;
    WriteResult::Success
}

fn encode_error(invoke: u32) -> Vec<u8> {
    pdu::encode_confirmed_error(invoke, |w| {
        w.integer(crate::ber::tag::Tag::context(0, false), 0);
    })
}

/// Responde `fileDirectory`: lista el proveedor de ficheros del servidor.
fn handle_file_directory(invoke: u32, service: &Tlv<'_>, model: &ServerModel) -> Vec<u8> {
    let Some(provider) = model.file_provider() else {
        return encode_error(invoke);
    };
    let Ok((prefix, _continue_after)) = file::decode_directory_request(service) else {
        return encode_error(invoke);
    };
    match provider.list(prefix.as_deref()) {
        Ok(entries) => pdu::encode_confirmed_response(invoke, |w| {
            file::encode_directory_response(
                w,
                &FileDirectory {
                    entries,
                    more_follows: false,
                },
            )
        }),
        Err(_) => encode_error(invoke),
    }
}

/// Responde `GetVariableAccessAttributes`: sintetiza el `TypeSpec` desde el valor
/// almacenado del item (el modelo simulado no conserva la tabla de tipos del SCL,
/// pero el valor en vivo basta para revelar la forma: escalar/estructura/array).
async fn handle_get_var_attr(
    invoke: u32,
    service: &Tlv<'_>,
    model: &ServerModel,
    store: &Store,
) -> Vec<u8> {
    let Ok((domain, item)) = type_attr::decode_request(service) else {
        return encode_error(invoke);
    };
    if !model.contains(&domain, &item) {
        return encode_error(invoke);
    }
    let guard = store.read().await;
    let Some(value) = guard.get(&(domain, item)) else {
        return encode_error(invoke);
    };
    let attrs = VariableAttributes {
        mms_deletable: false,
        type_spec: TypeSpec::from_mms_data(value),
    };
    pdu::encode_confirmed_response(invoke, |w| type_attr::encode_response(w, &attrs))
}

fn build_name_list(model: &ServerModel, req: &GetNameListRequest) -> GetNameListResponse {
    let source: &[String] = match (req.class, &req.scope) {
        (ObjectClass::Domain, ObjectScope::VmdSpecific) => model.domains(),
        (ObjectClass::NamedVariable, ObjectScope::DomainSpecific(d)) => {
            model.items_of(d).unwrap_or(&[])
        }
        _ => &[],
    };
    let start = match &req.continue_after {
        Some(ca) => source.partition_point(|x| x.as_str() <= ca.as_str()),
        None => 0,
    };
    let end = (start + model.page_size).min(source.len());
    GetNameListResponse {
        identifiers: source[start..end].to_vec(),
        more_follows: end < source.len(),
    }
}

async fn send_report(writer: &mut IsoWriter, pdu: &[u8]) -> Result<(), MmsError> {
    let ud = presentation::user_data(pdu, presentation::MMS_CONTEXT_ID);
    writer.send(&cotp::data_tpdu(&session::data(&ud))).await
}
