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

use iec61850_model::{BasicType, Model, ObjectReference, Value};
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
use crate::mms::journal::{self, JournalEntry};
use crate::mms::named_var_list;
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

/// Límites de robustez del servidor frente a clientes hostiles o defectuosos.
/// Configurables con [`MmsServer::with_limits`]; los valores por defecto son
/// conservadores para un IED de subestación.
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits {
    /// Conexiones simultáneas aceptadas. Las que exceden esperan a que se libere
    /// un hueco (evita agotar memoria/descriptores por avalancha de conexiones).
    pub max_connections: usize,
    /// Tiempo máximo para completar el handshake COTP+ACSE. Corta clientes que
    /// abren el socket y no progresan (slow-loris).
    pub handshake_timeout: Duration,
    /// Inactividad máxima de una sesión ya asociada antes de cerrarla.
    pub idle_timeout: Duration,
    /// Nº de eventos de reporting perdidos (`Lagged`) consecutivos que una
    /// conexión puede acumular antes de cerrarse: un cliente que no drena sus
    /// reportes no debe forzar al servidor a retenerlos indefinidamente.
    pub max_report_lag: u64,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            max_report_lag: 256,
        }
    }
}

/// Rol de acceso de un cliente autenticado (IEC 62351-8, simplificado). Determina
/// qué operaciones puede realizar tras asociarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Solo lectura y descubrimiento (no escribe ni controla).
    Viewer,
    /// Lectura + control (Oper/Select) y reporting; no cambia configuración.
    Operator,
    /// Acceso completo: además escribe configuración (CF/SP/SE), settings. Es el
    /// rol por defecto cuando no hay política de autenticación (`AuthPolicy::None`).
    #[default]
    Engineer,
    /// Rol **personalizado** con un conjunto de permisos arbitrario (IEC 62351-8
    /// permite roles definidos por el usuario más allá de los estándar).
    Custom(Permissions),
}

/// Conjunto de permisos de una asociación (IEC 62351-8, simplificado). Se modela
/// como bitflags sin dependencias externas; cada [`Role`] mapea a un conjunto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u16);

impl Permissions {
    /// Leer objetos de datos (Read / ReadDataSetValues).
    pub const DATA_READ: Self = Self(1 << 0);
    /// Escribir valores de proceso (ST/MX/SV...).
    pub const DATA_WRITE: Self = Self(1 << 1);
    /// Controlar (Oper/Select/Cancel, FC=CO).
    pub const CONTROL: Self = Self(1 << 2);
    /// Operar RCBs / reporting (habilitar, GI; FC=RP/BR).
    pub const REPORTING: Self = Self(1 << 3);
    /// Definir/borrar datasets dinámicos (Define/DeleteNamedVariableList).
    pub const DATASET_DEFINE: Self = Self(1 << 4);
    /// Escribir configuración (FC=CF).
    pub const CONFIG: Self = Self(1 << 5);
    /// Manejar grupos de ajuste (FC=SG/SE/SP-SGCB) y **leer** el buffer de
    /// edición (FC=SE), que es parte del flujo de ingeniería.
    pub const SETTING: Self = Self(1 << 6);
    /// Leer ficheros del servidor (fileOpen/Read, p. ej. oscilografías).
    pub const FILE_READ: Self = Self(1 << 7);
    /// Modificar el filestore del servidor: subir (obtainFile/SetFile), borrar
    /// (fileDelete) o renombrar (fileRename) ficheros.
    pub const FILE_WRITE: Self = Self(1 << 8);

    /// Conjunto vacío (ningún permiso), para construir roles personalizados.
    pub const NONE: Self = Self(0);

    /// ¿Contiene todos los permisos de `other`?
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Bits en crudo del conjunto (para serializarlo, p. ej. en un token 62351-8).
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Reconstruye un conjunto de permisos desde sus bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
}

impl std::ops::BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl Role {
    /// Conjunto de permisos del rol (IEC 62351-8).
    pub fn permissions(self) -> Permissions {
        use Permissions as P;
        match self {
            // Observador: lee datos y ficheros; no modifica nada.
            Role::Viewer => P::DATA_READ | P::FILE_READ,
            // Operador: además controla, opera reporting y define datasets de
            // monitoreo; no toca configuración ni settings.
            Role::Operator => {
                P::DATA_READ | P::CONTROL | P::REPORTING | P::DATASET_DEFINE | P::FILE_READ
            }
            // Ingeniero: acceso completo.
            Role::Engineer => {
                P::DATA_READ
                    | P::DATA_WRITE
                    | P::CONTROL
                    | P::REPORTING
                    | P::DATASET_DEFINE
                    | P::CONFIG
                    | P::SETTING
                    | P::FILE_READ
                    | P::FILE_WRITE
            }
            // Personalizado: el conjunto que porta.
            Role::Custom(p) => p,
        }
    }

    /// Rol a partir de un conjunto de permisos: si coincide con uno de los
    /// estándar devuelve su nombre; en otro caso, un [`Role::Custom`]. Sirve para
    /// reconstruir el rol de un token, que transporta el conjunto de permisos.
    pub fn from_permissions(perms: Permissions) -> Role {
        if perms == Role::Viewer.permissions() {
            Role::Viewer
        } else if perms == Role::Operator.permissions() {
            Role::Operator
        } else if perms == Role::Engineer.permissions() {
            Role::Engineer
        } else {
            Role::Custom(perms)
        }
    }

    /// Permiso exigido para **escribir** un `itemId`, según su FC.
    fn write_permission(item: &str) -> Permissions {
        if item.contains("$CO$") {
            Permissions::CONTROL
        } else if item.contains("$RP$") || item.contains("$BR$") {
            Permissions::REPORTING
        } else if is_setting_item(item) {
            Permissions::SETTING
        } else if item.contains("$CF$") {
            Permissions::CONFIG
        } else {
            Permissions::DATA_WRITE
        }
    }

    /// ¿Puede escribir la variable con este `itemId`?
    fn may_write(self, item: &str) -> bool {
        self.permissions().contains(Self::write_permission(item))
    }

    /// ¿Puede **leer** la variable con este `itemId`? El buffer de edición de
    /// settings (FC=SE) exige el permiso `SETTING`; el resto, `DATA_READ`.
    fn may_read(self, item: &str) -> bool {
        let p = self.permissions();
        if item.split('$').nth(1) == Some("SE") {
            p.contains(Permissions::SETTING)
        } else {
            p.contains(Permissions::DATA_READ)
        }
    }

    /// ¿Puede definir/borrar datasets dinámicos?
    fn may_define_dataset(self) -> bool {
        self.permissions().contains(Permissions::DATASET_DEFINE)
    }

    /// ¿Puede leer ficheros del servidor?
    fn may_read_files(self) -> bool {
        self.permissions().contains(Permissions::FILE_READ)
    }

    /// ¿Puede modificar el filestore (subir/borrar/renombrar ficheros)?
    fn may_write_files(self) -> bool {
        self.permissions().contains(Permissions::FILE_WRITE)
    }
}

/// ¿El `itemId` es un ajuste (FC=SG/SE) o control del SGCB (FC=SP `$SGCB`)?
fn is_setting_item(item: &str) -> bool {
    matches!(item.split('$').nth(1), Some("SG") | Some("SE")) || item.contains("$SP$SGCB")
}

/// Política de autenticación del servidor (IEC 62351-4). Por defecto, ninguna.
#[derive(Debug, Clone, Default)]
pub enum AuthPolicy {
    /// Sin autenticación: se aceptan todas las asociaciones como `Engineer`.
    #[default]
    None,
    /// Requiere un password ACSE; cada password mapea a un rol. Una asociación
    /// sin password válido se rechaza.
    Passwords(Vec<(String, Role)>),
    /// Requiere un **certificado de cliente** (mTLS): el CommonName del subject
    /// mapea a un rol. Una asociación sin certificado o con un CN desconocido se
    /// rechaza. Recomendado sobre el password (no viaja secreto por el canal).
    Certificates(Vec<(String, Role)>),
    /// Requiere un **access token firmado** (RBAC, IEC 62351-8): el cliente
    /// presenta en el `authentication-value` un token emitido por una autoridad;
    /// el servidor lo verifica con la clave de esa autoridad y toma el rol que
    /// declara. No necesita un mapeo estático de credenciales.
    #[cfg(feature = "tokens")]
    Token(iec61850_l2::Verifier),
}

impl AuthPolicy {
    /// Decide el rol de una asociación dadas las credenciales presentadas.
    /// `password` = authentication-value del AARQ; `cert_cn` = CommonName del
    /// certificado de cliente mTLS (si lo hubo). `None` ⇒ rechazar la asociación.
    fn authorize(&self, password: Option<&[u8]>, cert_cn: Option<&str>) -> Option<Role> {
        match self {
            AuthPolicy::None => Some(Role::Engineer),
            AuthPolicy::Passwords(list) => {
                let pw = password?;
                list.iter()
                    .find(|(p, _)| p.as_bytes() == pw)
                    .map(|(_, role)| *role)
            }
            AuthPolicy::Certificates(list) => {
                let cn = cert_cn?;
                list.iter().find(|(c, _)| c == cn).map(|(_, role)| *role)
            }
            #[cfg(feature = "tokens")]
            AuthPolicy::Token(authority) => {
                let token_bytes = password?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                crate::mms::token::verify(token_bytes, authority, now)
                    .ok()
                    .map(|t| t.role)
            }
        }
    }
}

/// Almacén de valores en vivo: `(domainId, itemId) -> MmsData`.
pub type Store = Arc<RwLock<HashMap<(String, String), MmsData>>>;

/// Notificación de cambio de un valor del almacén (alimenta el reporting).
#[derive(Debug, Clone)]
pub struct ValueChange {
    pub domain: String,
    pub item: String,
    pub value: MmsData,
}

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

impl RcbDef {
    /// Referencia completa del dataset del RCB (`"IED1LD0/LLN0$ds1"`, la forma
    /// de IEC 61850-8-1). El SCL da el nombre corto; se cualifica con el LN del
    /// propio RCB. Si ya viene cualificado, se respeta.
    fn dataset_ref(&self) -> Option<String> {
        let ds = self.dataset.as_deref()?;
        if ds.contains('/') || ds.contains('$') {
            return Some(ds.to_string());
        }
        let ln = self.base.split('$').next().unwrap_or_default();
        Some(format!("{}/{ln}${ds}", self.domain))
    }

    /// Componentes del RCB en el **orden exacto de IEC 61850-8-1** (verificado
    /// contra libiec61850): `(nombreAtributo, valorPorDefecto)`. El orden importa
    /// porque un cliente que lee el RCB como estructura asigna por posición.
    /// URCB: 11 componentes; BRCB: 14.
    fn components(&self) -> Vec<(&'static str, MmsData)> {
        let mut c: Vec<(&'static str, MmsData)> = vec![
            ("RptID", MmsData::Visible(self.rpt_id.clone())),
            ("RptEna", MmsData::Bool(false)),
        ];
        if !self.buffered {
            c.push(("Resv", MmsData::Bool(false)));
        }
        c.extend([
            (
                "DatSet",
                MmsData::Visible(self.dataset_ref().unwrap_or_default()),
            ),
            ("ConfRev", MmsData::Uint(self.conf_rev as u64)),
            (
                "OptFlds",
                MmsData::BitString(default_opt_flds(self.buffered)),
            ),
            ("BufTm", MmsData::Uint(0)),
            ("SqNum", MmsData::Uint(0)),
            (
                "TrgOps",
                MmsData::BitString(BitString::from_bits(&[false, true])),
            ),
            ("IntgPd", MmsData::Uint(0)),
            ("GI", MmsData::Bool(false)),
        ]);
        if self.buffered {
            c.extend([
                ("PurgeBuf", MmsData::Bool(false)),
                ("EntryID", MmsData::Octets(Vec::new())),
                ("TimeofEntry", MmsData::BinaryTime(vec![0; 6])),
                ("ResvTms", MmsData::Int(0)),
            ]);
        }
        c
    }
}

/// Definición de un Setting Group Control Block (SGCB) extraída del SCL.
#[derive(Debug, Clone)]
struct SgcbDef {
    domain: String,
    /// Base MMS del SGCB, `"<ln>$SP$SGCB"`.
    base: String,
    num_of_sgs: u32,
    act_sg: u32,
    resv_tms: bool,
}

impl SgcbDef {
    /// Componentes del SGCB en el orden de IEC 61850-8-1 (verificado contra
    /// libiec61850): `NumOfSG, ActSG, EditSG, CnfEdit, LActTm` (+`ResvTms`).
    fn components(&self) -> Vec<(&'static str, MmsData)> {
        let mut c = vec![
            ("NumOfSG", MmsData::Uint(self.num_of_sgs as u64)),
            ("ActSG", MmsData::Uint(self.act_sg as u64)),
            ("EditSG", MmsData::Uint(0)),
            ("CnfEdit", MmsData::Bool(false)),
            ("LActTm", MmsData::Utc(UtcTime { raw: [0; 8] })),
        ];
        if self.resv_tms {
            c.push(("ResvTms", MmsData::Uint(0)));
        }
        c
    }
}

/// Descriptor de un valor de setting group localizado en el namespace.
struct SettingRef {
    /// `true` si es la vista editable (FC=SE), `false` para la activa (FC=SG).
    editable: bool,
    /// Clave canónica del ajuste, `<ln>$<tail>`, común a las vistas SG y SE.
    canonical: String,
    num_of_sgs: u32,
}

/// Clave interna del store para el valor confirmado de un ajuste en el grupo `g`.
/// El prefijo `@` no aparece en itemIds MMS reales, así que no colisiona ni se
/// expone en `GetNameList`.
fn sg_group_key(group: u32, canonical: &str) -> String {
    format!("@sg@{group}@{canonical}")
}

/// Clave interna del store para el valor **en edición** (pendiente de confirmar)
/// de un ajuste.
fn sg_edit_key(canonical: &str) -> String {
    format!("@se@{canonical}")
}

/// Naturaleza de una escritura relacionada con grupos de ajuste.
enum SgWrite {
    /// `SelectActiveSG`: escribe `SGCB$ActSG`.
    SelectActive,
    /// `SelectEditSG`: escribe `SGCB$EditSG`.
    SelectEdit,
    /// `ConfirmEditSGValues`: escribe `SGCB$CnfEdit`.
    ConfirmEdit,
    /// Escritura de un valor editable (FC=SE) al buffer de edición.
    EditValue(SettingRef),
    /// Intento de escritura sobre la vista activa (FC=SG), de solo lectura.
    ActiveValue,
}

/// Extrae un `u32` de un `MmsData::Uint`.
fn mms_u32(v: &MmsData) -> Option<u32> {
    match v {
        MmsData::Uint(u) => Some(*u as u32),
        _ => None,
    }
}

/// Lee un atributo `Uint` del SGCB (p. ej. `ActSG`, `EditSG`) del mapa del store.
fn sgcb_u32(
    map: &HashMap<(String, String), MmsData>,
    domain: &str,
    base: Option<&str>,
    attr: &str,
) -> u32 {
    base.and_then(|b| map.get(&(domain.to_string(), format!("{b}${attr}"))))
        .and_then(mms_u32)
        .unwrap_or(0)
}

/// Resuelve el valor de un ajuste según su vista: FC=SG → grupo activo (ActSG);
/// FC=SE → valor pendiente de confirmar, o el del grupo en edición (EditSG).
fn resolve_setting(
    model: &ServerModel,
    map: &HashMap<(String, String), MmsData>,
    domain: &str,
    sr: &SettingRef,
) -> Option<MmsData> {
    let base = model.sgcb_base(domain);
    let clamp = |g: u32| -> u32 {
        if (1..=sr.num_of_sgs).contains(&g) {
            g
        } else {
            1
        }
    };
    if sr.editable {
        // Valor aún sin confirmar del grupo en edición, si lo hay.
        if let Some(v) = map.get(&(domain.to_string(), sg_edit_key(&sr.canonical))) {
            return Some(v.clone());
        }
        let g = clamp(sgcb_u32(map, domain, base, "EditSG"));
        map.get(&(domain.to_string(), sg_group_key(g, &sr.canonical)))
            .cloned()
    } else {
        let g = clamp(sgcb_u32(map, domain, base, "ActSG"));
        map.get(&(domain.to_string(), sg_group_key(g, &sr.canonical)))
            .cloned()
    }
}

/// Aplica una escritura de grupo de ajuste (ver [`SgWrite`]).
async fn handle_sg_write(
    model: &ServerModel,
    store: &Store,
    change_tx: &broadcast::Sender<ValueChange>,
    domain: &str,
    item: &str,
    value: MmsData,
    sgw: SgWrite,
) -> WriteResult {
    match sgw {
        SgWrite::SelectActive | SgWrite::SelectEdit => {
            // El grupo destino debe existir (1..=NumOfSG).
            let n = model.num_setting_groups(domain).unwrap_or(0) as u64;
            match &value {
                MmsData::Uint(g) if (1..=n).contains(g) => {
                    store_write(store, change_tx, domain, item, value).await
                }
                _ => WriteResult::Failure(DataAccessError::ObjectValueInvalid),
            }
        }
        SgWrite::ConfirmEdit => {
            if matches!(value, MmsData::Bool(true)) {
                confirm_edit_sg(model, store, domain).await;
            }
            // CnfEdit se auto-limpia tras procesar la confirmación.
            if let Some(base) = model.sgcb_base(domain) {
                store_write(
                    store,
                    change_tx,
                    domain,
                    &format!("{base}$CnfEdit"),
                    MmsData::Bool(false),
                )
                .await;
            }
            WriteResult::Success
        }
        SgWrite::EditValue(sr) => {
            // FC=SE: al buffer de edición, pendiente de ConfirmEditSGValues.
            store_write(store, change_tx, domain, &sg_edit_key(&sr.canonical), value).await
        }
        // FC=SG es de solo lectura (refleja el grupo activo).
        SgWrite::ActiveValue => WriteResult::Failure(DataAccessError::ObjectAccessDenied),
    }
}

/// `ConfirmEditSGValues`: vuelca los valores editados (FC=SE) al grupo en edición
/// (EditSG) y limpia el buffer de edición.
async fn confirm_edit_sg(model: &ServerModel, store: &Store, domain: &str) {
    let mut guard = store.write().await;
    let edit = sgcb_u32(&guard, domain, model.sgcb_base(domain), "EditSG");
    if !(1..=model.num_setting_groups(domain).unwrap_or(0)).contains(&edit) {
        return; // sin grupo de edición válido: nada que confirmar
    }
    let staged: Vec<(String, MmsData)> = guard
        .iter()
        .filter(|((d, it), _)| d == domain && it.starts_with("@se@"))
        .map(|((_, it), v)| (it.clone(), v.clone()))
        .collect();
    for (edit_key, v) in staged {
        if let Some(canonical) = edit_key.strip_prefix("@se@") {
            guard.insert((domain.to_string(), sg_group_key(edit, canonical)), v);
        }
        guard.remove(&(domain.to_string(), edit_key));
    }
}

/// Definición de un Log Control Block (LCB) extraída del SCL.
#[derive(Debug, Clone)]
struct LcbDef {
    domain: String,
    /// Base MMS del LCB, `"<ln>$LG$<name>"`.
    base: String,
    log_ena: bool,
    log_ref: String,
    dataset: Option<String>,
}

impl LcbDef {
    /// Componentes del LCB en el orden de IEC 61850-8-1 (verificado contra
    /// libiec61850): `LogEna, LogRef, DatSet, OldEntrTm, NewEntrTm, OldEntr,
    /// NewEntr, TrgOps, IntgPd`.
    fn components(&self) -> Vec<(&'static str, MmsData)> {
        vec![
            ("LogEna", MmsData::Bool(self.log_ena)),
            ("LogRef", MmsData::Visible(self.log_ref.clone())),
            (
                "DatSet",
                MmsData::Visible(self.dataset.clone().unwrap_or_default()),
            ),
            ("OldEntrTm", MmsData::BinaryTime(vec![0; 6])),
            ("NewEntrTm", MmsData::BinaryTime(vec![0; 6])),
            ("OldEntr", MmsData::Octets(vec![0; 8])),
            ("NewEntr", MmsData::Octets(vec![0; 8])),
            (
                "TrgOps",
                MmsData::BitString(BitString::from_bits(&[false, true, true])),
            ),
            ("IntgPd", MmsData::Uint(0)),
        ]
    }
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

/// Reserva de un RCB (`Resv` en URCB, `ResvTms` en BRCB): exclusividad de un
/// cliente sobre el bloque. Mientras la conexión vive, `until = None`; al
/// desconectar, una reserva con `resv_secs > 0` sobrevive esa ventana (permite
/// reconectar y resincronizar el BRCB sin que otro cliente lo tome).
struct Reservation {
    conn_id: u64,
    /// Segundos de reserva tras desconexión (`ResvTms`); 0 = solo en vida.
    resv_secs: u32,
    /// Expiración tras desconexión; `None` mientras la conexión vive.
    until: Option<Instant>,
}

impl Reservation {
    /// ¿Bloquea esta reserva a otra conexión en el instante `now`?
    fn holds(&self, now: Instant) -> bool {
        match self.until {
            None => true,       // conexión viva
            Some(t) => t > now, // ventana post-desconexión vigente
        }
    }
}

/// Reservas de RCB de todo el servidor, por `(domain, base)`.
type Reservations = Arc<Mutex<HashMap<(String, String), Reservation>>>;

/// Libera al morir la conexión: quita sus reservas sin `ResvTms` y arranca la
/// ventana de las que lo tienen. (Drop ⇒ corre también en salidas por error.)
struct ReservationGuard {
    conn_id: u64,
    reservations: Reservations,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut g = self.reservations.lock().unwrap();
        g.retain(|_, r| {
            if r.conn_id != self.conn_id {
                return true;
            }
            if r.resv_secs > 0 {
                r.until = Some(now + Duration::from_secs(r.resv_secs as u64));
                true
            } else {
                false
            }
        });
    }
}
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
    sgcbs: Vec<SgcbDef>,
    lcbs: Vec<LcbDef>,
    /// Dominios (LD) con SGCB → número de grupos de ajuste. Un DA con FC=SG/SE en
    /// uno de estos dominios es un valor de setting group (uno por grupo).
    sg_domains: HashMap<String, u32>,
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

        // Datasets, RCBs y SGCBs por nodo lógico.
        let mut datasets: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
        let mut rcbs: Vec<RcbDef> = Vec::new();
        let mut sgcbs: Vec<SgcbDef> = Vec::new();
        let mut lcbs: Vec<LcbDef> = Vec::new();
        for (objref, ln) in model.iter_logical_nodes() {
            let domain = objref.ld.clone();
            let ln_name = objref.ln.clone();
            // LCB (control de log): estructura con FC=LG en el LN.
            for lc in &ln.log_controls {
                let base = format!("{ln_name}$LG${}", lc.name);
                let def = LcbDef {
                    domain: domain.clone(),
                    base: base.clone(),
                    log_ena: lc.log_ena,
                    log_ref: format!("{domain}/{ln_name}${}", lc.name),
                    dataset: lc.dataset.clone(),
                };
                let dom_items = items.entry(domain.clone()).or_default();
                dom_items.push(base.clone());
                for (attr, _) in def.components() {
                    dom_items.push(format!("{base}${attr}"));
                }
                lcbs.push(def);
            }
            // SGCB (grupos de ajustes): estructura con FC=SP en el LN.
            if let Some(sgcb) = &ln.setting_group_control {
                let base = format!("{ln_name}$SP$SGCB");
                let def = SgcbDef {
                    domain: domain.clone(),
                    base: base.clone(),
                    num_of_sgs: sgcb.num_of_sgs,
                    act_sg: sgcb.act_sg,
                    resv_tms: sgcb.resv_tms,
                };
                let dom_items = items.entry(domain.clone()).or_default();
                dom_items.push(base.clone());
                for (attr, _) in def.components() {
                    dom_items.push(format!("{base}${attr}"));
                }
                sgcbs.push(def);
            }
            for ds in &ln.data_sets {
                // Resolución vía el modelo: honra el `ldInst` de cada FCDA
                // (miembros en OTRO dominio del mismo IED, habitual en CID
                // reales donde el dataset vive en LD0 y los datos en MON/CTRL).
                let members: Vec<(String, String)> = model
                    .resolve_dataset(&domain, &ds.name)
                    .map(|resolved| {
                        resolved
                            .iter()
                            .filter_map(|m| object_reference_to_mms(&m.reference).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                // Doble clave: nombre corto del SCL y forma MMS cualificada
                // por LN (`LLN0$ds1`), que es como lo referencian los clientes
                // conformes (readDataSetValues / GetNamedVariableListAttributes).
                datasets.insert(
                    (domain.clone(), format!("{ln_name}${}", ds.name)),
                    members.clone(),
                );
                datasets.insert((domain.clone(), ds.name.clone()), members);
            }
            for rc in &ln.report_controls {
                let fc = if rc.buffered { "BR" } else { "RP" };
                let base = format!("{ln_name}${fc}${}", rc.name);
                let rpt_id = rc
                    .rpt_id
                    .clone()
                    .unwrap_or_else(|| format!("{domain}/{ln_name}.{}", rc.name));
                let def = RcbDef {
                    domain: domain.clone(),
                    base: base.clone(),
                    rpt_id,
                    dataset: rc.dataset.clone(),
                    conf_rev: rc.conf_rev.unwrap_or(1),
                    buffered: rc.buffered,
                };
                // Namespace del RCB: la base (leíble como estructura) + cada
                // componente en el orden 8-1.
                let dom_items = items.entry(domain.clone()).or_default();
                dom_items.push(base.clone());
                for (attr, _) in def.components() {
                    dom_items.push(format!("{base}${attr}"));
                }
                rcbs.push(def);
            }
        }

        // Dominios con SGCB → número de grupos de ajuste.
        let mut sg_domains: HashMap<String, u32> = HashMap::new();
        for sgcb in &sgcbs {
            sg_domains
                .entry(sgcb.domain.clone())
                .and_modify(|n| *n = (*n).max(sgcb.num_of_sgs))
                .or_insert(sgcb.num_of_sgs);
        }
        // Para cada valor de setting (FC=SG) en un dominio con SGCB, exponer
        // además su vista editable FC=SE en el namespace (`<ln>$SE$<tail>`).
        for (domain, num) in &sg_domains {
            if *num == 0 {
                continue;
            }
            if let Some(list) = items.get_mut(domain) {
                let se_views: Vec<String> = list
                    .iter()
                    .filter_map(|it| {
                        let mut p = it.splitn(3, '$');
                        let ln = p.next()?;
                        let fc = p.next()?;
                        let tail = p.next()?;
                        (fc == "SG").then(|| format!("{ln}$SE${tail}"))
                    })
                    .collect();
                list.extend(se_views);
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
            sgcbs,
            lcbs,
            sg_domains,
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

    /// Si `(domain, item)` es la **base** de un RCB (sin sufijo de atributo),
    /// devuelve los nombres de sus componentes en el orden 8-1. Se usa para
    /// responder a la lectura del RCB completo como estructura (`getRCBValues`).
    fn rcb_component_names(&self, domain: &str, item: &str) -> Option<Vec<&'static str>> {
        let def = self.rcb_def(domain, item)?;
        Some(def.components().into_iter().map(|(name, _)| name).collect())
    }

    /// Ensambla una **estructura** MMS para un item que no es una hoja sino un
    /// objeto compuesto (un DO o SDO), leyendo sus hojas del `store`. Necesario
    /// para leer miembros de dataset que son objetos estructurados (p. ej. una
    /// medida `AnIn1[MX]` = `{ mag {f}, q, t }`). Devuelve `None` si el item no
    /// tiene hijos en el namespace (es hoja o no existe). El orden de los
    /// componentes sigue el del namespace (que preserva el orden del SCL).
    fn assemble_structured(
        &self,
        domain: &str,
        item: &str,
        store: &HashMap<(String, String), MmsData>,
    ) -> Option<MmsData> {
        let items = self.items.get(domain)?;
        let prefix = format!("{item}$");
        // Hijos directos: el primer segmento tras el prefijo, en orden, sin repetir.
        let mut children: Vec<String> = Vec::new();
        for it in items {
            if let Some(rest) = it.strip_prefix(&prefix) {
                let seg = rest.split('$').next().unwrap_or("");
                let child = format!("{item}${seg}");
                if !children.contains(&child) {
                    children.push(child);
                }
            }
        }
        if children.is_empty() {
            return None;
        }
        let comps = children
            .iter()
            .map(|child| {
                // Si el hijo tiene sub-hojas (es una sub-estructura como `mag`),
                // recursar; solo si no, tomar su valor plano del store. El orden
                // importa: el store contiene entradas espurias para los nodos
                // intermedios (bType="Struct" → default) que no deben ganar.
                self.assemble_structured(domain, child, store)
                    .or_else(|| store.get(&(domain.to_string(), child.clone())).cloned())
                    .unwrap_or(MmsData::Bool(false))
            })
            .collect();
        Some(MmsData::Structure(comps))
    }

    /// Si `(domain, item)` es la base de un SGCB, devuelve los nombres de sus
    /// componentes en el orden 8-1 (no alfabético). Análogo a `rcb_component_names`.
    fn sgcb_component_names(&self, domain: &str, item: &str) -> Option<Vec<&'static str>> {
        let def = self
            .sgcbs
            .iter()
            .find(|s| s.domain == domain && s.base == item)?;
        Some(def.components().into_iter().map(|(name, _)| name).collect())
    }

    /// Si `(domain, item)` es la base de un LCB, devuelve sus componentes en el
    /// orden 8-1. Análogo a `sgcb_component_names`.
    fn lcb_component_names(&self, domain: &str, item: &str) -> Option<Vec<&'static str>> {
        let def = self
            .lcbs
            .iter()
            .find(|l| l.domain == domain && l.base == item)?;
        Some(def.components().into_iter().map(|(name, _)| name).collect())
    }

    /// Si `(domain, item)` es un valor de setting group (FC=SG/SE en un dominio
    /// con SGCB), devuelve su descriptor: si es editable (SE) y su clave canónica
    /// `<ln>$<tail>` (independiente del FC, común a las vistas SG y SE) más el
    /// número de grupos.
    fn setting_ref(&self, domain: &str, item: &str) -> Option<SettingRef> {
        let num_of_sgs = *self.sg_domains.get(domain)?;
        let mut p = item.splitn(3, '$');
        let ln = p.next()?;
        let fc = p.next()?;
        let tail = p.next()?;
        let editable = match fc {
            "SG" => false,
            "SE" => true,
            _ => return None,
        };
        Some(SettingRef {
            editable,
            canonical: format!("{ln}${tail}"),
            num_of_sgs,
        })
    }

    /// Base MMS del SGCB de un dominio (`"<ln>$SP$SGCB"`), si lo hay.
    fn sgcb_base(&self, domain: &str) -> Option<&str> {
        self.sgcbs
            .iter()
            .find(|s| s.domain == domain)
            .map(|s| s.base.as_str())
    }

    /// Número de grupos de ajuste de un dominio (LD), si tiene SGCB.
    fn num_setting_groups(&self, domain: &str) -> Option<u32> {
        self.sg_domains.get(domain).copied()
    }

    /// Clasifica una escritura relacionada con grupos de ajuste sobre
    /// `(domain, item)`: control del SGCB (ActSG/EditSG/CnfEdit) o valor de un
    /// ajuste (FC=SE editable / FC=SG de solo lectura).
    fn classify_sg_write(&self, domain: &str, item: &str) -> Option<SgWrite> {
        if let Some(base) = self.sgcb_base(domain) {
            if item == format!("{base}$ActSG") {
                return Some(SgWrite::SelectActive);
            }
            if item == format!("{base}$EditSG") {
                return Some(SgWrite::SelectEdit);
            }
            if item == format!("{base}$CnfEdit") {
                return Some(SgWrite::ConfirmEdit);
            }
        }
        let sr = self.setting_ref(domain, item)?;
        Some(if sr.editable {
            SgWrite::EditValue(sr)
        } else {
            SgWrite::ActiveValue
        })
    }

    /// Si `(domain, item)` (p. ej. `"LLN0$EventLog"`) es el journal de un LCB
    /// conocido, devuelve sus entradas. Aún no se persisten eventos reales, así
    /// que genera entradas de ejemplo deterministas para exponer el servicio
    /// `ReadJournal`.
    fn journal_entries(&self, domain: &str, item: &str) -> Option<Vec<JournalEntry>> {
        let log_ref = format!("{domain}/{item}");
        self.lcbs.iter().find(|l| l.log_ref == log_ref)?;
        Some(vec![
            JournalEntry {
                entry_id: 1u64.to_be_bytes().to_vec(),
                occurrence_time: vec![0; 6],
                values: vec![MmsData::Bool(true)],
            },
            JournalEntry {
                entry_id: 2u64.to_be_bytes().to_vec(),
                occurrence_time: vec![0; 6],
                values: vec![MmsData::Bool(false)],
            },
        ])
    }

    /// Normaliza el **sufijo de instancia MMS** de un item de RCB. En el mapeo
    /// IEC 61850-8-1, las instancias de un ReportControl llevan un índice de dos
    /// dígitos (`EventsRCB` → `EventsRCB01`); clientes conformes (libiec61850) lo
    /// usan al referenciar el RCB. Nuestro namespace usa el nombre del SCL sin
    /// índice, así que aquí lo quitamos si con ello el RCB existe. Devuelve el
    /// item tal cual si no procede (no es un RCB o no lleva índice conocido).
    fn normalize_rcb_item(&self, domain: &str, item: &str) -> String {
        for fc in ["$RP$", "$BR$"] {
            let Some(pos) = item.find(fc) else { continue };
            let after = &item[pos + fc.len()..];
            let (rcb_name, rest) = match after.find('$') {
                Some(p) => (&after[..p], &after[p..]),
                None => (after, ""),
            };
            if let Some(stripped) = rcb_name.strip_suffix("01") {
                let base = format!("{}{fc}{stripped}", &item[..pos]);
                if self.rcb_def(domain, &base).is_some() {
                    return format!("{base}{rest}");
                }
            }
        }
        item.to_string()
    }
    /// Miembros de un dataset. Tolera las tres formas de nombre con que un
    /// cliente puede referirse a él: `"ds1"` (corto), `"LLN0$ds1"` (cualificado
    /// por LN, la forma MMS de 8-1) y `"IED1LD0/LLN0$ds1"` (con dominio).
    fn dataset_members(&self, domain: &str, name: &str) -> Option<&[(String, String)]> {
        let name = match name.split_once('/') {
            Some((d, rest)) if d == domain => rest,
            _ => name,
        };
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
                    .and_then(|v| value_to_mms(da, v))
                    .unwrap_or_else(|| default_for(&da.basic_type));
                // Valor de setting group (FC=SG): sembrar una copia por cada grupo
                // de ajuste (todos parten del mismo valor inicial del SCL).
                if let Some(sr) = self.setting_ref(&domain, &item) {
                    if !sr.editable {
                        for g in 1..=sr.num_of_sgs {
                            map.insert(
                                (domain.clone(), sg_group_key(g, &sr.canonical)),
                                value.clone(),
                            );
                        }
                    }
                }
                map.insert((domain, item), value);
            }
        }
        // Sembrar atributos de cada RCB en el orden estándar de 8-1.
        for rcb in &self.rcbs {
            for (attr, value) in rcb.components() {
                map.insert((rcb.domain.clone(), format!("{}${attr}", rcb.base)), value);
            }
        }
        // Sembrar los componentes de cada SGCB (grupos de ajustes).
        for sgcb in &self.sgcbs {
            for (attr, value) in sgcb.components() {
                map.insert(
                    (sgcb.domain.clone(), format!("{}${attr}", sgcb.base)),
                    value,
                );
            }
        }
        // Sembrar los componentes de cada LCB (control de log).
        for lcb in &self.lcbs {
            for (attr, value) in lcb.components() {
                map.insert((lcb.domain.clone(), format!("{}${attr}", lcb.base)), value);
            }
        }
        Arc::new(RwLock::new(map))
    }
}

/// Construye el itemId de un FCDA (`LN$FC$DO$...$DA`).

fn value_to_mms(da: &iec61850_model::DataAttribute, v: &Value) -> Option<MmsData> {
    use BasicType::*;
    Some(match da.basic_type {
        Boolean => MmsData::Bool(v.as_bool()?),
        Int8 | Int16 | Int32 | Int64 => MmsData::Int(v.as_i64()?),
        Int8u | Int16u | Int32u => MmsData::Uint(v.as_i64()? as u64),
        Float32 | Float64 => MmsData::Float(v.as_f64()?),
        // Un enum viaja por MMS como INTEGER (ordinal). El SCL puede dar el valor
        // como ordinal (`1`) o como literal (`"on"`); traducimos el literal a su
        // ordinal usando la tabla del EnumType (fidelidad SCL 3.4). Si no está en
        // la tabla, último recurso: el literal como string (no conforme, pero no
        // perdemos el dato).
        Enum | Dbpos | Tcmd => match v.as_i64() {
            Some(ord) => MmsData::Int(ord),
            None => match da.enum_ordinal(&v.raw) {
                Some(ord) => MmsData::Int(ord),
                None => MmsData::Visible(v.raw.clone()),
            },
        },
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
    reservations: Reservations,
    limits: ServerLimits,
    auth: AuthPolicy,
    #[cfg(feature = "tls")]
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    /// Fuente de revocación (IEC 62351-9): si se configura, el certificado del par
    /// se valida (vigencia + no revocado, CRL u OCSP) durante la asociación.
    #[cfg(feature = "tls")]
    revocation: Option<Arc<crate::transport::tls::RevocationSource>>,
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
            reservations: Arc::new(Mutex::new(HashMap::new())),
            limits: ServerLimits::default(),
            auth: AuthPolicy::None,
            #[cfg(feature = "tls")]
            acceptor: None,
            #[cfg(feature = "tls")]
            revocation: None,
        })
    }

    /// Ajusta los [`ServerLimits`] de robustez (conexiones, timeouts, lag).
    pub fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Configura la política de **autenticación** ACSE (IEC 62351-4) y el RBAC
    /// asociado (IEC 62351-8): asociaciones sin password válido se rechazan, y
    /// el rol del password limita qué puede escribir/controlar el cliente.
    pub fn with_auth(mut self, auth: AuthPolicy) -> Self {
        self.auth = auth;
        self
    }

    /// Configura una **lista de revocación de certificados** (CRL, IEC 62351-9).
    /// Con ella, el certificado de cliente (mTLS) se valida durante la asociación:
    /// se rechaza si está fuera de su ventana de validez o si su número de serie
    /// figura en la CRL. Parsea la CRL con [`crate::transport::tls::parse_crl`].
    #[cfg(feature = "tls")]
    pub fn with_crl(mut self, crl: crate::transport::tls::CrlInfo) -> Self {
        self.revocation = Some(Arc::new(crl.into()));
        self
    }

    /// Configura una **respuesta OCSP** (RFC 6960, IEC 62351-9) pre-obtenida como
    /// fuente de revocación: el certificado de cliente se rechaza si la OCSP lo
    /// marca revocado o desconocido. Parsea la respuesta con
    /// [`crate::transport::tls::parse_ocsp_response`].
    #[cfg(feature = "tls")]
    pub fn with_ocsp(mut self, ocsp: crate::transport::tls::OcspResponse) -> Self {
        self.revocation = Some(Arc::new(ocsp.into()));
        self
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
                self.model.clone(),
                self.store.clone(),
            ));
        }
        // Semáforo global: acota las conexiones simultáneas. Un permiso viaja
        // con cada tarea de conexión y se libera al terminar (RAII).
        let conn_limit = Arc::new(tokio::sync::Semaphore::new(self.limits.max_connections));
        let limits = self.limits;
        let auth = Arc::new(self.auth);
        let next_conn_id = Arc::new(std::sync::atomic::AtomicU64::new(1));
        loop {
            let (sock, _) = self.listener.accept().await?;
            // Espera un hueco antes de gastar recursos en el handshake.
            let permit = match conn_limit.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semáforo cerrado: nunca ocurre aquí
            };
            let model = self.model.clone();
            let store = self.store.clone();
            let change_tx = self.change_tx.clone();
            let buffers = self.buffers.clone();
            let buffer_rx = self.buffer_tx.subscribe();
            let reservations = self.reservations.clone();
            let conn_id = next_conn_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let auth = auth.clone();
            #[cfg(feature = "tls")]
            let acceptor = self.acceptor.clone();
            #[cfg(feature = "tls")]
            let revocation = self.revocation.clone();
            tokio::spawn(async move {
                let _permit = permit; // se libera al salir del scope
                // Establece el transporte (en claro o TLS) antes del handshake MMS.
                // El handshake TLS también está sujeto al timeout de handshake.
                #[cfg(feature = "tls")]
                let conn = match acceptor {
                    Some(acc) => {
                        match tokio::time::timeout(
                            limits.handshake_timeout,
                            IsoConnection::from_stream_tls(sock, &acc),
                        )
                        .await
                        {
                            Ok(Ok(c)) => c,
                            _ => return, // handshake TLS fallido o expirado
                        }
                    }
                    None => IsoConnection::from_stream(sock),
                };
                #[cfg(not(feature = "tls"))]
                let conn = IsoConnection::from_stream(sock);

                #[cfg(feature = "tls")]
                let _ = handle_connection(
                    conn,
                    model,
                    store,
                    change_tx,
                    buffers,
                    buffer_rx,
                    reservations,
                    conn_id,
                    limits,
                    auth,
                    revocation,
                )
                .await;
                #[cfg(not(feature = "tls"))]
                let _ = handle_connection(
                    conn,
                    model,
                    store,
                    change_tx,
                    buffers,
                    buffer_rx,
                    reservations,
                    conn_id,
                    limits,
                    auth,
                )
                .await;
            });
        }
        Ok(())
    }
}

/// Tarea de buffering por servidor: por cada cambio de valor, añade una entrada
/// (con EntryID) a los BRCB cuyo dataset contenga ese miembro, y notifica.
async fn buffering_task(
    mut change_rx: broadcast::Receiver<ValueChange>,
    buffers: Buffers,
    buffer_tx: broadcast::Sender<(String, String)>,
    brcbs: BrcbMembers,
    model: Arc<ServerModel>,
    store: Store,
) {
    loop {
        match change_rx.recv().await {
            Ok(change) => {
                for (key, members) in &brcbs {
                    let Some(idx) = member_covering(members, &change.domain, &change.item)
                    else {
                        continue;
                    };
                    let member = &members[idx];
                    let value = if member.1 == change.item {
                        change.value.clone()
                    } else {
                        // Miembro a nivel DO: bufferiza el DO completo.
                        let guard = store.read().await;
                        model
                            .assemble_structured(&member.0, &member.1, &guard)
                            .unwrap_or_else(|| change.value.clone())
                    };
                    {
                        let mut guard = buffers.lock().unwrap();
                        let buf = guard.entry(key.clone()).or_insert_with(BrcbBuffer::new);
                        let entry_id = buf.next_id;
                        buf.next_id += 1;
                        buf.entries.push_back(BufEntry {
                            entry_id,
                            member_idx: idx,
                            value,
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

/// `sboTimeout` por defecto (ms) cuando el CF no lo define o vale 0.
const DEFAULT_SBO_TIMEOUT_MS: u64 = 30_000;

/// Selección SBO vigente sobre un objeto de control.
struct Selection {
    /// Instante en que la selección expira (`sboTimeout` del CF o el defecto).
    expires: Instant,
}

/// Salida de un servicio confirmado, en orden de envío: mensajes no solicitados
/// previos a la respuesta (LastApplError), la respuesta y los posteriores
/// (reportes, CommandTermination).
struct ServiceOutput {
    pre: Vec<Vec<u8>>,
    resp: Vec<u8>,
    post: Vec<Vec<u8>>,
}

impl ServiceOutput {
    /// Sólo la respuesta, sin mensajes no solicitados.
    fn only(resp: Vec<u8>) -> Self {
        Self {
            pre: Vec::new(),
            resp,
            post: Vec::new(),
        }
    }
}

/// Estado de una conexión: RCBs habilitados, selecciones de control, ficheros
/// abiertos y datasets **dinámicos** creados por el cliente (por conexión).
#[derive(Default)]
struct ConnState {
    rcbs: HashMap<(String, String), RcbRuntime>, // (domain, base)
    selections: HashMap<(String, String), Selection>,
    files: HashMap<i32, FileReadState>,
    next_frsm: i32,
    /// Datasets dinámicos `(domain, name) -> miembros`, creados con
    /// `DefineNamedVariableList` y visibles solo en esta conexión.
    dynamic_datasets: HashMap<(String, String), Vec<(String, String)>>,
    /// Rol RBAC de esta conexión (IEC 62351-8), fijado tras la autenticación.
    role: Role,
    /// Identificador de esta conexión (para las reservas de RCB).
    conn_id: u64,
    /// Reservas de RCB compartidas del servidor (Resv/ResvTms).
    reservations: Reservations,
    /// Transferencia `obtainFile` en curso (SetFile entrante): el servidor lee
    /// del cliente con fileOpen/fileRead/fileClose inversos.
    obtain: Option<ObtainState>,
    /// invokeID de las peticiones que ESTE servidor envía al cliente.
    next_out_invoke: u32,
}

/// Estado de un `obtainFile` (SetFile) en curso.
struct ObtainState {
    /// invokeID de la petición obtainFile original (a responder al final).
    invoke: u32,
    /// Nombre de destino en el filestore del servidor.
    dest: String,
    /// frsmID de la lectura inversa (tras el fileOpen).
    frsm: Option<i32>,
    /// Contenido acumulado.
    data: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut conn: IsoConnection,
    model: Arc<ServerModel>,
    store: Store,
    change_tx: broadcast::Sender<ValueChange>,
    buffers: Buffers,
    mut buffer_rx: broadcast::Receiver<(String, String)>,
    reservations: Reservations,
    conn_id: u64,
    limits: ServerLimits,
    auth: Arc<AuthPolicy>,
    #[cfg(feature = "tls")] revocation: Option<Arc<crate::transport::tls::RevocationSource>>,
) -> Result<(), MmsError> {
    // Construye la respuesta de asociación (ACCEPT de sesión + CPA) para un
    // AARE dado, con los parámetros negociados con este peer concreto.
    type AcceptBuilder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send>;

    // Todo el handshake (COTP CR→CC + asociación ACSE) bajo un único timeout:
    // un peer que abre el socket y no progresa se descarta pronto.
    let (role, mms_ctx) = tokio::time::timeout(limits.handshake_timeout, async {
        // COTP: CR → CC.
        let cr = conn.recv().await?;
        let client_ref = cotp::parse_connection_request(&cr)?;
        conn.send(&cotp::connection_confirm(client_ref, OUR_SRC_REF))
            .await?;

        // Asociación. Negociación real de Sesión (ISO 8327) y Presentación
        // (ISO 8823): se parsea la SPDU CONNECT y el CP, se responde a CADA
        // contexto propuesto (aceptando ACSE/MMS con BER, rechazando el resto
        // con su razón) y la fase de datos usa el context-id MMS del cliente.
        // Si el peer manda algo no parseable, fallback al camino tolerante
        // (escaneo del fully-encoded-data + CPA de plantilla).
        let assoc = conn.recv_data().await?;
        let negotiation = session::parse_connect(&assoc)
            .and_then(|sess| Ok((presentation::parse_cp(sess.user_data)?, sess)));
        let (aarq, accept_of, mms_ctx): (&[u8], AcceptBuilder, i64) = match &negotiation {
            Ok((cp, sess)) => {
                let neg = presentation::negotiate(&cp.contexts);
                let (Some(acse_id), Some(mms_id)) = (neg.acse_id, neg.mms_id) else {
                    // Sin contexto ACSE o MMS utilizable no puede viajar ni el
                    // AARE: se cierra (rechazo a nivel de presentación).
                    return Err(MmsError::AssociateRejected(format!(
                        "CP sin contextos ACSE/MMS aceptables: {:?}",
                        neg.verdicts
                    )));
                };
                let called = cp.called_selector.map(|s| s.to_vec());
                let version = sess.negotiated_version();
                let builder: AcceptBuilder = Box::new(move |aare: &[u8]| {
                    session::accept_with_version(
                        &presentation::connect_cpa_negotiated(
                            aare,
                            &neg,
                            called.as_deref(),
                            acse_id,
                        ),
                        version,
                    )
                });
                (cp.inner_pdu, builder, mms_id)
            }
            Err(_) => {
                let aarq = presentation::extract_inner_pdu(&assoc)?;
                let builder: AcceptBuilder =
                    Box::new(|aare: &[u8]| session::accept(&presentation::connect_cpa(aare)));
                (aarq, builder, presentation::MMS_CONTEXT_ID)
            }
        };
        let password = acse::extract_auth_password(aarq);
        // Certificado de cliente (mTLS), si lo hubo: se valida (IEC 62351-9) —
        // vigencia y, con CRL configurada, no revocación — y se extrae el CN.
        #[cfg(feature = "tls")]
        let cert_cn = match conn.peer_certificate() {
            Some(der) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Err(e) =
                    crate::transport::tls::validate_certificate(&der, revocation.as_deref(), now)
                {
                    let reject = accept_of(&acse::aare_reject());
                    let _ = conn.send_data_tsdu(&reject).await;
                    return Err(MmsError::AssociateRejected(format!(
                        "certificado rechazado (62351-9): {e}"
                    )));
                }
                crate::transport::tls::cert_common_name(&der)
            }
            None => None,
        };
        #[cfg(not(feature = "tls"))]
        let cert_cn: Option<String> = None;
        let role = match auth.authorize(password.as_deref(), cert_cn.as_deref()) {
            Some(role) => role,
            None => {
                // Autenticación fallida: responder AARE de rechazo y cerrar.
                let reject = accept_of(&acse::aare_reject());
                let _ = conn.send_data_tsdu(&reject).await;
                return Err(MmsError::AssociateRejected(
                    "autenticación fallida (62351-4)".into(),
                ));
            }
        };
        let inner = acse::parse_aarq(aarq)?;
        let req = InitiateRequest::decode(inner)?;
        let resp = InitiateResponse::accept(&req);
        let accept = accept_of(&acse::aare(&resp.encode()));
        conn.send_data_tsdu(&accept).await?;
        Ok::<_, MmsError>((role, mms_ctx))
    })
    .await
    .map_err(|_| MmsError::Timeout)??;

    // Separar para poder leer peticiones y empujar reportes a la vez.
    let (mut reader, mut writer) = conn.split();
    let mut change_rx = change_tx.subscribe();
    // Al morir la conexión (incluidas salidas por error) se liberan sus
    // reservas de RCB; las que tienen ResvTms arrancan su ventana.
    let _resv_guard = ReservationGuard {
        conn_id,
        reservations: reservations.clone(),
    };
    let mut state = ConnState {
        role,
        conn_id,
        reservations,
        ..ConnState::default()
    };
    // Reportes perdidos acumulados por un cliente que no drena a tiempo.
    let mut report_lag: u64 = 0;

    loop {
        let next_int = state.next_integrity_deadline();
        let idle = tokio::time::sleep(limits.idle_timeout);
        tokio::select! {
            biased;

            _ = idle => {
                // Sin actividad de petición ni reporte en el plazo: cerrar.
                break;
            }

            r = reader.recv_data() => {
                let payload = match r { Ok(p) => p, Err(_) => break };
                let pdu = presentation::extract_inner_pdu(&payload)?;
                match pdu::peek_request_kind(pdu)? {
                    PduKind::ConfirmedRequest => {
                        let (invoke, service) = pdu::parse_confirmed_request(pdu)?;
                        // obtainFile (SetFile) difiere su respuesta: arranca la
                        // lectura inversa hacia el cliente.
                        if service.tag == pdu::service::OBTAIN_FILE {
                            for msg in state.start_obtain_file(invoke, &service, &model) {
                                send_report(&mut writer, mms_ctx, &msg).await?;
                            }
                            continue;
                        }
                        let out = state
                            .handle_request(invoke, &service, &model, &store, &change_tx, &buffers)
                            .await;
                        for msg in &out.pre {
                            send_report(&mut writer, mms_ctx, msg).await?;
                        }
                        send_report(&mut writer, mms_ctx, &out.resp).await?;
                        for msg in &out.post {
                            send_report(&mut writer, mms_ctx, msg).await?;
                        }
                    }
                    // Respuestas del CLIENTE a nuestras peticiones inversas
                    // (fileOpen/fileRead/fileClose de un obtainFile en curso).
                    PduKind::ConfirmedResponse | PduKind::ConfirmedError | PduKind::Reject => {
                        for msg in state.obtain_file_step(pdu, &model) {
                            send_report(&mut writer, mms_ctx, &msg).await?;
                        }
                    }
                    PduKind::ConcludeRequest => {
                        let mut w = BerWriter::new();
                        w.tlv(pdu::mmspdu::CONCLUDE_RESPONSE, |_| {});
                        send_report(&mut writer, mms_ctx, &w.into_bytes()).await?;
                        break;
                    }
                    _ => break,
                }
            }

            ch = change_rx.recv() => {
                match ch {
                    Ok(change) => {
                        for rep in state.on_value_change(&change, &model, &store).await {
                            send_report(&mut writer, mms_ctx, &rep).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // El cliente no drena sus reportes: contabiliza las tramas
                        // perdidas y desconecta si supera el umbral (anti-DoS de
                        // memoria; un URCB no bufferado no debe retenerlas).
                        report_lag = report_lag.saturating_add(n);
                        if report_lag > limits.max_report_lag {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            key = buffer_rx.recv() => {
                match key {
                    Ok(key) => {
                        for rep in state.on_buffer(&key, &buffers) {
                            send_report(&mut writer, mms_ctx, &rep).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        report_lag = report_lag.saturating_add(n);
                        if report_lag > limits.max_report_lag {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            _ = async { match next_int { Some(t) => sleep_until(t).await, None => std::future::pending().await } } => {
                for rep in state.on_integrity(&model, &store).await {
                    send_report(&mut writer, mms_ctx, &rep).await?;
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

    /// Atiende una petición confirmada; devuelve la salida ordenada: mensajes
    /// no solicitados previos (`pre`, p. ej. un LastApplError antes del Write−),
    /// la respuesta, y los posteriores (`post`, p. ej. reportes tras una GI o
    /// una CommandTermination tras el Write+).
    async fn handle_request(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
        buffers: &Buffers,
    ) -> ServiceOutput {
        let tag = service.tag;
        if tag == pdu::service::IDENTIFY_REQUEST {
            ServiceOutput::only(pdu::encode_confirmed_response(invoke, |w| {
                identify::encode_response(w, model.ident())
            }))
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
            ServiceOutput::only(resp)
        } else if tag == pdu::service::READ {
            ServiceOutput::only(self.handle_read(invoke, service, model, store).await)
        } else if tag == pdu::service::GET_VARIABLE_ACCESS_ATTRIBUTES {
            ServiceOutput::only(handle_get_var_attr(invoke, service, model, store).await)
        } else if tag == pdu::service::FILE_DIRECTORY {
            ServiceOutput::only(handle_file_directory(invoke, service, model))
        } else if tag == pdu::service::FILE_OPEN {
            ServiceOutput::only(self.handle_file_open(invoke, service, model))
        } else if tag == pdu::service::FILE_READ {
            ServiceOutput::only(self.handle_file_read(invoke, service))
        } else if tag == pdu::service::FILE_CLOSE {
            ServiceOutput::only(self.handle_file_close(invoke, service))
        } else if tag == pdu::service::FILE_DELETE {
            ServiceOutput::only(self.handle_file_delete(invoke, service, model))
        } else if tag == pdu::service::FILE_RENAME {
            ServiceOutput::only(self.handle_file_rename(invoke, service, model))
        } else if tag == pdu::service::WRITE {
            self.handle_write(invoke, service, model, store, change_tx, buffers)
                .await
        } else if tag == pdu::service::DEFINE_NAMED_VARIABLE_LIST {
            ServiceOutput::only(self.handle_define_dataset(invoke, service))
        } else if tag == pdu::service::DELETE_NAMED_VARIABLE_LIST {
            ServiceOutput::only(self.handle_delete_dataset(invoke, service))
        } else if tag == pdu::service::GET_NAMED_VARIABLE_LIST_ATTRIBUTES {
            ServiceOutput::only(self.handle_get_dataset_attrs(invoke, service, model))
        } else if tag == pdu::service::READ_JOURNAL {
            ServiceOutput::only(handle_read_journal(invoke, service, model))
        } else {
            ServiceOutput::only(encode_error(invoke))
        }
    }

    /// `DefineNamedVariableList`: crea un dataset dinámico en esta conexión.
    fn handle_define_dataset(&mut self, invoke: u32, service: &Tlv<'_>) -> Vec<u8> {
        // RBAC (IEC 62351-8): definir datasets exige el permiso correspondiente.
        if !self.role.may_define_dataset() {
            return encode_error(invoke);
        }
        let Ok(((domain, name), members)) = named_var_list::decode_define_request(service) else {
            return encode_error(invoke);
        };
        self.dynamic_datasets.insert((domain, name), members);
        pdu::encode_confirmed_response(invoke, named_var_list::encode_define_response)
    }

    /// `DeleteNamedVariableList`: borra los datasets dinámicos indicados.
    fn handle_delete_dataset(&mut self, invoke: u32, service: &Tlv<'_>) -> Vec<u8> {
        if !self.role.may_define_dataset() {
            return encode_error(invoke);
        }
        let Ok(names) = named_var_list::decode_delete_request(service) else {
            return encode_error(invoke);
        };
        let mut matched = 0;
        let mut deleted = 0;
        for key in names {
            matched += 1;
            if self.dynamic_datasets.remove(&key).is_some() {
                deleted += 1;
            }
        }
        pdu::encode_confirmed_response(invoke, |w| {
            named_var_list::encode_delete_response(
                w,
                named_var_list::DeleteResult { matched, deleted },
            )
        })
    }

    /// `GetNamedVariableListAttributes`: devuelve los miembros de un dataset
    /// (dinámico de esta conexión o estático del modelo).
    fn handle_get_dataset_attrs(
        &self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
    ) -> Vec<u8> {
        let Ok((domain, name)) = named_var_list::decode_get_attributes_request(service) else {
            return encode_error(invoke);
        };
        // Los dinámicos son borrables; los estáticos del SCL, no.
        let (deletable, members) =
            if let Some(m) = self.dynamic_datasets.get(&(domain.clone(), name.clone())) {
                (true, m.clone())
            } else if let Some(m) = model.dataset_members(&domain, &name) {
                (false, m.to_vec())
            } else {
                return encode_error(invoke);
            };
        pdu::encode_confirmed_response(invoke, |w| {
            named_var_list::encode_get_attributes_response(w, deletable, &members)
        })
    }

    /// `fileOpen`: lee el fichero del proveedor a memoria y asigna un frsmID.
    fn handle_file_open(&mut self, invoke: u32, service: &Tlv<'_>, model: &ServerModel) -> Vec<u8> {
        // RBAC (IEC 62351-8): la lectura de ficheros exige el permiso FILE_READ.
        if !self.role.may_read_files() {
            return encode_error(invoke);
        }
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

    /// `fileDelete [76]`: borra un fichero del filestore (RBAC: FILE_WRITE).
    fn handle_file_delete(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
    ) -> Vec<u8> {
        if !self.role.may_write_files() {
            return encode_error(invoke);
        }
        let (Some(provider), Ok(name)) =
            (model.file_provider(), file::decode_delete_request(service))
        else {
            return encode_error(invoke);
        };
        if provider.delete(&name).is_err() {
            return encode_error(invoke);
        }
        pdu::encode_confirmed_response(invoke, file::encode_delete_response)
    }

    /// `fileRename [75]`: renombra un fichero del filestore (RBAC: FILE_WRITE).
    fn handle_file_rename(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
    ) -> Vec<u8> {
        if !self.role.may_write_files() {
            return encode_error(invoke);
        }
        let (Some(provider), Ok((cur, new))) =
            (model.file_provider(), file::decode_rename_request(service))
        else {
            return encode_error(invoke);
        };
        if provider.rename(&cur, &new).is_err() {
            return encode_error(invoke);
        }
        pdu::encode_confirmed_response(invoke, file::encode_rename_response)
    }

    /// Arranca un `obtainFile [46]` (SetFile): valida permisos y provider, y
    /// devuelve la petición fileOpen inversa a enviar al cliente. La respuesta
    /// al obtainFile se emite al completar la transferencia.
    fn start_obtain_file(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
    ) -> Vec<Vec<u8>> {
        if !self.role.may_write_files() || model.file_provider().is_none() || self.obtain.is_some()
        {
            return vec![encode_error(invoke)];
        }
        let Ok((source, dest)) = file::decode_obtain_request(service) else {
            return vec![encode_error(invoke)];
        };
        self.next_out_invoke += 1;
        let out = self.next_out_invoke;
        self.obtain = Some(ObtainState {
            invoke,
            dest,
            frsm: None,
            data: Vec::new(),
        });
        vec![pdu::encode_confirmed_request(out, |w| {
            file::write_open_request(w, &source, 0)
        })]
    }

    /// Avanza el `obtainFile` en curso con una respuesta entrante del cliente
    /// (fileOpen/fileRead inversos). Devuelve los mensajes a enviar: la
    /// siguiente petición, o el fileClose + la respuesta final al obtainFile.
    fn obtain_file_step(&mut self, pdu_bytes: &[u8], model: &ServerModel) -> Vec<Vec<u8>> {
        let Some(mut st) = self.obtain.take() else {
            return Vec::new(); // p. ej. la respuesta del fileClose final
        };
        let Ok(cr) = pdu::parse_confirmed_response(pdu_bytes) else {
            // error o reject del cliente: el obtainFile falla.
            return vec![encode_error(st.invoke)];
        };
        match st.frsm {
            None => match file::decode_open_response(&cr.service) {
                Ok(open) => {
                    st.frsm = Some(open.frsm_id);
                    self.next_out_invoke += 1;
                    let out = self.next_out_invoke;
                    let req = pdu::encode_confirmed_request(out, |w| {
                        file::write_read_request(w, open.frsm_id)
                    });
                    self.obtain = Some(st);
                    vec![req]
                }
                Err(_) => vec![encode_error(st.invoke)],
            },
            Some(frsm) => match file::decode_read_response(&cr.service) {
                Ok(chunk) => {
                    st.data.extend_from_slice(&chunk.data);
                    self.next_out_invoke += 1;
                    let out = self.next_out_invoke;
                    if chunk.more_follows {
                        let req = pdu::encode_confirmed_request(out, |w| {
                            file::write_read_request(w, frsm)
                        });
                        self.obtain = Some(st);
                        vec![req]
                    } else {
                        let close = pdu::encode_confirmed_request(out, |w| {
                            file::write_close_request(w, frsm)
                        });
                        let saved = model
                            .file_provider()
                            .is_some_and(|p| p.write(&st.dest, &st.data).is_ok());
                        let resp = if saved {
                            pdu::encode_confirmed_response(st.invoke, |w| {
                                file::encode_obtain_response(w)
                            })
                        } else {
                            encode_error(st.invoke)
                        };
                        vec![close, resp]
                    }
                }
                Err(_) => vec![encode_error(st.invoke)],
            },
        }
    }

    async fn handle_read(
        &mut self,
        invoke: u32,
        service: &Tlv<'_>,
        model: &ServerModel,
        store: &Store,
    ) -> Vec<u8> {
        let vars = match read::decode_request(service) {
            // Lista explícita de variables.
            Ok(read::ReadTarget::Variables(v)) => v,
            // Dataset por nombre: resolver a sus miembros (readDataSetValues).
            // Busca primero entre los dinámicos de esta conexión, luego estáticos.
            Ok(read::ReadTarget::NamedList(domain, name)) => {
                let members = self
                    .dynamic_datasets
                    .get(&(domain.clone(), name.clone()))
                    .cloned()
                    .or_else(|| model.dataset_members(&domain, &name).map(|m| m.to_vec()));
                match members {
                    Some(m) => m,
                    None => {
                        // Dataset inexistente → un único fallo de acceso.
                        return pdu::encode_confirmed_response(invoke, |w| {
                            read::encode_response(
                                w,
                                &[AccessResult::Failure(DataAccessError::ObjectNonExistent)],
                            )
                        });
                    }
                }
            }
            Err(_) => return encode_error(invoke),
        };
        let guard = store.read().await;
        let results: Vec<AccessResult> = vars
            .iter()
            .map(|(d, i)| {
                // RBAC (IEC 62351-8): el rol debe permitir leer este item. Cubre
                // tanto Read como ReadDataSetValues (aquí `vars` son los miembros).
                if !self.role.may_read(i) {
                    return AccessResult::Failure(DataAccessError::ObjectAccessDenied);
                }
                // Select-before-operate: leer $SBO concede el control sólo si el
                // ctlModel es SBO (2/4); si no, cadena vacía = selección denegada.
                if let Some(base) = i.strip_suffix("$SBO") {
                    let kind = ctl_model_of(&guard, d, base);
                    if kind != 2 && kind != 4 {
                        return AccessResult::Success(MmsData::Visible(String::new()));
                    }
                    let timeout = sbo_timeout_of(&guard, d, base);
                    self.selections.insert(
                        (d.clone(), base.to_string()),
                        Selection {
                            expires: Instant::now() + timeout,
                        },
                    );
                    return AccessResult::Success(MmsData::Visible(i.clone()));
                }
                // Normaliza el sufijo de instancia MMS ("01") que añaden clientes
                // conformes (libiec61850): "EventsRCB01" → "EventsRCB".
                let i = &model.normalize_rcb_item(d, i);
                // Lectura del RCB completo (getRCBValues): ensamblar una estructura
                // con sus componentes en el orden 8-1.
                // RCB, SGCB o LCB completos: estructura con sus componentes en el
                // orden 8-1 (no el alfabético del namespace).
                if let Some(names) = model
                    .rcb_component_names(d, i)
                    .or_else(|| model.sgcb_component_names(d, i))
                    .or_else(|| model.lcb_component_names(d, i))
                {
                    let comps = names
                        .iter()
                        .map(|attr| {
                            guard
                                .get(&(d.clone(), format!("{i}${attr}")))
                                .cloned()
                                .unwrap_or(MmsData::Bool(false))
                        })
                        .collect();
                    return AccessResult::Success(MmsData::Structure(comps));
                }
                // Valor de setting group: la vista FC=SG devuelve el grupo activo
                // (ActSG); la FC=SE, el grupo en edición (EditSG) o su valor
                // pendiente de confirmar.
                if let Some(sr) = model.setting_ref(d, i) {
                    return match resolve_setting(model, &guard, d, &sr) {
                        Some(v) => AccessResult::Success(v),
                        None => AccessResult::Failure(DataAccessError::ObjectNonExistent),
                    };
                }
                // Hoja directa del store.
                if let Some(v) = guard.get(&(d.clone(), i.clone())) {
                    return AccessResult::Success(v.clone());
                }
                // Objeto compuesto (DO/SDO): ensamblar su estructura desde las hojas.
                if let Some(s) = model.assemble_structured(d, i, &guard) {
                    return AccessResult::Success(s);
                }
                AccessResult::Failure(DataAccessError::ObjectNonExistent)
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
    ) -> ServiceOutput {
        let Ok((vars, data)) = write::decode_request(service) else {
            return ServiceOutput::only(encode_error(invoke));
        };
        let mut results = Vec::with_capacity(vars.len());
        // `pre` va antes de la respuesta (LastApplError de un Write− de control);
        // `reports` después (reportes RCB, CommandTermination).
        let mut pre = Vec::new();
        let mut reports = Vec::new();

        for (k, (domain, item)) in vars.iter().enumerate() {
            let Some(value) = data.get(k).cloned() else {
                results.push(WriteResult::Failure(
                    DataAccessError::ObjectAttributeInconsistent,
                ));
                continue;
            };

            // Normaliza el sufijo de instancia MMS ("01") de items de RCB que
            // usan clientes conformes (libiec61850): "EventsRCB01$RptEna" →
            // "EventsRCB$RptEna". No afecta a variables que no son de RCB.
            let item = &model.normalize_rcb_item(domain, item);

            // RBAC (IEC 62351-8): el rol de la conexión debe permitir escribir
            // este item; si no, se rechaza con acceso denegado.
            if !self.role.may_write(item) {
                results.push(WriteResult::Failure(DataAccessError::ObjectAccessDenied));
                continue;
            }

            // Reserva de RCB (Resv/ResvTms, IEC 61850-7-2): un RCB reservado
            // por OTRA conexión (viva, o dentro de su ventana ResvTms tras
            // desconectar) no admite escrituras de esta.
            if let Some(denied) = self.check_rcb_reservation(domain, item, &value, model) {
                results.push(denied);
                continue;
            }

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
                    .general_interrogation(domain, base, &value, model, store)
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
                let (r, unsolicited) = self
                    .operate(domain, item, &value, model, store, change_tx)
                    .await;
                // Write− ⇒ el LastApplError lo precede; Write+ ⇒ la
                // CommandTermination (y su LastApplError si es negativa) lo sigue.
                if matches!(r, WriteResult::Failure(_)) {
                    pre.extend(unsolicited);
                } else {
                    reports.extend(unsolicited);
                }
                r
            } else if item.contains("$CO$") && item.ends_with("$Cancel") {
                if let Some(base) = item.strip_suffix("$Cancel") {
                    self.selections.remove(&(domain.clone(), base.to_string()));
                }
                WriteResult::Success
            } else if let Some(base) = item.strip_suffix("$SBOw") {
                // SelectWithValue: sólo modelos SBO (2/4); registra la selección
                // con su expiración (sboTimeout del CF o el defecto).
                let g = store.read().await;
                let kind = ctl_model_of(&g, domain, base);
                if kind == 2 || kind == 4 {
                    let timeout = sbo_timeout_of(&g, domain, base);
                    drop(g);
                    self.selections.insert(
                        (domain.clone(), base.to_string()),
                        Selection {
                            expires: Instant::now() + timeout,
                        },
                    );
                    WriteResult::Success
                } else {
                    drop(g);
                    pre.push(last_appl_error_for(
                        domain,
                        item,
                        &value,
                        crate::control::add_cause::NOT_SUPPORTED,
                    ));
                    WriteResult::Failure(DataAccessError::ObjectAccessDenied)
                }
            } else if let Some(sgw) = model.classify_sg_write(domain, item) {
                // Grupos de ajuste: SelectActiveSG/SelectEditSG (rango),
                // ConfirmEditSGValues, o escritura de un valor FC=SE/SG.
                handle_sg_write(model, store, change_tx, domain, item, value, sgw).await
            } else if model.contains(domain, item) {
                store_write(store, change_tx, domain, item, value).await
            } else {
                WriteResult::Failure(DataAccessError::ObjectNonExistent)
            };
            results.push(result);
        }
        ServiceOutput {
            pre,
            resp: pdu::encode_confirmed_response(invoke, |w| write::encode_response(w, &results)),
            post: reports,
        }
    }

    /// Aplica la semántica de reserva de RCB a una escritura entrante.
    /// Devuelve `Some(Failure)` si el RCB está reservado por otra conexión;
    /// `None` si la escritura puede continuar (y registra/libera la reserva
    /// cuando el atributo es `Resv`, `ResvTms` o `RptEna=true`).
    fn check_rcb_reservation(
        &mut self,
        domain: &str,
        item: &str,
        value: &MmsData,
        model: &ServerModel,
    ) -> Option<WriteResult> {
        let (base, attr) = item.rsplit_once('$')?;
        model.rcb_def(domain, base)?;
        let key = (domain.to_string(), base.to_string());
        let now = Instant::now();
        let mut g = self.reservations.lock().unwrap();

        if let Some(r) = g.get(&key) {
            if r.conn_id != self.conn_id && r.holds(now) {
                return Some(WriteResult::Failure(
                    DataAccessError::TemporarilyUnavailable,
                ));
            }
        }
        // Libre, mía, o expirada de otro: la escritura procede. Actualiza la
        // reserva según el atributo.
        match attr {
            "Resv" => {
                if matches!(value, MmsData::Bool(true)) {
                    g.insert(
                        key,
                        Reservation {
                            conn_id: self.conn_id,
                            resv_secs: 0,
                            until: None,
                        },
                    );
                } else {
                    g.remove(&key);
                }
            }
            "ResvTms" => {
                let secs = match value {
                    MmsData::Int(n) => (*n).max(0) as u32,
                    MmsData::Uint(n) => *n as u32,
                    _ => 0,
                };
                if secs > 0 {
                    g.insert(
                        key,
                        Reservation {
                            conn_id: self.conn_id,
                            resv_secs: secs,
                            until: None,
                        },
                    );
                } else {
                    g.remove(&key);
                }
            }
            "RptEna" if matches!(value, MmsData::Bool(true)) => {
                // Habilitar toma reserva implícita si el RCB estaba libre
                // (conserva una reserva mía previa, p. ej. con ResvTms).
                match g.get(&key) {
                    Some(r) if r.conn_id == self.conn_id => {}
                    _ => {
                        g.insert(
                            key,
                            Reservation {
                                conn_id: self.conn_id,
                                resv_secs: 0,
                                until: None,
                            },
                        );
                    }
                }
            }
            _ => {}
        }
        None
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
        // El nombre que viaja en los reportes (variableListName) es la forma
        // completa de 8-1 (`"IED1LD0/LLN0$ds1"`); dataset_members() tolera
        // cualquiera de las formas al resolver los miembros.
        let dataset_name = match get("DatSet") {
            Some(MmsData::Visible(s)) if !s.is_empty() => Some(s.clone()),
            _ => rcbdef.dataset_ref(),
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
        model: &ServerModel,
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
            .map(|m| member_value(model, &guard, m))
            .collect();
        drop(guard);
        rcb.seq_num += 1;
        Some(make_report(rcb, &all_included(rcb.members.len()), &values))
    }

    /// Ejecuta un `Oper` según el `ctlModel` del objeto (IEC 61850-7-2):
    /// 0 = status-only (no operable), 1 = direct-normal, 2 = sbo-normal,
    /// 3 = direct-enhanced, 4 = sbo-enhanced. Devuelve la respuesta Write y los
    /// informes no solicitados a emitir (LastApplError y/o CommandTermination).
    async fn operate(
        &mut self,
        domain: &str,
        oper_item: &str,
        value: &MmsData,
        model: &ServerModel,
        store: &Store,
        change_tx: &broadcast::Sender<ValueChange>,
    ) -> (WriteResult, Vec<Vec<u8>>) {
        use crate::control::add_cause;

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
                Vec::new(),
            );
        }

        let co_base = oper_item.trim_end_matches("$Oper").to_string();
        let (model_kind, blocked) = {
            let g = store.read().await;
            let kind = ctl_model_of(&g, domain, &co_base);
            let blk = interlock_check
                && cf_of_co(&co_base, "intlckBlk")
                    .map(|cf| matches!(g.get(&(domain.to_string(), cf)), Some(MmsData::Bool(true))))
                    .unwrap_or(false);
            (kind, blk)
        };
        let enhanced = model_kind == 3 || model_kind == 4;
        let sbo = model_kind == 2 || model_kind == 4;

        // status-only (o ctlModel desconocido): el objeto no es operable.
        if !(1..=4).contains(&model_kind) {
            let lae = last_appl_error_for(domain, oper_item, value, add_cause::NOT_SUPPORTED);
            return (
                WriteResult::Failure(DataAccessError::ObjectAccessDenied),
                vec![lae],
            );
        }

        // SBO: exige selección previa vigente (no expirada por sboTimeout).
        if sbo {
            let key = (domain.to_string(), co_base.clone());
            let now = Instant::now();
            let cause = match self.selections.get(&key) {
                None => Some(add_cause::OBJECT_NOT_SELECTED),
                Some(sel) if now >= sel.expires => Some(add_cause::TIME_LIMIT_OVER),
                Some(_) => None,
            };
            if let Some(cause) = cause {
                self.selections.remove(&key);
                let lae = last_appl_error_for(domain, oper_item, value, cause);
                return (
                    WriteResult::Failure(DataAccessError::ObjectAccessDenied),
                    vec![lae],
                );
            }
            // El comando consume la selección (one-shot).
            self.selections.remove(&key);
        }

        if !enhanced {
            if blocked {
                // Normal security: Write− con la causa en un LastApplError.
                let lae = last_appl_error_for(
                    domain,
                    oper_item,
                    value,
                    add_cause::BLOCKED_BY_INTERLOCKING,
                );
                return (
                    WriteResult::Failure(DataAccessError::ObjectAccessDenied),
                    vec![lae],
                );
            }
            apply_value(store, change_tx, domain.to_string(), status_item, ctl_val).await;
            return (WriteResult::Success, Vec::new());
        }

        // Enhanced: Write+ y luego CommandTermination (positiva/negativa). La
        // negativa va precedida del LastApplError con el AddCause (patrón 8-1).
        if blocked {
            let lae =
                last_appl_error_for(domain, oper_item, value, add_cause::BLOCKED_BY_INTERLOCKING);
            let term = report::encode_command_termination(
                domain,
                oper_item,
                value,
                false,
                DataAccessError::TemporarilyUnavailable.to_code(),
            );
            return (WriteResult::Success, vec![lae, term]);
        }
        apply_value(store, change_tx, domain.to_string(), status_item, ctl_val).await;
        let term = report::encode_command_termination(domain, oper_item, value, true, 0);
        (WriteResult::Success, vec![term])
    }

    /// Reportes a emitir ante un cambio de valor (disparo por dchg).
    async fn on_value_change(
        &mut self,
        change: &ValueChange,
        model: &ServerModel,
        store: &Store,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for rcb in self.rcbs.values_mut() {
            if !rcb.enabled || rcb.buffered {
                continue; // los BRCB se sirven por el buffer
            }
            let Some(idx) = member_covering(&rcb.members, &change.domain, &change.item) else {
                continue;
            };
            let member = rcb.members[idx].clone();
            let value = if member.1 == change.item {
                change.value.clone()
            } else {
                // Miembro a nivel DO (FCDA sin daName): reporta el DO completo.
                let guard = store.read().await;
                model
                    .assemble_structured(&member.0, &member.1, &guard)
                    .unwrap_or_else(|| change.value.clone())
            };
            if rcb.last_values.get(&member) != Some(&value) {
                rcb.last_values.insert(member, value.clone());
                rcb.seq_num += 1;
                let inclusion = single_included(rcb.members.len(), idx);
                out.push(make_report(rcb, &inclusion, std::slice::from_ref(&value)));
            }
        }
        out
    }

    /// Reportes de integridad periódica vencidos.
    async fn on_integrity(&mut self, model: &ServerModel, store: &Store) -> Vec<Vec<u8>> {
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
                .map(|m| member_value(model, &guard, m))
                .collect();
            rcb.seq_num += 1;
            out.push(make_report(rcb, &all_included(rcb.members.len()), &values));
            rcb.next_integrity = Some(now + Duration::from_millis(rcb.intg_pd as u64));
        }
        out
    }
}

/// Índice del miembro del dataset que **cubre** un item cambiado: coincidencia
/// exacta (miembro hoja) o por prefijo con separador `$` (miembro a nivel DO,
/// FCDA sin `daName` — el cambio de cualquier hoja contenida dispara el miembro).
fn member_covering(members: &[(String, String)], domain: &str, item: &str) -> Option<usize> {
    members.iter().position(|(d, i)| {
        d == domain
            && (i == item
                || item
                    .strip_prefix(i.as_str())
                    .is_some_and(|rest| rest.starts_with('$')))
    })
}

/// Valor actual de un miembro de dataset: hoja directa del almacén o, para
/// miembros a nivel DO, la estructura ensamblada recursivamente.
fn member_value(
    model: &ServerModel,
    guard: &HashMap<(String, String), MmsData>,
    member: &(String, String),
) -> MmsData {
    model
        .assemble_structured(&member.0, &member.1, guard)
        .or_else(|| guard.get(member).cloned())
        .unwrap_or(MmsData::Bool(false))
}

/// Item CF de un atributo del DO de control: `"LN$CO$<do>" + attr` →
/// `"LN$CF$<do>$attr"`. Devuelve `None` si la base no tiene forma `LN$CO$DO`.
fn cf_of_co(co_base: &str, attr: &str) -> Option<String> {
    let mut parts = co_base.split('$');
    let ln = parts.next()?;
    if parts.next()? != "CO" {
        return None;
    }
    let doi = parts.next()?;
    Some(format!("{ln}$CF${doi}${attr}"))
}

/// `ctlModel` del objeto de control (0 = status-only si no está definido).
fn ctl_model_of(guard: &HashMap<(String, String), MmsData>, domain: &str, co_base: &str) -> i64 {
    cf_of_co(co_base, "ctlModel")
        .and_then(|cf| guard.get(&(domain.to_string(), cf)).cloned())
        .map_or(0, |v| match v {
            MmsData::Int(n) => n,
            MmsData::Uint(n) => n as i64,
            _ => 0,
        })
}

/// `sboTimeout` del CF (ms); ausente o 0 → [`DEFAULT_SBO_TIMEOUT_MS`].
fn sbo_timeout_of(
    guard: &HashMap<(String, String), MmsData>,
    domain: &str,
    co_base: &str,
) -> Duration {
    let ms = cf_of_co(co_base, "sboTimeout")
        .and_then(|cf| guard.get(&(domain.to_string(), cf)).cloned())
        .map_or(0, |v| match v {
            MmsData::Int(n) => n.max(0) as u64,
            MmsData::Uint(n) => n,
            _ => 0,
        });
    Duration::from_millis(if ms == 0 { DEFAULT_SBO_TIMEOUT_MS } else { ms })
}

/// `LastApplError` de un comando de control rechazado: refleja origin/ctlNum
/// del `Oper` recibido y lleva el `AddCause` de la causa real.
fn last_appl_error_for(domain: &str, oper_item: &str, oper: &MmsData, cause: i64) -> Vec<u8> {
    let (or_cat, or_ident, ctl_num) = match oper {
        MmsData::Structure(f) => {
            let (cat, ident) = match f.get(1) {
                Some(MmsData::Structure(o)) => (
                    match o.first() {
                        Some(MmsData::Int(n)) => *n,
                        Some(MmsData::Uint(n)) => *n as i64,
                        _ => 0,
                    },
                    match o.get(1) {
                        Some(MmsData::Octets(b)) => b.clone(),
                        _ => Vec::new(),
                    },
                ),
                _ => (0, Vec::new()),
            };
            let num = match f.get(2) {
                Some(MmsData::Uint(n)) => *n,
                Some(MmsData::Int(n)) => *n as u64,
                _ => 0,
            };
            (cat, ident, num)
        }
        _ => (0, Vec::new(), 0),
    };
    report::encode_last_appl_error(&report::LastApplError {
        cntrl_obj: format!("{domain}/{oper_item}"),
        error: 1, // error-unknown
        or_cat,
        or_ident,
        ctl_num,
        add_cause: cause,
    })
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
/// `ReadJournal`: devuelve las entradas del journal (log) nombrado.
fn handle_read_journal(invoke: u32, service: &Tlv<'_>, model: &ServerModel) -> Vec<u8> {
    let Ok((domain, item)) = journal::decode_request(service) else {
        return encode_error(invoke);
    };
    match model.journal_entries(&domain, &item) {
        Some(entries) => {
            pdu::encode_confirmed_response(invoke, |w| journal::encode_response(w, &entries, false))
        }
        None => encode_error(invoke),
    }
}

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

/// Envía un PDU MMS en la fase de datos bajo el context-id de presentación
/// que el CLIENTE propuso para MMS en su CP (negociación ISO 8823).
async fn send_report(writer: &mut IsoWriter, mms_ctx: i64, pdu: &[u8]) -> Result<(), MmsError> {
    let ud = presentation::user_data(pdu, mms_ctx);
    writer.send_data(&session::data(&ud)).await
}
