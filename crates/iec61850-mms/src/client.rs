//! Cliente MMS asíncrono (IEC 61850-8-1). Sólo con la feature `client`.
//!
//! Modelo **demultiplexor**: tras negociar la asociación se separa el socket y
//! una tarea de fondo lee todos los PDU, enrutando las respuestas confirmadas
//! por invokeID y los `InformationReport` no solicitados a un canal de reportes.
//! Esto permite que los métodos sean `&self` y que los reportes lleguen mientras
//! hay peticiones en curso.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use iec61850_model::{FunctionalConstraint, ObjectReference};
use tokio::net::ToSocketAddrs;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::ber::writer::BerWriter;
use crate::control::{self, ControlParameters};
use crate::error::MmsError;
use crate::mapping::{mms_to_object_reference, object_reference_to_mms};
use crate::mms::data::MmsData;
use crate::mms::file::{self, FileChunk, FileDirectory, FileOpen};
use crate::mms::get_name_list::{self, ObjectClass, ObjectScope};
use crate::mms::identify::{self, IdentifyResponse};
use crate::mms::initiate::{InitiateRequest, InitiateResponse};
use crate::mms::journal;
use crate::mms::named_var_list;
use crate::mms::pdu::{self, PduKind};
use crate::mms::read::{self, AccessResult};
use crate::mms::report::{self, CommandTermination, LastApplError, Report, ReportConfig};
use crate::mms::type_attr::{self, VariableAttributes};
use crate::mms::write::{self, WriteResult};
use crate::transport::connection::{IsoConnection, IsoReader};
use crate::transport::cotp;
use crate::upper::{acse, presentation, session};

const LOCAL_SRC_REF: u16 = 0x0001;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Plazo del handshake ISO (CR/CC + asociación). Acota el `connect()` ante un IED
/// que abre el TCP pero no completa la negociación.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Recibe un único TPDU del handshake con plazo.
async fn recv_with_timeout(conn: &mut IsoConnection) -> Result<Vec<u8>, MmsError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.recv()).await {
        Ok(r) => r,
        Err(_) => Err(MmsError::Timeout),
    }
}

/// Recibe un TSDU (reensamblando fragmentos DT) del handshake con plazo.
async fn recv_data_with_timeout(conn: &mut IsoConnection) -> Result<Vec<u8>, MmsError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.recv_data()).await {
        Ok(r) => r,
        Err(_) => Err(MmsError::Timeout),
    }
}

type PendingMap = HashMap<u32, oneshot::Sender<Result<Vec<u8>, MmsError>>>;

struct Shared {
    pending: Mutex<PendingMap>,
    /// Último `LastApplError` recibido (control): la causa detallada del último
    /// rechazo/terminación negativa, correlacionable por objeto de control.
    last_appl_error: std::sync::Mutex<Option<LastApplError>>,
}

/// Cliente MMS conectado y asociado a un servidor.
pub struct MmsClient {
    writer: Mutex<crate::transport::connection::IsoWriter>,
    shared: Arc<Shared>,
    next_invoke: AtomicU32,
    negotiated: InitiateResponse,
    report_rx: Option<mpsc::Receiver<Report>>,
    term_tx: broadcast::Sender<CommandTermination>,
    reader_task: JoinHandle<()>,
    request_timeout: Duration,
}

impl Drop for MmsClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl MmsClient {
    /// Conecta, establece COTP y negocia la asociación; luego separa el socket y
    /// lanza la tarea lectora de fondo.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<MmsClient, MmsError> {
        Self::handshake(IsoConnection::connect(addr).await?, None).await
    }

    /// Conecta autenticándose con un **password** (IEC 62351-4): el password
    /// viaja en el AARQ de la asociación. Recomendado solo sobre TLS.
    pub async fn connect_with_password<A: ToSocketAddrs>(
        addr: A,
        password: &str,
    ) -> Result<MmsClient, MmsError> {
        Self::handshake(
            IsoConnection::connect(addr).await?,
            Some(password.as_bytes()),
        )
        .await
    }

    /// Conecta presentando un **access token firmado** (RBAC, IEC 62351-8): el
    /// token (emitido por una autoridad y verificable por el servidor) viaja en el
    /// `authentication-value` del AARQ. El servidor extrae el rol del token, sin
    /// necesitar un mapeo estático de credenciales. Recomendado sobre TLS.
    pub async fn connect_with_token<A: ToSocketAddrs>(
        addr: A,
        token: &[u8],
    ) -> Result<MmsClient, MmsError> {
        Self::handshake(IsoConnection::connect(addr).await?, Some(token)).await
    }

    /// Conecta sobre **TLS** (mTLS, IEC 62351-3) y asocia. `server_name` es el
    /// nombre verificado contra el certificado del servidor. Requiere `tls`.
    #[cfg(feature = "tls")]
    pub async fn connect_tls<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        connector: tokio_rustls::TlsConnector,
    ) -> Result<MmsClient, MmsError> {
        Self::handshake(
            IsoConnection::connect_tls(addr, server_name, &connector).await?,
            None,
        )
        .await
    }

    /// Conecta sobre TLS y además autentica con **password** (62351-3 + 62351-4).
    #[cfg(feature = "tls")]
    pub async fn connect_tls_with_password<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        connector: tokio_rustls::TlsConnector,
        password: &str,
    ) -> Result<MmsClient, MmsError> {
        Self::handshake(
            IsoConnection::connect_tls(addr, server_name, &connector).await?,
            Some(password.as_bytes()),
        )
        .await
    }

    /// Negocia COTP + asociación MMS sobre una conexión ya abierta y lanza la
    /// tarea lectora de fondo. `password` añade autenticación ACSE (62351-4).
    async fn handshake(
        mut conn: IsoConnection,
        auth_value: Option<&[u8]>,
    ) -> Result<MmsClient, MmsError> {
        // COTP: CR → CC. El handshake va con timeout: un IED que no responde no
        // debe colgar `connect()` indefinidamente (antes `read_exact` bloqueaba
        // sin plazo).
        conn.send(&cotp::connection_request(LOCAL_SRC_REF)).await?;
        let cc = recv_with_timeout(&mut conn).await?;
        cotp::parse_connection_confirm(&cc)?;

        // Asociación MMS.
        let initiate = InitiateRequest::default().encode();
        let aarq = acse::aarq_auth(&initiate, auth_value);
        let cp = presentation::connect_cp(&aarq);
        conn.send(&cotp::data_tpdu(&session::connect(&cp))).await?;
        let resp = recv_data_with_timeout(&mut conn).await?;
        let aare = presentation::extract_inner_pdu(&resp)?;
        let negotiated = InitiateResponse::decode(acse::parse_aare(aare)?)?;

        // Separar y lanzar la tarea lectora.
        let (reader, writer) = conn.split();
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            last_appl_error: std::sync::Mutex::new(None),
        });
        let (report_tx, report_rx) = mpsc::channel(256);
        let (term_tx, _) = broadcast::channel(64);
        let reader_task = tokio::spawn(reader_loop(
            reader,
            shared.clone(),
            report_tx,
            term_tx.clone(),
        ));

        Ok(MmsClient {
            writer: Mutex::new(writer),
            shared,
            next_invoke: AtomicU32::new(1),
            negotiated,
            report_rx: Some(report_rx),
            term_tx,
            reader_task,
            request_timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Parámetros negociados en la asociación.
    pub fn negotiated(&self) -> &InitiateResponse {
        &self.negotiated
    }

    /// Ajusta el tiempo máximo de espera por respuesta.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Toma el receptor de reportes (una sola vez) para moverlo a otra tarea.
    pub fn take_report_rx(&mut self) -> Option<mpsc::Receiver<Report>> {
        self.report_rx.take()
    }

    /// Recibe el siguiente reporte (si no se ha tomado el receptor con
    /// [`take_report_rx`](Self::take_report_rx)). `None` si la conexión se cerró.
    pub async fn recv_report(&mut self) -> Option<Report> {
        match &mut self.report_rx {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    fn next_id(&self) -> u32 {
        self.next_invoke.fetch_add(1, Ordering::Relaxed).max(1)
    }

    /// Envía una Confirmed-Request y espera su respuesta (correlacionada por
    /// invokeID a través de la tarea lectora).
    async fn request(
        &self,
        write_service: impl FnOnce(&mut BerWriter),
    ) -> Result<Vec<u8>, MmsError> {
        let id = self.next_id();
        let pdu = pdu::encode_confirmed_request(id, write_service);

        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(id, tx);

        let framed = {
            let ud = presentation::user_data(&pdu, presentation::MMS_CONTEXT_ID);
            cotp::data_tpdu(&session::data(&ud))
        };
        if let Err(e) = self.writer.lock().await.send(&framed).await {
            self.shared.pending.lock().await.remove(&id);
            return Err(e);
        }

        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(MmsError::ConnectionClosed),
            Err(_) => {
                self.shared.pending.lock().await.remove(&id);
                Err(MmsError::Timeout)
            }
        }
    }

    // --- Servicios de lectura/identificación (Fase 2) ---

    pub async fn identify(&self) -> Result<IdentifyResponse, MmsError> {
        let pdu = self.request(identify::write_request).await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        identify::decode_response(&cr.service)
    }

    pub async fn get_server_directory(&self) -> Result<Vec<String>, MmsError> {
        self.get_name_list_all(ObjectClass::Domain, ObjectScope::VmdSpecific)
            .await
    }

    pub async fn get_logical_device_directory(
        &self,
        ld: &str,
    ) -> Result<Vec<ObjectReference>, MmsError> {
        let names = self
            .get_name_list_all(
                ObjectClass::NamedVariable,
                ObjectScope::DomainSpecific(ld.to_string()),
            )
            .await?;
        Ok(names
            .iter()
            .filter_map(|item| mms_to_object_reference(ld, item).ok())
            .collect())
    }

    pub async fn read(&self, obj: &ObjectReference) -> Result<MmsData, MmsError> {
        let (domain, item) = object_reference_to_mms(obj)?;
        self.read_raw(&domain, &item).await?.into_data()
    }

    pub async fn read_raw(&self, domain_id: &str, item_id: &str) -> Result<AccessResult, MmsError> {
        let pdu = self
            .request(|w| read::write_request(w, domain_id, item_id))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        read::decode_response(&cr.service)?
            .pop()
            .ok_or(MmsError::UnexpectedPdu)
    }

    /// Lee todos los valores de un dataset **por nombre** (`readDataSetValues`):
    /// funciona con datasets estáticos (SCL) y dinámicos.
    pub async fn read_data_set(&self, domain: &str, name: &str) -> Result<Vec<MmsData>, MmsError> {
        let pdu = self
            .request(|w| read::write_data_set_request(w, domain, name))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        read::decode_response(&cr.service)?
            .into_iter()
            .map(|r| r.into_data())
            .collect()
    }

    // --- Logs (ReadJournal, ISO 9506) ---

    /// Lee las entradas de un **log** (`ReadJournal`). `domain` es el LD e `item`
    /// el nombre del journal (`"<LN>$<LogName>"`, p. ej. `"LLN0$EventLog"`).
    /// Devuelve las entradas y si hay más por leer (`moreFollows`).
    pub async fn read_journal(
        &self,
        domain: &str,
        item: &str,
    ) -> Result<(Vec<journal::JournalEntry>, bool), MmsError> {
        let pdu = self
            .request(|w| journal::write_request(w, domain, item))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        journal::decode_response(&cr.service)
    }

    // --- Grupos de ajustes (SGCB, IEC 61850-7-2) ---

    /// Selecciona el **grupo de ajustes activo** (`SelectActiveSG`): escribe
    /// `ActSG` del SGCB. `sgcb` es la referencia del bloque (`LD/LLN0.SGCB[SP]`).
    pub async fn select_active_sg(
        &self,
        sgcb: &ObjectReference,
        group: u32,
    ) -> Result<(), MmsError> {
        let mut obj = sgcb.clone();
        obj.path.push("ActSG".to_string());
        self.write(&obj, MmsData::Uint(group as u64)).await
    }

    /// Selecciona el grupo de ajustes en **edición** (`SelectEditSG`): escribe
    /// `EditSG` del SGCB.
    pub async fn select_edit_sg(&self, sgcb: &ObjectReference, group: u32) -> Result<(), MmsError> {
        let mut obj = sgcb.clone();
        obj.path.push("EditSG".to_string());
        self.write(&obj, MmsData::Uint(group as u64)).await
    }

    /// Confirma los valores editados del grupo en edición (`ConfirmEditSGValues`):
    /// escribe `CnfEdit = true` en el SGCB. Los valores escritos con FC=SE pasan a
    /// formar parte del grupo seleccionado con `select_edit_sg`.
    pub async fn confirm_edit_sg(&self, sgcb: &ObjectReference) -> Result<(), MmsError> {
        let mut obj = sgcb.clone();
        obj.path.push("CnfEdit".to_string());
        self.write(&obj, MmsData::Bool(true)).await
    }

    // --- Datasets dinámicos (named variable lists, IEC 61850-8-1 Ed.2) ---

    /// Crea un dataset dinámico (`DefineNamedVariableList`) en `domain` con el
    /// nombre `name` y los `members` indicados como `(domainId, itemId)` MMS.
    pub async fn create_data_set(
        &self,
        domain: &str,
        name: &str,
        members: &[(String, String)],
    ) -> Result<(), MmsError> {
        let pdu = self
            .request(|w| named_var_list::write_define_request(w, domain, name, members))
            .await?;
        let _ = pdu::parse_confirmed_response(&pdu)?;
        Ok(())
    }

    /// Borra un dataset dinámico (`DeleteNamedVariableList`). Devuelve cuántas
    /// listas coincidieron y cuántas se borraron.
    pub async fn delete_data_set(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<named_var_list::DeleteResult, MmsError> {
        let pdu = self
            .request(|w| named_var_list::write_delete_request(w, domain, name))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        named_var_list::decode_delete_response(&cr.service)
    }

    /// Obtiene los atributos de un dataset (`GetNamedVariableListAttributes`):
    /// si es borrable y sus miembros. Funciona con datasets estáticos y dinámicos.
    pub async fn get_data_set_directory(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<named_var_list::ListAttributes, MmsError> {
        let pdu = self
            .request(|w| named_var_list::write_get_attributes_request(w, domain, name))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        named_var_list::decode_get_attributes_response(&cr.service)
    }

    // --- Introspección de tipos (GetVariableAccessAttributes) ---

    /// Obtiene la especificación de tipo de una variable, **sin necesidad del SCL**.
    /// Útil para explorar IEDs desconocidos: revela si un objeto es un escalar
    /// (bool/int/float…) o una estructura/array, y sus componentes.
    pub async fn type_attributes(
        &self,
        obj: &ObjectReference,
    ) -> Result<VariableAttributes, MmsError> {
        let (domain, item) = object_reference_to_mms(obj)?;
        self.type_attributes_raw(&domain, &item).await
    }

    /// Variante por `(domainId, itemId)` MMS crudos.
    pub async fn type_attributes_raw(
        &self,
        domain_id: &str,
        item_id: &str,
    ) -> Result<VariableAttributes, MmsError> {
        let pdu = self
            .request(|w| type_attr::write_request(w, domain_id, item_id))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        type_attr::decode_response(&cr.service)
    }

    // --- Transferencia de ficheros (disturbance records, COMTRADE, logs) ---

    /// Lista el directorio de ficheros del IED. `prefix` filtra por ruta;
    /// `continue_after` reanuda una lista paginada (`more_follows`).
    pub async fn file_directory(
        &self,
        prefix: Option<&str>,
        continue_after: Option<&str>,
    ) -> Result<FileDirectory, MmsError> {
        let pdu = self
            .request(|w| file::write_directory_request(w, prefix, continue_after))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        file::decode_directory_response(&cr.service)
    }

    /// Abre un fichero para lectura desde `initial_position`. Devuelve el handle
    /// (`frsmID`) y los atributos (tamaño/fecha).
    pub async fn file_open(&self, name: &str, initial_position: u32) -> Result<FileOpen, MmsError> {
        let pdu = self
            .request(|w| file::write_open_request(w, name, initial_position))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        file::decode_open_response(&cr.service)
    }

    /// Lee el siguiente bloque de un fichero abierto.
    pub async fn file_read(&self, frsm_id: i32) -> Result<FileChunk, MmsError> {
        let pdu = self
            .request(|w| file::write_read_request(w, frsm_id))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        file::decode_read_response(&cr.service)
    }

    /// Cierra un fichero abierto (libera el `frsmID`).
    pub async fn file_close(&self, frsm_id: i32) -> Result<(), MmsError> {
        let pdu = self
            .request(|w| file::write_close_request(w, frsm_id))
            .await?;
        // La respuesta es NULL; basta con que no sea error/reject.
        pdu::parse_confirmed_response(&pdu)?;
        Ok(())
    }

    /// Descarga un fichero completo: abre, lee por bloques hasta `more_follows =
    /// false` y cierra. Conveniencia para recuperar oscilografías/registros.
    pub async fn download_file(&self, name: &str) -> Result<Vec<u8>, MmsError> {
        let open = self.file_open(name, 0).await?;
        let mut out = Vec::with_capacity(open.attributes.size as usize);
        loop {
            let chunk = self.file_read(open.frsm_id).await?;
            out.extend_from_slice(&chunk.data);
            if !chunk.more_follows {
                break;
            }
        }
        self.file_close(open.frsm_id).await?;
        Ok(out)
    }

    // --- Write ---

    pub async fn write(&self, obj: &ObjectReference, value: MmsData) -> Result<(), MmsError> {
        let (domain, item) = object_reference_to_mms(obj)?;
        self.write_raw(&domain, &item, &value).await?.into_result()
    }

    pub async fn write_raw(
        &self,
        domain_id: &str,
        item_id: &str,
        value: &MmsData,
    ) -> Result<WriteResult, MmsError> {
        let pdu = self
            .request(|w| write::write_request(w, domain_id, item_id, value))
            .await?;
        let cr = pdu::parse_confirmed_response(&pdu)?;
        write::decode_response(&cr.service)?
            .pop()
            .ok_or(MmsError::UnexpectedPdu)
    }

    // --- Control (IEC 61850-7-2, seguridad normal) ---

    /// Control directo: escribe `Oper` con parámetros por defecto.
    pub async fn operate(
        &self,
        do_control: &ObjectReference,
        ctl_val: MmsData,
    ) -> Result<(), MmsError> {
        self.operate_with(do_control, ctl_val, &ControlParameters::default())
            .await
    }

    /// Control directo con parámetros explícitos (origin, ctlNum, Test, Check).
    /// Un Write− acompañado de `LastApplError` se devuelve como
    /// [`MmsError::ControlTerminated`] con su AddCause.
    pub async fn operate_with(
        &self,
        do_control: &ObjectReference,
        ctl_val: MmsData,
        params: &ControlParameters,
    ) -> Result<(), MmsError> {
        let oper = control::build_oper(ctl_val, params, control::now_utc());
        let (domain, item) = control_item(do_control, "Oper")?;
        let res = self.write_raw(&domain, &item, &oper).await?.into_result();
        self.map_control_failure(&item, res)
    }

    /// Select-before-operate (seguridad normal): lee `SBO`. `true` = concedido.
    pub async fn select(&self, do_control: &ObjectReference) -> Result<bool, MmsError> {
        let (domain, item) = control_item(do_control, "SBO")?;
        match self.read_raw(&domain, &item).await? {
            AccessResult::Success(MmsData::Visible(s)) => Ok(!s.is_empty()),
            AccessResult::Success(_) => Ok(true),
            AccessResult::Failure(e) => Err(MmsError::DataAccess(e)),
        }
    }

    /// Select-with-value: escribe `SBOw` (estructura igual a `Oper`). Si el
    /// servidor rechaza con un `LastApplError`, devuelve
    /// [`MmsError::ControlTerminated`] con su AddCause.
    pub async fn select_with_value(
        &self,
        do_control: &ObjectReference,
        ctl_val: MmsData,
        params: &ControlParameters,
    ) -> Result<(), MmsError> {
        let sbow = control::build_oper(ctl_val, params, control::now_utc());
        let (domain, item) = control_item(do_control, "SBOw")?;
        let res = self.write_raw(&domain, &item, &sbow).await?.into_result();
        self.map_control_failure(&item, res)
    }

    /// Causa detallada (`LastApplError`) del último fallo de control recibido,
    /// si la hay. Consultarlo la consume.
    pub fn take_last_appl_error(&self) -> Option<LastApplError> {
        self.shared.last_appl_error.lock().unwrap().take()
    }

    /// Si el Write de control falló y hay un `LastApplError` del mismo objeto,
    /// convierte el error en [`MmsError::ControlTerminated`] con su AddCause.
    fn map_control_failure(&self, item: &str, res: Result<(), MmsError>) -> Result<(), MmsError> {
        let Err(e) = res else { return Ok(()) };
        let mut g = self.shared.last_appl_error.lock().unwrap();
        if let Some(lae) = g.as_ref() {
            if lae.cntrl_obj.ends_with(item) {
                let add_cause = lae.add_cause;
                *g = None;
                return Err(MmsError::ControlTerminated { add_cause });
            }
        }
        Err(e)
    }

    // --- Control de seguridad reforzada (enhanced security) ---

    /// Suscribe un receptor de [`CommandTermination`] (control reforzado).
    pub fn subscribe_terminations(&self) -> broadcast::Receiver<CommandTermination> {
        self.term_tx.subscribe()
    }

    /// Control con **seguridad reforzada**: escribe `Oper` y espera la
    /// `CommandTermination` correlacionada por objeto. Positiva ⇒ `Ok(())`;
    /// negativa ⇒ [`MmsError::ControlTerminated`]; sin respuesta ⇒
    /// [`MmsError::ControlTimeout`].
    pub async fn operate_enhanced(
        &self,
        do_control: &ObjectReference,
        ctl_val: MmsData,
        params: &ControlParameters,
    ) -> Result<(), MmsError> {
        let oper = control::build_oper(ctl_val, params, control::now_utc());
        let (domain, item) = control_item(do_control, "Oper")?;
        // Suscribir ANTES de enviar para no perder la terminación.
        let mut term_rx = self.term_tx.subscribe();
        // Write+ : la petición Oper fue aceptada. Un Write− de control llega
        // precedido de un LastApplError con el AddCause (p. ej. 18 =
        // object-not-selected): se convierte en ControlTerminated.
        let res = self.write_raw(&domain, &item, &oper).await?.into_result();
        self.map_control_failure(&item, res)?;
        loop {
            match tokio::time::timeout(params.select_timeout, term_rx.recv()).await {
                Ok(Ok(ct)) if ct.object_item == item => {
                    return if ct.positive {
                        Ok(())
                    } else {
                        Err(MmsError::ControlTerminated {
                            add_cause: ct.add_cause.unwrap_or(0),
                        })
                    };
                }
                Ok(Ok(_)) => continue, // otra terminación, seguir esperando
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return Err(MmsError::ConnectionClosed);
                }
                Err(_) => return Err(MmsError::ControlTimeout),
            }
        }
    }

    /// Cancela una selección/operación pendiente (escribe `Cancel`).
    pub async fn cancel(
        &self,
        do_control: &ObjectReference,
        params: &ControlParameters,
    ) -> Result<(), MmsError> {
        let cancel = control::build_oper(MmsData::Bool(false), params, control::now_utc());
        let (domain, item) = control_item(do_control, "Cancel")?;
        self.write_raw(&domain, &item, &cancel).await?.into_result()
    }

    // --- Reporting ---

    /// Configura y habilita un RCB (URCB o BRCB según la FC de `rcb`).
    pub async fn enable_report(
        &self,
        rcb: &ObjectReference,
        cfg: &ReportConfig,
    ) -> Result<(), MmsError> {
        if let Some(ds) = &cfg.dataset {
            self.write_rcb_attr(rcb, "DatSet", MmsData::Visible(ds.clone()))
                .await?;
        }
        if let Some(t) = &cfg.trg_ops {
            self.write_rcb_attr(rcb, "TrgOps", MmsData::BitString(t.clone()))
                .await?;
        }
        if let Some(o) = &cfg.opt_flds {
            self.write_rcb_attr(rcb, "OptFlds", MmsData::BitString(o.clone()))
                .await?;
        }
        if let Some(p) = cfg.integrity_period {
            self.write_rcb_attr(rcb, "IntgPd", MmsData::Uint(p as u64))
                .await?;
        }
        if let Some(b) = cfg.buf_time {
            self.write_rcb_attr(rcb, "BufTm", MmsData::Uint(b as u64))
                .await?;
        }
        self.write_rcb_attr(rcb, "RptEna", MmsData::Bool(true))
            .await?;
        if cfg.general_interrogation {
            self.write_rcb_attr(rcb, "GI", MmsData::Bool(true)).await?;
        }
        Ok(())
    }

    /// Deshabilita un RCB (`RptEna = false`).
    pub async fn disable_report(&self, rcb: &ObjectReference) -> Result<(), MmsError> {
        self.write_rcb_attr(rcb, "RptEna", MmsData::Bool(false))
            .await
    }

    /// Solicita una interrogación general (`GI = true`).
    pub async fn general_interrogation(&self, rcb: &ObjectReference) -> Result<(), MmsError> {
        self.write_rcb_attr(rcb, "GI", MmsData::Bool(true)).await
    }

    async fn write_rcb_attr(
        &self,
        rcb: &ObjectReference,
        attr: &str,
        value: MmsData,
    ) -> Result<(), MmsError> {
        let mut obj = rcb.clone();
        obj.path.push(attr.to_string());
        let (domain, item) = object_reference_to_mms(&obj)?;
        self.write_raw(&domain, &item, &value).await?.into_result()
    }

    async fn get_name_list_all(
        &self,
        class: ObjectClass,
        scope: ObjectScope,
    ) -> Result<Vec<String>, MmsError> {
        let mut out: Vec<String> = Vec::new();
        let mut continue_after: Option<String> = None;
        loop {
            let cont = continue_after.clone();
            let pdu = self
                .request(|w| get_name_list::write_request(w, class, &scope, cont.as_deref()))
                .await?;
            let cr = pdu::parse_confirmed_response(&pdu)?;
            let page = get_name_list::decode_response(&cr.service)?;
            let last = page.identifiers.last().cloned();
            out.extend(page.identifiers);
            match (page.more_follows, last) {
                (true, Some(l)) => continue_after = Some(l),
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Mapea una referencia a DO de control + componente (`Oper`/`SBO`/`SBOw`) a
/// nombres MMS, forzando FC=CO si no viene en la referencia.
fn control_item(
    do_control: &ObjectReference,
    component: &str,
) -> Result<(String, String), MmsError> {
    let mut obj = do_control.clone();
    if obj.fc.is_none() {
        obj.fc = Some(FunctionalConstraint::CO);
    }
    obj.path.push(component.to_string());
    Ok(object_reference_to_mms(&obj)?)
}

/// Bucle de la tarea lectora: demultiplexa respuestas y reportes.
async fn reader_loop(
    mut reader: IsoReader,
    shared: Arc<Shared>,
    report_tx: mpsc::Sender<Report>,
    term_tx: broadcast::Sender<CommandTermination>,
) {
    loop {
        match reader.recv_data().await {
            Ok(tsdu) => {
                let Ok(pdu) = presentation::extract_inner_pdu(&tsdu) else {
                    continue;
                };
                match pdu::peek_invoke_and_kind(pdu) {
                    Ok((PduKind::Unconfirmed, _)) => {
                        if let Ok(svc) = pdu::parse_unconfirmed(pdu) {
                            // Un LastApplError guarda la causa detallada del último
                            // fallo de control; una CommandTermination va a su propio
                            // canal (fusionando el AddCause del LastApplError previo);
                            // el resto son reportes RCB.
                            if let Some(lae) = report::parse_last_appl_error(&svc) {
                                *shared.last_appl_error.lock().unwrap() = Some(lae);
                            } else if let Some(mut ct) = report::parse_command_termination(&svc) {
                                if !ct.positive {
                                    let mut g = shared.last_appl_error.lock().unwrap();
                                    if let Some(lae) = g.as_ref() {
                                        if lae.cntrl_obj.ends_with(&ct.object_item) {
                                            ct.add_cause = Some(lae.add_cause);
                                            *g = None;
                                        }
                                    }
                                }
                                let _ = term_tx.send(ct);
                            } else if let Ok(report) = report::decode_information_report(&svc) {
                                let _ = report_tx.send(report).await;
                            }
                        }
                    }
                    Ok((_, Some(id))) => {
                        if let Some(tx) = shared.pending.lock().await.remove(&id) {
                            let _ = tx.send(Ok(pdu.to_vec()));
                        }
                    }
                    _ => {} // Other / sin invokeID → descartar
                }
            }
            Err(_) => {
                // conexión cerrada: notificar a todos los pendientes y cerrar reportes.
                let mut pending = shared.pending.lock().await;
                for (_, tx) in pending.drain() {
                    let _ = tx.send(Err(MmsError::ConnectionClosed));
                }
                break;
            }
        }
    }
}
