//! Suscriptor GOOSE: recibe tramas, las decodifica, sigue `stNum`/`sqNum` por
//! `gocbRef` y emite eventos (cambio de estado, retransmisión, pérdida, TTL).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iec61850_ber::{MmsData, UtcTime};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

use iec61850_l2::L2Link as GooseLink;

use crate::frame::{GooseFrame, MacAddr};

/// Filtro opcional de tramas entrantes.
#[derive(Debug, Clone, Default)]
pub struct GooseFilter {
    pub gocb_ref: Option<String>,
    pub appid: Option<u16>,
    pub dst: Option<MacAddr>,
}

impl GooseFilter {
    fn accepts(&self, frame: &GooseFrame) -> bool {
        self.appid.is_none_or(|a| a == frame.appid)
            && self.dst.is_none_or(|d| d == frame.dst)
            && self
                .gocb_ref
                .as_ref()
                .is_none_or(|g| *g == frame.pdu.gocb_ref)
    }
}

/// Tipo de evento GOOSE detectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GooseEventKind {
    /// `stNum` cambió (o primera trama del control block).
    StateChange,
    /// Misma `stNum`, `sqNum` incrementó en 1.
    Retransmission,
    /// Salto en `sqNum` (posible pérdida de tramas).
    LossSuspected { expected_sq: u32, got_sq: u32 },
    /// Venció `timeAllowedToLive` sin recibir nueva trama.
    Expired,
}

/// Evento entregado al consumidor.
#[derive(Debug, Clone)]
pub struct GooseEvent {
    pub gocb_ref: String,
    pub go_id: String,
    pub dat_set: String,
    /// APPID de la trama GOOSE (cabecera de capa 2).
    pub appid: u16,
    /// MAC de origen del publicador.
    pub src: MacAddr,
    pub st_num: u32,
    pub sq_num: u32,
    pub conf_rev: u32,
    pub test: bool,
    /// Bit "Simulated" de Ed.2: la trama es simulada/de prueba.
    pub simulation: bool,
    pub t: UtcTime,
    pub time_allowed_to_live: u32,
    pub values: Vec<MmsData>,
    pub kind: GooseEventKind,
}

struct Track {
    last_st: u32,
    last_sq: u32,
    deadline: Instant,
    // datos para el evento Expired
    go_id: String,
    dat_set: String,
    appid: u16,
    src: MacAddr,
    simulation: bool,
}

/// Suscriptor GOOSE sobre un enlace `L`.
pub struct GooseSubscriber<L> {
    link: L,
    filter: GooseFilter,
    sim_mode: Arc<AtomicBool>,
}

impl<L: GooseLink> GooseSubscriber<L> {
    pub fn new(link: L, filter: GooseFilter) -> Self {
        Self {
            link,
            filter,
            sim_mode: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Activa el **modo simulación** (equivalente a `LPHD.Sim` de Ed.2): con él
    /// activo el suscriptor acepta las tramas simuladas (bit S=1) y, una vez
    /// recibida la primera para una suscripción, **ignora las reales** de ese
    /// control block; con él inactivo (por defecto) descarta las simuladas y solo
    /// procesa las reales.
    pub fn simulation_mode(self, on: bool) -> Self {
        self.sim_mode.store(on, Ordering::Relaxed);
        self
    }

    /// Arranca la tarea de recepción; devuelve un handle con el canal de eventos.
    pub fn start(self) -> SubscriberHandle {
        let (events_tx, events_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = oneshot::channel();
        let sim_mode = self.sim_mode.clone();
        let task = tokio::spawn(run(
            self.link,
            self.filter,
            self.sim_mode,
            events_tx,
            stop_rx,
        ));
        SubscriberHandle {
            events_rx,
            stop_tx: Some(stop_tx),
            task,
            sim_mode,
        }
    }
}

/// Handle para consumir eventos y detener el suscriptor.
pub struct SubscriberHandle {
    events_rx: mpsc::Receiver<GooseEvent>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    sim_mode: Arc<AtomicBool>,
}

impl SubscriberHandle {
    /// Recibe el siguiente evento; `None` si el enlace se cerró.
    pub async fn recv_event(&mut self) -> Option<GooseEvent> {
        self.events_rx.recv().await
    }

    /// Activa/desactiva el modo simulación en vivo (como escribir `LPHD.Sim`).
    pub fn set_simulation_mode(&self, on: bool) {
        self.sim_mode.store(on, Ordering::Relaxed);
    }

    /// Estado actual del modo simulación.
    pub fn simulation_mode(&self) -> bool {
        self.sim_mode.load(Ordering::Relaxed)
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(24 * 3600)
}

async fn run<L: GooseLink>(
    link: L,
    filter: GooseFilter,
    sim_mode: Arc<AtomicBool>,
    events_tx: mpsc::Sender<GooseEvent>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut tracks: HashMap<String, Track> = HashMap::new();
    // Suscripciones (gocbRef) cuyas tramas reales se ignoran por estar bajo
    // simulación (ya llegó al menos una trama simulada en modo Sim).
    let mut simulated_subs: HashSet<String> = HashSet::new();
    let sweep = sleep(Duration::from_secs(24 * 3600));
    tokio::pin!(sweep);

    loop {
        tokio::select! {
            _ = &mut stop_rx => break,

            r = link.recv() => {
                let Ok(bytes) = r else { break };
                let Ok(frame) = GooseFrame::decode(&bytes) else { continue };
                if !filter.accepts(&frame) {
                    continue;
                }
                if !sim_gate(
                    sim_mode.load(Ordering::Relaxed),
                    &mut simulated_subs,
                    &frame.pdu.gocb_ref,
                    frame.simulation,
                ) {
                    continue; // descartada según el modo simulación
                }
                let event = track_and_build(&mut tracks, frame);
                if events_tx.send(event).await.is_err() {
                    break;
                }
                sweep.as_mut().reset(next_deadline(&tracks));
            }

            _ = &mut sweep => {
                let now = Instant::now();
                let mut expired = Vec::new();
                for (gocb, tr) in tracks.iter() {
                    if tr.deadline <= now {
                        expired.push(gocb.clone());
                    }
                }
                for gocb in expired {
                    if let Some(tr) = tracks.remove(&gocb) {
                        let ev = GooseEvent {
                            gocb_ref: gocb,
                            go_id: tr.go_id,
                            dat_set: tr.dat_set,
                            appid: tr.appid,
                            src: tr.src,
                            st_num: tr.last_st,
                            sq_num: tr.last_sq,
                            conf_rev: 0,
                            test: false,
                            simulation: tr.simulation,
                            t: UtcTime { raw: [0; 8] },
                            time_allowed_to_live: 0,
                            values: Vec::new(),
                            kind: GooseEventKind::Expired,
                        };
                        if events_tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
                sweep.as_mut().reset(next_deadline(&tracks));
            }
        }
    }
}

fn next_deadline(tracks: &HashMap<String, Track>) -> Instant {
    tracks
        .values()
        .map(|t| t.deadline)
        .min()
        .unwrap_or_else(far_future)
}

/// Decide si procesar una trama según el modo simulación (IEC 61850-8-1 Ed.2):
/// - `sim` desactivado: solo tramas reales (descarta las simuladas).
/// - `sim` activado: acepta las simuladas y, una vez vista la primera para un
///   `gocbRef`, ignora las reales de ese control block hasta salir de Sim.
///
/// `simulated_subs` guarda los `gocbRef` ya "enganchados" a simulación; al salir
/// de Sim se limpia (se reengancha en la siguiente simulada).
fn sim_gate(
    sim: bool,
    simulated_subs: &mut HashSet<String>,
    gocb_ref: &str,
    frame_simulated: bool,
) -> bool {
    if !sim {
        if !simulated_subs.is_empty() {
            simulated_subs.clear();
        }
        return !frame_simulated; // en modo normal se descartan las simuladas
    }
    if frame_simulated {
        simulated_subs.insert(gocb_ref.to_string());
        true
    } else {
        // Trama real: se ignora si esta suscripción ya está bajo simulación.
        !simulated_subs.contains(gocb_ref)
    }
}

fn track_and_build(tracks: &mut HashMap<String, Track>, frame: GooseFrame) -> GooseEvent {
    let appid = frame.appid;
    let src = frame.src;
    let simulation = frame.simulation;
    let p = frame.pdu;
    let deadline = Instant::now() + Duration::from_millis(p.time_allowed_to_live as u64);

    let kind = match tracks.get(&p.gocb_ref) {
        None => GooseEventKind::StateChange,
        Some(prev) if p.st_num != prev.last_st => GooseEventKind::StateChange,
        Some(prev) if p.sq_num == prev.last_sq.wrapping_add(1) => GooseEventKind::Retransmission,
        Some(prev) if p.sq_num > prev.last_sq.wrapping_add(1) => GooseEventKind::LossSuspected {
            expected_sq: prev.last_sq.wrapping_add(1),
            got_sq: p.sq_num,
        },
        Some(_) => GooseEventKind::Retransmission, // duplicado / fuera de orden
    };

    tracks.insert(
        p.gocb_ref.clone(),
        Track {
            last_st: p.st_num,
            last_sq: p.sq_num,
            deadline,
            go_id: p.go_id.clone(),
            dat_set: p.dat_set.clone(),
            appid,
            src,
            simulation,
        },
    );

    GooseEvent {
        gocb_ref: p.gocb_ref,
        go_id: p.go_id,
        dat_set: p.dat_set,
        appid,
        src,
        st_num: p.st_num,
        sq_num: p.sq_num,
        conf_rev: p.conf_rev,
        test: p.test,
        simulation,
        t: p.t,
        time_allowed_to_live: p.time_allowed_to_live,
        values: p.all_data,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CB: &str = "IED1LD0/LLN0.GO$gcb01";
    const CB2: &str = "IED1LD0/LLN0.GO$gcb02";

    #[test]
    fn sim_off_drops_simulated_keeps_real() {
        let mut s = HashSet::new();
        assert!(sim_gate(false, &mut s, CB, false)); // real → procesa
        assert!(!sim_gate(false, &mut s, CB, true)); // simulada → descarta
    }

    #[test]
    fn sim_on_latches_then_ignores_real() {
        let mut s = HashSet::new();
        // Antes de la primera simulada, la real aún se procesa.
        assert!(sim_gate(true, &mut s, CB, false));
        // Llega una simulada → se procesa y engancha la suscripción.
        assert!(sim_gate(true, &mut s, CB, true));
        // Ahora las reales de ese CB se ignoran...
        assert!(!sim_gate(true, &mut s, CB, false));
        // ...pero un CB distinto, sin simulada aún, sigue procesando reales.
        assert!(sim_gate(true, &mut s, CB2, false));
    }

    #[test]
    fn leaving_sim_clears_latch() {
        let mut s = HashSet::new();
        assert!(sim_gate(true, &mut s, CB, true)); // engancha
        assert!(!sim_gate(true, &mut s, CB, false)); // real ignorada
        // Salir de Sim: limpia el latch y procesa reales otra vez.
        assert!(sim_gate(false, &mut s, CB, false));
        assert!(s.is_empty());
        // Reentrar en Sim: la real vuelve a procesarse hasta nueva simulada.
        assert!(sim_gate(true, &mut s, CB, false));
    }
}
