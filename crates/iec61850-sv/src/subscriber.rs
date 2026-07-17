//! Suscriptor SV: recibe tramas, decodifica cada ASDU, sigue `smpCnt` por `svID`
//! y emite eventos (muestra normal, pérdida, wrap).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iec61850_ber::UtcTime;
use iec61850_l2::L2Link;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::frame::SvFrame;
use crate::nine_two_le::NineTwoLe;
use iec61850_l2::{AuthStatus, MacAddr, Verifier};

/// Filtro opcional de tramas SV entrantes.
#[derive(Debug, Clone, Default)]
pub struct SvFilter {
    pub appid: Option<u16>,
    pub dst: Option<MacAddr>,
    pub sv_id: Option<String>,
}

/// Tipo de evento SV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvEventKind {
    /// Muestra consecutiva esperada.
    Sample,
    /// Salto de `smpCnt` (posible pérdida de muestras).
    SampleLoss { expected: u16, got: u16 },
    /// `smpCnt` volvió a 0 (fin de ciclo esperado).
    Wrap,
    /// Con seguridad exigida (IEC 62351-6), la trama llegó con firma inválida o
    /// sin firmar. Se entrega para diagnóstico sin actualizar el seguimiento.
    AuthFailed { status: AuthStatus },
}

/// Muestra SV entregada al consumidor (una por ASDU).
#[derive(Debug, Clone)]
pub struct SvEvent {
    pub sv_id: String,
    /// APPID de la trama SV (cabecera de capa 2).
    pub appid: u16,
    /// MAC de origen del publicador.
    pub src: MacAddr,
    /// Bit "Simulated" de Ed.2: la trama es simulada/de prueba.
    pub simulation: bool,
    pub smp_cnt: u16,
    pub conf_rev: u32,
    pub smp_synch: u8,
    pub smp_rate: Option<u16>,
    pub refr_tm: Option<UtcTime>,
    pub sample: Vec<u8>,
    pub decoded_9_2le: Option<NineTwoLe>,
    pub kind: SvEventKind,
}

/// Suscriptor SV sobre un enlace `L`.
pub struct SvSubscriber<L> {
    link: L,
    filter: SvFilter,
    sim_mode: Arc<AtomicBool>,
    security: Option<Verifier>,
}

impl<L: L2Link> SvSubscriber<L> {
    pub fn new(link: L, filter: SvFilter) -> Self {
        Self {
            link,
            filter,
            sim_mode: Arc::new(AtomicBool::new(false)),
            security: None,
        }
    }

    /// Exige autenticación (IEC 62351-6): solo se procesan las tramas con firma
    /// válida bajo el verificador dado (HMAC-SHA256 o ECDSA P-256); las no
    /// firmadas o manipuladas se entregan con `kind = AuthFailed` (para
    /// diagnóstico) sin actualizar el seguimiento.
    pub fn security(mut self, verifier: impl Into<Verifier>) -> Self {
        self.security = Some(verifier.into());
        self
    }

    /// Activa el **modo simulación** (`LPHD.Sim` de Ed.2): acepta las muestras
    /// simuladas (bit S=1) y, una vez vista la primera para un `svID`, ignora las
    /// reales de ese flujo; inactivo (por defecto) descarta las simuladas.
    pub fn simulation_mode(self, on: bool) -> Self {
        self.sim_mode.store(on, Ordering::Relaxed);
        self
    }

    pub fn start(self) -> SvSubscriberHandle {
        let (events_tx, events_rx) = mpsc::channel(256);
        let (stop_tx, stop_rx) = oneshot::channel();
        let sim_mode = self.sim_mode.clone();
        let task = tokio::spawn(run(
            self.link,
            self.filter,
            self.sim_mode,
            self.security,
            events_tx,
            stop_rx,
        ));
        SvSubscriberHandle {
            events_rx,
            stop_tx: Some(stop_tx),
            task,
            sim_mode,
        }
    }
}

/// Handle para consumir muestras y detener el suscriptor.
pub struct SvSubscriberHandle {
    events_rx: mpsc::Receiver<SvEvent>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    sim_mode: Arc<AtomicBool>,
}

impl SvSubscriberHandle {
    pub async fn recv_sample(&mut self) -> Option<SvEvent> {
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

/// Decide si procesar una muestra SV según el modo simulación (Ed.2), por `svID`.
/// Misma semántica que en GOOSE: sim off descarta simuladas; sim on acepta
/// simuladas y, una vez enganchado un `svID`, ignora sus reales.
fn sim_gate(
    sim: bool,
    simulated_subs: &mut HashSet<String>,
    sv_id: &str,
    frame_simulated: bool,
) -> bool {
    if !sim {
        if !simulated_subs.is_empty() {
            simulated_subs.clear();
        }
        return !frame_simulated;
    }
    if frame_simulated {
        simulated_subs.insert(sv_id.to_string());
        true
    } else {
        !simulated_subs.contains(sv_id)
    }
}

async fn run<L: L2Link>(
    link: L,
    filter: SvFilter,
    sim_mode: Arc<AtomicBool>,
    security: Option<Verifier>,
    events_tx: mpsc::Sender<SvEvent>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut last: HashMap<String, u16> = HashMap::new();
    let mut simulated_subs: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            r = link.recv() => {
                let Ok(bytes) = r else { break };
                // Con seguridad exigida (62351-6), verifica el HMAC de la trama;
                // si falla, las muestras se entregan como AuthFailed sin tracking.
                let (frame, fail_status) = match &security {
                    Some(key) => match SvFrame::decode_verified(&bytes, key) {
                        Ok((f, AuthStatus::Valid)) => (f, None),
                        Ok((f, status)) => (f, Some(status)),
                        Err(_) => continue,
                    },
                    None => match SvFrame::decode(&bytes) {
                        Ok(f) => (f, None),
                        Err(_) => continue,
                    },
                };
                if filter.appid.is_some_and(|a| a != frame.appid)
                    || filter.dst.is_some_and(|d| d != frame.dst) {
                    continue;
                }
                let appid = frame.appid;
                let src = frame.src;
                let simulation = frame.simulation;
                let sim = sim_mode.load(Ordering::Relaxed);
                for asdu in frame.pdu.asdus {
                    if filter.sv_id.as_ref().is_some_and(|s| *s != asdu.sv_id) {
                        continue;
                    }
                    if let Some(status) = fail_status {
                        let decoded_9_2le = asdu.as_9_2le();
                        let ev = SvEvent {
                            sv_id: asdu.sv_id,
                            appid,
                            src,
                            simulation,
                            smp_cnt: asdu.smp_cnt,
                            conf_rev: asdu.conf_rev,
                            smp_synch: asdu.smp_synch,
                            smp_rate: asdu.smp_rate,
                            refr_tm: asdu.refr_tm,
                            sample: asdu.sample,
                            decoded_9_2le,
                            kind: SvEventKind::AuthFailed { status },
                        };
                        if events_tx.send(ev).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    if !sim_gate(sim, &mut simulated_subs, &asdu.sv_id, simulation) {
                        continue; // descartada según el modo simulación
                    }
                    let kind = match last.get(&asdu.sv_id) {
                        None => SvEventKind::Sample,
                        Some(&prev) if asdu.smp_cnt == prev.wrapping_add(1) => SvEventKind::Sample,
                        Some(&prev) if asdu.smp_cnt == 0 && prev > 0 => SvEventKind::Wrap,
                        Some(&prev) if asdu.smp_cnt > prev.wrapping_add(1) => {
                            SvEventKind::SampleLoss { expected: prev.wrapping_add(1), got: asdu.smp_cnt }
                        }
                        Some(_) => SvEventKind::Sample,
                    };
                    last.insert(asdu.sv_id.clone(), asdu.smp_cnt);
                    let decoded_9_2le = asdu.as_9_2le();
                    let ev = SvEvent {
                        sv_id: asdu.sv_id,
                        appid,
                        src,
                        simulation,
                        smp_cnt: asdu.smp_cnt,
                        conf_rev: asdu.conf_rev,
                        smp_synch: asdu.smp_synch,
                        smp_rate: asdu.smp_rate,
                        refr_tm: asdu.refr_tm,
                        sample: asdu.sample,
                        decoded_9_2le,
                        kind,
                    };
                    if events_tx.send(ev).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_off_drops_simulated() {
        let mut s = HashSet::new();
        assert!(sim_gate(false, &mut s, "MU01", false));
        assert!(!sim_gate(false, &mut s, "MU01", true));
    }

    #[test]
    fn sim_on_latches_per_sv_id() {
        let mut s = HashSet::new();
        assert!(sim_gate(true, &mut s, "MU01", true)); // simulada engancha
        assert!(!sim_gate(true, &mut s, "MU01", false)); // real ignorada
        assert!(sim_gate(true, &mut s, "MU02", false)); // otro flujo sin enganchar
        // Salir de Sim limpia el latch.
        assert!(sim_gate(false, &mut s, "MU01", false));
        assert!(s.is_empty());
    }
}
