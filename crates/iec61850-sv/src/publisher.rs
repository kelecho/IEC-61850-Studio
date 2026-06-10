//! Publicador SV: emite ASDUs a **tasa fija**, incrementando `smpCnt` en cada
//! periodo de muestreo, con la última muestra inyectada por la app.
//!
//! Limitación: a 4000 muestras/s el periodo es 250 µs; el `interval` de tokio no
//! garantiza tiempo real duro (jitter). Adecuado para pruebas/tasas moderadas,
//! no para protección.

use iec61850_l2::L2Link;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::{SvConfig, now_utc};
use crate::frame::SvFrame;
use crate::nine_two_le::NineTwoLe;
use crate::pdu::{Asdu, SvPdu};

/// Publicador SV sobre un enlace `L`.
pub struct SvPublisher<L> {
    link: L,
    config: SvConfig,
}

impl<L: L2Link> SvPublisher<L> {
    pub fn new(link: L, config: SvConfig) -> Self {
        Self { link, config }
    }

    /// Arranca la tarea de publicación a tasa fija.
    pub fn start(self) -> SvPublisherHandle {
        let (sample_tx, sample_rx) = watch::channel(Vec::new());
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run(self.link, self.config, sample_rx, stop_rx));
        SvPublisherHandle {
            sample_tx,
            stop_tx: Some(stop_tx),
            task,
        }
    }
}

/// Handle para inyectar la muestra actual y detener el publicador.
pub struct SvPublisherHandle {
    sample_tx: watch::Sender<Vec<u8>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl SvPublisherHandle {
    /// Fija la muestra cruda que se publicará en los siguientes periodos.
    pub fn set_sample(&self, bytes: Vec<u8>) {
        let _ = self.sample_tx.send(bytes);
    }
    /// Fija la muestra como dataset 9-2LE.
    pub fn set_9_2le(&self, n: &NineTwoLe) {
        self.set_sample(n.to_bytes().to_vec());
    }
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

async fn run<L: L2Link>(
    link: L,
    cfg: SvConfig,
    sample_rx: watch::Receiver<Vec<u8>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut smp_cnt: u16 = 0;
    let mut ticker = interval(cfg.sample_period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            _ = ticker.tick() => {
                let sample = sample_rx.borrow().clone();
                let asdu = Asdu {
                    sv_id: cfg.sv_id.clone(),
                    dat_set: cfg.dat_set.clone(),
                    smp_cnt,
                    conf_rev: cfg.conf_rev,
                    refr_tm: cfg.include_refr_tm.then(now_utc),
                    smp_synch: cfg.smp_synch,
                    smp_rate: Some(cfg.smp_rate),
                    sample,
                    smp_mod: None,
                };
                let frame = SvFrame {
                    dst: cfg.dst,
                    src: cfg.src,
                    vlan: cfg.vlan,
                    appid: cfg.appid,
                    simulation: cfg.simulation,
                    pdu: SvPdu { no_asdu: 1, asdus: vec![asdu] },
                };
                let _ = link.send(&frame.encode()).await;
                smp_cnt = if smp_cnt + 1 >= cfg.smp_cnt_wrap { 0 } else { smp_cnt + 1 };
            }
        }
    }
}
