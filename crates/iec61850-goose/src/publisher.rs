//! Publicador GOOSE: ante un cambio de estado incrementa `stNum`, reinicia
//! `sqNum` y retransmite con intervalos crecientes (backoff) hasta un máximo
//! estable.

use std::time::Duration;

use iec61850_ber::MmsData;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

use iec61850_l2::L2Link as GooseLink;

use crate::config::{GooseConfig, now_utc};
use crate::error::GooseError;
use crate::frame::GooseFrame;
use crate::pdu::GoosePdu;

/// Publicador GOOSE sobre un enlace `L`.
pub struct GoosePublisher<L> {
    link: L,
    config: GooseConfig,
}

impl<L: GooseLink> GoosePublisher<L> {
    pub fn new(link: L, config: GooseConfig) -> Self {
        Self { link, config }
    }

    /// Arranca la tarea de publicación y devuelve un handle para empujar valores.
    pub fn start(self) -> PublisherHandle {
        let (values_tx, values_rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run(self.link, self.config, values_rx, stop_rx));
        PublisherHandle {
            values_tx,
            stop_tx: Some(stop_tx),
            task,
        }
    }
}

/// Handle para inyectar nuevos valores y detener el publicador.
pub struct PublisherHandle {
    values_tx: mpsc::Sender<Vec<MmsData>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl PublisherHandle {
    /// Publica un nuevo conjunto de valores (dispara cambio de estado si difiere).
    pub async fn publish(&self, values: Vec<MmsData>) -> Result<(), GooseError> {
        self.values_tx
            .send(values)
            .await
            .map_err(|_| GooseError::Malformed("publicador detenido".into()))
    }

    /// Detiene el publicador y espera a que termine la tarea.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

async fn run<L: GooseLink>(
    link: L,
    config: GooseConfig,
    mut values_rx: mpsc::Receiver<Vec<MmsData>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut st_num: u32 = 1;
    let mut sq_num: u32 = 0;
    let mut last_values: Vec<MmsData> = Vec::new();
    let mut t = now_utc();
    let mut interval = config.t_min;
    let mut started = false;

    let timer = sleep(config.t_min);
    tokio::pin!(timer);

    loop {
        tokio::select! {
            _ = &mut stop_rx => break,

            maybe = values_rx.recv() => {
                let Some(values) = maybe else { break };
                if started && values == last_values {
                    continue; // sin cambio de estado: el ciclo de retransmisión sigue
                }
                if started {
                    st_num = st_num.wrapping_add(1);
                    if st_num == 0 {
                        st_num = 1; // stNum 0 reservado
                    }
                }
                sq_num = 0;
                last_values = values;
                t = now_utc();
                interval = config.t_min;
                started = true;
                send_frame(&link, &config, &last_values, st_num, sq_num, t, interval).await;
                timer.as_mut().reset(Instant::now() + interval);
            }

            _ = &mut timer, if started => {
                sq_num = sq_num.wrapping_add(1);
                interval = (interval * 2).min(config.t_max);
                send_frame(&link, &config, &last_values, st_num, sq_num, t, interval).await;
                timer.as_mut().reset(Instant::now() + interval);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_frame<L: GooseLink>(
    link: &L,
    config: &GooseConfig,
    values: &[MmsData],
    st_num: u32,
    sq_num: u32,
    t: iec61850_ber::UtcTime,
    next_interval: Duration,
) {
    let ttl_ms = (2 * next_interval.as_millis()).min(u32::MAX as u128) as u32;
    let pdu = GoosePdu {
        gocb_ref: config.gocb_ref.clone(),
        time_allowed_to_live: ttl_ms,
        dat_set: config.dat_set.clone(),
        go_id: config.go_id.clone(),
        t,
        st_num,
        sq_num,
        test: config.test,
        conf_rev: config.conf_rev,
        nds_com: false,
        num_dat_set_entries: values.len() as u32,
        all_data: values.to_vec(),
    };
    let frame = GooseFrame {
        dst: config.dst,
        src: config.src,
        vlan: config.vlan,
        appid: config.appid,
        simulation: config.simulation,
        pdu,
    };
    let bytes = match &config.security {
        Some(key) => frame.encode_signed(key),
        None => frame.encode(),
    };
    let _ = link.send(&bytes).await;
}
