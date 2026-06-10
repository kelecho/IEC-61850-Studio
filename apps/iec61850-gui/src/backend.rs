//! Puente entre la UI (egui, hilo principal) y el cliente MMS asíncrono, que
//! vive en un hilo con su propio runtime tokio. La UI envía [`Cmd`] (canal
//! tokio no acotado) y recibe [`Evt`] (canal `std::sync::mpsc`, sondeado cada
//! frame). El backend despierta la UI con `egui::Context::request_repaint`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::Sender as StdSender;

use eframe::egui;
use iec61850::ObjectReference;
use iec61850::mms::{MmsClient, MmsData, Report};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Comandos de la UI hacia el backend.
pub enum Cmd {
    Connect(String),
    Disconnect,
    Discover,
    Read(ObjectReference),
    EnableReport(ObjectReference),
    DisableReport(ObjectReference),
    /// Escribe un valor en una variable (modifica el IED).
    Write(ObjectReference, MmsData),
    /// Control directo: escribe `Oper` con `ctlVal` (modifica el IED).
    Operate(ObjectReference, MmsData),
    /// Select-before-operate (lectura de `SBO`): reserva el control.
    Select(ObjectReference),
}

/// Eventos del backend hacia la UI.
pub enum Evt {
    Connected(String),
    Disconnected,
    Error(String),
    /// Resultado positivo de una acción (escritura/operate/select).
    Ack(String),
    Directory(Vec<String>),
    Items {
        domain: String,
        items: Vec<String>,
    },
    ReadResult {
        reference: String,
        value: String,
    },
    Report(ReportView),
}

/// Resumen de un [`Report`] listo para mostrar (sin tipos con lifetime).
pub struct ReportView {
    pub rpt_id: String,
    pub seq_num: Option<u64>,
    pub dataset: Option<String>,
    pub entry_id: Option<String>,
    pub entries: Vec<String>,
}

impl ReportView {
    fn from(r: &Report) -> Self {
        ReportView {
            rpt_id: r.rpt_id.clone(),
            seq_num: r.seq_num,
            dataset: r.dataset.clone(),
            entry_id: r.entry_id.as_ref().map(|b| hex(b)),
            entries: r
                .entries
                .iter()
                .map(|e| format!("[{}] {}", e.member_index, fmt_value(&e.value)))
                .collect(),
        }
    }
}

/// Lanza el hilo backend con su runtime tokio. Devuelve el emisor de comandos.
pub fn spawn(evt_tx: StdSender<Evt>, ctx: egui::Context) -> UnboundedSender<Cmd> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime tokio");
        rt.block_on(actor(cmd_rx, evt_tx, ctx));
    });
    cmd_tx
}

async fn actor(mut cmd_rx: UnboundedReceiver<Cmd>, evt_tx: StdSender<Evt>, ctx: egui::Context) {
    let mut client: Option<Arc<MmsClient>> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Connect(addr) => match MmsClient::connect(&addr).await {
                Ok(mut c) => {
                    let neg = format!("asociado (MMS v{})", c.negotiated().version);
                    // Reenvía los reportes no solicitados a la UI.
                    if let Some(mut rx) = c.take_report_rx() {
                        let etx = evt_tx.clone();
                        let cx = ctx.clone();
                        tokio::spawn(async move {
                            while let Some(r) = rx.recv().await {
                                let _ = etx.send(Evt::Report(ReportView::from(&r)));
                                cx.request_repaint();
                            }
                        });
                    }
                    client = Some(Arc::new(c));
                    emit(&evt_tx, &ctx, Evt::Connected(neg));
                }
                Err(e) => emit(&evt_tx, &ctx, Evt::Error(format!("conexión: {e}"))),
            },
            Cmd::Disconnect => {
                client = None; // Drop aborta la tarea lectora y cierra el stream de reportes.
                emit(&evt_tx, &ctx, Evt::Disconnected);
            }
            Cmd::Discover => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    tokio::spawn(async move {
                        match c.get_server_directory().await {
                            Ok(domains) => {
                                let _ = etx.send(Evt::Directory(domains.clone()));
                                for d in domains {
                                    match c.get_logical_device_directory(&d).await {
                                        Ok(items) => {
                                            let items =
                                                items.iter().map(|r| r.to_string()).collect();
                                            let _ = etx.send(Evt::Items { domain: d, items });
                                        }
                                        Err(e) => {
                                            let _ = etx.send(Evt::Error(format!("items {d}: {e}")));
                                        }
                                    }
                                }
                                cx.request_repaint();
                            }
                            Err(e) => {
                                let _ = etx.send(Evt::Error(format!("descubrir: {e}")));
                                cx.request_repaint();
                            }
                        }
                    });
                }
            }
            Cmd::Read(obj) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    let reference = obj.to_string();
                    tokio::spawn(async move {
                        let value = match c.read(&obj).await {
                            Ok(v) => fmt_value(&v),
                            Err(e) => format!("<error: {e}>"),
                        };
                        let _ = etx.send(Evt::ReadResult { reference, value });
                        cx.request_repaint();
                    });
                }
            }
            Cmd::EnableReport(rcb) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = c.enable_report(&rcb, &Default::default()).await {
                            let _ = etx.send(Evt::Error(format!("habilitar reporte: {e}")));
                            cx.request_repaint();
                        }
                    });
                }
            }
            Cmd::DisableReport(rcb) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = c.disable_report(&rcb).await {
                            let _ = etx.send(Evt::Error(format!("deshabilitar reporte: {e}")));
                            cx.request_repaint();
                        }
                    });
                }
            }
            Cmd::Write(obj, value) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    let reference = obj.to_string();
                    tokio::spawn(async move {
                        let evt = match c.write(&obj, value).await {
                            Ok(()) => Evt::Ack(format!("escrito: {reference}")),
                            Err(e) => Evt::Error(format!("escritura {reference}: {e}")),
                        };
                        let _ = etx.send(evt);
                        cx.request_repaint();
                    });
                }
            }
            Cmd::Operate(obj, ctl_val) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    let reference = obj.to_string();
                    tokio::spawn(async move {
                        let evt = match c.operate(&obj, ctl_val).await {
                            Ok(()) => Evt::Ack(format!("operado: {reference}")),
                            Err(e) => Evt::Error(format!("operate {reference}: {e}")),
                        };
                        let _ = etx.send(evt);
                        cx.request_repaint();
                    });
                }
            }
            Cmd::Select(obj) => {
                if let Some(c) = client.clone() {
                    let etx = evt_tx.clone();
                    let cx = ctx.clone();
                    let reference = obj.to_string();
                    tokio::spawn(async move {
                        let evt = match c.select(&obj).await {
                            Ok(true) => Evt::Ack(format!("select concedido: {reference}")),
                            Ok(false) => Evt::Ack(format!("select denegado: {reference}")),
                            Err(e) => Evt::Error(format!("select {reference}: {e}")),
                        };
                        let _ = etx.send(evt);
                        cx.request_repaint();
                    });
                }
            }
        }
    }
}

fn emit(evt_tx: &StdSender<Evt>, ctx: &egui::Context, evt: Evt) {
    let _ = evt_tx.send(evt);
    ctx.request_repaint();
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Formatea un [`MmsData`] para mostrarlo en la UI.
pub fn fmt_value(v: &MmsData) -> String {
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

/// Cola acotada de reportes para la UI (descarta los más antiguos).
pub fn push_capped(buf: &mut VecDeque<ReportView>, item: ReportView, cap: usize) {
    if buf.len() >= cap {
        buf.pop_front();
    }
    buf.push_back(item);
}
