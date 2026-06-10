//! Estado y vista (egui) de la app: conectar, descubrir/leer variables y panel
//! de reportes en vivo. Sólo lectura/monitoreo.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::Receiver;

use eframe::egui;
use iec61850::ObjectReference;
use iec61850::mms::MmsData;
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::{Cmd, Evt, ReportView, push_capped};

const REPORTS_CAP: usize = 200;
const READS_CAP: usize = 100;

/// Tipo del valor a escribir/operar, elegido en la UI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    Bool,
    Int,
    Uint,
    Float,
    Text,
}

impl ValueKind {
    fn label(self) -> &'static str {
        match self {
            ValueKind::Bool => "Bool",
            ValueKind::Int => "Int",
            ValueKind::Uint => "Uint",
            ValueKind::Float => "Float",
            ValueKind::Text => "Texto",
        }
    }
}

/// Construye un `MmsData` a partir del tipo y el texto introducidos.
fn parse_value(kind: ValueKind, text: &str) -> Result<MmsData, String> {
    let t = text.trim();
    match kind {
        ValueKind::Bool => match t.to_ascii_lowercase().as_str() {
            "true" | "1" | "on" => Ok(MmsData::Bool(true)),
            "false" | "0" | "off" => Ok(MmsData::Bool(false)),
            _ => Err("bool: usa true/false".into()),
        },
        ValueKind::Int => t
            .parse::<i64>()
            .map(MmsData::Int)
            .map_err(|e| e.to_string()),
        ValueKind::Uint => t
            .parse::<u64>()
            .map(MmsData::Uint)
            .map_err(|e| e.to_string()),
        ValueKind::Float => t
            .parse::<f64>()
            .map(MmsData::Float)
            .map_err(|e| e.to_string()),
        ValueKind::Text => Ok(MmsData::Visible(text.to_string())),
    }
}

pub struct GuiApp {
    cmd_tx: UnboundedSender<Cmd>,
    evt_rx: Receiver<Evt>,
    addr: String,
    connected: bool,
    status: String,
    error: String,
    domains: Vec<String>,
    items: BTreeMap<String, Vec<String>>,
    selected: Option<String>,
    reads: Vec<(String, String)>,
    rcb: String,
    reports: VecDeque<ReportView>,
    // Escritura / control.
    notice: String,
    write_kind: ValueKind,
    write_val: String,
    ctrl_ref: String,
    ctrl_kind: ValueKind,
    ctrl_val: String,
    /// Acción mutante pendiente de confirmación: (descripción, comando).
    pending: Option<(String, Cmd)>,
}

impl GuiApp {
    pub fn new(cmd_tx: UnboundedSender<Cmd>, evt_rx: Receiver<Evt>) -> Self {
        Self {
            cmd_tx,
            evt_rx,
            addr: "127.0.0.1:10102".into(),
            connected: false,
            status: "desconectado".into(),
            error: String::new(),
            domains: Vec::new(),
            items: BTreeMap::new(),
            selected: None,
            reads: Vec::new(),
            rcb: "IED1LD0/LLN0.rcb1[RP]".into(),
            reports: VecDeque::new(),
            notice: String::new(),
            write_kind: ValueKind::Float,
            write_val: String::new(),
            ctrl_ref: "IED1LD0/GGIO1.SPCSO1[CO]".into(),
            ctrl_kind: ValueKind::Bool,
            ctrl_val: "true".into(),
            pending: None,
        }
    }

    /// Aplica los eventos pendientes del backend al estado.
    fn drain(&mut self) {
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                Evt::Connected(s) => {
                    self.connected = true;
                    self.status = s;
                    self.error.clear();
                }
                Evt::Disconnected => {
                    self.connected = false;
                    self.status = "desconectado".into();
                    self.domains.clear();
                    self.items.clear();
                    self.selected = None;
                }
                Evt::Error(e) => self.error = e,
                Evt::Ack(s) => {
                    self.notice = s;
                    self.error.clear();
                }
                Evt::Directory(d) => self.domains = d,
                Evt::Items { domain, items } => {
                    self.items.insert(domain, items);
                }
                Evt::ReadResult { reference, value } => {
                    self.reads.insert(0, (reference, value));
                    self.reads.truncate(READS_CAP);
                }
                Evt::Report(r) => push_capped(&mut self.reports, r, REPORTS_CAP),
            }
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();

        // --- Conexión ---
        egui::TopBottomPanel::top("conn").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("IED:");
                ui.add_enabled(
                    !self.connected,
                    egui::TextEdit::singleline(&mut self.addr).desired_width(180.0),
                );
                if !self.connected {
                    if ui.button("Conectar").clicked() {
                        let _ = self.cmd_tx.send(Cmd::Connect(self.addr.clone()));
                    }
                } else {
                    if ui.button("Desconectar").clicked() {
                        let _ = self.cmd_tx.send(Cmd::Disconnect);
                    }
                    if ui.button("Descubrir").clicked() {
                        let _ = self.cmd_tx.send(Cmd::Discover);
                    }
                }
                ui.separator();
                ui.label(format!("Estado: {}", self.status));
            });
            if !self.error.is_empty() {
                ui.colored_label(
                    egui::Color32::from_rgb(0xC0, 0x30, 0x30),
                    format!("⚠ {}", self.error),
                );
            } else if !self.notice.is_empty() {
                ui.colored_label(
                    egui::Color32::from_rgb(0x2E, 0x8B, 0x2E),
                    format!("✓ {}", self.notice),
                );
            }
        });

        // --- Variables (descubrimiento + selección) ---
        egui::SidePanel::left("vars")
            .resizable(true)
            .default_width(340.0)
            .show(ctx, |ui| {
                ui.heading("Variables");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for d in &self.domains {
                        egui::CollapsingHeader::new(d)
                            .default_open(true)
                            .show(ui, |ui| match self.items.get(d) {
                                Some(items) => {
                                    for it in items {
                                        let sel = self.selected.as_deref() == Some(it.as_str());
                                        if ui.selectable_label(sel, it).clicked() {
                                            self.selected = Some(it.clone());
                                        }
                                    }
                                }
                                None => {
                                    ui.weak("(pulsa «Descubrir»)");
                                }
                            });
                    }
                });
            });

        // --- Reportes en vivo ---
        egui::TopBottomPanel::bottom("reports")
            .resizable(true)
            .default_height(220.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("RCB:");
                    ui.add(egui::TextEdit::singleline(&mut self.rcb).desired_width(260.0));
                    if ui
                        .add_enabled(self.connected, egui::Button::new("Habilitar"))
                        .clicked()
                    {
                        match self.rcb.parse::<ObjectReference>() {
                            Ok(r) => {
                                let _ = self.cmd_tx.send(Cmd::EnableReport(r));
                            }
                            Err(_) => self.error = "RCB inválido".into(),
                        }
                    }
                    if ui
                        .add_enabled(self.connected, egui::Button::new("Deshabilitar"))
                        .clicked()
                    {
                        if let Ok(r) = self.rcb.parse::<ObjectReference>() {
                            let _ = self.cmd_tx.send(Cmd::DisableReport(r));
                        }
                    }
                    if ui.button("Limpiar").clicked() {
                        self.reports.clear();
                    }
                });
                ui.separator();
                ui.label(format!("Reportes recibidos: {}", self.reports.len()));
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for r in &self.reports {
                            let seq = r.seq_num.map(|s| s.to_string()).unwrap_or_default();
                            let eid = r
                                .entry_id
                                .as_deref()
                                .map(|e| format!(" entryID={e}"))
                                .unwrap_or_default();
                            let ds = r.dataset.as_deref().unwrap_or("");
                            ui.monospace(format!(
                                "{} [{ds}] seq={seq}{eid} → {}",
                                r.rpt_id,
                                r.entries.join(", ")
                            ));
                        }
                    });
            });

        // --- Acciones: escritura / control (mutan el IED → confirmación) ---
        egui::SidePanel::right("acciones")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading("Acciones");
                ui.label(
                    egui::RichText::new("Modifican el IED — piden confirmación.")
                        .small()
                        .weak(),
                );
                ui.separator();

                // Escribir el valor de la variable seleccionada.
                ui.strong("Escribir variable");
                match &self.selected {
                    Some(s) => {
                        ui.monospace(s);
                    }
                    None => {
                        ui.weak("selecciona una variable a la izquierda");
                    }
                }
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("write_kind")
                        .selected_text(self.write_kind.label())
                        .show_ui(ui, |ui| {
                            for k in [
                                ValueKind::Bool,
                                ValueKind::Int,
                                ValueKind::Uint,
                                ValueKind::Float,
                                ValueKind::Text,
                            ] {
                                ui.selectable_value(&mut self.write_kind, k, k.label());
                            }
                        });
                    ui.add(egui::TextEdit::singleline(&mut self.write_val).desired_width(120.0));
                });
                let can_write = self.connected && self.selected.is_some();
                if ui
                    .add_enabled(can_write, egui::Button::new("Escribir…"))
                    .clicked()
                {
                    if let Some(sel) = self.selected.clone() {
                        match (
                            sel.parse::<ObjectReference>(),
                            parse_value(self.write_kind, &self.write_val),
                        ) {
                            (Ok(obj), Ok(val)) => {
                                let desc = format!(
                                    "ESCRIBIR\n  objeto: {sel}\n  valor:  {} ({})",
                                    self.write_val.trim(),
                                    self.write_kind.label()
                                );
                                self.pending = Some((desc, Cmd::Write(obj, val)));
                            }
                            (Err(_), _) => self.error = "referencia inválida".into(),
                            (_, Err(e)) => self.error = format!("valor: {e}"),
                        }
                    }
                }

                ui.add_space(8.0);
                ui.separator();

                // Control: select / operate sobre un objeto de control [CO].
                ui.strong("Control (operate)");
                ui.add(egui::TextEdit::singleline(&mut self.ctrl_ref).desired_width(260.0));
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("ctrl_kind")
                        .selected_text(self.ctrl_kind.label())
                        .show_ui(ui, |ui| {
                            for k in [
                                ValueKind::Bool,
                                ValueKind::Int,
                                ValueKind::Uint,
                                ValueKind::Float,
                            ] {
                                ui.selectable_value(&mut self.ctrl_kind, k, k.label());
                            }
                        });
                    ui.add(egui::TextEdit::singleline(&mut self.ctrl_val).desired_width(100.0));
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.connected, egui::Button::new("Seleccionar"))
                        .clicked()
                    {
                        match self.ctrl_ref.parse::<ObjectReference>() {
                            Ok(obj) => {
                                let _ = self.cmd_tx.send(Cmd::Select(obj));
                            }
                            Err(_) => self.error = "control inválido".into(),
                        }
                    }
                    if ui
                        .add_enabled(self.connected, egui::Button::new("Operar…"))
                        .clicked()
                    {
                        match (
                            self.ctrl_ref.parse::<ObjectReference>(),
                            parse_value(self.ctrl_kind, &self.ctrl_val),
                        ) {
                            (Ok(obj), Ok(val)) => {
                                let desc = format!(
                                    "OPERAR (operate)\n  control: {}\n  ctlVal:  {} ({})",
                                    self.ctrl_ref.trim(),
                                    self.ctrl_val.trim(),
                                    self.ctrl_kind.label()
                                );
                                self.pending = Some((desc, Cmd::Operate(obj, val)));
                            }
                            (Err(_), _) => self.error = "control inválido".into(),
                            (_, Err(e)) => self.error = format!("ctlVal: {e}"),
                        }
                    }
                });
            });

        // --- Diálogo de confirmación de acción mutante ---
        if self.pending.is_some() {
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new("⚠ Confirmar acción")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if let Some((desc, _)) = &self.pending {
                        ui.label(egui::RichText::new(desc).monospace());
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Confirmar").clicked() {
                            confirm = true;
                        }
                        if ui.button("Cancelar").clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                if let Some((_, cmd)) = self.pending.take() {
                    let _ = self.cmd_tx.send(cmd);
                }
            } else if cancel {
                self.pending = None;
            }
        }

        // --- Lectura ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Lectura");
            ui.horizontal(|ui| {
                match &self.selected {
                    Some(s) => {
                        ui.monospace(s);
                    }
                    None => {
                        ui.weak("selecciona una variable a la izquierda");
                    }
                }
                let can = self.connected && self.selected.is_some();
                if ui.add_enabled(can, egui::Button::new("Leer")).clicked() {
                    if let Some(s) = &self.selected {
                        match s.parse::<ObjectReference>() {
                            Ok(o) => {
                                let _ = self.cmd_tx.send(Cmd::Read(o));
                            }
                            Err(_) => self.error = "referencia inválida".into(),
                        }
                    }
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("reads")
                    .striped(true)
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.strong("Referencia");
                        ui.strong("Valor");
                        ui.end_row();
                        for (r, v) in &self.reads {
                            ui.monospace(r);
                            ui.monospace(v);
                            ui.end_row();
                        }
                    });
            });
        });
    }
}
