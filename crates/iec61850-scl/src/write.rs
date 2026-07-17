//! Serialización de un [`SclDocument`] a XML SCL (IEC 61850-6).
//!
//! Permite el flujo **cargar → modificar → guardar** (round-trip) y generar un
//! CID/ICD desde un documento en memoria. Emite los elementos principales del
//! SCL; `Substation` no se serializa todavía (raro en un CID de IED).

use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

use crate::error::SclError;
use crate::model::communication::{Address, Communication, ConnectedAp, Gse, Smv, SubNetwork};
use crate::model::control::{DataSet, Fcda, GseControl, ReportControl, SettingControl, SmvControl};
use crate::model::ied::{AccessPoint, Ied, LDevice, Ln, Server};
use crate::model::instance::{Dai, Doi, Sdi, Val};
use crate::model::scl::{Header, SclDocument};
use crate::model::templates::{
    Bda, DAType, DOType, Da, DataTypeTemplates, EnumType, LNodeType, Sdo, TDo,
};

/// Namespace del SCL 2003 (el mismo que produce quick-xml al parsear).
const SCL_NS: &str = "http://www.iec.ch/61850/2003/SCL";

/// Serializa un documento SCL a una cadena XML.
pub fn write_scl_str(doc: &SclDocument) -> Result<String, SclError> {
    let mut x = Xml::new();
    x.raw(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    x.newline();
    x.start("SCL", &[("xmlns", SCL_NS)]);
    if let Some(h) = &doc.header {
        write_header(&mut x, h);
    }
    if let Some(c) = &doc.communication {
        write_communication(&mut x, c);
    }
    for ied in &doc.ieds {
        write_ied(&mut x, ied);
    }
    if let Some(dtt) = &doc.data_type_templates {
        write_templates(&mut x, dtt);
    }
    x.end("SCL");
    x.finish()
}

/// Serializa un documento SCL a un fichero.
pub fn write_scl_file<P: AsRef<std::path::Path>>(
    doc: &SclDocument,
    path: P,
) -> Result<(), SclError> {
    let xml = write_scl_str(doc)?;
    let path = path.as_ref().to_path_buf();
    std::fs::write(&path, xml).map_err(|source| SclError::Io { path, source })
}

// --- Elementos ---

fn write_header(x: &mut Xml, h: &Header) {
    let mut a = Attrs::new();
    a.put("id", &h.id);
    a.opt("version", &h.version);
    a.opt("revision", &h.revision);
    a.opt("toolID", &h.tool_id);
    a.opt("nameStructure", &h.name_structure);
    x.empty("Header", &a.as_slice());
}

fn write_communication(x: &mut Xml, c: &Communication) {
    x.start("Communication", &[]);
    for sn in &c.sub_networks {
        write_subnetwork(x, sn);
    }
    x.end("Communication");
}

fn write_subnetwork(x: &mut Xml, sn: &SubNetwork) {
    let mut a = Attrs::new();
    a.put("name", &sn.name);
    a.opt("type", &sn.kind);
    x.start("SubNetwork", &a.as_slice());
    for ap in &sn.connected_aps {
        write_connected_ap(x, ap);
    }
    x.end("SubNetwork");
}

fn write_connected_ap(x: &mut Xml, ap: &ConnectedAp) {
    x.start(
        "ConnectedAP",
        &[
            ("iedName", ap.ied_name.as_str()),
            ("apName", ap.ap_name.as_str()),
        ],
    );
    if let Some(addr) = &ap.address {
        write_address(x, addr);
    }
    for g in &ap.gse {
        write_gse(x, g);
    }
    for s in &ap.smv {
        write_smv(x, s);
    }
    x.end("ConnectedAP");
}

fn write_address(x: &mut Xml, addr: &Address) {
    x.start("Address", &[]);
    for p in &addr.params {
        x.text_elem("P", &[("type", p.kind.as_str())], &p.value);
    }
    x.end("Address");
}

fn write_gse(x: &mut Xml, g: &Gse) {
    let mut a = Attrs::new();
    a.opt("ldInst", &g.ld_inst);
    a.opt("cbName", &g.cb_name);
    if g.address.is_none() {
        x.empty("GSE", &a.as_slice());
        return;
    }
    x.start("GSE", &a.as_slice());
    if let Some(addr) = &g.address {
        write_address(x, addr);
    }
    x.end("GSE");
}

fn write_smv(x: &mut Xml, s: &Smv) {
    let mut a = Attrs::new();
    a.opt("ldInst", &s.ld_inst);
    a.opt("cbName", &s.cb_name);
    if s.address.is_none() {
        x.empty("SMV", &a.as_slice());
        return;
    }
    x.start("SMV", &a.as_slice());
    if let Some(addr) = &s.address {
        write_address(x, addr);
    }
    x.end("SMV");
}

fn write_ied(x: &mut Xml, ied: &Ied) {
    let mut a = Attrs::new();
    a.put("name", &ied.name);
    a.opt("type", &ied.kind);
    a.opt("manufacturer", &ied.manufacturer);
    a.opt("configVersion", &ied.config_version);
    x.start("IED", &a.as_slice());
    for ap in &ied.access_points {
        write_access_point(x, ap);
    }
    x.end("IED");
}

fn write_access_point(x: &mut Xml, ap: &AccessPoint) {
    x.start("AccessPoint", &[("name", ap.name.as_str())]);
    if let Some(server) = &ap.server {
        write_server(x, server);
    }
    x.end("AccessPoint");
}

fn write_server(x: &mut Xml, server: &Server) {
    x.start("Server", &[]);
    for ld in &server.ldevices {
        write_ldevice(x, ld);
    }
    x.end("Server");
}

fn write_ldevice(x: &mut Xml, ld: &LDevice) {
    let mut a = Attrs::new();
    a.put("inst", &ld.inst);
    a.opt("ldName", &ld.ld_name);
    a.opt("desc", &ld.desc);
    x.start("LDevice", &a.as_slice());
    if let Some(ln0) = &ld.ln0 {
        write_ln(x, ln0, true);
    }
    for ln in &ld.lns {
        write_ln(x, ln, false);
    }
    x.end("LDevice");
}

fn write_ln(x: &mut Xml, ln: &Ln, is_ln0: bool) {
    let tag = if is_ln0 { "LN0" } else { "LN" };
    let mut a = Attrs::new();
    if !ln.prefix.is_empty() {
        a.put("prefix", &ln.prefix);
    }
    a.put("lnClass", &ln.ln_class);
    if !is_ln0 {
        a.put("inst", &ln.inst);
    } else {
        a.put("inst", &ln.inst); // LN0 lleva inst="" explícito
    }
    a.put("lnType", &ln.ln_type);
    a.opt("desc", &ln.desc);
    x.start(tag, &a.as_slice());
    for ds in &ln.data_sets {
        write_dataset(x, ds);
    }
    for rc in &ln.report_controls {
        write_report_control(x, rc);
    }
    for gc in &ln.gse_controls {
        write_gse_control(x, gc);
    }
    for sc in &ln.smv_controls {
        write_smv_control(x, sc);
    }
    if let Some(sg) = &ln.setting_control {
        write_setting_control(x, sg);
    }
    for lc in &ln.log_controls {
        write_log_control(x, lc);
    }
    for doi in &ln.dois {
        write_doi(x, doi);
    }
    x.end(tag);
}

fn write_dataset(x: &mut Xml, ds: &DataSet) {
    let mut a = Attrs::new();
    a.put("name", &ds.name);
    a.opt("desc", &ds.desc);
    x.start("DataSet", &a.as_slice());
    for f in &ds.fcda {
        write_fcda(x, f);
    }
    x.end("DataSet");
}

fn write_fcda(x: &mut Xml, f: &Fcda) {
    let mut a = Attrs::new();
    a.opt("ldInst", &f.ld_inst);
    a.opt("prefix", &f.prefix);
    a.opt("lnClass", &f.ln_class);
    a.opt("lnInst", &f.ln_inst);
    a.opt("doName", &f.do_name);
    a.opt("daName", &f.da_name);
    a.opt("fc", &f.fc);
    a.opt("ix", &f.ix);
    x.empty("FCDA", &a.as_slice());
}

fn write_report_control(x: &mut Xml, rc: &ReportControl) {
    let mut a = Attrs::new();
    a.put("name", &rc.name);
    a.opt("rptID", &rc.rpt_id);
    a.opt("datSet", &rc.dat_set);
    let conf = rc.conf_rev.map(|v| v.to_string());
    a.opt("confRev", &conf);
    let buf = rc.buffered.map(|v| v.to_string());
    a.opt("buffered", &buf);
    let intg = rc.intg_pd.map(|v| v.to_string());
    a.opt("intgPd", &intg);
    if rc.trg_ops.is_none() {
        x.empty("ReportControl", &a.as_slice());
        return;
    }
    x.start("ReportControl", &a.as_slice());
    if let Some(t) = &rc.trg_ops {
        let mut ta = Attrs::new();
        let b = |v: Option<bool>| v.map(|x| x.to_string());
        ta.opt("dchg", &b(t.dchg));
        ta.opt("qchg", &b(t.qchg));
        ta.opt("dupd", &b(t.dupd));
        ta.opt("period", &b(t.period));
        ta.opt("gi", &b(t.gi));
        x.empty("TrgOps", &ta.as_slice());
    }
    x.end("ReportControl");
}

fn write_gse_control(x: &mut Xml, gc: &GseControl) {
    let mut a = Attrs::new();
    a.put("name", &gc.name);
    a.opt("datSet", &gc.dat_set);
    let conf = gc.conf_rev.map(|v| v.to_string());
    a.opt("confRev", &conf);
    a.opt("type", &gc.kind);
    a.opt("appID", &gc.app_id);
    x.empty("GSEControl", &a.as_slice());
}

fn write_smv_control(x: &mut Xml, sc: &SmvControl) {
    let mut a = Attrs::new();
    a.put("name", &sc.name);
    a.opt("datSet", &sc.dat_set);
    let conf = sc.conf_rev.map(|v| v.to_string());
    a.opt("confRev", &conf);
    a.opt("smvID", &sc.smv_id);
    x.empty("SampledValueControl", &a.as_slice());
}

fn write_log_control(x: &mut Xml, lc: &crate::model::control::LogControl) {
    let mut a = Attrs::new();
    a.put("name", &lc.name);
    a.opt("datSet", &lc.dat_set);
    a.opt("logName", &lc.log_name);
    let ena = lc.log_ena.map(|v| v.to_string());
    a.opt("logEna", &ena);
    let intg = lc.intg_pd.map(|v| v.to_string());
    a.opt("intgPd", &intg);
    if lc.trg_ops.is_none() {
        x.empty("LogControl", &a.as_slice());
        return;
    }
    x.start("LogControl", &a.as_slice());
    if let Some(t) = &lc.trg_ops {
        let mut ta = Attrs::new();
        let b = |v: Option<bool>| v.map(|x| x.to_string());
        ta.opt("dchg", &b(t.dchg));
        ta.opt("qchg", &b(t.qchg));
        ta.opt("dupd", &b(t.dupd));
        ta.opt("period", &b(t.period));
        ta.opt("gi", &b(t.gi));
        x.empty("TrgOps", &ta.as_slice());
    }
    x.end("LogControl");
}

fn write_setting_control(x: &mut Xml, sc: &SettingControl) {
    let mut a = Attrs::new();
    a.opt("desc", &sc.desc);
    let n = sc.num_of_sgs.to_string();
    a.put("numOfSGs", &n);
    let act = sc.act_sg.map(|v| v.to_string());
    a.opt("actSG", &act);
    let resv = sc.resv_tms.map(|v| v.to_string());
    a.opt("resvTms", &resv);
    x.empty("SettingControl", &a.as_slice());
}

fn write_doi(x: &mut Xml, doi: &Doi) {
    let mut a = Attrs::new();
    a.put("name", &doi.name);
    a.opt("ix", &doi.ix);
    a.opt("desc", &doi.desc);
    x.start("DOI", &a.as_slice());
    for sdi in &doi.sdi {
        write_sdi(x, sdi);
    }
    for dai in &doi.dai {
        write_dai(x, dai);
    }
    x.end("DOI");
}

fn write_sdi(x: &mut Xml, sdi: &Sdi) {
    let mut a = Attrs::new();
    a.put("name", &sdi.name);
    a.opt("ix", &sdi.ix);
    x.start("SDI", &a.as_slice());
    for s in &sdi.sdi {
        write_sdi(x, s);
    }
    for dai in &sdi.dai {
        write_dai(x, dai);
    }
    x.end("SDI");
}

fn write_dai(x: &mut Xml, dai: &Dai) {
    let mut a = Attrs::new();
    a.put("name", &dai.name);
    a.opt("ix", &dai.ix);
    let sg = dai.s_group.map(|v| v.to_string());
    a.opt("sGroup", &sg);
    if dai.val.is_empty() {
        x.empty("DAI", &a.as_slice());
        return;
    }
    x.start("DAI", &a.as_slice());
    for v in &dai.val {
        write_val(x, v);
    }
    x.end("DAI");
}

fn write_val(x: &mut Xml, v: &Val) {
    let mut a = Attrs::new();
    let sg = v.s_group.map(|s| s.to_string());
    a.opt("sGroup", &sg);
    x.text_elem("Val", &a.as_slice(), &v.text);
}

// --- DataTypeTemplates ---

fn write_templates(x: &mut Xml, dtt: &DataTypeTemplates) {
    x.start("DataTypeTemplates", &[]);
    for lt in &dtt.lnode_types {
        write_lnode_type(x, lt);
    }
    for dt in &dtt.do_types {
        write_do_type(x, dt);
    }
    for dat in &dtt.da_types {
        write_da_type(x, dat);
    }
    for et in &dtt.enum_types {
        write_enum_type(x, et);
    }
    x.end("DataTypeTemplates");
}

fn write_lnode_type(x: &mut Xml, lt: &LNodeType) {
    let mut a = Attrs::new();
    a.put("id", &lt.id);
    a.put("lnClass", &lt.ln_class);
    a.opt("desc", &lt.desc);
    x.start("LNodeType", &a.as_slice());
    for d in &lt.dos {
        write_tdo(x, d);
    }
    x.end("LNodeType");
}

fn write_tdo(x: &mut Xml, d: &TDo) {
    let mut a = Attrs::new();
    a.put("name", &d.name);
    a.put("type", &d.kind);
    let t = d.transient.map(|v| v.to_string());
    a.opt("transient", &t);
    a.opt("desc", &d.desc);
    x.empty("DO", &a.as_slice());
}

fn write_do_type(x: &mut Xml, dt: &DOType) {
    let mut a = Attrs::new();
    a.put("id", &dt.id);
    a.put("cdc", &dt.cdc);
    a.opt("desc", &dt.desc);
    x.start("DOType", &a.as_slice());
    for da in &dt.das {
        write_da(x, da);
    }
    for sdo in &dt.sdos {
        write_sdo(x, sdo);
    }
    x.end("DOType");
}

fn write_sdo(x: &mut Xml, sdo: &Sdo) {
    let mut a = Attrs::new();
    a.put("name", &sdo.name);
    a.put("type", &sdo.kind);
    a.opt("desc", &sdo.desc);
    x.empty("SDO", &a.as_slice());
}

fn write_da(x: &mut Xml, da: &Da) {
    let mut a = Attrs::new();
    a.put("name", &da.name);
    a.opt("desc", &da.desc);
    a.put("fc", &da.fc);
    a.put("bType", &da.b_type);
    a.opt("type", &da.kind);
    let b = |v: Option<bool>| v.map(|x| x.to_string());
    a.opt("dchg", &b(da.dchg));
    a.opt("qchg", &b(da.qchg));
    a.opt("dupd", &b(da.dupd));
    if da.val.is_empty() {
        x.empty("DA", &a.as_slice());
        return;
    }
    x.start("DA", &a.as_slice());
    for v in &da.val {
        write_val(x, v);
    }
    x.end("DA");
}

fn write_da_type(x: &mut Xml, dat: &DAType) {
    let mut a = Attrs::new();
    a.put("id", &dat.id);
    a.opt("desc", &dat.desc);
    x.start("DAType", &a.as_slice());
    for bda in &dat.bdas {
        write_bda(x, bda);
    }
    x.end("DAType");
}

fn write_bda(x: &mut Xml, bda: &Bda) {
    let mut a = Attrs::new();
    a.put("name", &bda.name);
    a.opt("desc", &bda.desc);
    a.put("bType", &bda.b_type);
    a.opt("type", &bda.kind);
    if bda.val.is_empty() {
        x.empty("BDA", &a.as_slice());
        return;
    }
    x.start("BDA", &a.as_slice());
    for v in &bda.val {
        write_val(x, v);
    }
    x.end("BDA");
}

fn write_enum_type(x: &mut Xml, et: &EnumType) {
    x.start("EnumType", &[("id", et.id.as_str())]);
    for ev in &et.values {
        let ord = ev.ord.to_string();
        x.text_elem("EnumVal", &[("ord", ord.as_str())], &ev.text);
    }
    x.end("EnumType");
}

// --- Escritor XML con indentación ---

struct Xml {
    w: Writer<Vec<u8>>,
}

impl Xml {
    fn new() -> Self {
        // Indentación de 2 espacios (legible y estable para round-trip por líneas).
        Self {
            w: Writer::new_with_indent(Vec::new(), b' ', 2),
        }
    }

    fn start(&mut self, name: &str, attrs: &[(&str, &str)]) {
        let mut e = BytesStart::new(name);
        for (k, v) in attrs {
            e.push_attribute((*k, *v));
        }
        self.w.write_event(Event::Start(e)).expect("write start");
    }

    fn empty(&mut self, name: &str, attrs: &[(&str, &str)]) {
        let mut e = BytesStart::new(name);
        for (k, v) in attrs {
            e.push_attribute((*k, *v));
        }
        self.w.write_event(Event::Empty(e)).expect("write empty");
    }

    fn end(&mut self, name: &str) {
        self.w
            .write_event(Event::End(BytesEnd::new(name)))
            .expect("write end");
    }

    fn text_elem(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) {
        let mut e = BytesStart::new(name);
        for (k, v) in attrs {
            e.push_attribute((*k, *v));
        }
        self.w.write_event(Event::Start(e)).expect("start");
        self.w
            .write_event(Event::Text(BytesText::new(text)))
            .expect("text");
        self.w
            .write_event(Event::End(BytesEnd::new(name)))
            .expect("end");
    }

    fn raw(&mut self, s: &str) {
        use std::io::Write;
        self.w.get_mut().write_all(s.as_bytes()).expect("raw");
    }

    fn newline(&mut self) {
        self.raw("\n");
    }

    fn finish(self) -> Result<String, SclError> {
        String::from_utf8(self.w.into_inner()).map_err(|e| {
            SclError::Xml(quick_xml::DeError::Custom(format!(
                "salida no es UTF-8: {e}"
            )))
        })
    }
}

/// Acumulador de atributos que descarta los `Option::None`.
struct Attrs {
    items: Vec<(&'static str, String)>,
}

impl Attrs {
    fn new() -> Self {
        Self { items: Vec::new() }
    }
    fn put(&mut self, key: &'static str, value: &str) {
        self.items.push((key, value.to_string()));
    }
    fn opt(&mut self, key: &'static str, value: &Option<String>) {
        if let Some(v) = value {
            self.items.push((key, v.clone()));
        }
    }
    fn as_slice(&self) -> Vec<(&str, &str)> {
        self.items.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
}
