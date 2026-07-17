//! Conjuntos de datos y bloques de control dentro de un nodo lógico
//! (`DataSet`, `ReportControl`, `GSEControl`, `SampledValueControl`).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DataSet {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "FCDA", default)]
    pub fcda: Vec<Fcda>,
}

/// Functionally Constrained Data (Attribute): entrada de un `DataSet`.
#[derive(Debug, Clone, Deserialize)]
pub struct Fcda {
    #[serde(rename = "@ldInst")]
    pub ld_inst: Option<String>,
    #[serde(rename = "@prefix")]
    pub prefix: Option<String>,
    #[serde(rename = "@lnClass")]
    pub ln_class: Option<String>,
    #[serde(rename = "@lnInst")]
    pub ln_inst: Option<String>,
    #[serde(rename = "@doName")]
    pub do_name: Option<String>,
    #[serde(rename = "@daName")]
    pub da_name: Option<String>,
    #[serde(rename = "@fc")]
    pub fc: Option<String>,
    #[serde(rename = "@ix")]
    pub ix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportControl {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@rptID")]
    pub rpt_id: Option<String>,
    #[serde(rename = "@datSet")]
    pub dat_set: Option<String>,
    #[serde(rename = "@confRev")]
    pub conf_rev: Option<u32>,
    #[serde(rename = "@buffered")]
    pub buffered: Option<bool>,
    #[serde(rename = "@intgPd")]
    pub intg_pd: Option<u32>,
    #[serde(rename = "TrgOps")]
    pub trg_ops: Option<TrgOps>,
}

/// Opciones de disparo (`<TrgOps>`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TrgOps {
    #[serde(rename = "@dchg")]
    pub dchg: Option<bool>,
    #[serde(rename = "@qchg")]
    pub qchg: Option<bool>,
    #[serde(rename = "@dupd")]
    pub dupd: Option<bool>,
    #[serde(rename = "@period")]
    pub period: Option<bool>,
    #[serde(rename = "@gi")]
    pub gi: Option<bool>,
}

/// `<LogControl>`: bloque de control de log (LCB). Controla el registro
/// persistente de eventos de un dataset en un `Log`.
#[derive(Debug, Clone, Deserialize)]
pub struct LogControl {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@datSet")]
    pub dat_set: Option<String>,
    #[serde(rename = "@logName")]
    pub log_name: Option<String>,
    #[serde(rename = "@logEna")]
    pub log_ena: Option<bool>,
    #[serde(rename = "@intgPd")]
    pub intg_pd: Option<u32>,
    #[serde(rename = "TrgOps")]
    pub trg_ops: Option<TrgOps>,
}

/// `<SettingControl>`: bloque de control de grupos de ajustes (SGCB), en LN0.
/// Define cuántos grupos de ajustes hay y cuál está activo por defecto.
#[derive(Debug, Clone, Deserialize)]
pub struct SettingControl {
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "@numOfSGs")]
    pub num_of_sgs: u32,
    #[serde(rename = "@actSG")]
    pub act_sg: Option<u32>,
    #[serde(rename = "@resvTms")]
    pub resv_tms: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GseControl {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@datSet")]
    pub dat_set: Option<String>,
    #[serde(rename = "@confRev")]
    pub conf_rev: Option<u32>,
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "@appID")]
    pub app_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmvControl {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@datSet")]
    pub dat_set: Option<String>,
    #[serde(rename = "@confRev")]
    pub conf_rev: Option<u32>,
    #[serde(rename = "@smvID")]
    pub smv_id: Option<String>,
}
