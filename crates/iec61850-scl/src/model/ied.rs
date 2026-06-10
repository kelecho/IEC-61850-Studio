//! `<IED>` y su contenido: puntos de acceso, servidor, dispositivos lógicos y
//! nodos lógicos.

use serde::Deserialize;

use super::control::{DataSet, GseControl, ReportControl, SmvControl};
use super::instance::Doi;

#[derive(Debug, Clone, Deserialize)]
pub struct Ied {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "@manufacturer")]
    pub manufacturer: Option<String>,
    #[serde(rename = "@configVersion")]
    pub config_version: Option<String>,
    #[serde(rename = "AccessPoint", default)]
    pub access_points: Vec<AccessPoint>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessPoint {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "Server")]
    pub server: Option<Server>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    #[serde(rename = "LDevice", default)]
    pub ldevices: Vec<LDevice>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LDevice {
    #[serde(rename = "@inst")]
    pub inst: String,
    #[serde(rename = "@ldName")]
    pub ld_name: Option<String>,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    /// Nodo lógico cero (obligatorio en el estándar).
    #[serde(rename = "LN0")]
    pub ln0: Option<Ln>,
    #[serde(rename = "LN", default)]
    pub lns: Vec<Ln>,
}

impl LDevice {
    /// Itera todos los nodos lógicos del LD, incluyendo `LN0`.
    pub fn all_lns(&self) -> impl Iterator<Item = &Ln> {
        self.ln0.iter().chain(self.lns.iter())
    }
}

/// Nodo lógico (`<LN>` o `<LN0>`). Comparten estructura; `LN0` simplemente no
/// tiene prefijo ni instancia y suele declarar `lnClass="LLN0"`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ln {
    #[serde(rename = "@prefix", default)]
    pub prefix: String,
    #[serde(rename = "@lnClass")]
    pub ln_class: String,
    #[serde(rename = "@inst", default)]
    pub inst: String,
    #[serde(rename = "@lnType")]
    pub ln_type: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "DataSet", default)]
    pub data_sets: Vec<DataSet>,
    #[serde(rename = "ReportControl", default)]
    pub report_controls: Vec<ReportControl>,
    #[serde(rename = "GSEControl", default)]
    pub gse_controls: Vec<GseControl>,
    #[serde(rename = "SampledValueControl", default)]
    pub smv_controls: Vec<SmvControl>,
    #[serde(rename = "DOI", default)]
    pub dois: Vec<Doi>,
}
