//! `<IED>` y su contenido: puntos de acceso, servidor, dispositivos lógicos y
//! nodos lógicos.

use serde::Deserialize;

use super::control::{DataSet, GseControl, LogControl, ReportControl, SettingControl, SmvControl};
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
#[serde(from = "RawLDevice")]
pub struct LDevice {
    pub inst: String,
    pub ld_name: Option<String>,
    pub desc: Option<String>,
    /// Nodo lógico cero (obligatorio en el estándar).
    pub ln0: Option<Ln>,
    pub lns: Vec<Ln>,
}

/// Representación de deserialización que tolera un `LN0` **intercalado** entre
/// los `LN` (habitual en SCL reales), que de otro modo rompería serde por
/// "campos duplicados" al no ser los `LN` consecutivos.
#[derive(Debug, Deserialize)]
struct RawLDevice {
    #[serde(rename = "@inst")]
    inst: String,
    #[serde(rename = "@ldName")]
    ld_name: Option<String>,
    #[serde(rename = "@desc")]
    desc: Option<String>,
    #[serde(rename = "$value", default)]
    items: Vec<LDeviceItem>,
}

#[derive(Debug, Deserialize)]
enum LDeviceItem {
    LN0(Box<Ln>),
    LN(Box<Ln>),
    /// Otros hijos (`AccessControl`, `Private`, ...) se ignoran.
    #[serde(other)]
    Other,
}

impl From<RawLDevice> for LDevice {
    fn from(raw: RawLDevice) -> Self {
        let mut ln0 = None;
        let mut lns = Vec::new();
        for item in raw.items {
            match item {
                LDeviceItem::LN0(ln) => ln0 = Some(*ln),
                LDeviceItem::LN(ln) => lns.push(*ln),
                LDeviceItem::Other => {}
            }
        }
        LDevice {
            inst: raw.inst,
            ld_name: raw.ld_name,
            desc: raw.desc,
            ln0,
            lns,
        }
    }
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
    #[serde(rename = "SettingControl")]
    pub setting_control: Option<SettingControl>,
    #[serde(rename = "LogControl", default)]
    pub log_controls: Vec<LogControl>,
    #[serde(rename = "DOI", default)]
    pub dois: Vec<Doi>,
}
