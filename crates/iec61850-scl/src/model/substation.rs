//! Sección física `<Substation>`. Modelo ligero (suficiente para diagnóstico
//! topológico); se conserva la jerarquía VoltageLevel → Bay → equipo.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Substation {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "VoltageLevel", default)]
    pub voltage_levels: Vec<VoltageLevel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VoltageLevel {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "Bay", default)]
    pub bays: Vec<Bay>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Bay {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "ConductingEquipment", default)]
    pub equipment: Vec<ConductingEquipment>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConductingEquipment {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
}
