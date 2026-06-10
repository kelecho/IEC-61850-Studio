//! Sección `<Communication>`: subredes, puntos de acceso conectados y sus
//! direcciones (IP, MAC, APPID, VLAN). Se preserva todo aunque en la Fase 1 no
//! se interprete: es la base para las fases GOOSE / Sampled Values.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Communication {
    #[serde(rename = "SubNetwork", default)]
    pub sub_networks: Vec<SubNetwork>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubNetwork {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "ConnectedAP", default)]
    pub connected_aps: Vec<ConnectedAp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectedAp {
    #[serde(rename = "@iedName")]
    pub ied_name: String,
    #[serde(rename = "@apName")]
    pub ap_name: String,
    #[serde(rename = "Address")]
    pub address: Option<Address>,
    #[serde(rename = "GSE", default)]
    pub gse: Vec<Gse>,
    #[serde(rename = "SMV", default)]
    pub smv: Vec<Smv>,
}

/// Conjunto de parámetros `<P type="...">valor</P>`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Address {
    #[serde(rename = "P", default)]
    pub params: Vec<P>,
}

impl Address {
    /// Devuelve el valor del parámetro de un tipo dado (p. ej. `"IP"`).
    pub fn param(&self, kind: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.kind == kind)
            .map(|p| p.value.as_str())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct P {
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(rename = "$text", default)]
    pub value: String,
}

/// Parámetros de comunicación GOOSE de un bloque de control.
#[derive(Debug, Clone, Deserialize)]
pub struct Gse {
    #[serde(rename = "@ldInst")]
    pub ld_inst: Option<String>,
    #[serde(rename = "@cbName")]
    pub cb_name: Option<String>,
    #[serde(rename = "Address")]
    pub address: Option<Address>,
}

/// Parámetros de comunicación de Sampled Values.
#[derive(Debug, Clone, Deserialize)]
pub struct Smv {
    #[serde(rename = "@ldInst")]
    pub ld_inst: Option<String>,
    #[serde(rename = "@cbName")]
    pub cb_name: Option<String>,
    #[serde(rename = "Address")]
    pub address: Option<Address>,
}
