//! Valores instanciados/configurados dentro de un nodo lógico:
//! `DOI` (Data Object Instance) → `SDI` (Sub Data Instance) → `DAI`
//! (Data Attribute Instance) → `Val`.
//!
//! Estos elementos sobreescriben los valores por defecto derivados de las
//! plantillas.

use serde::Deserialize;

/// Instancia de un objeto de datos con valores configurados.
#[derive(Debug, Clone, Deserialize)]
pub struct Doi {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@ix")]
    pub ix: Option<String>,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "SDI", default)]
    pub sdi: Vec<Sdi>,
    #[serde(rename = "DAI", default)]
    pub dai: Vec<Dai>,
}

/// Instancia de sub-dato (anidable).
#[derive(Debug, Clone, Deserialize)]
pub struct Sdi {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@ix")]
    pub ix: Option<String>,
    #[serde(rename = "SDI", default)]
    pub sdi: Vec<Sdi>,
    #[serde(rename = "DAI", default)]
    pub dai: Vec<Dai>,
}

/// Instancia de atributo de datos con sus valores.
#[derive(Debug, Clone, Deserialize)]
pub struct Dai {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@ix")]
    pub ix: Option<String>,
    #[serde(rename = "@sGroup")]
    pub s_group: Option<u32>,
    #[serde(rename = "Val", default)]
    pub val: Vec<Val>,
}

/// Valor configurado (`<Val>texto</Val>`), opcionalmente de un grupo de ajustes.
#[derive(Debug, Clone, Deserialize)]
pub struct Val {
    #[serde(rename = "@sGroup")]
    pub s_group: Option<u32>,
    #[serde(rename = "$text", default)]
    pub text: String,
}
