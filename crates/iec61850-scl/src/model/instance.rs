//! Valores instanciados/configurados dentro de un nodo lógico:
//! `DOI` (Data Object Instance) → `SDI` (Sub Data Instance) → `DAI`
//! (Data Attribute Instance) → `Val`.
//!
//! Estos elementos sobreescriben los valores por defecto derivados de las
//! plantillas.

use serde::Deserialize;

/// Instancia de un objeto de datos con valores configurados.
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "RawDoi")]
pub struct Doi {
    pub name: String,
    pub ix: Option<String>,
    pub desc: Option<String>,
    pub sdi: Vec<Sdi>,
    pub dai: Vec<Dai>,
}

/// Instancia de sub-dato (anidable).
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "RawSdi")]
pub struct Sdi {
    pub name: String,
    pub ix: Option<String>,
    pub sdi: Vec<Sdi>,
    pub dai: Vec<Dai>,
}

/// Representaciones de deserialización que toleran `DAI` y `SDI`
/// **intercalados** (habitual en exportadores reales, p. ej. IET600 de
/// ABB/Hitachi), que de otro modo rompen serde por "campos duplicados" al no
/// ser consecutivos los elementos del mismo nombre.
#[derive(Debug, Deserialize)]
struct RawDoi {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@ix")]
    ix: Option<String>,
    #[serde(rename = "@desc")]
    desc: Option<String>,
    #[serde(rename = "$value", default)]
    items: Vec<InstanceItem>,
}

#[derive(Debug, Deserialize)]
struct RawSdi {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@ix")]
    ix: Option<String>,
    #[serde(rename = "$value", default)]
    items: Vec<InstanceItem>,
}

#[derive(Debug, Deserialize)]
enum InstanceItem {
    SDI(Box<Sdi>),
    DAI(Box<Dai>),
    /// Otros hijos (`Private`, extensiones de fabricante, ...) se ignoran.
    #[serde(other)]
    Other,
}

fn split_items(items: Vec<InstanceItem>) -> (Vec<Sdi>, Vec<Dai>) {
    let mut sdi = Vec::new();
    let mut dai = Vec::new();
    for item in items {
        match item {
            InstanceItem::SDI(s) => sdi.push(*s),
            InstanceItem::DAI(d) => dai.push(*d),
            InstanceItem::Other => {}
        }
    }
    (sdi, dai)
}

impl From<RawDoi> for Doi {
    fn from(raw: RawDoi) -> Self {
        let (sdi, dai) = split_items(raw.items);
        Doi {
            name: raw.name,
            ix: raw.ix,
            desc: raw.desc,
            sdi,
            dai,
        }
    }
}

impl From<RawSdi> for Sdi {
    fn from(raw: RawSdi) -> Self {
        let (sdi, dai) = split_items(raw.items);
        Sdi {
            name: raw.name,
            ix: raw.ix,
            sdi,
            dai,
        }
    }
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
