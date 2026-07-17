//! `<DataTypeTemplates>`: catálogo de tipos que los nodos lógicos instancian.
//!
//! Relaciones: `LNodeType` → (por `type`) `DOType` → (por `type`) `DAType` /
//! `EnumType`. La [`crate::resolve`] sigue estas referencias para construir el
//! árbol instanciado.

use serde::Deserialize;

use super::instance::Val;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(from = "RawTemplates")]
pub struct DataTypeTemplates {
    pub lnode_types: Vec<LNodeType>,
    pub do_types: Vec<DOType>,
    pub da_types: Vec<DAType>,
    pub enum_types: Vec<EnumType>,
}

/// Representación de deserialización que preserva el **orden de aparición** de
/// los hijos. Necesaria porque quick-xml/serde exige que los elementos del mismo
/// nombre sean consecutivos, mientras que los SCL reales de muchas herramientas
/// **intercalan** `LNodeType`/`DOType`/`DAType`/`EnumType`. Capturarlos en un
/// único `$value` con un enum admite cualquier orden.
#[derive(Debug, Deserialize)]
struct RawTemplates {
    #[serde(rename = "$value", default)]
    items: Vec<TemplateItem>,
}

#[derive(Debug, Deserialize)]
enum TemplateItem {
    LNodeType(LNodeType),
    DOType(DOType),
    DAType(DAType),
    EnumType(EnumType),
    /// Cualquier otro hijo (p. ej. `Private`) se ignora sin romper el parseo.
    #[serde(other)]
    Other,
}

impl From<RawTemplates> for DataTypeTemplates {
    fn from(raw: RawTemplates) -> Self {
        let mut t = DataTypeTemplates::default();
        for item in raw.items {
            match item {
                TemplateItem::LNodeType(x) => t.lnode_types.push(x),
                TemplateItem::DOType(x) => t.do_types.push(x),
                TemplateItem::DAType(x) => t.da_types.push(x),
                TemplateItem::EnumType(x) => t.enum_types.push(x),
                TemplateItem::Other => {}
            }
        }
        t
    }
}

impl DataTypeTemplates {
    pub fn lnode_type(&self, id: &str) -> Option<&LNodeType> {
        self.lnode_types.iter().find(|t| t.id == id)
    }
    pub fn do_type(&self, id: &str) -> Option<&DOType> {
        self.do_types.iter().find(|t| t.id == id)
    }
    pub fn da_type(&self, id: &str) -> Option<&DAType> {
        self.da_types.iter().find(|t| t.id == id)
    }
    pub fn enum_type(&self, id: &str) -> Option<&EnumType> {
        self.enum_types.iter().find(|t| t.id == id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LNodeType {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@lnClass")]
    pub ln_class: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "DO", default)]
    pub dos: Vec<TDo>,
}

/// Declaración de un objeto de datos dentro de un `LNodeType`.
#[derive(Debug, Clone, Deserialize)]
pub struct TDo {
    #[serde(rename = "@name")]
    pub name: String,
    /// Referencia al `id` de un `DOType`.
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(rename = "@transient")]
    pub transient: Option<bool>,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DOType {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@cdc")]
    pub cdc: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "DA", default)]
    pub das: Vec<Da>,
    #[serde(rename = "SDO", default)]
    pub sdos: Vec<Sdo>,
}

/// Sub-objeto de datos dentro de un `DOType` (referencia a otro `DOType`).
#[derive(Debug, Clone, Deserialize)]
pub struct Sdo {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
}

/// Atributo de datos declarado en un `DOType`.
#[derive(Debug, Clone, Deserialize)]
pub struct Da {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "@fc")]
    pub fc: String,
    #[serde(rename = "@bType")]
    pub b_type: String,
    /// Para `bType="Struct"` referencia un `DAType`; para `bType="Enum"`
    /// referencia un `EnumType`.
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "@dchg")]
    pub dchg: Option<bool>,
    #[serde(rename = "@qchg")]
    pub qchg: Option<bool>,
    #[serde(rename = "@dupd")]
    pub dupd: Option<bool>,
    #[serde(rename = "Val", default)]
    pub val: Vec<Val>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DAType {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "BDA", default)]
    pub bdas: Vec<Bda>,
}

/// Atributo de datos básico dentro de un `DAType` (anidable vía `type`).
#[derive(Debug, Clone, Deserialize)]
pub struct Bda {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@desc")]
    pub desc: Option<String>,
    #[serde(rename = "@bType")]
    pub b_type: String,
    /// Para `bType="Struct"` referencia un `DAType`; para `bType="Enum"`
    /// referencia un `EnumType`.
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(rename = "Val", default)]
    pub val: Vec<Val>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnumType {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "EnumVal", default)]
    pub values: Vec<EnumVal>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnumVal {
    #[serde(rename = "@ord")]
    pub ord: i64,
    #[serde(rename = "$text", default)]
    pub text: String,
}
