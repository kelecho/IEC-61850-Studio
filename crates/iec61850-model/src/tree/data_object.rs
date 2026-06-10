//! Objeto de datos (`DataObject`, DO) y sub-objetos (SDO).

use crate::cdc::CommonDataClass;
use crate::tree::data_attribute::DataAttribute;

/// Objeto de datos: instancia de una clase de datos común (CDC) con sus
/// atributos y posibles sub-objetos.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataObject {
    pub name: String,
    pub cdc: CommonDataClass,
    /// Descripción legible (`desc` en SCL), si la hay.
    pub desc: Option<String>,
    /// `true` si el DO es transitorio (atributo `transient` en SCL).
    pub transient: bool,
    pub attributes: Vec<DataAttribute>,
    /// Sub-objetos de datos (SDO) anidados.
    pub sub_objects: Vec<DataObject>,
}

impl DataObject {
    /// Busca un atributo directo por nombre.
    pub fn attribute(&self, name: &str) -> Option<&DataAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Busca un sub-objeto directo por nombre.
    pub fn sub_object(&self, name: &str) -> Option<&DataObject> {
        self.sub_objects.iter().find(|s| s.name == name)
    }
}
