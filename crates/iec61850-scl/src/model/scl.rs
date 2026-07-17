//! Raíz del documento SCL y cabecera.

use serde::Deserialize;

use super::communication::Communication;
use super::ied::Ied;
use super::substation::Substation;
use super::templates::DataTypeTemplates;

/// Documento SCL completo (elemento raíz `<SCL>`).
///
/// Es un AST **fiel al XML**: refleja la estructura del archivo sin resolver
/// plantillas. La conversión al modelo de datos instanciado la hace
/// [`crate::resolve`].
#[derive(Debug, Clone, Deserialize)]
pub struct SclDocument {
    #[serde(rename = "Header")]
    pub header: Option<Header>,
    #[serde(rename = "Substation", default)]
    pub substations: Vec<Substation>,
    #[serde(rename = "Communication")]
    pub communication: Option<Communication>,
    #[serde(rename = "IED", default)]
    pub ieds: Vec<Ied>,
    #[serde(rename = "DataTypeTemplates")]
    pub data_type_templates: Option<DataTypeTemplates>,
}

impl SclDocument {
    /// IED por nombre.
    pub fn ied(&self, name: &str) -> Option<&Ied> {
        self.ieds.iter().find(|i| i.name == name)
    }

    /// ¿El documento no aportó ninguna sección? Señal de que el XML no casó con el
    /// esquema esperado (p. ej. elementos con prefijo de namespace sin resolver).
    pub fn is_empty(&self) -> bool {
        self.header.is_none()
            && self.substations.is_empty()
            && self.communication.is_none()
            && self.ieds.is_empty()
            && self.data_type_templates.is_none()
    }
}

/// Cabecera del SCL (`<Header>`).
#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@revision")]
    pub revision: Option<String>,
    #[serde(rename = "@toolID")]
    pub tool_id: Option<String>,
    #[serde(rename = "@nameStructure")]
    pub name_structure: Option<String>,
}
