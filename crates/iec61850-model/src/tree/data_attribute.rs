//! Atributo de datos (`DataAttribute`, DA) — la hoja del modelo.

use crate::basic_type::BasicType;
use crate::fc::FunctionalConstraint;
use crate::value::Value;

/// Opciones de disparo de un atributo (`triggerOptions` en SCL): qué cambios
/// generan un evento de reporte/GOOSE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TriggerOptions {
    /// Data change.
    pub dchg: bool,
    /// Quality change.
    pub qchg: bool,
    /// Data update.
    pub dupd: bool,
}

/// Atributo de datos: nombre, tipo, restricción funcional y, si es compuesto,
/// sub-atributos.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataAttribute {
    pub name: String,
    pub fc: FunctionalConstraint,
    pub basic_type: BasicType,
    /// Descripción legible (`desc` en SCL), si la hay.
    pub desc: Option<String>,
    /// Identificador del `EnumType` cuando `basic_type == Enum`.
    pub enum_type: Option<String>,
    pub trigger_options: TriggerOptions,
    /// Valor por defecto configurado (desde `DAI`/`Val` en SCL).
    pub value: Option<Value>,
    /// Sub-atributos cuando el tipo es compuesto (`Struct`).
    pub children: Vec<DataAttribute>,
}

impl DataAttribute {
    /// Busca un sub-atributo directo por nombre.
    pub fn child(&self, name: &str) -> Option<&DataAttribute> {
        self.children.iter().find(|c| c.name == name)
    }

    /// `true` si el atributo es compuesto.
    pub fn is_struct(&self) -> bool {
        self.basic_type.is_struct() || !self.children.is_empty()
    }
}
