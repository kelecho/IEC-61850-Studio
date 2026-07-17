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

/// Una entrada de un `EnumType`: el par ordinal ↔ literal (`<EnumVal ord="1">on`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnumValue {
    /// Ordinal (el valor que viaja por MMS como INTEGER).
    pub ord: i64,
    /// Literal legible (p. ej. `"on"`, `"blocked"`).
    pub literal: String,
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
    /// Tabla ordinal↔literal del `EnumType` (cuando `basic_type == Enum`),
    /// conservada del SCL para mostrar/aceptar literales en vez de ordinales.
    pub enum_values: Vec<EnumValue>,
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

    /// Literal legible de un ordinal de enum (`1` → `"on"`), si está en la tabla.
    pub fn enum_literal(&self, ord: i64) -> Option<&str> {
        self.enum_values
            .iter()
            .find(|e| e.ord == ord)
            .map(|e| e.literal.as_str())
    }

    /// Ordinal de un literal de enum (`"on"` → `1`), si está en la tabla.
    pub fn enum_ordinal(&self, literal: &str) -> Option<i64> {
        self.enum_values
            .iter()
            .find(|e| e.literal == literal)
            .map(|e| e.ord)
    }
}
