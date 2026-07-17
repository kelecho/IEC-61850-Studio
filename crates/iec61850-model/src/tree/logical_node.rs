//! Nodo lógico (`LogicalNode`, LN) — IEC 61850-7-2.
//!
//! El nombre de un LN se compone de `prefijo + clase + instancia`
//! (p. ej. prefijo `""`, clase `MMXU`, instancia `1` → `MMXU1`). `LLN0` es el
//! nodo lógico cero del dispositivo.

use crate::tree::control::{DataSet, LogControlBlock, ReportControl, SettingGroupControl};
use crate::tree::data_object::DataObject;

/// Nodo lógico instanciado.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogicalNode {
    /// Prefijo del nombre (`""` para `LLN0`).
    pub prefix: String,
    /// Clase de nodo lógico, p. ej. `MMXU`, `PTOC`, `LLN0`.
    pub class: String,
    /// Instancia, p. ej. `1` (`""` para `LLN0`).
    pub inst: String,
    /// Identificador del `LNodeType` de origen en las plantillas SCL.
    pub ln_type: String,
    /// Descripción legible (`desc` en SCL), si la hay.
    pub desc: Option<String>,
    pub data_objects: Vec<DataObject>,
    /// Conjuntos de datos definidos (típicamente en `LLN0`).
    pub data_sets: Vec<DataSet>,
    /// Bloques de control de reporte (típicamente en `LLN0`).
    pub report_controls: Vec<ReportControl>,
    /// Bloque de control de grupos de ajustes (SGCB), si el LN lo declara.
    pub setting_group_control: Option<SettingGroupControl>,
    /// Bloques de control de log (LCB) declarados en el LN.
    pub log_controls: Vec<LogControlBlock>,
}

impl LogicalNode {
    /// Nombre compuesto del nodo lógico (`prefijo + clase + instancia`).
    pub fn name(&self) -> String {
        format!("{}{}{}", self.prefix, self.class, self.inst)
    }

    /// Busca un objeto de datos directo por nombre.
    pub fn data_object(&self, name: &str) -> Option<&DataObject> {
        self.data_objects.iter().find(|d| d.name == name)
    }

    /// Busca un conjunto de datos por nombre.
    pub fn data_set(&self, name: &str) -> Option<&DataSet> {
        self.data_sets.iter().find(|d| d.name == name)
    }
}
