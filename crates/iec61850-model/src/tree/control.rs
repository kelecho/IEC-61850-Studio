//! Conjuntos de datos y bloques de control de reporte asociados a un nodo
//! lógico. Representación de modelo (independiente del SCL de origen).

use crate::fc::FunctionalConstraint;
use crate::tree::data_attribute::TriggerOptions;

/// Una entrada de un `DataSet` (FCDA): referencia a un dato funcionalmente
/// restringido dentro del IED.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Fcda {
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    /// Nombre del DO (puede incluir subdatos separados por `.`).
    pub do_name: String,
    /// Nombre del DA (vacío si la entrada apunta a un DO completo).
    pub da_name: String,
    pub fc: Option<FunctionalConstraint>,
}

/// Conjunto de datos (`DataSet`): lista ordenada de FCDA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSet {
    pub name: String,
    pub entries: Vec<Fcda>,
}

/// Bloque de control de reporte (`ReportControl`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportControl {
    pub name: String,
    pub rpt_id: Option<String>,
    /// Nombre del `DataSet` referenciado.
    pub dataset: Option<String>,
    pub buffered: bool,
    pub conf_rev: Option<u32>,
    pub trigger_options: TriggerOptions,
}
