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

/// Bloque de control de grupos de ajustes (`SGCB`), presente en LN0. Expone
/// cuántos grupos de ajustes hay (`num_of_sgs`) y el activo inicial (`act_sg`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SettingGroupControl {
    pub num_of_sgs: u32,
    pub act_sg: u32,
    /// Si el IED soporta la reserva de edición (`ResvTms` en el SGCB).
    pub resv_tms: bool,
}

/// Bloque de control de log (`LCB`): registra en un `Log` persistente los eventos
/// de un dataset. Análogo al RCB pero con almacenamiento en journal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogControlBlock {
    pub name: String,
    /// Nombre del `DataSet` cuyos cambios se registran.
    pub dataset: Option<String>,
    /// Nombre del `Log` de destino.
    pub log_name: Option<String>,
    /// Si el logging está habilitado por defecto.
    pub log_ena: bool,
}
