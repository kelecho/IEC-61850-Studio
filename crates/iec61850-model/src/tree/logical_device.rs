//! Dispositivo lógico (`LogicalDevice`, LD) — IEC 61850-7-2.

use crate::tree::logical_node::LogicalNode;

/// Dispositivo lógico: agrupa nodos lógicos.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogicalDevice {
    /// Instancia del LD (atributo `inst` en SCL).
    pub inst: String,
    /// Nombre funcional opcional (`ldName`); si está presente, es el nombre
    /// efectivo del LD en lugar de `IEDName + inst`.
    pub ld_name: Option<String>,
    pub logical_nodes: Vec<LogicalNode>,
}

impl LogicalDevice {
    /// Busca un nodo lógico por su nombre compuesto (p. ej. `MMXU1`, `LLN0`).
    pub fn logical_node(&self, name: &str) -> Option<&LogicalNode> {
        self.logical_nodes.iter().find(|ln| ln.name() == name)
    }
}
