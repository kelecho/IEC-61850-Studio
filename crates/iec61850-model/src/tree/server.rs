//! Servidor (`Server`) — raíz del modelo de datos expuesto por un punto de
//! acceso de un IED.

use crate::tree::logical_device::LogicalDevice;

/// Servidor: contiene los dispositivos lógicos de un punto de acceso.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    pub logical_devices: Vec<LogicalDevice>,
}

impl Server {
    /// Busca un dispositivo lógico por su instancia (`inst`) o `ldName`.
    pub fn logical_device(&self, name: &str) -> Option<&LogicalDevice> {
        self.logical_devices
            .iter()
            .find(|ld| ld.inst == name || ld.ld_name.as_deref() == Some(name))
    }
}
