//! Valor de un atributo de datos.
//!
//! En la Fase 1 sólo se usa para representar valores **configurados por
//! defecto** que aparecen en los elementos `Val` de SCL (dentro de `DAI`/`DOI`).
//! La codificación/decodificación MMS en tiempo de ejecución se añadirá en la
//! fase de comunicación; por eso los valores se guardan de forma laxa.

use std::fmt;

/// Valor configurado de un atributo de datos.
///
/// El texto crudo de SCL se conserva siempre en [`Value::raw`]; los accesores
/// tipados (`as_bool`, `as_i64`, …) son interpretaciones de conveniencia.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Value {
    /// Texto tal cual aparece en el `Val` de SCL.
    pub raw: String,
    /// Índice del grupo de ajustes (`sGroup`), si aplica.
    pub setting_group: Option<u32>,
}

impl Value {
    /// Crea un valor a partir del texto de SCL.
    pub fn new(raw: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            setting_group: None,
        }
    }

    /// Crea un valor de un grupo de ajustes concreto.
    pub fn with_group(raw: impl Into<String>, group: u32) -> Self {
        Self {
            raw: raw.into(),
            setting_group: Some(group),
        }
    }

    /// Interpreta el valor como booleano (`true`/`false`, `1`/`0`).
    pub fn as_bool(&self) -> Option<bool> {
        match self.raw.trim() {
            "true" | "True" | "1" => Some(true),
            "false" | "False" | "0" => Some(false),
            _ => None,
        }
    }

    /// Interpreta el valor como entero con signo.
    pub fn as_i64(&self) -> Option<i64> {
        self.raw.trim().parse().ok()
    }

    /// Interpreta el valor como número de punto flotante.
    pub fn as_f64(&self) -> Option<f64> {
        self.raw.trim().parse().ok()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpretations() {
        assert_eq!(Value::new("true").as_bool(), Some(true));
        assert_eq!(Value::new("0").as_bool(), Some(false));
        assert_eq!(Value::new("42").as_i64(), Some(42));
        assert_eq!(Value::new("3.5").as_f64(), Some(3.5));
        assert_eq!(Value::new("abc").as_i64(), None);
    }
}
