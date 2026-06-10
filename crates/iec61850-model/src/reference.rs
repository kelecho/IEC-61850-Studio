//! Referencia de objeto IEC 61850 (Object Reference).
//!
//! Formato: `<LDName>/<LNName>.<DataName>[.<DataName>…][\[FC\]]`
//!
//! Ejemplos:
//! - `LD0/LLN0.Mod.stVal`
//! - `IED1LD0/MMXU1.A.phsA.cVal.mag.f`
//! - `IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]` (con restricción funcional)
//!
//! El `LDName` puede o no incluir el prefijo del IED; esta estructura lo trata
//! como una unidad y no intenta separarlo.

use std::fmt;
use std::str::FromStr;

use crate::fc::FunctionalConstraint;

/// Referencia textual a un nodo del modelo de datos.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObjectReference {
    /// Nombre del dispositivo lógico (puede incluir el prefijo del IED).
    pub ld: String,
    /// Nombre del nodo lógico (prefijo + clase + instancia), p. ej. `MMXU1`.
    pub ln: String,
    /// Cadena de nombres DO/DA tras el nodo lógico, p. ej. `["Mod", "stVal"]`.
    pub path: Vec<String>,
    /// Restricción funcional, si la referencia la especifica con `[FC]`.
    pub fc: Option<FunctionalConstraint>,
}

/// Error al parsear una [`ObjectReference`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseReferenceError {
    #[error("referencia vacía")]
    Empty,
    #[error("falta el separador '/' entre LD y LN en '{0}'")]
    MissingSlash(String),
    #[error("falta el nodo lógico o el dato tras '/' en '{0}'")]
    MissingLogicalNode(String),
    #[error("restricción funcional inválida en '{0}'")]
    BadFc(String),
}

impl ObjectReference {
    /// Construye una referencia a partir de sus componentes.
    pub fn new(
        ld: impl Into<String>,
        ln: impl Into<String>,
        path: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            ld: ld.into(),
            ln: ln.into(),
            path: path.into_iter().map(Into::into).collect(),
            fc: None,
        }
    }

    /// Devuelve una copia sin la restricción funcional (útil como clave de
    /// índice, donde la ruta DO/DA ya es única dentro del LN).
    pub fn without_fc(&self) -> ObjectReference {
        ObjectReference {
            fc: None,
            ..self.clone()
        }
    }

    /// Clave canónica para indexación: `LD/LN.do.da…` sin la FC.
    pub fn key(&self) -> String {
        let mut s = format!("{}/{}", self.ld, self.ln);
        for p in &self.path {
            s.push('.');
            s.push_str(p);
        }
        s
    }
}

impl FromStr for ObjectReference {
    type Err = ParseReferenceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseReferenceError::Empty);
        }

        // Extrae una posible FC al final: "...[MX]".
        let (body, fc) = match (s.strip_suffix(']'), s.rfind('[')) {
            (Some(_), Some(open)) => {
                let inner = &s[open + 1..s.len() - 1];
                let fc = inner
                    .parse::<FunctionalConstraint>()
                    .map_err(|_| ParseReferenceError::BadFc(s.to_string()))?;
                (&s[..open], Some(fc))
            }
            _ => (s, None),
        };

        let (ld, rest) = body
            .split_once('/')
            .ok_or_else(|| ParseReferenceError::MissingSlash(s.to_string()))?;
        if ld.is_empty() || rest.is_empty() {
            return Err(ParseReferenceError::MissingLogicalNode(s.to_string()));
        }

        let mut parts = rest.split('.');
        let ln = parts.next().unwrap(); // siempre hay al menos un elemento
        if ln.is_empty() {
            return Err(ParseReferenceError::MissingLogicalNode(s.to_string()));
        }
        let path: Vec<String> = parts.map(|p| p.to_string()).collect();

        Ok(ObjectReference {
            ld: ld.to_string(),
            ln: ln.to_string(),
            path,
            fc,
        })
    }
}

impl fmt::Display for ObjectReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ld, self.ln)?;
        for p in &self.path {
            write!(f, ".{p}")?;
        }
        if let Some(fc) = self.fc {
            write!(f, "[{fc}]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() {
        let r: ObjectReference = "LD0/LLN0.Mod.stVal".parse().unwrap();
        assert_eq!(r.ld, "LD0");
        assert_eq!(r.ln, "LLN0");
        assert_eq!(r.path, vec!["Mod", "stVal"]);
        assert_eq!(r.fc, None);
        assert_eq!(r.to_string(), "LD0/LLN0.Mod.stVal");
    }

    #[test]
    fn deep_with_fc() {
        let r: ObjectReference = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse().unwrap();
        assert_eq!(r.ld, "IED1LD0");
        assert_eq!(r.ln, "MMXU1");
        assert_eq!(r.path, vec!["A", "phsA", "cVal", "mag", "f"]);
        assert_eq!(r.fc, Some(FunctionalConstraint::MX));
        assert_eq!(r.to_string(), "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]");
        assert_eq!(r.key(), "IED1LD0/MMXU1.A.phsA.cVal.mag.f");
    }

    #[test]
    fn errors() {
        assert_eq!(
            "".parse::<ObjectReference>(),
            Err(ParseReferenceError::Empty)
        );
        assert!(matches!(
            "LLN0.Mod".parse::<ObjectReference>(),
            Err(ParseReferenceError::MissingSlash(_))
        ));
        assert!(matches!(
            "LD0/MMXU1.x[ZZ]".parse::<ObjectReference>(),
            Err(ParseReferenceError::BadFc(_))
        ));
    }

    #[test]
    fn ln_only() {
        let r: ObjectReference = "LD0/LLN0".parse().unwrap();
        assert_eq!(r.ln, "LLN0");
        assert!(r.path.is_empty());
    }
}
