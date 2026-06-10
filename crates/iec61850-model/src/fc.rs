//! Restricciones funcionales (Functional Constraints, FC) — IEC 61850-7-2.
//!
//! Una FC clasifica los atributos de datos según su rol (estado, medida,
//! configuración, control, etc.). Aparece como atributo `fc` en los `DA`/`FCDA`
//! de los archivos SCL.

use std::fmt;
use std::str::FromStr;

/// Restricción funcional de un atributo de datos.
///
/// Conjunto cerrado definido por el estándar; se incluyen también las FC
/// relacionadas con servicios que pueden aparecer en `FCDA` dentro de SCL
/// (RP, BR, LG, GO, GS, MS, US).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum FunctionalConstraint {
    /// Status information.
    ST,
    /// Measurands (analog values).
    MX,
    /// Setpoint.
    SP,
    /// Substitution.
    SV,
    /// Configuration.
    CF,
    /// Description.
    DC,
    /// Setting group.
    SG,
    /// Setting group editable.
    SE,
    /// Control.
    CO,
    /// Blocking.
    BL,
    /// Extended definition.
    EX,
    /// Unbuffered report.
    RP,
    /// Buffered report.
    BR,
    /// Logging.
    LG,
    /// GOOSE control.
    GO,
    /// GSSE control.
    GS,
    /// Multicast sampled value control.
    MS,
    /// Unicast sampled value control.
    US,
    /// Operate received (service tracking).
    OR,
    /// Service response.
    SR,
}

impl FunctionalConstraint {
    /// Representación textual canónica (la que se usa en SCL).
    pub const fn as_str(self) -> &'static str {
        use FunctionalConstraint::*;
        match self {
            ST => "ST",
            MX => "MX",
            SP => "SP",
            SV => "SV",
            CF => "CF",
            DC => "DC",
            SG => "SG",
            SE => "SE",
            CO => "CO",
            BL => "BL",
            EX => "EX",
            RP => "RP",
            BR => "BR",
            LG => "LG",
            GO => "GO",
            GS => "GS",
            MS => "MS",
            US => "US",
            OR => "OR",
            SR => "SR",
        }
    }
}

/// Error al parsear una restricción funcional desconocida.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("restricción funcional desconocida: '{0}'")]
pub struct ParseFcError(pub String);

impl FromStr for FunctionalConstraint {
    type Err = ParseFcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use FunctionalConstraint::*;
        Ok(match s {
            "ST" => ST,
            "MX" => MX,
            "SP" => SP,
            "SV" => SV,
            "CF" => CF,
            "DC" => DC,
            "SG" => SG,
            "SE" => SE,
            "CO" => CO,
            "BL" => BL,
            "EX" => EX,
            "RP" => RP,
            "BR" => BR,
            "LG" => LG,
            "GO" => GO,
            "GS" => GS,
            "MS" => MS,
            "US" => US,
            "OR" => OR,
            "SR" => SR,
            other => return Err(ParseFcError(other.to_string())),
        })
    }
}

impl fmt::Display for FunctionalConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known() {
        for fc in [
            "ST", "MX", "SP", "SV", "CF", "DC", "SG", "SE", "CO", "BL", "EX", "RP", "BR", "LG",
            "GO", "GS", "MS", "US", "OR", "SR",
        ] {
            let parsed: FunctionalConstraint = fc.parse().unwrap();
            assert_eq!(parsed.as_str(), fc);
            assert_eq!(parsed.to_string(), fc);
        }
    }

    #[test]
    fn unknown_errors() {
        assert!("ZZ".parse::<FunctionalConstraint>().is_err());
    }
}
