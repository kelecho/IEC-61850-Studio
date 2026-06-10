//! Clases de datos comunes (Common Data Classes, CDC) — IEC 61850-7-3.
//!
//! Una CDC define la estructura típica de un `DataObject` (p. ej. `SPS` =
//! single point status, `MV` = measured value). En SCL aparece como atributo
//! `cdc` del `DOType`.

use std::fmt;
use std::str::FromStr;

/// Clase de datos común de un objeto de datos.
///
/// Incluye una variante [`CommonDataClass::Unknown`] para tolerar CDC
/// propietarias o de versiones futuras del estándar sin abortar la carga.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum CommonDataClass {
    // --- Información de estado ---
    SPS,
    DPS,
    INS,
    ENS,
    ACT,
    ACD,
    SEC,
    BCR,
    HST,
    VSS,
    // --- Información medida ---
    MV,
    CMV,
    SAV,
    WYE,
    DEL,
    SEQ,
    HMV,
    HWYE,
    HDEL,
    // --- Estado controlable ---
    SPC,
    DPC,
    INC,
    ENC,
    BSC,
    ISC,
    // --- Analógico controlable ---
    APC,
    BAC,
    // --- Ajustes (settings) ---
    SPG,
    ING,
    ENG,
    ASG,
    CURVE,
    CSG,
    // --- Descripción ---
    DPL,
    LPL,
    CSD,
    // --- Tolerancia ---
    /// CDC no reconocida; conserva el texto original.
    Unknown(String),
}

impl CommonDataClass {
    /// Construye desde el atributo `cdc` de SCL. Nunca falla.
    pub fn from_cdc(s: &str) -> Self {
        use CommonDataClass::*;
        match s {
            "SPS" => SPS,
            "DPS" => DPS,
            "INS" => INS,
            "ENS" => ENS,
            "ACT" => ACT,
            "ACD" => ACD,
            "SEC" => SEC,
            "BCR" => BCR,
            "HST" => HST,
            "VSS" => VSS,
            "MV" => MV,
            "CMV" => CMV,
            "SAV" => SAV,
            "WYE" => WYE,
            "DEL" => DEL,
            "SEQ" => SEQ,
            "HMV" => HMV,
            "HWYE" => HWYE,
            "HDEL" => HDEL,
            "SPC" => SPC,
            "DPC" => DPC,
            "INC" => INC,
            "ENC" => ENC,
            "BSC" => BSC,
            "ISC" => ISC,
            "APC" => APC,
            "BAC" => BAC,
            "SPG" => SPG,
            "ING" => ING,
            "ENG" => ENG,
            "ASG" => ASG,
            "CURVE" => CURVE,
            "CSG" => CSG,
            "DPL" => DPL,
            "LPL" => LPL,
            "CSD" => CSD,
            other => Unknown(other.to_string()),
        }
    }

    /// Representación textual canónica.
    pub fn as_str(&self) -> &str {
        use CommonDataClass::*;
        match self {
            SPS => "SPS",
            DPS => "DPS",
            INS => "INS",
            ENS => "ENS",
            ACT => "ACT",
            ACD => "ACD",
            SEC => "SEC",
            BCR => "BCR",
            HST => "HST",
            VSS => "VSS",
            MV => "MV",
            CMV => "CMV",
            SAV => "SAV",
            WYE => "WYE",
            DEL => "DEL",
            SEQ => "SEQ",
            HMV => "HMV",
            HWYE => "HWYE",
            HDEL => "HDEL",
            SPC => "SPC",
            DPC => "DPC",
            INC => "INC",
            ENC => "ENC",
            BSC => "BSC",
            ISC => "ISC",
            APC => "APC",
            BAC => "BAC",
            SPG => "SPG",
            ING => "ING",
            ENG => "ENG",
            ASG => "ASG",
            CURVE => "CURVE",
            CSG => "CSG",
            DPL => "DPL",
            LPL => "LPL",
            CSD => "CSD",
            Unknown(s) => s,
        }
    }

    /// `true` si la CDC no es reconocida.
    pub fn is_unknown(&self) -> bool {
        matches!(self, CommonDataClass::Unknown(_))
    }
}

impl FromStr for CommonDataClass {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CommonDataClass::from_cdc(s))
    }
}

impl fmt::Display for CommonDataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known() {
        assert_eq!(CommonDataClass::from_cdc("SPS"), CommonDataClass::SPS);
        assert_eq!(CommonDataClass::from_cdc("MV"), CommonDataClass::MV);
        assert!(!CommonDataClass::MV.is_unknown());
    }

    #[test]
    fn unknown_tolerated() {
        let c = CommonDataClass::from_cdc("XYZ");
        assert!(c.is_unknown());
        assert_eq!(c.as_str(), "XYZ");
    }
}
