//! Tipos tipados de **Quality** y **Timestamp** (IEC 61850-7-3).
//!
//! En el modelo, un atributo `q` viaja como un `BIT STRING` de 13 bits y un `t`
//! como un `UTC-Time` de 8 octetos: opacos de cara al diagnóstico. Estos tipos
//! los descomponen en sus campos (validez, banderas de detección, sincronía del
//! reloj…) para mostrarlos como hace una herramienta tipo IEDScout, sin que cada
//! capa reimplemente el bitfielding.
//!
//! Son tipos **puros** (sin dependencia de la pila de comunicación): toman bits o
//! bytes ya extraídos por la capa que decodifica el `MmsData`/GOOSE/SV.

use std::fmt;

/// Validez del dato (bits 0–1 de Quality, IEC 61850-7-3 §6.2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Validity {
    Good,
    Invalid,
    Reserved,
    Questionable,
}

impl Validity {
    fn from_bits(b0: bool, b1: bool) -> Self {
        match (b1, b0) {
            (false, false) => Validity::Good,
            (false, true) => Validity::Invalid,
            (true, false) => Validity::Reserved,
            (true, true) => Validity::Questionable,
        }
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Validity::Good => "good",
            Validity::Invalid => "invalid",
            Validity::Reserved => "reserved",
            Validity::Questionable => "questionable",
        };
        f.write_str(s)
    }
}

/// Origen del valor (bit 10 de Quality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Source {
    Process,
    Substituted,
}

/// Atributo de calidad IEC 61850-7-3 descompuesto.
///
/// Orden de bits según el estándar (bit 0 = primero del `BIT STRING`):
/// 0–1 validity · 2 overflow · 3 outOfRange · 4 badReference · 5 oscillatory ·
/// 6 failure · 7 oldData · 8 inconsistent · 9 inaccurate · 10 source ·
/// 11 test · 12 operatorBlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Quality {
    pub validity: Validity,
    pub overflow: bool,
    pub out_of_range: bool,
    pub bad_reference: bool,
    pub oscillatory: bool,
    pub failure: bool,
    pub old_data: bool,
    pub inconsistent: bool,
    pub inaccurate: bool,
    pub source: Source,
    pub test: bool,
    pub operator_blocked: bool,
}

impl Quality {
    /// Construye una calidad desde sus bits (índice 0 = primer bit del
    /// `BIT STRING`). Los bits ausentes se toman como `false`.
    pub fn from_bits(bits: &[bool]) -> Self {
        let b = |i: usize| bits.get(i).copied().unwrap_or(false);
        Quality {
            validity: Validity::from_bits(b(0), b(1)),
            overflow: b(2),
            out_of_range: b(3),
            bad_reference: b(4),
            oscillatory: b(5),
            failure: b(6),
            old_data: b(7),
            inconsistent: b(8),
            inaccurate: b(9),
            source: if b(10) {
                Source::Substituted
            } else {
                Source::Process
            },
            test: b(11),
            operator_blocked: b(12),
        }
    }

    /// Construye una calidad desde la representación de 2 octetos (bit 0 = MSB del
    /// primer octeto), tal como aparece p. ej. en el dato de calidad de SV 9-2LE.
    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        let mut bits = [false; 16];
        for (i, slot) in bits.iter_mut().enumerate() {
            let byte = bytes[i / 8];
            // bit 0 = MSB del primer octeto.
            *slot = (byte >> (7 - (i % 8))) & 1 == 1;
        }
        Quality::from_bits(&bits)
    }

    /// `true` si no hay ninguna bandera de detección activa y la validez es buena.
    pub fn is_good(&self) -> bool {
        self.validity == Validity::Good
            && !self.overflow
            && !self.out_of_range
            && !self.bad_reference
            && !self.oscillatory
            && !self.failure
            && !self.old_data
            && !self.inconsistent
            && !self.inaccurate
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.validity)?;
        let flags = [
            (self.overflow, "overflow"),
            (self.out_of_range, "outOfRange"),
            (self.bad_reference, "badReference"),
            (self.oscillatory, "oscillatory"),
            (self.failure, "failure"),
            (self.old_data, "oldData"),
            (self.inconsistent, "inconsistent"),
            (self.inaccurate, "inaccurate"),
            (self.source == Source::Substituted, "substituted"),
            (self.test, "test"),
            (self.operator_blocked, "operatorBlocked"),
        ];
        for (on, name) in flags {
            if on {
                write!(f, "+{name}")?;
            }
        }
        Ok(())
    }
}

/// Calidad del reloj que selló un `Timestamp` (octeto TimeQuality, IEC 61850-7-3
/// §6.1.2.9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeQuality {
    pub leap_seconds_known: bool,
    pub clock_failure: bool,
    pub clock_not_synchronized: bool,
    /// Número de bits significativos de la fracción de segundo (0–24).
    pub fraction_bits: u8,
}

impl TimeQuality {
    pub fn from_byte(b: u8) -> Self {
        TimeQuality {
            leap_seconds_known: b & 0x80 != 0,
            clock_failure: b & 0x40 != 0,
            clock_not_synchronized: b & 0x20 != 0,
            fraction_bits: b & 0x1F,
        }
    }
}

/// Marca de tiempo IEC 61850-7-3 (`Timestamp`/`UTC-Time`, 8 octetos): segundos
/// desde el epoch Unix (4 octetos), fracción de segundo (3 octetos) y calidad de
/// tiempo (1 octeto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Timestamp {
    pub seconds: u32,
    /// Fracción de segundo cruda (24 bits): la fracción real es `raw / 2^24`.
    pub fraction: u32,
    pub quality: TimeQuality,
}

impl Timestamp {
    /// Decodifica los 8 octetos del `UTC-Time`.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        let seconds = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let fraction = u32::from_be_bytes([0, b[4], b[5], b[6]]);
        Timestamp {
            seconds,
            fraction,
            quality: TimeQuality::from_byte(b[7]),
        }
    }

    /// Segundos desde el epoch Unix como `f64` (incluye la fracción).
    pub fn epoch_seconds(&self) -> f64 {
        self.seconds as f64 + self.fraction as f64 / (1u64 << 24) as f64
    }

    /// Componente fraccionaria en nanosegundos.
    pub fn nanos(&self) -> u32 {
        ((self.fraction as u64 * 1_000_000_000) / (1u64 << 24)) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_good_is_clean() {
        let q = Quality::from_bits(&[]);
        assert_eq!(q.validity, Validity::Good);
        assert!(q.is_good());
        assert_eq!(q.to_string(), "good");
    }

    #[test]
    fn quality_invalid_with_flags() {
        // validity=invalid (bit0=1,bit1=0), overflow(bit2), test(bit11).
        let mut bits = [false; 13];
        bits[0] = true; // validity bit0
        bits[2] = true; // overflow
        bits[11] = true; // test
        let q = Quality::from_bits(&bits);
        assert_eq!(q.validity, Validity::Invalid);
        assert!(q.overflow);
        assert!(q.test);
        assert!(!q.is_good());
        assert_eq!(q.to_string(), "invalid+overflow+test");
    }

    #[test]
    fn quality_questionable_from_bytes() {
        // bits 0 y 1 a 1 → questionable: primer octeto 0b1100_0000 = 0xC0.
        let q = Quality::from_be_bytes([0xC0, 0x00]);
        assert_eq!(q.validity, Validity::Questionable);
    }

    #[test]
    fn timestamp_decodes_seconds_fraction_quality() {
        // segundos = 0x00000064 = 100; fracción = 0x800000 = medio segundo;
        // calidad = 0x0A (10 bits de fracción, sin fallos).
        let ts = Timestamp::from_bytes([0x00, 0x00, 0x00, 0x64, 0x80, 0x00, 0x00, 0x0A]);
        assert_eq!(ts.seconds, 100);
        assert!((ts.epoch_seconds() - 100.5).abs() < 1e-9);
        assert_eq!(ts.nanos(), 500_000_000);
        assert_eq!(ts.quality.fraction_bits, 10);
        assert!(!ts.quality.clock_failure);
    }

    #[test]
    fn time_quality_flags() {
        let tq = TimeQuality::from_byte(0xE5); // leap+failure+notSync, fraction=5
        assert!(tq.leap_seconds_known);
        assert!(tq.clock_failure);
        assert!(tq.clock_not_synchronized);
        assert_eq!(tq.fraction_bits, 5);
    }
}
