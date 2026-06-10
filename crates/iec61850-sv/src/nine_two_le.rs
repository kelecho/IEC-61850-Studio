//! Perfil **9-2LE**: el `sample` de un ASDU como 8 canales (4 corrientes + 4
//! tensiones), cada canal = par `INT32` valor + `UINT32` calidad (64 octetos).

use crate::error::SvError;

/// Un canal: valor instantáneo + palabra de calidad (IEC 61850-7-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SvChannel {
    pub value: i32,
    pub quality: u32,
}

/// Índices de los 8 canales del perfil 9-2LE.
pub mod idx {
    pub const IA: usize = 0;
    pub const IB: usize = 1;
    pub const IC: usize = 2;
    pub const IN: usize = 3;
    pub const VA: usize = 4;
    pub const VB: usize = 5;
    pub const VC: usize = 6;
    pub const VN: usize = 7;
}

/// Dataset 9-2LE: 8 canales (IA,IB,IC,IN,VA,VB,VC,VN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NineTwoLe {
    pub channels: [SvChannel; 8],
}

impl NineTwoLe {
    /// Empaqueta los 8 canales en los 64 octetos del campo `sample`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, ch) in self.channels.iter().enumerate() {
            out[i * 8..i * 8 + 4].copy_from_slice(&ch.value.to_be_bytes());
            out[i * 8 + 4..i * 8 + 8].copy_from_slice(&ch.quality.to_be_bytes());
        }
        out
    }

    /// Interpreta 64 octetos de `sample` como los 8 canales del perfil.
    pub fn from_bytes(b: &[u8]) -> Result<NineTwoLe, SvError> {
        if b.len() != 64 {
            return Err(SvError::Malformed(format!(
                "sample 9-2LE debe tener 64 octetos, tiene {}",
                b.len()
            )));
        }
        let mut channels = [SvChannel::default(); 8];
        for (i, ch) in channels.iter_mut().enumerate() {
            ch.value = i32::from_be_bytes(b[i * 8..i * 8 + 4].try_into().unwrap());
            ch.quality = u32::from_be_bytes(b[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        }
        Ok(NineTwoLe { channels })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut n = NineTwoLe::default();
        n.channels[idx::IA] = SvChannel {
            value: 1000,
            quality: 0,
        };
        n.channels[idx::VA] = SvChannel {
            value: -5,
            quality: 0x0000_0040,
        };
        let bytes = n.to_bytes();
        // IA value 1000 = 0x000003E8 en los 4 primeros octetos.
        assert_eq!(&bytes[0..4], &[0x00, 0x00, 0x03, 0xE8]);
        assert_eq!(NineTwoLe::from_bytes(&bytes).unwrap(), n);
    }

    #[test]
    fn wrong_length() {
        assert!(NineTwoLe::from_bytes(&[0u8; 32]).is_err());
    }
}
