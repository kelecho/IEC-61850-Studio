//! Firma **asimétrica ECDSA P-256** de tramas GOOSE/SV (IEC 62351-6:2020).
//!
//! A diferencia del HMAC-SHA256 (simétrico, implementado a mano en [`crate::auth`]),
//! la firma de curva elíptica se apoya en el crate auditado
//! [`p256`](https://docs.rs/p256) (RustCrypto), tras la feature `ecdsa`: implementar
//! aritmética de curva a mano sería un riesgo criptográfico. La dependencia solo
//! entra si se activa la feature.
//!
//! Se usa **ECDSA con SHA-256 sobre P-256** (NIST), que es lo que especifica el
//! estándar, con firma determinista (RFC 6979). El firmante posee la clave
//! privada; el verificador, solo la pública (no viaja secreto por el canal, a
//! diferencia del HMAC). La firma va en formato fijo `r || s` (64 octetos), que
//! encaja en el perfil de trama (tag tras el APDU, longitud en Reserved2).

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::auth::{FrameSigner, FrameVerifier};

/// Longitud de una firma ECDSA P-256 en formato fijo `r || s`, en octetos.
pub const ECDSA_P256_TAG_LEN: usize = 64;

/// Error al construir una clave ECDSA.
#[derive(Debug, thiserror::Error)]
pub enum EcdsaError {
    /// El material de clave no es una clave P-256 válida.
    #[error("clave ECDSA P-256 inválida")]
    InvalidKey,
}

/// Firmante ECDSA P-256 (posee la clave privada). Se comparte por el publicador.
#[derive(Clone)]
pub struct EcdsaSigner {
    key: SigningKey,
}

impl EcdsaSigner {
    /// Construye un firmante desde el escalar privado (32 octetos, big-endian).
    pub fn from_scalar(bytes: &[u8]) -> Result<Self, EcdsaError> {
        let key = SigningKey::from_slice(bytes).map_err(|_| EcdsaError::InvalidKey)?;
        Ok(Self { key })
    }

    /// Verificador con la clave pública correspondiente (para distribuir a los
    /// suscriptores).
    pub fn verifier(&self) -> EcdsaVerifier {
        EcdsaVerifier {
            key: *self.key.verifying_key(),
        }
    }

    /// Firma `data` (ECDSA-SHA256) devolviendo la firma fija `r || s`.
    pub fn sign(&self, data: &[u8]) -> [u8; ECDSA_P256_TAG_LEN] {
        let sig: Signature = self.key.sign(data);
        let bytes = sig.to_bytes();
        let mut out = [0u8; ECDSA_P256_TAG_LEN];
        out.copy_from_slice(&bytes);
        out
    }
}

impl std::fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No se filtra la clave privada.
        f.write_str("EcdsaSigner(ECDSA P-256, ⟨privada oculta⟩)")
    }
}

/// Verificador ECDSA P-256 (solo la clave pública). Se comparte por el suscriptor.
#[derive(Clone, Debug)]
pub struct EcdsaVerifier {
    key: VerifyingKey,
}

impl EcdsaVerifier {
    /// Construye un verificador desde la clave pública en formato SEC1
    /// (comprimido de 33 octetos o sin comprimir de 65).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, EcdsaError> {
        let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| EcdsaError::InvalidKey)?;
        Ok(Self { key })
    }

    /// Clave pública en formato SEC1 comprimido (33 octetos).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.key.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Verifica una firma `r || s` (64 octetos) sobre `data`.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        self.key.verify(data, &signature).is_ok()
    }
}

impl FrameSigner for EcdsaSigner {
    fn tag_len(&self) -> usize {
        ECDSA_P256_TAG_LEN
    }
    fn sign_tag(&self, signed_data: &[u8]) -> Vec<u8> {
        self.sign(signed_data).to_vec()
    }
}

impl FrameVerifier for EcdsaVerifier {
    fn verify_tag(&self, signed_data: &[u8], tag: &[u8]) -> bool {
        self.verify(signed_data, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> EcdsaSigner {
        // Escalar privado de prueba (fijo, válido para P-256).
        EcdsaSigner::from_scalar(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x02, 0x04, 0x06, 0x08, 0x0A,
            0x0C, 0x0E, 0x10, 0x12,
        ])
        .unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let s = signer();
        let v = s.verifier();
        let msg = b"trama GOOSE de ejemplo";
        let sig = s.sign(msg);
        assert_eq!(sig.len(), ECDSA_P256_TAG_LEN);
        assert!(v.verify(msg, &sig));
        // Mensaje alterado.
        assert!(!v.verify(b"trama alterada", &sig));
        // Firma alterada.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!v.verify(msg, &bad));
    }

    #[test]
    fn deterministic_signature_rfc6979() {
        // ECDSA determinista: la misma clave y mensaje dan la misma firma.
        let s = signer();
        assert_eq!(s.sign(b"abc"), s.sign(b"abc"));
    }

    #[test]
    fn wrong_public_key_rejects() {
        let s1 = signer();
        let s2 = EcdsaSigner::from_scalar(&[0x07; 32]).unwrap();
        let sig = s1.sign(b"x");
        assert!(!s2.verifier().verify(b"x", &sig));
    }

    #[test]
    fn public_key_sec1_round_trip() {
        let v = signer().verifier();
        let sec1 = v.to_sec1_bytes();
        let v2 = EcdsaVerifier::from_sec1(&sec1).unwrap();
        let sig = signer().sign(b"m");
        assert!(v2.verify(b"m", &sig));
    }

    #[test]
    fn debug_hides_private_key() {
        assert!(!format!("{:?}", signer()).contains("22"));
    }
}
