//! **Access tokens firmados** para RBAC (IEC 62351-8).
//!
//! En lugar de que el servidor mantenga un mapeo estático de credenciales a roles
//! (password→rol, CN→rol), el cliente presenta un *token* emitido por una
//! **autoridad** que contiene su identidad, su rol y una ventana de validez, todo
//! **firmado**. El servidor solo necesita la clave (pública, o compartida) de la
//! autoridad para verificar el token y confiar en el rol que declara.
//!
//! La firma reutiliza las primitivas de [`iec61850_l2`] (la criptografía
//! compartida del proyecto): **HMAC-SHA256** (autoridad y servidor comparten
//! secreto) o **ECDSA P-256** (la autoridad firma con su privada; el servidor
//! verifica con la pública). El token se transporta en el `authentication-value`
//! del AARQ, igual que el password (IEC 62351-4).
//!
//! Formato (BER):
//! ```text
//! SignedToken ::= SEQUENCE { claims OCTET STRING, signature OCTET STRING }
//! Claims      ::= SEQUENCE { subject VisibleString, role INTEGER,
//!                            issuer VisibleString, notBefore INTEGER,
//!                            notAfter INTEGER }
//! ```
//! La firma cubre los octetos DER de `Claims` tal cual se embeben (sin reencode).

use iec61850_l2::{FrameSigner, FrameVerifier, Signer, Verifier};

use crate::ber::reader::BerReader;
use crate::ber::tag::universal;
use crate::ber::writer::BerWriter;
use crate::server::{Permissions, Role};

/// Reclamaciones (*claims*) de un access token 62351-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// Identidad del titular (p. ej. `"operator@subestacion"`).
    pub subject: String,
    /// Rol RBAC concedido.
    pub role: Role,
    /// Autoridad emisora.
    pub issuer: String,
    /// Inicio de validez (epoch s).
    pub not_before: u64,
    /// Fin de validez, exclusivo (epoch s).
    pub not_after: u64,
}

/// Error al verificar un access token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// El token no está bien formado (BER inválido o campos ausentes).
    #[error("access token malformado")]
    Malformed,
    /// La firma no valida con la clave de la autoridad.
    #[error("firma del access token inválida")]
    BadSignature,
    /// El token está fuera de su ventana de validez.
    #[error("access token expirado o aún no válido")]
    Expired,
}

fn encode_claims(t: &AccessToken) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.tlv(universal::SEQUENCE, |w| {
        w.visible_string(universal::VISIBLE_STRING, &t.subject);
        // El rol viaja como su **conjunto de permisos** (bits): así los roles
        // personalizados (Role::Custom) también se transportan sin perder detalle.
        w.integer(universal::INTEGER, t.role.permissions().bits() as i64);
        w.visible_string(universal::VISIBLE_STRING, &t.issuer);
        w.integer(universal::INTEGER, t.not_before as i64);
        w.integer(universal::INTEGER, t.not_after as i64);
    });
    w.into_bytes()
}

fn decode_claims(bytes: &[u8]) -> Result<AccessToken, TokenError> {
    let mut r = BerReader::new(bytes);
    let seq = r.read_tlv().map_err(|_| TokenError::Malformed)?;
    if seq.tag != universal::SEQUENCE {
        return Err(TokenError::Malformed);
    }
    let mut cr = BerReader::new(seq.content);
    let read_str = |cr: &mut BerReader| -> Result<String, TokenError> {
        let c = cr
            .expect(universal::VISIBLE_STRING)
            .map_err(|_| TokenError::Malformed)?;
        Ok(crate::ber::prim::decode_visible_string(c)
            .map_err(|_| TokenError::Malformed)?
            .to_string())
    };
    let read_int = |cr: &mut BerReader| -> Result<i64, TokenError> {
        let c = cr
            .expect(universal::INTEGER)
            .map_err(|_| TokenError::Malformed)?;
        crate::ber::prim::decode_integer(c).map_err(|_| TokenError::Malformed)
    };

    let subject = read_str(&mut cr)?;
    let role = Role::from_permissions(Permissions::from_bits(read_int(&mut cr)? as u16));
    let issuer = read_str(&mut cr)?;
    let not_before = read_int(&mut cr)? as u64;
    let not_after = read_int(&mut cr)? as u64;
    Ok(AccessToken {
        subject,
        role,
        issuer,
        not_before,
        not_after,
    })
}

/// **Emite** (firma) un access token con la clave de la autoridad. `signer` puede
/// ser un `Signer::Hmac` o `Signer::Ecdsa`.
pub fn issue(token: &AccessToken, signer: &Signer) -> Vec<u8> {
    let claims = encode_claims(token);
    let signature = signer.sign_tag(&claims);
    let mut w = BerWriter::new();
    w.tlv(universal::SEQUENCE, |w| {
        w.octet_string(universal::OCTET_STRING, &claims);
        w.octet_string(universal::OCTET_STRING, &signature);
    });
    w.into_bytes()
}

/// **Verifica** un access token con la clave de la autoridad y comprueba su
/// vigencia en `now` (epoch s). Devuelve las claims si todo es correcto.
pub fn verify(bytes: &[u8], authority: &Verifier, now: u64) -> Result<AccessToken, TokenError> {
    let mut r = BerReader::new(bytes);
    let outer = r.read_tlv().map_err(|_| TokenError::Malformed)?;
    if outer.tag != universal::SEQUENCE {
        return Err(TokenError::Malformed);
    }
    let mut ir = BerReader::new(outer.content);
    let claims = ir
        .expect(universal::OCTET_STRING)
        .map_err(|_| TokenError::Malformed)?;
    let signature = ir
        .expect(universal::OCTET_STRING)
        .map_err(|_| TokenError::Malformed)?;

    if !authority.verify_tag(claims, signature) {
        return Err(TokenError::BadSignature);
    }
    let token = decode_claims(claims)?;
    if !(token.not_before <= now && now < token.not_after) {
        return Err(TokenError::Expired);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_l2::HmacKey;

    fn sample() -> AccessToken {
        AccessToken {
            subject: "operator@subestacion".into(),
            role: Role::Operator,
            issuer: "AA-central".into(),
            not_before: 1_000,
            not_after: 2_000,
        }
    }

    #[test]
    fn hmac_issue_verify_round_trip() {
        let key: Signer = HmacKey::new(b"clave-autoridad").into();
        let auth: Verifier = HmacKey::new(b"clave-autoridad").into();
        let token = issue(&sample(), &key);
        let got = verify(&token, &auth, 1_500).unwrap();
        assert_eq!(got, sample());
        assert_eq!(got.role, Role::Operator);
    }

    #[test]
    fn rejects_wrong_authority() {
        let key: Signer = HmacKey::new(b"clave-buena").into();
        let auth: Verifier = HmacKey::new(b"clave-mala").into();
        let token = issue(&sample(), &key);
        assert_eq!(verify(&token, &auth, 1_500), Err(TokenError::BadSignature));
    }

    #[test]
    fn rejects_tampered_claims() {
        let key: Signer = HmacKey::new(b"k").into();
        let auth: Verifier = HmacKey::new(b"k").into();
        let mut token = issue(&sample(), &key);
        // Altera un octeto dentro de las claims embebidas.
        let n = token.len();
        token[n / 2] ^= 0x01;
        assert!(verify(&token, &auth, 1_500).is_err());
    }

    #[test]
    fn rejects_outside_validity_window() {
        let key: Signer = HmacKey::new(b"k").into();
        let auth: Verifier = HmacKey::new(b"k").into();
        let token = issue(&sample(), &key);
        assert_eq!(verify(&token, &auth, 500), Err(TokenError::Expired)); // antes
        assert_eq!(verify(&token, &auth, 2_000), Err(TokenError::Expired)); // not_after exclusivo
        assert!(verify(&token, &auth, 1_999).is_ok());
    }

    #[test]
    fn custom_role_round_trips_via_permission_bits() {
        // Un rol personalizado (permisos arbitrarios) sobrevive al token porque se
        // serializa por su conjunto de permisos, no por un ordinal.
        let key: Signer = HmacKey::new(b"k").into();
        let auth: Verifier = HmacKey::new(b"k").into();
        let role = Role::Custom(Permissions::DATA_READ | Permissions::CONTROL);
        let token = issue(&AccessToken { role, ..sample() }, &key);
        let got = verify(&token, &auth, 1_500).unwrap();
        assert_eq!(got.role, role);
    }

    #[test]
    fn ecdsa_issue_verify_round_trip() {
        use iec61850_l2::EcdsaSigner;
        let signer = EcdsaSigner::from_scalar(&[0x2A; 32]).unwrap();
        let authority: Verifier = signer.verifier().into();
        let token = issue(&sample(), &signer.into());
        let got = verify(&token, &authority, 1_500).unwrap();
        assert_eq!(got.role, Role::Operator);
        // Otra autoridad (clave pública distinta) rechaza.
        let other: Verifier = EcdsaSigner::from_scalar(&[0x3B; 32])
            .unwrap()
            .verifier()
            .into();
        assert_eq!(verify(&token, &other, 1_500), Err(TokenError::BadSignature));
    }
}
