//! Gestión del ciclo de vida de las **claves de grupo** GOOSE/SV (IEC 62351-9).
//!
//! Un [`KeyRing`] mantiene varias claves con un **identificador** (`key_id`) y una
//! **ventana de validez** temporal (`not_before`..`not_after`, en segundos epoch).
//! Con él se modela la **rotación con solapamiento**: la clave nueva se aprovisiona
//! con validez futura y, durante la transición, tanto la vieja como la nueva están
//! vigentes, de modo que no se pierden tramas mientras todos los IEDs adoptan la
//! nueva.
//!
//! - El **publicador** firma con la clave **activa** (la vigente de mayor `key_id`).
//! - El **suscriptor** acepta cualquier clave **vigente** (`valid`), lo que cubre
//!   el solapamiento.
//!
//! La *distribución* de las claves (un GKMS/GDOI real, IEC 62351-9 §9) queda fuera
//! de alcance: aquí se modela el almacén y la política de rotación, que es lo que
//! consume la pila GOOSE/SV. El anillo se conecta a [`crate::auth::Signer`] /
//! [`crate::auth::Verifier`] mediante sus variantes `Ring`.

use crate::auth::{FrameSigner, FrameVerifier};

/// Segundos transcurridos desde el epoch Unix (reloj del sistema).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Una clave del anillo, con su identificador y ventana de validez.
#[derive(Debug, Clone)]
pub struct KeyEntry<T> {
    /// Identificador de la clave (mayor = más reciente). Elige la clave activa.
    pub key_id: u32,
    /// Inicio de validez (epoch s). `0` = sin límite inferior.
    pub not_before: u64,
    /// Fin de validez, exclusivo (epoch s). `u64::MAX` = sin expiración.
    pub not_after: u64,
    /// Material de la clave (un [`crate::auth::Signer`] o `Verifier`).
    pub material: T,
}

impl<T> KeyEntry<T> {
    /// ¿La clave es válida en el instante `now` (epoch s)?
    pub fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// Anillo de claves de grupo con rotación (IEC 62351-9). Genérico sobre el
/// material: [`SignerRing`] para publicar, [`VerifierRing`] para suscribir.
#[derive(Debug, Clone)]
pub struct KeyRing<T> {
    entries: Vec<KeyEntry<T>>,
}

impl<T> Default for KeyRing<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> KeyRing<T> {
    /// Anillo vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade una clave con su `key_id` y ventana de validez.
    pub fn insert(&mut self, key_id: u32, not_before: u64, not_after: u64, material: T) {
        self.entries.push(KeyEntry {
            key_id,
            not_before,
            not_after,
            material,
        });
    }

    /// Igual que [`insert`](Self::insert), pero para una clave **sin expiración**
    /// (válida desde siempre). Cómodo para claves fijas o pruebas.
    pub fn insert_permanent(&mut self, key_id: u32, material: T) {
        self.insert(key_id, 0, u64::MAX, material);
    }

    /// Constructor encadenable: añade una clave permanente y devuelve el anillo.
    pub fn with_permanent(mut self, key_id: u32, material: T) -> Self {
        self.insert_permanent(key_id, material);
        self
    }

    /// La clave **activa** en `now`: la vigente con mayor `key_id` (la más
    /// reciente). Es la que usa el publicador para firmar.
    pub fn active(&self, now: u64) -> Option<&KeyEntry<T>> {
        self.entries
            .iter()
            .filter(|e| e.valid_at(now))
            .max_by_key(|e| e.key_id)
    }

    /// Todas las claves **vigentes** en `now` (para verificar durante el
    /// solapamiento de una rotación).
    pub fn valid(&self, now: u64) -> impl Iterator<Item = &KeyEntry<T>> {
        self.entries.iter().filter(move |e| e.valid_at(now))
    }

    /// Elimina las claves ya expiradas en `now` (`not_after <= now`).
    pub fn purge_expired(&mut self, now: u64) {
        self.entries.retain(|e| e.not_after > now);
    }

    /// Número de claves del anillo.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ¿El anillo está vacío?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Anillo de claves para **firmar** (publicador).
pub type SignerRing = KeyRing<crate::auth::Signer>;
/// Anillo de claves para **verificar** (suscriptor).
pub type VerifierRing = KeyRing<crate::auth::Verifier>;

impl FrameSigner for SignerRing {
    fn tag_len(&self) -> usize {
        self.active(now_secs())
            .map(|e| e.material.tag_len())
            .unwrap_or(0)
    }
    fn sign_tag(&self, signed_data: &[u8]) -> Vec<u8> {
        self.active(now_secs())
            .map(|e| e.material.sign_tag(signed_data))
            .unwrap_or_default()
    }
}

impl FrameVerifier for VerifierRing {
    fn verify_tag(&self, signed_data: &[u8], tag: &[u8]) -> bool {
        let now = now_secs();
        self.valid(now)
            .any(|e| e.material.verify_tag(signed_data, tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_picks_highest_valid_key_id() {
        let mut ring: KeyRing<&str> = KeyRing::new();
        ring.insert_permanent(1, "k1");
        ring.insert_permanent(3, "k3");
        ring.insert_permanent(2, "k2");
        assert_eq!(ring.active(100).unwrap().material, "k3");
    }

    #[test]
    fn rotation_with_overlap() {
        // Clave 1 válida [0, 200); clave 2 válida [100, 300). Solapan en [100, 200).
        let mut ring: KeyRing<&str> = KeyRing::new();
        ring.insert(1, 0, 200, "old");
        ring.insert(2, 100, 300, "new");

        // Antes del solape: solo la vieja está activa.
        assert_eq!(ring.active(50).unwrap().material, "old");
        assert_eq!(ring.valid(50).count(), 1);

        // Durante el solape: ambas vigentes; la activa es la nueva (mayor key_id).
        assert_eq!(ring.active(150).unwrap().material, "new");
        assert_eq!(ring.valid(150).count(), 2);

        // Tras expirar la vieja: solo la nueva.
        assert_eq!(ring.active(250).unwrap().material, "new");
        assert_eq!(ring.valid(250).count(), 1);

        // Todo expirado.
        assert!(ring.active(400).is_none());
        assert_eq!(ring.valid(400).count(), 0);
    }

    #[test]
    fn purge_removes_expired() {
        let mut ring: KeyRing<&str> = KeyRing::new();
        ring.insert(1, 0, 200, "old");
        ring.insert(2, 100, 300, "new");
        ring.purge_expired(250); // expira la clave 1 (not_after=200 <= 250)
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.active(250).unwrap().material, "new");
    }

    #[test]
    fn no_valid_key_outside_windows() {
        let mut ring: KeyRing<&str> = KeyRing::new();
        ring.insert(1, 100, 200, "k");
        assert!(ring.active(50).is_none());
        assert!(ring.active(200).is_none()); // not_after es exclusivo
        assert!(ring.active(150).is_some());
    }
}
