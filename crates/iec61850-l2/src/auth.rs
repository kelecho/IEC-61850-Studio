//! Autenticación de tramas GOOSE/SV (IEC 62351-6): **HMAC-SHA256** con clave
//! simétrica compartida.
//!
//! La primitiva criptográfica se implementa **sin dependencias externas**,
//! coherente con el resto del stack (el BER, el base64 y el PEM también son
//! propios). SHA-256 y HMAC son deterministas y se validan aquí con los vectores
//! oficiales (NIST FIPS 180-4 y RFC 4231).
//!
//! Perfil de trama (ver [`crate::eth`]): el tag de autenticación se **anexa tras
//! el APDU** y su longitud se señala en el campo `Reserved2` de la cabecera de
//! aplicación de 8 octetos. El MAC cubre desde el octeto `APPID` hasta el final
//! del APDU (los 8 octetos de cabecera —con `Length` y `Reserved2` ya fijados— más
//! el APDU), de modo que la verificación es autoconsistente sin ambigüedad.

/// Longitud del tag HMAC-SHA256 completo, en octetos.
pub const HMAC_SHA256_TAG_LEN: usize = 32;

/// Resultado de comprobar la autenticación de una trama recibida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// La trama no traía tag de autenticación (`Reserved2 == 0`).
    Unsigned,
    /// Traía tag y la autenticación coincide con la clave configurada.
    Valid,
    /// Traía tag pero no coincide (clave distinta o manipulación).
    Invalid,
}

/// Algo capaz de **firmar** una trama GOOSE/SV (IEC 62351-6): produce el tag de
/// autenticación que se anexa tras el APDU. Lo implementan [`HmacKey`]
/// (simétrico) y, con la feature `ecdsa`, `EcdsaSigner` (asimétrico).
pub trait FrameSigner {
    /// Longitud (en octetos) del tag que produce. Se codifica en `Reserved2`.
    fn tag_len(&self) -> usize;
    /// Calcula el tag sobre los octetos firmados (`APPID`..fin del APDU).
    fn sign_tag(&self, signed_data: &[u8]) -> Vec<u8>;
}

/// Algo capaz de **verificar** el tag de una trama GOOSE/SV.
pub trait FrameVerifier {
    /// ¿El `tag` es válido para `signed_data`?
    fn verify_tag(&self, signed_data: &[u8], tag: &[u8]) -> bool;
}

impl FrameSigner for HmacKey {
    fn tag_len(&self) -> usize {
        HMAC_SHA256_TAG_LEN
    }
    fn sign_tag(&self, signed_data: &[u8]) -> Vec<u8> {
        self.mac(signed_data).to_vec()
    }
}

impl FrameVerifier for HmacKey {
    fn verify_tag(&self, signed_data: &[u8], tag: &[u8]) -> bool {
        self.verify(signed_data, tag)
    }
}

/// Firmante concreto de tramas: HMAC-SHA256 (simétrico) o, con la feature
/// `ecdsa`, ECDSA P-256 (asimétrico). Es el tipo que almacena la configuración
/// del publicador; acepta cualquiera vía [`From`].
#[derive(Clone, Debug)]
pub enum Signer {
    /// Autenticación simétrica HMAC-SHA256.
    Hmac(HmacKey),
    /// Firma asimétrica ECDSA P-256 (IEC 62351-6:2020).
    #[cfg(feature = "ecdsa")]
    Ecdsa(crate::sign::EcdsaSigner),
    /// Anillo de claves de grupo con rotación (IEC 62351-9): firma con la clave
    /// activa según su ventana de validez.
    Ring(std::sync::Arc<crate::keystore::KeyRing<Signer>>),
}

/// Verificador concreto: contraparte de [`Signer`].
#[derive(Clone, Debug)]
pub enum Verifier {
    /// Verificación simétrica HMAC-SHA256.
    Hmac(HmacKey),
    /// Verificación de firma ECDSA P-256 (solo clave pública).
    #[cfg(feature = "ecdsa")]
    Ecdsa(crate::sign::EcdsaVerifier),
    /// Anillo de claves de grupo (IEC 62351-9): acepta cualquier clave vigente
    /// (cubre el solapamiento de una rotación).
    Ring(std::sync::Arc<crate::keystore::KeyRing<Verifier>>),
}

impl FrameSigner for Signer {
    fn tag_len(&self) -> usize {
        match self {
            Signer::Hmac(k) => k.tag_len(),
            #[cfg(feature = "ecdsa")]
            Signer::Ecdsa(s) => s.tag_len(),
            Signer::Ring(r) => r.tag_len(),
        }
    }
    fn sign_tag(&self, signed_data: &[u8]) -> Vec<u8> {
        match self {
            Signer::Hmac(k) => k.sign_tag(signed_data),
            #[cfg(feature = "ecdsa")]
            Signer::Ecdsa(s) => s.sign_tag(signed_data),
            Signer::Ring(r) => r.sign_tag(signed_data),
        }
    }
}

impl FrameVerifier for Verifier {
    fn verify_tag(&self, signed_data: &[u8], tag: &[u8]) -> bool {
        match self {
            Verifier::Hmac(k) => k.verify_tag(signed_data, tag),
            #[cfg(feature = "ecdsa")]
            Verifier::Ecdsa(v) => v.verify_tag(signed_data, tag),
            Verifier::Ring(r) => r.verify_tag(signed_data, tag),
        }
    }
}

impl From<crate::keystore::KeyRing<Signer>> for Signer {
    fn from(ring: crate::keystore::KeyRing<Signer>) -> Self {
        Signer::Ring(std::sync::Arc::new(ring))
    }
}

impl From<crate::keystore::KeyRing<Verifier>> for Verifier {
    fn from(ring: crate::keystore::KeyRing<Verifier>) -> Self {
        Verifier::Ring(std::sync::Arc::new(ring))
    }
}

impl From<HmacKey> for Signer {
    fn from(k: HmacKey) -> Self {
        Signer::Hmac(k)
    }
}

impl From<HmacKey> for Verifier {
    fn from(k: HmacKey) -> Self {
        Verifier::Hmac(k)
    }
}

#[cfg(feature = "ecdsa")]
impl From<crate::sign::EcdsaSigner> for Signer {
    fn from(s: crate::sign::EcdsaSigner) -> Self {
        Signer::Ecdsa(s)
    }
}

#[cfg(feature = "ecdsa")]
impl From<crate::sign::EcdsaVerifier> for Verifier {
    fn from(v: crate::sign::EcdsaVerifier) -> Self {
        Verifier::Ecdsa(v)
    }
}

// --- SHA-256 (FIPS 180-4) ---------------------------------------------------

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLOCK: usize = 64;

/// Estado incremental de SHA-256. Permite alimentar `ipad`/`opad` y el mensaje
/// por separado (para HMAC) sin concatenar buffers.
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buf: [u8; BLOCK],
    buf_len: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H0,
            buf: [0; BLOCK],
            buf_len: 0,
            total: 0,
        }
    }

    /// Procesa un bloque completo de 64 octetos.
    fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    /// Alimenta octetos sin actualizar el contador total (uso interno para el
    /// padding de la finalización).
    fn consume(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let need = BLOCK - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= BLOCK {
            let block: [u8; BLOCK] = data[..BLOCK].try_into().unwrap();
            Self::compress(&mut self.state, &block);
            data = &data[BLOCK..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        self.consume(data);
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        // 0x80 seguido de ceros hasta dejar 8 octetos para la longitud.
        let mut pad = [0u8; BLOCK + 8];
        pad[0] = 0x80;
        let rem = (self.buf_len + 1) % BLOCK;
        let zeros = if rem <= 56 {
            56 - rem
        } else {
            56 + BLOCK - rem
        };
        self.consume(&pad[..1 + zeros]);
        self.consume(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-256 de un mensaje completo.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg);
    h.finalize()
}

// --- HMAC-SHA256 (RFC 2104) -------------------------------------------------

/// Clave HMAC-SHA256 preparada (los bloques `ipad`/`opad` ya derivados). Es la
/// clave simétrica compartida entre publicador y suscriptor de un flujo
/// GOOSE/SV. Su gestión/distribución corresponde a IEC 62351-9 (fuera de alcance).
#[derive(Clone)]
pub struct HmacKey {
    ipad: [u8; BLOCK],
    opad: [u8; BLOCK],
}

impl HmacKey {
    /// Deriva la clave a partir de un material arbitrario (claves largas se
    /// reducen con SHA-256, como exige RFC 2104).
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        Self { ipad, opad }
    }

    /// Calcula el tag HMAC-SHA256 (32 octetos) del mensaje.
    pub fn mac(&self, msg: &[u8]) -> [u8; 32] {
        let mut inner = Sha256::new();
        inner.update(&self.ipad);
        inner.update(msg);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Verifica un tag recibido en tiempo constante. Solo acepta el tag completo
    /// de 32 octetos.
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        tag.len() == HMAC_SHA256_TAG_LEN && ct_eq(&self.mac(msg), tag)
    }
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No se filtra material de clave en logs/depuración.
        f.write_str("HmacKey(HMAC-SHA256, ⟨oculta⟩)")
    }
}

/// Comparación en tiempo constante (evita fugas por temporización al validar un
/// MAC frente a un valor controlado por el atacante).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_nist_vectors() {
        // FIPS 180-4 ejemplos.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_multiblock() {
        // Un millón de 'a' → vector conocido de FIPS 180-4 (ejercita el modo
        // incremental sobre muchos bloques).
        let mut h = Sha256::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hmac_rfc4231_vectors() {
        // RFC 4231 Test Case 1.
        let k = HmacKey::new(&[0x0b; 20]);
        assert_eq!(
            hex(&k.mac(b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 Test Case 2.
        let k = HmacKey::new(b"Jefe");
        assert_eq!(
            hex(&k.mac(b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 4231 Test Case 6 (clave de 131 octetos > bloque → se hashea).
        let k = HmacKey::new(&[0xaa; 131]);
        assert_eq!(
            hex(&k.mac(b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let k = HmacKey::new(b"clave-goose-de-prueba");
        let msg = b"trama GOOSE de ejemplo";
        let tag = k.mac(msg);
        assert!(k.verify(msg, &tag));

        // Mensaje alterado.
        assert!(!k.verify(b"trama GOOSE alterada!", &tag));
        // Tag alterado.
        let mut bad = tag;
        bad[0] ^= 0x01;
        assert!(!k.verify(msg, &bad));
        // Longitud incorrecta.
        assert!(!k.verify(msg, &tag[..16]));
        // Clave distinta.
        let k2 = HmacKey::new(b"otra-clave");
        assert!(!k2.verify(msg, &tag));
    }

    #[test]
    fn debug_hides_key_material() {
        let k = HmacKey::new(b"secreto");
        assert!(!format!("{k:?}").contains("secreto"));
    }
}
