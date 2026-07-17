//! Configuración de un publicador GOOSE.

use std::time::Duration;

use iec61850_ber::UtcTime;

use crate::frame::{MacAddr, Signer, VlanTag};

/// Parámetros de un control block GOOSE para publicar.
#[derive(Debug, Clone)]
pub struct GooseConfig {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<VlanTag>,
    pub appid: u16,
    pub gocb_ref: String,
    pub dat_set: String,
    pub go_id: String,
    pub conf_rev: u32,
    pub test: bool,
    /// Bit "Simulated" de Ed.2 (Reserved1): publica tramas que un IED en modo
    /// simulación acepta en lugar de las reales. Clave para pruebas de esquemas.
    pub simulation: bool,
    /// Intervalo mínimo de retransmisión tras un cambio de estado (T1, ~4 ms).
    pub t_min: Duration,
    /// Intervalo estable máximo de retransmisión (~1000 ms).
    pub t_max: Duration,
    /// Firmante de las tramas (IEC 62351-6): HMAC-SHA256 o ECDSA P-256. `None` =
    /// sin firma.
    pub security: Option<Signer>,
}

impl GooseConfig {
    /// Crea una configuración con los parámetros esenciales y valores por
    /// defecto de retransmisión (4 ms .. 1000 ms) sin VLAN.
    pub fn new(dst: MacAddr, src: MacAddr, appid: u16, gocb_ref: impl Into<String>) -> Self {
        Self {
            dst,
            src,
            vlan: None,
            appid,
            gocb_ref: gocb_ref.into(),
            dat_set: String::new(),
            go_id: String::new(),
            conf_rev: 1,
            test: false,
            simulation: false,
            t_min: Duration::from_millis(4),
            t_max: Duration::from_millis(1000),
            security: None,
        }
    }

    /// Activa la firma de tramas (IEC 62351-6) con el firmante dado (una
    /// [`HmacKey`](crate::HmacKey) o un `EcdsaSigner`).
    pub fn with_security(mut self, signer: impl Into<Signer>) -> Self {
        self.security = Some(signer.into());
        self
    }
}

/// Marca de tiempo UTC actual en formato MMS (4 s epoch + 3 fracción + 1 calidad).
pub fn now_utc() -> UtcTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut raw = [0u8; 8];
    if let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) {
        raw[0..4].copy_from_slice(&(d.as_secs() as u32).to_be_bytes());
        let frac = ((d.subsec_nanos() as u64) << 24) / 1_000_000_000;
        let fb = (frac as u32).to_be_bytes();
        raw[4..7].copy_from_slice(&fb[1..4]);
    }
    raw[7] = 0x0A;
    UtcTime { raw }
}
