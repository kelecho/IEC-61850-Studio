//! Configuración del publicador SV.

use std::time::Duration;

use iec61850_ber::UtcTime;
use iec61850_l2::{MacAddr, Signer, VlanTag};

/// Parámetros de un flujo SV a publicar.
#[derive(Debug, Clone)]
pub struct SvConfig {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<VlanTag>,
    pub appid: u16,
    pub sv_id: String,
    pub dat_set: Option<String>,
    pub conf_rev: u32,
    /// Tasa de muestreo (muestras/s), p. ej. 4000.
    pub smp_rate: u16,
    /// 0=none, 1=local, 2=global.
    pub smp_synch: u8,
    /// Periodo entre muestras (típicamente `1/smp_rate`).
    pub sample_period: Duration,
    /// Incluir `refrTm` (marca de tiempo) en cada ASDU.
    pub include_refr_tm: bool,
    /// Valor al que `smpCnt` vuelve a 0 (normalmente `smp_rate`).
    pub smp_cnt_wrap: u16,
    /// Bit "Simulated" de Ed.2 (Reserved1): publica muestras simuladas/de prueba.
    pub simulation: bool,
    /// Firmante de las tramas (IEC 62351-6): HMAC-SHA256 o ECDSA P-256. `None` =
    /// sin firma.
    pub security: Option<Signer>,
}

impl SvConfig {
    /// Configuración con parámetros esenciales y tasa de 4000 muestras/s.
    pub fn new(dst: MacAddr, src: MacAddr, appid: u16, sv_id: impl Into<String>) -> Self {
        Self {
            dst,
            src,
            vlan: None,
            appid,
            sv_id: sv_id.into(),
            dat_set: None,
            conf_rev: 1,
            smp_rate: 4000,
            smp_synch: 2,
            sample_period: Duration::from_micros(250),
            include_refr_tm: true,
            smp_cnt_wrap: 4000,
            simulation: false,
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

/// Marca de tiempo UTC actual en formato 9-2 (4 s epoch + 3 fracción + 1 calidad).
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
