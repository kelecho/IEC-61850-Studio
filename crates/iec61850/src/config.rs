//! Integración SCL → configuración de GOOSE/SV.
//!
//! Lee el AST de un [`SclDocument`](iec61850_scl::SclDocument) (sección
//! `Communication` + `GSEControl`/`SampledValueControl` en LN0) y produce un
//! [`GooseConfig`](iec61850_goose::GooseConfig) o [`SvConfig`](iec61850_sv::SvConfig)
//! listo para publicar, evitando la configuración manual de MAC/APPID/VLAN.

use iec61850_goose::{GooseConfig, MacAddr, VlanTag};
use iec61850_model::{DatasetMember, Model};
use iec61850_scl::SclDocument;
use iec61850_scl::model::communication::Address;
use iec61850_sv::SvConfig;

/// Error al construir una configuración desde SCL.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IED '{0}' no encontrado en el SCL")]
    IedNotFound(String),
    #[error("bloque de control '{0}' no encontrado en el IED")]
    ControlNotFound(String),
    #[error("no se encontró la dirección de comunicación para '{0}'")]
    AddressNotFound(String),
    #[error("dirección MAC inválida: '{0}'")]
    BadMac(String),
    #[error("APPID inválido: '{0}'")]
    BadAppid(String),
    #[error("dataset '{0}' no encontrado o sin resolver")]
    DatasetNotFound(String),
}

/// Construye un [`GooseConfig`] desde el `GSEControl` `cb_name` del IED `ied`.
/// `src` es la MAC de la interfaz publicadora (no está en el SCL).
pub fn goose_from_scl(
    doc: &SclDocument,
    ied: &str,
    cb_name: &str,
    src: MacAddr,
) -> Result<GooseConfig, ConfigError> {
    let (gc, ld_inst, ln_name) = find_gse_control(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::ControlNotFound(cb_name.into()))?;
    let address = find_gse_address(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::AddressNotFound(cb_name.into()))?;

    let dst = parse_mac(address.param("MAC-Address").unwrap_or(""))?;
    let appid = parse_appid(address.param("APPID").unwrap_or(""))?;

    let mut cfg = GooseConfig::new(
        dst,
        src,
        appid,
        format!("{ied}{ld_inst}/{ln_name}$GO${cb_name}"),
    );
    cfg.dat_set = gc.dat_set.clone().unwrap_or_default();
    cfg.go_id = gc.app_id.clone().unwrap_or_else(|| cb_name.to_string());
    cfg.conf_rev = gc.conf_rev.unwrap_or(1);
    cfg.vlan = parse_vlan(address);
    Ok(cfg)
}

/// Construye un [`SvConfig`] desde el `SampledValueControl` `cb_name` del IED.
pub fn sv_from_scl(
    doc: &SclDocument,
    ied: &str,
    cb_name: &str,
    src: MacAddr,
) -> Result<SvConfig, ConfigError> {
    let (sc, _ld_inst) = find_smv_control(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::ControlNotFound(cb_name.into()))?;
    let address = find_smv_address(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::AddressNotFound(cb_name.into()))?;

    let dst = parse_mac(address.param("MAC-Address").unwrap_or(""))?;
    let appid = parse_appid(address.param("APPID").unwrap_or(""))?;

    let sv_id = sc.smv_id.clone().unwrap_or_else(|| cb_name.to_string());
    let mut cfg = SvConfig::new(dst, src, appid, sv_id);
    cfg.dat_set = sc.dat_set.clone();
    cfg.conf_rev = sc.conf_rev.unwrap_or(1);
    cfg.vlan = parse_vlan(address);
    Ok(cfg)
}

/// Miembros (ordenados, con referencia/FC/tipo) del dataset del `GSEControl`.
pub fn goose_dataset_members(
    doc: &SclDocument,
    model: &Model,
    ied: &str,
    cb_name: &str,
) -> Result<Vec<DatasetMember>, ConfigError> {
    let (gc, ld_inst, _ln) = find_gse_control(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::ControlNotFound(cb_name.into()))?;
    let ds = gc
        .dat_set
        .as_deref()
        .ok_or_else(|| ConfigError::DatasetNotFound(cb_name.into()))?;
    let domain = format!("{ied}{ld_inst}");
    model
        .resolve_dataset(&domain, ds)
        .ok_or_else(|| ConfigError::DatasetNotFound(ds.into()))
}

/// Miembros del dataset del `SampledValueControl`.
pub fn sv_dataset_members(
    doc: &SclDocument,
    model: &Model,
    ied: &str,
    cb_name: &str,
) -> Result<Vec<DatasetMember>, ConfigError> {
    let (sc, ld_inst) = find_smv_control(doc, ied, cb_name)
        .ok_or_else(|| ConfigError::ControlNotFound(cb_name.into()))?;
    let ds = sc
        .dat_set
        .as_deref()
        .ok_or_else(|| ConfigError::DatasetNotFound(cb_name.into()))?;
    let domain = format!("{ied}{ld_inst}");
    model
        .resolve_dataset(&domain, ds)
        .ok_or_else(|| ConfigError::DatasetNotFound(ds.into()))
}

/// Localiza un `GSEControl` por nombre; devuelve `(control, ldInst, lnName)`.
fn find_gse_control<'a>(
    doc: &'a SclDocument,
    ied: &str,
    cb_name: &str,
) -> Option<(&'a iec61850_scl::model::control::GseControl, String, String)> {
    let ied = doc.ieds.iter().find(|i| i.name == ied)?;
    for ap in &ied.access_points {
        let Some(server) = &ap.server else { continue };
        for ld in &server.ldevices {
            for ln in ld.all_lns() {
                for gc in &ln.gse_controls {
                    if gc.name == cb_name {
                        let ln_name = format!("{}{}{}", ln.prefix, ln.ln_class, ln.inst);
                        return Some((gc, ld.inst.clone(), ln_name));
                    }
                }
            }
        }
    }
    None
}

fn find_smv_control<'a>(
    doc: &'a SclDocument,
    ied: &str,
    cb_name: &str,
) -> Option<(&'a iec61850_scl::model::control::SmvControl, String)> {
    let ied = doc.ieds.iter().find(|i| i.name == ied)?;
    for ap in &ied.access_points {
        let Some(server) = &ap.server else { continue };
        for ld in &server.ldevices {
            for ln in ld.all_lns() {
                if let Some(sc) = ln.smv_controls.iter().find(|s| s.name == cb_name) {
                    return Some((sc, ld.inst.clone()));
                }
            }
        }
    }
    None
}

fn find_gse_address<'a>(doc: &'a SclDocument, ied: &str, cb_name: &str) -> Option<&'a Address> {
    let comm = doc.communication.as_ref()?;
    for sn in &comm.sub_networks {
        for ap in &sn.connected_aps {
            if ap.ied_name != ied {
                continue;
            }
            for gse in &ap.gse {
                if gse.cb_name.as_deref() == Some(cb_name) {
                    return gse.address.as_ref();
                }
            }
        }
    }
    None
}

fn find_smv_address<'a>(doc: &'a SclDocument, ied: &str, cb_name: &str) -> Option<&'a Address> {
    let comm = doc.communication.as_ref()?;
    for sn in &comm.sub_networks {
        for ap in &sn.connected_aps {
            if ap.ied_name != ied {
                continue;
            }
            for smv in &ap.smv {
                if smv.cb_name.as_deref() == Some(cb_name) {
                    return smv.address.as_ref();
                }
            }
        }
    }
    None
}

/// Parsea una MAC `"01-0C-CD-01-00-01"` o `"01:0C:..."`.
fn parse_mac(s: &str) -> Result<MacAddr, ConfigError> {
    let parts: Vec<&str> = s.split(['-', ':']).collect();
    if parts.len() != 6 {
        return Err(ConfigError::BadMac(s.into()));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p.trim(), 16).map_err(|_| ConfigError::BadMac(s.into()))?;
    }
    Ok(mac)
}

/// Parsea un APPID en hexadecimal (`"0001"`).
fn parse_appid(s: &str) -> Result<u16, ConfigError> {
    let s = s.trim().trim_start_matches("0x");
    u16::from_str_radix(s, 16).map_err(|_| ConfigError::BadAppid(s.into()))
}

/// Construye la VLAN desde `VLAN-ID` (hex) y `VLAN-PRIORITY` (decimal), si existen.
fn parse_vlan(address: &Address) -> Option<VlanTag> {
    let vid_s = address.param("VLAN-ID")?;
    let vid = u16::from_str_radix(vid_s.trim().trim_start_matches("0x"), 16).ok()?;
    let pcp = address
        .param("VLAN-PRIORITY")
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(4);
    Some(VlanTag {
        pcp,
        dei: false,
        vid: vid & 0x0FFF,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_and_appid_parsers() {
        assert_eq!(
            parse_mac("01-0C-CD-01-00-01").unwrap(),
            [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]
        );
        assert_eq!(
            parse_mac("01:0C:CD:04:00:0A").unwrap(),
            [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x0A]
        );
        assert!(parse_mac("01-02-03").is_err());
        assert_eq!(parse_appid("4001").unwrap(), 0x4001);
        assert!(parse_appid("zz").is_err());
    }
}
