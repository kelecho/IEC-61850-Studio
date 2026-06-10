//! Integración SCL → config de GOOSE/SV (feature `config`).
#![cfg(feature = "config")]

use std::path::PathBuf;

use iec61850::config::{goose_dataset_members, goose_from_scl, sv_dataset_members, sv_from_scl};
use iec61850::model::BasicType;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/scd/goose_sv.scd")
}

const SRC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[test]
fn goose_config_from_scl() {
    let doc = iec61850::scl::parse_scl_file(fixture()).unwrap();
    let cfg = goose_from_scl(&doc, "IED1", "gcb01", SRC).unwrap();

    assert_eq!(cfg.dst, [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]);
    assert_eq!(cfg.src, SRC);
    assert_eq!(cfg.appid, 0x0001);
    assert_eq!(cfg.gocb_ref, "IED1LD0/LLN0$GO$gcb01");
    assert_eq!(cfg.dat_set, "ds1");
    assert_eq!(cfg.go_id, "GE1");
    assert_eq!(cfg.conf_rev, 1);
    let vlan = cfg.vlan.expect("VLAN configurada");
    assert_eq!(vlan.vid, 100); // 0x064
    assert_eq!(vlan.pcp, 4);
}

#[test]
fn sv_config_from_scl() {
    let doc = iec61850::scl::parse_scl_file(fixture()).unwrap();
    let cfg = sv_from_scl(&doc, "IED1", "smv01", SRC).unwrap();

    assert_eq!(cfg.dst, [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01]);
    assert_eq!(cfg.appid, 0x4000);
    assert_eq!(cfg.sv_id, "MU01");
    assert_eq!(cfg.dat_set.as_deref(), Some("ds1"));
    assert_eq!(cfg.conf_rev, 1);
    assert_eq!(cfg.vlan.expect("VLAN").vid, 101); // 0x065
}

#[test]
fn dataset_members_resolved() {
    let doc = iec61850::scl::parse_scl_file(fixture()).unwrap();
    let model = doc.resolve().unwrap();

    let members = goose_dataset_members(&doc, &model, "IED1", "gcb01").unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].reference.to_string(),
        "IED1LD0/LLN0.Mod.stVal[ST]"
    );
    assert_eq!(members[0].basic_type, Some(BasicType::Int32));

    // El SMV usa el mismo dataset ds1.
    let sv_members = sv_dataset_members(&doc, &model, "IED1", "smv01").unwrap();
    assert_eq!(sv_members.len(), 1);
    assert_eq!(sv_members[0].basic_type, Some(BasicType::Int32));
}

#[test]
fn errors_on_missing() {
    let doc = iec61850::scl::parse_scl_file(fixture()).unwrap();
    assert!(goose_from_scl(&doc, "NoIED", "gcb01", SRC).is_err());
    assert!(goose_from_scl(&doc, "IED1", "noexiste", SRC).is_err());
}
