//! Tests de integración: parseo y resolución del fixture `simple.icd`.

use std::path::PathBuf;

use iec61850_model::{BasicType, FunctionalConstraint, NodeRef};
use iec61850_scl::{Severity, parse_scl_file};

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

#[test]
fn parses_ast() {
    let doc = parse_scl_file(fixture("fixtures/icd/simple.icd")).expect("parsea");
    assert_eq!(doc.ieds.len(), 1);
    assert_eq!(doc.ieds[0].name, "IED1");
    assert_eq!(doc.header.as_ref().unwrap().id, "EJEMPLO_SIMPLE");

    let dtt = doc.data_type_templates.as_ref().expect("tiene plantillas");
    assert_eq!(dtt.lnode_types.len(), 4);
    assert_eq!(dtt.do_types.len(), 5);
    assert_eq!(dtt.da_types.len(), 4);
    assert_eq!(dtt.enum_types.len(), 2);

    // Comunicación preservada para fases futuras.
    let comm = doc.communication.as_ref().unwrap();
    let ap = &comm.sub_networks[0].connected_aps[0];
    assert_eq!(
        ap.address.as_ref().unwrap().param("IP"),
        Some("192.168.1.10")
    );
}

#[test]
fn resolves_without_errors() {
    let doc = parse_scl_file(fixture("fixtures/icd/simple.icd")).unwrap();
    let (_model, diags) = doc.resolve_lenient();
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "no debe haber errores de resolución: {errors:?}"
    );
}

#[test]
fn resolves_enum_attribute_with_default_value() {
    let model = parse_scl_file(fixture("fixtures/icd/simple.icd"))
        .unwrap()
        .resolve()
        .unwrap();

    let node = model
        .find("IED1LD0/LLN0.Mod.stVal")
        .expect("resuelve stVal");
    let NodeRef::DataAttribute(da) = node else {
        panic!("se esperaba DataAttribute")
    };
    assert_eq!(da.basic_type, BasicType::Enum);
    assert_eq!(da.enum_type.as_deref(), Some("Beh"));
    assert_eq!(da.fc, FunctionalConstraint::ST);
    assert!(da.trigger_options.dchg);
    // Valor superpuesto desde el DAI.
    assert_eq!(da.value.as_ref().map(|v| v.raw.as_str()), Some("on"));

    // Fidelidad SCL: la tabla ordinal↔literal del EnumType `Beh` se conserva.
    assert_eq!(da.enum_values.len(), 5, "Beh tiene 5 valores");
    assert_eq!(da.enum_literal(1), Some("on"));
    assert_eq!(da.enum_literal(2), Some("blocked"));
    assert_eq!(da.enum_literal(5), Some("off"));
    assert_eq!(da.enum_literal(99), None);
    assert_eq!(da.enum_ordinal("on"), Some(1));
    assert_eq!(da.enum_ordinal("off"), Some(5));
    assert_eq!(da.enum_ordinal("inexistente"), None);
}

/// Regresión de interoperabilidad: los SCL reales de muchas herramientas
/// intercalan elementos del mismo nombre (LN0 entre LN; DOType/DAType no
/// agrupados). El parser debe aceptarlos igualmente. Hallado auditando ficheros
/// de terceros con `examples/scl_audit`.
#[test]
fn parses_interleaved_elements() {
    let doc = parse_scl_file(fixture("fixtures/icd/interleaved.icd"))
        .expect("parsea pese al orden intercalado");

    // LN0 estaba entre dos LN: debe reconocerse como LN0 y no perder ningún LN.
    let ld = &doc.ieds[0].access_points[0]
        .server
        .as_ref()
        .unwrap()
        .ldevices[0];
    assert!(ld.ln0.is_some(), "LN0 intercalado debe capturarse");
    assert_eq!(ld.lns.len(), 2, "ambos LN deben conservarse");

    // Plantillas intercaladas: los 3 LNodeType, 3 DOType, 1 DAType, 1 EnumType.
    let dtt = doc.data_type_templates.as_ref().unwrap();
    assert_eq!(dtt.lnode_types.len(), 3);
    assert_eq!(dtt.do_types.len(), 3);
    assert_eq!(dtt.da_types.len(), 1);
    assert_eq!(dtt.enum_types.len(), 1);

    // Y resuelve sin errores.
    let (_model, diags) = doc.resolve_lenient();
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "resolución sin errores: {errors:?}");
}

/// Round-trip de escritura (3.4): parsear → serializar → re-parsear debe dar un
/// modelo resuelto equivalente (sin pérdida semántica en los elementos soportados).
#[test]
fn scl_write_round_trip() {
    let doc = parse_scl_file(fixture("fixtures/icd/simple.icd")).expect("parsea original");
    let model1 = doc.clone().resolve().expect("resuelve original");

    // Serializa y vuelve a parsear.
    let xml = iec61850_scl::write_scl_str(&doc).expect("serializa");
    let doc2 = iec61850_scl::parse_scl_str(&xml).expect("re-parsea el XML generado");
    let model2 = doc2.resolve().expect("resuelve el re-parseado");

    // El namespace, IEDs y plantillas se conservan.
    assert_eq!(doc2.ieds.len(), 1);
    assert_eq!(doc2.ieds[0].name, "IED1");
    let dtt = doc2.data_type_templates.as_ref().unwrap();
    assert_eq!(dtt.enum_types.len(), 2);

    // Un valor de enum y uno flotante sobreviven al round-trip.
    let stval1 = model1.find("IED1LD0/LLN0.Mod.stVal").unwrap();
    let stval2 = model2.find("IED1LD0/LLN0.Mod.stVal").unwrap();
    let (NodeRef::DataAttribute(a), NodeRef::DataAttribute(b)) = (stval1, stval2) else {
        panic!("se esperaban DataAttribute");
    };
    assert_eq!(
        a.value.as_ref().map(|v| &v.raw),
        b.value.as_ref().map(|v| &v.raw)
    );
    assert_eq!(a.enum_values, b.enum_values, "la tabla de enum sobrevive");

    let f1 = model1.find("IED1LD0/MMXU1.A.phsA.cVal.mag.f").unwrap();
    let f2 = model2.find("IED1LD0/MMXU1.A.phsA.cVal.mag.f").unwrap();
    let (NodeRef::DataAttribute(fa), NodeRef::DataAttribute(fb)) = (f1, f2) else {
        panic!("se esperaban DataAttribute");
    };
    assert_eq!(
        fa.value.as_ref().and_then(|v| v.as_f64()),
        fb.value.as_ref().and_then(|v| v.as_f64())
    );
}

#[test]
fn resolves_deep_struct_with_overlaid_value() {
    let model = parse_scl_file(fixture("fixtures/icd/simple.icd"))
        .unwrap()
        .resolve()
        .unwrap();

    let node = model
        .find("IED1LD0/MMXU1.A.phsA.cVal.mag.f")
        .expect("resuelve f");
    let NodeRef::DataAttribute(da) = node else {
        panic!("se esperaba DataAttribute")
    };
    assert_eq!(da.basic_type, BasicType::Float32);
    // La FC MX se hereda desde el DA padre 'phsA'.
    assert_eq!(da.fc, FunctionalConstraint::MX);
    assert_eq!(da.value.as_ref().and_then(|v| v.as_f64()), Some(1.5));
}

#[test]
fn datasets_and_reports_resolved() {
    let model = parse_scl_file(fixture("fixtures/icd/simple.icd"))
        .unwrap()
        .resolve()
        .unwrap();

    let server = model.ied("IED1").unwrap();
    let ld = server.logical_device("LD0").unwrap();
    let lln0 = ld.logical_node("LLN0").unwrap();

    assert_eq!(lln0.data_sets.len(), 1);
    let ds = &lln0.data_sets[0];
    assert_eq!(ds.name, "ds1");
    assert_eq!(ds.entries[0].do_name, "A.phsA.cVal.mag");
    assert_eq!(ds.entries[0].fc, Some(FunctionalConstraint::MX));

    assert_eq!(lln0.report_controls.len(), 2);
    let rcb = &lln0.report_controls[0];
    assert_eq!(rcb.name, "rcb1");
    assert_eq!(rcb.dataset.as_deref(), Some("ds1"));
    assert!(rcb.trigger_options.dchg && rcb.trigger_options.qchg);
    let brcb = &lln0.report_controls[1];
    assert_eq!(brcb.name, "brcb1");
    assert!(brcb.buffered);
}

#[test]
fn resolve_dataset_members() {
    let model = parse_scl_file(fixture("fixtures/icd/simple.icd"))
        .unwrap()
        .resolve()
        .unwrap();

    let members = model
        .resolve_dataset("IED1LD0", "ds1")
        .expect("dataset ds1");
    assert_eq!(members.len(), 1);
    let m = &members[0];
    assert_eq!(
        m.reference.to_string(),
        "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]"
    );
    assert_eq!(m.fc, FunctionalConstraint::MX);
    assert_eq!(m.basic_type, Some(BasicType::Float32));

    assert!(model.resolve_dataset("IED1LD0", "noexiste").is_none());
}

#[test]
fn iterates_all_data_attributes() {
    let model = parse_scl_file(fixture("fixtures/icd/simple.icd"))
        .unwrap()
        .resolve()
        .unwrap();

    let refs: Vec<String> = model.iter_data_attributes().map(|(r, _)| r.key()).collect();
    assert!(refs.contains(&"IED1LD0/LLN0.Mod.stVal".to_string()));
    assert!(refs.contains(&"IED1LD0/MMXU1.A.phsA.cVal.mag.f".to_string()));
}
