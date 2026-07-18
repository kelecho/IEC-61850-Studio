//! Robustez del parser SCL frente a **particularidades de ficheros reales de
//! fabricantes** (SEL, Siemens, ABB, GE, …).
//!
//! No se pueden vendorizar ficheros propietarios en el repo, así que estos tests
//! reproducen de forma **sintética** los rasgos que suelen romper parsers ingenuos:
//! elementos `Private` con XML ajeno, comentarios, `<Text>`/`<History>`, atributos
//! de extensión desconocidos, secciones CDATA y declaración BOM. El criterio es
//! que el documento **parsee y resuelva sin errores**, ignorando lo que no modela.

use iec61850_scl::{Severity, parse_scl_str};

/// Comprueba que el XML parsea, resuelve sin errores y descubre el IED esperado.
fn assert_parses_and_resolves(xml: &str) {
    let doc = parse_scl_str(xml).expect("el SCL debe parsear pese a las particularidades");
    let (model, diags) = doc.resolve_lenient();
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "resolución con errores: {errors:?}");
    assert!(
        model.ieds.contains_key("I1"),
        "debe resolverse el IED I1: {:?}",
        model.ieds.keys().collect::<Vec<_>>()
    );
}

/// SCL base compacto pero completo (IED + LD + LN0 + plantillas). `extra` se
/// inserta como hijos adicionales del elemento raíz para probar particularidades.
fn base_scl(root_attrs: &str, extra: &str, ln_extra: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL"{root_attrs}>
  <Header id="X" version="1" revision="A"/>
  {extra}
  <IED name="I1" manufacturer="ACME">
    <AccessPoint name="A1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="T0">
            {ln_extra}
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="T0" lnClass="LLN0">
      <DO name="Mod" type="D0"/>
    </LNodeType>
    <DOType id="D0" cdc="INC">
      <DA name="stVal" bType="INT32" fc="ST"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

#[test]
fn baseline_parses() {
    assert_parses_and_resolves(&base_scl("", "", ""));
}

#[test]
fn private_elements_with_foreign_xml() {
    // Los fabricantes embeben datos propietarios en <Private> a muchos niveles,
    // a veces con espacios de nombres ajenos y estructura arbitraria.
    let extra = r#"<Private type="ACME.config">
        <acme:Settings xmlns:acme="http://acme.example/scl">
          <acme:Param name="x">42</acme:Param>
        </acme:Settings>
      </Private>"#;
    let ln_extra = r#"<Private type="ACME.ln"><![CDATA[binario-propietario]]></Private>"#;
    assert_parses_and_resolves(&base_scl("", extra, ln_extra));
}

#[test]
fn header_with_history_and_text() {
    // Header con <History>/<Hitem> y <Text> descriptivo (habitual en export reales).
    let extra = r#"<Text>Descripción libre del proyecto</Text>"#;
    let xml = base_scl("", extra, "").replace(
        r#"<Header id="X" version="1" revision="A"/>"#,
        r#"<Header id="X" version="1" revision="A">
        <Text>cabecera</Text>
        <History>
          <Hitem version="1" revision="A" when="2020-01-01" who="tool" what="creado"/>
        </History>
      </Header>"#,
    );
    assert_parses_and_resolves(&xml);
}

#[test]
fn xml_comments_between_elements() {
    let extra = r#"<!-- comentario del exportador -->"#;
    let ln_extra = r#"<!-- nota en el LN0 --><Private type="p">x</Private>"#;
    assert_parses_and_resolves(&base_scl("", extra, ln_extra));
}

#[test]
fn unknown_vendor_attributes_are_ignored() {
    // Atributos de extensión (namespaced o no) sobre elementos conocidos.
    let xml = base_scl(
        r#" xmlns:sxy="http://siemens.example/scl" sxy:tool="DIGSI""#,
        "",
        "",
    )
    .replace(
        r#"<IED name="I1" manufacturer="ACME">"#,
        r#"<IED name="I1" manufacturer="ACME" sxy:internal="1" originalSclVersion="2007B">"#,
    );
    assert_parses_and_resolves(&xml);
}

#[test]
fn bom_prefixed_document() {
    // Muchos exportadores anteponen un BOM UTF-8.
    let xml = format!("\u{feff}{}", base_scl("", "", ""));
    assert_parses_and_resolves(&xml);
}

#[test]
fn edition2_namespaces_and_service_elements() {
    // Declaraciones de namespaces de Ed.2/2.1 y elementos de servicio que el
    // parser no modela pero debe ignorar.
    let root_attrs =
        r#" xmlns:ed2="http://www.iec.ch/61850/2016/SCL" version="2007" revision="B" release="4""#;
    let ln_extra = r#"<Private type="eIEC61850"/>"#;
    assert_parses_and_resolves(&base_scl(root_attrs, "", ln_extra));
}

#[test]
fn access_point_services_are_ignored() {
    // <Services>/<ServiceSettings> y <Authentication> bajo AccessPoint/Server:
    // muy habituales en export reales; el parser no los modela pero no debe romper.
    let xml = base_scl("", "", "")
        .replace(
            r#"<AccessPoint name="A1">"#,
            r#"<AccessPoint name="A1">
        <Services nameLength="64">
          <DynDataSet max="10" maxAttributes="50"/>
          <ConfDataSet max="10" maxAttributes="50" modify="true"/>
          <GOOSE max="8"/>
          <ReportSettings cbName="Conf" datSet="Conf" rptID="Dyn" bufTime="Dyn"/>
        </Services>"#,
        )
        .replace(r#"<Server>"#, r#"<Server><Authentication none="true"/>"#);
    assert_parses_and_resolves(&xml);
}

#[test]
fn edition2_setting_group_values() {
    // Valores de instancia con índice de grupo de ajuste (Ed.2): <Val sGroup="n">.
    let ln_extra = r#"<DOI name="Mod">
        <DAI name="stVal">
          <Val sGroup="1">1</Val>
          <Val sGroup="2">5</Val>
        </DAI>
      </DOI>"#;
    assert_parses_and_resolves(&base_scl("", "", ln_extra));
}

#[test]
fn multiple_lns_and_ldevices() {
    // Varios LDevice y LN (incl. LN0 intercalado): el orden y la repetición no
    // deben romper la deserialización.
    let xml = base_scl("", "", "").replace(
        r#"<LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="T0">

          </LN0>
        </LDevice>"#,
        r#"<LDevice inst="LD0">
          <LN prefix="" lnClass="LPHD" inst="1" lnType="T0"/>
          <LN0 lnClass="LLN0" inst="" lnType="T0"/>
          <LN prefix="Q" lnClass="CSWI" inst="1" lnType="T0"/>
        </LDevice>
        <LDevice inst="LD1">
          <LN0 lnClass="LLN0" inst="" lnType="T0"/>
        </LDevice>"#,
    );
    assert_parses_and_resolves(&xml);
}

#[test]
fn namespace_prefixed_elements_are_normalized() {
    // Algunos exportadores prefijan TODOS los elementos (`<scl:SCL><scl:Header>`).
    // El parser normaliza los prefijos y reconoce el documento igualmente.
    let xml = r#"<?xml version="1.0"?>
<scl:SCL xmlns:scl="http://www.iec.ch/61850/2003/SCL" xmlns:acme="http://acme.example">
  <scl:Header id="HDR" version="1"/>
  <scl:IED name="I1" manufacturer="ACME">
    <scl:AccessPoint name="A1">
      <scl:Server>
        <scl:LDevice inst="LD0">
          <scl:LN0 lnClass="LLN0" inst="" lnType="T0"/>
        </scl:LDevice>
      </scl:Server>
    </scl:AccessPoint>
  </scl:IED>
  <scl:DataTypeTemplates>
    <scl:LNodeType id="T0" lnClass="LLN0">
      <scl:DO name="Mod" type="D0"/>
    </scl:LNodeType>
    <scl:DOType id="D0" cdc="INC">
      <scl:DA name="stVal" bType="INT32" fc="ST"/>
    </scl:DOType>
  </scl:DataTypeTemplates>
</scl:SCL>"#;
    let doc = parse_scl_str(xml).expect("parsea el SCL prefijado");
    assert_eq!(doc.header.as_ref().unwrap().id, "HDR");
    assert!(doc.ied("I1").is_some());
    let (model, diags) = doc.resolve_lenient();
    assert!(diags.iter().all(|d| d.severity != Severity::Error));
    assert!(model.ieds.contains_key("I1"));
}

#[test]
fn xsi_type_attributes_on_address_params() {
    // Los exportadores de ABB/Hitachi (IET600) anotan cada `<P>` con su tipo de
    // esquema: `<P type="IP" xsi:type="tP_IP">`. quick-xml colapsa ambos
    // atributos al nombre local `@type` y abortaba con «duplicate field».
    let xml = base_scl(
        r#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#,
        r#"<Communication>
    <SubNetwork name="W1" type="8-MMS">
      <ConnectedAP iedName="I1" apName="A1">
        <Address>
          <P type="IP" xsi:type="tP_IP">192.168.2.10</P>
          <P type="IP-SUBNET" xsi:type="tP_IP-SUBNET">255.255.255.0</P>
          <P type="OSI-AP-Title" xsi:type="tP_OSI-AP-Title">1,3,9999,23</P>
        </Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>"#,
        "",
    );
    let doc = parse_scl_str(&xml).expect("el SCL con xsi:type debe parsear");
    let comm = doc.communication.as_ref().expect("sección Communication");
    let ap = &comm.sub_networks[0].connected_aps[0];
    let addr = ap.address.as_ref().expect("Address");
    assert_eq!(addr.param("IP"), Some("192.168.2.10"));
    assert_eq!(addr.param("IP-SUBNET"), Some("255.255.255.0"));
    assert_parses_and_resolves(&xml);
}

#[test]
fn interleaved_dai_and_sdi_inside_doi() {
    // IET600 (ABB/Hitachi) intercala DAI y SDI dentro de DOI (y dentro de SDI):
    // `<DOI><DAI/><SDI/><DAI/></DOI>`. quick-xml exige elementos del mismo
    // nombre consecutivos y abortaba con «duplicate field `DAI`».
    let xml = base_scl(
        "",
        "",
        r#"<DOI name="Mod">
      <DAI name="stVal"><Val>on</Val></DAI>
      <SDI name="origin">
        <DAI name="orCat"><Val>3</Val></DAI>
        <SDI name="nested"><DAI name="x"><Val>1</Val></DAI></SDI>
        <DAI name="orIdent"><Val>id</Val></DAI>
      </SDI>
      <DAI name="q"><Val>good</Val></DAI>
    </DOI>"#,
    );
    let doc = parse_scl_str(&xml).expect("el SCL con DAI/SDI intercalados debe parsear");
    let ied = doc.ied("I1").expect("IED I1");
    let ln0 = ied.access_points[0].server.as_ref().unwrap().ldevices[0]
        .ln0
        .as_ref()
        .expect("LN0");
    let doi = &ln0.dois[0];
    assert_eq!(doi.dai.len(), 2, "dos DAI directos (stVal, q)");
    assert_eq!(doi.sdi.len(), 1, "un SDI (origin)");
    assert_eq!(doi.sdi[0].dai.len(), 2, "orCat y orIdent");
    assert_eq!(doi.sdi[0].sdi.len(), 1, "SDI anidado");
    assert_parses_and_resolves(&xml);
}
