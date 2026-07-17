//! Validación **estructural** de un [`SclDocument`] (IEC 61850-6).
//!
//! No es una validación XSD completa: los esquemas oficiales de SCL son
//! propiedad de la IEC y no se redistribuyen libremente, y además una validación
//! por esquema no cubre la coherencia semántica entre plantillas (referencias de
//! tipo, unicidad de IDs). Esta comprobación cubre los errores prácticos que un
//! integrador comete al editar SCL a mano, con diagnósticos accionables.
//!
//! Complementa a [`crate::resolve::SclDocument::resolve_lenient`] (que detecta
//! referencias colgantes durante la instanciación); aquí se validan las
//! `DataTypeTemplates` de forma independiente.

use std::collections::HashSet;

use crate::error::Diagnostic;
use crate::model::SclDocument;

impl SclDocument {
    /// Comprueba la coherencia estructural de las `DataTypeTemplates`:
    /// unicidad de los `id` de tipo y que cada referencia de tipo (`DO.type`,
    /// `DA.type`, `SDO.type`, `BDA.type`) apunte a un tipo definido. Devuelve la
    /// lista de [`Diagnostic`] (vacía si todo es coherente).
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut diags = Vec::new();
        let Some(dtt) = &self.data_type_templates else {
            return diags;
        };

        // 1) Unicidad de IDs (un ID repetido hace ambiguo qué tipo se resuelve).
        let mut seen: HashSet<&str> = HashSet::new();
        let ids = dtt
            .lnode_types
            .iter()
            .map(|t| (t.id.as_str(), "LNodeType"))
            .chain(dtt.do_types.iter().map(|t| (t.id.as_str(), "DOType")))
            .chain(dtt.da_types.iter().map(|t| (t.id.as_str(), "DAType")))
            .chain(dtt.enum_types.iter().map(|t| (t.id.as_str(), "EnumType")));
        for (id, kind) in ids {
            if !seen.insert(id) {
                diags.push(Diagnostic::error(
                    format!("id de tipo duplicado '{id}'"),
                    format!("DataTypeTemplates/{kind}"),
                ));
            }
        }

        // Conjuntos de IDs por categoría para validar referencias.
        let do_ids: HashSet<&str> = dtt.do_types.iter().map(|t| t.id.as_str()).collect();
        let da_ids: HashSet<&str> = dtt.da_types.iter().map(|t| t.id.as_str()).collect();
        let enum_ids: HashSet<&str> = dtt.enum_types.iter().map(|t| t.id.as_str()).collect();

        // 2) Referencias de tipo válidas.
        for lt in &dtt.lnode_types {
            for d in &lt.dos {
                if !do_ids.contains(d.kind.as_str()) {
                    diags.push(Diagnostic::error(
                        format!(
                            "DO '{}' referencia un DOType '{}' inexistente",
                            d.name, d.kind
                        ),
                        format!("LNodeType[{}]", lt.id),
                    ));
                }
            }
        }
        for dt in &dtt.do_types {
            for sdo in &dt.sdos {
                if !do_ids.contains(sdo.kind.as_str()) {
                    diags.push(Diagnostic::error(
                        format!(
                            "SDO '{}' referencia un DOType '{}' inexistente",
                            sdo.name, sdo.kind
                        ),
                        format!("DOType[{}]", dt.id),
                    ));
                }
            }
            for da in &dt.das {
                // Un DA con tipo referencia un DAType (struct) o un EnumType (enum).
                if let Some(kind) = &da.kind {
                    let ok = da_ids.contains(kind.as_str()) || enum_ids.contains(kind.as_str());
                    if !ok {
                        diags.push(Diagnostic::error(
                            format!(
                                "DA '{}' referencia un tipo '{kind}' (DAType/EnumType) inexistente",
                                da.name
                            ),
                            format!("DOType[{}]", dt.id),
                        ));
                    }
                }
            }
        }
        for dat in &dtt.da_types {
            for bda in &dat.bdas {
                if let Some(kind) = &bda.kind {
                    let ok = da_ids.contains(kind.as_str()) || enum_ids.contains(kind.as_str());
                    if !ok {
                        diags.push(Diagnostic::error(
                            format!(
                                "BDA '{}' referencia un tipo '{kind}' (DAType/EnumType) inexistente",
                                bda.name
                            ),
                            format!("DAType[{}]", dat.id),
                        ));
                    }
                }
            }
        }
        diags
    }
}

#[cfg(test)]
mod tests {
    use crate::parse_scl_str;

    const GOOD: &str = r#"<?xml version="1.0"?>
    <SCL xmlns="http://www.iec.ch/61850/2003/SCL">
      <DataTypeTemplates>
        <LNodeType id="LLN01" lnClass="LLN0"><DO name="Mod" type="ENC_Mod"/></LNodeType>
        <DOType id="ENC_Mod" cdc="ENC"><DA name="stVal" bType="Enum" type="Mod_ENUM" fc="ST"/></DOType>
        <EnumType id="Mod_ENUM"><EnumVal ord="1">on</EnumVal></EnumType>
      </DataTypeTemplates>
    </SCL>"#;

    #[test]
    fn valid_templates_have_no_diagnostics() {
        let doc = parse_scl_str(GOOD).unwrap();
        assert!(doc.validate().is_empty(), "{:?}", doc.validate());
    }

    #[test]
    fn detects_dangling_type_reference() {
        // El DA referencia un EnumType inexistente.
        let bad = GOOD.replace(r#"type="Mod_ENUM""#, r#"type="NoExiste""#);
        let doc = parse_scl_str(&bad).unwrap();
        let diags = doc.validate();
        assert!(
            diags.iter().any(|d| d.message.contains("NoExiste")),
            "debe detectar la referencia colgante: {diags:?}"
        );
    }

    #[test]
    fn detects_duplicate_id() {
        let bad = GOOD.replace(
            r#"<EnumType id="Mod_ENUM"><EnumVal ord="1">on</EnumVal></EnumType>"#,
            r#"<EnumType id="Mod_ENUM"><EnumVal ord="1">on</EnumVal></EnumType>
               <EnumType id="Mod_ENUM"><EnumVal ord="2">off</EnumVal></EnumType>"#,
        );
        let doc = parse_scl_str(&bad).unwrap();
        let diags = doc.validate();
        assert!(
            diags.iter().any(|d| d.message.contains("duplicado")),
            "debe detectar el id duplicado: {diags:?}"
        );
    }
}
