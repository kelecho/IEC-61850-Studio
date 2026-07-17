//! Punto de entrada de navegación del modelo: [`Model`] agrupa los servidores
//! de uno o varios IED y permite resolver referencias de objeto textuales.

use std::collections::BTreeMap;

use crate::basic_type::BasicType;
use crate::fc::FunctionalConstraint;
use crate::reference::ObjectReference;
use crate::tree::{DataAttribute, DataObject, LogicalDevice, LogicalNode, Server};

/// Un miembro de un `DataSet`, resuelto a su referencia, restricción funcional y
/// (cuando es una hoja) su tipo básico. Para GOOSE/SV define el orden y el tipo
/// de cada valor en `allData`/`sample`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DatasetMember {
    pub reference: ObjectReference,
    pub fc: FunctionalConstraint,
    /// `None` si el miembro es un objeto/estructura (no una hoja).
    pub basic_type: Option<BasicType>,
}

/// Referencia prestada a un nodo cualquiera del modelo, devuelta por
/// [`Model::resolve`] / [`Model::find`].
#[derive(Debug, Clone, Copy)]
pub enum NodeRef<'a> {
    LogicalDevice(&'a LogicalDevice),
    LogicalNode(&'a LogicalNode),
    DataObject(&'a DataObject),
    DataAttribute(&'a DataAttribute),
}

/// Modelo de datos completo: mapa de nombre de IED a su [`Server`].
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Model {
    /// Servidores indexados por nombre de IED.
    pub ieds: BTreeMap<String, Server>,
}

impl Model {
    /// Crea un modelo vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserta (o reemplaza) el servidor de un IED.
    pub fn insert_ied(&mut self, name: impl Into<String>, server: Server) {
        self.ieds.insert(name.into(), server);
    }

    /// Devuelve el servidor de un IED por nombre.
    pub fn ied(&self, name: &str) -> Option<&Server> {
        self.ieds.get(name)
    }

    /// Nombre efectivo de un LD tal como aparece en las referencias:
    /// su `ldName` si lo tiene, o `IEDName + inst` en caso contrario.
    fn effective_ld_name(ied: &str, ld: &LogicalDevice) -> String {
        ld.ld_name
            .clone()
            .unwrap_or_else(|| format!("{ied}{}", ld.inst))
    }

    /// Resuelve una referencia de objeto a su nodo. Devuelve `None` si no
    /// existe ningún nodo con esa referencia.
    pub fn resolve(&self, r: &ObjectReference) -> Option<NodeRef<'_>> {
        for (ied_name, server) in &self.ieds {
            for ld in &server.logical_devices {
                if Self::effective_ld_name(ied_name, ld) != r.ld {
                    continue;
                }
                if r.ln.is_empty() {
                    return Some(NodeRef::LogicalDevice(ld));
                }
                let Some(ln) = ld.logical_node(&r.ln) else {
                    continue;
                };
                if r.path.is_empty() {
                    return Some(NodeRef::LogicalNode(ln));
                }
                return descend_logical_node(ln, &r.path);
            }
        }
        None
    }

    /// Conveniencia: resuelve una referencia dada como cadena.
    /// Devuelve `None` tanto si la cadena es inválida como si no existe.
    pub fn find(&self, reference: &str) -> Option<NodeRef<'_>> {
        let r: ObjectReference = reference.parse().ok()?;
        self.resolve(&r)
    }

    /// Itera todos los nodos lógicos del modelo junto con su referencia.
    pub fn iter_logical_nodes(&self) -> impl Iterator<Item = (ObjectReference, &LogicalNode)> {
        let mut out = Vec::new();
        for (ied_name, server) in &self.ieds {
            for ld in &server.logical_devices {
                let ld_name = Self::effective_ld_name(ied_name, ld);
                for ln in &ld.logical_nodes {
                    out.push((
                        ObjectReference::new(ld_name.clone(), ln.name(), Vec::<String>::new()),
                        ln,
                    ));
                }
            }
        }
        out.into_iter()
    }

    /// Resuelve un `DataSet` (por dominio y nombre) a la lista **ordenada** de
    /// sus miembros, cada uno con su referencia, FC y tipo. Devuelve `None` si el
    /// dataset no existe. Un miembro por FCDA (no se expanden los objetos).
    pub fn resolve_dataset(&self, domain: &str, name: &str) -> Option<Vec<DatasetMember>> {
        for (ied_name, server) in &self.ieds {
            for ld in &server.logical_devices {
                if Self::effective_ld_name(ied_name, ld) != domain {
                    continue;
                }
                for ln in &ld.logical_nodes {
                    let Some(ds) = ln.data_sets.iter().find(|d| d.name == name) else {
                        continue;
                    };
                    let mut members = Vec::with_capacity(ds.entries.len());
                    for f in &ds.entries {
                        let member_ld = if f.ld_inst.is_empty() {
                            domain.to_string()
                        } else {
                            format!("{ied_name}{}", f.ld_inst)
                        };
                        let ln_name = format!("{}{}{}", f.prefix, f.ln_class, f.ln_inst);
                        let mut path: Vec<String> =
                            f.do_name.split('.').map(str::to_string).collect();
                        if !f.da_name.is_empty() {
                            path.push(f.da_name.clone());
                        }
                        let mut reference = ObjectReference::new(member_ld, ln_name, path);
                        reference.fc = f.fc;

                        // El tipo se obtiene resolviendo el nodo (resolve ignora la FC).
                        let basic_type = match self.resolve(&reference) {
                            Some(NodeRef::DataAttribute(da)) => Some(da.basic_type.clone()),
                            _ => None,
                        };
                        let resolved_fc = match self.resolve(&reference) {
                            Some(NodeRef::DataAttribute(da)) => Some(da.fc),
                            _ => None,
                        };
                        let Some(fc) = resolved_fc.or(f.fc) else {
                            continue; // sin FC no es un miembro válido
                        };
                        reference.fc = Some(fc);
                        members.push(DatasetMember {
                            reference,
                            fc,
                            basic_type,
                        });
                    }
                    return Some(members);
                }
            }
        }
        None
    }

    /// Itera todos los atributos de datos (hoja y compuestos, recursivamente)
    /// junto con su referencia de objeto completa.
    pub fn iter_data_attributes(&self) -> impl Iterator<Item = (ObjectReference, &DataAttribute)> {
        let mut out = Vec::new();
        for (ied_name, server) in &self.ieds {
            for ld in &server.logical_devices {
                let ld_name = Self::effective_ld_name(ied_name, ld);
                for ln in &ld.logical_nodes {
                    let ln_name = ln.name();
                    for dobj in &ln.data_objects {
                        collect_data_attributes(
                            &ld_name,
                            &ln_name,
                            std::slice::from_ref(&dobj.name),
                            dobj,
                            &mut out,
                        );
                    }
                }
            }
        }
        out.into_iter()
    }
}

/// Desciende por la cadena de nombres DO/DA dentro de un nodo lógico.
fn descend_logical_node<'a>(ln: &'a LogicalNode, path: &[String]) -> Option<NodeRef<'a>> {
    let (first, rest) = path.split_first()?;
    let dobj = ln.data_object(first)?;
    descend_data_object(dobj, rest)
}

/// Desciende dentro de un DO: los siguientes nombres pueden ser sub-objetos o
/// atributos.
fn descend_data_object<'a>(dobj: &'a DataObject, path: &[String]) -> Option<NodeRef<'a>> {
    let Some((first, rest)) = path.split_first() else {
        return Some(NodeRef::DataObject(dobj));
    };
    // Preferimos atributo; si no, sub-objeto.
    if let Some(da) = dobj.attribute(first) {
        return descend_data_attribute(da, rest);
    }
    if let Some(sdo) = dobj.sub_object(first) {
        return descend_data_object(sdo, rest);
    }
    None
}

/// Desciende dentro de un DA por sus sub-atributos.
fn descend_data_attribute<'a>(da: &'a DataAttribute, path: &[String]) -> Option<NodeRef<'a>> {
    let Some((first, rest)) = path.split_first() else {
        return Some(NodeRef::DataAttribute(da));
    };
    let child = da.child(first)?;
    descend_data_attribute(child, rest)
}

/// Recolecta recursivamente los atributos de un DO (incluyendo sub-objetos).
fn collect_data_attributes<'a>(
    ld: &str,
    ln: &str,
    do_path: &[String],
    dobj: &'a DataObject,
    out: &mut Vec<(ObjectReference, &'a DataAttribute)>,
) {
    for da in &dobj.attributes {
        let mut path = do_path.to_vec();
        path.push(da.name.clone());
        collect_attribute_recursive(ld, ln, &path, da, out);
    }
    for sdo in &dobj.sub_objects {
        let mut path = do_path.to_vec();
        path.push(sdo.name.clone());
        collect_data_attributes(ld, ln, &path, sdo, out);
    }
}

fn collect_attribute_recursive<'a>(
    ld: &str,
    ln: &str,
    path: &[String],
    da: &'a DataAttribute,
    out: &mut Vec<(ObjectReference, &'a DataAttribute)>,
) {
    let mut r = ObjectReference::new(ld.to_string(), ln.to_string(), path.iter().cloned());
    r.fc = Some(da.fc);
    out.push((r, da));
    for child in &da.children {
        let mut child_path = path.to_vec();
        child_path.push(child.name.clone());
        collect_attribute_recursive(ld, ln, &child_path, child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic_type::BasicType;
    use crate::cdc::CommonDataClass;
    use crate::fc::FunctionalConstraint;
    use crate::tree::*;

    fn sample_model() -> Model {
        let st_val = DataAttribute {
            name: "stVal".into(),
            fc: FunctionalConstraint::ST,
            basic_type: BasicType::Enum,
            desc: None,
            enum_type: Some("Beh".into()),
            enum_values: vec![
                crate::EnumValue {
                    ord: 1,
                    literal: "on".into(),
                },
                crate::EnumValue {
                    ord: 2,
                    literal: "off".into(),
                },
            ],
            trigger_options: TriggerOptions {
                dchg: true,
                ..Default::default()
            },
            value: None,
            children: vec![],
        };
        let mod_do = DataObject {
            name: "Mod".into(),
            cdc: CommonDataClass::INC,
            desc: None,
            transient: false,
            attributes: vec![st_val],
            sub_objects: vec![],
        };
        let lln0 = LogicalNode {
            prefix: String::new(),
            class: "LLN0".into(),
            inst: String::new(),
            ln_type: "LLN0_0".into(),
            desc: None,
            data_objects: vec![mod_do],
            data_sets: vec![],
            report_controls: vec![],
            setting_group_control: None,
            log_controls: vec![],
        };
        let ld = LogicalDevice {
            inst: "LD0".into(),
            ld_name: None,
            logical_nodes: vec![lln0],
        };
        let mut model = Model::new();
        model.insert_ied(
            "IED1",
            Server {
                logical_devices: vec![ld],
            },
        );
        model
    }

    #[test]
    fn resolve_da() {
        let m = sample_model();
        let node = m.find("IED1LD0/LLN0.Mod.stVal").expect("debe resolver");
        match node {
            NodeRef::DataAttribute(da) => assert_eq!(da.name, "stVal"),
            other => panic!("se esperaba DataAttribute, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn resolve_intermediate_levels() {
        let m = sample_model();
        assert!(matches!(
            m.find("IED1LD0/LLN0.Mod"),
            Some(NodeRef::DataObject(_))
        ));
        assert!(matches!(
            m.find("IED1LD0/LLN0"),
            Some(NodeRef::LogicalNode(_))
        ));
    }

    #[test]
    fn resolve_missing() {
        let m = sample_model();
        assert!(m.find("IED1LD0/LLN0.Mod.noExiste").is_none());
        assert!(m.find("IEDX/LLN0").is_none());
    }

    #[test]
    fn iterate_attributes() {
        let m = sample_model();
        let attrs: Vec<_> = m.iter_data_attributes().collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0.to_string(), "IED1LD0/LLN0.Mod.stVal[ST]");
    }
}
