//! Resolución de plantillas: convierte el AST de SCL ([`SclDocument`]) en el
//! modelo de datos instanciado ([`Model`]).
//!
//! Sigue las referencias `LNodeType → DOType → DAType/EnumType` y superpone los
//! valores configurados de `DOI/SDI/DAI`. Las referencias colgantes se reportan
//! como [`Diagnostic`] en lugar de abortar (modo laxo).

use std::str::FromStr;

use iec61850_model::Model;
use iec61850_model::basic_type::BasicType;
use iec61850_model::cdc::CommonDataClass;
use iec61850_model::fc::FunctionalConstraint;
use iec61850_model::tree::{
    DataAttribute, DataObject, DataSet, Fcda, LogicalDevice, LogicalNode, ReportControl, Server,
    TriggerOptions,
};
use iec61850_model::value::Value;

use crate::error::{Diagnostic, SclError, Severity};
use crate::model::instance::{Doi, Sdi, Val};
use crate::model::templates::{Da, DataTypeTemplates};
use crate::model::{SclDocument, ied};

/// Estado de la resolución: plantillas + diagnósticos acumulados.
struct Resolver<'a> {
    templates: &'a DataTypeTemplates,
    diags: Vec<Diagnostic>,
}

impl SclDocument {
    /// Resuelve el documento a un [`Model`]. Falla si hay problemas
    /// estructurales (referencias de tipo sin resolver).
    pub fn resolve(&self) -> Result<Model, SclError> {
        let (model, diags) = self.resolve_lenient();
        if let Some(err) = diags.iter().find(|d| d.severity == Severity::Error) {
            return Err(SclError::Resolution {
                message: err.message.clone(),
                location: err.location.clone(),
            });
        }
        Ok(model)
    }

    /// Resuelve el documento de forma laxa: nunca falla, devolviendo el modelo
    /// construido junto con los diagnósticos encontrados.
    pub fn resolve_lenient(&self) -> (Model, Vec<Diagnostic>) {
        let empty = DataTypeTemplates::default();
        let templates = self.data_type_templates.as_ref().unwrap_or(&empty);
        let mut resolver = Resolver {
            templates,
            diags: Vec::new(),
        };

        let mut model = Model::new();
        for ied in &self.ieds {
            let server = resolver.resolve_ied(ied);
            model.insert_ied(&ied.name, server);
        }
        (model, resolver.diags)
    }
}

impl Resolver<'_> {
    fn warn(&mut self, message: impl Into<String>, location: impl Into<String>) {
        self.diags.push(Diagnostic::warning(message, location));
    }

    fn error(&mut self, message: impl Into<String>, location: impl Into<String>) {
        self.diags.push(Diagnostic::error(message, location));
    }

    /// Fusiona los LDevice de todos los puntos de acceso del IED en un servidor.
    fn resolve_ied(&mut self, ied: &ied::Ied) -> Server {
        let mut server = Server::default();
        for ap in &ied.access_points {
            let Some(scl_server) = &ap.server else {
                continue;
            };
            for ld in &scl_server.ldevices {
                let resolved = self.resolve_ldevice(&ied.name, ld);
                server.logical_devices.push(resolved);
            }
        }
        server
    }

    fn resolve_ldevice(&mut self, ied_name: &str, ld: &ied::LDevice) -> LogicalDevice {
        let logical_nodes = ld
            .all_lns()
            .map(|ln| self.resolve_ln(ied_name, &ld.inst, ln))
            .collect();
        LogicalDevice {
            inst: ld.inst.clone(),
            ld_name: ld.ld_name.clone(),
            logical_nodes,
        }
    }

    fn resolve_ln(&mut self, ied_name: &str, ld_inst: &str, ln: &ied::Ln) -> LogicalNode {
        let ln_name = format!("{}{}{}", ln.prefix, ln.ln_class, ln.inst);
        let location = format!("{ied_name}/{ld_inst}/{ln_name}");

        // Construye los DO a partir del LNodeType.
        let mut data_objects = Vec::new();
        match self.templates.lnode_type(&ln.ln_type) {
            Some(lnt) => {
                for tdo in &lnt.dos {
                    if let Some(dobj) = self.resolve_do(
                        &tdo.name,
                        &tdo.kind,
                        tdo.transient.unwrap_or(false),
                        tdo.desc.clone(),
                        &location,
                    ) {
                        data_objects.push(dobj);
                    }
                }
            }
            None => self.error(
                format!("LNodeType '{}' no encontrado", ln.ln_type),
                location.clone(),
            ),
        }

        // Superpone valores configurados desde los DOI.
        for doi in &ln.dois {
            match data_objects.iter_mut().find(|d| d.name == doi.name) {
                Some(dobj) => overlay_doi(dobj, doi),
                None => self.warn(
                    format!("DOI '{}' no corresponde a ningún DO del tipo", doi.name),
                    location.clone(),
                ),
            }
        }

        let ln_desc = ln
            .desc
            .clone()
            .or_else(|| self.templates.lnode_type(&ln.ln_type).and_then(|l| l.desc.clone()));
        LogicalNode {
            prefix: ln.prefix.clone(),
            class: ln.ln_class.clone(),
            inst: ln.inst.clone(),
            ln_type: ln.ln_type.clone(),
            desc: ln_desc,
            data_objects,
            data_sets: ln.data_sets.iter().map(convert_data_set).collect(),
            report_controls: ln
                .report_controls
                .iter()
                .map(convert_report_control)
                .collect(),
        }
    }

    fn resolve_do(
        &mut self,
        name: &str,
        do_type_id: &str,
        transient: bool,
        desc: Option<String>,
        location: &str,
    ) -> Option<DataObject> {
        let Some(dotype) = self.templates.do_type(do_type_id) else {
            self.error(
                format!("DOType '{do_type_id}' no encontrado"),
                location.to_string(),
            );
            return None;
        };

        let attributes = dotype
            .das
            .iter()
            .filter_map(|da| self.resolve_da(da, location))
            .collect();

        let mut sub_objects = Vec::new();
        for sdo in &dotype.sdos {
            if let Some(sub) = self.resolve_do(&sdo.name, &sdo.kind, false, sdo.desc.clone(), location) {
                sub_objects.push(sub);
            }
        }

        Some(DataObject {
            name: name.to_string(),
            cdc: CommonDataClass::from_cdc(&dotype.cdc),
            desc: desc.or_else(|| dotype.desc.clone()),
            transient,
            attributes,
            sub_objects,
        })
    }

    /// Resuelve un `DA` de un `DOType` (la FC vive aquí; los sub-atributos la
    /// heredan).
    fn resolve_da(&mut self, da: &Da, location: &str) -> Option<DataAttribute> {
        let fc = match FunctionalConstraint::from_str(&da.fc) {
            Ok(fc) => fc,
            Err(_) => {
                self.warn(
                    format!(
                        "FC '{}' inválida en DA '{}'; se omite el atributo",
                        da.fc, da.name
                    ),
                    location.to_string(),
                );
                return None;
            }
        };
        let trg = TriggerOptions {
            dchg: da.dchg.unwrap_or(false),
            qchg: da.qchg.unwrap_or(false),
            dupd: da.dupd.unwrap_or(false),
        };
        Some(self.build_attribute(
            &da.name,
            fc,
            &da.b_type,
            da.kind.as_deref(),
            da.val.first(),
            trg,
            da.desc.clone(),
            location,
        ))
    }

    /// Construye un atributo y, si es compuesto, resuelve recursivamente sus
    /// sub-atributos desde el `DAType`. La FC se hereda en toda la sub-jerarquía.
    #[allow(clippy::too_many_arguments)]
    fn build_attribute(
        &mut self,
        name: &str,
        fc: FunctionalConstraint,
        b_type: &str,
        type_ref: Option<&str>,
        val: Option<&Val>,
        trigger_options: TriggerOptions,
        desc: Option<String>,
        location: &str,
    ) -> DataAttribute {
        let basic_type = BasicType::from_btype(b_type);
        let enum_type = if matches!(basic_type, BasicType::Enum) {
            type_ref.map(str::to_string)
        } else {
            None
        };

        let mut children = Vec::new();
        if basic_type.is_struct() {
            match type_ref.and_then(|id| self.templates.da_type(id)) {
                Some(datype) => {
                    // clonamos las BDA para no mantener el préstamo de self.templates
                    let bdas = datype.bdas.clone();
                    for bda in &bdas {
                        children.push(self.build_attribute(
                            &bda.name,
                            fc,
                            &bda.b_type,
                            bda.kind.as_deref(),
                            bda.val.first(),
                            TriggerOptions::default(),
                            bda.desc.clone(),
                            location,
                        ));
                    }
                }
                None => {
                    if let Some(id) = type_ref {
                        self.error(
                            format!("DAType '{id}' no encontrado para DA '{name}'"),
                            location.to_string(),
                        );
                    }
                }
            }
        }

        DataAttribute {
            name: name.to_string(),
            fc,
            basic_type,
            desc,
            enum_type,
            trigger_options,
            value: val.map(to_value),
            children,
        }
    }
}

fn to_value(v: &Val) -> Value {
    match v.s_group {
        Some(g) => Value::with_group(v.text.clone(), g),
        None => Value::new(v.text.clone()),
    }
}

/// Superpone los valores de un `DOI` sobre un `DataObject` ya construido.
fn overlay_doi(dobj: &mut DataObject, doi: &Doi) {
    for dai in &doi.dai {
        if let Some(attr) = dobj.attributes.iter_mut().find(|a| a.name == dai.name) {
            attr.value = dai.val.first().map(to_value);
        }
    }
    for sdi in &doi.sdi {
        // Un SDI puede corresponder a un sub-objeto o a un atributo compuesto.
        if let Some(attr) = dobj.attributes.iter_mut().find(|a| a.name == sdi.name) {
            overlay_sdi_on_attr(attr, sdi);
        } else if let Some(sub) = dobj.sub_objects.iter_mut().find(|s| s.name == sdi.name) {
            overlay_sdi_on_do(sub, sdi);
        }
    }
}

fn overlay_sdi_on_do(dobj: &mut DataObject, sdi: &Sdi) {
    for dai in &sdi.dai {
        if let Some(attr) = dobj.attributes.iter_mut().find(|a| a.name == dai.name) {
            attr.value = dai.val.first().map(to_value);
        }
    }
    for nested in &sdi.sdi {
        if let Some(attr) = dobj.attributes.iter_mut().find(|a| a.name == nested.name) {
            overlay_sdi_on_attr(attr, nested);
        } else if let Some(sub) = dobj.sub_objects.iter_mut().find(|s| s.name == nested.name) {
            overlay_sdi_on_do(sub, nested);
        }
    }
}

fn overlay_sdi_on_attr(attr: &mut DataAttribute, sdi: &Sdi) {
    for dai in &sdi.dai {
        if let Some(child) = attr.children.iter_mut().find(|c| c.name == dai.name) {
            child.value = dai.val.first().map(to_value);
        }
    }
    for nested in &sdi.sdi {
        if let Some(child) = attr.children.iter_mut().find(|c| c.name == nested.name) {
            overlay_sdi_on_attr(child, nested);
        }
    }
}

fn convert_data_set(ds: &crate::model::control::DataSet) -> DataSet {
    DataSet {
        name: ds.name.clone(),
        entries: ds
            .fcda
            .iter()
            .map(|f| Fcda {
                ld_inst: f.ld_inst.clone().unwrap_or_default(),
                prefix: f.prefix.clone().unwrap_or_default(),
                ln_class: f.ln_class.clone().unwrap_or_default(),
                ln_inst: f.ln_inst.clone().unwrap_or_default(),
                do_name: f.do_name.clone().unwrap_or_default(),
                da_name: f.da_name.clone().unwrap_or_default(),
                fc: f
                    .fc
                    .as_deref()
                    .and_then(|s| FunctionalConstraint::from_str(s).ok()),
            })
            .collect(),
    }
}

fn convert_report_control(rc: &crate::model::control::ReportControl) -> ReportControl {
    let trigger_options = rc
        .trg_ops
        .as_ref()
        .map(|t| TriggerOptions {
            dchg: t.dchg.unwrap_or(false),
            qchg: t.qchg.unwrap_or(false),
            dupd: t.dupd.unwrap_or(false),
        })
        .unwrap_or_default();
    ReportControl {
        name: rc.name.clone(),
        rpt_id: rc.rpt_id.clone(),
        dataset: rc.dat_set.clone(),
        buffered: rc.buffered.unwrap_or(false),
        conf_rev: rc.conf_rev,
        trigger_options,
    }
}
