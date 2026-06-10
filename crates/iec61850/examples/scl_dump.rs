//! Ejemplo de diagnóstico: carga un archivo SCL, vuelca el árbol del modelo y,
//! opcionalmente, resuelve una referencia de objeto.
//!
//! Uso:
//!   cargo run --example scl_dump -- <archivo.scd> [referencia]
//!   cargo run --example scl_dump -- fixtures/icd/simple.icd IED1LD0/LLN0.Mod.stVal

use anyhow::{Context, Result};
use clap::Parser;

use iec61850::model::NodeRef;
use iec61850::scl::parse_scl_file;

#[derive(Parser)]
#[command(about = "Carga un SCL, vuelca su modelo y resuelve una referencia opcional")]
struct Args {
    /// Ruta al archivo SCL (.icd/.cid/.scd/.ssd).
    file: String,
    /// Referencia de objeto a resolver, p. ej. "IED1LD0/LLN0.Mod.stVal".
    reference: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let doc = parse_scl_file(&args.file).with_context(|| format!("parseando {}", args.file))?;

    let (model, diags) = doc.resolve_lenient();
    if !diags.is_empty() {
        eprintln!("== {} diagnóstico(s) ==", diags.len());
        for d in &diags {
            eprintln!("  [{:?}] {} @ {}", d.severity, d.message, d.location);
        }
    }

    // Vuelca el árbol.
    for (ied_name, server) in &model.ieds {
        println!("IED {ied_name}");
        for ld in &server.logical_devices {
            println!("  LD {}", ld.inst);
            for ln in &ld.logical_nodes {
                println!("    LN {}  (lnType={})", ln.name(), ln.ln_type);
                for dobj in &ln.data_objects {
                    println!("      DO {} [{}]", dobj.name, dobj.cdc);
                    for da in &dobj.attributes {
                        dump_attr(da, 4);
                    }
                }
                for ds in &ln.data_sets {
                    println!("      DataSet {} ({} entradas)", ds.name, ds.entries.len());
                }
                for rc in &ln.report_controls {
                    println!("      ReportControl {}", rc.name);
                }
            }
        }
    }

    // Resuelve la referencia opcional.
    if let Some(reference) = &args.reference {
        println!("\n== resolviendo '{reference}' ==");
        match model.find(reference) {
            Some(NodeRef::DataAttribute(da)) => {
                println!(
                    "DataAttribute {} : {} [{}]{}{}",
                    da.name,
                    da.basic_type,
                    da.fc,
                    da.enum_type
                        .as_deref()
                        .map(|e| format!("  enum={e}"))
                        .unwrap_or_default(),
                    da.value
                        .as_ref()
                        .map(|v| format!("  val={}", v.raw))
                        .unwrap_or_default(),
                );
            }
            Some(NodeRef::DataObject(d)) => println!("DataObject {} [{}]", d.name, d.cdc),
            Some(NodeRef::LogicalNode(ln)) => println!("LogicalNode {}", ln.name()),
            Some(NodeRef::LogicalDevice(ld)) => println!("LogicalDevice {}", ld.inst),
            None => println!("(no encontrado)"),
        }
    }

    Ok(())
}

fn dump_attr(da: &iec61850::model::DataAttribute, indent: usize) {
    let pad = "  ".repeat(indent);
    let val = da
        .value
        .as_ref()
        .map(|v| format!(" = {}", v.raw))
        .unwrap_or_default();
    println!("{pad}DA {} : {} [{}]{val}", da.name, da.basic_type, da.fc);
    for child in &da.children {
        dump_attr(child, indent + 1);
    }
}
