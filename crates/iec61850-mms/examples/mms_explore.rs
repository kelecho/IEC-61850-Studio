//! Herramienta de diagnóstico: conecta a un servidor MMS, lo identifica,
//! descubre sus dispositivos lógicos y variables, y opcionalmente lee una
//! referencia.
//!
//! Uso:
//!   cargo run -p iec61850-mms --features client --example mms_explore -- <ip[:puerto]> [referencia]
//!
//! Ejemplos:
//!   ... -- 192.168.1.10
//!   ... -- 192.168.1.10:102 "IED1LD0/LLN0.Mod.stVal[ST]"
//!
//! Requiere un servidor/IED MMS real escuchando (no se puede ejecutar contra
//! los tests de este repositorio).

use std::process::ExitCode;

use iec61850_mms::MmsClient;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(target) = args.next() else {
        eprintln!("uso: mms_explore <ip[:puerto]> [referencia]");
        return ExitCode::FAILURE;
    };
    let addr = if target.contains(':') {
        target
    } else {
        format!("{target}:102")
    };
    let reference = args.next();

    match explore(&addr, reference.as_deref()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn explore(addr: &str, reference: Option<&str>) -> Result<(), iec61850_mms::MmsError> {
    println!("Conectando a {addr} …");
    let client = MmsClient::connect(addr).await?;
    let neg = client.negotiated();
    println!(
        "Asociado (versión {}, maxServOut {}/{}).",
        neg.version, neg.max_serv_out_calling, neg.max_serv_out_called
    );

    let id = client.identify().await?;
    println!("Identify: {} / {} / {}", id.vendor, id.model, id.revision);

    let lds = client.get_server_directory().await?;
    println!("\nDispositivos lógicos ({}):", lds.len());
    for ld in &lds {
        println!("  {ld}");
    }

    if let Some(first) = lds.first() {
        let refs = client.get_logical_device_directory(first).await?;
        println!("\nVariables de {first} ({}):", refs.len());
        for r in refs.iter().take(40) {
            println!("  {r}");
        }
        if refs.len() > 40 {
            println!("  … (+{} más)", refs.len() - 40);
        }
    }

    if let Some(reference) = reference {
        let obj = reference.parse().map_err(|_| {
            iec61850_mms::MmsError::Transport(format!("referencia inválida: {reference}"))
        })?;
        println!("\nLeyendo {reference} …");
        let value = client.read(&obj).await?;
        println!("  = {value:?}");
    }

    Ok(())
}
