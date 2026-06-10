//! IED simulado: carga un archivo SCL, arranca un servidor MMS y va inyectando
//! un measurand en vivo vía el handle del servidor.
//!
//! Uso:
//!   cargo run -p iec61850-mms --features server --example ied_sim -- [archivo.icd] [ip:puerto]
//!
//! Por defecto sirve `fixtures/icd/simple.icd` en `0.0.0.0:10102` (puerto sin
//! privilegios). Conéctate con `mms_explore` o cualquier cliente MMS.

use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::{IdentifyResponse, MmsData, MmsServer, ServerModel};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "fixtures/icd/simple.icd".into());
    let addr = args.next().unwrap_or_else(|| "0.0.0.0:10102".into());

    let model = iec61850_scl::load_model(&path)?;
    let ident = IdentifyResponse {
        vendor: "iec61850-rs".into(),
        model: "ied_sim".into(),
        revision: "0.1".into(),
    };
    let server_model = ServerModel::from_model(&model, ident);
    let store = server_model.init_store(&model);

    let server = MmsServer::bind(&addr, Arc::new(server_model), store).await?;
    let local = server.local_addr()?;
    let handle = server.handle();
    println!("IED simulado escuchando en {local} (modelo: {path})");

    // Simula un measurand variando una corriente cada segundo.
    tokio::spawn(async move {
        if let Ok(reference) = "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse() {
            let mut v = 0.0_f64;
            loop {
                handle.set_value(&reference, MmsData::Float(v)).await.ok();
                v += 0.5;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    server.serve().await?;
    Ok(())
}
