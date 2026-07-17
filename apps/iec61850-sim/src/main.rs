//! `iec61850-sim` — simulador de IED IEC 61850 (servidor MMS).
//!
//! Carga un archivo SCL **real** (`.cid`/`.icd`/`.scd`/`.iid`), arranca un
//! servidor MMS y queda a la escucha en la red, listo para ser **descubierto**
//! por una herramienta cliente (p. ej. el botón «Buscar IEDs» de la app, o
//! cualquier cliente IEC 61850). Sustituye al antiguo `ied_sim` de ejemplo por
//! una herramienta de primera clase con CLI.
//!
//! Ejemplos:
//! ```text
//! # IED en el puerto estándar 102 (requiere privilegios: sudo o setcap):
//! iec61850-sim --scl miIED.cid
//!
//! # En un puerto sin privilegios, sirviendo además registros COMTRADE:
//! iec61850-sim --scl miIED.icd --bind 0.0.0.0:10102 --files ./registros
//!
//! # Banco de pruebas: varios IEDs en puertos distintos (un proceso cada uno).
//! iec61850-sim --scl ied1.cid --bind 0.0.0.0:10102 &
//! iec61850-sim --scl ied2.cid --bind 0.0.0.0:10103 &
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use iec61850::mms::{IdentifyResponse, MmsData, MmsServer, ServerModel};
use iec61850::model::{BasicType, FunctionalConstraint};
use iec61850::{Model, ObjectReference};

/// Simulador de IED IEC 61850 (servidor MMS) descubrible en la red.
#[derive(Parser)]
#[command(name = "iec61850-sim", version, about)]
struct Cli {
    /// Archivo SCL del IED a simular (.cid/.icd/.scd/.iid).
    #[arg(short, long)]
    scl: PathBuf,

    /// Dirección de escucha `ip:puerto`. El puerto 102 (estándar) requiere
    /// privilegios; usa p. ej. `0.0.0.0:10102` para correr sin ellos.
    #[arg(short, long, default_value = "0.0.0.0:102")]
    bind: String,

    /// Fabricante reportado en Identify.
    #[arg(long, default_value = "iec61850-rs")]
    vendor: String,

    /// Modelo reportado en Identify.
    #[arg(long, default_value = "iec61850-sim")]
    model: String,

    /// Revisión reportada en Identify.
    #[arg(long, default_value = "1.0")]
    revision: String,

    /// Directorio a exponer por **file transfer** (registros de perturbación,
    /// COMTRADE, logs).
    #[arg(long)]
    files: Option<PathBuf>,

    /// Referencia concreta a variar en vivo (por defecto: el primer measurand
    /// `MX` de tipo flotante del modelo).
    #[arg(long)]
    vary: Option<String>,

    /// No variar ningún valor: sirve el modelo estático tal cual.
    #[arg(long)]
    no_vary: bool,

    /// Periodo de actualización del valor variado, en milisegundos.
    #[arg(long, default_value_t = 500)]
    vary_period_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let model = iec61850::scl::load_model(&cli.scl)
        .map_err(|e| anyhow::anyhow!("cargar SCL {}: {e}", cli.scl.display()))?;

    let ident = IdentifyResponse {
        vendor: cli.vendor.clone(),
        model: cli.model.clone(),
        revision: cli.revision.clone(),
    };

    // Elige el measurand a variar: explícito, autodetectado, o ninguno.
    let vary_ref: Option<ObjectReference> = if cli.no_vary {
        None
    } else if let Some(r) = &cli.vary {
        match r.parse() {
            Ok(reference) => Some(reference),
            Err(_) => anyhow::bail!("referencia --vary inválida: {r}"),
        }
    } else {
        first_measurand(&model)
    };

    let mut server_model = ServerModel::from_model(&model, ident);
    if let Some(dir) = &cli.files {
        server_model = server_model.with_file_root(dir.clone());
    }
    let store = server_model.init_store(&model);

    let server = MmsServer::bind(&cli.bind, Arc::new(server_model), store)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "no se pudo escuchar en {}: {e}\n  (el puerto 102 requiere privilegios: \
                 prueba con sudo, `setcap`, o `--bind 0.0.0.0:10102`)",
                cli.bind
            )
        })?;
    let local = server.local_addr()?;
    let handle = server.handle();

    println!(
        "● IED simulado «{}» de {} escuchando en {local}",
        cli.model, cli.vendor
    );
    println!("  modelo SCL : {}", cli.scl.display());
    if let Some(dir) = &cli.files {
        println!("  ficheros   : {}", dir.display());
    }
    match &vary_ref {
        Some(r) => println!("  variando   : {r} cada {} ms", cli.vary_period_ms),
        None => println!("  variación  : (ninguna; modelo estático)"),
    }
    println!("  Ctrl-C para detener.");

    // Variación en vivo del measurand elegido (onda triangular 0..100).
    if let Some(reference) = vary_ref {
        let period = Duration::from_millis(cli.vary_period_ms.max(10));
        tokio::spawn(async move {
            let mut v = 0.0_f64;
            let mut rising = true;
            loop {
                if rising {
                    v += 0.5;
                    if v >= 100.0 {
                        rising = false;
                    }
                } else {
                    v -= 0.5;
                    if v <= 0.0 {
                        rising = true;
                    }
                }
                handle.set_value(&reference, MmsData::Float(v)).await.ok();
                tokio::time::sleep(period).await;
            }
        });
    }

    // Sirve hasta Ctrl-C.
    tokio::select! {
        r = server.serve() => { r?; }
        _ = tokio::signal::ctrl_c() => {
            println!("\nDeteniendo simulador…");
        }
    }
    Ok(())
}

/// Primer atributo de medida (`FC = MX`) de tipo flotante del modelo, para
/// animarlo en vivo sin que el usuario tenga que conocer la referencia.
fn first_measurand(model: &Model) -> Option<ObjectReference> {
    model.iter_data_attributes().find_map(|(reference, da)| {
        if da.fc == FunctionalConstraint::MX
            && matches!(da.basic_type, BasicType::Float32 | BasicType::Float64)
        {
            Some(reference)
        } else {
            None
        }
    })
}
