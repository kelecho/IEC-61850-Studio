# iec61850

Librería **IEC 61850** en Rust, construida desde cero como base para soluciones
de ingeniería de **pruebas y diagnóstico** de IEDs y subestaciones.

> **Fases 1–2 (actual):** modelo de datos + parser SCL, y **cliente MMS** (asociación + descubrimiento + lectura).
> Fases siguientes (planificadas): servidor/IED, GOOSE y Sampled Values.

## Estructura del workspace

| Crate | Contenido |
|-------|-----------|
| [`iec61850-model`](crates/iec61850-model) | Modelo de datos puro: jerarquía `Server → LogicalDevice → LogicalNode → DataObject → DataAttribute`, primitivas del estándar (`FunctionalConstraint`, `CommonDataClass`, `BasicType`) y `ObjectReference`. Sin dependencias de XML ni red. |
| [`iec61850-ber`](crates/iec61850-ber) | Codec **BER** (ASN.1) propio y el tipo `Data` de MMS (`MmsData`), compartido por MMS, GOOSE y SV. Solo `thiserror`. |
| [`iec61850-l2`](crates/iec61850-l2) | Capa 2 común: cabecera Ethernet/802.1Q/APPID, trait `L2Link` (+ `MockLink`) y socket `RawSocket` (AF_PACKET, `libc`+`tokio`, feature `net`, Linux) parametrizado por EtherType. Compartido por GOOSE y SV. |
| [`iec61850-scl`](crates/iec61850-scl) | Parser **SCL** (IEC 61850-6) sobre `quick-xml` + resolución de plantillas (`DataTypeTemplates`) al modelo instanciado. |
| [`iec61850-mms`](crates/iec61850-mms) | **MMS** (IEC 61850-8-1 / ISO 9506): pila ISO (TPKT/COTP/Session/Presentation/ACSE), **cliente** asíncrono (Identify/GetNameList/Read/Write/Control/Reporting) y **servidor / IED simulado** (asociar/GetNameList/Read/Write, reporting URCB+BRCB, control normal y reforzado) sobre `tokio`. Con la feature `tls`, transporte **TLS/mTLS** (IEC 62351-3) vía rustls, con material en **DER o PEM** (cadenas leaf+intermedios y bundles de CA). |
| [`iec61850-goose`](crates/iec61850-goose) | **GOOSE** (IEC 61850-8-1): codec de trama (goosePdu, reusa BER+MmsData+l2), **publicador** (retransmisión con backoff) y **suscriptor** (cambio de estado/retransmisión/pérdida/TTL). |
| [`iec61850-sv`](crates/iec61850-sv) | **Sampled Values** (IEC 61850-9-2): codec savPdu/ASDU + helper del perfil **9-2LE** (8 canales), **publicador** a tasa fija y **suscriptor** (seguimiento de smpCnt: muestra/pérdida/wrap). |
| [`iec61850`](crates/iec61850) | Fachada con *feature flags* (`scl`, `mms`, `mms-server`, `goose`, `goose-net`, `sv`, `sv-net`, `config`, `serde`) que re-exporta los demás. Con `config`, helpers `config::goose_from_scl`/`sv_from_scl` que construyen `GooseConfig`/`SvConfig` desde el SCL (MAC/APPID/VLAN de `Communication` + GSEControl/SampledValueControl). |

## Uso

```rust
use iec61850::scl::load_model;
use iec61850::model::NodeRef;

let model = load_model("subestacion.scd")?;

// Navegación por referencia de objeto.
if let Some(NodeRef::DataAttribute(da)) = model.find("IED1LD0/LLN0.Mod.stVal") {
    println!("{} : {} [{}]", da.name, da.basic_type, da.fc);
}

// Iterar todos los atributos de datos del modelo.
for (reference, _da) in model.iter_data_attributes() {
    println!("{reference}");
}
# Ok::<(), iec61850::scl::SclError>(())
```

Para cargar archivos imperfectos sin abortar, use `SclDocument::resolve_lenient`,
que devuelve los `Diagnostic` encontrados (referencias colgantes, tipos faltantes).

## Cliente MMS (Fase 2)

El cliente es **asíncrono (tokio)** con un modelo **demultiplexor**: una tarea de
fondo lee todos los PDU y enruta las respuestas por invokeID, entregando los
reportes no solicitados por un canal aparte.

```rust
use iec61850::mms::{MmsClient, MmsData};

# async fn run() -> Result<(), iec61850::mms::MmsError> {
let mut client = MmsClient::connect("192.168.1.10:102").await?;
println!("{:?}", client.identify().await?);                 // fabricante/modelo/revisión

for ld in client.get_server_directory().await? {            // dispositivos lógicos
    for reference in client.get_logical_device_directory(&ld).await? {
        println!("{reference}");                            // descubre variables
    }
}

// Leer / escribir
let mod_ref = "IED1LD0/LLN0.Mod.stVal[ST]".parse().unwrap();
let value = client.read(&mod_ref).await?;
client.write(&"IED1LD0/GGIO1.SPCSO1.ctlVal[CF]".parse().unwrap(), MmsData::Bool(true)).await?;

// Control (directo / select-before-operate, seguridad normal)
let breaker = "IED1LD0/CSWI1.Pos[CO]".parse().unwrap();
if client.select(&breaker).await? {
    client.operate(&breaker, MmsData::Bool(true)).await?;   // cierra el interruptor
}

// Reporting: habilitar un RCB y consumir InformationReport
let rcb = "IED1LD0/LLN0.urcb01[RP]".parse().unwrap();
client.enable_report(&rcb, &Default::default()).await?;
let mut reports = client.take_report_rx().unwrap();
while let Some(report) = reports.recv().await {
    println!("{} → {} entradas", report.rpt_id, report.entries.len());
}
# let _ = value; Ok(()) }
```

## Servidor / IED simulado (Fase 3)

```rust
use std::sync::Arc;
use iec61850::mms::{MmsServer, ServerModel, IdentifyResponse, MmsData};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let model = iec61850::scl::load_model("ied.icd")?;          // reutiliza el parser SCL
let ident = IdentifyResponse { vendor: "ACME".into(), model: "IED-SIM".into(), revision: "1.0".into() };
let sm = Arc::new(ServerModel::from_model(&model, ident));
let store = ServerModel::init_store(&model);                 // valores por defecto del SCL

let server = MmsServer::bind("0.0.0.0:10102", sm, store).await?;
let handle = server.handle();                                // inyectar valores en vivo
tokio::spawn(server.serve());

// la app simula un measurand:
handle.set_value(&"IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]".parse()?, MmsData::Float(12.3)).await?;
# Ok(()) }
```

El servidor expone el namespace MMS derivado del SCL (dominios = LDs, variables =
`LN$FC$DO$DA…`) y responde Identify/GetNameList/Read/Write contra un almacén
compartido (`Arc<RwLock>`).

## GOOSE (Fase 4)

```rust
use iec61850::goose::{GooseConfig, GoosePublisher, GooseSubscriber, GooseFilter, MmsData};
use iec61850::goose::socket::RawSocket;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
const DST: [u8;6] = [0x01,0x0C,0xCD,0x01,0x00,0x01];
// Publicar (requiere CAP_NET_RAW):
let cfg = GooseConfig::new(DST, [0,0,0,0,0,1], 0x0001, "IED1LD0/LLN0.GO$gcb01");
let pubr = GoosePublisher::new(RawSocket::open("eth0", DST)?, cfg).start();
pubr.publish(vec![MmsData::Bool(true)]).await?;   // dispara un nuevo estado + ráfaga

// Suscribir:
let mut sub = GooseSubscriber::new(RawSocket::open("eth0", DST)?, GooseFilter::default()).start();
while let Some(ev) = sub.recv_event().await {
    println!("{:?} st={} sq={}", ev.kind, ev.st_num, ev.sq_num);
}
# Ok(()) }
```

La configuración (MAC/APPID/VLAN, gocbRef, dataset) puede derivarse del SCL:
```rust
# #[cfg(feature = "config")]
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let doc = iec61850::scl::parse_scl_file("subestacion.scd")?;
let cfg = iec61850::config::goose_from_scl(&doc, "IED1", "gcb01", [0,0,0,0,0,1])?;
// let cfg_sv = iec61850::config::sv_from_scl(&doc, "IED1", "smv01", src)?;
# let _ = cfg; Ok(()) }
```

El **codec** de trama (Ethernet/802.1Q + goosePdu) reutiliza el BER y `MmsData`, y se
prueba sin privilegios. La lógica de publicador/suscriptor (retransmisión con backoff,
seguimiento de stNum/sqNum, pérdida y expiración de TTL) se prueba con un enlace en memoria
(`MockLink`) y el reloj de tokio pausado. Los sockets reales (AF_PACKET) requieren Linux y
`CAP_NET_RAW`/root; ver ejemplos `goose_publish`/`goose_monitor`.

## Sampled Values (Fase 5)

```rust
use iec61850::sv::{SvConfig, SvPublisher, SvSubscriber, SvFilter, NineTwoLe, SvChannel};
use iec61850::sv::RawSocket;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
const DST: [u8;6] = [0x01,0x0C,0xCD,0x04,0x00,0x01];
// Publicar a 4000 muestras/s (requiere CAP_NET_RAW):
let cfg = SvConfig::new(DST, [0,0,0,0,0,1], 0x4000, "MU01");
let pubr = SvPublisher::new(RawSocket::open("eth0", 0x88BA, DST)?, cfg).start();
let mut n = NineTwoLe::default();
n.channels[0] = SvChannel { value: 1234, quality: 0 };  // IA
pubr.set_9_2le(&n);                                       // la app actualiza la muestra

// Suscribir:
let mut sub = SvSubscriber::new(RawSocket::open("eth0", 0x88BA, DST)?, SvFilter::default()).start();
while let Some(ev) = sub.recv_sample().await {
    println!("{:?} smpCnt={}", ev.kind, ev.smp_cnt);
}
# Ok(()) }
```

El codec savPdu/ASDU y el helper 9-2LE se prueban sin privilegios; la lógica de
publicador (tasa fija) y suscriptor (seguimiento de smpCnt: muestra/pérdida/wrap) se
prueba con `MockLink` y el reloj de tokio pausado. **Limitación:** a 4000 muestras/s
(250 µs) `tokio::time` no garantiza tiempo real duro (jitter) — adecuado para pruebas
y tasas moderadas, no para protección.

## Simulador de IED (`iec61850-sim`)

[`apps/iec61850-sim`](apps/iec61850-sim) es un **simulador de IED** de línea de
comandos: carga un archivo SCL **real**, arranca un servidor MMS y queda a la
escucha en la red, listo para que una herramienta cliente lo **descubra** (p. ej.
«Buscar IEDs»). Ideal para montar un **banco de pruebas sin hardware**.

```sh
# Un IED en el puerto estándar (102 requiere privilegios):
sudo cargo run -p iec61850-sim -- --scl miIED.cid

# Sin privilegios, sirviendo además registros por file transfer:
cargo run -p iec61850-sim -- --scl miIED.icd --bind 0.0.0.0:10102 --files ./registros

# Banco de varios IEDs (un proceso por puerto), luego descúbrelos con la app:
cargo run -p iec61850-sim -- --scl ied1.cid --bind 0.0.0.0:10102 &
cargo run -p iec61850-sim -- --scl ied2.cid --bind 0.0.0.0:10103 &
```

Autodetecta un *measurand* (`MX` flotante) y lo anima en vivo; opciones de
`--vendor/--model/--revision`, `--vary`/`--no-vary`, `--files`.

## App de escritorio (demo)

[`apps/iec61850-gui`](apps/iec61850-gui) es una app **egui** de demostración:
cliente MMS para conectar a un IED, descubrir/leer variables, ver **reportes en
vivo** y **escribir/operar** (con confirmación, porque modifican el IED). Está
fuera de los `default-members`, así que no afecta a los builds/tests de las
librerías.

```sh
# Terminal 1 — un IED simulado en la red:
cargo run -p iec61850-sim -- --scl fixtures/icd/simple.icd --bind 0.0.0.0:10102
# Terminal 2 — la app:
cargo run -p iec61850-gui
```

También hay una variante con **UI web (Tauri v2 + React)** en
[`apps/iec61850-tauri`](apps/iec61850-tauri) — mismo cliente MMS, frontend web
(requiere Node y el webview del sistema; ver su README).

## Pruebas

El codec BER y el ensamblado de PDUs se prueban **sin red** (vectores de bytes,
X.690). Un test de integración levanta el `MmsServer` real y conecta el `MmsClient`
real en proceso, validando **ambos lados de la pila ISO entre sí** (asociación,
GetNameList con paginación, Read/Write e inyección por handle).

**Limitaciones documentadas (sin validar contra hardware de terceros):** las capas
Session/Presentation/ACSE son plantillas (cliente y servidor del crate sí
interoperan); la decodificación de reportes es de mejor esfuerzo guiada por
`OptFlds`; el control sólo cubre seguridad normal (directo + SBO); los enums se
sirven como entero (el modelo no conserva la tabla de ordinales del SCL).

## Comandos

```sh
cargo test --workspace                              # modelo, SCL e integración SCL
cargo test -p iec61850-mms --features "client server" # codec MMS + loopback cliente↔servidor
cargo run --example scl_dump -- fixtures/icd/simple.icd IED1LD0/LLN0.Mod.stVal
# IED simulado (servidor) en :10102:
cargo run -p iec61850-mms --features server --example ied_sim
# cliente contra un IED real (requiere hardware):
cargo run -p iec61850-mms --features client --example mms_explore -- 192.168.1.10
cargo clippy --workspace --all-targets
```

## Diseño

- **Dos capas en SCL:** un AST fiel al XML (`iec61850_scl::model`) y una capa de
  resolución (`iec61850_scl::resolve`) que sigue `LNodeType → DOType →
  DAType/EnumType` y superpone los valores de `DOI/SDI/DAI`.
- **Robustez sobre rigor** (es una herramienta de diagnóstico): CDC/tipos
  desconocidos se toleran (`CommonDataClass::Unknown`, `BasicType::Other`) y las
  referencias colgantes se reportan como diagnósticos.
- **Preparado para crecer:** la sección `Communication` (MAC/APPID/IP) y los
  `DataSet`/`ReportControl` ya se parsean para alimentar las futuras capas
  MMS/GOOSE/SV.
