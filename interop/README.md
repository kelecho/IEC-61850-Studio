# Banco de interoperabilidad

Valida la pila IEC 61850-8-1 contra una **implementación independiente**
([libiec61850](https://github.com/mz-automation/libiec61850), el servidor MMS
open source de referencia), en ambos sentidos. Es la medida real de
interoperabilidad: el test de loopback prueba nuestro cliente contra nuestro
servidor; esto prueba contra código de terceros.

> **Licencia:** libiec61850 es GPLv3. Aquí solo se **ejecuta** como servidor de
> pruebas (comunicación por red MMS); no se vendoriza ni se enlaza con nuestro
> código, así que no afecta a la licencia del proyecto. No se comprometen sus
> ficheros en este repo.

## 1. Nuestro cliente ↔ su servidor

Levanta el servidor de referencia y corre el arnés de interop:

```sh
# Arranca server_example_basic_io de libiec61850 en el puerto 10102 del host.
docker compose -f interop/docker-compose.yml up --build -d

# Corre nuestro MmsClient contra él.
IEC61850_INTEROP_ADDR=127.0.0.1:10102 \
  cargo test -p iec61850-mms --features client --test interop_client -- --nocapture

docker compose -f interop/docker-compose.yml down
```

El arnés (`crates/iec61850-mms/tests/interop_client.rs`) ejercita: asociación,
Identify, GetServerDirectory, GetLogicalDeviceDirectory, Read, Write, **control
directo/SBO**, **reporting URCB y BRCB** (con EntryID) y **file transfer**
(fileDirectory + descarga por bloques). Se salta solo si `IEC61850_INTEROP_ADDR`
no está definida.

Para file transfer se necesita un servidor con file service habilitado, p. ej.
`server_example_files` (el `server_example_basic_io` lo trae deshabilitado).

Usa **`--test-threads=1`**: server_example_basic_io acepta pocas conexiones
concurrentes y varios tests asociándose a la vez lo saturan.

### File services (server_example_files)

El compose levanta `server_example_files` (puerto **10104**) con el filestore
de ejemplo de libiec61850. Los tests
`interop_files_*` cubren: listado (recursivo), GetFileAttributeValues, descarga
byte-verificada y el ciclo **SetFile** completo — `obtainFile` con lecturas
inversas servidas por nuestro cliente, verificación del fichero subido,
re-descarga y `fileDelete`:

```sh
IEC61850_INTEROP_FILES_ADDR=127.0.0.1:10104 \
  cargo test -p iec61850-mms --features client --test interop_client \
    interop_files -- --nocapture --test-threads=1
```

### Modelos de control (server_example_control)

El compose levanta además `server_example_control` (puerto **10103**), que expone
`GGIO1.SPCSO1..4` con los cuatro modelos operables del 7-2 (direct-normal,
sbo-normal, direct-enhanced, sbo-enhanced). Los tests `interop_control_*` lo usan:

```sh
IEC61850_INTEROP_CONTROL_ADDR=127.0.0.1:10103 \
  cargo test -p iec61850-mms --features client --test interop_client \
    interop_control -- --nocapture --test-threads=1
```

Cubren: lectura del `ctlModel` de cada SPCSO, operate directo, select+operate
(SBO), `operate_enhanced` con recepción de **CommandTermination+** y el rechazo
de un operate sin select con **LastApplError** (AddCause 18, object-not-selected)
emitido por libiec61850 y decodificado por nuestro cliente.

## 2. Su cliente ↔ nuestro servidor

El sentido inverso usa nuestro simulador y el cliente de ejemplo de libiec61850.
Valida nuestro **servidor** contra un cliente conforme e independiente (destapa
bugs de conformidad del lado emisor que el loopback no ve):

```sh
# Nuestro servidor, con el mismo SCL simpleIO que usan los ejemplos de libiec61850.
cargo run -p iec61850-sim -- \
  --scl <checkout>/examples/server_example_files/simpleIO_direct_control.cid \
  --bind 0.0.0.0:10102 &

# client_example1 de libiec61850 (desde un checkout compilado):
#   examples/iec61850_client_example1/client_example1 localhost 10102
```

`client_example1` ejercita: asociación, readObject, readDataSetValues,
getRCBValues, setRCBValues (activar reporte) y recepción de InformationReports.
Verificado extremo a extremo contra `iec61850-sim`.

La imagen del banco incluye `client_example1` compilado, así que el sentido
inverso se puede lanzar sin checkout local:

```sh
cargo run -p iec61850-sim -- --scl <simpleIO_direct_control.cid> --bind 0.0.0.0:10105 &
docker run --rm --network host \
  "$(docker compose -f interop/docker-compose.yml config --images | head -1)" \
  client_example1 127.0.0.1 10105
```

Con la **negociación real de Sesión/Presentación** del servidor (ISO 8327/8823:
parseo de la SPDU CONNECT y del CP, Result-list respondiendo a cada contexto
propuesto, fase de datos bajo el context-id MMS del cliente), este flujo se
verificó de nuevo completo: asociación, lecturas y reportes recibidos.

## En CI

El sentido 1 (nuestro cliente ↔ libiec61850) corre automáticamente en
`.github/workflows/interop.yml`: **manual** (`workflow_dispatch`) y **cada noche**
(cron). Compila el servidor de referencia con el mismo `docker-compose.yml`, espera
al healthcheck (`--wait`) y ejecuta el arnés. No bloquea los PR (libiec61850 es
código externo GPLv3); los fallos se revisan en el propio job (incluye los logs del
servidor).

El **corpus PCAP** (`fixtures/pcap/`, capturas GOOSE/SV sintéticas y congeladas) es
regresión de codecs sin red y sí forma parte del CI normal; ver
`fixtures/pcap/README.md`.

## 3. Corpus de SCL de terceros (parser)

Complementario, sin red: valida que nuestro parser digiere SCL reales sin panic.

```sh
IEC61850_SCL_CORPUS=/ruta/a/libiec61850 \
  cargo test -p iec61850-scl --test external_corpus -- --nocapture
```

Ver también `crates/iec61850-scl/examples/scl_audit.rs` para auditar ficheros
sueltos con recuento de diagnósticos.

## Estado / hallazgos

Cada bug de interop encontrado se corrige en nuestro código y se cubre con una
regresión propia (no vendorizada). Historial:

- **MMS Read no conforme** (verificado contra libiec61850 v1.6.1): el Read
  request omitía el envoltorio `variableAccessSpecification [1]` y ponía el
  `listOfVariable [0]` directamente. libiec61850 lo rechazaba con
  `reject-PDU: pdu-error`. El loopback no lo detectaba (cliente y servidor
  propios compartían el error). Corregido en `mms/read.rs`; Read pasó de 0/40 a
  40/40 lecturas hoja. Guardián de bytes en `read.rs::request_single_variable`.
  Nota: en `WriteRequest` el `variableAccessSpecification` va SIN envoltorio
  (asimetría real del estándar) — documentado en `mms/write.rs`.
- **fileDirectory: nivel SEQUENCE OF extra.** libiec61850 anida las entradas en
  un `SEQUENCE OF` universal adicional dentro de `listOfDirectoryEntry [0]`. El
  decoder ahora tolera ambas formas (`mms/file.rs::collect_directory_entries`).
- **fileRead-Response constructed.** La respuesta de fileRead es un `SEQUENCE`
  (tag constructed 73), no el tag primitivo del request. Definíamos solo el
  primitivo → `UnexpectedPdu`. Añadido `FILE_READ_RESPONSE` (73, true). Ambos
  con guardián de bytes en `mms/file.rs`.
- **Elementos SCL no consecutivos** (LN0 intercalado entre LN; DOType/DAType no
  agrupados): rompían la deserialización serde. Corregido con captura en
  `$value`+enum; regresión en `fixtures/icd/interleaved.icd`. Con ello 44/46
  ficheros de libiec61850 parsean (los 2 restantes son inválidos a propósito).
- **Tags MMS de named variable lists invertidos.** Usábamos
  deleteNamedVariableList=`[12]` y getNamedVariableListAttributes=`[13]`; ISO
  9506-2 define `[12]`=getAttrs y `[13]`=delete. libiec61850 rechazaba nuestro
  GetNamedVariableListAttributes con reject-PDU (pdu-error). El loopback no lo
  veía (ambos lados compartían la inversión). Corregido en `mms/pdu.rs`;
  verificado en ambos sentidos (resolución de datasets contra su servidor y
  `client_example4` contra el nuestro).
- **DatSet/dataset de reportes en nombre corto.** El servidor servía y
  reportaba el dataset como `"ds1"`; 8-1 usa la referencia completa
  (`"IED1LD0/LLN0$ds1"`, como libiec61850). Corregido (`RcbDef::dataset_ref`),
  con lookup tolerante a las tres formas de nombre.
- **Sin fragmentación COTP en el envío.** Los TSDU salían en una única DT TPDU
  con EOT, ignorando el TPDU size negociado (1024): libiec61850 **abortaba la
  conexión** al recibir una DT de 8 KiB (bloque de fichero servido durante un
  obtainFile). La recepción ya reensamblaba; el envío no troceaba. Corregido
  con `cotp::data_tpdus` (ISO 8073 clase 0, EOT solo en la última) aplicado a
  toda la fase de datos de cliente y servidor — afectaba a cualquier PDU >1024
  contra stacks estrictos. Regresión en `cotp::frag_tests`.

Servicios verificados contra libiec61850 v1.6.1 (cliente→servidor): asociación ·
Identify · GetServerDirectory · GetLogicalDeviceDirectory · Read · Write · control
directo (Oper→stVal) · SBO · reporting URCB y BRCB (EntryID) · file transfer.

Contra `server_example_control` (v1.5.3, puerto 10103): los **cuatro modelos de
control operables del 7-2** — direct-normal, sbo-normal (select+operate),
direct-enhanced y sbo-enhanced (`SBOw` + `Oper` + **CommandTermination+**), más
el rechazo de un operate sin select con **LastApplError** (AddCause 18,
object-not-selected) decodificado y correlacionado por nuestro cliente. De aquí
salieron dos correcciones de conformidad propias: el AddCause de interlocking
(1→**10**) y la CommandTermination− (el `failure` lleva `DataAccessError`; el
AddCause viaja en el LastApplError previo).

### Bugs de conformidad del **servidor** (sentido inverso, su cliente → nuestro sim)

Corregidos para que `client_example1` complete el flujo entero:

- **AARE ACSE no conforme**: `result [2]` y `result-source-diagnostic [3]` iban
  IMPLICIT y faltaba el diagnostic; en ACSE (X.227) son EXPLICIT. Sin esto,
  ningún cliente estricto asociaba. Corregido en `upper/acse.rs`.
- **`readDataSetValues` (variableListName)**: el servidor solo leía
  `listOfVariable`; ahora `read::ReadTarget` distingue el dataset por nombre y el
  servidor lo resuelve a sus miembros.
- **`getRCBValues` (RCB como estructura)**: el servidor no servía el RCB completo;
  ahora ensambla la estructura con los 11 (URCB) / 14 (BRCB) componentes en el
  orden exacto de 8-1 (`RcbDef::components`).
- **Sufijo de instancia MMS `01`**: clientes conformes referencian `EventsRCB01`;
  nuestro namespace usa el nombre del SCL. `ServerModel::normalize_rcb_item` lo tolera.
- **InformationReport sin cabecera `variableListName "RPT"`**: sin la
  `variableAccessSpecification` con `vmd-specific "RPT"`, el cliente descartaba el
  reporte. Corregido en `mms/report.rs::encode_information_report`.
- **Datasets dinámicos (`DefineNamedVariableList`)**: verificado con
  `client_example4` (createDataSet/readDataSetValues/deleteDataSet). Tres bugs:
  (1) `listOfVariable` con tag `[0]` (no `0x30`); (2) respuesta de Define con tag
  `[11]` **primitivo**; (3) lectura de miembros que son DOs estructurados requería
  ensamblar la estructura desde las hojas (`assemble_structured`).
- **Settings groups (SGCB)**: verificado leyendo el SGCB de
  `server_example_setting_groups` (`NumOfSG=5`) — decodificación de la estructura
  del SGCB conforme (orden de componentes 8-1).
