# Modelo de amenazas

Documento de una página del modelo de amenazas de `iec61850-rs`, para diligencia
de compradores industriales (encaja aguas arriba de IEC 62443). No sustituye una
evaluación de riesgos del sistema donde se despliega.

## Activos a proteger

1. **Integridad del proceso** (disponibilidad del IED/gateway): un pánico o un
   agotamiento de memoria detiene la comunicación de subestación.
2. **Integridad de datos y control**: valores medidos, reportes y órdenes de
   control (Oper) no deben poder falsificarse ni alterarse.
3. **Confidencialidad** (menor en OT, pero relevante bajo 62351): topología y
   datos operativos.
4. **Confianza de la configuración**: el fichero SCL y los certificados.

## Superficies de ataque y mitigaciones

| # | Superficie | Amenaza | Mitigación en el proyecto |
|---|-----------|---------|---------------------------|
| A | Decodificadores BER/COTP/TPKT/MMS | PDU malformada → pánico/OOM/stack overflow | Lector BER zero-copy con límites de longitud; `MAX_NESTING_DEPTH`=32 en `Data`; `MAX_TYPE_SPEC_DEPTH`=16; forma indefinida rechazada; `MAX_PAYLOAD_LEN` en TPKT. Fuzzing continuo (`fuzz/`). |
| B | Servidor MMS (post-asociación) | Cliente hostil agota recursos | `ServerLimits`: máx. conexiones (semáforo), timeout de handshake (slow-loris), timeout de inactividad, desconexión por exceso de `Lagged` en reporting. |
| C | Escritura/control MMS | Escritura o mando no autorizado | Validación de FC/tipo en Write; control con SBO y enhanced security (Check/interlock); **RBAC por rol** (62351-8): el rol del peer autenticado limita qué puede escribir/controlar. |
| D | Transferencia de ficheros | Path traversal fuera del directorio | `DirFileProvider::resolve` acepta solo `Component::Normal`; rechaza `..`, rutas absolutas y prefijos (con test de regresión). |
| E | Transporte MMS | Escucha / MITM / suplantación | TLS 1.2/1.3 + **mTLS** (IEC 62351-3) con rustls; anclas de confianza explícitas; sin la feature `tls` el tráfico es en claro (solo redes de confianza). |
| F | GOOSE / SV (multicast L2) | Inyección/replay de tramas | Decodificadores fuzzeados y tolerantes; detección de salto de `stNum`/`smpCnt` y pérdida. **Autenticidad**: fuera del alcance del transporte — corresponde a IEC 62351-6 y a segmentación de red (ver Limitaciones). |
| G | Parser SCL | Fichero de config malicioso → pánico | Modo `lenient` sin pánico; parser XML `quick-xml` ≥0.41 (parcheado contra DoS); fuzzing de `scl_parse`. |
| H | Cadena de suministro | Dependencia comprometida/vulnerable | `cargo audit` + `cargo deny` diarios; SBOM CycloneDX por release; `unsafe` prohibido salvo en `iec61850-l2`. |

## Atacante considerado

- **Red de proceso/estación**: puede enviar tráfico MMS a los puertos abiertos e
  inyectar GOOSE/SV en el segmento L2. Es el atacante principal.
- **Fichero de configuración**: SCL de origen no plenamente confiable.
- **No** se considera un atacante con acceso de root al host (queda para el
  hardening del SO) ni ataques físicos al hardware.

## Matriz de conformidad IEC 62351

| Parte | Alcance | Estado |
|-------|---------|--------|
| **62351-3** | TLS/mTLS para MMS | **Implementado** (rustls, DER/PEM, cadenas/CA). Pendiente: recarga de certificados en caliente. |
| **62351-4** | Autenticación ACSE (asociación) | **Implementado por password** (AARQ authentication-value; verificado contra libiec61850) **y por certificado** (CN del cert mTLS → rol). |
| **62351-8** | RBAC (control de acceso por rol) | **Implementado**: roles `Viewer/Operator/Engineer` → conjunto de permisos (`Permissions`); se limitan **Write/control** (por FC), **Read** (incl. `ReadDataSetValues`; el buffer de edición de settings FC=SE exige rol de ingeniería), **definición de datasets** y **lectura de ficheros**. Asignación de rol por password, CN de certificado o **access token firmado** (`AuthPolicy::Token`, feature `tokens`): la autoridad emite un token (HMAC-SHA256 o ECDSA P-256) con identidad/rol/validez; el servidor lo verifica y aplica el rol, sin mapeo estático. Además de los roles estándar, se admiten **roles personalizados** (`Role::Custom(Permissions)`) con conjuntos de permisos arbitrarios; el token los transporta por su conjunto de permisos (bits). |
| **62351-6** | Seguridad GOOSE/SV | **Implementado**: firma opcional de tramas (tag tras el APDU, longitud en Reserved2); publicador firma, suscriptor verifica. **HMAC-SHA256** (simétrico, propio) y **ECDSA P-256** (asimétrico, RFC6979, vía crate `p256` auditado bajo feature `ecdsa`; no viaja secreto). Pendiente: gestión/distribución de claves (62351-9), interop con hardware. |

## Limitaciones conocidas (riesgos aceptados / diferidos)

- **Autenticación por password sin TLS viaja en claro.** El password ACSE
  (62351-4) debe usarse **sobre TLS** (`connect_tls_with_password`); en claro es
  interceptable. Pendiente: autenticación por **certificado** (subject/SAN → rol).
- **RBAC**: cubre Write/control, Read (incl. `ReadDataSetValues` y el buffer de
  edición de settings FC=SE), definición de datasets y lectura de ficheros. El
  **descubrimiento** (GetNameList/GetServerDirectory) no se restringe por rol
  (todo peer autenticado ve el namespace). Los roles son un enum fijo
  (`Viewer/Operator/Engineer`); no hay aún roles personalizados ni tokens firmados.
- **GOOSE/SV firmadas (IEC 62351-6)**: autenticación opcional por HMAC-SHA256
  (simétrica) o ECDSA P-256 (asimétrica). Sin firma, la autenticidad depende de la
  segmentación de red. La firma asimétrica a alta tasa SV es costosa (HMAC preferido
  en tiempo real).
- **Rotación de claves de grupo (IEC 62351-9)**: el `KeyRing` modela el ciclo de
  vida (key_id + validez temporal + solapamiento) y lo consume la pila GOOSE/SV, pero
  la **distribución** de claves (un GKMS/GDOI real) queda fuera de alcance: las claves
  se aprovisionan por configuración/aplicación, no por protocolo de red.
- **Sin validación XSD del SCL**: se confía en la buena formación del XML; la
  robustez se garantiza por fuzzing, no por conformidad de esquema.
- **Interoperabilidad no certificada**: sin pruebas formales 61850-10 ni contra
  hardware de terceros.

## Referencias

- Límites de robustez: `ServerLimits` en `crates/iec61850-mms/src/server.rs`.
- Arnés de fuzzing: `fuzz/README.md`.
- Despliegue: `docs/secure-deployment.md`.
