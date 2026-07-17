# Soporte de SCL (IEC 61850-6)

Estado del parser, resolución, validación y escritura de SCL, y qué ediciones se
soportan.

## Ediciones

| Edición | Namespace | Estado |
|---------|-----------|--------|
| **Ed.1** (2003) | `http://www.iec.ch/61850/2003/SCL` | **Soportada** — es el namespace nativo del parser/escritor. |
| **Ed.2** (2007) | `http://www.iec.ch/61850/2007/SCL` | **Soportada en la práctica**: el parser ignora el namespace y lee los elementos por nombre; los ficheros Ed.2 se digieren (verificado con el corpus de libiec61850). Elementos exclusivos de Ed.2 no modelados se ignoran sin fallar (modo `lenient`). |
| **Ed.2.1** (2020) | `http://www.iec.ch/61850/2007/SCL` (rev.) | **Parcial**: mismos elementos base; extensiones 2.1 no específicamente modeladas. |

El escritor emite siempre el namespace Ed.1 (`2003/SCL`), que todo stack lee.

## Elementos soportados

| Elemento | Parseo | Resolución | Escritura |
|----------|:------:|:----------:|:---------:|
| `Header` | ✅ | — | ✅ |
| `IED` / `AccessPoint` / `Server` / `LDevice` / `LN0` / `LN` | ✅ | ✅ | ✅ |
| `DOI` / `SDI` / `DAI` / `Val` (incl. `sGroup`) | ✅ | ✅ | ✅ |
| `DataSet` / `FCDA` | ✅ | ✅ | ✅ |
| `ReportControl` / `TrgOps` | ✅ | ✅ | ✅ |
| `GSEControl` / `SampledValueControl` | ✅ | ✅ | ✅ |
| `SettingControl` (SGCB) | ✅ | ✅ | ✅ |
| `Communication` / `SubNetwork` / `ConnectedAP` / `Address` / `GSE` / `SMV` | ✅ | ✅ | ✅ |
| `DataTypeTemplates`: `LNodeType` / `DOType` / `DAType` / `EnumType` (con literales) | ✅ | ✅ | ✅ |
| `Substation` / `VoltageLevel` / `Bay` | ✅ (parcial) | — | ❌ (no se serializa) |
| `Private`, `sAddr`, extensiones de vendor | ❌ (se ignoran) | — | ❌ |

## Robustez

- **Modo lenient** (`resolve_lenient`): carga SCL imperfectos devolviendo
  diagnósticos en vez de abortar. Digiere 44/46 ficheros de libiec61850 (los 2 que
  fallan son inválidos a propósito).
- **Elementos no consecutivos**: tolerados (LN0 intercalado entre LN; DOType/DAType
  no agrupados) — un fallo real de otras herramientas.
- **Particularidades de fabricantes** (`tests/vendor_quirks.rs`): se digieren sin
  romper `Private` con XML/namespaces ajenos, comentarios, `<Text>`/`<History>/<Hitem>`,
  `<Services>`/`<ServiceSettings>`/`<Authentication>`, atributos de extensión
  (prefijados o no), CDATA, BOM y valores de setting group (`<Val sGroup="n">`).
- **Prefijos de namespace**: los exportadores que prefijan todos los elementos
  (`<scl:SCL><scl:Header>…`) se normalizan automáticamente (se quitan los prefijos y
  las declaraciones `xmlns`) y el documento se reconoce igual. El fast-path sin
  prefijos no se ve afectado (la normalización solo actúa si el parseo queda vacío).
- **Fuzzing** del parser (`fuzz/scl_parse`): ninguna entrada causa panic.

## Validación

- `SclDocument::validate()` — validación **estructural** (no XSD): unicidad de IDs
  de tipo y referencias de tipo (`DO.type`/`DA.type`/`SDO.type`/`BDA.type`) contra
  tipos definidos. Diagnósticos accionables.
- `SclDocument::resolve_lenient()` — detecta referencias colgantes durante la
  instanciación.
- **Por qué no validación XSD**: los esquemas oficiales de SCL son propiedad de la
  IEC (no redistribuibles), y una validación por esquema no cubre la coherencia
  semántica entre plantillas. La validación estructural cubre los errores prácticos
  de edición sin ese problema de licencia.

## Escritura (round-trip)

- `write_scl_str` / `write_scl_file` — serializa un `SclDocument` a XML SCL.
- **Round-trip verificado**: parsear → serializar → re-parsear da un modelo
  equivalente en **43/43** ficheros reales de libiec61850
  (`examples/scl_roundtrip`).
- Habilita el flujo *cargar → modificar → guardar* de una herramienta de ingeniería.
- Limitación: `Substation` y los `Private`/`sAddr` no se re-emiten todavía (round
  trip sin pérdida solo de los elementos de la tabla anterior).
