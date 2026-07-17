# Corpus PCAP (regresión de codecs L2)

Capturas **congeladas** en formato pcap clásico (`LINKTYPE_ETHERNET`), generadas
por la propia librería con tramas deterministas. Sirven de red de seguridad: si un
cambio altera de forma incompatible el codec GOOSE/SV, el test de regresión que las
lee falla.

| Fichero | Contenido |
|---|---|
| `goose.pcap` | 3 tramas GOOSE: sin VLAN, con VLAN (prio 4) y firmada (IEC 62351-6, HMAC-SHA256). |
| `sv.pcap` | 3 ASDUs SV (9-2LE): sin VLAN, con VLAN y firmada. |

Cada trama se compara **byte a byte** contra la que produce el codec y se decodifica
verificando sus campos (incl. la verificación HMAC de las firmadas). Tests:

- `crates/iec61850-goose/tests/pcap_corpus.rs`
- `crates/iec61850-sv/tests/pcap_corpus.rs`

Se validan en el CI normal (job `test`, features completas en Linux).

## Regenerar (solo tras un cambio de formato intencionado)

```sh
cargo test -p iec61850-goose --features net --test pcap_corpus regenerate -- --ignored
cargo test -p iec61850-sv     --features net --test pcap_corpus regenerate -- --ignored
```

Estas capturas son **sintéticas** (las genera esta librería). No proceden de
equipos de terceros y no incorporan datos con licencias ajenas. Las tramas MMS
(TCP/IP) no forman parte del corpus PCAP: su regresión se cubre con vectores de
bytes en los tests unitarios del codec (`crates/iec61850-mms`), ya que un PCAP de
MMS conforme exigiría sintetizar la pila IP/TCP completa.
