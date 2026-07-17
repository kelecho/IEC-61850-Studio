# Fuzzing de los decodificadores

Arnés [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libFuzzer)
sobre todos los parsers que procesan **entrada de red no confiable**. La meta de
seguridad de la fase 2 del ROADMAP: ninguna entrada debe provocar panic, OOM ni
desbordamiento de pila.

## Objetivos

| Target | Superficie | Origen de la entrada hostil |
|--------|-----------|------------------------------|
| `ber_data` | `Data` MMS (BER) | valores de un servidor/publicador |
| `tpkt_cotp` | TPKT + TPDUs COTP | primer byte del socket TCP/102 |
| `mms_request` | Initiate + peticiones confirmadas | cliente hostil tras el handshake |
| `goose_pdu` | PDU GOOSE | multicast L2 no autenticado |
| `sv_pdu` | PDU Sampled Values | multicast L2 no autenticado |
| `scl_parse` | parser SCL + resolución | fichero ICD/CID/SCD de terceros |

## Uso

Requiere toolchain **nightly** (los sanitizers de libFuzzer lo exigen):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# Ejecutar un objetivo (Ctrl-C para parar)
cargo +nightly fuzz run ber_data

# Tanda acotada (como en CI)
cargo +nightly fuzz run scl_parse -- -max_total_time=900 -rss_limit_mb=2048

# Reproducir un crash concreto
cargo +nightly fuzz run ber_data fuzz/artifacts/ber_data/crash-<hash>
```

El `corpus/` incluye semillas iniciales (fixtures SCL y vectores BER conocidos);
libFuzzer lo amplía solo. Un crash se guarda en `fuzz/artifacts/<target>/` y debe
convertirse en un caso de test de regresión en el crate correspondiente.

CI: `.github/workflows/fuzz.yml` corre 60 s por objetivo en cada PR que toque un
parser y 15 min por objetivo cada noche.
