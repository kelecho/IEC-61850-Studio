# Publicación (release) en crates.io

La librería es un workspace de 9 crates. Esta guía cubre cómo publicarlos. La
publicación es **irreversible** (una versión publicada no se puede borrar, solo
"yank"), así que conviene validar antes con `--dry-run`/`cargo package`.

## 0. Antes de la primera publicación

1. **Repositorio:** edita `repository`/`homepage` en `Cargo.toml` (`[workspace.package]`),
   hoy con el placeholder `https://github.com/USUARIO/iec61850`. crates.io enlaza ahí.
2. **CI:** aún no hay (se eligió posponerla). Recomendado antes de publicar: un
   workflow con `cargo fmt --check`, `cargo clippy -D warnings`, los tests del
   workspace y `cargo doc`. Ver "Comandos de validación" abajo para las invocaciones.
3. **Cuenta y token:** `cargo login <token>` (token de https://crates.io/me).
4. Revisa que cada `Cargo.toml` tiene `description`, `license` y `repository`
   (heredados del workspace) — requisito de crates.io.

## 1. Orden de publicación (por dependencias)

Cada crate debe estar en crates.io antes de que se publique quien depende de él:

```
iec61850-model      # base, sin deps internas
iec61850-ber        # base
iec61850-l2         # base
iec61850-scl        # → model
iec61850-goose      # → ber, l2
iec61850-sv         # → ber, l2
iec61850-mms        # → model, ber, l2
iec61850            # fachada → todos (opcionales)
```

Publica uno por uno y espera a que cada uno esté indexado antes del siguiente:

```sh
cargo publish -p iec61850-model
cargo publish -p iec61850-ber
cargo publish -p iec61850-l2
cargo publish -p iec61850-scl
cargo publish -p iec61850-goose
cargo publish -p iec61850-sv
cargo publish -p iec61850-mms
cargo publish -p iec61850
```

> Nota: las dependencias internas usan `path` + `version`. Al publicar, cargo usa la
> `version` y resuelve desde el registro, por eso importa el orden.

## 2. Comandos de validación (no suben nada)

```sh
# Empaquetado y metadata de los crates base (sin deps internas):
for c in iec61850-model iec61850-ber iec61850-l2; do
  cargo package --no-verify -p "$c";
done
# Los crates con deps internas (scl/goose/sv/mms/iec61850) solo empaquetan
# cuando sus dependencias YA están en crates.io: falla con "no matching package
# named ... found" hasta entonces. Es esperado; valida cada uno en el momento de
# publicarlo, siguiendo el orden de la sección 1.

# Documentación (como la verá docs.rs), tratando avisos como error:
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Calidad:
cargo fmt --all --check
cargo clippy --workspace --all-targets \
  --features "iec61850/config iec61850-mms/client iec61850-mms/server iec61850-mms/tls iec61850-goose/net iec61850-sv/net"
cargo test --workspace \
  --features "iec61850/config iec61850-mms/client iec61850-mms/server iec61850-mms/tls iec61850-goose/net iec61850-sv/net"
```

## 3. Versionado

Todos los crates comparten `version` (`[workspace.package]`). Para una nueva
release, sube esa versión y la de `[workspace.dependencies]` a la vez (deben
coincidir), siguiendo SemVer.

## 4. docs.rs

docs.rs compila automáticamente al publicar. Cada crate con features declara qué
compilar en `[package.metadata.docs.rs]` (la fachada con `all-features`, MMS con
`client/server/tls`, GOOSE/SV con `net`).
