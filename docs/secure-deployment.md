# Guía de despliegue seguro

Recomendaciones para desplegar un servidor/gateway basado en `iec61850-rs`
(p. ej. `iec61850-sim` o un binario propio) en un entorno de subestación.

## 1. Privilegios mínimos

- **No ejecutar como root.** El servidor MMS solo necesita enlazar su puerto TCP.
- El puerto MMS estándar es el **102** (privilegiado). Opciones:
  - Enlazar un puerto alto (p. ej. `:10102`) y redirigir con el firewall, **o**
  - conceder solo la capability de puertos bajos al binario:
    ```sh
    sudo setcap 'cap_net_bind_service=+ep' /ruta/al/binario
    ```
- **GOOSE/SV** (captura/publicación en capa 2) requieren `CAP_NET_RAW`. Concédela
  **solo** al binario que lo necesite y **solo** si se usa esa función:
  ```sh
  sudo setcap 'cap_net_raw,cap_net_admin=+ep' /ruta/al/binario
  ```
  No la combines en un binario que también esté expuesto a MMS de red si puedes
  separarlos.

## 2. Aislamiento con systemd

Unidad de ejemplo con sandboxing (ajusta rutas y usuario):

```ini
[Service]
User=iec61850
Group=iec61850
ExecStart=/opt/iec61850/bin/iec61850-sim --scl /etc/iec61850/ied.cid --bind 0.0.0.0:10102 --files /var/lib/iec61850/records
# Sandbox
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadOnlyPaths=/etc/iec61850
ReadWritePaths=/var/lib/iec61850
RestrictAddressFamilies=AF_INET AF_INET6
# Si NO se usa GOOSE/SV, elimina AF_PACKET y CAP_NET_RAW:
CapabilityBoundingSet=
AmbientCapabilities=
# Reinicio ante fallo
Restart=on-failure
```

Para GOOSE/SV añade `AF_PACKET` a `RestrictAddressFamilies` y
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`.

## 3. Red

- Coloca el servicio en la **VLAN/segmento** correcto (estación o proceso) y
  filtra por firewall qué clientes pueden alcanzar el puerto MMS.
- **GOOSE/SV en una VLAN dedicada** de la red de proceso; no atraviesan routers.
  Al no llevar autenticación de trama (salvo 62351-6), la segmentación es la
  defensa principal contra inyección.
- Limita el alcance del descubrimiento de red a rangos administrados.

## 4. TLS / mTLS (IEC 62351-3)

- Habilita la feature `tls` y usa **autenticación mutua** (`mTLS`): el servidor
  verifica el certificado de cliente contra su CA y viceversa.
- Provisión de certificados con una PKI propia; un IED = un certificado.
- Rota certificados y publica/consume CRL (revocación).
- Sin TLS, trata la red como no confiable: el tráfico va en claro y no hay
  autenticación de peer (ver el modelo de amenazas).

## 5. Límites de robustez del servidor

Ajusta `ServerLimits` al dimensionamiento real del IED:

```rust
use iec61850_mms::{MmsServer, ServerLimits};
use std::time::Duration;

let limits = ServerLimits {
    max_connections: 16,                       // nº de clientes SCADA esperados
    handshake_timeout: Duration::from_secs(5),
    idle_timeout: Duration::from_secs(60),
    max_report_lag: 128,
};
let server = MmsServer::bind(addr, model, store).await?.with_limits(limits);
```

- `max_connections` acota el consumo de memoria/descriptores.
- `handshake_timeout` corta conexiones lentas (slow-loris).
- `idle_timeout` cierra sesiones asociadas inactivas.
- `max_report_lag` desconecta a un cliente que no drena sus reportes.

## 6. Ficheros

- Sirve la transferencia de ficheros desde un **directorio dedicado** de solo
  lectura con los registros (COMTRADE, logs); nunca desde una raíz sensible.
- `DirFileProvider` ya impide salir del directorio (`..`, rutas absolutas), pero
  aplica también permisos del SO como defensa en profundidad.

## 7. Operación

- Mantén las dependencias al día: el CI corre `cargo audit`/`cargo deny` a diario;
  revisa sus alertas.
- Actualiza ante cualquier aviso de seguridad publicado (ver `SECURITY.md`).
- Registra y monitoriza reconexiones frecuentes o desconexiones por límite: son
  señal de un cliente defectuoso o de un intento de abuso.
