# Política de seguridad

## Versiones soportadas

El proyecto está en desarrollo activo (pre-1.0). Se dan parches de seguridad
para la última versión publicada de la rama `0.x`. Hasta la 1.0 la API puede
cambiar entre versiones menores.

## Reporte de vulnerabilidades

**No abras un issue público para una vulnerabilidad.**

Usa el reporte privado de seguridad de GitHub (pestaña *Security* →
*Report a vulnerability*) o escribe a la dirección de contacto del mantenedor.

Incluye, en la medida de lo posible:

- Componente afectado (crate, versión, feature flags).
- Descripción del impacto (DoS, lectura/escritura no autorizada, RCE, etc.).
- Pasos de reproducción o prueba de concepto (idealmente un caso de fuzzing o
  un PCAP).
- Configuración de despliegue relevante (TLS on/off, expuesto a red, etc.).

### Compromiso de respuesta

| Fase | Plazo objetivo |
|------|----------------|
| Acuse de recibo | 72 horas |
| Evaluación inicial de severidad | 7 días |
| Parche o mitigación | según severidad (críticas: prioridad) |
| Divulgación coordinada | tras el parche, de acuerdo con quien reporta |

## Alcance

Interesan especialmente:

- **Parsers de red no confiable** — pánico, agotamiento de memoria o
  desbordamiento de pila en los decodificadores BER/COTP/TPKT/MMS/GOOSE/SV/SCL
  (ver `fuzz/`). Estos se consideran vulnerabilidades, no meros bugs.
- **Servidor MMS** — evasión de los límites de robustez (`ServerLimits`),
  agotamiento de recursos, o acceso a datos/control sin la autorización debida.
- **TLS/mTLS (IEC 62351-3)** — validación incorrecta de certificados, degradación
  de cifrado, o cualquier fallo que permita MITM.
- **Transferencia de ficheros** — salida del directorio servido (path traversal).

Fuera de alcance:

- Las apps de escritorio de ejemplo (`iec61850-gui`, `iec61850-tauri`) como
  productos finales — son demostradores.
- Denegación de servicio que requiera acceso físico al segmento de red de
  proceso (GOOSE/SV son multicast L2 sin autenticación por diseño del estándar;
  la mitigación es de red/62351-6, ver el modelo de amenazas).

## Prácticas del proyecto

- `unsafe_code = "forbid"` en todos los crates salvo `iec61850-l2` (syscalls
  AF_PACKET, cada bloque justificado con `// SAFETY:`).
- Fuzzing continuo de todos los parsers (`fuzz/`, CI nocturno).
- `cargo audit` + `cargo deny` diarios sobre el árbol de dependencias.
- Auditoría de la cadena de suministro con SBOM (CycloneDX) por release.

Ver [`docs/threat-model.md`](docs/threat-model.md) y
[`docs/secure-deployment.md`](docs/secure-deployment.md).
