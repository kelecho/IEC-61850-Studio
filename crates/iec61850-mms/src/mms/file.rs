//! Servicios MMS de **transferencia de ficheros** (ISO 9506-2): `fileDirectory`
//! [77], `fileOpen` [72], `fileRead` [73] y `fileClose` [74].
//!
//! Permiten **listar y descargar ficheros del IED** — registros de perturbación
//! (disturbance records), oscilografías COMTRADE, logs — una función de
//! commissioning de IEDScout. La descarga es por bloques: `fileOpen` devuelve un
//! `frsmID` y el tamaño; `fileRead` se repite hasta `moreFollows = false`;
//! `fileClose` libera el handle.

use crate::ber::reader::{BerReader, Tlv};
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::error::MmsError;
use crate::mms::pdu::{self, service};

/// `GraphicString` (UNIVERSAL 25): el tipo de los componentes de `FileName`.
const GRAPHIC_STRING: Tag = Tag::universal(0x19, false);

/// Entrada de directorio: nombre, tamaño en octetos y fecha de última
/// modificación (si el IED la informa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub size: u32,
    pub last_modified: Option<String>,
}

/// Atributos de un fichero abierto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttributes {
    pub size: u32,
    pub last_modified: Option<String>,
}

/// Resultado de abrir un fichero: handle (`frsmID`) y atributos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpen {
    pub frsm_id: i32,
    pub attributes: FileAttributes,
}

/// Un bloque leído: datos y si quedan más bloques.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunk {
    pub data: Vec<u8>,
    pub more_follows: bool,
}

/// Resultado de listar un directorio: entradas y si la lista continúa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDirectory {
    pub entries: Vec<FileEntry>,
    pub more_follows: bool,
}

// --- FileName ---

/// Escribe el contenido de un `FileName` (`SEQUENCE OF GraphicString`) con un
/// único componente. El tag de contexto que lo envuelve (`[0]`/`[1]`) actúa como
/// el `SEQUENCE` IMPLICIT, así que aquí solo van los `GraphicString`.
fn write_file_name(w: &mut BerWriter, name: &str) {
    w.visible_string(GRAPHIC_STRING, name);
}

/// Decodifica el contenido de un `FileName` (los `GraphicString` directamente) →
/// el último componente (en 61850 suele haber uno solo: la ruta completa).
fn decode_file_name(content: &[u8]) -> Result<String, MmsError> {
    let mut r = BerReader::new(content);
    let mut name = String::new();
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        name = crate::ber::prim::decode_visible_string(tlv.content)?.to_string();
    }
    Ok(name)
}

// --- fileDirectory [77] ---

/// Escribe `fileDirectory [77] { fileSpecification [0]? , continueAfter [1]? }`.
pub fn write_directory_request(
    w: &mut BerWriter,
    prefix: Option<&str>,
    continue_after: Option<&str>,
) {
    w.tlv(service::FILE_DIRECTORY, |w| {
        if let Some(p) = prefix {
            w.tlv(Tag::context(0, true), |w| write_file_name(w, p));
        }
        if let Some(c) = continue_after {
            w.tlv(Tag::context(1, true), |w| write_file_name(w, c));
        }
    });
}

/// Decodifica la respuesta `fileDirectory`.
pub fn decode_directory_response(service_tlv: &Tlv<'_>) -> Result<FileDirectory, MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_DIRECTORY)?;
    let mut r = BerReader::new(content);
    // listOfDirectoryEntry [0] IMPLICIT SEQUENCE OF DirectoryEntry
    let list = r.expect(Tag::context(0, true))?;
    let mut lr = BerReader::new(list);
    let mut entries = Vec::new();
    while !lr.is_empty() {
        let entry = lr.read_tlv()?; // DirectoryEntry ::= SEQUENCE
        entries.push(decode_directory_entry(entry.content)?);
    }
    // moreFollows [1] IMPLICIT BOOLEAN DEFAULT FALSE
    let more_follows = match r.read_if(Tag::context(1, false))? {
        Some(c) => crate::ber::prim::decode_bool(c)?,
        None => false,
    };
    Ok(FileDirectory {
        entries,
        more_follows,
    })
}

fn decode_directory_entry(content: &[u8]) -> Result<FileEntry, MmsError> {
    let mut r = BerReader::new(content);
    // fileName [0] FileName
    let name = decode_file_name(r.expect(Tag::context(0, true))?)?;
    // fileAttributes [1] IMPLICIT FileAttributes
    let attrs = decode_file_attributes(r.expect(Tag::context(1, true))?)?;
    Ok(FileEntry {
        name,
        size: attrs.size,
        last_modified: attrs.last_modified,
    })
}

fn decode_file_attributes(content: &[u8]) -> Result<FileAttributes, MmsError> {
    let mut r = BerReader::new(content);
    // sizeOfFile [0] IMPLICIT Unsigned32
    let size = crate::ber::prim::decode_unsigned(r.expect(Tag::context(0, false))?)? as u32;
    // lastModified [1] IMPLICIT GeneralizedTime OPTIONAL
    let last_modified = match r.read_if(Tag::context(1, false))? {
        Some(c) => Some(crate::ber::prim::decode_visible_string(c)?.to_string()),
        None => None,
    };
    Ok(FileAttributes {
        size,
        last_modified,
    })
}

// --- fileOpen [72] ---

/// Escribe `fileOpen [72] { fileName [0] FileName, initialPosition [1] Unsigned32 }`.
pub fn write_open_request(w: &mut BerWriter, name: &str, initial_position: u32) {
    w.tlv(service::FILE_OPEN, |w| {
        w.tlv(Tag::context(0, true), |w| write_file_name(w, name));
        w.unsigned(Tag::context(1, false), initial_position as u64);
    });
}

/// Decodifica la respuesta `fileOpen`.
pub fn decode_open_response(service_tlv: &Tlv<'_>) -> Result<FileOpen, MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_OPEN)?;
    let mut r = BerReader::new(content);
    // frsmID [0] IMPLICIT Integer32
    let frsm_id = crate::ber::prim::decode_integer(r.expect(Tag::context(0, false))?)? as i32;
    // fileAttributes [1] IMPLICIT FileAttributes
    let attributes = decode_file_attributes(r.expect(Tag::context(1, true))?)?;
    Ok(FileOpen {
        frsm_id,
        attributes,
    })
}

// --- fileRead [73] ---

/// Escribe `fileRead [73] IMPLICIT Integer32` (= frsmID).
pub fn write_read_request(w: &mut BerWriter, frsm_id: i32) {
    w.integer(service::FILE_READ, frsm_id as i64);
}

/// Decodifica la respuesta `fileRead`.
pub fn decode_read_response(service_tlv: &Tlv<'_>) -> Result<FileChunk, MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_READ)?;
    let mut r = BerReader::new(content);
    // fileData [0] IMPLICIT OCTET STRING
    let data = r.expect(Tag::context(0, false))?.to_vec();
    // moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE
    let more_follows = match r.read_if(Tag::context(1, false))? {
        Some(c) => crate::ber::prim::decode_bool(c)?,
        None => true,
    };
    Ok(FileChunk { data, more_follows })
}

// --- fileClose [74] ---

/// Escribe `fileClose [74] IMPLICIT Integer32` (= frsmID).
pub fn write_close_request(w: &mut BerWriter, frsm_id: i32) {
    w.integer(service::FILE_CLOSE, frsm_id as i64);
}

// =====================================================================
// Lado servidor: decodificar peticiones y codificar respuestas.
// =====================================================================

/// Decodifica `fileDirectory` → `(prefijo?, continueAfter?)`.
pub fn decode_directory_request(
    service_tlv: &Tlv<'_>,
) -> Result<(Option<String>, Option<String>), MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_DIRECTORY)?;
    let mut r = BerReader::new(content);
    let prefix = match r.read_if(Tag::context(0, true))? {
        Some(c) => Some(decode_file_name(c)?),
        None => None,
    };
    let continue_after = match r.read_if(Tag::context(1, true))? {
        Some(c) => Some(decode_file_name(c)?),
        None => None,
    };
    Ok((prefix, continue_after))
}

/// Decodifica `fileOpen` → `(nombre, posición inicial)`.
pub fn decode_open_request(service_tlv: &Tlv<'_>) -> Result<(String, u32), MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_OPEN)?;
    let mut r = BerReader::new(content);
    let name = decode_file_name(r.expect(Tag::context(0, true))?)?;
    let pos = crate::ber::prim::decode_unsigned(r.expect(Tag::context(1, false))?)? as u32;
    Ok((name, pos))
}

/// Decodifica `fileRead` → frsmID.
pub fn decode_read_request(service_tlv: &Tlv<'_>) -> Result<i32, MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_READ)?;
    Ok(crate::ber::prim::decode_integer(content)? as i32)
}

/// Decodifica `fileClose` → frsmID.
pub fn decode_close_request(service_tlv: &Tlv<'_>) -> Result<i32, MmsError> {
    let content = pdu::expect_service(service_tlv, service::FILE_CLOSE)?;
    Ok(crate::ber::prim::decode_integer(content)? as i32)
}

/// Codifica la respuesta `fileDirectory`.
pub fn encode_directory_response(w: &mut BerWriter, dir: &FileDirectory) {
    w.tlv(service::FILE_DIRECTORY, |w| {
        w.tlv(Tag::context(0, true), |w| {
            for e in &dir.entries {
                w.sequence(|w| {
                    w.tlv(Tag::context(0, true), |w| write_file_name(w, &e.name));
                    w.tlv(Tag::context(1, true), |w| {
                        w.unsigned(Tag::context(0, false), e.size as u64);
                        if let Some(lm) = &e.last_modified {
                            w.visible_string(Tag::context(1, false), lm);
                        }
                    });
                });
            }
        });
        if dir.more_follows {
            w.boolean(Tag::context(1, false), true);
        }
    });
}

/// Codifica la respuesta `fileOpen`.
pub fn encode_open_response(w: &mut BerWriter, open: &FileOpen) {
    w.tlv(service::FILE_OPEN, |w| {
        w.integer(Tag::context(0, false), open.frsm_id as i64);
        w.tlv(Tag::context(1, true), |w| {
            w.unsigned(Tag::context(0, false), open.attributes.size as u64);
            if let Some(lm) = &open.attributes.last_modified {
                w.visible_string(Tag::context(1, false), lm);
            }
        });
    });
}

/// Codifica la respuesta `fileRead`.
pub fn encode_read_response(w: &mut BerWriter, chunk: &FileChunk) {
    w.tlv(service::FILE_READ, |w| {
        w.octet_string(Tag::context(0, false), &chunk.data);
        // moreFollows DEFAULT TRUE: lo emitimos solo cuando es false.
        if !chunk.more_follows {
            w.boolean(Tag::context(1, false), false);
        }
    });
}

/// Codifica la respuesta `fileClose` (`NULL`).
pub fn encode_close_response(w: &mut BerWriter) {
    w.null(service::FILE_CLOSE);
}

/// Fuente de ficheros que un [`crate::server::MmsServer`] expone por MMS.
pub trait FileProvider: Send + Sync {
    /// Lista los ficheros cuyo nombre empieza por `prefix` (None = todos).
    fn list(&self, prefix: Option<&str>) -> std::io::Result<Vec<FileEntry>>;
    /// Lee el contenido completo de un fichero.
    fn read(&self, name: &str) -> std::io::Result<Vec<u8>>;
}

/// Proveedor de ficheros respaldado por un directorio del disco. Sirve los
/// ficheros (no recursivo) de `base`, con protección contra *path traversal*.
pub struct DirFileProvider {
    base: std::path::PathBuf,
}

impl DirFileProvider {
    pub fn new(base: impl Into<std::path::PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Resuelve `name` dentro de `base` rechazando `..`, rutas absolutas y
    /// prefijos: solo se permiten componentes de nombre normales.
    fn resolve(&self, name: &str) -> std::io::Result<std::path::PathBuf> {
        use std::path::Component;
        let rel = name.trim_start_matches('/');
        let mut path = self.base.clone();
        for comp in std::path::Path::new(rel).components() {
            match comp {
                Component::Normal(c) => path.push(c),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "ruta de fichero no permitida",
                    ));
                }
            }
        }
        Ok(path)
    }
}

impl FileProvider for DirFileProvider {
    fn list(&self, prefix: Option<&str>) -> std::io::Result<Vec<FileEntry>> {
        let prefix = prefix.map(|p| p.trim_start_matches('/').to_string());
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.base)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(p) = &prefix {
                if !name.starts_with(p) {
                    continue;
                }
            }
            out.push(FileEntry {
                name,
                size: meta.len() as u32,
                last_modified: None,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.resolve(name)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye un PDU de respuesta confirmada con un servicio dado y lo
    /// reabre, para validar encode↔decode del lado servidor contra el cliente.
    fn service_tlv(write: impl FnOnce(&mut BerWriter)) -> Vec<u8> {
        let mut w = BerWriter::new();
        write(&mut w);
        w.into_bytes()
    }

    #[test]
    fn directory_request_shape() {
        let mut w = BerWriter::new();
        write_directory_request(&mut w, Some("/COMTRADE/"), None);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(svc.tag, service::FILE_DIRECTORY);
        assert!(bytes.windows(10).any(|c| c == b"/COMTRADE/"));
    }

    #[test]
    fn directory_response_round_trip() {
        // Respuesta del servidor: 2 entradas + moreFollows true.
        let bytes = service_tlv(|w| {
            w.tlv(service::FILE_DIRECTORY, |w| {
                w.tlv(Tag::context(0, true), |w| {
                    // entry 1
                    w.sequence(|w| {
                        w.tlv(Tag::context(0, true), |w| write_file_name(w, "rec001.cfg"));
                        w.tlv(Tag::context(1, true), |w| {
                            w.unsigned(Tag::context(0, false), 1024);
                            w.visible_string(Tag::context(1, false), "20260610120000Z");
                        });
                    });
                    // entry 2 (sin lastModified)
                    w.sequence(|w| {
                        w.tlv(Tag::context(0, true), |w| write_file_name(w, "rec001.dat"));
                        w.tlv(Tag::context(1, true), |w| {
                            w.unsigned(Tag::context(0, false), 65536);
                        });
                    });
                });
                w.boolean(Tag::context(1, false), true);
            });
        });
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        let dir = decode_directory_response(&svc).unwrap();
        assert!(dir.more_follows);
        assert_eq!(dir.entries.len(), 2);
        assert_eq!(dir.entries[0].name, "rec001.cfg");
        assert_eq!(dir.entries[0].size, 1024);
        assert_eq!(
            dir.entries[0].last_modified.as_deref(),
            Some("20260610120000Z")
        );
        assert_eq!(dir.entries[1].name, "rec001.dat");
        assert_eq!(dir.entries[1].size, 65536);
        assert_eq!(dir.entries[1].last_modified, None);
    }

    #[test]
    fn open_round_trip() {
        let bytes = service_tlv(|w| {
            w.tlv(service::FILE_OPEN, |w| {
                w.integer(Tag::context(0, false), 7); // frsmID
                w.tlv(Tag::context(1, true), |w| {
                    w.unsigned(Tag::context(0, false), 4096);
                });
            });
        });
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        let open = decode_open_response(&svc).unwrap();
        assert_eq!(open.frsm_id, 7);
        assert_eq!(open.attributes.size, 4096);

        // y la petición lleva el nombre y la posición inicial.
        let mut rw = BerWriter::new();
        write_open_request(&mut rw, "/COMTRADE/rec001.cfg", 0);
        assert!(
            rw.into_bytes()
                .windows(20)
                .any(|c| c == b"/COMTRADE/rec001.cfg")
        );
    }

    #[test]
    fn read_response_data_and_more() {
        // con moreFollows explícito false
        let bytes = service_tlv(|w| {
            w.tlv(service::FILE_READ, |w| {
                w.octet_string(Tag::context(0, false), &[1, 2, 3, 4]);
                w.boolean(Tag::context(1, false), false);
            });
        });
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        let chunk = decode_read_response(&svc).unwrap();
        assert_eq!(chunk.data, vec![1, 2, 3, 4]);
        assert!(!chunk.more_follows);

        // sin moreFollows → DEFAULT TRUE
        let bytes = service_tlv(|w| {
            w.tlv(service::FILE_READ, |w| {
                w.octet_string(Tag::context(0, false), &[9]);
            });
        });
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert!(decode_read_response(&svc).unwrap().more_follows);
    }

    #[test]
    fn dir_provider_lists_and_rejects_traversal() {
        let dir = std::env::temp_dir().join(format!("iec61850_fp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.cfg"), b"hello").unwrap();
        std::fs::write(dir.join("b.dat"), b"world!!").unwrap();
        let p = DirFileProvider::new(&dir);

        let all = p.list(None).unwrap();
        assert_eq!(all.len(), 2);
        let only_cfg = p.list(Some("a")).unwrap();
        assert_eq!(only_cfg.len(), 1);
        assert_eq!(only_cfg[0].name, "a.cfg");
        assert_eq!(only_cfg[0].size, 5);

        assert_eq!(p.read("b.dat").unwrap(), b"world!!");
        // path traversal rechazado.
        assert!(p.read("../secreto").is_err());
        assert!(p.read("/etc/passwd").is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_and_close_requests_carry_frsm_id() {
        let mut w = BerWriter::new();
        write_read_request(&mut w, 42);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let svc = r.read_tlv().unwrap();
        assert_eq!(svc.tag, service::FILE_READ);
        assert_eq!(crate::ber::prim::decode_integer(svc.content).unwrap(), 42);

        let mut w = BerWriter::new();
        write_close_request(&mut w, 42);
        let mut r = BerReader::new(w.as_bytes());
        let svc = r.read_tlv().unwrap();
        assert_eq!(svc.tag, service::FILE_CLOSE);
    }
}
