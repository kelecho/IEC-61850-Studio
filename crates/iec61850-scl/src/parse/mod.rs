//! Lectura de documentos SCL desde texto o disco.

use std::path::Path;

use crate::error::SclError;
use crate::model::SclDocument;

/// Parsea un documento SCL desde una cadena XML.
///
/// Robustez frente a ficheros de fabricantes: si el parseo directo queda **vacío**
/// (típico cuando el exportador **prefija** todos los elementos, p. ej.
/// `<scl:SCL><scl:Header>…`, que quick-xml no reconoce) o **falla** (p. ej.
/// atributos `xsi:type` que quick-xml colapsa al nombre local `@type` y
/// colisionan con el atributo `type` propio del SCL, como emite IET600 de
/// ABB/Hitachi), se reintenta tras **normalizar los prefijos de namespace**.
pub fn parse_scl_str(xml: &str) -> Result<SclDocument, SclError> {
    let direct: Result<SclDocument, _> = quick_xml::de::from_str(xml);
    let retry = match &direct {
        Ok(doc) => doc.is_empty(),
        Err(_) => true,
    };
    if retry {
        if let Some(normalized) = strip_namespace_prefixes(xml) {
            if let Ok(doc2) = quick_xml::de::from_str::<SclDocument>(&normalized) {
                if !doc2.is_empty() {
                    return Ok(doc2);
                }
            }
        }
    }
    Ok(direct?)
}

/// Reescribe el XML quitando el **prefijo de namespace** de los nombres de
/// elementos y eliminando las declaraciones `xmlns`. Así los ficheros
/// con todo prefijado (`<scl:SCL>…`) casan con los nombres locales que espera el
/// parser. Los **atributos con prefijo** (`xsi:type`, `eABB:…`) pertenecen a
/// namespaces ajenos al SCL y se **descartan**: localizarlos podría duplicar un
/// atributo propio del mismo nombre (`type` vs `xsi:type`). Devuelve `None` si
/// el XML no se puede re-tokenizar.
fn strip_namespace_prefixes(xml: &str) -> Option<String> {
    use quick_xml::events::{BytesEnd, BytesStart, Event};
    use quick_xml::{Reader, Writer};

    fn local(name: &[u8]) -> &[u8] {
        match name.iter().rposition(|&b| b == b':') {
            Some(i) => &name[i + 1..],
            None => name,
        }
    }
    fn rewrite_start(e: &BytesStart) -> Option<BytesStart<'static>> {
        let name = e.name();
        let local_name = String::from_utf8_lossy(local(name.as_ref())).into_owned();
        let mut out = BytesStart::new(local_name);
        for attr in e.attributes().with_checks(false) {
            let attr = attr.ok()?;
            let key = attr.key.as_ref();
            // Descarta las declaraciones de namespace y los atributos de
            // namespaces ajenos (todo atributo con prefijo).
            if key == b"xmlns" || key.contains(&b':') {
                continue;
            }
            let key_local = String::from_utf8_lossy(key).into_owned();
            let raw = std::str::from_utf8(attr.value.as_ref()).ok()?;
            let value = quick_xml::escape::unescape(raw).ok()?.into_owned();
            out.push_attribute((key_local.as_str(), value.as_str()));
        }
        Some(out)
    }

    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    loop {
        match reader.read_event().ok()? {
            Event::Eof => break,
            Event::Start(e) => writer.write_event(Event::Start(rewrite_start(&e)?)).ok()?,
            Event::Empty(e) => writer.write_event(Event::Empty(rewrite_start(&e)?)).ok()?,
            Event::End(e) => {
                let name = String::from_utf8_lossy(local(e.name().as_ref())).into_owned();
                writer.write_event(Event::End(BytesEnd::new(name))).ok()?;
            }
            other => writer.write_event(other).ok()?,
        }
    }
    String::from_utf8(writer.into_inner()).ok()
}

/// Parsea un documento SCL desde un archivo (`.icd`, `.cid`, `.scd`, `.ssd`).
pub fn parse_scl_file<P: AsRef<Path>>(path: P) -> Result<SclDocument, SclError> {
    let path = path.as_ref();
    let xml = std::fs::read_to_string(path).map_err(|source| SclError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_scl_str(&xml)
}
