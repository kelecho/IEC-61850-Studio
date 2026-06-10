//! Mapeo IEC 61850-8-1 entre una [`ObjectReference`] del modelo y los nombres
//! MMS *domain-specific* (`domainId` / `itemId`).
//!
//! Regla:
//! - `domainId` = nombre del dispositivo lógico (el campo `ld` de la referencia,
//!   que ya incluye el prefijo del IED si aplica).
//! - `itemId` = `LN$FC$seg1$seg2$…`, es decir el nodo lógico, seguido de la
//!   restricción funcional, seguido de los segmentos DO/DA unidos por `$`.
//!
//! Ejemplo: `IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]`
//!   → `domainId = "IED1LD0"`, `itemId = "MMXU1$MX$A$phsA$cVal$mag$f"`.

use std::str::FromStr;

use iec61850_model::{FunctionalConstraint, ObjectReference};

/// Error de mapeo 8-1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("la referencia '{0}' no especifica restricción funcional (FC), requerida para MMS")]
    MissingFc(String),
    #[error("el itemId MMS '{0}' no sigue el patrón 'LN$FC$...'")]
    UnexpectedItemId(String),
    #[error("FC desconocida en el itemId MMS: '{0}'")]
    BadFc(String),
}

/// Convierte una referencia de objeto a `(domainId, itemId)` MMS.
///
/// Requiere que la referencia tenga FC (MMS la necesita en el `itemId`).
pub fn object_reference_to_mms(obj: &ObjectReference) -> Result<(String, String), MappingError> {
    let fc = obj
        .fc
        .ok_or_else(|| MappingError::MissingFc(obj.to_string()))?;

    let mut item = String::with_capacity(
        obj.ln.len() + 4 + obj.path.iter().map(|p| p.len() + 1).sum::<usize>(),
    );
    item.push_str(&obj.ln);
    item.push('$');
    item.push_str(fc.as_str());
    for seg in &obj.path {
        item.push('$');
        item.push_str(seg);
    }

    Ok((obj.ld.clone(), item))
}

/// Reconstruye una referencia de objeto a partir de los nombres MMS, p. ej. al
/// descubrir variables con `GetNameList`.
pub fn mms_to_object_reference(
    domain_id: &str,
    item_id: &str,
) -> Result<ObjectReference, MappingError> {
    let mut parts = item_id.split('$');
    let ln = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MappingError::UnexpectedItemId(item_id.to_string()))?;
    let fc_str = parts
        .next()
        .ok_or_else(|| MappingError::UnexpectedItemId(item_id.to_string()))?;
    let fc = FunctionalConstraint::from_str(fc_str)
        .map_err(|_| MappingError::BadFc(fc_str.to_string()))?;
    let path: Vec<String> = parts.map(|s| s.to_string()).collect();

    Ok(ObjectReference {
        ld: domain_id.to_string(),
        ln: ln.to_string(),
        path,
        fc: Some(fc),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(reference: &str, domain: &str, item: &str) {
        let obj: ObjectReference = reference.parse().unwrap();
        let (d, i) = object_reference_to_mms(&obj).unwrap();
        assert_eq!((d.as_str(), i.as_str()), (domain, item), "forward");

        let back = mms_to_object_reference(domain, item).unwrap();
        assert_eq!(back, obj, "inverso");
    }

    #[test]
    fn simple_status() {
        round_trip("IED1LD0/LLN0.Mod.stVal[ST]", "IED1LD0", "LLN0$ST$Mod$stVal");
    }

    #[test]
    fn deep_measurand() {
        round_trip(
            "IED1LD0/MMXU1.A.phsA.cVal.mag.f[MX]",
            "IED1LD0",
            "MMXU1$MX$A$phsA$cVal$mag$f",
        );
    }

    #[test]
    fn ln_only_with_fc() {
        // Referencia a un DO completo: LN$FC sin segmentos extra... realmente
        // aquí es LN + FC + un DO. Probamos LN + FC sin path.
        let obj = ObjectReference {
            ld: "IED1LD0".into(),
            ln: "LLN0".into(),
            path: vec![],
            fc: Some(FunctionalConstraint::ST),
        };
        let (d, i) = object_reference_to_mms(&obj).unwrap();
        assert_eq!((d.as_str(), i.as_str()), ("IED1LD0", "LLN0$ST"));
    }

    #[test]
    fn missing_fc_errors() {
        let obj: ObjectReference = "IED1LD0/LLN0.Mod.stVal".parse().unwrap();
        assert!(matches!(
            object_reference_to_mms(&obj),
            Err(MappingError::MissingFc(_))
        ));
    }

    #[test]
    fn unexpected_item_id() {
        // itemId sin FC válida (p. ej. nombre de dataset) → error.
        assert!(matches!(
            mms_to_object_reference("IED1LD0", "ds1"),
            Err(MappingError::UnexpectedItemId(_))
        ));
        assert!(matches!(
            mms_to_object_reference("IED1LD0", "LLN0$ZZ$Mod"),
            Err(MappingError::BadFc(_))
        ));
    }
}
