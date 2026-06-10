//! Re-export del tipo `Data` de MMS, ahora en el crate compartido
//! [`iec61850_ber`]. Se mantiene el path `iec61850_mms::mms::data::*` por
//! compatibilidad.

pub use iec61850_ber::data::*;
