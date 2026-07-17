//! Escritor de capturas en formato **pcap clásico** (el que leen Wireshark,
//! tcpdump, libpcap).
//!
//! Permite volcar a disco las tramas capturadas por el sniffer L2 (GOOSE/SV, o
//! todo el tráfico de la subestación con [`crate::socket::RawSocket::open_all`])
//! para analizarlas byte a byte en herramientas externas — una función central
//! de IEDScout (export PCAP/PCAPNG). Es **puro** (solo `std::io`): se prueba sin
//! red y sirve también para reproducir capturas en tests.

use std::io::{self, Write};
use std::time::SystemTime;

/// `LINKTYPE_ETHERNET`: las tramas incluyen la cabecera Ethernet completa.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Magic number del formato pcap en orden little-endian (`0xA1B2C3D4`).
const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
/// El mismo magic visto con orden de bytes invertido (captura big-endian).
const PCAP_MAGIC_SWAPPED: u32 = 0xD4C3_B2A1;
/// `snaplen` por defecto: tramas Ethernet completas con margen para jumbo/VLAN.
const DEFAULT_SNAPLEN: u32 = 65_536;

/// Escritor incremental de un archivo pcap.
///
/// Escribe la cabecera global al construirse y una cabecera de registro por cada
/// trama. Genérico sobre cualquier `Write` (archivo, buffer en memoria, …).
pub struct PcapWriter<W: Write> {
    inner: W,
    snaplen: u32,
}

impl<W: Write> PcapWriter<W> {
    /// Crea un escritor `LINKTYPE_ETHERNET` con `snaplen` por defecto.
    pub fn new(inner: W) -> io::Result<Self> {
        Self::with_linktype(inner, LINKTYPE_ETHERNET, DEFAULT_SNAPLEN)
    }

    /// Crea un escritor con `linktype` y `snaplen` explícitos.
    pub fn with_linktype(mut inner: W, linktype: u32, snaplen: u32) -> io::Result<Self> {
        // Cabecera global (24 octetos), little-endian.
        inner.write_all(&PCAP_MAGIC.to_le_bytes())?;
        inner.write_all(&2u16.to_le_bytes())?; // version_major
        inner.write_all(&4u16.to_le_bytes())?; // version_minor
        inner.write_all(&0i32.to_le_bytes())?; // thiszone (GMT)
        inner.write_all(&0u32.to_le_bytes())?; // sigfigs
        inner.write_all(&snaplen.to_le_bytes())?; // snaplen
        inner.write_all(&linktype.to_le_bytes())?; // network
        Ok(Self { inner, snaplen })
    }

    /// Escribe una trama con su marca de tiempo (segundos + microsegundos desde el
    /// epoch). Si la trama excede `snaplen` se trunca el contenido capturado pero
    /// se registra su longitud original (igual que libpcap).
    pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> io::Result<()> {
        let orig_len = data.len() as u32;
        let incl_len = orig_len.min(self.snaplen);
        self.inner.write_all(&ts_sec.to_le_bytes())?;
        self.inner.write_all(&ts_usec.to_le_bytes())?;
        self.inner.write_all(&incl_len.to_le_bytes())?;
        self.inner.write_all(&orig_len.to_le_bytes())?;
        self.inner.write_all(&data[..incl_len as usize])?;
        Ok(())
    }

    /// Escribe una trama con marca de tiempo tomada de un [`SystemTime`].
    pub fn write_packet_at(&mut self, ts: SystemTime, data: &[u8]) -> io::Result<()> {
        let (sec, usec) = match ts.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
            Err(_) => (0, 0),
        };
        self.write_packet(sec, usec, data)
    }

    /// Escribe una trama con la marca de tiempo del reloj del sistema en este
    /// instante (sello en software, no de hardware).
    pub fn write_packet_now(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_packet_at(SystemTime::now(), data)
    }

    /// Vacía el buffer subyacente.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Devuelve el `Write` subyacente.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Un paquete leído de una captura pcap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapPacket {
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Datos capturados (hasta `snaplen` octetos).
    pub data: Vec<u8>,
}

/// Lector de capturas en formato **pcap clásico**. Complemento de [`PcapWriter`]:
/// itera los paquetes de un buffer en memoria, tolerando tanto el orden
/// little-endian como big-endian (magic invertido). Es puro (sin E/S ni red), así
/// que reproduce capturas del corpus en tests de regresión de los codecs.
pub struct PcapReader {
    data: Vec<u8>,
    pos: usize,
    big_endian: bool,
    /// Tipo de enlace de la cabecera global (p. ej. [`LINKTYPE_ETHERNET`]).
    pub linktype: u32,
    /// `snaplen` declarado en la cabecera global.
    pub snaplen: u32,
}

impl PcapReader {
    /// Abre una captura desde sus bytes. Falla si la cabecera global está
    /// truncada o el magic number no es de pcap clásico.
    pub fn new(bytes: impl Into<Vec<u8>>) -> io::Result<Self> {
        let data = bytes.into();
        if data.len() < 24 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "cabecera pcap truncada",
            ));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let big_endian = match magic {
            PCAP_MAGIC => false,
            PCAP_MAGIC_SWAPPED => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "magic number pcap desconocido",
                ));
            }
        };
        let rd = |b: &[u8], be: bool| -> u32 {
            let a: [u8; 4] = b.try_into().unwrap();
            if be {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        };
        let snaplen = rd(&data[16..20], big_endian);
        let linktype = rd(&data[20..24], big_endian);
        Ok(Self {
            data,
            pos: 24,
            big_endian,
            linktype,
            snaplen,
        })
    }

    fn read_u32(&self, at: usize) -> u32 {
        let a: [u8; 4] = self.data[at..at + 4].try_into().unwrap();
        if self.big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
}

impl Iterator for PcapReader {
    type Item = PcapPacket;

    fn next(&mut self) -> Option<PcapPacket> {
        // Cabecera de registro: 16 octetos (ts_sec, ts_usec, incl_len, orig_len).
        if self.pos + 16 > self.data.len() {
            return None;
        }
        let ts_sec = self.read_u32(self.pos);
        let ts_usec = self.read_u32(self.pos + 4);
        let incl_len = self.read_u32(self.pos + 8) as usize;
        self.pos += 16;
        if self.pos + incl_len > self.data.len() {
            return None; // registro truncado: fin de la captura
        }
        let data = self.data[self.pos..self.pos + incl_len].to_vec();
        self.pos += incl_len;
        Some(PcapPacket {
            ts_sec,
            ts_usec,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_is_well_formed() {
        let buf = Vec::new();
        let w = PcapWriter::new(buf).unwrap();
        let out = w.into_inner();
        assert_eq!(out.len(), 24);
        assert_eq!(&out[0..4], &PCAP_MAGIC.to_le_bytes()); // magic LE
        assert_eq!(&out[4..6], &2u16.to_le_bytes()); // v2
        assert_eq!(&out[6..8], &4u16.to_le_bytes()); // .4
        assert_eq!(
            u32::from_le_bytes(out[20..24].try_into().unwrap()),
            LINKTYPE_ETHERNET
        );
    }

    #[test]
    fn packet_record_round_trip() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        let frame = [0xAAu8, 0xBB, 0xCC, 0xDD];
        w.write_packet(0x1122_3344, 0x0000_07D0, &frame).unwrap();
        let out = w.into_inner();
        // 24 (global) + 16 (record header) + 4 (data)
        assert_eq!(out.len(), 24 + 16 + 4);
        let rec = &out[24..];
        assert_eq!(
            u32::from_le_bytes(rec[0..4].try_into().unwrap()),
            0x1122_3344
        );
        assert_eq!(u32::from_le_bytes(rec[4..8].try_into().unwrap()), 2000); // 0x7D0
        assert_eq!(u32::from_le_bytes(rec[8..12].try_into().unwrap()), 4); // incl_len
        assert_eq!(u32::from_le_bytes(rec[12..16].try_into().unwrap()), 4); // orig_len
        assert_eq!(&rec[16..20], &frame);
    }

    #[test]
    fn reader_round_trips_writer() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1, 2, &[0xAA, 0xBB]).unwrap();
        w.write_packet(3, 4, &[0xCC, 0xDD, 0xEE]).unwrap();
        let bytes = w.into_inner();

        let reader = PcapReader::new(bytes).unwrap();
        assert_eq!(reader.linktype, LINKTYPE_ETHERNET);
        let pkts: Vec<_> = reader.collect();
        assert_eq!(
            pkts,
            vec![
                PcapPacket {
                    ts_sec: 1,
                    ts_usec: 2,
                    data: vec![0xAA, 0xBB]
                },
                PcapPacket {
                    ts_sec: 3,
                    ts_usec: 4,
                    data: vec![0xCC, 0xDD, 0xEE]
                },
            ]
        );
    }

    #[test]
    fn reader_accepts_big_endian_magic() {
        // Cabecera global big-endian con un registro de 1 octeto.
        let mut b = Vec::new();
        b.extend_from_slice(&PCAP_MAGIC_SWAPPED.to_le_bytes()); // magic tal cual (BE visto en LE)
        b.extend_from_slice(&2u16.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&65_536u32.to_be_bytes());
        b.extend_from_slice(&LINKTYPE_ETHERNET.to_be_bytes());
        // registro
        b.extend_from_slice(&9u32.to_be_bytes()); // ts_sec
        b.extend_from_slice(&0u32.to_be_bytes()); // ts_usec
        b.extend_from_slice(&1u32.to_be_bytes()); // incl_len
        b.extend_from_slice(&1u32.to_be_bytes()); // orig_len
        b.push(0x42);

        let mut reader = PcapReader::new(b).unwrap();
        assert!(reader.big_endian);
        let p = reader.next().unwrap();
        assert_eq!((p.ts_sec, p.data), (9, vec![0x42]));
        assert!(reader.next().is_none());
    }

    #[test]
    fn reader_rejects_bad_magic() {
        assert!(PcapReader::new(vec![0u8; 24]).is_err());
    }

    #[test]
    fn truncates_to_snaplen_but_keeps_orig_len() {
        let mut w = PcapWriter::with_linktype(Vec::new(), LINKTYPE_ETHERNET, 2).unwrap();
        w.write_packet(0, 0, &[1, 2, 3, 4, 5]).unwrap();
        let out = w.into_inner();
        let rec = &out[24..];
        assert_eq!(u32::from_le_bytes(rec[8..12].try_into().unwrap()), 2); // incl_len
        assert_eq!(u32::from_le_bytes(rec[12..16].try_into().unwrap()), 5); // orig_len
        assert_eq!(&rec[16..], &[1, 2]); // solo snaplen octetos
    }
}
