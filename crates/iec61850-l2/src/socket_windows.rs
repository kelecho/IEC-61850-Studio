//! Socket de capa 2 sobre **Npcap** (Windows). `wpcap.dll` se carga en tiempo
//! de ejecución con `libloading`: no hace falta el SDK de Npcap al compilar y
//! la aplicación arranca aunque Npcap no esté instalado — el error aparece,
//! claro y accionable, al intentar abrir la captura.
//!
//! Mismo contrato que el backend `AF_PACKET` de Linux ([`RawSocket`] +
//! [`interfaces`]): el resto del stack (GOOSE/SV/PCAP) no distingue el SO.
//!
//! El handle `pcap_t` no es seguro entre hilos: un hilo propietario hace la
//! captura (con timeout corto) y drena una cola de envíos; `RawSocket` habla
//! con él por canales. Al soltar el `RawSocket`, el hilo cierra el handle.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::OnceLock;
use std::sync::mpsc as std_mpsc;

use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::error::L2Error;
use crate::eth::MacAddr;
use crate::link::L2Link;

/// Tamaño del buffer de error de libpcap (`PCAP_ERRBUF_SIZE`).
const ERRBUF: usize = 256;
/// Timeout de lectura del handle, ms: mantiene vivo el bucle envío/recepción.
const READ_TIMEOUT_MS: c_int = 25;
/// Capacidad de la cola de tramas entrantes (se descartan si nadie consume).
const IN_QUEUE: usize = 1024;

type PcapT = c_void;

/// Nodo de `pcap_findalldevs` (prefijo estable del layout de `pcap_if_t`).
#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: c_uint,
}

/// `struct bpf_program` (opaco: solo se pasa entre compile/setfilter/freecode).
#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

/// `struct pcap_pkthdr`: `timeval` de Windows (2 × `long` de 32 bits) + tamaños.
#[repr(C)]
struct PcapPkthdr {
    tv_sec: i32,
    tv_usec: i32,
    caplen: u32,
    len: u32,
}

/// Símbolos de `wpcap.dll` resueltos una sola vez (la `Library` vive aquí).
struct Wpcap {
    _lib: libloading::Library,
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    open_live: unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut PcapT,
    compile: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int,
    setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    sendpacket: unsafe extern "C" fn(*mut PcapT, *const u8, c_int) -> c_int,
    next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int,
    geterr: unsafe extern "C" fn(*mut PcapT) -> *mut c_char,
    close: unsafe extern "C" fn(*mut PcapT),
}

// SAFETY: los punteros a función de wpcap son reentrantes por handle; el handle
// en sí solo lo usa su hilo propietario.
unsafe impl Send for Wpcap {}
unsafe impl Sync for Wpcap {}

impl Wpcap {
    fn load() -> Result<Self, String> {
        // SAFETY: cargar wpcap.dll ejecuta su DllMain, como cualquier LoadLibrary.
        let lib = unsafe { libloading::Library::new("wpcap.dll") }.map_err(|e| {
            format!(
                "no se pudo cargar wpcap.dll ({e}); instala Npcap (https://npcap.com) \
                 marcando «WinPcap API-compatible Mode»"
            )
        })?;
        macro_rules! sym {
            ($name:literal) => {
                // SAFETY: el símbolo es una función C exportada por wpcap.dll con
                // la firma declarada; la Library se conserva en el struct.
                *unsafe { lib.get($name) }.map_err(|e| format!("símbolo {:?}: {e}", $name))?
            };
        }
        let findalldevs = sym!(b"pcap_findalldevs\0");
        let freealldevs = sym!(b"pcap_freealldevs\0");
        let open_live = sym!(b"pcap_open_live\0");
        let compile = sym!(b"pcap_compile\0");
        let setfilter = sym!(b"pcap_setfilter\0");
        let freecode = sym!(b"pcap_freecode\0");
        let sendpacket = sym!(b"pcap_sendpacket\0");
        let next_ex = sym!(b"pcap_next_ex\0");
        let geterr = sym!(b"pcap_geterr\0");
        let close = sym!(b"pcap_close\0");
        Ok(Wpcap {
            _lib: lib,
            findalldevs,
            freealldevs,
            open_live,
            compile,
            setfilter,
            freecode,
            sendpacket,
            next_ex,
            geterr,
            close,
        })
    }
}

/// wpcap.dll cargada una única vez por proceso.
fn wpcap() -> Result<&'static Wpcap, L2Error> {
    static LIB: OnceLock<Result<Wpcap, String>> = OnceLock::new();
    LIB.get_or_init(Wpcap::load)
        .as_ref()
        .map_err(|e| L2Error::Io(std::io::Error::other(e.clone())))
}

fn errbuf_msg(errbuf: &[c_char; ERRBUF]) -> String {
    // SAFETY: libpcap escribe una cadena C NUL-terminada en errbuf.
    unsafe { CStr::from_ptr(errbuf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Último error del handle (`pcap_geterr`).
fn handle_msg(api: &Wpcap, handle: *mut PcapT) -> String {
    // SAFETY: geterr devuelve un puntero a cadena C interna del handle vivo.
    unsafe { CStr::from_ptr((api.geterr)(handle)) }
        .to_string_lossy()
        .into_owned()
}

fn mac_str(m: &MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Puntero trasladable al hilo de captura (solo lo usa ese hilo).
struct HandlePtr(*mut PcapT);
// SAFETY: el handle se mueve al hilo propietario y no se comparte.
unsafe impl Send for HandlePtr {}

/// Socket de capa 2 sobre una interfaz Ethernet (backend Npcap).
pub struct RawSocket {
    out_tx: std_mpsc::Sender<Vec<u8>>,
    in_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl RawSocket {
    /// Abre el socket en `interface`, filtrando `ethertype` y el grupo multicast
    /// `group` (modo publicador/suscriptor de un único flujo).
    pub fn open(interface: &str, ethertype: u16, group: MacAddr) -> Result<Self, L2Error> {
        let filter = format!(
            "ether proto 0x{ethertype:04x} and ether dst {}",
            mac_str(&group)
        );
        Self::open_inner(interface, Some(filter))
    }

    /// Abre el socket en modo promiscuo filtrando un `ethertype`: recibe ese
    /// EtherType dirigido a cualquier MAC (sniffer tipo IEDScout).
    pub fn open_promiscuous(interface: &str, ethertype: u16) -> Result<Self, L2Error> {
        Self::open_inner(interface, Some(format!("ether proto 0x{ethertype:04x}")))
    }

    /// Abre el socket capturando todo el tráfico de la interfaz (para PCAP).
    pub fn open_all(interface: &str) -> Result<Self, L2Error> {
        Self::open_inner(interface, None)
    }

    fn open_inner(interface: &str, filter: Option<String>) -> Result<Self, L2Error> {
        let api = wpcap()?;
        let dev = CString::new(interface)
            .map_err(|_| L2Error::Malformed("nombre de interfaz inválido".into()))?;
        let mut errbuf = [0 as c_char; ERRBUF];
        // Promiscuo siempre: los filtros BPF ya limitan lo que se entrega.
        // SAFETY: dev es NUL-terminada y errbuf tiene PCAP_ERRBUF_SIZE octetos.
        let handle = unsafe {
            (api.open_live)(dev.as_ptr(), 65_535, 1, READ_TIMEOUT_MS, errbuf.as_mut_ptr())
        };
        if handle.is_null() {
            let msg = errbuf_msg(&errbuf);
            return Err(if msg.to_ascii_lowercase().contains("denied") {
                L2Error::Permission
            } else {
                L2Error::Io(std::io::Error::other(format!("pcap_open_live: {msg}")))
            });
        }
        if let Some(f) = filter {
            let cf = CString::new(f)
                .map_err(|_| L2Error::Malformed("filtro BPF inválido".into()))?;
            let mut prog = BpfProgram {
                bf_len: 0,
                bf_insns: ptr::null_mut(),
            };
            // SAFETY: handle y prog válidos; netmask desconocida = 0xffffffff.
            if unsafe { (api.compile)(handle, &mut prog, cf.as_ptr(), 1, 0xffff_ffff) } < 0 {
                let msg = handle_msg(api, handle);
                // SAFETY: handle válido, se cierra una única vez.
                unsafe { (api.close)(handle) };
                return Err(L2Error::Io(std::io::Error::other(format!(
                    "pcap_compile: {msg}"
                ))));
            }
            // SAFETY: prog compilado arriba; se libera siempre tras setfilter.
            let rc = unsafe { (api.setfilter)(handle, &mut prog) };
            unsafe { (api.freecode)(&mut prog) };
            if rc < 0 {
                let msg = handle_msg(api, handle);
                // SAFETY: handle válido, se cierra una única vez.
                unsafe { (api.close)(handle) };
                return Err(L2Error::Io(std::io::Error::other(format!(
                    "pcap_setfilter: {msg}"
                ))));
            }
        }

        let (out_tx, out_rx) = std_mpsc::channel::<Vec<u8>>();
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(IN_QUEUE);
        let moved = HandlePtr(handle);
        std::thread::Builder::new()
            .name("npcap-l2".into())
            .spawn(move || {
                // Reasignar la variable base fuerza a la captura disjunta (ed.
                // 2021) a mover el `HandlePtr` entero — que es `Send` — en vez
                // del campo `*mut c_void`, que no lo es.
                let moved = moved;
                let handle = moved.0;
                loop {
                    // Drena la cola de envíos pendientes.
                    loop {
                        match out_rx.try_recv() {
                            // SAFETY: handle vivo (lo cierra solo este hilo).
                            Ok(frame) => unsafe {
                                let _ = (api.sendpacket)(
                                    handle,
                                    frame.as_ptr(),
                                    frame.len() as c_int,
                                );
                            },
                            Err(std_mpsc::TryRecvError::Empty)
                            | Err(std_mpsc::TryRecvError::Disconnected) => break,
                        }
                    }
                    if in_tx.is_closed() {
                        break; // RawSocket soltado: nadie escucha ya
                    }
                    let mut hdr: *mut PcapPkthdr = ptr::null_mut();
                    let mut data: *const u8 = ptr::null();
                    // SAFETY: handle vivo; hdr/data los rellena libpcap.
                    match unsafe { (api.next_ex)(handle, &mut hdr, &mut data) } {
                        1 => {
                            // SAFETY: con retorno 1, hdr y data apuntan a la
                            // trama capturada, válida hasta la próxima llamada.
                            let frame = unsafe {
                                std::slice::from_raw_parts(data, (*hdr).caplen as usize)
                            }
                            .to_vec();
                            // Cola llena: se descarta la trama (igual que un
                            // socket con buffer lleno); si está cerrada, salir.
                            if in_tx.try_send(frame).is_err() && in_tx.is_closed() {
                                break;
                            }
                        }
                        0 => continue, // timeout: vuelve a mirar envíos/cierre
                        _ => break,    // error o EOF del handle
                    }
                }
                // SAFETY: única llamada a close para este handle.
                unsafe { (api.close)(handle) };
            })
            .map_err(|e| L2Error::Io(std::io::Error::other(e.to_string())))?;

        Ok(Self {
            out_tx,
            in_rx: Mutex::new(in_rx),
        })
    }
}

impl L2Link for RawSocket {
    async fn send(&self, frame: &[u8]) -> Result<(), L2Error> {
        self.out_tx
            .send(frame.to_vec())
            .map_err(|_| L2Error::Io(std::io::Error::other("captura cerrada")))
    }

    async fn recv(&self) -> Result<Vec<u8>, L2Error> {
        self.in_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| L2Error::Io(std::io::Error::other("captura cerrada")))
    }
}

/// Lista los nombres de dispositivo de captura (`pcap_findalldevs`), tal como
/// los espera [`RawSocket::open`] (p. ej. `\Device\NPF_{GUID}`). Vacía si
/// Npcap no está instalado.
pub fn interfaces() -> Vec<String> {
    let Ok(api) = wpcap() else {
        return Vec::new();
    };
    let mut devs: *mut PcapIf = ptr::null_mut();
    let mut errbuf = [0 as c_char; ERRBUF];
    // SAFETY: punteros de salida válidos; la lista se libera con freealldevs.
    if unsafe { (api.findalldevs)(&mut devs, errbuf.as_mut_ptr()) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = devs;
    while !cur.is_null() {
        // SAFETY: cur apunta a un nodo válido de la lista enlazada de libpcap.
        unsafe {
            if !(*cur).name.is_null() {
                out.push(CStr::from_ptr((*cur).name).to_string_lossy().into_owned());
            }
            cur = (*cur).next;
        }
    }
    // SAFETY: devs proviene de findalldevs y no se ha liberado aún.
    unsafe { (api.freealldevs)(devs) };
    out.sort();
    out
}
