//! Socket de capa 2 (`AF_PACKET`/`SOCK_RAW`) sobre Linux, vía `libc` envuelto en
//! `tokio::io::unix::AsyncFd`. Parametrizado por EtherType (GOOSE 0x88B8, SV
//! 0x88BA, …). Requiere `CAP_NET_RAW`/root.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::error::L2Error;
use crate::eth::MacAddr;
use crate::link::L2Link;

/// `ETH_P_ALL`: protocolo "todos" para capturar cualquier EtherType.
const ETH_P_ALL: u16 = 0x0003;

/// Cómo se afilia el socket para recibir tráfico de la interfaz.
enum Membership {
    /// Solo un grupo multicast concreto (el modo de un publicador/suscriptor).
    Multicast(MacAddr),
    /// Modo **promiscuo**: todas las tramas de la interfaz (sniffing pasivo).
    Promiscuous,
}

/// Socket de capa 2 sobre una interfaz Ethernet, filtrando por un EtherType.
pub struct RawSocket {
    inner: AsyncFd<OwnedFd>,
    recv_len: usize,
}

/// Tamaño del buffer de recepción para tráfico IEC 61850 (GOOSE/SV: ≤ MTU).
const FRAME_BUF: usize = 1522;
/// Buffer de recepción para captura general (incluye MMS/C-S sobre TCP).
const CAPTURE_BUF: usize = 65_536;

impl RawSocket {
    /// Abre el socket en `interface`, filtrando `ethertype` y uniéndose al grupo
    /// multicast `group` (modo publicador/suscriptor de un único flujo).
    pub fn open(interface: &str, ethertype: u16, group: MacAddr) -> Result<Self, L2Error> {
        Self::open_inner(
            interface,
            ethertype,
            Membership::Multicast(group),
            FRAME_BUF,
        )
    }

    /// Abre el socket en modo **promiscuo** filtrando un `ethertype`: recibe ese
    /// EtherType dirigido a **cualquier** MAC, no solo a un grupo multicast.
    ///
    /// Es lo que necesita un sniffer tipo IEDScout para ver **todos** los
    /// publicadores GOOSE/SV de la red, no solo los de un destino conocido (antes
    /// `open` solo se unía a un grupo, perdiendo el resto). Requiere
    /// `CAP_NET_RAW`.
    pub fn open_promiscuous(interface: &str, ethertype: u16) -> Result<Self, L2Error> {
        Self::open_inner(interface, ethertype, Membership::Promiscuous, FRAME_BUF)
    }

    /// Abre el socket capturando **todo** el tráfico de la interfaz (`ETH_P_ALL`,
    /// promiscuo): GOOSE, SV, MMS/C-S sobre TCP, ARP… Para volcar a PCAP el
    /// tráfico completo de la subestación. `recv` devuelve la trama Ethernet
    /// entera. Requiere `CAP_NET_RAW`.
    pub fn open_all(interface: &str) -> Result<Self, L2Error> {
        Self::open_inner(interface, ETH_P_ALL, Membership::Promiscuous, CAPTURE_BUF)
    }

    fn open_inner(
        interface: &str,
        ethertype: u16,
        membership: Membership,
        recv_len: usize,
    ) -> Result<Self, L2Error> {
        let proto = ethertype.to_be() as libc::c_int;
        // SAFETY: socket() es seguro; validamos el retorno.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                proto,
            )
        };
        if fd < 0 {
            return Err(map_os_error());
        }
        // SAFETY: fd recién creado y válido; OwnedFd lo cierra en Drop.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let cname = std::ffi::CString::new(interface)
            .map_err(|_| L2Error::Malformed("nombre de interfaz inválido".into()))?;
        // SAFETY: cname es un puntero C válido NUL-terminado.
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(L2Error::Io(io::Error::last_os_error()));
        }

        bind_interface(owned.as_raw_fd(), ifindex, ethertype)?;
        match membership {
            Membership::Multicast(group) => {
                add_multicast_membership(owned.as_raw_fd(), ifindex, group)?
            }
            Membership::Promiscuous => set_promiscuous(owned.as_raw_fd(), ifindex)?,
        }

        Ok(Self {
            inner: AsyncFd::new(owned)?,
            recv_len,
        })
    }
}

impl L2Link for RawSocket {
    async fn send(&self, frame: &[u8]) -> Result<(), L2Error> {
        self.inner
            .async_io(Interest::WRITABLE, |fd| {
                // SAFETY: fd válido durante la llamada; frame es un slice válido.
                let n = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        frame.as_ptr() as *const libc::c_void,
                        frame.len(),
                        0,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })
            .await
            .map_err(L2Error::Io)
    }

    async fn recv(&self) -> Result<Vec<u8>, L2Error> {
        let mut buf = vec![0u8; self.recv_len];
        let n = self
            .inner
            .async_io(Interest::READABLE, |fd| {
                // SAFETY: fd válido; buf es un buffer mutable válido.
                let n = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            })
            .await
            .map_err(L2Error::Io)?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn bind_interface(fd: i32, ifindex: u32, ethertype: u16) -> Result<(), L2Error> {
    // SAFETY: sockaddr_ll inicializado a cero y rellenado; bind valida el fd.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ethertype.to_be();
    sll.sll_ifindex = ifindex as i32;
    // SAFETY: sll vive en el stack durante la llamada y el tamaño pasado es el real.
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(map_os_error());
    }
    Ok(())
}

fn add_multicast_membership(fd: i32, ifindex: u32, group: MacAddr) -> Result<(), L2Error> {
    // SAFETY: packet_mreq inicializado a cero; setsockopt valida el fd.
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = libc::PACKET_MR_MULTICAST as u16;
    mreq.mr_alen = 6;
    mreq.mr_address[..6].copy_from_slice(&group);
    // SAFETY: mreq vive en el stack durante la llamada y el tamaño pasado es el real.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq as *const libc::packet_mreq as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(map_os_error());
    }
    Ok(())
}

fn set_promiscuous(fd: i32, ifindex: u32) -> Result<(), L2Error> {
    // PACKET_MR_PROMISC sin dirección: recibe todas las tramas de la interfaz.
    // SAFETY: packet_mreq inicializado a cero; setsockopt valida el fd.
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
    // SAFETY: mreq vive en el stack durante la llamada y el tamaño pasado es el real.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq as *const libc::packet_mreq as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(map_os_error());
    }
    Ok(())
}

fn map_os_error() -> L2Error {
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => L2Error::Permission,
        _ => L2Error::Io(e),
    }
}
