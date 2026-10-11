//! IPv4 route dump and update over `NETLINK_ROUTE`.
//!
//! A datagram holds one or more `nlmsghdr` values. A dump ends with
//! `NLMSG_DONE`. Route replies are `RTM_NEWROUTE`, not `RTM_GETROUTE`.
//! Destination, gateway, output-interface index, metric (`RTA_PRIORITY`)
//! and preferred source (`RTA_PREFSRC`) live in attributes after `rtmsg`.
//!
//! Oracle: `ip -4 route`. The interface column is an index. A missing gateway
//! is `None` and is omitted from the one-line summary (the TUI shows `-`).

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use thiserror::Error;

use crate::msg::{parse_msg, Msg};
use crate::route::Route;

/// Netlink alignment (4 bytes).
const ALIGN: usize = 4;
/// Receive buffer size per datagram.
const BUF: usize = 8192;
/// Upper bound on datagrams per dump, guards against endless streams.
const MAX_RECVS: usize = 64;
/// Size of `nlmsghdr`.
pub const HDR: usize = 16;
/// Size of `rtmsg`.
pub const RTMSG: usize = 12;

/// `nlmsg` flags.
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
/// `ROOT | MATCH`, i.e. a full dump.
pub const NLM_F_DUMP: u16 = 0x300;

/// `nlmsg` types.
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

/// Route attributes we care about.
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;

/// `rtmsg` well-known values (see `<linux/rtnetlink.h>`).
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RTN_UNICAST: u8 = 1;

/// Monotonic netlink sequence numbers.
static SEQ: AtomicU32 = AtomicU32::new(1);

/// Errors for dump and route mutation.
#[derive(Debug, Error)]
pub enum DumpError {
    /// `socket(AF_NETLINK)` failed.
    #[error("socket: {0}")]
    Socket(io::Error),
    /// `bind` failed.
    #[error("bind: {0}")]
    Bind(io::Error),
    /// `sendto` failed.
    #[error("send: {0}")]
    Send(io::Error),
    /// `recv` failed.
    #[error("recv: {0}")]
    Recv(io::Error),
    /// Kernel answered with a non-zero error.
    #[error("kernel: {0}")]
    Kernel(io::Error),
    /// A message was shorter than its header claims.
    #[error("truncated netlink message")]
    Truncated,
    /// Dump did not finish within the datagram budget.
    #[error("dump exceeded {MAX_RECVS} datagrams")]
    Unfinished,
    /// CLI argument did not parse (CIDR, IP, interface, ...).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Mutating routes needs root (`CAP_NET_ADMIN`).
    #[error("need root to change routes (run with sudo)")]
    NeedsRoot,
    /// No `default` route exists to replace.
    #[error("no default route found")]
    NoDefaultRoute,
    /// Named interface does not exist.
    #[error("unknown interface: {0}")]
    UnknownInterface(String),
    /// Terminal setup/rendering failed (the TUI needs a real TTY).
    #[error("terminal: {0}")]
    Terminal(io::Error),
}

/// Owned wrapper around a raw `AF_NETLINK` fd.
pub struct NlSocket(pub RawFd);

impl NlSocket {
    /// Open an unbound `AF_NETLINK` datagram socket.
    pub fn open() -> Result<Self, DumpError> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(DumpError::Socket(io::Error::last_os_error()));
        }
        Ok(NlSocket(fd))
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Round `n` up to the netlink alignment.
pub fn align(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// Next sequence number for an outgoing request.
pub fn next_seq() -> u32 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Read a native-endian `u16` at `buf[at..at+2]`.
pub fn read_u16(buf: &[u8], at: usize) -> Result<u16, DumpError> {
    let end = at.checked_add(2).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 2] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(u16::from_ne_bytes(*bytes))
}

/// Read a native-endian `u32` at `buf[at..at+4]`.
pub fn read_u32(buf: &[u8], at: usize) -> Result<u32, DumpError> {
    let end = at.checked_add(4).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 4] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(u32::from_ne_bytes(*bytes))
}

/// Read a native-endian `i32` at `buf[at..at+4]`.
pub fn read_i32(buf: &[u8], at: usize) -> Result<i32, DumpError> {
    let end = at.checked_add(4).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 4] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(i32::from_ne_bytes(*bytes))
}

/// Interpret exactly 4 bytes as an IPv4 address.
pub fn ipv4_at(buf: &[u8]) -> Result<Ipv4Addr, DumpError> {
    let bytes: &[u8; 4] = buf.try_into().map_err(|_| DumpError::Truncated)?;
    Ok(Ipv4Addr::from(*bytes))
}

/// Dump the IPv4 routing table, like `ip -4 route`.
pub fn dump(fd: RawFd) -> Result<Vec<Route>, DumpError> {
    bind_local(fd)?;
    send_bytes(fd, &encode_get_route())?;
    let mut buf = [0u8; BUF];
    let mut routes = Vec::new();
    for _ in 0..MAX_RECVS {
        let n = recv_into(fd, &mut buf)?;
        let (batch, done) = parse_datagram(buf.get(..n).ok_or(DumpError::Truncated)?)?;
        routes.extend(batch);
        if done {
            return Ok(routes);
        }
    }
    Err(DumpError::Unfinished)
}

/// Send `req` and wait for the kernel `NLMSG_ERROR` ACK.
///
/// A zero error code means success; anything else becomes [`DumpError::Kernel`].
pub fn transact_ack(fd: RawFd, req: &[u8]) -> Result<(), DumpError> {
    bind_local(fd)?;
    send_bytes(fd, req)?;
    let mut buf = [0u8; BUF];
    for _ in 0..MAX_RECVS {
        let n = recv_into(fd, &mut buf)?;
        let mut off = 0;
        let datagram = buf.get(..n).ok_or(DumpError::Truncated)?;
        while off + HDR <= datagram.len() {
            let rest = datagram.get(off..).ok_or(DumpError::Truncated)?;
            let len = read_u32(rest, 0)? as usize;
            if len < HDR || off + align(len) > datagram.len() {
                return Err(DumpError::Truncated);
            }
            match parse_msg(rest)? {
                Msg::Ack => return Ok(()),
                Msg::Ignore | Msg::Route(_) | Msg::Done => {}
            }
            off = off.checked_add(align(len)).ok_or(DumpError::Truncated)?;
        }
    }
    Err(DumpError::Unfinished)
}

/// Bind to the local (autobind) netlink address. Idempotent.
fn bind_local(fd: RawFd) -> Result<(), DumpError> {
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        // Autobind twice returns EINVAL; a socket that is already bound is fine.
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(DumpError::Bind(err));
        }
    }
    Ok(())
}

/// `sendto` a raw request to the kernel (`nl_pid = 0`).
fn send_bytes(fd: RawFd, req: &[u8]) -> Result<(), DumpError> {
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            fd,
            req.as_ptr().cast(),
            req.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if sent < 0 {
        return Err(DumpError::Send(io::Error::last_os_error()));
    }
    Ok(())
}

/// `recv` one datagram into `buf`, returning its length.
fn recv_into(fd: RawFd, buf: &mut [u8]) -> Result<usize, DumpError> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(DumpError::Recv(io::Error::last_os_error()));
    }
    usize::try_from(n).map_err(|_| DumpError::Truncated)
}

/// Encode `RTM_GETROUTE` with `NLM_F_DUMP` for IPv4.
fn encode_get_route() -> [u8; HDR + RTMSG] {
    let mut buf = [0u8; HDR + RTMSG];
    let len = (buf.len() as u32).to_ne_bytes();
    buf[0..4].copy_from_slice(&len);
    buf[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf[8..12].copy_from_slice(&next_seq().to_ne_bytes());
    buf[HDR] = libc::AF_INET as u8;
    buf
}

/// Split one datagram into routes; `true` once `NLMSG_DONE` is seen.
fn parse_datagram(buf: &[u8]) -> Result<(Vec<Route>, bool), DumpError> {
    let mut routes = Vec::new();
    let mut off = 0;
    while off + HDR <= buf.len() {
        let rest = buf.get(off..).ok_or(DumpError::Truncated)?;
        let len = read_u32(rest, 0)? as usize;
        let msg = parse_msg(rest)?;
        match msg {
            Msg::Done => return Ok((routes, true)),
            Msg::Route(route) => routes.push(route),
            Msg::Ack | Msg::Ignore => {}
        }
        off = off.checked_add(align(len)).ok_or(DumpError::Truncated)?;
    }
    Ok((routes, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_to_four() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
        assert_eq!(align(28), 28);
    }

    #[test]
    fn readers_reject_short_buffers() {
        assert!(read_u16(&[1], 0).is_err());
        assert!(read_u32(&[1, 2, 3], 0).is_err());
        assert!(read_i32(&[], 0).is_err());
        assert!(ipv4_at(&[1, 2, 3]).is_err());
    }

    #[test]
    fn readers_use_native_endian() {
        let v = 0x1234u16.to_ne_bytes();
        assert_eq!(read_u16(&v, 0).unwrap(), 0x1234);
        let w = 0xdead_beefu32.to_ne_bytes();
        assert_eq!(read_u32(&w, 0).unwrap(), 0xdead_beef);
    }

    #[test]
    fn seq_increases() {
        let a = next_seq();
        let b = next_seq();
        assert_eq!(b, a + 1);
    }
}
