//! IPv4 route dump over NETLINK_ROUTE.
//!
//! A datagram holds one or more nlmsghdr values. A dump ends with NLMSG_DONE.
//! Route replies are RTM_NEWROUTE, not RTM_GETROUTE. Destination, gateway, and
//! interface index live in attributes after rtmsg.
//!
//! Oracle: `ip -4 route`. The interface column is an index. A missing gateway
//! is None and prints as `-`.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use thiserror::Error;

use crate::msg::{parse_msg, Msg};
use crate::route::Route;

const ALIGN: usize = 4;
const BUF: usize = 8192;
const MAX_RECVS: usize = 64;
pub const HDR: usize = 16;
pub const RTMSG: usize = 12;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;

#[derive(Debug, Error)]
pub enum DumpError {
    #[error("socket: {0}")]
    Socket(io::Error),
    #[error("bind: {0}")]
    Bind(io::Error),
    #[error("send: {0}")]
    Send(io::Error),
    #[error("recv: {0}")]
    Recv(io::Error),
    #[error("kernel: {0}")]
    Kernel(io::Error),
    #[error("truncated netlink message")]
    Truncated,
    #[error("dump exceeded {MAX_RECVS} datagrams")]
    Unfinished,
}

pub struct NlSocket(pub RawFd);

impl NlSocket {
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

pub fn align(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

pub fn read_u16(buf: &[u8], at: usize) -> Result<u16, DumpError> {
    let end = at.checked_add(2).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 2] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(u16::from_ne_bytes(*bytes))
}

pub fn read_u32(buf: &[u8], at: usize) -> Result<u32, DumpError> {
    let end = at.checked_add(4).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 4] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(u32::from_ne_bytes(*bytes))
}

pub fn read_i32(buf: &[u8], at: usize) -> Result<i32, DumpError> {
    let end = at.checked_add(4).ok_or(DumpError::Truncated)?;
    let bytes: &[u8; 4] = buf
        .get(at..end)
        .ok_or(DumpError::Truncated)?
        .try_into()
        .map_err(|_| DumpError::Truncated)?;
    Ok(i32::from_ne_bytes(*bytes))
}

pub fn ipv4_at(buf: &[u8]) -> Result<Ipv4Addr, DumpError> {
    let bytes: &[u8; 4] = buf.try_into().map_err(|_| DumpError::Truncated)?;
    Ok(Ipv4Addr::from(*bytes))
}



pub fn dump(fd: RawFd) -> Result<Vec<Route>, DumpError> {
    bind_local(fd)?;
    send_get_route(fd)?;
    let mut buf = [0u8; BUF];
    let mut routes = Vec::new();
    for _ in 0..MAX_RECVS {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(DumpError::Recv(io::Error::last_os_error()));
        }
        let n = usize::try_from(n).map_err(|_| DumpError::Truncated)?;
        let (batch, done) = parse_datagram(buf.get(..n).ok_or(DumpError::Truncated)?)?;
        routes.extend(batch);
        if done {
            return Ok(routes);
        }
    }
    Err(DumpError::Unfinished)
}

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
        return Err(DumpError::Bind(io::Error::last_os_error()));
    }
    Ok(())
}

fn send_get_route(fd: RawFd) -> Result<(), DumpError> {
    let req = encode_get_route();
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

fn encode_get_route() -> [u8; HDR + RTMSG] {
    let mut buf = [0u8; HDR + RTMSG];
    let len = (buf.len() as u32).to_ne_bytes();
    buf[0..4].copy_from_slice(&len);
    buf[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
    buf[HDR] = libc::AF_INET as u8;
    buf
}

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
