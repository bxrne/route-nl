//! Single netlink message classification.
//!
//! A datagram is a run of `nlmsghdr` frames. This module looks at the type
//! field and routes each frame: `NLMSG_DONE` ends a dump, `NLMSG_ERROR`
//! is an ACK (zero) or a kernel error (non-zero), `RTM_NEWROUTE` carries a
//! [`Route`](crate::route::Route), and anything else is ignored.

use std::io;

use crate::route::{parse_route, Route};
use crate::socket::{read_i32, read_u16, read_u32, DumpError, HDR, NLMSG_DONE, NLMSG_ERROR, RTM_NEWROUTE};

/// One classified netlink message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// `NLMSG_DONE`: the dump is complete.
    Done,
    /// `NLMSG_ERROR` with code 0: the kernel accepted the request.
    Ack,
    /// `RTM_NEWROUTE`: one routing-table row.
    Route(Route),
    /// Any other type: safely ignored.
    Ignore,
}

/// Classify the first message in `buf` (which may hold trailing messages).
///
/// `buf[0..4]` is the message length; only those bytes are inspected.
pub fn parse_msg(buf: &[u8]) -> Result<Msg, DumpError> {
    let len = read_u32(buf, 0)? as usize;
    if len < HDR || len > buf.len() {
        return Err(DumpError::Truncated);
    }
    let msg = buf.get(..len).ok_or(DumpError::Truncated)?;
    match read_u16(msg, 4)? {
        NLMSG_DONE => Ok(Msg::Done),
        NLMSG_ERROR => parse_error(msg),
        RTM_NEWROUTE => Ok(Msg::Route(parse_route(msg)?)),
        _ => Ok(Msg::Ignore),
    }
}

/// Decode `NLMSG_ERROR`: zero means ACK, otherwise a negated errno.
fn parse_error(msg: &[u8]) -> Result<Msg, DumpError> {
    let err = read_i32(msg, HDR)?;
    if err == 0 {
        return Ok(Msg::Ack);
    }
    Err(DumpError::Kernel(io::Error::from_raw_os_error(-err)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::RTM_NEWROUTE as NEW;

    /// Build a minimal `nlmsghdr` with the given type and length.
    fn hdr(nl_type: u16, len: u32) -> Vec<u8> {
        let mut v = vec![0u8; HDR.max(len as usize)];
        v[0..4].copy_from_slice(&len.to_ne_bytes());
        v[4..6].copy_from_slice(&nl_type.to_ne_bytes());
        v
    }

    #[test]
    fn done_is_done() {
        assert_eq!(parse_msg(&hdr(NLMSG_DONE, HDR as u32)).unwrap(), Msg::Done);
    }

    #[test]
    fn unknown_types_are_ignored() {
        assert_eq!(parse_msg(&hdr(0x1234, HDR as u32)).unwrap(), Msg::Ignore);
    }

    #[test]
    fn ack_is_zero_error() {
        let mut v = hdr(NLMSG_ERROR, (HDR + 4) as u32);
        v[HDR..HDR + 4].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(parse_msg(&v).unwrap(), Msg::Ack);
    }

    #[test]
    fn nonzero_error_surfaces() {
        let mut v = hdr(NLMSG_ERROR, (HDR + 4) as u32);
        v[HDR..HDR + 4].copy_from_slice(&(-13i32).to_ne_bytes());
        assert!(parse_msg(&v).is_err());
    }

    #[test]
    fn short_len_rejected() {
        assert!(parse_msg(&hdr(NEW, 4)).is_err());
    }
}
