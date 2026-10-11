//! Netlink route attributes (`RTA_*`).
//!
//! Each attribute is `struct rtattr { u16 len; u16 type; payload... }`,
//! padded to 4 bytes. Unknown types and unexpected payload lengths decode
//! to [`Attr::Skip`] so a dump keeps working when the kernel adds fields.

use std::net::Ipv4Addr;

use crate::socket::{
    align, ipv4_at, read_u16, read_u32, DumpError, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PREFSRC,
    RTA_PRIORITY,
};

/// A decoded route attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    /// Destination prefix address (`RTA_DST`).
    Dst(Ipv4Addr),
    /// Next-hop gateway (`RTA_GATEWAY`).
    Gateway(Ipv4Addr),
    /// Output interface index (`RTA_OIF`).
    Oif(u32),
    /// Metric (`RTA_PRIORITY`).
    Priority(u32),
    /// Preferred source address (`RTA_PREFSRC`).
    PrefSrc(Ipv4Addr),
    /// Unknown type or unexpected length; ignored by the caller.
    Skip,
}

/// Iterator over the attribute stream after `rtmsg`.
pub struct AttrIter<'a> {
    /// Remaining attribute bytes.
    pub buf: &'a [u8],
    /// Current offset into `buf`.
    pub off: usize,
    /// Set once a malformed attribute is seen; iteration stops after the error.
    pub failed: bool,
}

impl<'a> AttrIter<'a> {
    /// Iterate over `buf`, which must start at the first `rtattr`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            off: 0,
            failed: false,
        }
    }
}

impl Iterator for AttrIter<'_> {
    type Item = Result<Attr, DumpError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.off + 4 > self.buf.len() {
            return None;
        }
        let parsed = parse_one_attr(self);
        if parsed.is_err() {
            self.failed = true;
        }
        Some(parsed)
    }
}

/// Parse the attribute at the iterator cursor and advance past its padding.
fn parse_one_attr(it: &mut AttrIter<'_>) -> Result<Attr, DumpError> {
    let rlen = read_u16(it.buf, it.off)? as usize;
    if rlen < 4 || it.off + rlen > it.buf.len() {
        return Err(DumpError::Truncated);
    }
    let kind = read_u16(it.buf, it.off + 2)?;
    let payload = it
        .buf
        .get(it.off + 4..it.off + rlen)
        .ok_or(DumpError::Truncated)?;
    it.off = it
        .off
        .checked_add(align(rlen))
        .ok_or(DumpError::Truncated)?;
    decode_attr(kind, payload)
}

/// Decode one attribute payload; non-4-byte payloads are skipped.
fn decode_attr(kind: u16, payload: &[u8]) -> Result<Attr, DumpError> {
    if payload.len() != 4 {
        return Ok(Attr::Skip);
    }
    match kind {
        RTA_DST => Ok(Attr::Dst(ipv4_at(payload)?)),
        RTA_GATEWAY => Ok(Attr::Gateway(ipv4_at(payload)?)),
        RTA_OIF => Ok(Attr::Oif(read_u32(payload, 0)?)),
        RTA_PRIORITY => Ok(Attr::Priority(read_u32(payload, 0)?)),
        RTA_PREFSRC => Ok(Attr::PrefSrc(ipv4_at(payload)?)),
        _ => Ok(Attr::Skip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one `rtattr` with 4-byte payload.
    fn attr(kind: u16, payload: &[u8; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&8u16.to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn decodes_known_attrs() {
        let mut buf = Vec::new();
        buf.extend(attr(RTA_DST, &[10, 0, 0, 0]));
        buf.extend(attr(RTA_GATEWAY, &[10, 0, 0, 1]));
        buf.extend(attr(RTA_OIF, &2u32.to_ne_bytes()));
        buf.extend(attr(RTA_PRIORITY, &600u32.to_ne_bytes()));
        buf.extend(attr(RTA_PREFSRC, &[10, 0, 0, 5]));
        let got: Vec<_> = AttrIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(got.len(), 5);
    }

    #[test]
    fn skips_unknown_types() {
        let buf = attr(999, &[1, 2, 3, 4]);
        let got: Vec<_> = AttrIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(got, vec![Attr::Skip]);
    }

    #[test]
    fn rejects_truncated_attr() {
        let buf = [8u8, 0, 1, 0, 1, 2];
        let mut it = AttrIter::new(&buf);
        assert!(it.next().unwrap().is_err());
    }
}
