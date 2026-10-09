use std::net::Ipv4Addr;

use crate::socket::{align, ipv4_at, read_u16, read_u32, DumpError, RTA_DST, RTA_GATEWAY, RTA_OIF};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    Dst(Ipv4Addr),
    Gateway(Ipv4Addr),
    Oif(u32),
    Skip,
}

pub struct AttrIter<'a> {
    pub buf: &'a [u8],
    pub off: usize,
    pub failed: bool,
}

impl<'a> AttrIter<'a> {
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
    it.off = it.off.checked_add(align(rlen)).ok_or(DumpError::Truncated)?;
    decode_attr(kind, payload)
}

fn decode_attr(kind: u16, payload: &[u8]) -> Result<Attr, DumpError> {
    if payload.len() != 4 {
        return Ok(Attr::Skip);
    }
    match kind {
        RTA_DST => Ok(Attr::Dst(ipv4_at(payload)?)),
        RTA_GATEWAY => Ok(Attr::Gateway(ipv4_at(payload)?)),
        RTA_OIF => Ok(Attr::Oif(read_u32(payload, 0)?)),
        _ => Ok(Attr::Skip),
    }
}
