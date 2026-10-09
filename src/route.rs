use std::net::Ipv4Addr;

use crate::attr::{Attr, AttrIter};
use crate::{align, DumpError, HDR, RTMSG};

/// Missing RTA_DST is default, not 0.0.0.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefix {
    Default { len: u8 },
    Network { addr: Ipv4Addr, len: u8 },
}

impl Prefix {
    pub fn from_parts(dst_len: u8, dst: Option<Ipv4Addr>) -> Self {
        match dst {
            Some(addr) => Prefix::Network { addr, len: dst_len },
            None => Prefix::Default { len: dst_len },
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Prefix::Default { len } => write!(f, "default/{len}"),
            Prefix::Network { addr, len } => write!(f, "{addr}/{len}"),
        }
    }
}

/// Absent attributes stay None. They are not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub prefix: Prefix,
    pub gateway: Option<Ipv4Addr>,
    pub oif: Option<u32>,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gw = self
            .gateway
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());
        let oif = self
            .oif
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
        write!(f, "{}\tvia {gw}\tdev {oif}", self.prefix)
    }
}

pub fn parse_route(msg: &[u8]) -> Result<Route, DumpError> {
    if msg.len() < HDR + RTMSG {
        return Err(DumpError::Truncated);
    }
    let dst_len = *msg.get(HDR + 1).ok_or(DumpError::Truncated)?;
    let attr_at = HDR + align(RTMSG);
    let attrs = msg.get(attr_at..).ok_or(DumpError::Truncated)?;
    let mut dst = None;
    let mut gateway = None;
    let mut oif = None;
    for attr in AttrIter::new(attrs) {
        match attr? {
            Attr::Dst(addr) => dst = Some(addr),
            Attr::Gateway(addr) => gateway = Some(addr),
            Attr::Oif(index) => oif = Some(index),
            Attr::Skip => {}
        }
    }
    Ok(Route {
        prefix: Prefix::from_parts(dst_len, dst),
        gateway,
        oif,
    })
}
