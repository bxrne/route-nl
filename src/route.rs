//! IPv4 route model: prefix, gateway, interface, metric.
//!
//! A missing `RTA_DST` means the default route, not `0.0.0.0/0` with an
//! address — [`Prefix::Default`] keeps that distinction. Absent gateway,
//! interface, metric and preferred-source attributes stay `None`; they are
//! not zero.

use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::attr::{Attr, AttrIter};
use crate::ifname::if_index_to_name;
use crate::socket::{align, DumpError, HDR, RTMSG};

/// Destination prefix: either default or a network address plus length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prefix {
    /// No `RTA_DST` was present (usually `dst_len == 0`).
    Default {
        /// Prefix length from `rtmsg` (0 for the default route).
        len: u8,
    },
    /// A concrete destination address plus length.
    Network {
        /// Destination address from `RTA_DST`.
        addr: Ipv4Addr,
        /// Prefix length from `rtmsg`.
        len: u8,
    },
}

impl Prefix {
    /// Combine `rtmsg` length with the optional `RTA_DST` address.
    pub fn from_parts(dst_len: u8, dst: Option<Ipv4Addr>) -> Self {
        match dst {
            Some(addr) => Prefix::Network { addr, len: dst_len },
            None => Prefix::Default { len: dst_len },
        }
    }

    /// Parse `default`, `0.0.0.0/0` or `ADDR/LEN`.
    pub fn parse(s: &str) -> Result<Self, DumpError> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("default") {
            return Ok(Prefix::Default { len: 0 });
        }
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| DumpError::InvalidArgument(format!("prefix {s:?} needs ADDR/LEN")))?;
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|_| DumpError::InvalidArgument(format!("bad IPv4 address {addr:?}")))?;
        let len: u8 = len
            .parse()
            .map_err(|_| DumpError::InvalidArgument(format!("bad prefix length in {s:?}")))?;
        if len > 32 {
            return Err(DumpError::InvalidArgument(format!(
                "prefix length {len} > 32"
            )));
        }
        if ip.is_unspecified() && len == 0 {
            return Ok(Prefix::Default { len: 0 });
        }
        Ok(Prefix::Network { addr: ip, len })
    }

    /// Prefix length from `rtmsg`.
    pub fn len(&self) -> u8 {
        match *self {
            Prefix::Default { len } => len,
            Prefix::Network { len, .. } => len,
        }
    }

    /// Destination address for `RTA_DST`, if any.
    pub fn addr(&self) -> Option<Ipv4Addr> {
        match *self {
            Prefix::Default { .. } => None,
            Prefix::Network { addr, .. } => Some(addr),
        }
    }

    /// True for the default route (`default/0` with no address).
    pub fn is_default(&self) -> bool {
        matches!(self, Prefix::Default { len: 0 })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Bare `default`, like `ip route`.
            Prefix::Default { len: 0 } => write!(f, "default"),
            Prefix::Default { len } => write!(f, "default/{len}"),
            Prefix::Network { addr, len } => write!(f, "{addr}/{len}"),
        }
    }
}

impl FromStr for Prefix {
    type Err = DumpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Prefix::parse(s)
    }
}

/// One IPv4 route row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Destination prefix.
    pub prefix: Prefix,
    /// Next-hop gateway (`RTA_GATEWAY`), if any.
    pub gateway: Option<Ipv4Addr>,
    /// Output interface index (`RTA_OIF`), if any.
    pub oif: Option<u32>,
    /// Metric (`RTA_PRIORITY`), if any.
    pub metric: Option<u32>,
    /// Preferred source (`RTA_PREFSRC`), if any.
    pub pref_src: Option<Ipv4Addr>,
}

impl Route {
    /// True for the `default/0` route.
    pub fn is_default(&self) -> bool {
        self.prefix.is_default()
    }

    /// Interface name via `if_indextoname`, if the index resolves.
    pub fn if_name(&self) -> Option<String> {
        self.oif.and_then(if_index_to_name)
    }

    /// Short `ip -4 route`-style rendering.
    pub fn summary(&self) -> String {
        let via = self
            .gateway
            .map(|a| format!("via {a}"))
            .unwrap_or_default();
        let dev = self
            .if_name()
            .or_else(|| self.oif.map(|n| n.to_string()))
            .map(|n| format!("dev {n}"))
            .unwrap_or_default();
        let metric = self
            .metric
            .map(|m| format!("metric {m}"))
            .unwrap_or_default();
        let src = self
            .pref_src
            .map(|s| format!("src {s}"))
            .unwrap_or_default();
        [self.prefix.to_string(), via, dev, metric, src]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Parse one `RTM_NEWROUTE` message (header + `rtmsg` + attributes).
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
    let mut metric = None;
    let mut pref_src = None;
    for attr in AttrIter::new(attrs) {
        match attr? {
            Attr::Dst(addr) => dst = Some(addr),
            Attr::Gateway(addr) => gateway = Some(addr),
            Attr::Oif(index) => oif = Some(index),
            Attr::Priority(m) => metric = Some(m),
            Attr::PrefSrc(addr) => pref_src = Some(addr),
            Attr::Skip => {}
        }
    }
    Ok(Route {
        prefix: Prefix::from_parts(dst_len, dst),
        gateway,
        oif,
        metric,
        pref_src,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parses_default_forms() {
        assert_eq!(Prefix::parse("default").unwrap(), Prefix::Default { len: 0 });
        assert_eq!(
            Prefix::parse("0.0.0.0/0").unwrap(),
            Prefix::Default { len: 0 }
        );
        assert_eq!(
            Prefix::parse("192.168.1.0/24").unwrap(),
            Prefix::Network {
                addr: Ipv4Addr::new(192, 168, 1, 0),
                len: 24,
            }
        );
    }

    #[test]
    fn prefix_rejects_bad_input() {
        assert!(Prefix::parse("nope").is_err());
        assert!(Prefix::parse("10.0.0.0/33").is_err());
        assert!(Prefix::parse("999.1.1.1/24").is_err());
    }

    #[test]
    fn summary_omits_missing_fields() {
        let r = Route {
            prefix: Prefix::Default { len: 0 },
            gateway: Some(Ipv4Addr::new(192, 168, 2, 254)),
            oif: Some(3),
            metric: Some(600),
            pref_src: None,
        };
        let s = r.summary();
        assert!(s.starts_with("default "));
        assert!(s.contains("via 192.168.2.254"));
        assert!(s.contains("metric 600"));
    }

    #[test]
    fn display_matches_summary() {
        let r = Route {
            prefix: Prefix::Network {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                len: 8,
            },
            gateway: None,
            oif: None,
            metric: None,
            pref_src: None,
        };
        assert_eq!(r.to_string(), "10.0.0.0/8");
    }
}
