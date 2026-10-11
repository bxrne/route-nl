//! Route mutations: add, delete, replace, and set the default gateway.
//!
//! Reads go through [`crate::socket::dump`]; writes build `RTM_NEWROUTE` /
//! `RTM_DELROUTE` requests and wait for the kernel ACK via
//! [`crate::socket::transact_ack`]. Everything here is IPv4 (`AF_INET`)
//! on `RT_TABLE_MAIN`.
//!
//! Mutations need `CAP_NET_ADMIN` — usually root. Use `dry_run` (or the
//! `--dry-run` flag) to preview the bytes without touching the table.

use std::net::Ipv4Addr;

use crate::ifname::if_name_to_index;
use crate::route::{Prefix, Route};
use crate::socket::{
    next_seq, transact_ack, DumpError, HDR, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTM_DELROUTE,
    RTM_NEWROUTE, RTN_UNICAST, RTPROT_BOOT, RTPROT_STATIC, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};
use crate::socket::{NlSocket, RTMSG, dump};

/// What a mutation *would* do (used by `--dry-run` and the TUI preview).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedOp {
    /// Human description, e.g. `replace default/0 via 192.168.2.1 dev wlp5s0`.
    pub summary: String,
    /// Raw netlink request bytes that would be sent.
    pub bytes: Vec<u8>,
}

/// True when running as root (`euid == 0`).
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Require root before mutating the table.
fn require_root() -> Result<(), DumpError> {
    if is_root() {
        Ok(())
    } else {
        Err(DumpError::NeedsRoot)
    }
}

/// Fetch the current default (`default/0`) route, if any.
pub fn current_default() -> Result<Option<Route>, DumpError> {
    let sock = NlSocket::open()?;
    let routes = dump(sock.0)?;
    Ok(routes.into_iter().find(|r| r.is_default()))
}

/// Resolve `--dev NAME` to an index, passing through explicit indexes.
pub fn resolve_oif(dev: Option<&str>) -> Result<Option<u32>, DumpError> {
    match dev {
        None => Ok(None),
        Some(name) => {
            if let Ok(idx) = name.parse::<u32>() {
                return Ok(Some(idx));
            }
            Ok(Some(if_name_to_index(name)?))
        }
    }
}

/// Append one `rtattr` (header + payload, padded) to `buf`.
fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let start = buf.len();
    let len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(payload);
    while (buf.len() - start) % 4 != 0 {
        buf.push(0);
    }
}

/// Shared `nlmsghdr + rtmsg` prefix for route requests.
fn msg_prefix(buf: &mut Vec<u8>, nl_type: u16, flags: u16, dst_len: u8, table: u8, proto: u8) {
    // Reserve room for nlmsg_len, filled in by `finish_msg`.
    let hdr_at = buf.len();
    buf.extend_from_slice(&[0u8; HDR]);
    let rt_at = buf.len();
    buf.extend_from_slice(&[0u8; RTMSG]);
    // nlmsg header (len patched later).
    buf[hdr_at + 4..hdr_at + 6].copy_from_slice(&nl_type.to_ne_bytes());
    buf[hdr_at + 6..hdr_at + 8].copy_from_slice(&flags.to_ne_bytes());
    buf[hdr_at + 8..hdr_at + 12].copy_from_slice(&next_seq().to_ne_bytes());
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
    buf[rt_at] = libc::AF_INET as u8;
    buf[rt_at + 1] = dst_len;
    buf[rt_at + 4] = table;
    buf[rt_at + 5] = proto;
    buf[rt_at + 6] = RT_SCOPE_UNIVERSE;
    buf[rt_at + 7] = RTN_UNICAST;
}

/// Patch the leading `nlmsg_len` once the message is complete.
fn finish_msg(buf: &mut Vec<u8>) {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
}

/// Encode `RTM_NEWROUTE` with `CREATE | REPLACE` (upsert semantics).
pub fn encode_replace(
    prefix: &Prefix,
    gateway: Option<Ipv4Addr>,
    oif: Option<u32>,
    metric: Option<u32>,
    pref_src: Option<Ipv4Addr>,
) -> Vec<u8> {
    encode_newroute(
        prefix,
        gateway,
        oif,
        metric,
        pref_src,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        RTPROT_BOOT,
    )
}

/// Encode `RTM_NEWROUTE` with `CREATE | EXCL` (fail if the route exists).
pub fn encode_add(
    prefix: &Prefix,
    gateway: Option<Ipv4Addr>,
    oif: Option<u32>,
    metric: Option<u32>,
    pref_src: Option<Ipv4Addr>,
) -> Vec<u8> {
    encode_newroute(
        prefix,
        gateway,
        oif,
        metric,
        pref_src,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        RTPROT_STATIC,
    )
}
/// Encode `RTM_DELROUTE` for `prefix`, narrowed by `oif`/`metric` when given.
pub fn encode_del(prefix: &Prefix, oif: Option<u32>, metric: Option<u32>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HDR + RTMSG + 32);
    msg_prefix(
        &mut buf,
        RTM_DELROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        prefix.len(),
        RT_TABLE_MAIN,
        RTPROT_BOOT,
    );
    if let Some(dst) = prefix.addr() {
        push_attr(&mut buf, RTA_DST, &dst.octets());
    }
    if let Some(idx) = oif {
        push_attr(&mut buf, RTA_OIF, &idx.to_ne_bytes());
    }
    if let Some(m) = metric {
        push_attr(&mut buf, RTA_PRIORITY, &m.to_ne_bytes());
    }
    finish_msg(&mut buf);
    buf
}

/// Shared `RTM_NEWROUTE` encoder.
fn encode_newroute(
    prefix: &Prefix,
    gateway: Option<Ipv4Addr>,
    oif: Option<u32>,
    metric: Option<u32>,
    pref_src: Option<Ipv4Addr>,
    flags: u16,
    proto: u8,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HDR + RTMSG + 48);
    msg_prefix(
        &mut buf,
        RTM_NEWROUTE,
        flags,
        prefix.len(),
        RT_TABLE_MAIN,
        proto,
    );
    if let Some(dst) = prefix.addr() {
        push_attr(&mut buf, RTA_DST, &dst.octets());
    }
    if let Some(gw) = gateway {
        push_attr(&mut buf, RTA_GATEWAY, &gw.octets());
    }
    if let Some(idx) = oif {
        push_attr(&mut buf, RTA_OIF, &idx.to_ne_bytes());
    }
    if let Some(m) = metric {
        push_attr(&mut buf, RTA_PRIORITY, &m.to_ne_bytes());
    }
    if let Some(src) = pref_src {
        push_attr(&mut buf, RTA_PREFSRC, &src.octets());
    }
    finish_msg(&mut buf);
    buf
}

/// Replace (upsert) `prefix`. Set `dry_run` to only build the bytes.
pub fn replace_route(
    prefix: &Prefix,
    gateway: Option<Ipv4Addr>,
    oif: Option<u32>,
    metric: Option<u32>,
    pref_src: Option<Ipv4Addr>,
    dry_run: bool,
) -> Result<PlannedOp, DumpError> {
    let bytes = encode_replace(prefix, gateway, oif, metric, pref_src);
    let summary = format!(
        "replace {} {}",
        prefix,
        describe_attrs(gateway, oif, metric)
    );
    if dry_run {
        return Ok(PlannedOp {
            summary,
            bytes,
        });
    }
    require_root()?;
    let sock = NlSocket::open()?;
    transact_ack(sock.0, &bytes)?;
    Ok(PlannedOp { summary, bytes })
}

/// Add `prefix`, failing if it already exists.
pub fn add_route(
    prefix: &Prefix,
    gateway: Option<Ipv4Addr>,
    oif: Option<u32>,
    metric: Option<u32>,
    pref_src: Option<Ipv4Addr>,
    dry_run: bool,
) -> Result<PlannedOp, DumpError> {
    let bytes = encode_add(prefix, gateway, oif, metric, pref_src);
    let summary = format!("add {} {}", prefix, describe_attrs(gateway, oif, metric));
    if dry_run {
        return Ok(PlannedOp { summary, bytes });
    }
    require_root()?;
    let sock = NlSocket::open()?;
    transact_ack(sock.0, &bytes)?;
    Ok(PlannedOp { summary, bytes })
}

/// Delete `prefix`, narrowed by `oif`/`metric` when given.
///
/// Passing the route's own `oif`/`metric` avoids hitting a sibling route
/// when several entries share a prefix (multipath / metrics).
pub fn del_route(
    prefix: &Prefix,
    oif: Option<u32>,
    metric: Option<u32>,
    dry_run: bool,
) -> Result<PlannedOp, DumpError> {
    let bytes = encode_del(prefix, oif, metric);
    let summary = format!("delete {prefix}");
    if dry_run {
        return Ok(PlannedOp { summary, bytes });
    }
    require_root()?;
    let sock = NlSocket::open()?;
    transact_ack(sock.0, &bytes)?;
    Ok(PlannedOp { summary, bytes })
}

/// Point the default route at `gateway`, keeping the current device, metric
/// and preferred source unless overridden. This is the "adjust the gateway
/// stuff" entry point used by both `set-gw` and the TUI editor.
///
/// Each of `--dev` / `--metric` is inherited independently: passing only one
/// keeps the other from the live default route.
pub fn set_default_gateway(
    gateway: Ipv4Addr,
    dev: Option<&str>,
    metric: Option<u32>,
    dry_run: bool,
) -> Result<PlannedOp, DumpError> {
    let oif = resolve_oif(dev)?;
    // In dry-run there may be no default route (CI containers); still
    // produce a preview instead of erroring with NoDefaultRoute.
    let current = match current_default() {
        Ok(d) => d,
        Err(e) if dry_run => {
            let _ = e;
            None
        }
        Err(e) => return Err(e),
    };
    let oif = oif.or_else(|| current.as_ref().and_then(|r| r.oif));
    let metric = metric.or_else(|| current.as_ref().and_then(|r| r.metric));
    let pref_src = current.as_ref().and_then(|r| r.pref_src);
    if !dry_run && current.is_none() && oif.is_none() {
        // No live default and no --dev pinned: we cannot know the device,
        // and creating a dev-less default is almost never what is wanted.
        return Err(DumpError::NoDefaultRoute);
    }
    let prefix = Prefix::Default { len: 0 };
    let bytes = encode_replace(&prefix, Some(gateway), oif, metric, pref_src);
    let summary = format!(
        "replace {} {}",
        prefix,
        describe_attrs(Some(gateway), oif, metric)
    );
    if dry_run {
        return Ok(PlannedOp { summary, bytes });
    }
    require_root()?;
    let sock = NlSocket::open()?;
    transact_ack(sock.0, &bytes)?;
    Ok(PlannedOp { summary, bytes })
}

/// Render `via X dev Y metric Z` for summaries and dry-run output.
fn describe_attrs(gateway: Option<Ipv4Addr>, oif: Option<u32>, metric: Option<u32>) -> String {
    let mut parts = Vec::new();
    if let Some(gw) = gateway {
        parts.push(format!("via {gw}"));
    }
    if let Some(idx) = oif {
        parts.push(format!("dev {idx}"));
    }
    if let Some(m) = metric {
        parts.push(format!("metric {m}"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::{read_u16, read_u32, HDR, RTM_DELROUTE, RTM_NEWROUTE};

    fn nl_type(bytes: &[u8]) -> u16 {
        read_u16(bytes, 4).unwrap()
    }

    #[test]
    fn replace_has_create_replace_flags() {
        let bytes = encode_replace(&Prefix::Default { len: 0 }, None, None, None, None);
        let flags = read_u16(&bytes, 6).unwrap();
        assert_eq!(nl_type(&bytes), RTM_NEWROUTE);
        assert_ne!(flags & (NLM_F_CREATE | NLM_F_REPLACE), 0);
        let len = read_u32(&bytes, 0).unwrap() as usize;
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn del_targets_prefix() {
        let prefix = Prefix::parse("10.0.0.0/8").unwrap();
        let bytes = encode_del(&prefix, None, None);
        assert_eq!(nl_type(&bytes), RTM_DELROUTE);
        assert_eq!(bytes[HDR + 1], 8);
    }

    #[test]
    fn dry_run_needs_no_root() {
        let op = replace_route(
            &Prefix::Default { len: 0 },
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            Some(2),
            None,
            None,
            true,
        )
        .unwrap();
        assert!(op.summary.contains("192.168.1.1"));
        assert!(!op.bytes.is_empty());
    }

    #[test]
    fn set_gateway_dry_run_inherits_or_previews() {
        let op = set_default_gateway(Ipv4Addr::new(10, 0, 0, 1), None, None, true).unwrap();
        assert!(op.summary.contains("10.0.0.1"));
    }

    #[test]
    fn set_gateway_partial_override_keeps_other_field() {
        // --dev alone must not drop the live metric and vice versa.
        let live = current_default().ok().flatten();
        let Some(live) = live else {
            return;
        };
        let op = set_default_gateway(Ipv4Addr::new(10, 0, 0, 9), Some("lo"), None, true).unwrap();
        assert!(op.summary.contains("10.0.0.9"));
        if live.metric.is_some() {
            assert!(op.summary.contains("metric"));
        }
    }

    #[test]
    fn delete_carries_oif_metric() {
        let prefix = Prefix::parse("10.0.0.0/8").unwrap();
        let op = del_route(&prefix, Some(2), Some(100), true).unwrap();
        // DST(8) + OIF(8) + PRIO(8) over the 28-byte header.
        assert_eq!(op.bytes.len(), 28 + 8 + 8 + 8);
    }

    #[test]
    fn resolve_numeric_dev() {
        assert_eq!(resolve_oif(Some("7")).unwrap(), Some(7));
        assert_eq!(resolve_oif(None).unwrap(), None);
    }
}
