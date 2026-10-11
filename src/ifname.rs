//! Interface-index helpers built on `libc`.
//!
//! The routing table stores interfaces as numeric indexes (`RTA_OIF`).
//! These helpers translate between names (`wlp5s0`) and indexes so the CLI
//! accepts `--dev NAME` while netlink speaks numbers.

use std::ffi::{CStr, CString};

use crate::socket::DumpError;

/// Buffer for `if_indextoname` (sized by `IFNAMSIZ`).
const IFNAME_BUF: usize = libc::IFNAMSIZ as usize;

/// Resolve `name` (e.g. `wlp5s0`) to its kernel interface index.
///
/// Returns [`DumpError::UnknownInterface`] when the name does not exist.
pub fn if_name_to_index(name: &str) -> Result<u32, DumpError> {
    let c = CString::new(name)
        .map_err(|_| DumpError::InvalidArgument(format!("bad interface name {name:?}")))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(DumpError::UnknownInterface(name.to_string()));
    }
    Ok(idx)
}

/// Resolve an interface index back to its name, if it still exists.
pub fn if_index_to_name(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; IFNAME_BUF];
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if name.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

/// List `(index, name)` for every local interface via `/sys/class/net`.
///
/// Falls back to an empty list when sysfs is unavailable (e.g. tests).
pub fn all_interfaces() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(idx) = if_name_to_index(&name) {
            out.push((idx, name));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves() {
        let idx = if_name_to_index("lo").unwrap();
        assert!(idx > 0);
        assert_eq!(if_index_to_name(idx).as_deref(), Some("lo"));
    }

    #[test]
    fn unknown_name_errors() {
        assert!(matches!(
            if_name_to_index("route-nl-definitely-missing-0"),
            Err(DumpError::UnknownInterface(_))
        ));
    }

    #[test]
    fn unknown_index_returns_none() {
        assert_eq!(if_index_to_name(u32::MAX), None);
    }
}
