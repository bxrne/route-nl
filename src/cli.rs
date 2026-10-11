//! Command-line interface: `dump`, `default`, `set-gw`, `add`, `del`, `watch`, `tui`.
//!
//! Read-only commands (`dump`, `default`, `watch`) work for any user.
//! Mutations (`set-gw`, `add`, `del`) need root unless `--dry-run` is given,
//! in which case the planned netlink bytes are printed instead of sent.

use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};

/// Linux netlink client: dump the IPv4 table and adjust its gateway.
#[derive(Debug, Parser)]
#[command(author, version, about = "Linux netlink client: monitor and adjust gateways")]
pub struct Args {
    /// Subcommand to run.
    #[command(subcommand)]
    pub cmd: Commands,
}

/// All subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Dump the IPv4 routing table (`ip -4 route`).
    Dump {
        /// Emit JSON instead of human-readable lines.
        #[arg(long)]
        json: bool,
    },
    /// Show the current default gateway, if any.
    Default {
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Point the default route at a new gateway (keeps dev/metric by default).
    SetGw {
        /// New gateway address, e.g. `192.168.2.1`.
        gateway: Ipv4Addr,
        /// Output device name or index (default: keep the current one).
        #[arg(long)]
        dev: Option<String>,
        /// Metric override (default: keep the current one).
        #[arg(long)]
        metric: Option<u32>,
        /// Print the planned change without sending it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a route, failing if the prefix already exists.
    Add {
        /// Prefix: `default`, `0.0.0.0/0` or `ADDR/LEN`.
        #[arg(long)]
        prefix: String,
        /// Next-hop gateway.
        #[arg(long)]
        via: Option<Ipv4Addr>,
        /// Output device name or index.
        #[arg(long)]
        dev: Option<String>,
        /// Metric (`RTA_PRIORITY`).
        #[arg(long)]
        metric: Option<u32>,
        /// Print the planned change without sending it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Delete a route by prefix.
    Del {
        /// Prefix: `default`, `0.0.0.0/0` or `ADDR/LEN`.
        #[arg(long)]
        prefix: String,
        /// Narrow the match by output device (defaults to the route's own).
        #[arg(long)]
        dev: Option<String>,
        /// Narrow the match by metric (defaults to the route's own).
        #[arg(long)]
        metric: Option<u32>,
        /// Print the planned change without sending it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Poll the table and print on every change (Ctrl-C to stop).
    Watch {
        /// Seconds between dumps.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Open the interactive monitor/editor (Ratatui).
    Tui {
        /// Seconds between background refreshes.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
}
