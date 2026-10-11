//! `route-nl`: dump the IPv4 table and adjust its gateway.
//!
//! Read-only commands work for everyone; mutations need root (or `--dry-run`).
//! The `tui` subcommand opens the interactive Ratatui monitor/editor.

pub mod attr;
pub mod cli;
pub mod ifname;
pub mod msg;
pub mod ops;
pub mod route;
pub mod socket;
pub mod tui;

use std::io::Write;
use std::time::Duration;

use clap::Parser;

use cli::{Args, Commands};
use socket::{dump, DumpError, NlSocket};

/// Entry point: parse args, dispatch, and report errors without panicking.
fn run() -> Result<(), DumpError> {
    let args = Args::parse();
    match args.cmd {
        Commands::Dump { json } => cmd_dump(json),
        Commands::Default { json } => cmd_default(json),
        Commands::SetGw {
            gateway,
            dev,
            metric,
            dry_run,
        } => {
            let op = ops::set_default_gateway(gateway, dev.as_deref(), metric, dry_run)?;
            println!("{}", op.summary);
            if dry_run {
                println!("dry-run: {} bytes, not sent", op.bytes.len());
            }
            Ok(())
        }
        Commands::Add {
            prefix,
            via,
            dev,
            metric,
            dry_run,
        } => {
            let prefix = route::Prefix::parse(&prefix)?;
            if via.is_none() && dev.is_none() {
                return Err(DumpError::InvalidArgument(
                    "add needs --via and/or --dev".to_string(),
                ));
            }
            let oif = ops::resolve_oif(dev.as_deref())?;
            let op = ops::add_route(&prefix, via, oif, metric, None, dry_run)?;
            println!("{}", op.summary);
            if dry_run {
                println!("dry-run: {} bytes, not sent", op.bytes.len());
            }
            Ok(())
        }
        Commands::Del {
            prefix,
            dev,
            metric,
            dry_run,
        } => {
            let prefix = route::Prefix::parse(&prefix)?;
            // Default to the live route's own device/metric so the delete
            // hits the exact entry shown by `dump`, even when the caller
            // only names the prefix.
            let (oif, metric) = match ops::resolve_oif(dev.as_deref())? {
                explicit @ Some(_) => (explicit, metric),
                None => match NlSocket::open()
                    .ok()
                    .and_then(|s| dump(s.0).ok())
                    .and_then(|routes| routes.into_iter().find(|r| r.prefix == prefix))
                {
                    Some(live) => (live.oif, metric.or(live.metric)),
                    None => (None, metric),
                },
            };
            let op = ops::del_route(&prefix, oif, metric, dry_run)?;
            println!("{}", op.summary);
            if dry_run {
                println!("dry-run: {} bytes, not sent", op.bytes.len());
            }
            Ok(())
        }
        Commands::Watch { interval } => cmd_watch(interval),
        Commands::Tui { interval } => tui::run(interval),
    }
}

/// Print every route, either human-readable or as JSON.
fn cmd_dump(json: bool) -> Result<(), DumpError> {
    let sock = NlSocket::open()?;
    let routes = dump(sock.0)?;
    if json {
        let text = serde_json::to_string_pretty(&routes)
            .map_err(|e| DumpError::InvalidArgument(format!("json: {e}")))?;
        println!("{text}");
    } else {
        for route in &routes {
            println!("{route}");
        }
    }
    Ok(())
}

/// Print just the default route (or a friendly "none" message).
fn cmd_default(json: bool) -> Result<(), DumpError> {
    let def = ops::current_default()?;
    if json {
        let text = serde_json::to_string_pretty(&def)
            .map_err(|e| DumpError::InvalidArgument(format!("json: {e}")))?;
        println!("{text}");
        return Ok(());
    }
    match def {
        Some(route) => println!("{route}"),
        None => println!("no default route"),
    }
    Ok(())
}

/// Poll the table and print a fresh snapshot whenever it changes.
///
/// Reuses one socket across polls; a transient failure is reported to
/// stderr and retried instead of aborting the watch.
/// Runs until Ctrl-C (SIGINT) terminates the process.
fn cmd_watch(interval: u64) -> Result<(), DumpError> {
    let every = Duration::from_secs(interval.max(1));
    let sock = NlSocket::open()?;
    let mut previous: Vec<route::Route> = Vec::new();
    let mut first = true;
    loop {
        match dump(sock.0) {
            Ok(routes) => {
                if first || routes != previous {
                    print_snapshot(&routes);
                    previous = routes;
                    first = false;
                }
            }
            Err(e) => eprintln!("route-nl watch: refresh failed: {e}"),
        }
        std::thread::sleep(every);
    }
}

/// Print one timestamped snapshot for `watch`.
fn print_snapshot(routes: &[route::Route]) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("--- {secs} ({} routes) ---", routes.len());
    for route in routes {
        println!("{route}");
    }
    let _ = std::io::stdout().flush();
}

fn main() {
    if let Err(err) = run() {
        eprintln!("route-nl error: {err}");
        std::process::exit(1);
    }
}
