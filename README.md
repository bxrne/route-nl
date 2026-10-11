# route-nl

Linux netlink client. Dump the IPv4 table, watch it live, and adjust its gateway —
from the CLI or from an interactive Ratatui TUI.

## Run

```bash
cargo run -- dump                  # human-readable table (like `ip -4 route`)
cargo run -- dump --json            # JSON for scripts
cargo run -- default                # show the default gateway
cargo run -- watch                  # poll and print on change (Ctrl-C to stop)
cargo run -- tui                    # fullscreen monitor + gateway editor

# Mutations need root (or preview with --dry-run):
sudo cargo run -- set-gw 192.168.2.1
cargo run -- set-gw 192.168.2.1 --dry-run
sudo cargo run -- add --prefix 10.99.0.0/16 --via 10.99.0.1 --dev wlp5s0
sudo cargo run -- del --prefix 10.99.0.0/16   # narrows by live dev/metric
```

## TUI keys

| Key | Action |
| --- | ------ |
| `↑/↓` or `j/k` | select route |
| `e` / `g` | edit gateway of selected route |
| `d` | delete selected route (confirms) |
| `r` | refresh now |
| `q` / `Esc` | quit (in dialogs: cancel) |
| `Enter` | apply dialog |

`set-gw` and the TUI editor keep the current device, metric and preferred
source unless `--dev` / `--metric` override them — each flag is inherited
independently. `del` narrows by the live route's device/metric when `--dev`
/ `--metric` are omitted. Applying changes needs `CAP_NET_ADMIN`
(usually: run with `sudo`); without it you get a clear `need root` error
instead of a bare `EPERM`.

## Layout

- `src/socket.rs` — `AF_NETLINK` open/dump/ACK, readers, constants
- `src/attr.rs` — `RTA_*` attribute iterator (`DST`, `GATEWAY`, `OIF`, `PRIORITY`, `PREFSRC`)
- `src/route.rs` — `Prefix` / `Route` model, CIDR parsing, `ip`-style summary, serde
- `src/msg.rs` — per-message classification (`DONE` / `ACK` / `NEWROUTE` / ignore)
- `src/ifname.rs` — index ↔ name via `if_nametoindex` / `if_indextoname`
- `src/ops.rs` — `RTM_NEWROUTE` / `RTM_DELROUTE` encoders + `add`/`del`/`replace`/`set_default_gateway`
- `src/cli.rs` — clap command tree
- `src/tui.rs` — Ratatui monitor/editor
- `src/main.rs` — dispatch + `watch` loop

## Test

```bash
cargo test
```

28 unit tests cover alignment, readers, attributes, prefix parsing,
message encoding (incl. `PREFSRC` preservation and `del` narrowing),
`set-gw` per-field inheritance, and TUI cursor/edit validation.
The netlink oracle is `ip -4 route`: `dump` must show the same default
gateway/device/metric.
