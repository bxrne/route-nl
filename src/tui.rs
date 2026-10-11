//! Interactive gateway monitor/editor built on Ratatui.
//!
//! Shows the IPv4 table live, highlights the default route, and lets the
//! user point it at a new gateway without leaving the terminal.
//!
//! Keys: `↑/↓` or `j/k` select, `e` edit gateway, `d` delete route,
//! `r` refresh, `q`/`Esc` quit. While editing: `Enter` applies,
//! `Esc` cancels.

use std::io::{self, Stdout};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};

use crate::ops::replace_route;
use crate::route::Route;
use crate::socket::{dump, DumpError, NlSocket};

/// Which input mode the TUI is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    /// Navigating the table.
    #[default]
    Normal,
    /// Typing a new gateway address.
    Editing,
    /// Confirming deletion of the selected route.
    ConfirmDelete,
}

/// Live application state.
struct App {
    /// Current table rows.
    routes: Vec<Route>,
    /// Table selection cursor.
    state: TableState,
    /// Status / error line shown in the footer.
    status: String,
    /// Input mode.
    mode: Mode,
    /// Gateway text being typed in the editor.
    input: String,
    /// Seconds between background refreshes.
    interval: u64,
    /// Last successful refresh.
    last_refresh: Instant,
}

impl App {
    /// Load the table once; failures become the status line, not a crash.
    fn new(interval: u64) -> Self {
        let mut app = Self {
            routes: Vec::new(),
            state: TableState::default(),
            status: String::new(),
            mode: Mode::Normal,
            input: String::new(),
            interval,
            last_refresh: Instant::now(),
        };
        app.refresh();
        if !app.routes.is_empty() {
            app.state.select(Some(0));
        }
        app
    }

    /// Re-dump the table and keep the cursor in range.
    ///
    /// Returns `true` on success; failures become the status line.
    fn refresh(&mut self) -> bool {
        match fetch_routes() {
            Ok(routes) => {
                self.routes = routes;
                self.last_refresh = Instant::now();
                if self.status.starts_with("refresh failed") {
                    self.status.clear();
                }
                let max = self.routes.len().saturating_sub(1);
                match self.state.selected() {
                    Some(i) if i > max && !self.routes.is_empty() => {
                        self.state.select(Some(max));
                    }
                    None if !self.routes.is_empty() => self.state.select(Some(0)),
                    _ => {}
                }
                true
            }
            Err(e) => {
                self.status = format!("refresh failed: {e}");
                false
            }
        }
    }

    /// Currently selected route, if any.
    fn selected(&self) -> Option<&Route> {
        self.state.selected().and_then(|i| self.routes.get(i))
    }

    /// Move the cursor, wrapping around the list.
    fn move_cursor(&mut self, delta: i32) {
        if self.routes.is_empty() {
            return;
        }
        let len = self.routes.len() as i32;
        let cur = self.state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(len) as usize;
        self.state.select(Some(next));
    }

    /// Begin editing the gateway of the selected route.
    fn begin_edit(&mut self) {
        let Some(route) = self.selected().cloned() else {
            return;
        };
        self.input = route.gateway.map(|g| g.to_string()).unwrap_or_default();
        self.mode = Mode::Editing;
        self.status = format!("editing gateway for {}", route.prefix);
    }

    /// Apply the typed gateway to the selected route.
    fn apply_edit(&mut self) {
        let Some(route) = self.selected().cloned() else {
            self.mode = Mode::Normal;
            return;
        };
        let text = self.input.trim();
        let Ok(gw) = text.parse::<Ipv4Addr>() else {
            self.status = format!("invalid IPv4 address {text:?}");
            return;
        };
        // The default route keeps its device/metric/source via the dedicated
        // helper; other prefixes are replaced in place with the same
        // device/metric/source so pins are not silently dropped.
        let result = if route.is_default() {
            crate::ops::set_default_gateway(gw, None, None, false)
        } else {
            replace_route(
                &route.prefix,
                Some(gw),
                route.oif,
                route.metric,
                route.pref_src,
                false,
            )
        };
        match result {
            Ok(op) => {
                self.status = format!("applied: {}", op.summary);
                self.mode = Mode::Normal;
                self.input.clear();
                self.refresh();
            }
            Err(e) => self.status = format!("apply failed: {e}"),
        }
    }

    /// Delete the selected route after confirmation.
    fn apply_delete(&mut self) {
        let Some(route) = self.selected().cloned() else {
            self.mode = Mode::Normal;
            return;
        };
        match crate::ops::del_route(&route.prefix, route.oif, route.metric, false) {
            Ok(op) => {
                self.status = format!("applied: {}", op.summary);
                self.mode = Mode::Normal;
                self.refresh();
            }
            Err(e) => self.status = format!("delete failed: {e}"),
        }
    }
}

/// Dump the table on a fresh socket.
fn fetch_routes() -> Result<Vec<Route>, DumpError> {
    let sock = NlSocket::open()?;
    dump(sock.0)
}

/// Run the fullscreen TUI until the user quits.
pub fn run(interval: u64) -> Result<(), DumpError> {
    let mut stdout = io::stdout();
    enable_raw_mode().map_err(DumpError::Terminal)?;
    execute!(stdout, EnterAlternateScreen).map_err(DumpError::Terminal)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(DumpError::Terminal)?;
    let result = event_loop(&mut terminal, interval);
    restore_terminal(terminal);
    result
}

/// Restore cooked mode and leave the alternate screen, ignoring errors.
fn restore_terminal(mut terminal: Terminal<CrosstermBackend<Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

/// Main loop: draw, handle keys, auto-refresh on a timer.
fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    interval: u64,
) -> Result<(), DumpError> {
    let mut app = App::new(interval);
    let tick = Duration::from_millis(200);
    loop {
        terminal.draw(|f| draw(f, &mut app)).map_err(DumpError::Terminal)?;
        if event::poll(tick).map_err(DumpError::Terminal)? {
            let ev = event::read().map_err(DumpError::Terminal)?;
            if handle_event(&mut app, ev) {
                return Ok(());
            }
        }
        if app.last_refresh.elapsed() >= Duration::from_secs(app.interval.max(1)) {
            app.refresh();
        }
    }
}

/// Handle one crossterm event. Returns `true` when the user quits.
fn handle_event(app: &mut App, ev: Event) -> bool {
    let Event::Key(key) = ev else {
        return false;
    };
    // Ctrl-C always quits.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    match app.mode {
        Mode::Editing => match key.code {
            KeyCode::Enter => {
                app.apply_edit();
            }
            KeyCode::Esc => {
                app.mode = Mode::Normal;
                app.status = "edit cancelled".to_string();
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Char(c) => {
                app.input.push(c);
            }
            _ => {}
        },
        Mode::ConfirmDelete => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => app.apply_delete(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => {
                app.mode = Mode::Normal;
                app.status = "delete cancelled".to_string();
            }
            _ => {}
        },
        Mode::Normal => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Down | KeyCode::Char('j') => app.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => app.move_cursor(-1),
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if app.refresh() {
                    app.status = "refreshed".to_string();
                }
            }
            KeyCode::Char('e') | KeyCode::Char('g') => app.begin_edit(),
            KeyCode::Char('d') | KeyCode::Char('D') => {
                if app.selected().is_some() {
                    app.mode = Mode::ConfirmDelete;
                }
            }
            _ => {}
        },
    }
    false
}

/// Draw the whole screen: header, table, footer, plus any popup.
fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(4),
        ])
        .split(area);

    draw_header(f, rows[0], app);
    draw_table(f, rows[1], app);
    draw_footer(f, rows[2], app);

    match app.mode {
        Mode::Editing => draw_editor(f, area, app),
        Mode::ConfirmDelete => draw_confirm(f, area, app),
        Mode::Normal => {}
    }
}

/// Top bar with the current default gateway.
///
/// Reads from the already-fetched table so drawing never blocks on sockets.
fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let default_line = match app.routes.iter().find(|r| r.is_default()) {
        Some(route) => {
            let gw = route
                .gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!("default via {gw}  ({route})")
        }
        None => "no default route".to_string(),
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "route-nl  ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(default_line),
    ]))
    .block(Block::default().borders(Borders::ALL).title("gateway monitor"));
    f.render_widget(header, area);
}

/// Main route table with the default row highlighted.
fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec!["prefix", "gateway", "dev", "metric", "src"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);
    let rows = app.routes.iter().map(|r| {
        let dev = r
            .if_name()
            .or_else(|| r.oif.map(|n| n.to_string()))
            .unwrap_or_else(|| "-".to_string());
        let mut row = Row::new(vec![
            Cell::from(r.prefix.to_string()),
            Cell::from(r.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into())),
            Cell::from(dev),
            Cell::from(r.metric.map(|m| m.to_string()).unwrap_or_else(|| "-".into())),
            Cell::from(
                r.pref_src
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
            ),
        ]);
        if r.is_default() {
            row = row.style(Style::default().fg(Color::Yellow));
        }
        row
    });
    let widths = [
        Constraint::Length(20),
        Constraint::Length(16),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(16),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("routes"))
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(table, area, &mut app.state);
}

/// Bottom bar with keys and the current status message.
fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let keys = match app.mode {
        Mode::Normal => "↑/↓ j/k select · e edit gateway · d delete · r refresh · q quit",
        Mode::Editing => "Enter apply · Esc cancel",
        Mode::ConfirmDelete => "y confirm delete · n/Esc cancel",
    };
    let status = if app.status.is_empty() {
        "(need sudo to apply changes)".to_string()
    } else {
        app.status.clone()
    };
    let footer = Paragraph::new(vec![Line::from(keys), Line::from(status)])
        .block(Block::default().borders(Borders::ALL).title("keys / status"));
    f.render_widget(footer, area);
}

/// Centered popup for typing the new gateway address.
fn draw_editor(f: &mut Frame, area: Rect, app: &App) {
    let popup = centered(area, 60, 5);
    f.render_widget(Clear, popup);
    let selected = app
        .selected()
        .map(|r| r.prefix.to_string())
        .unwrap_or_else(|| "-".to_string());
    let editor = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("new gateway for {selected}")),
    );
    f.render_widget(editor, popup);
}

/// Centered confirmation popup for deletions.
fn draw_confirm(f: &mut Frame, area: Rect, app: &App) {
    let popup = centered(area, 60, 5);
    f.render_widget(Clear, popup);
    let target = app
        .selected()
        .map(|r| r.to_string())
        .unwrap_or_else(|| "-".to_string());
    let prompt = Paragraph::new(format!("delete {target}?  (y/n)"))
        .block(Block::default().borders(Borders::ALL).title("confirm"));
    f.render_widget(prompt, popup);
}

/// Helper: a centered rectangle of `w`/`h` inside `area`.
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let h_margin = area.width.saturating_sub(w) / 2;
    let v_margin = area.height.saturating_sub(h) / 2;
    Rect {
        x: area.x + h_margin,
        y: area.y + v_margin,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Prefix;

    #[test]
    fn cursor_wraps() {
        let mut app = App {
            routes: vec![
                Route {
                    prefix: Prefix::Default { len: 0 },
                    gateway: None,
                    oif: None,
                    metric: None,
                    pref_src: None,
                },
                Route {
                    prefix: Prefix::parse("10.0.0.0/8").unwrap(),
                    gateway: None,
                    oif: None,
                    metric: None,
                    pref_src: None,
                },
            ],
            state: TableState::default(),
            status: String::new(),
            mode: Mode::Normal,
            input: String::new(),
            interval: 2,
            last_refresh: Instant::now(),
        };
        app.state.select(Some(1));
        app.move_cursor(1);
        assert_eq!(app.state.selected(), Some(0));
        app.move_cursor(-1);
        assert_eq!(app.state.selected(), Some(1));
    }

    #[test]
    fn invalid_gateway_keeps_editor_open() {
        let mut app = App::new(60);
        app.routes = vec![Route {
            prefix: Prefix::Default { len: 0 },
            gateway: None,
            oif: None,
            metric: None,
            pref_src: None,
        }];
        app.state.select(Some(0));
        app.begin_edit();
        app.input = "not-an-ip".to_string();
        app.apply_edit();
        assert_eq!(app.mode, Mode::Editing);
        assert!(app.status.contains("invalid"));
    }
}
