//! Firewall Visualization Tool
//!
//! Graphically displays crmonban firewall chains, rules, and packet flow.

use std::io::stdout;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    symbols::border,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde::Deserialize;

// nftables JSON schema structures
#[derive(Debug, Deserialize)]
struct Nftables {
    nftables: Vec<NfObject>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum NfObject {
    Metainfo { metainfo: Metainfo },
    Table { table: Table },
    Chain { chain: Chain },
    Rule { rule: Rule },
    Set { set: Set },
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct Metainfo {
    #[allow(dead_code)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Table {
    family: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Chain {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    chain_type: Option<String>,
    hook: Option<String>,
    prio: Option<i32>,
    policy: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    family: String,
    table: String,
    chain: String,
    #[allow(dead_code)]
    handle: Option<u64>,
    comment: Option<String>,
    expr: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct Set {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    set_type: Option<serde_json::Value>,
    elem: Option<Vec<serde_json::Value>>,
}

/// Parsed firewall state
struct FirewallState {
    tables: Vec<TableInfo>,
}

struct TableInfo {
    name: String,
    family: String,
    chains: Vec<ChainInfo>,
    sets: Vec<SetInfo>,
}

struct ChainInfo {
    name: String,
    #[allow(dead_code)]
    chain_type: Option<String>,
    hook: Option<String>,
    priority: Option<i32>,
    policy: Option<String>,
    rules: Vec<RuleInfo>,
}

struct RuleInfo {
    comment: Option<String>,
    action: String,
    matches: Vec<String>,
}

struct SetInfo {
    name: String,
    set_type: String,
    elements: Vec<String>,
}

/// Application state
struct App {
    firewall: FirewallState,
    details_scroll: u16,
    selected_chain: usize,
    show_flow: bool,
    flow_animation_frame: usize,
}

impl App {
    fn new() -> Result<Self> {
        let firewall = load_nftables_state()?;
        Ok(Self {
            firewall,
            details_scroll: 0,
            selected_chain: 0,
            show_flow: true,
            flow_animation_frame: 0,
        })
    }

    fn reload(&mut self) -> Result<()> {
        self.firewall = load_nftables_state()?;
        Ok(())
    }

    fn total_chains(&self) -> usize {
        self.firewall
            .tables
            .iter()
            .map(|t| t.chains.len())
            .sum()
    }
}

fn load_nftables_state() -> Result<FirewallState> {
    // Run nft -j list ruleset
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .context("Failed to run nft command. Is nftables installed?")?;

    if !output.status.success() {
        // Try with sudo
        let output = Command::new("sudo")
            .args(["nft", "-j", "list", "ruleset"])
            .output()
            .context("Failed to run nft with sudo")?;

        if !output.status.success() {
            anyhow::bail!(
                "nft command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        return parse_nftables_json(&output.stdout);
    }

    parse_nftables_json(&output.stdout)
}

fn parse_nftables_json(json_data: &[u8]) -> Result<FirewallState> {
    let nft: Nftables = serde_json::from_slice(json_data).context("Failed to parse nft JSON")?;

    let mut tables: Vec<TableInfo> = Vec::new();

    // First pass: collect tables
    for obj in &nft.nftables {
        if let NfObject::Table { table } = obj {
            tables.push(TableInfo {
                name: table.name.clone(),
                family: table.family.clone(),
                chains: Vec::new(),
                sets: Vec::new(),
            });
        }
    }

    // Second pass: collect chains
    for obj in &nft.nftables {
        if let NfObject::Chain { chain } = obj {
            if let Some(table) = tables
                .iter_mut()
                .find(|t| t.name == chain.table && t.family == chain.family)
            {
                table.chains.push(ChainInfo {
                    name: chain.name.clone(),
                    chain_type: chain.chain_type.clone(),
                    hook: chain.hook.clone(),
                    priority: chain.prio,
                    policy: chain.policy.clone(),
                    rules: Vec::new(),
                });
            }
        }
    }

    // Third pass: collect rules
    for obj in &nft.nftables {
        if let NfObject::Rule { rule } = obj {
            if let Some(table) = tables
                .iter_mut()
                .find(|t| t.name == rule.table && t.family == rule.family)
            {
                if let Some(chain) = table.chains.iter_mut().find(|c| c.name == rule.chain) {
                    let (action, matches) = parse_rule_expr(&rule.expr);
                    chain.rules.push(RuleInfo {
                        comment: rule.comment.clone(),
                        action,
                        matches,
                    });
                }
            }
        }
    }

    // Fourth pass: collect sets
    for obj in &nft.nftables {
        if let NfObject::Set { set } = obj {
            if let Some(table) = tables
                .iter_mut()
                .find(|t| t.name == set.table && t.family == set.family)
            {
                let set_type = match &set.set_type {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(serde_json::Value::Array(arr)) => arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" . "),
                    _ => "unknown".to_string(),
                };

                let elements = set
                    .elem
                    .as_ref()
                    .map(|elems| {
                        elems
                            .iter()
                            .filter_map(|e| {
                                if let serde_json::Value::String(s) = e {
                                    Some(s.clone())
                                } else if let serde_json::Value::Object(obj) = e {
                                    // Handle elem with timeout
                                    obj.get("elem")
                                        .and_then(|v| v.get("val"))
                                        .and_then(|v| v.as_str())
                                        .map(String::from)
                                } else {
                                    None
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                table.sets.push(SetInfo {
                    name: set.name.clone(),
                    set_type,
                    elements,
                });
            }
        }
    }

    Ok(FirewallState { tables })
}

fn parse_rule_expr(expr: &Option<Vec<serde_json::Value>>) -> (String, Vec<String>) {
    let mut action = String::from("accept");
    let mut matches = Vec::new();

    if let Some(exprs) = expr {
        for e in exprs {
            if let serde_json::Value::Object(obj) = e {
                // Check for actions
                if obj.contains_key("drop") {
                    action = "DROP".to_string();
                } else if obj.contains_key("accept") {
                    action = "ACCEPT".to_string();
                } else if obj.contains_key("reject") {
                    action = "REJECT".to_string();
                } else if obj.contains_key("return") {
                    action = "RETURN".to_string();
                } else if obj.contains_key("jump") {
                    if let Some(target) = obj.get("jump").and_then(|v| v.get("target")) {
                        action = format!("JUMP {}", target);
                    }
                } else if obj.contains_key("goto") {
                    if let Some(target) = obj.get("goto").and_then(|v| v.get("target")) {
                        action = format!("GOTO {}", target);
                    }
                } else if obj.contains_key("queue") {
                    if let Some(q) = obj.get("queue") {
                        let num = q.get("num").and_then(|v| v.as_u64()).unwrap_or(0);
                        action = format!("QUEUE num {}", num);
                    }
                } else if obj.contains_key("log") {
                    if let Some(log) = obj.get("log") {
                        let prefix = log
                            .get("prefix")
                            .and_then(|v| v.as_str())
                            .unwrap_or("LOG");
                        action = format!("LOG \"{}\"", prefix.trim());
                    }
                } else if obj.contains_key("redirect") {
                    if let Some(redir) = obj.get("redirect") {
                        let port = redir.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                        action = format!("REDIRECT to :{}", port);
                    }
                }

                // Check for matches
                if let Some(match_obj) = obj.get("match") {
                    let left = format_expr(match_obj.get("left"));
                    let right = format_expr(match_obj.get("right"));
                    let op = match_obj
                        .get("op")
                        .and_then(|v| v.as_str())
                        .unwrap_or("==");
                    matches.push(format!("{} {} {}", left, op, right));
                }
            }
        }
    }

    (action, matches)
}

fn format_expr(expr: Option<&serde_json::Value>) -> String {
    match expr {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Object(obj)) => {
            if let Some(payload) = obj.get("payload") {
                let proto = payload
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let field = payload
                    .get("field")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("{}.{}", proto, field)
            } else if let Some(meta) = obj.get("meta") {
                if let Some(key) = meta.get("key").and_then(|v| v.as_str()) {
                    format!("meta.{}", key)
                } else {
                    "meta".to_string()
                }
            } else if let Some(ct) = obj.get("ct") {
                if let Some(key) = ct.get("key").and_then(|v| v.as_str()) {
                    format!("ct.{}", key)
                } else {
                    "ct".to_string()
                }
            } else {
                format!("{:?}", obj)
            }
        }
        _ => "?".to_string(),
    }
}

fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App::new()?;

    // Main loop
    loop {
        terminal.draw(|frame| ui(frame, &app))?;

        // Handle events with timeout for animation
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') => {
                            let _ = app.reload();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.selected_chain > 0 {
                                app.selected_chain -= 1;
                                app.details_scroll = 0; // Reset details scroll on chain change
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.selected_chain + 1 < app.total_chains() {
                                app.selected_chain += 1;
                                app.details_scroll = 0; // Reset details scroll on chain change
                            }
                        }
                        KeyCode::Char('f') => {
                            app.show_flow = !app.show_flow;
                        }
                        KeyCode::PageUp => {
                            app.details_scroll = app.details_scroll.saturating_sub(10);
                        }
                        KeyCode::PageDown => {
                            app.details_scroll = app.details_scroll.saturating_add(10);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Animate flow
        if app.show_flow {
            app.flow_animation_frame = (app.flow_animation_frame + 1) % 20;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

fn ui(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Main layout: header, content, footer
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Content
            Constraint::Length(3),  // Footer
        ])
        .split(area);

    // Header
    let header = Paragraph::new("CRMONBAN FIREWALL VISUALIZATION")
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(border::THICK),
        );
    frame.render_widget(header, main_layout[0]);

    // Content layout: flow diagram on top, chains below
    let content_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if app.show_flow { 9 } else { 0 }),
            Constraint::Min(5),
        ])
        .split(main_layout[1]);

    // Packet flow diagram
    if app.show_flow {
        render_flow_diagram(frame, content_layout[0], app);
    }

    // Chains and rules layout
    let chains_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // Chain list
            Constraint::Percentage(70), // Rules/details
        ])
        .split(content_layout[1]);

    render_chain_list(frame, chains_layout[0], app);
    render_chain_details(frame, chains_layout[1], app, app.details_scroll);

    // Footer with help
    let footer = Paragraph::new(" q: Quit | r: Reload | f: Toggle Flow | ↑↓: Navigate | PgUp/PgDn: Scroll ")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, main_layout[2]);
}

fn render_flow_diagram(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Packet Flow ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build flow diagram based on chains
    let mut hooks: Vec<(&str, i32, Vec<&str>)> = Vec::new(); // (hook_name, priority, chain_names)

    for table in &app.firewall.tables {
        for chain in &table.chains {
            if let Some(hook) = &chain.hook {
                let prio = chain.priority.unwrap_or(0);
                if let Some(existing) = hooks.iter_mut().find(|(h, p, _)| h == hook && *p == prio) {
                    existing.2.push(&chain.name);
                } else {
                    hooks.push((hook, prio, vec![&chain.name]));
                }
            }
        }
    }

    // Sort by hook order: prerouting -> input/forward/output -> postrouting
    let hook_order = ["prerouting", "input", "forward", "output", "postrouting"];
    hooks.sort_by(|a, b| {
        let a_idx = hook_order.iter().position(|h| *h == a.0).unwrap_or(99);
        let b_idx = hook_order.iter().position(|h| *h == b.0).unwrap_or(99);
        a_idx.cmp(&b_idx).then(a.1.cmp(&b.1))
    });

    // Animation character
    let anim_chars = ['>', '>', '>', '-', '-', '-'];
    let anim_idx = app.flow_animation_frame % anim_chars.len();
    let anim_char = anim_chars[anim_idx];

    // Build the flow text
    let mut lines: Vec<Line> = Vec::new();

    // Top line: Network packet flow
    lines.push(Line::from(vec![
        Span::styled("  NETWORK ", Style::default().fg(Color::Yellow).bold()),
        Span::styled(
            format!("{}{}{}> ", anim_char, anim_char, anim_char),
            Style::default().fg(Color::Green),
        ),
    ]));

    // Flow through hooks
    let mut flow_line = vec![Span::raw("  ")];

    for (i, (hook, prio, chains)) in hooks.iter().enumerate() {
        let hook_style = match *hook {
            "prerouting" => Style::default().fg(Color::Magenta),
            "input" => Style::default().fg(Color::Green),
            "forward" => Style::default().fg(Color::Yellow),
            "output" => Style::default().fg(Color::Cyan),
            "postrouting" => Style::default().fg(Color::Red),
            _ => Style::default().fg(Color::White),
        };

        let chain_list = chains.join(",");
        flow_line.push(Span::styled(
            format!("[{} p:{}]", hook.to_uppercase(), prio),
            hook_style.bold(),
        ));

        if !chain_list.is_empty() && chain_list != *hook {
            flow_line.push(Span::styled(
                format!("({})", chain_list),
                Style::default().fg(Color::DarkGray),
            ));
        }

        if i < hooks.len() - 1 {
            flow_line.push(Span::styled(
                format!(" {}{}> ", anim_char, anim_char),
                Style::default().fg(Color::Green),
            ));
        }
    }

    lines.push(Line::from(flow_line));

    // Legend
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("PREROUTING", Style::default().fg(Color::Magenta)),
        Span::raw(" → "),
        Span::styled("INPUT", Style::default().fg(Color::Green)),
        Span::raw("/"),
        Span::styled("FORWARD", Style::default().fg(Color::Yellow)),
        Span::raw("/"),
        Span::styled("OUTPUT", Style::default().fg(Color::Cyan)),
        Span::raw(" → "),
        Span::styled("POSTROUTING", Style::default().fg(Color::Red)),
    ]));

    let para = Paragraph::new(lines);
    frame.render_widget(para, inner);
}

fn render_chain_list(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Chains ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    let mut chain_idx = 0;
    let mut selected_line: u16 = 0;

    for table in &app.firewall.tables {
        // Table header
        lines.push(Line::from(vec![Span::styled(
            format!("▼ {} [{}]", table.name, table.family),
            Style::default().fg(Color::Cyan).bold(),
        )]));

        for chain in &table.chains {
            let is_selected = chain_idx == app.selected_chain;
            if is_selected {
                selected_line = lines.len() as u16;
            }

            let style = if is_selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                Style::default()
            };

            let hook_info = chain
                .hook
                .as_ref()
                .map(|h| format!(" [{}]", h))
                .unwrap_or_default();

            let prefix = if is_selected { "► " } else { "  " };

            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(&chain.name, style.bold()),
                Span::styled(hook_info, style.fg(Color::DarkGray)),
            ]));

            chain_idx += 1;
        }

        // Sets
        if !table.sets.is_empty() {
            lines.push(Line::from(vec![Span::styled(
                "  Sets:",
                Style::default().fg(Color::Magenta),
            )]));
            for set in &table.sets {
                let elem_count = set.elements.len();
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(&set.name, Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!(" ({}) [{}]", set.set_type, elem_count),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
        }

        lines.push(Line::from(""));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No firewall rules found",
            Style::default().fg(Color::Red),
        )));
    }

    // Auto-scroll to keep selected chain visible
    let visible_height = inner.height;
    let scroll_offset = if selected_line >= visible_height {
        selected_line.saturating_sub(visible_height / 2)
    } else {
        0
    };

    let para = Paragraph::new(lines)
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);
}

fn render_chain_details(frame: &mut Frame, area: Rect, app: &App, scroll: u16) {
    let block = Block::default()
        .title(" Chain Details & Rules ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Find selected chain
    let mut chain_idx = 0;
    let mut selected_chain: Option<(&TableInfo, &ChainInfo)> = None;

    'outer: for table in &app.firewall.tables {
        for chain in &table.chains {
            if chain_idx == app.selected_chain {
                selected_chain = Some((table, chain));
                break 'outer;
            }
            chain_idx += 1;
        }
    }

    let mut lines: Vec<Line> = Vec::new();

    if let Some((table, chain)) = selected_chain {
        // Chain header
        lines.push(Line::from(vec![
            Span::styled("Chain: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&chain.name, Style::default().fg(Color::Cyan).bold()),
            Span::raw(" in table "),
            Span::styled(&table.name, Style::default().fg(Color::Yellow)),
        ]));

        // Chain properties
        if let Some(ref hook) = chain.hook {
            lines.push(Line::from(vec![
                Span::styled("  Hook: ", Style::default().fg(Color::DarkGray)),
                Span::styled(hook.to_uppercase(), Style::default().fg(Color::Magenta)),
            ]));
        }

        if let Some(prio) = chain.priority {
            lines.push(Line::from(vec![
                Span::styled("  Priority: ", Style::default().fg(Color::DarkGray)),
                Span::styled(prio.to_string(), Style::default().fg(Color::White)),
            ]));
        }

        if let Some(ref policy) = chain.policy {
            let policy_color = match policy.as_str() {
                "accept" => Color::Green,
                "drop" => Color::Red,
                _ => Color::Yellow,
            };
            lines.push(Line::from(vec![
                Span::styled("  Policy: ", Style::default().fg(Color::DarkGray)),
                Span::styled(policy.to_uppercase(), Style::default().fg(policy_color)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("Rules ({}):", chain.rules.len()),
            Style::default().fg(Color::Green).bold(),
        )]));

        // Rules
        for (i, rule) in chain.rules.iter().enumerate() {
            lines.push(Line::from(""));

            // Rule number and action
            let action_color = match rule.action.as_str() {
                "DROP" => Color::Red,
                "ACCEPT" => Color::Green,
                "REJECT" => Color::Yellow,
                _ if rule.action.starts_with("QUEUE") => Color::Magenta,
                _ if rule.action.starts_with("LOG") => Color::Blue,
                _ if rule.action.starts_with("REDIRECT") => Color::Cyan,
                _ => Color::White,
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  [{}] ", i + 1), Style::default().fg(Color::DarkGray)),
                Span::styled(&rule.action, Style::default().fg(action_color).bold()),
            ]));

            // Comment
            if let Some(ref comment) = rule.comment {
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled(
                        format!("# {}", comment),
                        Style::default().fg(Color::DarkGray).italic(),
                    ),
                ]));
            }

            // Matches
            for m in &rule.matches {
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled(m, Style::default().fg(Color::White)),
                ]));
            }
        }

        if chain.rules.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (no rules)",
                Style::default().fg(Color::DarkGray).italic(),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Select a chain to view details",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);
}
