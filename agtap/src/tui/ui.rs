use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, Borders, Cell, Padding, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, Wrap,
};
use ratatui::Frame;

use super::state::{AppState, DetailTab, FocusedPanel, UiAreas};
use crate::output::CallKind;

const SCROLL_INDICATOR: &[&str] = &[" ", " ", "\u{00b7}", "\u{00b7}", "\u{00b7}"];

fn draw_scroll_indicators(
    buf: &mut Buffer,
    inner: Rect,
    top_y: u16,
    show_top: bool,
    show_bottom: bool,
) {
    if inner.height == 0 {
        return;
    }
    let style = Style::default().fg(Color::DarkGray);
    if show_top {
        for (i, s) in SCROLL_INDICATOR.iter().enumerate() {
            if i as u16 >= inner.width {
                break;
            }
            if let Some(cell) = buf.cell_mut((inner.x + i as u16, top_y)) {
                cell.set_symbol(s).set_style(style);
            }
        }
    }
    if show_bottom {
        let y = inner.y + inner.height - 1;
        for (i, s) in SCROLL_INDICATOR.iter().enumerate() {
            if i as u16 >= inner.width {
                break;
            }
            if let Some(cell) = buf.cell_mut((inner.x + i as u16, y)) {
                cell.set_symbol(s).set_style(style);
            }
        }
    }
}

/// Two-pass indicator resolution: indicators steal rows from the data area,
/// which can change the scroll offset and indicator visibility.
/// Returns (offset, data_rows, show_top, show_bottom).
fn resolve_scroll_indicators(
    full_visible: usize,
    inner_height: u16,
    total_items: usize,
    compute_offset: impl Fn(usize) -> usize,
) -> (usize, usize, bool, bool) {
    if inner_height < 3 {
        let offset = compute_offset(full_visible);
        return (offset, full_visible, false, false);
    }
    let off1 = compute_offset(full_visible);
    let top1 = off1 > 0;
    let bot1 = off1 + full_visible < total_items;
    if !top1 && !bot1 {
        return (off1, full_visible, false, false);
    }
    let needed = top1 as usize + bot1 as usize;
    let dr = full_visible.saturating_sub(needed);
    let off2 = compute_offset(dr);
    let top2 = off2 > 0;
    let bot2 = off2 + dr < total_items;
    let needed2 = top2 as usize + bot2 as usize;
    if needed2 == needed {
        (off2, dr, top2, bot2)
    } else {
        let dr2 = full_visible.saturating_sub(needed2);
        let off3 = compute_offset(dr2);
        let top3 = off3 > 0;
        let bot3 = off3 + dr2 < total_items;
        (off3, dr2, top3, bot3)
    }
}

pub fn render(f: &mut Frame, state: &AppState) -> UiAreas {
    let mut areas = UiAreas::default();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),      // header
            Constraint::Percentage(30), // middle (agents + metrics)
            Constraint::Min(6),         // event log (+ detail when open)
            Constraint::Length(1),      // footer hints
        ])
        .split(f.area());

    render_header(f, state, chunks[0]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    render_agent_list(f, state, middle[0], &mut areas);

    let filtered = state.filtered_indices();

    render_global_metrics(f, state, middle[1], &filtered);

    if state.detail_open {
        let event_detail = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(chunks[2]);

        render_event_log(f, state, event_detail[0], &mut areas, &filtered);
        render_detail_pane(f, state, event_detail[1], &mut areas);
    } else {
        render_event_log(f, state, chunks[2], &mut areas, &filtered);
    }

    render_footer(f, state, chunks[3]);

    areas
}

// ── Header ───────────────────────────────────────────────────────────────────

fn render_header(f: &mut Frame, state: &AppState, area: Rect) {
    let uptime = state.global.uptime();
    let uptime_str = format_uptime(uptime.as_secs());

    let status_span = if state.connected {
        Span::styled("  connected", Style::default().fg(Color::Green))
    } else {
        Span::styled("  connecting...", Style::default().fg(Color::Yellow))
    };

    let line = Line::from(vec![
        Span::styled(
            " agtap ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        status_span,
        Span::raw("  uptime: "),
        Span::styled(&uptime_str, Style::default().fg(Color::White)),
    ]);

    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::DarkGray)),
        area,
    );
}

// ── Agent list ───────────────────────────────────────────────────────────────

fn render_agent_list(f: &mut Frame, state: &AppState, area: Rect, areas: &mut UiAreas) {
    let border_color = if state.focused_panel == FocusedPanel::AgentList {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .title(" Agents ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);

    if state.agents.is_empty() {
        areas.agent_list_area = Some(inner);
        areas.agent_list_scroll_area = Some(inner);
        let msg = Paragraph::new("  Waiting for events...")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        f.render_widget(msg, area);
        return;
    }

    // Render border separately; table is drawn blockless into inner
    f.render_widget(block, area);

    let header = Row::new(vec![
        Cell::from("Last Seen"),
        Cell::from("Process"),
        Cell::from("API"),
        Cell::from("MCP"),
        Cell::from("Avg Lat"),
        Cell::from("Tokens"),
    ])
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    let agent_count = state.agents.len();
    let full_visible = inner.height.saturating_sub(1) as usize; // subtract header

    let (scroll_offset, data_rows, show_top, show_bottom) =
        resolve_scroll_indicators(full_visible, inner.height, agent_count, |h| {
            state.agent_scroll_offset(h)
        });

    let rows: Vec<Row> = state
        .agents
        .iter()
        .rev()
        .skip(scroll_offset)
        .take(data_rows)
        .enumerate()
        .map(|(vi, ((_pid, _name), agent))| {
            let i = scroll_offset + vi;
            let is_selected = (agent_count - 1 - i) == state.selected_agent;
            let time = format_short_ts(&agent.last_seen);

            let row = Row::new(vec![
                Cell::from(time).style(Style::default().fg(Color::DarkGray)),
                Cell::from(agent.label()).style(Style::default().fg(Color::White)),
                Cell::from(format!("{}", agent.api_calls))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{}", agent.mcp_calls))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{:.1}s", agent.avg_latency_ms() as f64 / 1000.0))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(if agent.has_llm_calls {
                    format_number(agent.total_input_tokens + agent.total_output_tokens)
                } else {
                    format_bytes(agent.total_request_bytes + agent.total_response_bytes)
                })
                .style(Style::default().fg(Color::Green)),
            ]);

            if is_selected {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let widths = vec![
        Constraint::Length(12), // Last Seen
        Constraint::Min(12),    // Process
        Constraint::Length(5),  // API
        Constraint::Length(5),  // MCP
        Constraint::Length(7),  // Avg Lat
        Constraint::Length(8),  // Tokens
    ];

    // Render header into first row, data table into sub-rect below (skipping indicator rows)
    let header_rect = Rect::new(inner.x, inner.y, inner.width, 1);
    f.render_widget(
        Table::new(Vec::<Row>::new(), widths.clone()).header(header),
        header_rect,
    );

    let data_y = inner.y + 1 + show_top as u16;
    let data_rect = Rect::new(inner.x, data_y, inner.width, data_rows as u16);
    f.render_widget(Table::new(rows, widths), data_rect);

    areas.agent_list_area = Some(data_rect);
    areas.agent_list_scroll_area = Some(inner);

    // Draw indicators on their dedicated (empty) rows
    draw_scroll_indicators(f.buffer_mut(), inner, inner.y + 1, show_top, show_bottom);
}

// ── Global metrics ───────────────────────────────────────────────────────────

fn round_nice(n: u64) -> u64 {
    if n < 10 {
        return n;
    }
    let digits = n.ilog10();
    let factor = 10u64.pow(digits.saturating_sub(1));
    ((n + factor / 2) / factor) * factor
}

fn format_axis_label(ms: u64) -> String {
    let ms = round_nice(ms);
    let s = ms as f64 / 1000.0;
    if s >= 10.0 {
        format!("{:.0}s", s)
    } else if s >= 1.0 {
        format!("{:.1}s", s)
    } else if s >= 0.01 {
        format!("{:.2}s", s)
    } else if ms > 0 {
        "<.01s".to_string()
    } else {
        "0".to_string()
    }
}

fn render_global_metrics(f: &mut Frame, state: &AppState, area: Rect, filtered: &[usize]) {
    const LABEL_W: u16 = 8;

    let block = Block::default()
        .title(" Metrics ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    // Split area: top for text metrics, bottom for latency chart
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(3)])
        .split(inner);

    let avg_latency = {
        let (sum, count) = state.agents.values().fold((0u64, 0u64), |(s, c), a| {
            (
                s + a.latencies.iter().sum::<u64>(),
                c + a.latencies.len() as u64,
            )
        });
        sum.checked_div(count).unwrap_or(0)
    };

    let label = |name: &str, val: String| -> Line {
        Line::from(vec![
            Span::styled(
                format!(" {:<18}", name),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(val, Style::default().fg(Color::White)),
        ])
    };

    let metrics_text = vec![
        label("API calls", format!("{}", state.global.api_calls)),
        label("MCP calls", format!("{}", state.global.mcp_calls)),
        label(
            "Input tokens",
            format_number(state.global.total_input_tokens),
        ),
        label(
            "Output tokens",
            format_number(state.global.total_output_tokens),
        ),
        label(
            "Avg latency",
            format!("{:.1}s", avg_latency as f64 / 1000.0),
        ),
    ];

    f.render_widget(Paragraph::new(metrics_text), chunks[0]);

    // Render a parent block with TOP border and title spanning full width
    let chart_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let chart_inner = chart_block.inner(chunks[1]);
    f.render_widget(chart_block, chunks[1]);

    let use_labels = chart_inner.width >= LABEL_W + 3;

    let (label_area, chart_area) = if use_labels {
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(LABEL_W), Constraint::Min(1)])
            .split(chart_inner);
        (Some(chart_chunks[0]), chart_chunks[1])
    } else {
        (None, chart_inner)
    };

    let chart_width = chart_area.width as usize;
    let skip = filtered.len().saturating_sub(chart_width);

    let max_val = filtered
        .iter()
        .skip(skip)
        .map(|&i| state.event_log[i].latency_ms)
        .max()
        .unwrap_or(0);

    let min_visible = if chart_area.height > 0 && max_val > 0 {
        max_val.div_ceil(chart_area.height as u64)
    } else {
        1
    };

    let bars: Vec<Bar> = filtered
        .iter()
        .skip(skip)
        .map(|&i| {
            let e = &state.event_log[i];
            Bar::default()
                .value(if e.latency_ms > 0 {
                    e.latency_ms.max(min_visible)
                } else {
                    0
                })
                .style(Style::default().fg(provider_color(&e.provider)))
                .text_value(String::new())
        })
        .collect();
    let chart = BarChart::default()
        .data(BarGroup::default().bars(&bars))
        .bar_width(1)
        .bar_gap(0);
    f.render_widget(chart, chart_area);

    // Draw y-axis labels and axis line if there's room and data exists
    if let Some(la) = label_area {
        let label_style = Style::default().fg(Color::DarkGray);
        let buf = f.buffer_mut();
        let bar_height = chart_area.height;

        let label_w = (LABEL_W - 2) as usize;
        let draw_label = |buf: &mut Buffer, val: u64, y: u16| {
            let text = format!("{:>width$}", format_axis_label(val), width = label_w);
            let mut tmp = [0u8; 4];
            for (i, ch) in text.chars().enumerate() {
                let s = ch.encode_utf8(&mut tmp);
                if let Some(cell) = buf.cell_mut((la.x + i as u16, y)) {
                    cell.set_symbol(s).set_style(label_style);
                }
            }
        };

        if max_val > 0 && bar_height >= 2 {
            // Max label at top of bar area
            draw_label(buf, max_val, chart_area.y);

            // Mid label only if bar area is tall enough
            if bar_height > 2 {
                let mid_val = max_val / 2;
                draw_label(buf, mid_val, chart_area.y + (bar_height - 1) / 2);
            }
        }

        // Draw vertical axis line
        if chart_area.height > 0 {
            let axis_x = la.x + LABEL_W - 1;
            // Connect to parent block's TOP border
            if let Some(cell) = buf.cell_mut((axis_x, chunks[1].y)) {
                cell.set_symbol("├").set_style(label_style);
            }
            // Vertical line for bar area
            for row in chart_area.y..=(chart_area.y + chart_area.height.saturating_sub(1)) {
                if let Some(cell) = buf.cell_mut((axis_x, row)) {
                    cell.set_symbol("│").set_style(label_style);
                }
            }
        }
    }

    // Draw ├ and ┤ on the outer panel border at the divider row
    let border_style = Style::default().fg(Color::DarkGray);
    let y = chunks[1].y;
    let buf = f.buffer_mut();
    if let Some(cell) = buf.cell_mut((area.x, y)) {
        cell.set_symbol("├").set_style(border_style);
    }
    if let Some(cell) = buf.cell_mut((area.x + area.width - 1, y)) {
        cell.set_symbol("┤").set_style(border_style);
    }

    // Draw title on the divider row, right after ├
    let title = " Latency ";
    let mut tmp = [0u8; 4];
    for (i, ch) in title.chars().enumerate() {
        let s = ch.encode_utf8(&mut tmp);
        if let Some(cell) = buf.cell_mut((area.x + 1 + i as u16, y)) {
            cell.set_symbol(s).set_style(border_style);
        }
    }
}

// ── Event log (adaptive columns based on width) ─────────────────────────────

fn render_event_log(
    f: &mut Frame,
    state: &AppState,
    area: Rect,
    areas: &mut UiAreas,
    filtered: &[usize],
) {
    let wide = area.width > 60;

    let border_color = if state.focused_panel == FocusedPanel::EventLog {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .title(" Event Log ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);

    if state.event_log.is_empty() {
        areas.event_log_area = Some(inner);
        let msg = Paragraph::new("  No events yet...")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        f.render_widget(msg, area);
        return;
    }

    // Render border separately; table is drawn blockless into inner
    f.render_widget(block, area);

    let header = if wide {
        Row::new(vec![
            Cell::from("Time"),
            Cell::from("Process"),
            Cell::from("Target"),
            Cell::from("Kind"),
            Cell::from("Latency"),
            Cell::from("Tokens"),
        ])
    } else {
        Row::new(vec![
            Cell::from("Time"),
            Cell::from("Target"),
            Cell::from("Lat"),
        ])
    }
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    let full_inner_height = inner.height.saturating_sub(1) as usize; // minus header

    let total = filtered.len();

    let (viewport_start, data_rows, show_top, show_bottom) =
        resolve_scroll_indicators(full_inner_height, inner.height, total, |h| {
            state.viewport_start_for(filtered, h)
        });

    let rows: Vec<Row> = (viewport_start..viewport_start + data_rows)
        .filter_map(|display_row| {
            if display_row >= total {
                return None;
            }
            let idx = filtered[total - 1 - display_row];
            let e = &state.event_log[idx];

            let time = format_short_ts(&e.ts);
            let model_short = if e.kind == CallKind::McpCall {
                e.model.clone()
            } else {
                shorten_model(&e.model)
            };

            let is_selected = idx == state.selected_event;

            let row = if wide {
                let tokens = if e.kind == CallKind::McpCall {
                    match (e.request_bytes, e.response_bytes) {
                        (None, None) => "-".to_string(),
                        (req, resp) => {
                            format_bytes(req.unwrap_or(0) as u64 + resp.unwrap_or(0) as u64)
                        }
                    }
                } else {
                    format!(
                        "{}/{}",
                        e.input_tokens
                            .map_or("-".to_string(), |t| format_number_short(t as u64)),
                        e.output_tokens
                            .map_or("-".to_string(), |t| format_number_short(t as u64)),
                    )
                };
                let kind_style = match e.kind {
                    CallKind::ToolUse => Style::default().fg(Color::Yellow),
                    CallKind::McpCall => Style::default().fg(Color::Magenta),
                    CallKind::LlmCall => Style::default().fg(Color::White),
                };

                Row::new(vec![
                    Cell::from(time.clone()).style(Style::default().fg(Color::DarkGray)),
                    Cell::from(e.process.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(model_short).style(Style::default().fg(provider_color(&e.provider))),
                    Cell::from(e.kind.as_str()).style(kind_style),
                    Cell::from(format!("{:.1}s", e.latency_ms as f64 / 1000.0))
                        .style(Style::default().fg(Color::White)),
                    Cell::from(tokens).style(Style::default().fg(Color::DarkGray)),
                ])
            } else {
                let marker = if is_selected { ">" } else { " " };

                Row::new(vec![
                    Cell::from(format!("{}{}", marker, time))
                        .style(Style::default().fg(Color::DarkGray)),
                    Cell::from(model_short).style(Style::default().fg(provider_color(&e.provider))),
                    Cell::from(format!("{:.1}s", e.latency_ms as f64 / 1000.0))
                        .style(Style::default().fg(Color::White)),
                ])
            };

            let row = if is_selected {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            };

            Some(row)
        })
        .collect();

    let widths: Vec<Constraint> = if wide {
        vec![
            Constraint::Length(12),
            Constraint::Min(10),
            Constraint::Min(8),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Min(5),
        ]
    } else {
        vec![
            Constraint::Length(13),
            Constraint::Min(6),
            Constraint::Length(6),
        ]
    };

    // Render header into first row, data table into sub-rect below (skipping indicator rows)
    let header_rect = Rect::new(inner.x, inner.y, inner.width, 1);
    f.render_widget(
        Table::new(Vec::<Row>::new(), widths.clone()).header(header),
        header_rect,
    );

    let data_y = inner.y + 1 + show_top as u16;
    let data_rect = Rect::new(inner.x, data_y, inner.width, data_rows as u16);
    f.render_widget(Table::new(rows, widths), data_rect);

    areas.event_log_area = Some(data_rect);

    // Draw indicators on their dedicated (empty) rows
    draw_scroll_indicators(f.buffer_mut(), inner, inner.y + 1, show_top, show_bottom);
}

// ── Detail pane (split mode, right panel) ────────────────────────────────────

fn render_detail_pane(f: &mut Frame, state: &AppState, area: Rect, areas: &mut UiAreas) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tab bar
            Constraint::Min(1),    // content
        ])
        .split(area);

    render_detail_tab_bar(f, state, chunks[0], areas);
    render_detail_content(f, state, chunks[1]);
}

fn render_detail_tab_bar(f: &mut Frame, state: &AppState, area: Rect, areas: &mut UiAreas) {
    let tab_style = |tab: DetailTab| -> Style {
        if state.detail_tab == tab {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    };

    let req_label = " Request ";
    let resp_label = " Response ";
    let det_label = " Details ";

    let tab_bar = Line::from(vec![
        Span::raw(" "),
        Span::styled(req_label, tab_style(DetailTab::Request)),
        Span::raw("  "),
        Span::styled(resp_label, tab_style(DetailTab::Response)),
        Span::raw("  "),
        Span::styled(det_label, tab_style(DetailTab::Details)),
    ]);

    // Calculate tab areas for mouse clicks
    let x = area.x;
    let y = area.y;
    let req_start = x + 1;
    let req_width = req_label.len() as u16;
    let resp_start = req_start + req_width + 2;
    let resp_width = resp_label.len() as u16;
    let det_start = resp_start + resp_width + 2;
    let det_width = det_label.len() as u16;

    areas.detail_tab_areas[0] = Some(Rect::new(req_start, y, req_width, 1));
    areas.detail_tab_areas[1] = Some(Rect::new(resp_start, y, resp_width, 1));
    areas.detail_tab_areas[2] = Some(Rect::new(det_start, y, det_width, 1));

    f.render_widget(
        Paragraph::new(tab_bar).style(Style::default().bg(Color::DarkGray)),
        area,
    );
}

fn render_detail_content(f: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let content_lines = match state.detail_tab {
        DetailTab::Request => build_request_tab(state),
        DetailTab::Response => build_response_tab(state),
        DetailTab::Details => build_details_tab(state),
    };

    let paragraph = Paragraph::new(content_lines).wrap(Wrap { trim: false });
    let total_visual_lines = paragraph.line_count(inner.width);
    let max_scroll = total_visual_lines.saturating_sub(inner.height as usize);
    let scroll = state.detail_scroll.min(max_scroll);
    let paragraph = paragraph.scroll((scroll as u16, 0));
    f.render_widget(paragraph, inner);

    // Scrollbar
    let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
    f.render_stateful_widget(scrollbar, inner, &mut scrollbar_state);
}

// ── Footer hints ─────────────────────────────────────────────────────────────

fn render_footer(f: &mut Frame, state: &AppState, area: Rect) {
    let line = if state.filter_active {
        Line::from(vec![
            Span::styled(" / ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}_", state.filter_text),
                Style::default().fg(Color::White),
            ),
        ])
    } else if state.detail_open {
        let mut spans = vec![
            Span::styled(" ↑/↓", Style::default().fg(Color::Cyan)),
            Span::styled(": navigate  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::styled(": switch tab  ", Style::default().fg(Color::DarkGray)),
            Span::styled("PgUp/Dn", Style::default().fg(Color::Cyan)),
            Span::styled(": scroll  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Cyan)),
            Span::styled(": close  ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::styled(": quit", Style::default().fg(Color::DarkGray)),
        ];
        if !state.filter_text.is_empty() {
            spans.push(Span::styled(
                "  filter: ",
                Style::default().fg(Color::Yellow),
            ));
            spans.push(Span::styled(
                state.filter_text.clone(),
                Style::default().fg(Color::White),
            ));
        }
        Line::from(spans)
    } else {
        let mut spans = vec![
            Span::styled(" ↑/↓", Style::default().fg(Color::Cyan)),
            Span::styled(": navigate  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::styled(": switch panel  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::styled(
                if state.focused_panel == FocusedPanel::AgentList {
                    ": filter agent  "
                } else {
                    ": open detail  "
                },
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("/", Style::default().fg(Color::Cyan)),
            Span::styled(": filter  ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::styled(": quit", Style::default().fg(Color::DarkGray)),
        ];
        if !state.filter_text.is_empty() {
            spans.push(Span::styled(
                "  filter: ",
                Style::default().fg(Color::Yellow),
            ));
            spans.push(Span::styled(
                state.filter_text.clone(),
                Style::default().fg(Color::White),
            ));
            spans.push(Span::styled("  Esc", Style::default().fg(Color::Cyan)));
            spans.push(Span::styled(
                ": clear",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Line::from(spans)
    };

    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::DarkGray)),
        area,
    );
}

// ── Tab content builders ─────────────────────────────────────────────────────

fn build_request_tab(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let http = match &state.detail_http {
        Some(h) => h,
        None => {
            lines.push(Line::styled(
                " Body data unavailable (expired or missing).",
                Style::default().fg(Color::Yellow),
            ));
            return lines;
        }
    };

    // Method + path
    lines.push(Line::from(vec![Span::styled(
        format!(" {} {}", http.request_method, http.request_path),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::raw(""));

    // Headers
    lines.push(Line::styled(
        " Headers",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    render_headers(&http.request_headers, &mut lines);
    lines.push(Line::raw(""));

    // Body
    lines.push(Line::styled(
        " Body",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    render_body_content(&http.request_body, false, &mut lines);

    lines
}

fn build_response_tab(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let (event, http) = match (&state.detail_event, &state.detail_http) {
        (Some(e), Some(h)) => (e, h),
        (Some(_), None) => {
            lines.push(Line::styled(
                " Body data unavailable (expired or missing).",
                Style::default().fg(Color::Yellow),
            ));
            return lines;
        }
        _ => return lines,
    };

    // Status line
    if http.response_status == 0 {
        lines.push(Line::styled(
            " (no HTTP status \u{2014} pipe/stdio)",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        let status_color = match http.response_status {
            200..=299 => Color::Green,
            400..=499 => Color::Yellow,
            _ => Color::Red,
        };
        lines.push(Line::from(vec![Span::styled(
            format!(
                " {} {}",
                http.response_status,
                status_phrase(http.response_status)
            ),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )]));
    }
    lines.push(Line::raw(""));

    // Headers
    lines.push(Line::styled(
        " Headers",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    render_headers(&http.response_headers, &mut lines);
    lines.push(Line::raw(""));

    // Body
    lines.push(Line::styled(
        " Body",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    render_body_content(&http.response_body, event.streaming, &mut lines);

    lines
}

fn build_details_tab(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let event = match &state.detail_event {
        Some(e) => e,
        None => return lines,
    };

    let kv = |key: &str, val: String| -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!("   {:<18}", key),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(val, Style::default().fg(Color::White)),
        ])
    };

    lines.push(Line::raw(""));
    lines.push(kv("Provider", event.provider.clone()));
    lines.push(kv("Target", event.model.clone()));
    lines.push(kv("Kind", event.kind.as_str().to_string()));
    lines.push(kv("Streaming", event.streaming.to_string()));
    lines.push(kv("Stop reason", event.stop_reason.clone()));
    lines.push(Line::raw(""));

    lines.push(kv(
        "Input tokens",
        event.input_tokens.map_or("-".into(), |t| t.to_string()),
    ));
    lines.push(kv(
        "Output tokens",
        event.output_tokens.map_or("-".into(), |t| t.to_string()),
    ));
    if let Some(cc) = event.cache_creation_input_tokens {
        lines.push(kv("Cache creation", cc.to_string()));
    }
    if let Some(cr) = event.cache_read_input_tokens {
        lines.push(kv("Cache read", cr.to_string()));
    }
    if let Some(rb) = event.request_bytes {
        lines.push(kv("Request size", format_bytes(rb as u64)));
    }
    if let Some(rb) = event.response_bytes {
        lines.push(kv("Response size", format_bytes(rb as u64)));
    }
    lines.push(Line::raw(""));

    lines.push(kv(
        "Latency",
        format!("{:.1}s", event.latency_ms as f64 / 1000.0),
    ));
    if let Some(ttft) = event.ttft_ms {
        lines.push(kv("TTFT", format!("{:.1}s", ttft as f64 / 1000.0)));
    }
    lines.push(kv("Timestamp", event.ts.clone()));
    lines.push(Line::raw(""));

    lines.push(kv("Server", event.server_address.clone()));
    lines.push(kv("PID", event.pid.to_string()));
    lines.push(kv("Process", event.process.clone()));
    lines.push(kv("ID", event.id.clone()));

    if !event.tools.is_empty() {
        lines.push(Line::raw(""));
        lines.push(kv("Tools", event.tools.join(", ")));
    }

    lines
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const SENSITIVE_HEADERS: &[&str] = &["x-api-key", "authorization", "api-key"];

fn render_headers(headers: &[(String, String)], lines: &mut Vec<Line<'static>>) {
    for (name, value) in headers {
        let display_value = if SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str()) {
            mask_header_value(value)
        } else {
            value.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("   {}: ", name),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(display_value, Style::default().fg(Color::White)),
        ]));
    }
}

fn mask_header_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        "****".into()
    } else {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}...{}", prefix, suffix)
    }
}

fn render_body_content(body: &str, is_streaming: bool, lines: &mut Vec<Line<'static>>) {
    if body.is_empty() {
        lines.push(Line::styled(
            "   (empty)",
            Style::default().fg(Color::DarkGray),
        ));
        return;
    }

    if is_streaming && body.contains("event:") {
        // SSE format
        render_sse_body(body, lines);
    } else if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        // Pretty-printed JSON with syntax coloring
        render_json_value(&json, 1, lines);
    } else {
        // Raw text
        for line in body.lines() {
            lines.push(Line::styled(
                format!("   {}", line),
                Style::default().fg(Color::White),
            ));
        }
    }
}

fn render_sse_body(body: &str, lines: &mut Vec<Line<'static>>) {
    for line in body.lines() {
        if line.starts_with("event:") {
            lines.push(Line::from(vec![Span::styled(
                format!("   {}", line),
                Style::default().fg(Color::Cyan),
            )]));
        } else if line.starts_with("data:") {
            let payload = line
                .strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
                .unwrap_or("");
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) {
                lines.push(Line::from(vec![Span::styled(
                    "   data:",
                    Style::default().fg(Color::Green),
                )]));
                render_json_value(&json, 2, lines);
            } else {
                lines.push(Line::from(vec![Span::styled(
                    format!("   {}", line),
                    Style::default().fg(Color::Green),
                )]));
            }
        } else if line.is_empty() {
            lines.push(Line::raw(""));
        } else {
            lines.push(Line::styled(
                format!("   {}", line),
                Style::default().fg(Color::White),
            ));
        }
    }
}

/// Recursively render a JSON value with syntax coloring.
fn render_json_value(value: &serde_json::Value, indent: usize, lines: &mut Vec<Line<'static>>) {
    let pad = "   ".to_string() + &"  ".repeat(indent);
    let pad_inner = "   ".to_string() + &"  ".repeat(indent + 1);

    match value {
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                lines.push(Line::from(vec![Span::styled(
                    format!("{}{{}}", &pad[..pad.len().saturating_sub(2)]),
                    Style::default().fg(Color::DarkGray),
                )]));
                return;
            }
            lines.push(Line::from(vec![Span::styled(
                format!("{}{{", &pad[..pad.len().saturating_sub(2)]),
                Style::default().fg(Color::DarkGray),
            )]));
            let len = map.len();
            for (i, (key, val)) in map.iter().enumerate() {
                let comma = if i < len - 1 { "," } else { "" };
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("{}\"{}\"", pad_inner, key),
                                Style::default().fg(Color::Cyan),
                            ),
                            Span::styled(": ", Style::default().fg(Color::DarkGray)),
                        ]));
                        render_json_value(val, indent + 1, lines);
                        // Add comma to last line of nested value
                        if !comma.is_empty() {
                            if let Some(last) = lines.last_mut() {
                                last.spans.push(Span::styled(
                                    comma.to_string(),
                                    Style::default().fg(Color::DarkGray),
                                ));
                            }
                        }
                    }
                    _ => {
                        let mut spans = vec![
                            Span::styled(
                                format!("{}\"{}\"", pad_inner, key),
                                Style::default().fg(Color::Cyan),
                            ),
                            Span::styled(": ", Style::default().fg(Color::DarkGray)),
                        ];
                        spans.extend(value_spans(val));
                        spans.push(Span::styled(
                            comma.to_string(),
                            Style::default().fg(Color::DarkGray),
                        ));
                        lines.push(Line::from(spans));
                    }
                }
            }
            lines.push(Line::from(vec![Span::styled(
                format!("{}}}", pad),
                Style::default().fg(Color::DarkGray),
            )]));
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                lines.push(Line::from(vec![Span::styled(
                    format!("{}[]", &pad[..pad.len().saturating_sub(2)]),
                    Style::default().fg(Color::DarkGray),
                )]));
                return;
            }
            lines.push(Line::from(vec![Span::styled(
                format!("{}[", &pad[..pad.len().saturating_sub(2)]),
                Style::default().fg(Color::DarkGray),
            )]));
            let len = arr.len();
            for (i, val) in arr.iter().enumerate() {
                let comma = if i < len - 1 { "," } else { "" };
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        render_json_value(val, indent + 1, lines);
                        if !comma.is_empty() {
                            if let Some(last) = lines.last_mut() {
                                last.spans.push(Span::styled(
                                    comma.to_string(),
                                    Style::default().fg(Color::DarkGray),
                                ));
                            }
                        }
                    }
                    _ => {
                        let mut spans = vec![Span::styled(pad_inner.clone(), Style::default())];
                        spans.extend(value_spans(val));
                        spans.push(Span::styled(
                            comma.to_string(),
                            Style::default().fg(Color::DarkGray),
                        ));
                        lines.push(Line::from(spans));
                    }
                }
            }
            lines.push(Line::from(vec![Span::styled(
                format!("{}]", pad),
                Style::default().fg(Color::DarkGray),
            )]));
        }
        _ => {
            let mut spans = vec![Span::styled(pad, Style::default())];
            spans.extend(value_spans(value));
            lines.push(Line::from(spans));
        }
    }
}

/// Return styled spans for a JSON scalar value.
fn value_spans(value: &serde_json::Value) -> Vec<Span<'static>> {
    match value {
        serde_json::Value::String(s) => {
            // Truncate very long strings for display
            let display = if s.len() > 200 {
                let end = s.floor_char_boundary(200);
                format!("\"{}...\"", &s[..end])
            } else {
                format!("\"{}\"", s)
            };
            vec![Span::styled(display, Style::default().fg(Color::Green))]
        }
        serde_json::Value::Number(n) => {
            vec![Span::styled(
                n.to_string(),
                Style::default().fg(Color::Yellow),
            )]
        }
        serde_json::Value::Bool(b) => {
            vec![Span::styled(
                b.to_string(),
                Style::default().fg(Color::Magenta),
            )]
        }
        serde_json::Value::Null => {
            vec![Span::styled(
                "null".to_string(),
                Style::default().fg(Color::Magenta),
            )]
        }
        _ => vec![Span::raw(value.to_string())],
    }
}

fn status_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

// ── Shared utilities ─────────────────────────────────────────────────────────

// "openai" = any OpenAI-compatible API (matches /v1/chat/completions)
fn provider_color(provider: &str) -> Color {
    match provider {
        "anthropic" => Color::Cyan,
        "openai" => Color::Green,
        "google" => Color::Yellow,
        "mcp" => Color::Magenta,
        _ => Color::White,
    }
}

fn shorten_model(model: &str) -> String {
    if model.contains("opus-4-6") {
        "opus-4.6".into()
    } else if model.contains("sonnet-4-6") {
        "sonnet-4.6".into()
    } else if model.contains("opus-4") {
        "opus-4".into()
    } else if model.contains("sonnet-4") {
        "sonnet-4".into()
    } else if model.contains("haiku-4-5") {
        "haiku-4.5".into()
    } else if model.contains("haiku-4") {
        "haiku-4".into()
    } else if model.contains("sonnet-3") || model.contains("3-5-sonnet") {
        "sonnet-3.5".into()
    } else if model.starts_with("gpt-4o-mini") {
        "gpt-4o-mini".into()
    } else if model.starts_with("gpt-4o") {
        "gpt-4o".into()
    } else if model.starts_with("gpt-4") {
        "gpt-4".into()
    } else if model.starts_with("o1") || model.starts_with("o3") || model.starts_with("o4") {
        model.split('-').take(2).collect::<Vec<_>>().join("-")
    } else {
        // fallback: take first 3 segments
        model.split('-').take(3).collect::<Vec<_>>().join("-")
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = secs % 86400 / 3600;
    let mins = secs % 3600 / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{}d{:02}h", days, hours)
    } else if hours > 0 {
        format!("{}h{:02}m", hours, mins)
    } else if mins > 0 {
        format!("{}m{:02}s", mins, s)
    } else {
        format!("{}s", s)
    }
}

fn format_short_ts(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.format("%b %-d %H:%M").to_string())
        .unwrap_or_else(|_| ts.to_string())
}

fn format_number_impl(n: u64, compact: bool) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        if compact {
            format!("{:.1}k", n as f64 / 1_000.0)
        } else {
            format!("{},{:03}", n / 1_000, n % 1_000)
        }
    } else {
        n.to_string()
    }
}

fn format_number(n: u64) -> String {
    format_number_impl(n, false)
}

fn format_number_short(n: u64) -> String {
    format_number_impl(n, true)
}

fn format_bytes(n: u64) -> String {
    if n >= 1_073_741_824 {
        format!("{:.1} GB", n as f64 / 1_073_741_824.0)
    } else if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_color() {
        assert_eq!(provider_color("anthropic"), Color::Cyan);
        assert_eq!(provider_color("openai"), Color::Green);
        assert_eq!(provider_color("mcp"), Color::Magenta);
        assert_eq!(provider_color("something_else"), Color::White);
    }

    #[test]
    fn test_shorten_model_anthropic() {
        assert_eq!(shorten_model("claude-sonnet-4-6"), "sonnet-4.6");
        assert_eq!(shorten_model("claude-sonnet-4-20250514"), "sonnet-4");
        assert_eq!(shorten_model("claude-haiku-4-5-20251001"), "haiku-4.5");
        assert_eq!(shorten_model("claude-opus-4-6"), "opus-4.6");
        assert_eq!(shorten_model("claude-opus-4-20250514"), "opus-4");
        assert_eq!(shorten_model("claude-3-5-sonnet-20241022"), "sonnet-3.5");
    }

    #[test]
    fn test_shorten_model_openai() {
        assert_eq!(shorten_model("gpt-4o-mini-2024-07-18"), "gpt-4o-mini");
        assert_eq!(shorten_model("gpt-4o"), "gpt-4o");
        assert_eq!(shorten_model("gpt-4-turbo"), "gpt-4");
    }

    #[test]
    fn test_shorten_model_reasoning() {
        assert_eq!(shorten_model("o3-mini-2025-01-31"), "o3-mini");
        assert_eq!(shorten_model("o1-preview"), "o1-preview");
        assert_eq!(shorten_model("o4-mini-2025-04-16"), "o4-mini");
    }

    #[test]
    fn test_shorten_model_fallback() {
        assert_eq!(shorten_model(""), "");
        assert_eq!(shorten_model("some-unknown-model-v2"), "some-unknown-model");
    }

    #[test]
    fn test_round_nice() {
        assert_eq!(round_nice(0), 0);
        assert_eq!(round_nice(5), 5);
        assert_eq!(round_nice(9), 9);
        assert_eq!(round_nice(10), 10);
        assert_eq!(round_nice(42), 42);
        assert_eq!(round_nice(128), 130);
        assert_eq!(round_nice(999), 1000);
        assert_eq!(round_nice(1000), 1000);
        assert_eq!(round_nice(1284), 1300);
        assert_eq!(round_nice(5000), 5000);
        assert_eq!(round_nice(12847), 13000);
        assert_eq!(round_nice(99999), 100000);
        assert_eq!(round_nice(100000), 100000);
        assert_eq!(round_nice(1_500_000), 1_500_000);
    }

    #[test]
    fn test_format_axis_label() {
        assert_eq!(format_axis_label(0), "0");
        assert_eq!(format_axis_label(5), "<.01s");
        assert_eq!(format_axis_label(42), "0.04s");
        assert_eq!(format_axis_label(500), "0.50s");
        assert_eq!(format_axis_label(1284), "1.3s");
        assert_eq!(format_axis_label(12847), "13s");
        assert_eq!(format_axis_label(50000), "50s");
        assert_eq!(format_axis_label(10), "0.01s");
        assert_eq!(format_axis_label(9999), "10s");
        assert_eq!(format_axis_label(10000), "10s");
        assert_eq!(format_axis_label(130_000), "130s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_572_864), "1.5 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
        assert_eq!(format_bytes(2_684_354_560), "2.5 GB");
    }

    #[test]
    fn test_format_short_ts() {
        assert_eq!(format_short_ts("2025-03-03T14:30:45.000Z"), "Mar 3 14:30");
        assert_eq!(format_short_ts("2025-12-25T09:05:00.000Z"), "Dec 25 09:05");
        assert_eq!(format_short_ts("bad"), "bad");
        // Invalid month values fall back gracefully
        assert_eq!(
            format_short_ts("2025-00-03T14:30:45.000Z"),
            "2025-00-03T14:30:45.000Z"
        );
        assert_eq!(
            format_short_ts("2025-13-03T14:30:45.000Z"),
            "2025-13-03T14:30:45.000Z"
        );
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(42), "42s");
        assert_eq!(format_uptime(65), "1m05s");
        assert_eq!(format_uptime(3661), "1h01m");
        assert_eq!(format_uptime(90061), "1d01h");
    }
}
