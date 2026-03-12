use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use indexmap::map::Entry;
use indexmap::IndexMap;
use ratatui::layout::{Position, Rect};

use crate::body_store::BodyStore;
use crate::output::{AgentEvent, CallKind};
use crate::providers::HttpDetail;

fn load_body(event: &AgentEvent) -> Option<HttpDetail> {
    event
        .body_path
        .as_ref()
        .and_then(|p| BodyStore::read(Path::new(p)).ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPanel {
    EventLog,
    AgentList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Request,
    Response,
    Details,
}

#[derive(Default, Clone)]
pub struct UiAreas {
    pub event_log_area: Option<Rect>,
    pub detail_tab_areas: [Option<Rect>; 3],
    pub agent_list_area: Option<Rect>,
    /// Full inner rect for scroll hit-testing (includes header + indicator rows).
    pub agent_list_scroll_area: Option<Rect>,
}

pub struct GlobalStats {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub api_calls: u64,
    pub mcp_calls: u64,
    pub started: Instant,
}

impl GlobalStats {
    fn new() -> Self {
        Self {
            total_input_tokens: 0,
            total_output_tokens: 0,
            api_calls: 0,
            mcp_calls: 0,
            started: Instant::now(),
        }
    }

    fn update(&mut self, event: &AgentEvent) {
        self.total_input_tokens += event.input_tokens.unwrap_or(0) as u64;
        self.total_output_tokens += event.output_tokens.unwrap_or(0) as u64;
        if event.kind == CallKind::McpCall {
            self.mcp_calls += 1;
        } else {
            self.api_calls += 1;
        }
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.started.elapsed()
    }
}

const MAX_LATENCIES: usize = 1000;

pub fn agent_label(process: &str, pid: u32) -> String {
    format!("{} ({})", process, pid)
}

pub struct AgentStats {
    pub pid: u32,
    pub process: String,
    pub api_calls: u64,
    pub mcp_calls: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub has_llm_calls: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub latencies: VecDeque<u64>,
    latency_sum: u64,
}

impl AgentStats {
    fn new(event: &AgentEvent) -> Self {
        Self {
            pid: event.pid,
            process: event.process.clone(),
            api_calls: 0,
            mcp_calls: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_request_bytes: 0,
            total_response_bytes: 0,
            has_llm_calls: false,
            first_seen: event.ts.clone(),
            last_seen: event.ts.clone(),
            latencies: VecDeque::new(),
            latency_sum: 0,
        }
    }

    fn update(&mut self, event: &AgentEvent) {
        if event.kind == CallKind::McpCall {
            self.mcp_calls += 1;
        } else {
            self.api_calls += 1;
        }
        self.total_input_tokens += event.input_tokens.unwrap_or(0) as u64;
        self.total_output_tokens += event.output_tokens.unwrap_or(0) as u64;
        self.total_request_bytes += event.request_bytes.unwrap_or(0) as u64;
        self.total_response_bytes += event.response_bytes.unwrap_or(0) as u64;
        if !self.has_llm_calls && event.kind != CallKind::McpCall {
            self.has_llm_calls = true;
        }
        self.last_seen = event.ts.clone();
        if self.latencies.len() >= MAX_LATENCIES {
            self.latency_sum -= self.latencies.pop_front().unwrap();
        }
        self.latency_sum += event.latency_ms;
        self.latencies.push_back(event.latency_ms);
    }

    pub fn label(&self) -> String {
        agent_label(&self.process, self.pid)
    }

    /// Rolling average of last N calls.
    pub fn avg_latency_ms(&self) -> u64 {
        if self.latencies.is_empty() {
            return 0;
        }
        self.latency_sum / self.latencies.len() as u64
    }
}

pub struct AppState {
    // data
    pub agents: IndexMap<(u32, String), AgentStats>,
    pub global: GlobalStats,
    pub event_log: VecDeque<AgentEvent>,
    event_log_capacity: usize,
    // connection status (for TUI reconnect indicator)
    pub connected: bool,
    // navigation
    pub focused_panel: FocusedPanel,
    pub selected_agent: usize,
    /// Absolute VecDeque index of the selected event (0 = oldest, len-1 = newest).
    pub selected_event: usize,
    /// Whether the cursor is following the newest event (auto-scroll).
    follow_mode: bool,
    // detail view
    pub detail_open: bool,
    pub detail_tab: DetailTab,
    pub detail_scroll: usize,
    pub detail_event: Option<AgentEvent>,
    pub detail_http: Option<HttpDetail>,
    // debounced body loading
    detail_dirty: bool,
    detail_last_load: Instant,
    // ui areas for mouse clicks
    pub areas: UiAreas,
    // filter
    pub filter_text: String,
    pub filter_active: bool,
    // backfill mode (server sends oldest-first, push_back preserves chronological order)
    backfilling: bool,
}

impl AppState {
    pub fn new(event_log_capacity: usize) -> Self {
        Self {
            agents: IndexMap::new(),
            global: GlobalStats::new(),
            event_log: VecDeque::with_capacity(event_log_capacity),
            event_log_capacity,
            connected: false,
            focused_panel: FocusedPanel::EventLog,
            selected_agent: 0,
            selected_event: 0,
            follow_mode: true,
            detail_open: false,
            detail_tab: DetailTab::Request,
            detail_scroll: 0,
            detail_event: None,
            detail_http: None,
            detail_dirty: false,
            detail_last_load: Instant::now(),
            areas: UiAreas::default(),
            filter_text: String::new(),
            filter_active: false,
            backfilling: false,
        }
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    pub fn start_backfill(&mut self) {
        self.backfilling = true;
    }

    pub fn is_backfilling(&self) -> bool {
        self.backfilling
    }

    pub fn end_backfill(&mut self) {
        self.backfilling = false;
        self.selected_event = self.event_log.len().saturating_sub(1);
        self.follow_mode = true;
        // Replay stats from the now-chronological event_log
        for i in 0..self.event_log.len() {
            let event = &self.event_log[i];
            self.global.update(event);
            let key = (event.pid, event.process.clone());
            self.agents
                .entry(key)
                .or_insert_with(|| AgentStats::new(event))
                .update(event);
        }
        // Pin agent cursor on newest (must be after replay populates agents)
        self.selected_agent = self.agents.len().saturating_sub(1);
    }

    pub fn ingest(&mut self, event: AgentEvent) {
        if self.backfilling {
            // Backfill mode: only insert into deque, skip stats
            // Server sends oldest-first → push_back preserves chronological order
            self.event_log.push_back(event);
            return;
        }

        // Live mode: existing logic unchanged
        self.global.update(&event);
        let key = (event.pid, event.process.clone());
        let entry = self.agents.entry(key);
        let is_new_agent = matches!(&entry, Entry::Vacant(_));
        entry
            .or_insert_with(|| AgentStats::new(&event))
            .update(&event);

        if is_new_agent {
            self.selected_agent = self.agents.len() - 1;
        }

        // Track whether cursor was on newest before insertion
        let was_at_newest = self.follow_mode
            || self.event_log.is_empty()
            || self.selected_event == self.event_log.len().saturating_sub(1);

        // Evict oldest if at capacity
        let evicted = if self.event_log.len() >= self.event_log_capacity {
            self.event_log.pop_front();
            true
        } else {
            false
        };

        self.event_log.push_back(event);

        if was_at_newest {
            // Follow mode: cursor stays on newest
            self.selected_event = self.event_log.len().saturating_sub(1);
            self.follow_mode = true;
        } else if evicted {
            // Clamp cursor when front was evicted
            self.selected_event = self.selected_event.saturating_sub(1);
        }
    }

    /// Returns indices (into event_log VecDeque) of events matching the current filter.
    /// Returns all indices if filter_text is empty.
    pub fn filtered_indices(&self) -> Vec<usize> {
        if self.filter_text.is_empty() {
            return (0..self.event_log.len()).collect();
        }
        let needle = self.filter_text.to_lowercase();
        (0..self.event_log.len())
            .filter(|&i| {
                let e = &self.event_log[i];
                e.model.to_lowercase().contains(&needle)
                    || e.provider.to_lowercase().contains(&needle)
                    || e.process.to_lowercase().contains(&needle)
                    || e.stop_reason.to_lowercase().contains(&needle)
                    || e.kind.as_str().contains(&needle)
                    || agent_label(&e.process, e.pid)
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect()
    }

    fn select_event(&mut self, idx: usize) {
        self.selected_event = idx;
        self.follow_mode = idx == self.event_log.len().saturating_sub(1);
        if self.detail_open {
            self.detail_dirty = true;
        }
    }

    fn reset_selection_to_newest_visible(&mut self) {
        let filtered = self.filtered_indices();
        if let Some(&last) = filtered.last() {
            self.select_event(last);
        }
    }

    /// Compute the viewport for the filtered event log.
    /// Returns (filtered_indices, viewport_start). Returns empty vec if nothing visible.
    pub fn compute_viewport(&self, inner_height: usize) -> (Vec<usize>, usize) {
        let filtered = self.filtered_indices();
        let vs = self.viewport_start_for(&filtered, inner_height);
        (filtered, vs)
    }

    /// Compute viewport_start for pre-computed filtered indices (avoids redundant allocation).
    pub fn viewport_start_for(&self, filtered: &[usize], inner_height: usize) -> usize {
        let total = filtered.len();
        if total == 0 || inner_height == 0 {
            return 0;
        }
        let sel_pos = filtered
            .iter()
            .rposition(|&i| i <= self.selected_event)
            .unwrap_or(0);
        let selected_display_row = total.saturating_sub(1).saturating_sub(sel_pos);
        if selected_display_row < inner_height {
            0
        } else {
            selected_display_row - inner_height + 1
        }
    }

    /// Navigate by `steps` visible events in the given direction within filtered indices.
    /// `forward` = true means toward newer (higher index), false means toward older.
    /// Computes filtered indices once instead of looping single-step navigation.
    fn navigate_filtered_by(&mut self, steps: usize, forward: bool) {
        if steps == 0 {
            return;
        }
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return;
        }
        let cur_pos = filtered.iter().rposition(|&i| i <= self.selected_event);

        let new_pos = if forward {
            cur_pos.map(|p| (p + steps).min(filtered.len() - 1))
        } else {
            cur_pos.map(|p| {
                // If selected_event is between filtered entries (rposition snapped),
                // the snap itself counts as one step.
                let start = if filtered[p] == self.selected_event {
                    p
                } else {
                    p + 1
                };
                start.saturating_sub(steps)
            })
        };

        if let Some(pos) = new_pos {
            self.select_event(filtered[pos]);
        }
    }

    pub fn agent_scroll_offset(&self, inner_height: usize) -> usize {
        let agent_count = self.agents.len();
        let display_index = if agent_count > 0 {
            agent_count - 1 - self.selected_agent
        } else {
            0
        };
        (display_index + 1).saturating_sub(inner_height)
    }

    pub fn set_areas(&mut self, areas: UiAreas) {
        self.areas = areas;
    }

    pub fn maybe_load_detail(&mut self) {
        if !self.detail_dirty || self.detail_last_load.elapsed() < Duration::from_millis(50) {
            return;
        }

        if self.event_log.is_empty() {
            return;
        }

        let idx = self
            .selected_event
            .min(self.event_log.len().saturating_sub(1));
        let event = self.event_log[idx].clone();
        let http_detail = load_body(&event);

        self.detail_event = Some(event);
        self.detail_http = http_detail;
        self.detail_scroll = 0;
        self.detail_dirty = false;
        self.detail_last_load = Instant::now();
    }

    pub fn handle_input(&mut self, event: Event) -> Action {
        match event {
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => {
                // Filter-active mode: capture all keys for the filter bar
                if self.filter_active {
                    match code {
                        KeyCode::Esc => {
                            self.filter_text.clear();
                            self.filter_active = false;
                            self.reset_selection_to_newest_visible();
                        }
                        KeyCode::Enter => {
                            self.filter_active = false;
                        }
                        KeyCode::Backspace => {
                            self.filter_text.pop();
                            self.reset_selection_to_newest_visible();
                        }
                        KeyCode::Char(c) => {
                            self.filter_text.push(c);
                            self.reset_selection_to_newest_visible();
                        }
                        _ => {}
                    }
                    return Action::None;
                }

                // Normal mode
                match (code, modifiers) {
                    (KeyCode::Char('q'), _) => return Action::Quit,
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Action::Quit,
                    (KeyCode::Char('/'), _) => {
                        self.filter_active = true;
                    }
                    (KeyCode::Tab, _) if !self.detail_open => {
                        self.focused_panel = match self.focused_panel {
                            FocusedPanel::EventLog => FocusedPanel::AgentList,
                            FocusedPanel::AgentList => FocusedPanel::EventLog,
                        };
                    }
                    (KeyCode::Down | KeyCode::Char('j'), _) => match self.focused_panel {
                        FocusedPanel::EventLog => self.navigate_filtered_by(1, false),
                        FocusedPanel::AgentList => {
                            self.selected_agent = self.selected_agent.saturating_sub(1);
                        }
                    },
                    (KeyCode::Up | KeyCode::Char('k'), _) => match self.focused_panel {
                        FocusedPanel::EventLog => self.navigate_filtered_by(1, true),
                        FocusedPanel::AgentList => {
                            if !self.agents.is_empty() {
                                self.selected_agent =
                                    (self.selected_agent + 1).min(self.agents.len() - 1);
                            }
                        }
                    },
                    (KeyCode::Enter, _) => {
                        if self.detail_open {
                            self.detail_open = false;
                            self.detail_event = None;
                            self.detail_http = None;
                        } else if self.focused_panel == FocusedPanel::AgentList {
                            self.filter_to_selected_agent();
                        } else {
                            self.open_detail();
                        }
                    }
                    (KeyCode::Esc, _) => {
                        if self.detail_open {
                            self.detail_open = false;
                            self.detail_event = None;
                            self.detail_http = None;
                        } else if !self.filter_text.is_empty() {
                            self.filter_text.clear();
                            self.reset_selection_to_newest_visible();
                        }
                    }
                    (KeyCode::Tab, _) if self.detail_open => {
                        self.focused_panel = FocusedPanel::EventLog;
                        self.detail_tab = match self.detail_tab {
                            DetailTab::Request => DetailTab::Response,
                            DetailTab::Response => DetailTab::Details,
                            DetailTab::Details => DetailTab::Request,
                        };
                        self.detail_scroll = 0;
                    }
                    (KeyCode::BackTab, _) if self.detail_open => {
                        self.focused_panel = FocusedPanel::EventLog;
                        self.detail_tab = match self.detail_tab {
                            DetailTab::Request => DetailTab::Details,
                            DetailTab::Response => DetailTab::Request,
                            DetailTab::Details => DetailTab::Response,
                        };
                        self.detail_scroll = 0;
                    }
                    (KeyCode::PageDown, _) if self.detail_open => {
                        self.detail_scroll += 20;
                    }
                    (KeyCode::PageUp, _) if self.detail_open => {
                        self.detail_scroll = self.detail_scroll.saturating_sub(20);
                    }
                    (KeyCode::Char('g'), _) if self.detail_open => {
                        self.detail_scroll = 0;
                    }
                    (KeyCode::Char('G'), _) if self.detail_open => {
                        self.detail_scroll = usize::MAX; // clamped on render
                    }
                    _ => {}
                }
            }
            Event::Mouse(mouse) => {
                if mouse.kind == MouseEventKind::ScrollUp
                    || mouse.kind == MouseEventKind::ScrollDown
                {
                    let scroll_up = mouse.kind == MouseEventKind::ScrollUp;

                    // If detail is open, check if mouse is over the detail pane area
                    // (right side of the event log split). Use a simple heuristic:
                    // if there's an event_log_area, anything to its right is the detail pane.
                    let over_detail = self.detail_open
                        && self
                            .areas
                            .event_log_area
                            .is_some_and(|a| mouse.column >= a.x + a.width);

                    let mouse_pos = Position::new(mouse.column, mouse.row);
                    let over_agent_list = self
                        .areas
                        .agent_list_scroll_area
                        .is_some_and(|a| a.contains(mouse_pos));

                    if over_detail {
                        // Scroll detail pane content
                        if scroll_up {
                            self.detail_scroll = self.detail_scroll.saturating_sub(3);
                        } else {
                            self.detail_scroll += 3;
                        }
                    } else if over_agent_list {
                        self.focused_panel = FocusedPanel::AgentList;
                        if !self.agents.is_empty() {
                            if scroll_up {
                                self.selected_agent =
                                    (self.selected_agent + 1).min(self.agents.len() - 1);
                            } else {
                                self.selected_agent = self.selected_agent.saturating_sub(1);
                            }
                        }
                    } else {
                        // Scroll event log (navigate events)
                        self.focused_panel = FocusedPanel::EventLog;
                        self.navigate_filtered_by(3, scroll_up);
                    }
                } else if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                    let col = mouse.column;
                    let row = mouse.row;
                    let click_pos = Position::new(col, row);

                    // Check agent list area click
                    if let Some(area) = self.areas.agent_list_area {
                        if area.contains(click_pos) && !self.agents.is_empty() {
                            self.focused_panel = FocusedPanel::AgentList;
                            let click_row = (row - area.y) as usize;
                            let scroll_offset = self.agent_scroll_offset(area.height as usize);
                            let agent_idx = (click_row + scroll_offset).min(self.agents.len() - 1);
                            self.selected_agent = self.agents.len() - 1 - agent_idx;
                        }
                    }
                    // Check event log area click
                    else if let Some(area) = self.areas.event_log_area {
                        if area.contains(click_pos) {
                            let display_row = (row - area.y) as usize;
                            let inner_height = area.height as usize;
                            let (filtered, viewport_start) = self.compute_viewport(inner_height);
                            let total = filtered.len();
                            if total > 0 {
                                let actual_display_row = viewport_start + display_row;
                                if actual_display_row < total {
                                    let idx = filtered[total - 1 - actual_display_row];
                                    self.select_event(idx);
                                }
                            }
                        }
                    }

                    // Check detail tab clicks
                    for (i, tab_area) in self.areas.detail_tab_areas.iter().enumerate() {
                        if let Some(area) = tab_area {
                            if area.contains(click_pos) {
                                self.detail_tab = match i {
                                    0 => DetailTab::Request,
                                    1 => DetailTab::Response,
                                    _ => DetailTab::Details,
                                };
                                self.detail_scroll = 0;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Action::None
    }

    fn filter_to_selected_agent(&mut self) {
        if let Some((_key, agent)) = self.agents.get_index(self.selected_agent) {
            self.filter_text = agent.label();
            self.focused_panel = FocusedPanel::EventLog;
            self.reset_selection_to_newest_visible();
        }
    }

    fn open_detail(&mut self) {
        if self.event_log.is_empty() {
            return;
        }
        let idx = self
            .selected_event
            .min(self.event_log.len().saturating_sub(1));
        let event = self.event_log[idx].clone();

        // Load body from disk immediately (no debounce for explicit open)
        let http_detail = load_body(&event);

        self.detail_event = Some(event);
        self.detail_http = http_detail;
        self.detail_tab = DetailTab::Request;
        self.detail_scroll = 0;
        self.focused_panel = FocusedPanel::EventLog;
        self.detail_open = true;
        self.detail_dirty = false;
        self.detail_last_load = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::MouseEvent;

    fn make_event(pid: u32, process: &str, kind: CallKind) -> AgentEvent {
        AgentEvent {
            pid,
            process: process.into(),
            kind,
            ..AgentEvent::test_default()
        }
    }

    #[test]
    fn test_ingest_updates_global_stats() {
        let mut state = AppState::new(100);
        state.ingest(make_event(123, "claude-code", CallKind::LlmCall));
        state.ingest(make_event(123, "claude-code", CallKind::McpCall));

        assert_eq!(state.global.api_calls, 1);
        assert_eq!(state.global.mcp_calls, 1);
        assert_eq!(state.global.total_input_tokens, 2000);
        assert_eq!(state.global.total_output_tokens, 400);
    }

    #[test]
    fn test_ingest_creates_agent_entry() {
        let mut state = AppState::new(100);
        state.ingest(make_event(123, "claude-code", CallKind::LlmCall));
        state.ingest(make_event(456, "node", CallKind::LlmCall));

        assert_eq!(state.agents.len(), 2);
        let agent = &state.agents[&(123, "claude-code".into())];
        assert_eq!(agent.api_calls, 1);
        assert_eq!(agent.mcp_calls, 0);
    }

    #[test]
    fn test_agent_byte_accumulation_and_has_llm_calls() {
        let mut state = AppState::new(100);

        // MCP-only agent
        state.ingest(make_event(100, "mcp-agent", CallKind::McpCall));
        state.ingest(make_event(100, "mcp-agent", CallKind::McpCall));
        let agent = &state.agents[&(100, "mcp-agent".into())];
        assert_eq!(agent.api_calls, 0);
        assert_eq!(agent.mcp_calls, 2);
        assert!(!agent.has_llm_calls);
        assert_eq!(agent.total_request_bytes, 512);
        assert_eq!(agent.total_response_bytes, 1024);
        assert_eq!(agent.total_input_tokens, 2000); // make_event sets 1000 per call

        // Mixed agent: starts with MCP, then LLM
        state.ingest(make_event(200, "mixed", CallKind::McpCall));
        let agent = &state.agents[&(200, "mixed".into())];
        assert!(!agent.has_llm_calls);

        state.ingest(make_event(200, "mixed", CallKind::LlmCall));
        let agent = &state.agents[&(200, "mixed".into())];
        assert!(agent.has_llm_calls);
        assert_eq!(agent.total_request_bytes, 512);
        assert_eq!(agent.total_response_bytes, 1024);

        // LLM-only agent
        state.ingest(make_event(300, "llm-agent", CallKind::LlmCall));
        let agent = &state.agents[&(300, "llm-agent".into())];
        assert!(agent.has_llm_calls);
        assert_eq!(agent.total_request_bytes, 256);
        assert_eq!(agent.total_response_bytes, 512);
    }

    #[test]
    fn test_event_log_ring_buffer() {
        let mut state = AppState::new(3);
        for i in 0..5 {
            state.ingest(make_event(i, "test", CallKind::LlmCall));
        }
        assert_eq!(state.event_log.len(), 3);
        // Oldest should be pid=2 (0 and 1 were evicted)
        assert_eq!(state.event_log[0].pid, 2);
    }

    #[test]
    fn test_handle_input_quit() {
        let mut state = AppState::new(100);
        let event = Event::Key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert_eq!(state.handle_input(event), Action::Quit);
    }

    #[test]
    fn test_handle_input_tab_cycles_detail_tabs() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "test", CallKind::LlmCall));

        // Open detail
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);
        assert_eq!(state.detail_tab, DetailTab::Request);

        // Tab cycles through tabs
        let tab = Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        state.handle_input(tab.clone());
        assert_eq!(state.detail_tab, DetailTab::Response);
        state.handle_input(tab.clone());
        assert_eq!(state.detail_tab, DetailTab::Details);
        state.handle_input(tab);
        assert_eq!(state.detail_tab, DetailTab::Request);
    }

    #[test]
    fn test_scroll_events_correct_direction() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "a", CallKind::LlmCall));
        state.ingest(make_event(2, "b", CallKind::LlmCall));
        state.ingest(make_event(3, "c", CallKind::LlmCall));

        // Initially at newest (selected_event = 2 = len-1)
        assert_eq!(state.selected_event, 2);

        // Down = visually down = toward older = decrement
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert_eq!(state.selected_event, 1);

        // Another down
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert_eq!(state.selected_event, 0);

        // Can't go past oldest
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert_eq!(state.selected_event, 0);

        // Up = visually up = toward newer = increment
        let up = Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        state.handle_input(up);
        assert_eq!(state.selected_event, 1);

        let up = Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        state.handle_input(up);
        assert_eq!(state.selected_event, 2);

        // Can't go past newest
        let up = Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        state.handle_input(up);
        assert_eq!(state.selected_event, 2);
    }

    #[test]
    fn test_enter_toggles_detail() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "test", CallKind::LlmCall));

        assert!(!state.detail_open);

        // Enter opens detail from EventLog panel
        state.focused_panel = FocusedPanel::EventLog;
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);
        assert!(state.detail_event.is_some());
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);

        // Enter closes detail
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(!state.detail_open);
        assert!(state.detail_event.is_none());
    }

    #[test]
    fn test_esc_closes_detail() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "test", CallKind::LlmCall));

        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);

        let esc = Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        state.handle_input(esc);
        assert!(!state.detail_open);
    }

    #[test]
    fn test_detail_dirty_on_scroll_while_open() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "a", CallKind::LlmCall));
        state.ingest(make_event(2, "b", CallKind::LlmCall));

        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);
        assert!(!state.detail_dirty);

        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert!(state.detail_dirty);
    }

    // ── Filter tests ──────────────────────────────────────────────────────

    fn make_event_with_model(pid: u32, process: &str, model: &str) -> AgentEvent {
        let mut e = make_event(pid, process, CallKind::LlmCall);
        e.model = model.into();
        e
    }

    #[test]
    fn test_filter_indices_empty() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "a", CallKind::LlmCall));
        state.ingest(make_event(2, "b", CallKind::LlmCall));
        let indices = state.filtered_indices();
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn test_filter_indices_matches() {
        let mut state = AppState::new(100);
        state.ingest(make_event_with_model(1, "a", "claude-sonnet-4-20250514"));
        state.ingest(make_event_with_model(2, "b", "gpt-4o"));
        state.ingest(make_event_with_model(3, "c", "claude-sonnet-4-20250514"));
        state.filter_text = "sonnet".into();
        let indices = state.filtered_indices();
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn test_filter_active_esc_clears() {
        let mut state = AppState::new(100);
        state.filter_active = true;
        state.filter_text = "son".into();

        let esc = Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        state.handle_input(esc);
        assert!(!state.filter_active);
        assert!(state.filter_text.is_empty());
    }

    #[test]
    fn test_filter_typing() {
        let mut state = AppState::new(100);
        state.filter_active = true;

        let a = Event::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        let b = Event::Key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        state.handle_input(a);
        state.handle_input(b);
        assert_eq!(state.filter_text, "ab");
    }

    #[test]
    fn test_filter_backspace() {
        let mut state = AppState::new(100);
        state.filter_active = true;
        state.filter_text = "abc".into();

        let bs = Event::Key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        state.handle_input(bs);
        assert_eq!(state.filter_text, "ab");
    }

    #[test]
    fn test_filter_enter_deactivates() {
        let mut state = AppState::new(100);
        state.filter_active = true;
        state.filter_text = "test".into();

        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(!state.filter_active);
        assert_eq!(state.filter_text, "test"); // text preserved
    }

    #[test]
    fn test_esc_precedence_filter_active() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "test", CallKind::LlmCall));

        // Open detail, then activate filter
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);

        state.filter_active = true;
        state.filter_text = "x".into();

        // Esc should clear filter, NOT close detail
        let esc = Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        state.handle_input(esc);
        assert!(!state.filter_active);
        assert!(state.filter_text.is_empty());
        assert!(state.detail_open); // detail still open
    }

    #[test]
    fn test_esc_precedence_committed_filter() {
        let mut state = AppState::new(100);
        state.ingest(make_event(1, "test", CallKind::LlmCall));

        // Set a committed filter (not active)
        state.filter_text = "something".into();
        state.filter_active = false;
        state.detail_open = false;

        // Esc should clear filter_text
        let esc = Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        state.handle_input(esc);
        assert!(state.filter_text.is_empty());
    }

    #[test]
    fn test_filter_change_resets_selection() {
        let mut state = AppState::new(100);
        state.ingest(make_event_with_model(1, "a", "claude-sonnet-4-20250514"));
        state.ingest(make_event_with_model(2, "b", "gpt-4o"));
        state.ingest(make_event_with_model(3, "c", "claude-sonnet-4-20250514"));

        // Select the oldest event
        state.selected_event = 0;

        // Start typing filter
        state.filter_active = true;
        let g = Event::Key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        let p = Event::Key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        let t = Event::Key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        state.handle_input(g);
        state.handle_input(p);
        state.handle_input(t);

        // Filter "gpt" matches only index 1
        assert_eq!(state.filter_text, "gpt");
        // selected_event should reset to newest visible = index 1
        assert_eq!(state.selected_event, 1);
    }

    #[test]
    fn test_mouse_scroll_changes_selection() {
        let mut state = AppState::new(100);
        for i in 0..10 {
            state.ingest(make_event(i, "test", CallKind::LlmCall));
        }
        assert_eq!(state.selected_event, 9); // newest

        let scroll_down = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_down);
        assert!(
            state.selected_event < 9,
            "scroll down should move toward older"
        );
        // Should move 3 steps
        assert_eq!(state.selected_event, 6);
    }

    #[test]
    fn test_mouse_scroll_up_moves_toward_newer() {
        let mut state = AppState::new(100);
        for i in 0..10 {
            state.ingest(make_event(i, "test", CallKind::LlmCall));
        }
        // Move to oldest first
        state.selected_event = 0;
        state.follow_mode = false;

        let scroll_up = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_up);
        assert_eq!(state.selected_event, 3); // 3 steps toward newer
    }

    #[test]
    fn test_viewport_follows_selection_after_scroll() {
        let mut state = AppState::new(100);
        for i in 0..50 {
            state.ingest(make_event(i, "test", CallKind::LlmCall));
        }
        // Scroll down 10 times (30 events toward older)
        for _ in 0..10 {
            let scroll = Event::Mouse(MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 5,
                row: 5,
                modifiers: KeyModifiers::NONE,
            });
            state.handle_input(scroll);
        }
        let (filtered, viewport_start) = state.compute_viewport(20);
        let sel_pos = filtered
            .iter()
            .rposition(|&i| i <= state.selected_event)
            .unwrap();
        let display_row = filtered.len() - 1 - sel_pos;
        // Selection must be within the viewport
        assert!(display_row >= viewport_start);
        assert!(display_row < viewport_start + 20);
    }

    #[test]
    fn test_navigate_filtered_skips_non_matching() {
        let mut state = AppState::new(100);
        state.ingest(make_event_with_model(1, "a", "claude-sonnet-4-20250514")); // idx 0
        state.ingest(make_event_with_model(2, "b", "gpt-4o")); // idx 1
        state.ingest(make_event_with_model(3, "c", "claude-sonnet-4-20250514")); // idx 2

        state.filter_text = "sonnet".into();
        // filtered = [0, 2]; newest visible = 2
        state.selected_event = 2;

        // Down (toward older) should jump to idx 0, skipping idx 1
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert_eq!(state.selected_event, 0);

        // Another down should stay at 0 (oldest visible)
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down);
        assert_eq!(state.selected_event, 0);

        // Up (toward newer) should jump back to idx 2
        let up = Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        state.handle_input(up);
        assert_eq!(state.selected_event, 2);
    }

    #[test]
    fn test_mouse_scroll_with_filter() {
        let mut state = AppState::new(100);
        // 10 events: even PIDs use "claude-sonnet-4-20250514", odd use "gpt-4o"
        for i in 0..10 {
            let model = if i % 2 == 0 {
                "claude-sonnet-4-20250514"
            } else {
                "gpt-4o"
            };
            state.ingest(make_event_with_model(i, "test", model));
        }
        // Filter to "sonnet" → matches indices [0, 2, 4, 6, 8] (5 events)
        state.filter_text = "sonnet".into();
        // Start at newest visible (8)
        state.reset_selection_to_newest_visible();
        assert_eq!(state.selected_event, 8);

        // Scroll down by 3 (toward older) within filtered set
        let scroll_down = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_down);
        // From position 4 (idx 8) in filtered [0,2,4,6,8], 3 steps back → position 1 (idx 2)
        assert_eq!(state.selected_event, 2);
    }

    // ── Agent list navigation tests ─────────────────────────────────────

    #[test]
    fn test_agent_scroll_mouse() {
        let mut state = AppState::new(100);
        for i in 0..5 {
            state.ingest(make_event(i, &format!("agent-{}", i), CallKind::LlmCall));
        }
        assert_eq!(state.agents.len(), 5);
        assert_eq!(state.selected_agent, 4); // auto-selected newest
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);

        // Set scroll area so mouse detection works
        state.areas.agent_list_scroll_area = Some(Rect::new(1, 1, 40, 20));

        // Scroll down → toward older agents (lower index), focus switches
        let scroll_down = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_down);
        assert_eq!(state.selected_agent, 3);
        assert_eq!(state.focused_panel, FocusedPanel::AgentList);

        // Scroll up → toward newer agents (higher index)
        let scroll_up = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_up);
        assert_eq!(state.selected_agent, 4);
    }

    #[test]
    fn test_agent_scroll_clamps() {
        // Empty agents: scroll should not panic
        let mut state = AppState::new(100);
        state.areas.agent_list_scroll_area = Some(Rect::new(1, 1, 40, 20));

        let scroll_up = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_up);
        assert_eq!(state.selected_agent, 0);

        // With agents: clamp at bounds
        for i in 0..3 {
            state.ingest(make_event(i, &format!("agent-{}", i), CallKind::LlmCall));
        }
        state.selected_agent = 0; // oldest agent

        let scroll_down = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_down);
        assert_eq!(state.selected_agent, 0); // already at min

        state.selected_agent = 2;
        let scroll_up = Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(scroll_up);
        assert_eq!(state.selected_agent, 2); // already at max
    }

    #[test]
    fn test_agent_click_selects() {
        let mut state = AppState::new(100);
        for i in 0..5 {
            state.ingest(make_event(i, &format!("agent-{}", i), CallKind::LlmCall));
        }
        // Data-only area starts at (1, 2), 40 wide, 19 tall (header excluded)
        state.areas.agent_list_area = Some(Rect::new(1, 2, 40, 19));

        // Click on row 7: click_row = 7-2(area.y) = 5, agent_idx = min(5,4) = 4
        // selected_agent = 5-1-4 = 0
        let click = Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 7,
            modifiers: KeyModifiers::NONE,
        });
        state.handle_input(click);
        assert_eq!(state.selected_agent, 0);
        assert_eq!(state.focused_panel, FocusedPanel::AgentList);
    }

    #[test]
    fn test_tab_toggles_focus() {
        let mut state = AppState::new(100);
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);

        let tab = Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        state.handle_input(tab.clone());
        assert_eq!(state.focused_panel, FocusedPanel::AgentList);

        state.handle_input(tab.clone());
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);

        // When detail is open, Tab should cycle detail tabs, not toggle focus
        state.ingest(make_event(1, "test", CallKind::LlmCall));
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);
        assert!(state.detail_open);

        state.focused_panel = FocusedPanel::AgentList;
        state.handle_input(tab);
        // Tab cycles detail tabs and moves focus to EventLog
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);
        assert_eq!(state.detail_tab, DetailTab::Response);
    }

    #[test]
    fn test_enter_on_agent_list_sets_filter() {
        let mut state = AppState::new(100);
        state.ingest(make_event(42, "my-agent", CallKind::LlmCall));
        state.ingest(make_event(99, "other", CallKind::LlmCall));

        state.focused_panel = FocusedPanel::AgentList;
        // selected_agent defaults to newest (index 1 = "other")
        assert_eq!(state.selected_agent, 1);

        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        state.handle_input(enter);

        assert_eq!(state.filter_text, "other (99)");
        assert_eq!(state.focused_panel, FocusedPanel::EventLog);
        assert!(!state.detail_open);

        // Only the matching event should be visible
        let indices = state.filtered_indices();
        assert_eq!(indices.len(), 1);
        assert_eq!(state.event_log[indices[0]].pid, 99);
    }

    // ── Backfill tests ────────────────────────────────────────────────

    #[test]
    fn test_backfill_builds_chronological_order() {
        let mut state = AppState::new(100);
        state.start_backfill();

        // Server sends oldest first: event1, event2, event3
        let mut e1 = make_event(1, "a", CallKind::LlmCall);
        e1.ts = "2025-01-01T00:00:01.000Z".into();
        let mut e2 = make_event(2, "b", CallKind::LlmCall);
        e2.ts = "2025-01-01T00:00:02.000Z".into();
        let mut e3 = make_event(3, "c", CallKind::LlmCall);
        e3.ts = "2025-01-01T00:00:03.000Z".into();

        state.ingest(e1);
        state.ingest(e2);
        state.ingest(e3);

        // Deque should be chronological: oldest at front
        assert_eq!(state.event_log.len(), 3);
        assert_eq!(state.event_log[0].pid, 1); // oldest
        assert_eq!(state.event_log[1].pid, 2);
        assert_eq!(state.event_log[2].pid, 3); // newest
    }

    #[test]
    fn test_backfill_cursor_tracks_newest() {
        let mut state = AppState::new(100);
        state.start_backfill();

        state.ingest(make_event(1, "a", CallKind::LlmCall));
        state.ingest(make_event(2, "b", CallKind::LlmCall));
        state.ingest(make_event(3, "c", CallKind::LlmCall));

        // Cursor + follow_mode are set in end_backfill, not per-event
        state.end_backfill();
        assert_eq!(state.selected_event, 2); // newest at end
        assert_eq!(state.selected_agent, 2); // newest agent (3 distinct pids)
        assert!(state.follow_mode);
    }

    #[test]
    fn test_live_events_after_backfill() {
        let mut state = AppState::new(100);
        state.start_backfill();

        // Backfill: oldest first
        state.ingest(make_event(1, "a", CallKind::LlmCall));
        state.ingest(make_event(2, "b", CallKind::LlmCall));
        state.end_backfill();

        // Deque: [pid=1, pid=2]
        assert_eq!(state.event_log[0].pid, 1);
        assert_eq!(state.event_log[1].pid, 2);

        // Live event appends normally
        state.ingest(make_event(3, "c", CallKind::LlmCall));
        assert_eq!(state.event_log.len(), 3);
        assert_eq!(state.event_log[2].pid, 3);
        assert_eq!(state.selected_event, 2); // follows newest
    }

    #[test]
    fn test_backfill_stats_correct() {
        let mut state = AppState::new(100);
        state.start_backfill();

        // Oldest first
        let mut e1 = make_event(1, "agent", CallKind::LlmCall);
        e1.ts = "2025-01-01T00:00:01.000Z".into();
        let mut e2 = make_event(1, "agent", CallKind::McpCall);
        e2.ts = "2025-01-01T00:00:02.000Z".into();

        state.ingest(e1);
        state.ingest(e2);

        // During backfill, no stats updated
        assert_eq!(state.global.api_calls, 0);
        assert!(state.agents.is_empty());

        state.end_backfill();

        // After end_backfill, stats are correct
        assert_eq!(state.global.api_calls, 1);
        assert_eq!(state.global.mcp_calls, 1);
        assert_eq!(state.global.total_input_tokens, 2000);
        assert_eq!(state.global.total_output_tokens, 400);

        let agent = &state.agents[&(1, "agent".into())];
        assert_eq!(agent.api_calls, 1);
        assert_eq!(agent.mcp_calls, 1);
        // first_seen should be the earlier timestamp (chronological replay)
        assert_eq!(agent.first_seen, "2025-01-01T00:00:01.000Z");
        assert_eq!(agent.last_seen, "2025-01-01T00:00:02.000Z");
    }

    #[test]
    fn test_keyboard_agent_navigation() {
        let mut state = AppState::new(100);
        for i in 0..5 {
            state.ingest(make_event(i, &format!("agent-{}", i), CallKind::LlmCall));
        }
        state.focused_panel = FocusedPanel::AgentList;
        assert_eq!(state.selected_agent, 4); // auto-selected newest

        // Down (visually downward = toward older agents = lower index)
        let down = Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        state.handle_input(down.clone());
        assert_eq!(state.selected_agent, 3);

        // Up (visually upward = toward newer agents = higher index)
        let up = Event::Key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        state.handle_input(up.clone());
        assert_eq!(state.selected_agent, 4);

        // Clamp at max
        state.handle_input(up.clone());
        assert_eq!(state.selected_agent, 4); // already at len-1

        // Navigate down to 0
        state.selected_agent = 1;
        state.handle_input(down.clone());
        assert_eq!(state.selected_agent, 0);

        // Clamp at 0
        state.handle_input(down);
        assert_eq!(state.selected_agent, 0);
    }
}
