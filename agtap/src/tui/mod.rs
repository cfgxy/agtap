pub mod state;
mod ui;

use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, EventStream};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::io::AsyncBufReadExt;

use crate::output::AgentEvent;
use crate::socket;
use state::{Action, AppState, UiAreas};

pub async fn run(sock_path: &Path) -> anyhow::Result<()> {
    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = io::stderr().execute(LeaveAlternateScreen);
        let _ = io::stderr().execute(DisableMouseCapture);
        original_hook(info);
    }));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stderr();
    stdout.execute(EnterAlternateScreen)?;
    stdout.execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut state = AppState::new(1000);
    let mut input_stream = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    // Initial draw
    let mut areas = UiAreas::default();
    terminal.draw(|f| {
        areas = ui::render(f, &state);
    })?;
    state.set_areas(areas);

    // Auto-reconnecting socket reader
    let mut reader: Option<tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>> = None;
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(2));
    let mut line = String::new();

    loop {
        // Try to connect if not connected
        if reader.is_none() {
            match socket::connect(sock_path).await {
                Ok(r) => {
                    reader = Some(r);
                    state.set_connected(true);
                    state.start_backfill();
                }
                Err(_) => {
                    state.set_connected(false);
                }
            }
        }

        tokio::select! {
            // Read from socket (only if connected)
            result = async {
                if let Some(ref mut r) = reader {
                    r.read_line(&mut line).await
                } else {
                    std::future::pending().await
                }
            } => {
                match result {
                    Ok(0) | Err(_) => {
                        // Daemon disconnected — reset, will reconnect
                        reader = None;
                        state = AppState::new(1000);
                        state.set_connected(false);
                    }
                    Ok(_) => {
                        if line.as_bytes() == socket::BACKFILL_SENTINEL {
                            state.end_backfill();
                        } else if let Ok(event) = serde_json::from_str::<AgentEvent>(&line) {
                            // Live events always pass (body was just written); backfill
                            // events require the file to still exist on disk.
                            let has_body = event.body_path.as_ref().is_some_and(|p| {
                                !state.is_backfilling() || std::path::Path::new(p).exists()
                            });
                            if has_body {
                                state.ingest(event);
                            }
                        }
                        line.clear();
                    }
                }
            }
            Some(Ok(input)) = input_stream.next() => {
                if state.handle_input(input) == Action::Quit {
                    break;
                }
            }
            _ = tick.tick() => {}
            _ = reconnect_interval.tick(), if reader.is_none() => {
                // loop head will attempt reconnect
            }
        }

        if !state.is_backfilling() {
            // Debounced body loading for detail pane
            state.maybe_load_detail();

            let mut areas = UiAreas::default();
            terminal.draw(|f| {
                areas = ui::render(f, &state);
            })?;
            state.set_areas(areas);
        }
    }

    // Teardown terminal
    disable_raw_mode()?;
    terminal.backend_mut().execute(DisableMouseCapture)?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
