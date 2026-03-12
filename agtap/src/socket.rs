use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::output::AgentEvent;

/// Sentinel line sent after the backfill to signal transition to live mode.
pub const BACKFILL_SENTINEL: &[u8] = b"---\n";

// ── Server ──────────────────────────────────────────────────────────────────

pub struct SocketServer {
    backlog: VecDeque<String>,
    backlog_capacity: usize,
    clients: Vec<OwnedWriteHalf>,
}

impl SocketServer {
    /// Bind the unix socket and return a sender the caller uses to push events.
    ///
    /// The server task runs inside a tokio::spawn — call this once during daemon
    /// startup. The returned sender is !Clone; the caller fans out itself.
    pub fn start(
        path: &Path,
        capacity: usize,
        seed: Vec<String>,
    ) -> anyhow::Result<mpsc::Sender<AgentEvent>> {
        // Prepare socket directory
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
                crate::chown_to_real_user(parent);
            }
        }

        // Remove stale socket
        let _ = std::fs::remove_file(path);

        let listener = UnixListener::bind(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
            crate::chown_to_real_user(path);
        }

        let (tx, rx) = mpsc::channel::<AgentEvent>(4096);

        let mut backlog = VecDeque::with_capacity(capacity);
        let skip = seed.len().saturating_sub(capacity);
        backlog.extend(seed.into_iter().skip(skip));

        let mut server = SocketServer {
            backlog,
            backlog_capacity: capacity,
            clients: Vec::new(),
        };

        tokio::spawn(async move {
            server.run(listener, rx).await;
        });

        Ok(tx)
    }

    async fn run(&mut self, listener: UnixListener, mut rx: mpsc::Receiver<AgentEvent>) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        self.handle_new_client(stream).await;
                    }
                }
                event = rx.recv() => {
                    match event {
                        Some(event) => self.broadcast(event).await,
                        None => break, // sender dropped — daemon shutting down
                    }
                }
            }
        }
    }

    async fn handle_new_client(&mut self, stream: UnixStream) {
        let (_, mut writer) = stream.into_split();

        // Send backfill oldest-first so TUI builds chronological order naturally
        for line in &self.backlog {
            if writer.write_all(line.as_bytes()).await.is_err() {
                return; // client disconnected during backfill
            }
        }
        // Sentinel marks end of backfill
        if writer.write_all(BACKFILL_SENTINEL).await.is_err() {
            return;
        }
        if writer.flush().await.is_err() {
            return;
        }

        self.clients.push(writer);
    }

    async fn broadcast(&mut self, event: AgentEvent) {
        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(_) => return,
        };
        let line = format!("{}\n", json);

        // Update backlog
        if self.backlog.len() >= self.backlog_capacity {
            self.backlog.pop_front();
        }
        self.backlog.push_back(line.clone());

        // Write to all clients, removing any that error
        let mut failed = Vec::new();
        for (i, client) in self.clients.iter_mut().enumerate() {
            if client.write_all(line.as_bytes()).await.is_err() {
                failed.push(i);
            }
        }
        // Remove in reverse order to preserve indices
        for i in failed.into_iter().rev() {
            self.clients.swap_remove(i);
        }
    }
}

// ── Client ──────────────────────────────────────────────────────────────────

pub async fn connect(path: &Path) -> anyhow::Result<BufReader<tokio::net::unix::OwnedReadHalf>> {
    let stream = UnixStream::connect(path).await?;
    let (reader, _writer) = stream.into_split();
    Ok(BufReader::new(reader))
}

// ── Socket path ─────────────────────────────────────────────────────────────

pub fn default_sock_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGTAP_SOCK") {
        return PathBuf::from(path);
    }
    crate::default_runtime_dir().join("agtap.sock")
}
