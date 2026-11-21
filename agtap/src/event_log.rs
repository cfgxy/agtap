use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::archive::{ArchiveCompression, ArchiveQueue};
use crate::output::AgentEvent;

pub struct LogWriter {
    writer: BufWriter<File>,
    log_path: PathBuf,
    bytes_written: u64,
    max_bytes: u64,
    max_files: usize,
    archive_queue: Option<Arc<ArchiveQueue>>,
    archive_prefix: String,
    archive_compression: ArchiveCompression,
    archive_recovery_needed: bool,
}

fn open_log_file(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o640));
        crate::chown_to_real_user(path);
    }

    Ok(file)
}

impl LogWriter {
    pub fn open(path: &Path, max_bytes: u64, max_files: usize) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o750));
                crate::chown_to_real_user(parent);
            }
        }

        let file = open_log_file(path)?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            writer: BufWriter::new(file),
            log_path: path.to_path_buf(),
            bytes_written,
            max_bytes,
            max_files: max_files.max(1),
            archive_queue: None,
            archive_prefix: "agtap".to_string(),
            archive_compression: ArchiveCompression::Zstd,
            archive_recovery_needed: false,
        })
    }

    pub fn set_archive_queue(
        &mut self,
        queue: Arc<ArchiveQueue>,
        prefix: String,
        compression: ArchiveCompression,
    ) -> anyhow::Result<()> {
        queue.recover_rotations_with_compression(&self.log_path, &prefix, compression)?;
        self.archive_queue = Some(queue);
        self.archive_prefix = prefix;
        self.archive_compression = compression;
        self.archive_recovery_needed = false;
        Ok(())
    }

    pub fn write_event(&mut self, event: &AgentEvent) {
        if self.archive_recovery_needed {
            if let Some(queue) = &self.archive_queue {
                match queue.recover_rotations_with_compression(
                    &self.log_path,
                    &self.archive_prefix,
                    self.archive_compression,
                ) {
                    Ok(()) => self.archive_recovery_needed = false,
                    Err(err) => {
                        eprintln!("agtap: archive rotation recovery failed: {err}");
                    }
                }
            }
        }
        if let Ok(json) = serde_json::to_string(event) {
            let len = json.len() as u64 + 1; // +1 for newline
            if writeln!(self.writer, "{}", json).is_ok() {
                let _ = self.writer.flush();
                self.bytes_written += len;
                if self.bytes_written >= self.max_bytes {
                    if let Err(e) = self.rotate() {
                        eprintln!("agtap: log rotation failed: {}", e);
                        self.archive_recovery_needed = self.archive_queue.is_some();
                    }
                }
            }
        }
    }

    fn rotate(&mut self) -> anyhow::Result<()> {
        let _ = self.writer.flush();

        let rotation_id = self
            .archive_queue
            .as_ref()
            .map(|queue| queue.begin_rotation(&self.log_path, self.bytes_written))
            .transpose()?;

        // Delete the oldest rotated file if it exists
        let oldest = rotated_path(&self.log_path, self.max_files);
        let _ = fs::remove_file(&oldest);

        // Shift existing rotated files: .{N-1} -> .{N}
        for i in (1..self.max_files).rev() {
            let from = rotated_path(&self.log_path, i);
            let to = rotated_path(&self.log_path, i + 1);
            match fs::rename(&from, &to) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Rename current log -> .1
        let first_rotated = rotated_path(&self.log_path, 1);
        fs::rename(&self.log_path, &first_rotated)?;

        // Open fresh log file
        let file = open_log_file(&self.log_path)?;
        self.writer = BufWriter::new(file);
        self.bytes_written = 0;

        if let Some(queue) = &self.archive_queue {
            if let Some(rotation_id) = rotation_id {
                queue
                    .enqueue_rotation_with_compression(
                        &rotation_id,
                        &self.archive_prefix,
                        self.archive_compression,
                        &first_rotated,
                    )
                    .map_err(|err| anyhow::anyhow!("persist archive job: {err}"))?;
                queue.complete_rotation(&rotation_id)?;
            }
        }
        Ok(())
    }
}

fn rotated_path(base: &Path, n: usize) -> PathBuf {
    let name = format!(
        "{}.{}",
        base.file_name().unwrap_or_default().to_string_lossy(),
        n
    );
    base.with_file_name(name)
}

/// Read the last `n` lines from a JSONL file. Returns each line including its
/// trailing newline. Gracefully returns an empty vec on any error.
///
/// Uses reverse-seeking to avoid reading the entire file into memory.
pub fn read_last_lines(path: &Path, n: usize) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let file_len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return Vec::new(),
    };
    if file_len == 0 {
        return Vec::new();
    }

    // Read backward in chunks to find the last N newlines
    const CHUNK: u64 = 64 * 1024;
    let mut tail = Vec::new();
    let mut remaining = file_len;
    let mut newline_count = 0usize;

    while remaining > 0 {
        let read_size = CHUNK.min(remaining);
        remaining -= read_size;
        file.seek(SeekFrom::Start(remaining)).ok();
        let mut buf = vec![0u8; read_size as usize];
        if file.read_exact(&mut buf).is_err() {
            return Vec::new();
        }
        // Count newlines in this chunk (we need n+1 to delimit n lines)
        newline_count += buf.iter().filter(|&&b| b == b'\n').count();
        tail.splice(0..0, buf);
        if newline_count > n {
            break;
        }
    }

    // Parse lines from the collected tail bytes
    let text = String::from_utf8_lossy(&tail);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .filter(|l| !l.is_empty())
        .map(|l| format!("{}\n", l))
        .collect()
}

pub fn default_log_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGTAP_LOG") {
        return PathBuf::from(path);
    }
    crate::default_runtime_dir().join("events.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_event() -> AgentEvent {
        AgentEvent::test_default()
    }

    #[test]
    fn test_rotation_triggers_at_threshold() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let mut writer = LogWriter::open(&log_path, 100, 3).unwrap();

        for _ in 0..5 {
            writer.write_event(&make_event());
        }

        let rotated = dir.path().join("events.jsonl.1");
        assert!(
            rotated.exists(),
            "events.jsonl.1 should exist after rotation"
        );
        let current_size = fs::metadata(&log_path).unwrap().len();
        assert!(
            current_size < 100,
            "current log should be smaller than threshold after rotation"
        );
    }

    #[test]
    fn test_rotation_shifts_files() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let mut writer = LogWriter::open(&log_path, 50, 3).unwrap();

        for _ in 0..30 {
            writer.write_event(&make_event());
        }

        let r1 = dir.path().join("events.jsonl.1");
        let r2 = dir.path().join("events.jsonl.2");
        let r4 = dir.path().join("events.jsonl.4");
        assert!(r1.exists(), "events.jsonl.1 should exist");
        assert!(r2.exists(), "events.jsonl.2 should exist");
        assert!(
            !r4.exists(),
            "events.jsonl.4 should not exist (max_files=3)"
        );
    }

    #[test]
    fn test_oldest_file_deleted() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let mut writer = LogWriter::open(&log_path, 50, 2).unwrap();

        for _ in 0..30 {
            writer.write_event(&make_event());
        }

        let r3 = dir.path().join("events.jsonl.3");
        assert!(
            !r3.exists(),
            "events.jsonl.3 should not exist (max_files=2)"
        );
    }

    #[test]
    fn test_existing_file_size_counted_on_open() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");

        fs::write(&log_path, "x".repeat(80)).unwrap();

        let mut writer = LogWriter::open(&log_path, 100, 3).unwrap();
        assert_eq!(writer.bytes_written, 80);

        writer.write_event(&make_event());
        let rotated = dir.path().join("events.jsonl.1");
        assert!(
            rotated.exists(),
            "should rotate since existing + new > threshold"
        );
    }

    #[test]
    fn test_max_files_clamped_to_one() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let writer = LogWriter::open(&log_path, 100, 0).unwrap();
        assert_eq!(writer.max_files, 1);
    }

    #[test]
    fn test_archive_snapshot_survives_rotated_rename() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let queue = Arc::new(ArchiveQueue::open(dir.path()).unwrap());
        let mut writer = LogWriter::open(&log_path, 50, 2).unwrap();
        writer
            .set_archive_queue(queue.clone(), "tests".to_string(), ArchiveCompression::Lz4)
            .unwrap();

        for _ in 0..30 {
            writer.write_event(&make_event());
        }

        assert!(dir.path().join("events.jsonl.1").exists());
        assert!(dir.path().join("events.jsonl.2").exists());
        assert!(queue.pending_count() >= 2);
        assert!(dir
            .path()
            .join("archive/closed")
            .read_dir()
            .unwrap()
            .next()
            .is_some());
    }

    #[test]
    fn rotation_retries_after_transient_error() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let blocked = dir.path().join("events.jsonl.1");
        fs::create_dir(&blocked).unwrap();
        let mut writer = LogWriter::open(&log_path, 1, 1).unwrap();

        writer.write_event(&make_event());
        assert!(blocked.is_dir());

        fs::remove_dir(&blocked).unwrap();
        writer.write_event(&make_event());
        assert!(blocked.is_file(), "a later event should retry rotation");
    }

    #[test]
    fn test_read_last_lines_normal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        fs::write(&path, "line1\nline2\nline3\nline4\nline5\n").unwrap();
        let lines = read_last_lines(&path, 3);
        assert_eq!(lines, vec!["line3\n", "line4\n", "line5\n"]);
    }

    #[test]
    fn test_read_last_lines_n_exceeds_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        fs::write(&path, "a\nb\n").unwrap();
        let lines = read_last_lines(&path, 100);
        assert_eq!(lines, vec!["a\n", "b\n"]);
    }

    #[test]
    fn test_read_last_lines_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        fs::write(&path, "").unwrap();
        let lines = read_last_lines(&path, 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_read_last_lines_nonexistent() {
        let lines = read_last_lines(Path::new("/tmp/does_not_exist_agtap_test.jsonl"), 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_read_last_lines_no_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        fs::write(&path, "line1\nline2\nline3").unwrap();
        let lines = read_last_lines(&path, 2);
        assert_eq!(lines, vec!["line2\n", "line3\n"]);
    }
}
