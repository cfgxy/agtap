use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::providers::HttpDetail;

/// How often (seconds) cleanup runs at most.
const CLEANUP_INTERVAL_SECS: u64 = 600;
/// When over the size limit, delete oldest files until at this percentage of max.
const CLEANUP_TARGET_PERCENT: u64 = 80;

pub struct BodyStore {
    dir: PathBuf,
    total_bytes: u64,
    max_bytes: u64,
    retention_secs: u64,
    last_cleanup: Instant,
}

impl BodyStore {
    pub fn open(dir: &Path, max_mb: u64, retention_hours: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
            crate::chown_to_real_user(dir);
        }

        // Sum existing files to initialize total_bytes
        let mut total_bytes: u64 = 0;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total_bytes += meta.len();
                    }
                }
            }
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            total_bytes,
            max_bytes: max_mb * 1024 * 1024,
            retention_secs: retention_hours * 3600,
            last_cleanup: Instant::now(),
        })
    }

    pub fn write(
        &mut self,
        pid: u32,
        timestamp_ns: u64,
        event_id: &str,
        detail: &HttpDetail,
    ) -> io::Result<PathBuf> {
        // Sanitize event_id for filename safety (replace non-alphanumeric except - and _)
        let safe_id: String = event_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let filename = format!("{}-{}-{}.json", pid, timestamp_ns, safe_id);
        let path = self.dir.join(&filename);

        let json = serde_json::to_vec(detail)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        fs::write(&path, &json)?;
        #[cfg(unix)]
        crate::chown_to_real_user(&path);
        self.total_bytes += json.len() as u64;

        Ok(path)
    }

    /// Read an HttpDetail from a body file. Static — no BodyStore instance needed.
    pub fn read(path: &Path) -> io::Result<HttpDetail> {
        let data = fs::read(path)?;
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Delete old files and enforce size limit. Called periodically (every 10 min).
    pub fn cleanup_if_needed(&mut self, protected_paths: &HashSet<PathBuf>) {
        if self.last_cleanup.elapsed().as_secs() < CLEANUP_INTERVAL_SECS {
            return;
        }
        self.last_cleanup = Instant::now();

        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!(
                    "body_store cleanup: failed to read {}: {}",
                    self.dir.display(),
                    e
                );
                return;
            }
        };

        let now = std::time::SystemTime::now();
        let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();

        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let modified = meta.modified().unwrap_or(now);
            files.push((entry.path(), meta.len(), modified));
        }

        // Pass 1: delete files older than retention
        files.retain(|&(ref path, size, modified)| {
            if protected_paths.contains(path) {
                return true;
            }
            let age = now.duration_since(modified).unwrap_or_default();
            if age.as_secs() > self.retention_secs {
                if fs::remove_file(path).is_ok() {
                    self.total_bytes = self.total_bytes.saturating_sub(size);
                }
                false
            } else {
                true
            }
        });

        // Pass 2: if still over limit, delete oldest until under 80%
        if self.total_bytes > self.max_bytes {
            files.sort_by_key(|&(_, _, modified)| modified);
            let target = self.max_bytes * CLEANUP_TARGET_PERCENT / 100;
            for (path, size, _) in &files {
                if self.total_bytes <= target {
                    break;
                }
                if protected_paths.contains(path) {
                    continue;
                }
                if fs::remove_file(path).is_ok() {
                    self.total_bytes = self.total_bytes.saturating_sub(*size);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    #[test]
    fn cleanup_does_not_remove_protected_body() {
        let dir = TempDir::new().unwrap();
        let mut store = BodyStore::open(dir.path(), 0, 24).unwrap();
        let detail = crate::providers::test_helpers::make_exchange(
            "example.test",
            "/v1/test",
            b"request",
            b"response",
        );
        let http_detail = crate::providers::build_http_detail(&detail, &detail.response.body);
        let body_path = store.write(1, 1, "event", &http_detail).unwrap();
        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);

        let mut protected = HashSet::new();
        protected.insert(body_path.clone());
        store.cleanup_if_needed(&protected);
        assert!(body_path.exists());

        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        store.cleanup_if_needed(&HashSet::new());
        assert!(!body_path.exists());
    }

    #[test]
    fn cleanup_protects_body_during_unqueued_rotation_recovery() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let body_dir = dir.path().join("bodies");
        let queue = crate::archive::ArchiveQueue::open(&runtime).unwrap();
        let mut store = BodyStore::open(&body_dir, 0, 24).unwrap();
        let body_path = body_dir.join("body.json");
        fs::write(&body_path, br#"{"request_body":"hello"}"#).unwrap();
        let log = dir.path().join("events.jsonl");
        fs::write(
            &log,
            format!(r#"{{"id":"e1","body_path":"{}"}}"#, body_path.display()) + "\n",
        )
        .unwrap();

        let source_len = fs::metadata(&log).unwrap().len();
        queue.begin_rotation(&log, source_len).unwrap();

        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        let protected_before_enqueue = queue.protected_body_paths(None);
        assert!(protected_before_enqueue.contains(&body_path));
        store.cleanup_if_needed(&protected_before_enqueue);
        assert!(
            body_path.exists(),
            "intent must protect body before job creation"
        );

        let rotated = dir.path().join("events.jsonl.1");
        fs::rename(&log, &rotated).unwrap();
        queue.recover_rotations(&log, "tests").unwrap();
        assert_eq!(queue.pending_count(), 1);

        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        let protected_after_recovery = queue.protected_body_paths(None);
        assert!(protected_after_recovery.contains(&body_path));
        store.cleanup_if_needed(&protected_after_recovery);
        assert!(
            body_path.exists(),
            "recovered job must keep body available for packaging"
        );
    }
}
