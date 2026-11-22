use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use crate::providers::HttpDetail;

/// How often (seconds) cleanup runs at most.
const CLEANUP_INTERVAL_SECS: u64 = 600;
/// When over the size limit, delete oldest files until at this percentage of max.
const CLEANUP_TARGET_PERCENT: u64 = 80;

pub struct BodyStore {
    dir: PathBuf,
    total_bytes: u64,
    retention_secs: u64,
    high_water_bytes: u64,
    hard_water_bytes: u64,
    dropped_new_bodies: u64,
    last_cleanup: Instant,
}

impl BodyStore {
    pub fn open(dir: &Path, max_mb: u64, retention_hours: u64) -> io::Result<Self> {
        Self::open_with_watermarks(dir, max_mb, retention_hours, 90, 100)
    }

    pub fn open_with_watermarks(
        dir: &Path,
        max_mb: u64,
        retention_hours: u64,
        high_water_percent: u8,
        hard_water_percent: u8,
    ) -> io::Result<Self> {
        if high_water_percent == 0
            || hard_water_percent == 0
            || high_water_percent > hard_water_percent
            || hard_water_percent > 100
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "body store watermarks must satisfy 0 < high <= hard <= 100",
            ));
        }
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
            retention_secs: retention_hours * 3600,
            high_water_bytes: max_mb * 1024 * 1024 * high_water_percent as u64 / 100,
            hard_water_bytes: max_mb * 1024 * 1024 * hard_water_percent as u64 / 100,
            dropped_new_bodies: 0,
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
        self.write_inner(pid, timestamp_ns, event_id, detail)
    }

    /// Return `Ok(None)` at the configured hard water mark. The caller still
    /// emits the event, so capture degradation never changes the forwarded call.
    pub fn write_if_within_hard_water(
        &mut self,
        pid: u32,
        timestamp_ns: u64,
        event_id: &str,
        detail: &HttpDetail,
    ) -> io::Result<Option<PathBuf>> {
        if self.total_bytes >= self.hard_water_bytes {
            self.dropped_new_bodies = self.dropped_new_bodies.saturating_add(1);
            log::warn!(
                "body_store hard watermark reached; new body capture skipped (stored_bytes={}, hard_bytes={}, skipped={})",
                self.total_bytes,
                self.hard_water_bytes,
                self.dropped_new_bodies
            );
            return Ok(None);
        }
        self.write_inner(pid, timestamp_ns, event_id, detail)
            .map(Some)
    }

    fn write_inner(
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

    pub fn is_over_high_water(&self) -> bool {
        self.total_bytes >= self.high_water_bytes
    }

    pub fn dropped_new_bodies(&self) -> u64 {
        self.dropped_new_bodies
    }

    /// Delete old files and enforce size limit. Called periodically (every 10 min).
    pub fn cleanup_if_needed(&mut self, protected_paths: &HashSet<PathBuf>) {
        self.cleanup_if_needed_with_checkpoint(protected_paths, |_| true);
    }

    /// A body becomes reclaimable only after the callback has made a durable,
    /// verified checkpoint. Returning false protects the body for a later retry.
    pub fn cleanup_if_needed_with_checkpoint<F>(
        &mut self,
        protected_paths: &HashSet<PathBuf>,
        mut checkpoint: F,
    ) where
        F: FnMut(&Path) -> bool,
    {
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
                let removed = checkpoint(path) && fs::remove_file(path).is_ok();
                if removed {
                    self.total_bytes = self.total_bytes.saturating_sub(size);
                }
                !removed
            } else {
                true
            }
        });

        // Pass 2: begin pressure cleanup at the configurable high watermark,
        // then leave headroom below it for incoming bodies and checkpoint work.
        if self.total_bytes > self.high_water_bytes {
            files.sort_by_key(|&(_, _, modified)| modified);
            let target = self.high_water_bytes * CLEANUP_TARGET_PERCENT / 100;
            for (path, size, _) in &files {
                if self.total_bytes <= target {
                    break;
                }
                if protected_paths.contains(path) {
                    continue;
                }
                if checkpoint(path) && fs::remove_file(path).is_ok() {
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
    fn cleanup_requires_checkpoint_before_removal() {
        let dir = TempDir::new().unwrap();
        let mut store = BodyStore::open(dir.path(), 0, 24).unwrap();
        let path = dir.path().join("body.json");
        fs::write(&path, b"body").unwrap();
        store.total_bytes = 4;
        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);

        store.cleanup_if_needed_with_checkpoint(&HashSet::new(), |_| false);
        assert!(path.exists(), "an uncheckpointed body must be retained");

        store.last_cleanup = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        store.cleanup_if_needed_with_checkpoint(&HashSet::new(), |_| true);
        assert!(!path.exists());
    }

    #[test]
    fn hard_watermark_skips_new_capture_without_error() {
        let dir = TempDir::new().unwrap();
        let mut store = BodyStore::open_with_watermarks(dir.path(), 1, 24, 80, 80).unwrap();
        store.total_bytes = store.hard_water_bytes;
        let detail = crate::providers::test_helpers::make_exchange(
            "example.test",
            "/v1/test",
            b"request",
            b"response",
        );
        let http_detail = crate::providers::build_http_detail(&detail, &detail.response.body);
        assert!(store
            .write_if_within_hard_water(1, 1, "event", &http_detail)
            .unwrap()
            .is_none());
        assert_eq!(store.dropped_new_bodies(), 1);
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
