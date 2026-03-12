use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

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
    pub fn cleanup_if_needed(&mut self) {
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
                if fs::remove_file(path).is_ok() {
                    self.total_bytes = self.total_bytes.saturating_sub(*size);
                }
            }
        }
    }
}
