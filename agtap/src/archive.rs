use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const ARCHIVE_FORMAT: &str = "agtap-archive-v1";
const WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY_SECS: u64 = 300;

#[derive(Clone, Debug)]
pub struct ArchiveConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub retry_delay_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ArchiveJob {
    id: String,
    #[serde(default)]
    rotation_id: Option<String>,
    source_path: String,
    #[serde(default)]
    rotated_path: Option<String>,
    payload_path: Option<String>,
    body_paths: Vec<String>,
    object_key: String,
    payload_sha256: Option<String>,
    attempts: u32,
    next_attempt_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RotationIntent {
    id: String,
    log_path: String,
    rotated_path: String,
    snapshot_path: String,
    source_len: u64,
    source_identity: Option<String>,
    source_sha256: String,
}

#[derive(Debug, Serialize)]
struct ArchivePackage {
    format: &'static str,
    events: Vec<Value>,
    bodies: Vec<ArchiveBody>,
}

#[derive(Debug, Serialize)]
struct ArchiveBody {
    path: String,
    content: Value,
}

#[derive(Clone)]
pub struct ArchiveQueue {
    pending_dir: PathBuf,
    closed_dir: PathBuf,
    payload_dir: PathBuf,
}

impl ArchiveQueue {
    pub fn open(runtime_dir: &Path) -> io::Result<Self> {
        let root = runtime_dir.join("archive");
        let pending_dir = root.join("pending");
        let closed_dir = root.join("closed");
        let payload_dir = root.join("payloads");
        for dir in [&pending_dir, &closed_dir, &payload_dir] {
            fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
                crate::chown_to_real_user(dir);
            }
        }
        Ok(Self {
            pending_dir,
            closed_dir,
            payload_dir,
        })
    }

    pub fn enqueue_rotated(&self, rotated_path: &Path, object_prefix: &str) -> io::Result<()> {
        self.enqueue_rotated_with_source(rotated_path, object_prefix, None)
    }

    pub(crate) fn enqueue_rotated_with_source(
        &self,
        rotated_path: &Path,
        object_prefix: &str,
        rotated_source: Option<&Path>,
    ) -> io::Result<()> {
        if !rotated_path.is_file() {
            return Ok(());
        }

        let id = unique_id();
        let snapshot = self.closed_dir.join(format!("{}.jsonl", id));
        // A hard link gives the worker a stable snapshot without copying the rotated log on the
        // event path. The fallback is for filesystems that do not support hard links.
        if let Err(link_err) = fs::hard_link(rotated_path, &snapshot) {
            fs::copy(rotated_path, &snapshot).map_err(|copy_err| {
                io::Error::new(
                    copy_err.kind(),
                    format!(
                        "archive snapshot failed after hard-link error: {link_err}; {copy_err}"
                    ),
                )
            })?;
        }

        if let Err(err) = self.enqueue_snapshot(&snapshot, object_prefix, None, rotated_source) {
            let _ = fs::remove_file(&snapshot);
            return Err(err);
        }
        Ok(())
    }

    fn enqueue_snapshot(
        &self,
        snapshot: &Path,
        object_prefix: &str,
        rotation_id: Option<&str>,
        rotated_source: Option<&Path>,
    ) -> io::Result<()> {
        let id = unique_id();
        let object_key = format!("{}/{}.json", object_prefix.trim_matches('/'), id);
        let job = ArchiveJob {
            id: id.clone(),
            rotation_id: rotation_id.map(str::to_owned),
            source_path: snapshot.to_string_lossy().into_owned(),
            rotated_path: rotated_source.map(|path| path.to_string_lossy().into_owned()),
            payload_path: None,
            body_paths: Vec::new(),
            object_key,
            payload_sha256: None,
            attempts: 0,
            next_attempt_at: 0,
        };
        self.save_job(&job)
    }

    pub(crate) fn enqueue_rotation(
        &self,
        rotation_id: &str,
        object_prefix: &str,
        rotated_source: &Path,
    ) -> io::Result<()> {
        let snapshot = self
            .closed_dir
            .join(format!("rotation-{rotation_id}.jsonl"));
        if !snapshot.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("rotation snapshot missing: {}", snapshot.display()),
            ));
        }
        self.enqueue_snapshot(
            &snapshot,
            object_prefix,
            Some(rotation_id),
            Some(rotated_source),
        )
    }

    pub fn begin_rotation(&self, log_path: &Path, source_len: u64) -> io::Result<String> {
        let id = unique_id();
        let snapshot_path = self.closed_dir.join(format!("rotation-{id}.jsonl"));
        let source_bytes = fs::read(log_path)?;
        let intent = RotationIntent {
            id: id.clone(),
            log_path: log_path.to_string_lossy().into_owned(),
            rotated_path: rotated_log_path(log_path, 1).to_string_lossy().into_owned(),
            snapshot_path: snapshot_path.to_string_lossy().into_owned(),
            source_len,
            source_identity: file_identity(log_path).ok(),
            source_sha256: sha256_hex(&source_bytes),
        };
        let path = self.pending_dir.join(format!(".rotation-{id}.json"));
        let temp = self.pending_dir.join(format!(".rotation-{id}.json.tmp"));
        let bytes = serde_json::to_vec_pretty(&intent)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        fs::write(&temp, bytes)?;
        fs::rename(temp, path)?;
        if let Err(link_err) = fs::hard_link(log_path, &snapshot_path) {
            fs::copy(log_path, &snapshot_path).map_err(|copy_err| {
                io::Error::new(
                    copy_err.kind(),
                    format!(
                        "rotation snapshot failed after hard-link error: {link_err}; {copy_err}"
                    ),
                )
            })?;
        }
        Ok(id)
    }

    pub fn complete_rotation(&self, id: &str) -> io::Result<()> {
        let path = self.pending_dir.join(format!(".rotation-{id}.json"));
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn recover_rotations(&self, log_path: &Path, object_prefix: &str) -> io::Result<()> {
        let entries = fs::read_dir(&self.pending_dir)?;
        let mut jobs = self.load_jobs();
        let mut intents = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with(".rotation-")
                || path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }
            let intent: RotationIntent = match fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<RotationIntent>(&bytes).ok())
            {
                Some(intent) if Path::new(&intent.log_path) == log_path => intent,
                _ => continue,
            };
            intents.push(intent);
        }

        let snapshots = fs::read_dir(&self.closed_dir)?;
        let referenced_snapshots = jobs
            .iter()
            .map(|job| job.source_path.clone())
            .collect::<HashSet<_>>();
        let intent_snapshots = intents
            .iter()
            .map(|intent| intent.snapshot_path.clone())
            .collect::<HashSet<_>>();
        let orphan_snapshots = snapshots
            .flatten()
            .map(|entry| entry.path())
            .filter(|snapshot| {
                snapshot.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
                    && !referenced_snapshots.contains(&snapshot.to_string_lossy().into_owned())
                    && !intent_snapshots.contains(&snapshot.to_string_lossy().into_owned())
            })
            .collect::<Vec<_>>();

        for intent in intents {
            let already_enqueued = jobs.iter().any(|job| {
                job.rotation_id.as_deref() == Some(intent.id.as_str())
                    || job.source_path == intent.snapshot_path
            });
            if already_enqueued {
                self.complete_rotation(&intent.id)?;
                continue;
            }

            if !rotation_completed(log_path, &intent) {
                let _ = fs::remove_file(&intent.snapshot_path);
                self.complete_rotation(&intent.id)?;
                continue;
            }

            if Path::new(&intent.snapshot_path).is_file() {
                self.enqueue_snapshot(
                    Path::new(&intent.snapshot_path),
                    object_prefix,
                    Some(&intent.id),
                    Some(Path::new(&intent.rotated_path)),
                )?;
                jobs = self.load_jobs();
                self.complete_rotation(&intent.id)?;
            }
        }

        for snapshot in orphan_snapshots {
            if snapshot.is_file() {
                self.enqueue_snapshot(&snapshot, object_prefix, None, None)?;
            }
        }
        Ok(())
    }

    fn save_job(&self, job: &ArchiveJob) -> io::Result<()> {
        let path = self.pending_dir.join(format!("{}.json", job.id));
        let temp = self.pending_dir.join(format!("{}.json.tmp", job.id));
        let bytes = serde_json::to_vec_pretty(job)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        fs::write(&temp, bytes)?;
        fs::rename(temp, path)?;
        Ok(())
    }

    fn load_jobs(&self) -> Vec<ArchiveJob> {
        let Ok(entries) = fs::read_dir(&self.pending_dir) else {
            return Vec::new();
        };
        let mut jobs = entries
            .flatten()
            .filter(|entry| entry.path().extension().and_then(|v| v.to_str()) == Some("json"))
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<ArchiveJob>(&bytes).ok())
            .collect::<Vec<_>>();
        jobs.sort_by_key(|job| (job.next_attempt_at, job.id.clone()));
        jobs
    }

    pub fn pending_count(&self) -> usize {
        self.load_jobs().len()
    }

    fn load_job(&self, id: &str) -> Option<ArchiveJob> {
        let path = self.pending_dir.join(format!("{}.json", id));
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    fn mark_retry(&self, mut job: ArchiveJob, base_delay_secs: u64) {
        job.attempts = job.attempts.saturating_add(1);
        let exponent = job.attempts.saturating_sub(1).min(8);
        let backoff = base_delay_secs
            .saturating_mul(1u64 << exponent)
            .min(MAX_RETRY_DELAY_SECS);
        job.next_attempt_at = unix_secs().saturating_add(backoff);
        let _ = self.save_job(&job);
        log::warn!(
            "archive upload failed; retry scheduled (job={}, attempt={}, delay={}s)",
            job.id,
            job.attempts,
            backoff
        );
    }

    fn complete(&self, job: &ArchiveJob) {
        let protected = self.protected_body_paths(Some(&job.id));
        for body_path in &job.body_paths {
            let path = Path::new(body_path);
            if !protected.contains(path) {
                let _ = fs::remove_file(path);
            }
        }
        let _ = fs::remove_file(&job.source_path);
        if let Some(payload_path) = &job.payload_path {
            let _ = fs::remove_file(payload_path);
        }
        let _ = fs::remove_file(self.pending_dir.join(format!("{}.json", job.id)));
    }

    /// Return body files referenced by queued jobs and unfinished rotation intents. The current
    /// job and intent remain protected until their queue records are removed, so normal cleanup
    /// cannot race rotation recovery or an upload.
    pub fn protected_body_paths(&self, exclude_job: Option<&str>) -> HashSet<PathBuf> {
        let mut protected = HashSet::new();
        for job in self.load_jobs() {
            if exclude_job == Some(job.id.as_str()) {
                continue;
            }
            if !job.body_paths.is_empty() {
                protected.extend(job.body_paths.iter().map(PathBuf::from));
                continue;
            }
            if let Ok(paths) = body_paths_from_log(Path::new(&job.source_path)) {
                protected.extend(paths.into_iter().map(PathBuf::from));
            }
        }

        let Ok(entries) = fs::read_dir(&self.pending_dir) else {
            return protected;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with(".rotation-")
                || path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(intent) = serde_json::from_slice::<RotationIntent>(&bytes) else {
                continue;
            };

            // The snapshot is the immutable source for recovery. If snapshot creation itself
            // failed after the intent was persisted, protect the still-active log as well.
            for source in [&intent.snapshot_path, &intent.log_path] {
                if let Ok(paths) = body_paths_from_log(Path::new(source)) {
                    protected.extend(paths.into_iter().map(PathBuf::from));
                }
            }
        }
        protected
    }

    fn prepare(&self, mut job: ArchiveJob) -> io::Result<(ArchiveJob, Vec<u8>, String)> {
        if let (Some(payload_path), Some(digest)) = (&job.payload_path, &job.payload_sha256) {
            let bytes = fs::read(payload_path)?;
            let actual_digest = sha256_hex(&bytes);
            if actual_digest == *digest {
                return Ok((job, bytes, actual_digest));
            }
            log::warn!(
                "archive payload checksum mismatch; rebuilding (job={}, expected={}, actual={})",
                job.id,
                digest,
                actual_digest
            );
        }

        let (package, body_paths) = package_log(Path::new(&job.source_path))?;
        let bytes = serde_json::to_vec(&package)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let digest = sha256_hex(&bytes);
        let payload_path = self.payload_dir.join(format!("{}.json", job.id));
        let temp = self.payload_dir.join(format!("{}.json.tmp", job.id));
        fs::write(&temp, &bytes)?;
        fs::rename(temp, &payload_path)?;
        job.payload_path = Some(payload_path.to_string_lossy().into_owned());
        job.body_paths = body_paths;
        job.payload_sha256 = Some(digest.clone());
        self.save_job(&job)?;
        Ok((job, bytes, digest))
    }
}

#[async_trait]
trait ArchiveUploader: Send + Sync {
    async fn upload(&self, key: &str, bytes: Vec<u8>, digest: &str) -> Result<(), String>;
}

struct S3Uploader {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Uploader {
    async fn new(config: &ArchiveConfig) -> anyhow::Result<Self> {
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()))
            .load()
            .await;
        let mut builder =
            aws_sdk_s3::config::Builder::from(&shared).force_path_style(config.endpoint.is_some());
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
        })
    }
}

#[async_trait]
impl ArchiveUploader for S3Uploader {
    async fn upload(&self, key: &str, bytes: Vec<u8>, digest: &str) -> Result<(), String> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/json")
            .metadata("sha256", digest)
            .body(ByteStream::from(bytes.clone()))
            .send()
            .await
            .map_err(|_| "put_object failed".to_string())?;

        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| "head_object verification failed".to_string())?;
        if head.content_length().unwrap_or(-1) != bytes.len() as i64 {
            return Err("head_object size verification failed".to_string());
        }
        if head
            .metadata()
            .and_then(|metadata| metadata.get("sha256"))
            .map(String::as_str)
            != Some(digest)
        {
            return Err("head_object checksum verification failed".to_string());
        }
        Ok(())
    }
}

pub struct ArchiveHandle {
    stop: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl ArchiveHandle {
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.join.await;
    }
}

pub async fn start(
    queue: Arc<ArchiveQueue>,
    config: ArchiveConfig,
) -> anyhow::Result<ArchiveHandle> {
    let uploader = Arc::new(S3Uploader::new(&config).await?);
    let (stop_tx, stop_rx) = oneshot::channel();
    let join = tokio::spawn(run_worker(
        queue,
        uploader,
        config.retry_delay_secs.max(1),
        stop_rx,
    ));
    Ok(ArchiveHandle {
        stop: Some(stop_tx),
        join,
    })
}

async fn run_worker(
    queue: Arc<ArchiveQueue>,
    uploader: Arc<dyn ArchiveUploader>,
    retry_delay_secs: u64,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep(WORKER_POLL_INTERVAL) => {}
        }

        let now = unix_secs();
        for job in queue.load_jobs() {
            if job.next_attempt_at > now {
                continue;
            }
            let Some(current) = queue.load_job(&job.id) else {
                continue;
            };
            let (prepared, bytes, digest) = match queue.prepare(current) {
                Ok(value) => value,
                Err(_) => {
                    queue.mark_retry(job, retry_delay_secs);
                    continue;
                }
            };
            if uploader
                .upload(&prepared.object_key, bytes, &digest)
                .await
                .is_ok()
            {
                queue.complete(&prepared);
            } else {
                queue.mark_retry(prepared, retry_delay_secs);
            }
        }
    }
}

fn package_log(path: &Path) -> io::Result<(ArchivePackage, Vec<String>)> {
    let text = fs::read_to_string(path)?;
    let mut events = Vec::new();
    let mut bodies = Vec::new();
    let mut body_paths = Vec::new();
    let mut seen = HashSet::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if let Some(body_path) = event.get("body_path").and_then(Value::as_str) {
            if seen.insert(body_path.to_string()) {
                let body_bytes = fs::read(body_path)?;
                let content: Value = serde_json::from_slice(&body_bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                bodies.push(ArchiveBody {
                    path: body_path.to_string(),
                    content,
                });
                body_paths.push(body_path.to_string());
            }
        }
        events.push(event);
    }

    Ok((
        ArchivePackage {
            format: ARCHIVE_FORMAT,
            events,
            bodies,
        },
        body_paths,
    ))
}

fn body_paths_from_log(path: &Path) -> io::Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if let Some(path) = event.get("body_path").and_then(Value::as_str) {
            if seen.insert(path.to_string()) {
                paths.push(path.to_string());
            }
        }
    }
    Ok(paths)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn rotated_log_path(base: &Path, n: usize) -> PathBuf {
    let name = format!(
        "{}.{}",
        base.file_name().unwrap_or_default().to_string_lossy(),
        n
    );
    base.with_file_name(name)
}

fn rotation_completed(log_path: &Path, intent: &RotationIntent) -> bool {
    let Ok(_) = fs::metadata(log_path) else {
        return true;
    };

    if let (Some(expected), Ok(actual)) =
        (intent.source_identity.as_deref(), file_identity(log_path))
    {
        return expected != actual;
    }

    fs::read(log_path)
        .map(|bytes| sha256_hex(&bytes) != intent.source_sha256)
        .unwrap_or(true)
}

#[cfg(unix)]
fn file_identity(path: &Path) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    Ok(format!("{}:{:?}", metadata.len(), metadata.modified()?))
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", nanos, std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct FailingUploader {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ArchiveUploader for FailingUploader {
        async fn upload(&self, _key: &str, _bytes: Vec<u8>, _digest: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err("test upload failure".to_string())
        }
    }

    struct VerifyingUploader {
        calls: AtomicUsize,
        failures_remaining: AtomicUsize,
        uploaded: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl ArchiveUploader for VerifyingUploader {
        async fn upload(&self, _key: &str, bytes: Vec<u8>, digest: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if sha256_hex(&bytes) != digest {
                return Err("test checksum verification failed".to_string());
            }
            if self
                .failures_remaining
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    if remaining > 0 {
                        Some(remaining - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return Err("test transient upload failure".to_string());
            }
            *self.uploaded.lock().unwrap() = bytes;
            Ok(())
        }
    }

    #[test]
    fn queue_keeps_rotated_snapshot_and_protects_body() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let body = dir.path().join("body.json");
        fs::write(&body, br#"{"request_body":"hello"}"#).unwrap();
        let log = dir.path().join("events.jsonl.1");
        let event = format!(r#"{{"id":"e1","body_path":"{}"}}"#, body.display()) + "\n";
        fs::write(&log, event).unwrap();

        queue.enqueue_rotated(&log, "tests").unwrap();
        let protected = queue.protected_body_paths(None);
        assert!(protected.contains(&body));
        assert_eq!(queue.load_jobs().len(), 1);
        assert!(queue.closed_dir.read_dir().unwrap().next().is_some());
    }

    #[test]
    fn package_contains_events_and_bodies() {
        let dir = TempDir::new().unwrap();
        let body = dir.path().join("body.json");
        fs::write(&body, br#"{"request_body":"hello"}"#).unwrap();
        let log = dir.path().join("events.jsonl");
        fs::write(
            &log,
            format!(r#"{{"id":"e1","body_path":"{}"}}"#, body.display()) + "\n",
        )
        .unwrap();
        let (package, paths) = package_log(&log).unwrap();
        assert_eq!(package.format, ARCHIVE_FORMAT);
        assert_eq!(package.events.len(), 1);
        assert_eq!(package.bodies.len(), 1);
        assert_eq!(paths, vec![body.to_string_lossy().to_string()]);
    }

    #[test]
    fn pending_jobs_survive_queue_reopen() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl.1");
        fs::write(&log, "{\"id\":\"e1\"}\n").unwrap();
        queue.enqueue_rotated(&log, "tests").unwrap();
        assert_eq!(queue.pending_count(), 1);

        let reopened = ArchiveQueue::open(&runtime).unwrap();
        assert_eq!(reopened.pending_count(), 1);
        assert_eq!(reopened.protected_body_paths(None).len(), 0);
    }

    #[test]
    fn rotation_intent_recovers_after_restart() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl");
        let rotated = dir.path().join("events.jsonl.1");
        fs::write(&log, "{\"id\":\"e1\"}\n").unwrap();
        let source_len = fs::metadata(&log).unwrap().len();
        let intent_id = queue.begin_rotation(&log, source_len).unwrap();
        fs::rename(&log, &rotated).unwrap();
        drop(queue);

        let reopened = ArchiveQueue::open(&runtime).unwrap();
        reopened.recover_rotations(&log, "tests").unwrap();

        assert_eq!(reopened.pending_count(), 1);
        assert!(
            reopened
                .pending_dir
                .join(format!(".rotation-{intent_id}.json"))
                .exists()
                == false
        );
        assert!(reopened.closed_dir.read_dir().unwrap().next().is_some());
    }

    #[test]
    fn orphan_snapshot_is_requeued_after_restart() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let snapshot = queue.closed_dir.join("orphan.jsonl");
        fs::write(&snapshot, "{\"id\":\"orphan\"}\n").unwrap();

        queue
            .recover_rotations(&dir.path().join("events.jsonl"), "tests")
            .unwrap();

        let jobs = queue.load_jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].source_path, snapshot.to_string_lossy());
    }

    #[test]
    fn rotation_recovery_uses_intent_snapshot_not_same_length_orphan() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl");
        let rotated = dir.path().join("events.jsonl.1");
        let current_contents = "{\"id\":\"new\"}\n";
        let stale_contents = "{\"id\":\"old\"}\n";
        assert_eq!(current_contents.len(), stale_contents.len());
        fs::write(&log, current_contents).unwrap();
        let source_len = fs::metadata(&log).unwrap().len();
        let rotation_id = queue.begin_rotation(&log, source_len).unwrap();
        let stable_snapshot = queue
            .closed_dir
            .join(format!("rotation-{rotation_id}.jsonl"));
        fs::rename(&log, &rotated).unwrap();
        let orphan = queue.closed_dir.join("orphan.jsonl");
        fs::write(&orphan, stale_contents).unwrap();

        queue.recover_rotations(&log, "tests").unwrap();

        let jobs = queue.load_jobs();
        let rotation_job = jobs
            .iter()
            .find(|job| job.rotation_id.as_deref() == Some(rotation_id.as_str()))
            .unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(rotation_job.source_path, stable_snapshot.to_string_lossy());
        assert_eq!(
            fs::read_to_string(&rotation_job.source_path).unwrap(),
            current_contents
        );
        assert_eq!(
            rotation_job.rotated_path.as_deref(),
            Some(rotated.to_str().unwrap())
        );
    }

    #[test]
    fn rotation_recovery_keeps_distinct_intents_after_rotated_path_reuse() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl");
        let first_rotated = dir.path().join("events.jsonl.1");
        let second_rotated = dir.path().join("events.jsonl.2");

        fs::write(&log, "{\"id\":\"first\"}\n").unwrap();
        let first_len = fs::metadata(&log).unwrap().len();
        let first_id = queue.begin_rotation(&log, first_len).unwrap();
        fs::rename(&log, &first_rotated).unwrap();
        queue
            .enqueue_rotation(&first_id, "tests", &first_rotated)
            .unwrap();

        fs::rename(&first_rotated, &second_rotated).unwrap();
        fs::write(&log, "{\"id\":\"second\"}\n").unwrap();
        let second_len = fs::metadata(&log).unwrap().len();
        let second_id = queue.begin_rotation(&log, second_len).unwrap();
        let second_snapshot = queue.closed_dir.join(format!("rotation-{second_id}.jsonl"));
        fs::rename(&log, &first_rotated).unwrap();

        queue.recover_rotations(&log, "tests").unwrap();

        let jobs = queue.load_jobs();
        assert_eq!(jobs.len(), 2);
        assert!(jobs
            .iter()
            .any(|job| job.rotation_id.as_deref() == Some(first_id.as_str())));
        let second_job = jobs
            .iter()
            .find(|job| job.rotation_id.as_deref() == Some(second_id.as_str()))
            .unwrap();
        assert_eq!(second_job.source_path, second_snapshot.to_string_lossy());
        assert_eq!(
            fs::read_to_string(&second_job.source_path).unwrap(),
            "{\"id\":\"second\"}\n"
        );
    }

    #[test]
    fn corrupt_payload_is_rebuilt_before_upload() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl.1");
        fs::write(&log, "{\"id\":\"e1\"}\n").unwrap();
        queue.enqueue_rotated(&log, "tests").unwrap();

        let job = queue.load_jobs().pop().unwrap();
        let (prepared, original, digest) = queue.prepare(job).unwrap();
        let payload_path = prepared.payload_path.clone().unwrap();
        let corrupted = vec![0u8; original.len()];
        fs::write(&payload_path, &corrupted).unwrap();

        let (rebuilt_job, rebuilt, rebuilt_digest) = queue.prepare(prepared).unwrap();
        assert_eq!(rebuilt.len(), corrupted.len());
        assert_ne!(rebuilt, corrupted);
        assert_eq!(rebuilt_digest, sha256_hex(&rebuilt));
        assert_eq!(rebuilt_digest, digest);
        assert_eq!(
            rebuilt_job.payload_path.as_deref(),
            Some(payload_path.as_str())
        );
    }

    #[tokio::test]
    async fn worker_keeps_failed_job_for_retry() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = Arc::new(ArchiveQueue::open(&runtime).unwrap());
        let log = dir.path().join("events.jsonl.1");
        fs::write(&log, "{\"id\":\"e1\"}\n").unwrap();
        queue.enqueue_rotated(&log, "tests").unwrap();

        let uploader = Arc::new(FailingUploader {
            calls: AtomicUsize::new(0),
        });
        let (stop_tx, stop_rx) = oneshot::channel();
        let worker = tokio::spawn(run_worker(queue.clone(), uploader.clone(), 60, stop_rx));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = stop_tx.send(());
        worker.await.unwrap();

        let jobs = queue.load_jobs();
        assert_eq!(uploader.calls.load(Ordering::Relaxed), 1);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].attempts, 1);
        assert!(jobs[0].next_attempt_at > unix_secs());
    }

    #[tokio::test]
    async fn worker_upload_retry_verifies_and_cleans_successfully() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = Arc::new(ArchiveQueue::open(&runtime).unwrap());
        let body = dir.path().join("body.json");
        fs::write(&body, br#"{"request_body":"hello"}"#).unwrap();
        let log = dir.path().join("events.jsonl.1");
        let event = format!(r#"{{"id":"e1","body_path":"{}"}}"#, body.display()) + "\n";
        fs::write(&log, event).unwrap();
        queue.enqueue_rotated(&log, "tests").unwrap();

        let uploader = Arc::new(VerifyingUploader {
            calls: AtomicUsize::new(0),
            failures_remaining: AtomicUsize::new(1),
            uploaded: Mutex::new(Vec::new()),
        });
        let (stop_tx, stop_rx) = oneshot::channel();
        let worker = tokio::spawn(run_worker(queue.clone(), uploader.clone(), 1, stop_rx));
        tokio::time::sleep(Duration::from_secs(4)).await;
        let _ = stop_tx.send(());
        worker.await.unwrap();

        assert!(uploader.calls.load(Ordering::Relaxed) >= 2);
        assert!(!uploader.uploaded.lock().unwrap().is_empty());
        assert_eq!(queue.pending_count(), 0);
        assert!(!body.exists());
    }

    #[test]
    fn successful_completion_removes_payload_and_body() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let body = dir.path().join("body.json");
        fs::write(&body, br#"{"request_body":"hello"}"#).unwrap();
        let log = dir.path().join("events.jsonl.1");
        let event = format!(r#"{{"id":"e1","body_path":"{}"}}"#, body.display()) + "\n";
        fs::write(&log, event).unwrap();
        queue.enqueue_rotated(&log, "tests").unwrap();

        let job = queue.load_jobs().pop().unwrap();
        let (prepared, bytes, digest) = queue.prepare(job).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(sha256_hex(&bytes), digest);
        let payload_path = prepared.payload_path.clone().unwrap();
        assert!(Path::new(&payload_path).exists());

        queue.complete(&prepared);

        assert_eq!(queue.pending_count(), 0);
        assert!(!Path::new(&prepared.source_path).exists());
        assert!(!Path::new(&payload_path).exists());
        assert!(!body.exists());
    }
}
