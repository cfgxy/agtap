use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const ARCHIVE_FORMAT: &str = "agtap-hive-jsonl-v1";
const WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY_SECS: u64 = 300;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveCompression {
    /// LZ4 frame is retained as an explicit compatibility option.
    Lz4,
    #[default]
    Zstd,
}

impl ArchiveCompression {
    fn extension(self) -> &'static str {
        match self {
            Self::Lz4 => "lz4",
            Self::Zstd => "zst",
        }
    }

    fn compress(self, input: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Lz4 => {
                let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
                encoder.write_all(input)?;
                encoder.finish().map_err(io::Error::other)
            }
            Self::Zstd => zstd::stream::encode_all(input, 0).map_err(io::Error::other),
        }
    }

    #[cfg(test)]
    fn decompress(self, input: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Lz4 => {
                let mut decoder = lz4_flex::frame::FrameDecoder::new(input);
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
            Self::Zstd => zstd::stream::decode_all(input).map_err(io::Error::other),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub retry_delay_secs: u64,
    pub compression: ArchiveCompression,
}

/// The cleanup path may reclaim a body only for either of these successful,
/// distinguishable outcomes. Any I/O or event-log parse error remains a
/// protection failure and therefore retains the body for a later retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointOutcome {
    Checkpointed,
    Orphaned,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ArchiveJob {
    id: String,
    #[serde(default)]
    rotation_id: Option<String>,
    source_path: String,
    #[serde(default)]
    rotated_path: Option<String>,
    #[serde(default)]
    body_paths: Vec<String>,
    #[serde(default = "default_archive_prefix")]
    object_prefix: String,
    #[serde(default)]
    compression: ArchiveCompression,
    #[serde(default)]
    partition_month: String,
    #[serde(default)]
    partition_day: String,
    #[serde(default)]
    bodies_key: String,
    #[serde(default)]
    events_key: String,
    #[serde(default)]
    manifest_key: String,
    #[serde(default)]
    bodies_payload_path: Option<String>,
    #[serde(default)]
    events_payload_path: Option<String>,
    #[serde(default)]
    manifest_payload_path: Option<String>,
    #[serde(default)]
    bodies_sha256: Option<String>,
    #[serde(default)]
    events_sha256: Option<String>,
    #[serde(default)]
    manifest_sha256: Option<String>,
    /// Non-empty only for an active-log body checkpoint. These IDs are excluded from
    /// the later rotation package, because the checkpoint owns their manifest.
    #[serde(default)]
    checkpoint_event_ids: Vec<String>,
    /// Original body path and content digest retained in the checkpoint record.
    #[serde(default)]
    checkpoint_body_path: Option<String>,
    #[serde(default)]
    checkpoint_body_sha256: Option<String>,
    /// Committed checkpoints excluded while preparing this normal rotation.
    #[serde(default)]
    consumed_checkpoint_event_ids: Vec<String>,
    attempts: u32,
    next_attempt_at: u64,
}

fn default_archive_prefix() -> String {
    "agtap".to_string()
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

#[derive(Clone)]
pub struct ArchiveQueue {
    pending_dir: PathBuf,
    closed_dir: PathBuf,
    payload_dir: PathBuf,
    committed_dir: PathBuf,
}

impl ArchiveQueue {
    pub fn open(runtime_dir: &Path) -> io::Result<Self> {
        let root = runtime_dir.join("archive");
        let pending_dir = root.join("pending");
        let closed_dir = root.join("closed");
        let payload_dir = root.join("payloads");
        // A committed checkpoint stays indexed until the active log is rotated.
        // That prevents the later rotation package from re-emitting an event whose
        // body was already archived through the pressure-path checkpoint.
        let committed_dir = root.join("committed");
        for dir in [&pending_dir, &closed_dir, &payload_dir, &committed_dir] {
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
            committed_dir,
        })
    }

    pub fn enqueue_rotated(&self, rotated_path: &Path, object_prefix: &str) -> io::Result<()> {
        self.enqueue_rotated_with_compression(rotated_path, object_prefix, ArchiveCompression::Zstd)
    }

    pub fn enqueue_rotated_with_compression(
        &self,
        rotated_path: &Path,
        object_prefix: &str,
        compression: ArchiveCompression,
    ) -> io::Result<()> {
        self.enqueue_rotated_with_source(rotated_path, object_prefix, compression, None)
    }

    pub(crate) fn enqueue_rotated_with_source(
        &self,
        rotated_path: &Path,
        object_prefix: &str,
        compression: ArchiveCompression,
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

        if let Err(err) =
            self.enqueue_snapshot(&snapshot, object_prefix, compression, None, rotated_source)
        {
            let _ = fs::remove_file(&snapshot);
            return Err(err);
        }
        Ok(())
    }

    fn enqueue_snapshot(
        &self,
        snapshot: &Path,
        object_prefix: &str,
        compression: ArchiveCompression,
        rotation_id: Option<&str>,
        rotated_source: Option<&Path>,
    ) -> io::Result<()> {
        let id = unique_id();
        let job = ArchiveJob {
            id: id.clone(),
            rotation_id: rotation_id.map(str::to_owned),
            source_path: snapshot.to_string_lossy().into_owned(),
            rotated_path: rotated_source.map(|path| path.to_string_lossy().into_owned()),
            body_paths: Vec::new(),
            object_prefix: object_prefix.trim_matches('/').to_string(),
            compression,
            partition_month: String::new(),
            partition_day: String::new(),
            bodies_key: String::new(),
            events_key: String::new(),
            manifest_key: String::new(),
            bodies_payload_path: None,
            events_payload_path: None,
            manifest_payload_path: None,
            bodies_sha256: None,
            events_sha256: None,
            manifest_sha256: None,
            checkpoint_event_ids: Vec::new(),
            checkpoint_body_path: None,
            checkpoint_body_sha256: None,
            consumed_checkpoint_event_ids: Vec::new(),
            attempts: 0,
            next_attempt_at: 0,
        };
        self.save_job(&job)
    }

    /// Persist a self-contained archive job for a body which is still referenced by
    /// the active event log. This is deliberately called by the cleanup path, not
    /// the capture or forwarding path: the network worker only sees it after the
    /// local checkpoint has been atomically written and verified.
    pub fn checkpoint_active_body(
        &self,
        active_log: &Path,
        body_path: &Path,
        object_prefix: &str,
        compression: ArchiveCompression,
    ) -> io::Result<CheckpointOutcome> {
        if !body_path.is_file() {
            return Ok(CheckpointOutcome::Orphaned);
        }
        let body = fs::read(body_path)?;
        let body_sha256 = sha256_hex(&body);
        let source = fs::read_to_string(active_log)?;
        let original_path = body_path.to_string_lossy().into_owned();
        let mut matching_lines = Vec::new();
        for line in source.lines().filter(|line| !line.trim().is_empty()) {
            let event: Value = serde_json::from_str(line).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("active event log is not valid JSON: {err}"),
                )
            })?;
            if event.get("body_path").and_then(Value::as_str) == Some(original_path.as_str()) {
                matching_lines.push((line.to_string(), event));
            }
        }
        if matching_lines.is_empty() {
            return Ok(CheckpointOutcome::Orphaned);
        }

        let mut seed = body.clone();
        for (line, _) in &matching_lines {
            seed.extend_from_slice(line.as_bytes());
            seed.push(b'\n');
        }
        let id = format!("checkpoint-{}", sha256_hex(&seed));
        if let Some(job) = self.load_job(&id) {
            return self
                .verify_checkpoint(&job)?
                .then_some(CheckpointOutcome::Checkpointed)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "checkpoint record failed verification",
                    )
                });
        }

        let stable_body = self.closed_dir.join(format!("{id}.body.json"));
        let snapshot = self.closed_dir.join(format!("{id}.jsonl"));
        let mut event_ids = Vec::new();
        let mut checkpoint_events = Vec::new();
        for (_, mut event) in matching_lines {
            let Some(event_id) = event.get("id").and_then(Value::as_str) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active event with a body_path has no stable id",
                ));
            };
            if event_id.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active event with a body_path has an empty stable id",
                ));
            }
            event_ids.push(event_id.to_string());
            event["body_path"] = Value::String(stable_body.to_string_lossy().into_owned());
            append_jsonl(&mut checkpoint_events, &event)?;
        }
        event_ids.sort();
        event_ids.dedup();
        if event_ids.iter().all(|event_id| {
            self.committed_dir
                .join(format!("{}.json", checkpoint_marker_id(event_id)))
                .is_file()
        }) {
            return Ok(CheckpointOutcome::Checkpointed);
        }

        write_atomic(&stable_body, &body)?;
        write_atomic(&snapshot, &checkpoint_events)?;
        if sha256_hex(&fs::read(&stable_body)?) != body_sha256
            || fs::read(&snapshot)? != checkpoint_events
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "checkpoint payload verification failed",
            ));
        }

        let job = ArchiveJob {
            id: id.clone(),
            rotation_id: None,
            source_path: snapshot.to_string_lossy().into_owned(),
            rotated_path: None,
            // Protect the original until this verified record lets the cleanup
            // caller remove it. `prepare` replaces this with the stable snapshot
            // path before a worker can complete the job.
            body_paths: vec![original_path.clone()],
            object_prefix: object_prefix.trim_matches('/').to_string(),
            compression,
            partition_month: String::new(),
            partition_day: String::new(),
            bodies_key: String::new(),
            events_key: String::new(),
            manifest_key: String::new(),
            bodies_payload_path: None,
            events_payload_path: None,
            manifest_payload_path: None,
            bodies_sha256: None,
            events_sha256: None,
            manifest_sha256: None,
            checkpoint_event_ids: event_ids,
            checkpoint_body_path: Some(original_path),
            checkpoint_body_sha256: Some(body_sha256),
            consumed_checkpoint_event_ids: Vec::new(),
            attempts: 0,
            next_attempt_at: 0,
        };
        self.save_job(&job)?;
        self.load_job(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "checkpoint record disappeared"))
            .and_then(|saved| {
                self.verify_checkpoint(&saved)?
                    .then_some(CheckpointOutcome::Checkpointed)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "checkpoint record failed verification",
                        )
                    })
            })
    }

    fn verify_checkpoint(&self, job: &ArchiveJob) -> io::Result<bool> {
        let (Some(original), Some(expected_sha)) = (
            job.checkpoint_body_path.as_deref(),
            job.checkpoint_body_sha256.as_deref(),
        ) else {
            return Ok(false);
        };
        if job.checkpoint_event_ids.is_empty() || !Path::new(&job.source_path).is_file() {
            return Ok(false);
        }
        let paths = body_paths_from_log(Path::new(&job.source_path))?;
        if paths.len() != 1 || sha256_hex(&fs::read(&paths[0])?) != expected_sha {
            return Ok(false);
        }
        // The event IDs and original path are both part of the persisted record;
        // the original is intentionally not dereferenced during verification.
        Ok(!original.is_empty())
    }

    pub(crate) fn enqueue_rotation_with_compression(
        &self,
        rotation_id: &str,
        object_prefix: &str,
        compression: ArchiveCompression,
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
            compression,
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
        self.recover_rotations_with_compression(log_path, object_prefix, ArchiveCompression::Zstd)
    }

    pub fn recover_rotations_with_compression(
        &self,
        log_path: &Path,
        object_prefix: &str,
        compression: ArchiveCompression,
    ) -> io::Result<()> {
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
                    compression,
                    Some(&intent.id),
                    Some(Path::new(&intent.rotated_path)),
                )?;
                jobs = self.load_jobs();
                self.complete_rotation(&intent.id)?;
            }
        }

        for snapshot in orphan_snapshots {
            if snapshot.is_file() {
                self.enqueue_snapshot(&snapshot, object_prefix, compression, None, None)?;
            }
        }
        Ok(())
    }

    fn save_job(&self, job: &ArchiveJob) -> io::Result<()> {
        let path = self.pending_dir.join(format!("{}.json", job.id));
        let bytes = serde_json::to_vec_pretty(job)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_atomic(&path, &bytes)
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

    /// Counts only metadata; it never exposes body paths or payload contents.
    pub fn checkpoint_backlog_count(&self) -> usize {
        self.load_jobs()
            .into_iter()
            .filter(|job| !job.checkpoint_event_ids.is_empty())
            .count()
    }

    fn checkpoint_event_ids(&self) -> HashSet<String> {
        let mut ids = self
            .load_jobs()
            .into_iter()
            .flat_map(|job| job.checkpoint_event_ids)
            .collect::<HashSet<_>>();
        if let Ok(entries) = fs::read_dir(&self.committed_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = fs::read(entry.path()) {
                    if let Some(event_id) =
                        serde_json::from_slice::<Value>(&bytes)
                            .ok()
                            .and_then(|value| {
                                value
                                    .get("event_id")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned)
                            })
                    {
                        ids.insert(event_id);
                    }
                }
            }
        }
        ids
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

    /// Mark a job complete only after checkpoint de-duplication markers are durable.
    /// Returning an error leaves all job inputs in place for the worker retry path.
    fn complete(&self, job: &ArchiveJob) -> io::Result<()> {
        for event_id in &job.checkpoint_event_ids {
            let bytes = serde_json::to_vec(&serde_json::json!({"event_id": event_id}))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            write_atomic(
                &self
                    .committed_dir
                    .join(format!("{}.json", checkpoint_marker_id(event_id))),
                &bytes,
            )?;
        }
        for event_id in &job.consumed_checkpoint_event_ids {
            let _ = fs::remove_file(
                self.committed_dir
                    .join(format!("{}.json", checkpoint_marker_id(event_id))),
            );
        }
        let protected = self.protected_body_paths(Some(&job.id));
        for body_path in &job.body_paths {
            let path = Path::new(body_path);
            if !protected.contains(path) {
                let _ = fs::remove_file(path);
            }
        }
        let _ = fs::remove_file(&job.source_path);
        for payload_path in [
            &job.bodies_payload_path,
            &job.events_payload_path,
            &job.manifest_payload_path,
        ]
        .into_iter()
        .flatten()
        {
            let _ = fs::remove_file(payload_path);
        }
        let _ = fs::remove_file(self.pending_dir.join(format!("{}.json", job.id)));
        Ok(())
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
            for source in [&intent.snapshot_path, &intent.log_path] {
                if let Ok(paths) = body_paths_from_log(Path::new(source)) {
                    protected.extend(paths.into_iter().map(PathBuf::from));
                }
            }
        }
        protected
    }

    fn prepare(&self, mut job: ArchiveJob) -> io::Result<PreparedArchive> {
        ensure_layout(&mut job);
        if let Some(prepared) = self.load_cached(&job)? {
            return Ok(prepared);
        }

        let excluded_checkpoint_ids = if job.checkpoint_event_ids.is_empty() {
            self.checkpoint_event_ids()
        } else {
            HashSet::new()
        };
        let (events_jsonl, bodies_jsonl, body_paths) =
            tables_from_log(Path::new(&job.source_path), &excluded_checkpoint_ids)?;
        let bodies = job.compression.compress(&bodies_jsonl)?;
        let events = job.compression.compress(&events_jsonl)?;
        let bodies_digest = sha256_hex(&bodies);
        let events_digest = sha256_hex(&events);

        let bodies_path =
            self.write_payload(&job.id, "bodies", job.compression.extension(), &bodies)?;
        let events_path =
            self.write_payload(&job.id, "events", job.compression.extension(), &events)?;
        let manifest_value = serde_json::json!({
            "format": ARCHIVE_FORMAT,
            "rotation_id": job.rotation_id.as_deref().unwrap_or(&job.id),
            "partition": {"m": job.partition_month, "d": job.partition_day},
            "objects": [
                {"table": "agtap_bodies", "key": job.bodies_key, "sha256": bodies_digest, "size": bodies.len(), "compression": job.compression.extension()},
                {"table": "agtap_events", "key": job.events_key, "sha256": events_digest, "size": events.len(), "compression": job.compression.extension()}
            ]
        });
        let manifest = serde_json::to_vec(&manifest_value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let manifest_digest = sha256_hex(&manifest);
        let manifest_path = self.write_payload(&job.id, "manifest", "json", &manifest)?;

        job.body_paths = body_paths;
        job.bodies_payload_path = Some(bodies_path.to_string_lossy().into_owned());
        job.events_payload_path = Some(events_path.to_string_lossy().into_owned());
        job.manifest_payload_path = Some(manifest_path.to_string_lossy().into_owned());
        job.bodies_sha256 = Some(bodies_digest.clone());
        job.events_sha256 = Some(events_digest.clone());
        job.manifest_sha256 = Some(manifest_digest.clone());
        job.consumed_checkpoint_event_ids = excluded_checkpoint_ids.into_iter().collect();
        self.save_job(&job)?;

        let bodies_key = job.bodies_key.clone();
        let events_key = job.events_key.clone();
        let manifest_key = job.manifest_key.clone();
        Ok(PreparedArchive {
            job,
            bodies: ArchiveObject {
                key: bodies_key,
                bytes: bodies,
                digest: bodies_digest,
            },
            events: ArchiveObject {
                key: events_key,
                bytes: events,
                digest: events_digest,
            },
            manifest: ArchiveObject {
                key: manifest_key,
                bytes: manifest,
                digest: manifest_digest,
            },
        })
    }

    fn write_payload(
        &self,
        id: &str,
        kind: &str,
        extension: &str,
        bytes: &[u8],
    ) -> io::Result<PathBuf> {
        let path = self.payload_dir.join(format!("{id}.{kind}.{extension}"));
        let temp = self
            .payload_dir
            .join(format!("{id}.{kind}.{extension}.tmp"));
        fs::write(&temp, bytes)?;
        fs::rename(temp, &path)?;
        Ok(path)
    }

    fn load_cached(&self, job: &ArchiveJob) -> io::Result<Option<PreparedArchive>> {
        let Some(bodies) = load_object(
            &job.bodies_payload_path,
            &job.bodies_sha256,
            &job.bodies_key,
        )?
        else {
            return Ok(None);
        };
        let Some(events) = load_object(
            &job.events_payload_path,
            &job.events_sha256,
            &job.events_key,
        )?
        else {
            return Ok(None);
        };
        let Some(manifest) = load_object(
            &job.manifest_payload_path,
            &job.manifest_sha256,
            &job.manifest_key,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(PreparedArchive {
            job: job.clone(),
            bodies,
            events,
            manifest,
        }))
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
            if job.next_attempt_at <= now {
                process_job(&queue, uploader.as_ref(), job, retry_delay_secs).await;
            }
        }
    }
}

async fn process_job(
    queue: &ArchiveQueue,
    uploader: &dyn ArchiveUploader,
    job: ArchiveJob,
    retry_delay_secs: u64,
) {
    let Some(current) = queue.load_job(&job.id) else {
        return;
    };
    let prepared = match queue.prepare(current) {
        Ok(value) => value,
        Err(_) => {
            queue.mark_retry(job, retry_delay_secs);
            return;
        }
    };
    // These keys are immutable per rotation. The manifest is deliberately the
    // final commit marker: cleanup is impossible until all three individually
    // head-verified uploads succeed.
    let uploaded = if let Err(err) = uploader
        .upload(
            &prepared.bodies.key,
            prepared.bodies.bytes,
            &prepared.bodies.digest,
        )
        .await
    {
        Err(err)
    } else if let Err(err) = uploader
        .upload(
            &prepared.events.key,
            prepared.events.bytes,
            &prepared.events.digest,
        )
        .await
    {
        Err(err)
    } else {
        uploader
            .upload(
                &prepared.manifest.key,
                prepared.manifest.bytes,
                &prepared.manifest.digest,
            )
            .await
    };
    if uploaded.is_ok() {
        if queue.complete(&prepared.job).is_err() {
            queue.mark_retry(prepared.job, retry_delay_secs);
        }
    } else {
        queue.mark_retry(prepared.job, retry_delay_secs);
    }
}

struct ArchiveObject {
    key: String,
    bytes: Vec<u8>,
    digest: String,
}

struct PreparedArchive {
    job: ArchiveJob,
    bodies: ArchiveObject,
    events: ArchiveObject,
    manifest: ArchiveObject,
}

fn ensure_layout(job: &mut ArchiveJob) {
    if job.partition_month.is_empty() || job.partition_day.is_empty() {
        let now = Utc::now();
        job.partition_month = format!("{:04}{:02}", now.year(), now.month());
        job.partition_day = format!("{:02}", now.day());
    }
    let rotation_id = job.rotation_id.as_deref().unwrap_or(&job.id);
    let prefix = job.object_prefix.trim_matches('/');
    let partition = format!("m={}/d={}", job.partition_month, job.partition_day);
    let codec = job.compression.extension();
    if job.bodies_key.is_empty() {
        job.bodies_key =
            format!("{prefix}/agtap_bodies/{partition}/part-{rotation_id}.jsonl.{codec}");
    }
    if job.events_key.is_empty() {
        job.events_key =
            format!("{prefix}/agtap_events/{partition}/part-{rotation_id}.jsonl.{codec}");
    }
    if job.manifest_key.is_empty() {
        job.manifest_key =
            format!("{prefix}/agtap_manifests/{partition}/commit-{rotation_id}.json");
    }
}

fn load_object(
    path: &Option<String>,
    digest: &Option<String>,
    key: &str,
) -> io::Result<Option<ArchiveObject>> {
    let (Some(path), Some(digest)) = (path, digest) else {
        return Ok(None);
    };
    let bytes = match fs::read(path) {
        Ok(bytes) if sha256_hex(&bytes) == *digest => bytes,
        Ok(_) => return Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    Ok(Some(ArchiveObject {
        key: key.to_string(),
        bytes,
        digest: digest.clone(),
    }))
}

fn tables_from_log(
    path: &Path,
    excluded_event_ids: &HashSet<String>,
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<String>)> {
    let text = fs::read_to_string(path)?;
    let mut events = Vec::new();
    let mut bodies = Vec::new();
    let mut body_paths = Vec::new();
    let mut body_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut emitted_body_ids = HashSet::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut event: Value = serde_json::from_str(line)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if event
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| excluded_event_ids.contains(id))
        {
            continue;
        }
        let body_id = if let Some(body_path) = event.get("body_path").and_then(Value::as_str) {
            let body_path = body_path.to_string();
            if let Some(id) = body_ids.get(&body_path) {
                id.clone()
            } else {
                let bytes = fs::read(&body_path)?;
                let detail: Value = serde_json::from_slice(&bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                let id = sha256_hex(&bytes);
                let row = serde_json::json!({
                    "body_id": id,
                    "request": detail.get("request_body").cloned().unwrap_or(Value::Null),
                    "response": detail.get("response_body").cloned().unwrap_or(Value::Null),
                });
                if emitted_body_ids.insert(id.clone()) {
                    append_jsonl(&mut bodies, &row)?;
                }
                body_paths.push(body_path.clone());
                body_ids.insert(body_path, id.clone());
                id
            }
        } else {
            String::new()
        };
        let object = event.as_object_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "event is not a JSON object")
        })?;
        object.remove("body_path");
        object.insert(
            "body_id".to_string(),
            if body_id.is_empty() {
                Value::Null
            } else {
                Value::String(body_id)
            },
        );
        append_jsonl(&mut events, &event)?;
    }
    Ok((events, bodies, body_paths))
}

fn append_jsonl(output: &mut Vec<u8>, row: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, row)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    output.push(b'\n');
    Ok(())
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

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(temp, path)
}

fn checkpoint_marker_id(event_id: &str) -> String {
    sha256_hex(event_id.as_bytes())
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
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct RecordingUploader {
        keys: Mutex<Vec<String>>,
        fail_key: Option<&'static str>,
    }

    #[async_trait]
    impl ArchiveUploader for RecordingUploader {
        async fn upload(&self, key: &str, bytes: Vec<u8>, digest: &str) -> Result<(), String> {
            if sha256_hex(&bytes) != digest {
                return Err("checksum mismatch".to_string());
            }
            self.keys.lock().unwrap().push(key.to_string());
            if self.fail_key.is_some_and(|expected| key.contains(expected)) {
                return Err("forced object verification failure".to_string());
            }
            Ok(())
        }
    }

    fn fixture(
        queue: &ArchiveQueue,
        dir: &TempDir,
        compression: ArchiveCompression,
    ) -> (PathBuf, PathBuf) {
        let body = dir.path().join("body.json");
        fs::write(
            &body,
            br#"{"request_body":"hello","response_body":"world","request_path":"/v1/chat/completions"}"#,
        )
        .unwrap();
        let log = dir.path().join("events.jsonl.1");
        fs::write(
            &log,
            format!(
                "{{\"id\":\"e1\",\"model\":\"m\",\"body_path\":\"{}\"}}\n{{\"id\":\"e2\",\"model\":\"m\"}}\n",
                body.display()
            ),
        )
        .unwrap();
        queue
            .enqueue_rotated_with_compression(&log, "tenant", compression)
            .unwrap();
        (log, body)
    }

    #[test]
    fn jsonl_parts_have_partitioned_paths_and_body_id_join() {
        let dir = TempDir::new().unwrap();
        let queue = ArchiveQueue::open(&dir.path().join("runtime")).unwrap();
        let (_, body_path) = fixture(&queue, &dir, ArchiveCompression::Lz4);
        let prepared = queue.prepare(queue.load_jobs().pop().unwrap()).unwrap();

        assert!(prepared.events.key.starts_with("tenant/agtap_events/m="));
        assert!(prepared.events.key.contains("/d="));
        assert!(prepared.events.key.ends_with(".jsonl.lz4"));
        assert!(prepared.bodies.key.starts_with("tenant/agtap_bodies/m="));
        assert!(prepared
            .manifest
            .key
            .starts_with("tenant/agtap_manifests/m="));
        assert!(prepared.manifest.key.ends_with(".json"));

        let events = String::from_utf8(
            ArchiveCompression::Lz4
                .decompress(&prepared.events.bytes)
                .unwrap(),
        )
        .unwrap();
        let bodies = String::from_utf8(
            ArchiveCompression::Lz4
                .decompress(&prepared.bodies.bytes)
                .unwrap(),
        )
        .unwrap();
        let event_lines = events.lines().collect::<Vec<_>>();
        let body_lines = bodies.lines().collect::<Vec<_>>();
        assert_eq!(event_lines.len(), 2);
        assert_eq!(body_lines.len(), 1);
        let event: Value = serde_json::from_str(event_lines[0]).unwrap();
        let body: Value = serde_json::from_str(body_lines[0]).unwrap();
        assert_eq!(event["body_id"], body["body_id"]);
        assert!(event.get("body_path").is_none());
        assert_eq!(body["request"], "hello");
        assert_eq!(body["response"], "world");
        assert!(body_path.exists());
    }

    #[test]
    fn default_compression_is_zstd() {
        assert_eq!(ArchiveCompression::default(), ArchiveCompression::Zstd);
    }

    #[test]
    fn lz4_frame_and_zstd_round_trip_jsonl() {
        let source = b"{\"body_id\":\"b\"}\n";
        for compression in [ArchiveCompression::Lz4, ArchiveCompression::Zstd] {
            let encoded = compression.compress(source).unwrap();
            assert_eq!(compression.decompress(&encoded).unwrap(), source);
        }
        // LZ4 frame magic, not a raw LZ4 block.
        assert_eq!(
            ArchiveCompression::Lz4.compress(source).unwrap()[..4],
            [0x04, 0x22, 0x4d, 0x18]
        );
    }

    #[tokio::test]
    async fn manifest_is_last_and_failed_verification_keeps_job_for_restart() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let (_, body) = fixture(&queue, &dir, ArchiveCompression::Zstd);
        let job = queue.load_jobs().pop().unwrap();
        let failing = RecordingUploader {
            keys: Mutex::new(Vec::new()),
            fail_key: Some("agtap_manifests/"),
        };
        process_job(&queue, &failing, job, 1).await;
        assert_eq!(queue.pending_count(), 1);
        assert!(body.exists());
        let queued = queue.load_jobs().pop().unwrap();
        assert!(Path::new(&queued.source_path).exists());
        assert!(queued
            .bodies_payload_path
            .as_ref()
            .is_some_and(|path| Path::new(path).exists()));
        let failed_keys = failing.keys.lock().unwrap().clone();
        assert_eq!(failed_keys.len(), 3);
        assert!(failed_keys[0].contains("agtap_bodies/"));
        assert!(failed_keys[1].contains("agtap_events/"));
        assert!(failed_keys[2].contains("agtap_manifests/"));

        let reopened = ArchiveQueue::open(&runtime).unwrap();
        let job = reopened.load_jobs().pop().unwrap();
        let succeeding = RecordingUploader {
            keys: Mutex::new(Vec::new()),
            fail_key: None,
        };
        process_job(&reopened, &succeeding, job, 1).await;
        assert_eq!(reopened.pending_count(), 0);
        assert!(!body.exists());
        let keys = succeeding.keys.lock().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys[0].contains("agtap_bodies/"));
        assert!(keys[1].contains("agtap_events/"));
        assert!(keys[2].contains("agtap_manifests/"));
    }

    #[test]
    fn rotation_intent_reopens_as_same_zstd_job() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let log = dir.path().join("events.jsonl");
        let rotated = dir.path().join("events.jsonl.1");
        fs::write(&log, "{\"id\":\"e1\"}\n").unwrap();
        let rotation_id = queue
            .begin_rotation(&log, fs::metadata(&log).unwrap().len())
            .unwrap();
        fs::rename(&log, &rotated).unwrap();
        drop(queue);

        let reopened = ArchiveQueue::open(&runtime).unwrap();
        reopened
            .recover_rotations_with_compression(&log, "tenant", ArchiveCompression::Zstd)
            .unwrap();
        let job = reopened.load_jobs().pop().unwrap();
        assert_eq!(job.rotation_id.as_deref(), Some(rotation_id.as_str()));
        assert_eq!(job.compression, ArchiveCompression::Zstd);
    }

    #[tokio::test]
    async fn checkpoint_marker_write_failure_retains_job_until_retry() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let body = dir.path().join("body.json");
        fs::write(
            &body,
            br#"{"request_body":"fixture-request","response_body":"fixture-response"}"#,
        )
        .unwrap();
        let active = dir.path().join("events.jsonl");
        fs::write(
            &active,
            format!(
                "{{\"id\":\"checkpoint-event\",\"body_path\":\"{}\"}}\n",
                body.display()
            ),
        )
        .unwrap();
        assert_eq!(
            queue
                .checkpoint_active_body(&active, &body, "tenant", ArchiveCompression::Zstd)
                .unwrap(),
            CheckpointOutcome::Checkpointed
        );
        // The cleanup path may already have reclaimed this original after the
        // checkpoint record was verified; the stable checkpoint body is distinct.
        fs::remove_file(&body).unwrap();
        let job = queue.load_jobs().pop().unwrap();
        let stable_snapshot = PathBuf::from(&job.source_path);
        let stable_body = body_paths_from_log(&stable_snapshot)
            .unwrap()
            .pop()
            .unwrap();

        let committed = runtime.join("archive/committed");
        fs::remove_dir(&committed).unwrap();
        fs::write(&committed, b"failure injection").unwrap();
        let uploader = RecordingUploader {
            keys: Mutex::new(Vec::new()),
            fail_key: None,
        };
        process_job(&queue, &uploader, job, 1).await;

        let retained = queue.load_jobs().pop().unwrap();
        assert!(stable_snapshot.exists());
        assert!(Path::new(&stable_body).exists());
        assert!(retained
            .manifest_payload_path
            .as_ref()
            .is_some_and(|path| Path::new(path).exists()));
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(retained.attempts, 1);

        fs::remove_file(&committed).unwrap();
        fs::create_dir(&committed).unwrap();
        process_job(&queue, &uploader, retained, 1).await;
        assert_eq!(queue.pending_count(), 0);
        assert!(!stable_snapshot.exists());
        assert!(!Path::new(&stable_body).exists());
        assert!(committed.read_dir().unwrap().next().is_some());
    }

    #[tokio::test]
    async fn active_log_checkpoint_survives_failure_restart_and_rotation() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        let body = dir.path().join("body.json");
        fs::write(
            &body,
            br#"{"request_body":"fixture-request","response_body":"fixture-response"}"#,
        )
        .unwrap();
        let sse_body = dir.path().join("sse-body.json");
        fs::write(
            &sse_body,
            br#"{"request_body":"fixture-sse-request","response_body":"fixture-sse-response"}"#,
        )
        .unwrap();
        let active = dir.path().join("events.jsonl");
        fs::write(
            &active,
            format!(
                "{{\"id\":\"plain\",\"streaming\":false,\"body_path\":\"{}\"}}\n{{\"id\":\"sse\",\"streaming\":true,\"body_path\":\"{}\"}}\n",
                body.display(),
                sse_body.display(),
            ),
        )
        .unwrap();

        assert_eq!(
            queue
                .checkpoint_active_body(&active, &body, "tenant", ArchiveCompression::Zstd)
                .unwrap(),
            CheckpointOutcome::Checkpointed
        );
        assert!(queue.protected_body_paths(None).contains(&body));
        // This models cleanup after the verified local checkpoint, not a worker upload.
        fs::remove_file(&body).unwrap();

        let job = queue.load_jobs().pop().unwrap();
        let failing = RecordingUploader {
            keys: Mutex::new(Vec::new()),
            fail_key: Some("agtap_manifests/"),
        };
        process_job(&queue, &failing, job, 1).await;
        assert_eq!(queue.checkpoint_backlog_count(), 1);
        drop(queue);

        // Restart after payload preparation but before a verified manifest.
        let reopened = ArchiveQueue::open(&runtime).unwrap();
        let checkpoint = reopened
            .load_jobs()
            .into_iter()
            .find(|job| !job.checkpoint_event_ids.is_empty())
            .unwrap();
        assert!(reopened.verify_checkpoint(&checkpoint).unwrap());
        let succeeding = RecordingUploader {
            keys: Mutex::new(Vec::new()),
            fail_key: None,
        };
        process_job(&reopened, &succeeding, checkpoint, 1).await;
        assert_eq!(reopened.checkpoint_backlog_count(), 0);

        // A later normal rotation excludes the already committed event but keeps
        // the SSE event, so there is exactly one stable event/body association.
        let rotated = dir.path().join("events.jsonl.1");
        fs::rename(&active, &rotated).unwrap();
        reopened
            .enqueue_rotated_with_compression(&rotated, "tenant", ArchiveCompression::Zstd)
            .unwrap();
        let rotation = reopened
            .load_jobs()
            .into_iter()
            .find(|job| job.checkpoint_event_ids.is_empty())
            .unwrap();
        let prepared = reopened.prepare(rotation.clone()).unwrap();
        let events = String::from_utf8(
            ArchiveCompression::Zstd
                .decompress(&prepared.events.bytes)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(events.lines().count(), 1);
        assert!(events.contains("sse"));
        assert!(!events.contains("plain"));
        let bodies = String::from_utf8(
            ArchiveCompression::Zstd
                .decompress(&prepared.bodies.bytes)
                .unwrap(),
        )
        .unwrap();
        let event: Value = serde_json::from_str(events.lines().next().unwrap()).unwrap();
        let archived_body: Value = serde_json::from_str(bodies.lines().next().unwrap()).unwrap();
        assert_eq!(event["body_id"], archived_body["body_id"]);
        assert_eq!(
            archived_body["body_id"],
            Value::String(sha256_hex(&fs::read(&sse_body).unwrap()))
        );

        process_job(&reopened, &succeeding, rotation, 1).await;
        assert!(reopened.checkpoint_event_ids().is_empty());
    }

    #[test]
    fn invalid_active_log_never_classifies_a_body_as_orphan() {
        let dir = TempDir::new().unwrap();
        let queue = ArchiveQueue::open(&dir.path().join("runtime")).unwrap();
        let body = dir.path().join("body.json");
        fs::write(&body, b"fixture").unwrap();
        let log = dir.path().join("events.jsonl");
        fs::write(&log, "not-json\n").unwrap();

        assert!(queue
            .checkpoint_active_body(&log, &body, "tenant", ArchiveCompression::Zstd)
            .is_err());
        assert_eq!(queue.pending_count(), 0);
        assert!(body.exists());
    }

    #[test]
    fn checkpoint_is_idempotent_before_worker_runs() {
        let dir = TempDir::new().unwrap();
        let queue = ArchiveQueue::open(&dir.path().join("runtime")).unwrap();
        let body = dir.path().join("body.json");
        fs::write(
            &body,
            br#"{"request_body":"fixture","response_body":"fixture"}"#,
        )
        .unwrap();
        let log = dir.path().join("events.jsonl");
        fs::write(
            &log,
            format!("{{\"id\":\"e1\",\"body_path\":\"{}\"}}\n", body.display()),
        )
        .unwrap();
        assert_eq!(
            queue
                .checkpoint_active_body(&log, &body, "tenant", ArchiveCompression::Zstd)
                .unwrap(),
            CheckpointOutcome::Checkpointed
        );
        assert_eq!(
            queue
                .checkpoint_active_body(&log, &body, "tenant", ArchiveCompression::Zstd)
                .unwrap(),
            CheckpointOutcome::Checkpointed
        );
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn pending_jobs_survive_queue_reopen() {
        let dir = TempDir::new().unwrap();
        let runtime = dir.path().join("runtime");
        let queue = ArchiveQueue::open(&runtime).unwrap();
        fixture(&queue, &dir, ArchiveCompression::Lz4);
        assert_eq!(queue.pending_count(), 1);
        let reopened = ArchiveQueue::open(&runtime).unwrap();
        assert_eq!(reopened.pending_count(), 1);
    }
}
