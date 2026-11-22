mod bpf;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aya::maps::RingBuf;
use clap::{Parser, Subcommand};
use log::{info, warn};
use tokio::signal;
use tokio::sync::mpsc;

use agtap::archive::{self, ArchiveCompression, ArchiveConfig, ArchiveQueue};
use agtap::body_store::BodyStore;
use agtap::pipe;
use agtap::providers::{self, anthropic, gemini, mcp, openai_completions, openai_responses};
use agtap::reassembly::{ApiKind, HttpExchange};
use agtap::stdio_reassembly::StdioReassembler;
use agtap::tui;
use agtap::{event_log, output, reassembly, socket, telemetry, tls};
use agtap_common::{SslEvent, MAX_HTTP_HEADER_CAPTURE_SIZE, TCP_CLOSE_FLAG, TCP_FLAG};
use telemetry::PrometheusMetrics;

/// How often (seconds) we check for idle connections and run body store cleanup.
const CLEANUP_CHECK_INTERVAL_SECS: u64 = 10;
/// Non-streaming connections idle longer than this are flushed (seconds).
const IDLE_TIMEOUT_SECS: u64 = 60;
/// Streaming connections idle longer than this are flushed (seconds).
const STREAMING_IDLE_TIMEOUT_SECS: u64 = 30;
/// How often (seconds) we re-scan /proc for new SSL/libc targets.
const RESCAN_INTERVAL_SECS: u64 = 60;

fn resolve_process_name(cache: &mut HashMap<u32, String>, pid: u32, comm: &str) -> String {
    cache
        .entry(pid)
        .or_insert_with(|| pipe::identify_process(pid, comm))
        .clone()
}

/// Resolve process name, checking MCP `_meta` / `clientInfo` for agent identification first.
/// Caches successful detection so subsequent MCP events from the same PID inherit the name.
fn resolve_proc_name(
    cache: &mut HashMap<u32, String>,
    pid: u32,
    comm: &str,
    call: &providers::LlmCall,
    detail: &providers::HttpDetail,
) -> String {
    if call.provider == "mcp" {
        if let Some(cached) = cache.get(&pid) {
            return cached.clone();
        }
        if let Some(name) = providers::detect_meta_process(&detail.request_body) {
            let s = name.to_string();
            cache.insert(pid, s.clone());
            return s;
        }
    }
    resolve_process_name(cache, pid, comm)
}

fn parse_exchange(
    api_kind: ApiKind,
    exchange: HttpExchange,
) -> Option<(providers::LlmCall, providers::HttpDetail)> {
    match api_kind {
        ApiKind::Anthropic => anthropic::parse_exchange(exchange),
        ApiKind::Gemini => gemini::parse_exchange(exchange),
        ApiKind::OpenAi if exchange.request.path.ends_with("/v1/responses") => {
            openai_responses::parse_exchange(exchange)
        }
        ApiKind::OpenAi if exchange.request.path.is_empty() => {
            // Response-only capture: peek at body to distinguish Responses vs Completions API
            if looks_like_openai_responses_api(&exchange.response.body) {
                openai_responses::parse_exchange(exchange)
            } else {
                openai_completions::parse_exchange(exchange)
            }
        }
        ApiKind::OpenAi => openai_completions::parse_exchange(exchange),
        ApiKind::Mcp => mcp::parse_exchange(exchange),
    }
}

/// Quick byte-level check to distinguish OpenAI Responses API from Completions API.
/// Responses API has `"output":[` in the body; Completions API has `"choices":[`.
fn looks_like_openai_responses_api(body: &[u8]) -> bool {
    body.windows(b"\"output\":[".len())
        .any(|w| w == b"\"output\":[")
        || body
            .windows(b"\"output\": [".len())
            .any(|w| w == b"\"output\": [")
}

#[derive(Parser, Debug)]
#[command(name = "agtap", version, about = "eBPF-based LLM API call profiler")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Attach to specific PID
    #[arg(short, long)]
    pid: Option<i32>,

    /// Attach by process name
    #[arg(short, long)]
    comm: Option<String>,

    /// Verbose output (show BPF loading, TLS discovery debug info)
    #[arg(short, long)]
    verbose: bool,

    /// Enable OpenTelemetry export to the given OTLP endpoint (e.g. http://localhost:4318)
    #[arg(long)]
    otel: Option<String>,

    /// Maximum body store size in MB (default: 500)
    #[arg(long, default_value = "500")]
    max_body_store: u64,

    /// Body file retention in hours (default: 24)
    #[arg(long, default_value = "24")]
    body_retention: u64,

    /// Maximum request/response body retained in each detail file (default: 512 KiB; hard cap: 1024 KiB)
    #[arg(long, default_value = "512")]
    max_body_retain_kb: u64,

    /// Expose Prometheus metrics endpoint (e.g. 127.0.0.1:9464)
    #[arg(long)]
    metrics_addr: Option<String>,

    /// Maximum event log size in MB before rotation (default: 50)
    #[arg(long, default_value = "50")]
    max_log_size: u64,

    /// Maximum number of rotated log files to keep (default: 3)
    #[arg(long, default_value = "3")]
    max_log_files: usize,

    /// S3-compatible endpoint. Leave unset for AWS S3.
    #[arg(long)]
    archive_s3_endpoint: Option<String>,

    /// S3 bucket enabling asynchronous archive uploads.
    #[arg(long)]
    archive_s3_bucket: Option<String>,

    /// Object key prefix for archived packages (default: agtap)
    #[arg(long, default_value = "agtap")]
    archive_s3_prefix: String,

    /// S3 region (default: us-east-1)
    #[arg(long, default_value = "us-east-1")]
    archive_s3_region: String,

    /// Compression for archive JSONL parts: zstd (default) or explicit lz4 frame.
    #[arg(long, value_enum, default_value = "zstd")]
    archive_compression: ArchiveCompression,

    /// Base delay before retrying a failed archive upload (seconds)
    #[arg(long, default_value = "5")]
    archive_retry_delay_secs: u64,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Live TUI dashboard (connects to running daemon)
    Tui,
    /// Remove all runtime data (logs, bodies, socket) from /tmp/agtap/
    Clean,
}

/// Get boot time in nanoseconds for converting ktime_ns to wall clock.
fn get_boot_time_ns() -> u64 {
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            if line.starts_with("btime ") {
                if let Some(secs_str) = line.split_whitespace().nth(1) {
                    if let Ok(secs) = secs_str.parse::<u64>() {
                        return secs * 1_000_000_000;
                    }
                }
            }
        }
    }
    0
}

/// Groups the 4 output sinks that every event is fanned out to.
struct EventSinks<'a> {
    log_writer: &'a mut event_log::LogWriter,
    socket_tx: &'a mpsc::Sender<output::AgentEvent>,
    otel_handle: Option<&'a telemetry::TelemetryHandle>,
    prom_metrics: Option<&'a Arc<PrometheusMetrics>>,
}

impl EventSinks<'_> {
    async fn emit(&mut self, event: &output::AgentEvent) {
        output::print_event(event);
        self.log_writer.write_event(event);
        let _ = self.socket_tx.send(event.clone()).await;
        if let Some(otel) = self.otel_handle {
            telemetry::record_event(otel, event);
        }
        if let Some(prom) = self.prom_metrics {
            telemetry::record_prometheus(prom, event);
        }
    }
}

/// Process all pending events from the ring buffer, parsing exchanges and
/// dispatching AgentEvents to stdout, log file, socket server, and OTel.
#[allow(clippy::too_many_arguments)]
async fn drain_ring_events(
    ring: &mut RingBuf<impl std::borrow::Borrow<aya::maps::MapData>>,
    reassembler: &mut reassembly::Reassembler,
    stdio_reassembler: &mut StdioReassembler,
    boot_time_ns: u64,
    comm_filter: &Option<String>,
    target_pid: Option<i32>,
    verbose: bool,
    sinks: &mut EventSinks<'_>,
    body_store: &mut BodyStore,
    process_name_cache: &mut HashMap<u32, String>,
) {
    while let Some(item) = ring.next() {
        let data = &*item;
        if data.len() < std::mem::size_of::<SslEvent>() {
            continue;
        }

        let event = unsafe { &*(data.as_ptr() as *const SslEvent) };

        let data_len = event.data_len as usize;
        let actual_data = if data_len <= agtap_common::MAX_DATA_SIZE {
            &event.data[..data_len]
        } else {
            &event.data[..]
        };

        let comm = std::str::from_utf8(&event.comm)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let is_pipe = StdioReassembler::is_pipe_event(event.direction);
        let is_tcp = (event.direction & TCP_FLAG) != 0;
        let is_tcp_close = is_tcp && (event.direction & TCP_CLOSE_FLAG) != 0;
        let actual_dir = reassembly::actual_direction(event.direction);

        if verbose {
            let source = if is_pipe {
                "PIPE"
            } else if is_tcp {
                "TCP"
            } else {
                "SSL"
            };
            let dir = if actual_dir == 0 { "WRITE" } else { "READ" };
            let id_label = if is_pipe {
                "ino"
            } else if is_tcp {
                "fd"
            } else {
                "ssl"
            };
            let preview = String::from_utf8_lossy(&actual_data[..actual_data.len().min(120)]);
            eprintln!(
                "[{}] pid={} {}={:#x} {} {} len={}\n  {}",
                comm, event.pid, id_label, event.ssl_ptr, source, dir, data_len, preview
            );
        }

        if is_pipe {
            // Kprobes are global — apply PID/comm filter, allowing child processes through
            if let Some(pid) = target_pid {
                let dominated = event.pid == pid as u32
                    || stdio_reassembler.is_descendant_cached(event.pid, pid as u32);
                if !dominated {
                    continue;
                }
            }
            if let Some(ref filter) = comm_filter {
                if comm != *filter {
                    let dominated =
                        stdio_reassembler
                            .cached_parent(event.pid)
                            .is_some_and(|ppid| {
                                pipe::comm_of(ppid).as_deref() == Some(filter.as_str())
                            });
                    if !dominated {
                        continue;
                    }
                }
            }

            for (call, detail) in stdio_reassembler.process_event(
                event.pid,
                event.ssl_ptr,
                event.direction,
                actual_data,
                event.timestamp_ns,
            ) {
                let body_path = body_store
                    .write(event.pid, event.timestamp_ns, &call.id, &detail)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned());
                let proc_name =
                    resolve_proc_name(process_name_cache, event.pid, &comm, &call, &detail);
                let agent_event =
                    output::format_event(&call, event.pid, &proc_name, boot_time_ns, body_path);
                sinks.emit(&agent_event).await;
            }
        } else {
            // The syscall kprobes are global, so enforce the selected PID
            // again before accepting TCP or SSL data in userspace.
            if let Some(pid) = target_pid {
                if event.pid != pid as u32 {
                    continue;
                }
            }

            // Connection ID encoding uses upper 4 bits as type tag:
            //   0x0_... = SSL pointer (from SSL uprobe, ssl_ptr field is real pointer)
            //   0x1_... = TCP fd (from send/recv uprobe or Go syscall kprobe)
            let conn_id = if is_tcp {
                event.ssl_ptr | (1u64 << 60) // type tag: TCP
            } else {
                event.ssl_ptr // type tag: SSL (0x0)
            };

            if is_tcp_close {
                reassembler.close_connection(event.pid, conn_id);
                continue;
            }
            if data_len == 0 {
                continue;
            }

            // SSL or TCP event — apply comm filter (existing behavior)
            if let (Some(ref filter), None) = (comm_filter, target_pid) {
                if comm != *filter {
                    continue;
                }
            }

            if let Some((api_kind, exchange)) = reassembler.process_event(
                event.pid,
                conn_id,
                event.direction,
                actual_data,
                event.timestamp_ns,
                &comm,
            ) {
                if verbose {
                    eprintln!(
                        "  exchange: req={} bytes, resp={} bytes, streaming={} kind={:?}",
                        exchange.request.body.len(),
                        exchange.response.body.len(),
                        exchange.response.is_streaming,
                        api_kind,
                    );
                }
                let parsed = parse_exchange(api_kind, exchange);
                if let Some((call, detail)) = parsed {
                    let body_path = body_store
                        .write(event.pid, event.timestamp_ns, &call.id, &detail)
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned());
                    let proc_name =
                        resolve_proc_name(process_name_cache, event.pid, &comm, &call, &detail);
                    let agent_event =
                        output::format_event(&call, event.pid, &proc_name, boot_time_ns, body_path);
                    sinks.emit(&agent_event).await;
                } else if verbose {
                    eprintln!("  parse_exchange returned None");
                }
            }
        }
    }
}

fn body_retain_bytes(max_body_retain_kb: u64) -> anyhow::Result<usize> {
    let requested = max_body_retain_kb
        .checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("--max-body-retain-kb is too large"))?;
    let maximum = providers::MAX_BODY_RETAIN_HARD_LIMIT as u64;
    if requested == 0 || requested > maximum {
        anyhow::bail!(
            "--max-body-retain-kb must be between 1 and {} KiB; larger values are rejected so Go direct-syscall capture cannot silently omit body data",
            maximum / 1024
        );
    }
    Ok(requested as usize)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle subcommands — no root needed
    match cli.command {
        Some(Command::Tui) => {
            let sock_path = socket::default_sock_path();
            tui::run(&sock_path).await?;
            return Ok(());
        }
        Some(Command::Clean) => {
            let runtime_dir = agtap::default_runtime_dir();
            // Guard: refuse if daemon is running
            let sock_path = socket::default_sock_path();
            if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
                anyhow::bail!("daemon appears to be running — stop it first");
            }
            if runtime_dir.exists() {
                let mut total_bytes: u64 = 0;
                let mut file_count: u64 = 0;
                fn count_dir(dir: &std::path::Path, bytes: &mut u64, count: &mut u64) {
                    if let Ok(entries) = fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                count_dir(&path, bytes, count);
                            } else {
                                *bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                                *count += 1;
                            }
                        }
                    }
                }
                count_dir(&runtime_dir, &mut total_bytes, &mut file_count);
                fs::remove_dir_all(&runtime_dir)?;
                eprintln!(
                    "agtap: cleaned {} ({} files, {:.1} MB)",
                    runtime_dir.display(),
                    file_count,
                    total_bytes as f64 / 1_048_576.0
                );
            } else {
                eprintln!(
                    "agtap: nothing to clean ({}/ does not exist)",
                    runtime_dir.display()
                );
            }
            return Ok(());
        }
        None => {} // fall through to capture mode
    }

    // ── Capture mode (default) ──────────────────────────────────────────

    let retain_bytes = body_retain_bytes(cli.max_body_retain_kb)?;
    providers::set_max_body_retain_size(retain_bytes);

    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    // Determine target PID and libssl path
    let comm_filter = cli.comm.clone();

    let (target_pid, libssl_path) = match (&cli.pid, &comm_filter) {
        (Some(pid), _) => {
            let pid = *pid;
            let path = match tls::find_ssl_binary_for_pid(pid as u32) {
                Ok(p) => p,
                Err(_) => {
                    info!("No SSL symbols for PID {}, trying system libssl", pid);
                    tls::find_system_libssl()?
                }
            };
            (Some(pid), path)
        }
        (None, Some(comm)) => {
            match tls::find_pids_by_comm(comm) {
                Ok(pids) => {
                    info!("Found PIDs for '{}': {:?}", comm, pids);
                    // Probe the first PID — typically all processes with the same
                    // comm name use the same binary.
                    let pid = pids[0] as i32;
                    let path = match tls::find_ssl_binary_for_pid(pid as u32) {
                        Ok(p) => p,
                        Err(_) => tls::find_system_libssl()?,
                    };
                    (Some(pid), path)
                }
                Err(_) => {
                    info!(
                        "No running process '{}' — attaching system-wide, will filter by comm",
                        comm
                    );
                    let path = tls::find_system_libssl()?;
                    (None, path)
                }
            }
        }
        (None, None) => {
            let path = tls::find_system_libssl()?;
            (None, path)
        }
    };

    info!("Using SSL binary: {}", libssl_path.display());
    if let Some(pid) = target_pid {
        info!("Targeting PID: {}", pid);
    } else if let Some(ref comm) = comm_filter {
        info!("System-wide mode, filtering for comm '{}'", comm);
    } else {
        info!("System-wide mode");
    }

    // Load BPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/agtap-probes"
    )))?;

    let libssl_str = libssl_path.to_string_lossy().to_string();

    for &(prog_name, symbols) in bpf::SSL_PROBES {
        bpf::load_and_attach(&mut ebpf, prog_name, symbols, &libssl_str, target_pid)?;
    }

    eprintln!(
        "agtap: attached to {} — listening for LLM API calls...",
        libssl_path.display()
    );

    // Attach pipe kprobes for stdio MCP monitoring.
    // In aya 0.13, kprobes and kretprobes both use the KProbe type.
    let pipe_progs: &[(&str, &str)] = &[
        ("pipe_vfs_write", "vfs_write"),
        ("pipe_vfs_read_entry", "vfs_read"),
        ("pipe_vfs_read_ret", "vfs_read"),
    ];

    bpf::load_and_attach_kprobes(
        &mut ebpf,
        pipe_progs,
        "pipe kprobes attached — stdio MCP monitoring enabled",
        "stdio MCP disabled",
        "Some pipe kprobes failed to attach — stdio MCP may be incomplete (stash map may fill and stabilize)",
    );

    // Attach writev/readv pipe kprobes (Node.js/libuv uses writev for pipe I/O).
    // Separate group so failure doesn't block existing vfs_write/vfs_read probes.
    let pipev_progs: &[(&str, &str)] = &[
        ("pipe_vfs_writev", "vfs_writev"),
        ("pipe_vfs_readv_entry", "vfs_readv"),
        ("pipe_vfs_readv_ret", "vfs_readv"),
    ];

    bpf::load_and_attach_kprobes(
        &mut ebpf,
        pipev_progs,
        "writev/readv pipe kprobes attached — Node.js MCP capture enabled",
        "writev/readv pipe capture disabled",
        "Some writev/readv pipe kprobes failed to attach",
    );

    // Plain HTTP capture via glibc send()/recv() uprobes.
    // Captures Python, curl, Ruby, Java HTTP clients.
    // Does NOT capture Node.js (writev) or Go (direct syscalls).
    // Musl-based apps are captured via extra libc discovery below.
    let libc_result_path: anyhow::Result<PathBuf> = (|| {
        let libc_path = match (&cli.pid, &comm_filter) {
            (Some(pid), _) => {
                tls::find_libc_for_pid(*pid as u32).or_else(|_| tls::find_system_libc())?
            }
            _ => tls::find_system_libc()?,
        };
        let libc_str = libc_path.to_string_lossy().to_string();
        for &(prog_name, symbols) in bpf::LIBC_PROBES {
            bpf::load_and_attach(&mut ebpf, prog_name, symbols, &libc_str, target_pid)?;
        }
        eprintln!("agtap: libc send/recv uprobes attached — plain HTTP capture enabled");
        Ok(libc_path)
    })();
    if let Err(ref e) = libc_result_path {
        warn!(
            "Plain HTTP capture unavailable: {} (only TLS traffic will be captured)",
            e
        );
    }

    // A statically linked Go server bypasses libc send/recv. ARM64 syscall kprobes
    // are attached only with an exact selected PID and the BPF map filters events
    // to sockets accepted by that process.
    if let Some(pid) = target_pid {
        let syscall_capture_bytes = retain_bytes
            .saturating_add(MAX_HTTP_HEADER_CAPTURE_SIZE)
            .min(agtap_common::MAX_SYSCALL_CAPTURE_SIZE) as u32;
        bpf::load_and_attach_go_syscalls(&mut ebpf, pid, syscall_capture_bytes).map_err(|err| {
            anyhow::anyhow!(
                "Go direct-syscall HTTP capture could not load for PID {}; refusing to start without the selected target's capture path: {}",
                pid,
                err
            )
        })?;
        eprintln!("agtap: Go arm64 syscall kprobes attached for PID {}", pid);
    } else {
        info!("Go direct-syscall HTTP capture requires --pid or a resolved --comm target");
    }

    let boot_time_ns = get_boot_time_ns();

    // Initialize sinks
    let otel_handle = if let Some(ref endpoint) = cli.otel {
        match telemetry::init(telemetry::TelemetryConfig {
            endpoint: endpoint.clone(),
            boot_time_ns,
        }) {
            Ok(handle) => {
                eprintln!("agtap: OTel export enabled → {}", endpoint);
                Some(handle)
            }
            Err(e) => {
                eprintln!("agtap: failed to init OTel (continuing without): {}", e);
                None
            }
        }
    } else {
        None
    };

    let prom_metrics = if let Some(ref addr) = cli.metrics_addr {
        let metrics = Arc::new(telemetry::init_prometheus());
        let addr: std::net::SocketAddr = addr.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("agtap: prometheus metrics at http://{}/metrics", addr);
        tokio::spawn(telemetry::serve_prometheus(listener, metrics.clone()));
        Some(metrics)
    } else {
        None
    };

    let runtime_dir = agtap::default_runtime_dir();
    let archive_queue = cli
        .archive_s3_bucket
        .as_ref()
        .map(|_| {
            ArchiveQueue::open(&runtime_dir)
                .map(Arc::new)
                .map_err(|err| anyhow::anyhow!("open archive queue: {err}"))
        })
        .transpose()?;

    let archive_handle = if let (Some(bucket), Some(queue)) =
        (cli.archive_s3_bucket.clone(), archive_queue.clone())
    {
        let config = ArchiveConfig {
            endpoint: cli.archive_s3_endpoint.clone(),
            bucket,
            region: cli.archive_s3_region.clone(),
            retry_delay_secs: cli.archive_retry_delay_secs,
            compression: cli.archive_compression,
        };
        match archive::start(queue.clone(), config).await {
            Ok(handle) => {
                eprintln!("agtap: asynchronous S3 archive enabled");
                Some(handle)
            }
            Err(err) => {
                eprintln!("agtap: S3 archive disabled: {err}");
                None
            }
        }
    } else {
        None
    };

    let log_path = event_log::default_log_path();
    let max_log_bytes = cli.max_log_size * 1024 * 1024;
    let mut log_writer = event_log::LogWriter::open(&log_path, max_log_bytes, cli.max_log_files)?;
    if let Some(queue) = archive_queue.clone() {
        log_writer.set_archive_queue(
            queue,
            cli.archive_s3_prefix.clone(),
            cli.archive_compression,
        )?;
    }
    eprintln!("agtap: logging to {}", log_path.display());

    let sock_path = socket::default_sock_path();
    const BACKLOG_CAPACITY: usize = 1000;
    let seed = event_log::read_last_lines(&log_path, BACKLOG_CAPACITY);
    let socket_tx = socket::SocketServer::start(&sock_path, BACKLOG_CAPACITY, seed)?;
    eprintln!("agtap: socket at {}", sock_path.display());

    let mut reassembler = reassembly::Reassembler::new();
    let mut stdio_reassembler = StdioReassembler::new();
    let mut last_cleanup = Instant::now();
    let mut process_name_cache: HashMap<u32, String> = HashMap::new();

    let bodies_dir = runtime_dir.join("bodies");
    let mut body_store = BodyStore::open(&bodies_dir, cli.max_body_store, cli.body_retention)?;
    eprintln!("agtap: body store at {}", bodies_dir.display());

    // Track known paths for periodic re-scanning.
    let mut known_ssl_targets: HashSet<PathBuf> = HashSet::new();
    let mut known_libc_targets: HashSet<PathBuf> = HashSet::new();

    // Seed with primary paths
    let libssl_canon = libssl_path
        .canonicalize()
        .unwrap_or_else(|_| libssl_path.clone());
    known_ssl_targets.insert(libssl_canon);
    if let Ok(ref libc_path) = libc_result_path {
        let libc_canon = libc_path
            .canonicalize()
            .unwrap_or_else(|_| libc_path.clone());
        known_libc_targets.insert(libc_canon);
    }

    if target_pid.is_none() {
        bpf::discover_and_attach(
            &mut ebpf,
            &mut known_ssl_targets,
            &mut known_libc_targets,
            libc_result_path.is_ok(),
        );

        // One-shot ldconfig scan — cache rarely changes, no need to re-run on periodic rescans.
        bpf::discover_and_track(
            &mut ebpf,
            &mut known_ssl_targets,
            tls::find_ldconfig_libssl_paths,
            bpf::SSL_PROBES,
            "SSL",
        );
        if libc_result_path.is_ok() {
            bpf::discover_and_track(
                &mut ebpf,
                &mut known_libc_targets,
                tls::find_ldconfig_libc_paths,
                bpf::LIBC_PROBES,
                "libc",
            );
        }
    }

    let mut ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    // Poll directly instead of relying solely on ring-buffer readiness notifications:
    // adaptive wakeups can otherwise leave a quiet completed SSE exchange pending.
    let mut ring_poll = tokio::time::interval(Duration::from_millis(50));
    ring_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_rescan = Instant::now();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                eprintln!("\nagtap: shutting down");
                break;
            }
            _ = ring_poll.tick() => {
                drain_ring_events(
                    &mut ring_buf,
                    &mut reassembler,
                    &mut stdio_reassembler,
                    boot_time_ns,
                    &comm_filter,
                    target_pid,
                    cli.verbose,
                    &mut EventSinks {
                        log_writer: &mut log_writer,
                        socket_tx: &socket_tx,
                        otel_handle: otel_handle.as_ref(),
                        prom_metrics: prom_metrics.as_ref(),
                    },
                    &mut body_store,
                    &mut process_name_cache,
                ).await;
            }
        }

        if last_cleanup.elapsed().as_secs() > CLEANUP_CHECK_INTERVAL_SECS {
            let partials = reassembler.cleanup_idle(IDLE_TIMEOUT_SECS, STREAMING_IDLE_TIMEOUT_SECS);
            let protected_body_paths = archive_queue
                .as_ref()
                .map(|queue| queue.protected_body_paths(None))
                .unwrap_or_default();
            body_store.cleanup_if_needed(&protected_body_paths);
            stdio_reassembler.cleanup_idle(IDLE_TIMEOUT_SECS);
            process_name_cache.retain(|pid, _| fs::metadata(format!("/proc/{}", pid)).is_ok());
            last_cleanup = Instant::now();

            let mut sinks = EventSinks {
                log_writer: &mut log_writer,
                socket_tx: &socket_tx,
                otel_handle: otel_handle.as_ref(),
                prom_metrics: prom_metrics.as_ref(),
            };
            for (pid, comm, api_kind, exchange) in partials {
                let parsed = parse_exchange(api_kind, exchange);
                if let Some((call, detail)) = parsed {
                    let body_path = body_store
                        .write(pid, 0, &call.id, &detail)
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned());
                    let proc_name =
                        resolve_proc_name(&mut process_name_cache, pid, &comm, &call, &detail);
                    let agent_event =
                        output::format_event(&call, pid, &proc_name, boot_time_ns, body_path);
                    sinks.emit(&agent_event).await;
                }
            }
        }

        // Periodic re-scan for new SSL/libc targets (every 60s, system-wide mode only).
        if target_pid.is_none() && last_rescan.elapsed().as_secs() >= RESCAN_INTERVAL_SECS {
            bpf::discover_and_attach(
                &mut ebpf,
                &mut known_ssl_targets,
                &mut known_libc_targets,
                libc_result_path.is_ok(),
            );
            last_rescan = Instant::now();
        }
    }

    if cli.verbose {
        eprintln!(
            "agtap: pipe stats — received={} matched={} dropped={} deferred={}",
            stdio_reassembler.pipe_events_received,
            stdio_reassembler.pipe_events_matched,
            stdio_reassembler.pipe_events_dropped,
            stdio_reassembler.pipe_events_deferred,
        );
    }

    if let Some(handle) = otel_handle {
        telemetry::shutdown(handle);
    }

    // Clean up socket file
    let _ = std::fs::remove_file(&sock_path);

    if let Some(handle) = archive_handle {
        handle.shutdown().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{body_retain_bytes, ArchiveCompression, Cli};
    use clap::Parser;

    #[test]
    fn body_retain_limit_accepts_supported_go_capture_maximum() {
        assert_eq!(body_retain_bytes(1024).unwrap(), 1024 * 1024);
    }

    #[test]
    fn body_retain_limit_rejects_unsupported_value_instead_of_clamping() {
        let error = body_retain_bytes(1025).unwrap_err().to_string();
        assert!(error.contains("rejected"));
        assert!(error.contains("1024 KiB"));
    }

    #[test]
    fn archive_compression_defaults_to_zstd_and_rejects_unknown_value() {
        let defaults = Cli::try_parse_from(["agtap"]).unwrap();
        assert_eq!(defaults.archive_compression, ArchiveCompression::Zstd);
        assert!(Cli::try_parse_from(["agtap", "--archive-compression", "brotli"]).is_err());
        assert!(Cli::try_parse_from(["agtap", "--archive-compression", "lz4"]).is_ok());
    }

    #[test]
    fn archive_docs_use_zstd_and_disclaim_lz4_duckdb_support() {
        let docs = include_str!("../../docs/s3-archive.md");
        assert!(docs.contains("--archive-compression zstd"));
        assert!(docs.contains(".jsonl.zst"));
        assert!(docs.contains("不承诺"));
    }
}
