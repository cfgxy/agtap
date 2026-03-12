use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agtap_mock::scenario::{self, Expected, Scenario};
use clap::Parser;
use serde_json::Value;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "agtap-test", about = "Integration test runner for agtap")]
struct Args {
    /// Run against real APIs instead of mock server (requires API keys)
    #[arg(long)]
    live: bool,

    /// Run a single scenario by name (e.g., "anthropic/streaming_simple")
    #[arg(long)]
    scenario: Option<String>,

    /// Path to scenarios directory
    #[arg(long, default_value = "scenarios")]
    scenarios_dir: PathBuf,

    /// Path to agtap binary
    #[arg(long, default_value = "target/release/agtap")]
    agtap_bin: PathBuf,
}

// ── Drop guard for child processes ──────────────────────────────────────────

struct ChildGuard {
    child: Option<Child>,
    name: String,
    sudo: bool,
}

impl ChildGuard {
    fn new(child: Child, name: &str, sudo: bool) -> Self {
        Self {
            child: Some(child),
            name: name.to_string(),
            sudo,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            eprintln!("  Stopping {}...", self.name);
            if self.sudo {
                // For sudo processes, send SIGTERM via sudo kill
                let _ = Command::new("sudo")
                    .args(["kill", &child.id().to_string()])
                    .status();
            } else {
                let _ = child.kill();
            }
            // Wait with timeout
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(30) {
                            eprintln!("  {} didn't exit in 30s, force killing", self.name);
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

// ── Test result ─────────────────────────────────────────────────────────────

struct TestResult {
    name: String,
    passed: bool,
    message: String,
    duration: Duration,
}

// ── Field validation ─────────────────────────────────────────────────────────

/// Validate output JSON against expected fields. Returns a list of (field, error_msg) failures.
fn validate_fields(output: &Value, expected: &Expected, live: bool) -> Vec<(String, String)> {
    let mut failures = Vec::new();

    if live {
        // Live mode: relaxed validation — only structural fields
        if let Some(ref id) = expected.id {
            // In live mode, just check id starts with "msg_"
            let _ = id; // expected id is unknown in live mode
            if let Some(actual_id) = output.get("id").and_then(|v| v.as_str()) {
                if !actual_id.starts_with("msg_") {
                    failures.push((
                        "id".into(),
                        format!("expected to start with 'msg_', got '{}'", actual_id),
                    ));
                }
            }
        }
        if let Some(ref model) = expected.model {
            if let Some(actual) = output.get("model").and_then(|v| v.as_str()) {
                if actual != model {
                    failures.push((
                        "model".into(),
                        format!("expected '{}', got '{}'", model, actual),
                    ));
                }
            } else {
                failures.push(("model".into(), "missing".into()));
            }
        }
        if let Some(streaming) = expected.streaming {
            if let Some(actual) = output.get("streaming").and_then(|v| v.as_bool()) {
                if actual != streaming {
                    failures.push((
                        "streaming".into(),
                        format!("expected {}, got {}", streaming, actual),
                    ));
                }
            } else {
                failures.push(("streaming".into(), "missing".into()));
            }
        }
        if let Some(ref kind) = expected.kind {
            if let Some(actual) = output.get("kind").and_then(|v| v.as_str()) {
                if actual != kind {
                    failures.push((
                        "kind".into(),
                        format!("expected '{}', got '{}'", kind, actual),
                    ));
                }
            } else {
                failures.push(("kind".into(), "missing".into()));
            }
        }
        if let Some(ref stop_reason) = expected.stop_reason {
            if let Some(actual) = output.get("stop_reason").and_then(|v| v.as_str()) {
                if actual != stop_reason {
                    failures.push((
                        "stop_reason".into(),
                        format!("expected '{}', got '{}'", stop_reason, actual),
                    ));
                }
            }
            // Don't fail if stop_reason is missing in live mode — it might vary
        }
    } else {
        // Mock mode: exact validation of all fields
        macro_rules! check_str {
            ($field:expr, $expected_val:expr) => {
                if let Some(ref expected_val) = $expected_val {
                    match output.get($field).and_then(|v| v.as_str()) {
                        Some(actual) if actual == expected_val.as_str() => {}
                        Some(actual) => failures.push((
                            $field.into(),
                            format!("expected '{}', got '{}'", expected_val, actual),
                        )),
                        None => failures.push((
                            $field.into(),
                            format!("missing (expected '{}')", expected_val),
                        )),
                    }
                }
            };
        }

        macro_rules! check_u64 {
            ($field:expr, $expected_val:expr) => {
                if let Some(expected_val) = $expected_val {
                    match output.get($field).and_then(|v| v.as_u64()) {
                        Some(actual) if actual == expected_val as u64 => {}
                        Some(actual) => failures.push((
                            $field.into(),
                            format!("expected {}, got {}", expected_val, actual),
                        )),
                        None => failures.push((
                            $field.into(),
                            format!("missing (expected {})", expected_val),
                        )),
                    }
                }
            };
        }

        check_str!("id", expected.id);
        check_str!("model", expected.model);
        check_str!("stop_reason", expected.stop_reason);
        check_str!("kind", expected.kind);
        check_u64!("input_tokens", expected.input_tokens);
        check_u64!("output_tokens", expected.output_tokens);
        check_u64!("latency_ms", expected.latency_ms);

        if let Some(streaming) = expected.streaming {
            match output.get("streaming").and_then(|v| v.as_bool()) {
                Some(actual) if actual == streaming => {}
                Some(actual) => failures.push((
                    "streaming".into(),
                    format!("expected {}, got {}", streaming, actual),
                )),
                None => failures.push((
                    "streaming".into(),
                    format!("missing (expected {})", streaming),
                )),
            }
        }

        if let Some(ttft_ms) = expected.ttft_ms {
            match output.get("ttft_ms").and_then(|v| v.as_u64()) {
                Some(actual) if actual == ttft_ms => {}
                Some(actual) => failures.push((
                    "ttft_ms".into(),
                    format!("expected {}, got {}", ttft_ms, actual),
                )),
                None => {
                    failures.push(("ttft_ms".into(), format!("missing (expected {})", ttft_ms)))
                }
            }
        }

        if let Some(ref tools) = expected.tools {
            let actual_tools: Vec<String> = output
                .get("tools")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if &actual_tools != tools {
                failures.push((
                    "tools".into(),
                    format!("expected {:?}, got {:?}", tools, actual_tools),
                ));
            }
        }
    }

    failures
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Load scenarios
    let scenarios = scenario::load_scenarios(&args.scenarios_dir, args.scenario.as_deref());
    if scenarios.is_empty() {
        eprintln!(
            "agtap-test: no scenarios found in {}",
            args.scenarios_dir.display()
        );
        std::process::exit(1);
    }

    // In live mode, filter out scenarios with live=false
    let scenarios: Vec<(String, Scenario)> = if args.live {
        scenarios
            .into_iter()
            .filter(|(_, s)| s.meta.live.unwrap_or(true))
            .collect()
    } else {
        scenarios
    };

    let scenarios_with_expected: Vec<_> = scenarios
        .iter()
        .filter(|(_, s)| s.expected.is_some())
        .collect();
    let expected_count = scenarios_with_expected.len();

    eprintln!(
        "agtap-test: loaded {} scenarios ({} with expected output){}",
        scenarios.len(),
        expected_count,
        if args.live { " [LIVE MODE]" } else { "" },
    );

    // Check agtap binary exists
    if !args.agtap_bin.exists() {
        eprintln!(
            "agtap-test: binary not found at {}",
            args.agtap_bin.display()
        );
        eprintln!("  Run: cargo build -p agtap --release");
        std::process::exit(1);
    }

    // In live mode, check for API key
    let api_key = if args.live {
        let key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
        if key.is_empty() {
            eprintln!("agtap-test: ANTHROPIC_API_KEY not set (required for --live mode)");
            std::process::exit(1);
        }
        Some(key)
    } else {
        None
    };

    // Start mock server (skip in live mode)
    let _mock_handle = if args.live {
        None
    } else {
        let config = agtap_mock::MockConfig {
            scenarios_dir: args.scenarios_dir.clone(),
            port: 0, // random port
        };
        let (addr, handle) = agtap_mock::start_server(config).await;
        eprintln!("agtap-test: mock server on https://{}", addr);
        Some((addr, handle))
    };
    let mock_addr = _mock_handle.as_ref().map(|(addr, _)| *addr);

    // Start agtap
    eprintln!("agtap-test: starting agtap...");
    let mut agtap_proc = Command::new("sudo")
        .args([args.agtap_bin.to_string_lossy().as_ref(), "-c", "curl"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agtap (is sudo available?)");

    let agtap_stderr = agtap_proc.stderr.take().unwrap();
    let agtap_stdout = agtap_proc.stdout.take().unwrap();
    let mut agtap_guard = ChildGuard::new(agtap_proc, "agtap", true);

    // Spawn stdout reader thread — collects JSON lines incrementally
    let output_lines: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let output_lines_writer = Arc::clone(&output_lines);
    std::thread::spawn(move || {
        let reader = BufReader::new(agtap_stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Ok(val) = serde_json::from_str::<Value>(&line) {
                    output_lines_writer.lock().unwrap().push(val);
                }
            }
        }
    });

    // Wait for readiness: poll stderr for "listening for" line
    let stderr_reader = BufReader::new(agtap_stderr);
    let ready_timeout = Duration::from_secs(30);
    let ready_start = Instant::now();
    let mut ready = false;

    // Read stderr in a separate thread to avoid blocking
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in stderr_reader.lines() {
            if let Ok(line) = line {
                eprintln!("  [agtap] {}", line);
                let _ = stderr_tx.send(line);
            }
        }
    });

    while ready_start.elapsed() < ready_timeout {
        if let Ok(line) = stderr_rx.recv_timeout(Duration::from_millis(500)) {
            if line.contains("listening for") {
                ready = true;
                break;
            }
        }
    }

    if !ready {
        eprintln!("agtap-test: agtap didn't become ready within 30s");
        std::process::exit(1);
    }
    eprintln!("agtap-test: agtap is ready");

    // Run scenarios
    let mut results = Vec::new();

    for (i, (name, scenario_data)) in scenarios.iter().enumerate() {
        let start = Instant::now();

        // Only run curl for scenarios with expected output
        if scenario_data.expected.is_none() {
            results.push(TestResult {
                name: name.clone(),
                passed: true,
                message: "skipped (error scenario — no curl needed)".into(),
                duration: Duration::ZERO,
            });
            continue;
        }

        eprintln!(
            "  [{}/{}] Running scenario: {}",
            i + 1,
            scenarios.len(),
            name,
        );

        let body = scenario_data.request.body.raw.trim();

        let curl_result = if args.live {
            // Live mode: send to real API
            let api_key = api_key.as_ref().unwrap();
            let url = "https://api.anthropic.com/v1/messages";
            Command::new("curl")
                .args([
                    "--http1.1",
                    "-sk",
                    "--max-time",
                    "30",
                    url,
                    "-H",
                    "content-type: application/json",
                    "-H",
                    "anthropic-version: 2023-06-01",
                    "-H",
                    &format!("x-api-key: {}", api_key),
                    "-d",
                    body,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        } else {
            // Mock mode: send to mock server with ?scenario= param
            let port = mock_addr.unwrap().port();
            let url = format!(
                "https://api.anthropic.com:{}/v1/messages?scenario={}",
                port, name,
            );
            Command::new("curl")
                .args([
                    "--http1.1",
                    "-sk",
                    "--max-time",
                    "30",
                    "--resolve",
                    &format!("api.anthropic.com:{}:127.0.0.1", port),
                    &url,
                    "-H",
                    "content-type: application/json",
                    "-H",
                    "anthropic-version: 2023-06-01",
                    "-d",
                    body,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };

        match curl_result {
            Ok(status) if status.success() => {
                results.push(TestResult {
                    name: name.clone(),
                    passed: true,
                    message: "curl succeeded".into(),
                    duration: start.elapsed(),
                });
            }
            Ok(status) => {
                results.push(TestResult {
                    name: name.clone(),
                    passed: false,
                    message: format!("curl failed with exit code: {:?}", status.code()),
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                results.push(TestResult {
                    name: name.clone(),
                    passed: false,
                    message: format!("curl error: {}", e),
                    duration: start.elapsed(),
                });
            }
        }

        // Brief pause for agtap to process the event
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Sanity check after first scenario: verify agtap is producing output
        if i == 0 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let line_count = output_lines.lock().unwrap().len();
            if line_count == 0 && results.last().map_or(false, |r| r.passed) {
                eprintln!("agtap-test: WARNING — first curl succeeded but no agtap output yet");
                eprintln!("  Possible causes:");
                eprintln!("  - curl binary is not linked against system libssl");
                eprintln!("  - agtap -c curl filter didn't match");
                eprintln!("  - libssl version mismatch");
                // Give it one more second before giving up
                tokio::time::sleep(Duration::from_secs(1)).await;
                let line_count = output_lines.lock().unwrap().len();
                if line_count == 0 {
                    eprintln!("agtap-test: FAIL — still zero output lines after first scenario");
                    std::process::exit(1);
                }
            }
        }
    }

    // Stop agtap gracefully — take child out of guard to avoid double-kill
    eprintln!("agtap-test: stopping agtap...");
    let mut child = agtap_guard.child.take().unwrap();
    let pid_str = child.id().to_string();
    let _ = Command::new("sudo").args(["kill", &pid_str]).status();

    // Wait for exit (up to 5s)
    let kill_start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if kill_start.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    // Give stdout reader a moment to flush
    std::thread::sleep(Duration::from_millis(200));

    let output_lines = output_lines.lock().unwrap();

    eprintln!(
        "agtap-test: captured {} output lines (expected {})",
        output_lines.len(),
        expected_count,
    );

    // Sanity check
    if output_lines.is_empty() && expected_count > 0 {
        eprintln!("agtap-test: FAIL — zero output lines!");
        eprintln!("  Possible causes:");
        eprintln!("  - curl binary is not linked against system libssl");
        eprintln!("  - agtap -c curl filter didn't match");
        eprintln!("  - libssl version mismatch");
        std::process::exit(1);
    }

    // Match output lines to scenarios and validate fields
    let mut validation_fail_count = 0;

    if args.live {
        // Live mode: match by model + streaming + kind combination
        for (name, scenario_data) in &scenarios {
            let expected = match &scenario_data.expected {
                Some(e) => e,
                None => continue,
            };

            let exp_model = expected.model.as_deref().unwrap_or("");
            let exp_streaming = expected.streaming.unwrap_or(false);
            let exp_kind = expected.kind.as_deref().unwrap_or("llm_call");

            let matched_line = output_lines.iter().find(|line| {
                let model_match = line.get("model").and_then(|v| v.as_str()) == Some(exp_model);
                let streaming_match =
                    line.get("streaming").and_then(|v| v.as_bool()) == Some(exp_streaming);
                let kind_match = line.get("kind").and_then(|v| v.as_str()) == Some(exp_kind);
                model_match && streaming_match && kind_match
            });

            match matched_line {
                Some(line) => {
                    let failures = validate_fields(line, expected, true);
                    if failures.is_empty() {
                        eprintln!("  [VALID] {} — all fields match", name);
                    } else {
                        eprintln!(
                            "  [VALID-FAIL] {} — {} field(s) mismatched:",
                            name,
                            failures.len()
                        );
                        for (field, msg) in &failures {
                            eprintln!("    {}: {}", field, msg);
                        }
                        validation_fail_count += 1;
                    }
                }
                None => {
                    eprintln!(
                        "  [VALID-MISS] {} — no matching output (model={}, streaming={}, kind={})",
                        name, exp_model, exp_streaming, exp_kind,
                    );
                    validation_fail_count += 1;
                }
            }
        }
    } else {
        // Mock mode: match by id field
        for (name, scenario_data) in &scenarios {
            let expected = match &scenario_data.expected {
                Some(e) => e,
                None => continue,
            };

            let expected_id = expected.id.as_deref().unwrap_or("");
            let matched_line = output_lines
                .iter()
                .find(|line| line.get("id").and_then(|v| v.as_str()) == Some(expected_id));

            match matched_line {
                Some(line) => {
                    let failures = validate_fields(line, expected, false);
                    if failures.is_empty() {
                        eprintln!("  [VALID] {} — all fields match", name);
                    } else {
                        eprintln!(
                            "  [VALID-FAIL] {} — {} field(s) mismatched:",
                            name,
                            failures.len()
                        );
                        for (field, msg) in &failures {
                            eprintln!("    {}: {}", field, msg);
                        }
                        validation_fail_count += 1;
                    }
                }
                None => {
                    eprintln!(
                        "  [VALID-MISS] {} — no output line with id='{}'",
                        name, expected_id,
                    );
                    validation_fail_count += 1;
                }
            }
        }
    }

    // Print results
    eprintln!("\n=== Results ===");
    let mut pass_count = 0;
    let mut fail_count = 0;

    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        eprintln!(
            "  [{}] {} ({:.1}ms) {}",
            status,
            result.name,
            result.duration.as_secs_f64() * 1000.0,
            if result.passed {
                "".to_string()
            } else {
                format!("— {}", result.message)
            },
        );
        if result.passed {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
    }

    let total_failures = fail_count + validation_fail_count;
    eprintln!(
        "\nagtap-test: {} passed, {} failed (curl: {}, validation: {}), {} output lines captured",
        pass_count,
        total_failures,
        fail_count,
        validation_fail_count,
        output_lines.len(),
    );

    if total_failures > 0 {
        std::process::exit(1);
    }
    if output_lines.len() != expected_count {
        eprintln!(
            "agtap-test: WARNING — expected {} output lines but got {}",
            expected_count,
            output_lines.len(),
        );
    }
}
