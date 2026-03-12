use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

// ── Shared TOML scenario types ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct Scenario {
    pub meta: Meta,
    pub request: Request,
    pub response: Response,
    pub transport: Option<Transport>,
    pub timing: Option<Timing>,
    pub expected: Option<Expected>,
}

#[derive(Deserialize)]
pub struct Meta {
    pub name: String,
    #[allow(dead_code)]
    pub protocol: String,
    /// Set to false to skip this scenario in --live mode (default: true)
    pub live: Option<bool>,
}

#[derive(Deserialize)]
pub struct Request {
    pub method: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<BTreeMap<String, String>>,
    pub body: RequestBody,
}

#[derive(Deserialize)]
pub struct RequestBody {
    pub raw: String,
}

#[derive(Deserialize)]
pub struct Response {
    pub status: u16,
    pub headers: Option<BTreeMap<String, String>>,
    pub body: ResponseBody,
}

#[derive(Deserialize)]
pub struct ResponseBody {
    pub raw: String,
}

#[derive(Deserialize)]
pub struct Transport {
    pub request_fragments: Option<usize>,
    pub response_fragments: Option<usize>,
    pub response_split_points: Option<Vec<usize>>,
    pub chunked: Option<bool>,
    pub gzip: Option<bool>,
    pub override_content_length: Option<usize>,
}

#[derive(Deserialize)]
pub struct Timing {
    pub request_start_ns: u64,
    pub response_first_byte_ns: u64,
    pub response_complete_ns: u64,
    #[allow(dead_code)]
    pub fragment_timestamps_ns: Option<Vec<u64>>,
}

#[derive(Deserialize)]
pub struct Expected {
    pub id: Option<String>,
    pub model: Option<String>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
    pub stop_reason: Option<String>,
    pub streaming: Option<bool>,
    pub kind: Option<String>,
    pub tools: Option<Vec<String>>,
    pub latency_ms: Option<u64>,
    pub ttft_ms: Option<u64>,
}

// ── Scenario loader ─────────────────────────────────────────────────────────

/// Load scenarios from a directory, optionally filtering by name/path substring.
pub fn load_scenarios(dir: &Path, filter: Option<&str>) -> Vec<(String, Scenario)> {
    let mut results = Vec::new();
    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for sub_entry in sub.flatten() {
                        let sub_path = sub_entry.path();
                        if sub_path.extension().map_or(false, |e| e == "toml") {
                            files.push(sub_path);
                        }
                    }
                }
            } else if path.extension().map_or(false, |e| e == "toml") {
                files.push(path);
            }
        }
    }
    files.sort();

    for path in files {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(scenario) = toml::from_str::<Scenario>(&contents) {
                let name = scenario.meta.name.clone();
                if let Some(f) = filter {
                    if !name.contains(f) && !path.to_string_lossy().contains(f) {
                        continue;
                    }
                }
                results.push((name, scenario));
            }
        }
    }

    results
}
