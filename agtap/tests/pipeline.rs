//! Scenario-driven pipeline tests.
//!
//! Each TOML file in `scenarios/` defines an HTTP exchange that gets fed through
//! the reassembler → parser → output pipeline. One `#[test]` per TOML file.

use std::io::Write;
use std::path::Path;

use agtap_mock::scenario::Scenario;
use flate2::write::GzEncoder;
use flate2::Compression;

use agtap::output;
use agtap::providers::{anthropic, gemini, mcp, openai_completions, openai_responses};
use agtap::reassembly::Reassembler;

// ── HTTP byte builders ───────────────────────────────────────────────────────

fn build_http_request(scenario: &Scenario) -> Vec<u8> {
    let body = scenario.request.body.raw.trim();
    let method = scenario.request.method.as_deref().unwrap_or("POST");

    // Default path and host based on protocol
    let (default_path, default_host) = match scenario.meta.protocol.as_str() {
        "openai_completions" => ("/v1/chat/completions", "api.openai.com"),
        "openai_responses" => ("/v1/responses", "api.openai.com"),
        "mcp" => ("/mcp", "localhost:3000"),
        "gemini" => (
            "/v1beta/models/gemini-2.5-flash:generateContent",
            "generativelanguage.googleapis.com",
        ),
        _ => ("/v1/messages", "api.anthropic.com"),
    };
    let path = scenario.request.path.as_deref().unwrap_or(default_path);
    let host = scenario.request.host.as_deref().unwrap_or(default_host);

    let mut buf = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host,);
    if let Some(headers) = &scenario.request.headers {
        for (k, v) in headers {
            buf.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    // Always add content-length for POST
    if !body.is_empty() {
        buf.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    buf.push_str("\r\n");
    buf.push_str(body);
    buf.into_bytes()
}

fn build_http_response(scenario: &Scenario) -> Vec<u8> {
    let body_str = scenario.response.body.raw.trim();
    let status = scenario.response.status;
    let phrase = match status {
        200 => "OK",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let transport = scenario.transport.as_ref();
    let chunked = transport.and_then(|t| t.chunked).unwrap_or(false);
    let gzip = transport.and_then(|t| t.gzip).unwrap_or(false);
    let override_cl = transport.and_then(|t| t.override_content_length);

    // Optionally gzip-compress the body bytes
    let body_bytes: Vec<u8> = if gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body_str.as_bytes()).unwrap();
        encoder.finish().unwrap()
    } else {
        body_str.as_bytes().to_vec()
    };

    let mut buf = format!("HTTP/1.1 {} {}\r\n", status, phrase);

    if let Some(headers) = &scenario.response.headers {
        for (k, v) in headers {
            // Skip transfer-encoding if we're handling chunked ourselves
            if k == "transfer-encoding" && chunked {
                continue;
            }
            buf.push_str(&format!("{}: {}\r\n", k, v));
        }
    }

    if gzip {
        buf.push_str("content-encoding: gzip\r\n");
    }

    // Check if this is a streaming (SSE) response
    let is_sse = scenario.response.headers.as_ref().map_or(false, |h| {
        h.iter()
            .any(|(k, v)| k == "content-type" && v.contains("text/event-stream"))
    });

    let mut result = Vec::new();

    if chunked {
        buf.push_str("Transfer-Encoding: chunked\r\n");
        buf.push_str("\r\n");
        result.extend_from_slice(buf.as_bytes());
        // Encode body as a single chunk + terminator
        result.extend_from_slice(format!("{:x}\r\n", body_bytes.len()).as_bytes());
        result.extend_from_slice(&body_bytes);
        result.extend_from_slice(b"\r\n0\r\n\r\n");
    } else if is_sse {
        // SSE streams: no Content-Length, no chunked encoding.
        // The reassembler detects completion via protocol-specific markers.
        buf.push_str("\r\n");
        result.extend_from_slice(buf.as_bytes());
        result.extend_from_slice(&body_bytes);
    } else {
        let cl = override_cl.unwrap_or(body_bytes.len());
        buf.push_str(&format!("Content-Length: {}\r\n", cl));
        buf.push_str("\r\n");
        result.extend_from_slice(buf.as_bytes());
        result.extend_from_slice(&body_bytes);
    }

    result
}

// ── Fragment splitter ────────────────────────────────────────────────────────

fn split_into_fragments(data: &[u8], n: usize, split_points: Option<&[usize]>) -> Vec<Vec<u8>> {
    if n <= 1 {
        return vec![data.to_vec()];
    }

    if let Some(points) = split_points {
        let mut frags = Vec::new();
        let mut prev = 0;
        for &point in points {
            let point = point.min(data.len());
            if point > prev {
                frags.push(data[prev..point].to_vec());
                prev = point;
            }
        }
        if prev < data.len() {
            frags.push(data[prev..].to_vec());
        }
        frags
    } else {
        // Split evenly
        let chunk_size = (data.len() + n - 1) / n;
        data.chunks(chunk_size.max(1)).map(|c| c.to_vec()).collect()
    }
}

// ── Timestamp interpolation ──────────────────────────────────────────────────

fn interpolate_timestamps(first_ns: u64, complete_ns: u64, count: usize) -> Vec<u64> {
    if count <= 1 {
        return vec![first_ns];
    }
    let step = if complete_ns > first_ns {
        (complete_ns - first_ns) / (count as u64 - 1)
    } else {
        0
    };
    (0..count).map(|i| first_ns + step * i as u64).collect()
}

// ── Test runner ──────────────────────────────────────────────────────────────

fn run_scenario(path: &Path) -> datatest_stable::Result<()> {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let scenario: Scenario = toml::from_str(&contents)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

    let timing = scenario.timing.as_ref().expect(&format!(
        "Scenario '{}' missing [timing] section",
        scenario.meta.name
    ));

    let pid: u32 = 1000;
    let ssl_ptr: u64 = 0xdead_cafe;

    let transport = scenario.transport.as_ref();
    let req_frags = transport.and_then(|t| t.request_fragments).unwrap_or(1);
    let resp_frags = transport.and_then(|t| t.response_fragments).unwrap_or(1);
    let resp_split_points = transport.and_then(|t| t.response_split_points.as_deref());
    let override_cl = transport.and_then(|t| t.override_content_length);

    let req_bytes = build_http_request(&scenario);
    let resp_bytes = build_http_response(&scenario);

    let req_fragments = split_into_fragments(&req_bytes, req_frags, None);
    let resp_fragments = split_into_fragments(&resp_bytes, resp_frags, resp_split_points);

    let req_timestamps = interpolate_timestamps(
        timing.request_start_ns,
        timing.request_start_ns, // request is instant in our model
        req_fragments.len(),
    );
    let resp_timestamps = interpolate_timestamps(
        timing.response_first_byte_ns,
        timing.response_complete_ns,
        resp_fragments.len(),
    );

    let mut reassembler = Reassembler::new();

    // Feed request fragments
    for (frag, ts) in req_fragments.iter().zip(req_timestamps.iter()) {
        let result = reassembler.process_event(pid, ssl_ptr, 0, frag, *ts, "");
        assert!(result.is_none(), "Request should not produce an exchange");
    }

    // Feed response fragments
    let mut exchange = None;
    for (frag, ts) in resp_fragments.iter().zip(resp_timestamps.iter()) {
        if let Some((_api_kind, ex)) = reassembler.process_event(pid, ssl_ptr, 1, frag, *ts, "") {
            exchange = Some(ex);
            break;
        }
    }

    // If there's an override_content_length that's larger than actual body,
    // the response will never complete — exchange should be None
    if override_cl.is_some() && override_cl.unwrap() > scenario.response.body.raw.trim().len() {
        assert!(
            exchange.is_none(),
            "Scenario '{}': expected no exchange due to content-length mismatch",
            scenario.meta.name,
        );
        assert!(
            scenario.expected.is_none(),
            "Scenario '{}': has override_content_length but also has [expected]",
            scenario.meta.name,
        );
        return Ok(());
    }

    match &scenario.expected {
        Some(expected) => {
            let exchange = exchange.unwrap_or_else(|| {
                panic!(
                    "Scenario '{}': expected an exchange but reassembler returned None",
                    scenario.meta.name,
                )
            });

            // Dispatch to the correct parser based on protocol
            let parsed = match scenario.meta.protocol.as_str() {
                "anthropic" => anthropic::parse_exchange(exchange),
                "gemini" => gemini::parse_exchange(exchange),
                "openai_completions" => openai_completions::parse_exchange(exchange),
                "openai_responses" => openai_responses::parse_exchange(exchange),
                "mcp" => mcp::parse_exchange(exchange),
                other => panic!("Unknown protocol: {}", other),
            };

            let (call, _detail) = parsed.unwrap_or_else(|| {
                panic!(
                    "Scenario '{}': parse_exchange returned None",
                    scenario.meta.name,
                )
            });

            // Format as output event
            let event = output::format_event(&call, pid, "test", 0, None);

            // Validate expected fields
            if let Some(ref id) = expected.id {
                assert_eq!(
                    &call.id, id,
                    "Scenario '{}': id mismatch",
                    scenario.meta.name
                );
            }
            if let Some(ref model) = expected.model {
                assert_eq!(
                    &call.model, model,
                    "Scenario '{}': model mismatch",
                    scenario.meta.name
                );
            }
            if let Some(input_tokens) = expected.input_tokens {
                assert_eq!(
                    call.input_tokens,
                    Some(input_tokens),
                    "Scenario '{}': input_tokens",
                    scenario.meta.name,
                );
            }
            if let Some(output_tokens) = expected.output_tokens {
                assert_eq!(
                    call.output_tokens,
                    Some(output_tokens),
                    "Scenario '{}': output_tokens",
                    scenario.meta.name,
                );
            }
            if let Some(ref stop_reason) = expected.stop_reason {
                assert_eq!(
                    &call.stop_reason, stop_reason,
                    "Scenario '{}': stop_reason",
                    scenario.meta.name
                );
            }
            if let Some(streaming) = expected.streaming {
                assert_eq!(
                    call.streaming, streaming,
                    "Scenario '{}': streaming",
                    scenario.meta.name
                );
            }
            if let Some(ref kind) = expected.kind {
                assert_eq!(
                    event.kind.as_str(),
                    kind.as_str(),
                    "Scenario '{}': kind",
                    scenario.meta.name
                );
            }
            if let Some(ref tools) = expected.tools {
                assert_eq!(
                    &event.tools, tools,
                    "Scenario '{}': tools",
                    scenario.meta.name
                );
            }
            if let Some(latency_ms) = expected.latency_ms {
                assert_eq!(
                    event.latency_ms, latency_ms,
                    "Scenario '{}': latency_ms",
                    scenario.meta.name
                );
            }
            if let Some(ttft_ms) = expected.ttft_ms {
                assert_eq!(
                    event.ttft_ms,
                    Some(ttft_ms),
                    "Scenario '{}': ttft_ms",
                    scenario.meta.name,
                );
            }
            if let Some(cache_creation) = expected.cache_creation_input_tokens {
                assert_eq!(
                    call.cache_creation_input_tokens,
                    Some(cache_creation),
                    "Scenario '{}': cache_creation_input_tokens",
                    scenario.meta.name,
                );
            }
            if let Some(cache_read) = expected.cache_read_input_tokens {
                assert_eq!(
                    call.cache_read_input_tokens,
                    Some(cache_read),
                    "Scenario '{}': cache_read_input_tokens",
                    scenario.meta.name,
                );
            }
        }
        None => {
            // Error scenarios: either reassembler doesn't produce an exchange,
            // or parse_exchange returns None
            if let Some(exchange) = exchange {
                let parsed = match scenario.meta.protocol.as_str() {
                    "anthropic" => anthropic::parse_exchange(exchange),
                    "gemini" => gemini::parse_exchange(exchange),
                    "openai_completions" => openai_completions::parse_exchange(exchange),
                    "openai_responses" => openai_responses::parse_exchange(exchange),
                    "mcp" => mcp::parse_exchange(exchange),
                    other => panic!("Unknown protocol: {}", other),
                };
                assert!(
                    parsed.is_none(),
                    "Scenario '{}': expected parse_exchange to return None for error scenario",
                    scenario.meta.name,
                );
            }
            // If exchange is None, that's also valid for error scenarios
        }
    }

    Ok(())
}

// ── datatest-stable harness ──────────────────────────────────────────────────

datatest_stable::harness!(run_scenario, "../scenarios", r"\.toml$");
