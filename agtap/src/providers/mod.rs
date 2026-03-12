pub mod anthropic;
pub mod gemini;
pub mod mcp;
pub mod openai_completions;
pub mod openai_responses;

use flate2::read::{DeflateDecoder, GzDecoder};
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::reassembly::HttpExchange;

/// Maximum body size to retain (512 KB). Larger bodies are truncated.
pub const MAX_BODY_RETAIN_SIZE: usize = 512 * 1024;

/// Full HTTP request + response detail for the detail view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDetail {
    pub request_method: String,
    pub request_path: String,
    pub request_host: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: String,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
}

/// Build an HttpDetail from a completed exchange and the already-decoded response body.
pub(crate) fn build_http_detail(
    exchange: &HttpExchange,
    decoded_response_body: &[u8],
) -> HttpDetail {
    let request_body_str = String::from_utf8_lossy(&exchange.request.body);
    let request_body = if request_body_str.len() > MAX_BODY_RETAIN_SIZE {
        let end = request_body_str.floor_char_boundary(MAX_BODY_RETAIN_SIZE);
        format!("{}[truncated]", &request_body_str[..end])
    } else {
        request_body_str.into_owned()
    };

    let response_body_str = String::from_utf8_lossy(decoded_response_body);
    let response_body = if response_body_str.len() > MAX_BODY_RETAIN_SIZE {
        let end = response_body_str.floor_char_boundary(MAX_BODY_RETAIN_SIZE);
        format!("{}[truncated]", &response_body_str[..end])
    } else {
        response_body_str.into_owned()
    };

    HttpDetail {
        request_method: exchange.request.method.clone(),
        request_path: exchange.request.path.clone(),
        request_host: exchange.request.host.clone(),
        request_headers: exchange.request.headers.clone(),
        request_body,
        response_status: exchange.response.status,
        response_headers: exchange.response.headers.clone(),
        response_body,
    }
}

/// Provider-agnostic parsed LLM API call.
#[derive(Debug)]
pub struct LlmCall {
    pub id: String,
    pub provider: &'static str,
    pub model: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
    pub stop_reason: String,
    pub tools: Vec<String>,
    pub streaming: bool,
    pub request_timestamp_ns: u64,
    pub first_response_byte_ns: Option<u64>,
    pub response_complete_ns: u64,
    pub host: String,
    pub request_bytes: u32,
    pub response_bytes: u32,
}

impl LlmCall {
    /// Construct an LlmCall from an HttpExchange, filling in the 7 exchange-derived
    /// fields automatically (streaming, timestamps, host, byte counts).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_exchange(
        exchange: &HttpExchange,
        id: String,
        provider: &'static str,
        model: String,
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        cache_creation_input_tokens: Option<u32>,
        cache_read_input_tokens: Option<u32>,
        stop_reason: String,
        tools: Vec<String>,
    ) -> Self {
        Self {
            id,
            provider,
            model,
            input_tokens,
            output_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
            stop_reason,
            tools,
            streaming: exchange.response.is_streaming,
            request_timestamp_ns: exchange.request.timestamp_ns,
            first_response_byte_ns: exchange.response.first_byte_ns,
            response_complete_ns: exchange.response.timestamp_ns,
            host: exchange.request.host.clone(),
            request_bytes: exchange.request.body.len() as u32,
            response_bytes: exchange.response.body.len() as u32,
        }
    }

    /// Convenience constructor for error responses: no tokens, empty tools, synthetic ID.
    pub(crate) fn error_from_exchange(
        exchange: &HttpExchange,
        provider: &'static str,
        model: String,
        stop_reason: String,
    ) -> Self {
        let id = format!("err-{}", exchange.request.timestamp_ns);
        Self::from_exchange(
            exchange,
            id,
            provider,
            model,
            None,
            None,
            None,
            None,
            stop_reason,
            vec![],
        )
    }
}

/// Check MCP request body for markers indicating the calling agent.
/// Checks two locations:
/// 1. `params._meta` keys (e.g. `claudecode/toolUseId`) — present in `tools/call`
/// 2. `params.clientInfo.name` (e.g. `"claude-code"`) — present in `initialize`
///
/// Returns a human-readable process name override if detected.
pub fn detect_meta_process(request_body: &str) -> Option<&'static str> {
    let json: serde_json::Value = serde_json::from_str(request_body).ok()?;
    let params = json.get("params")?;
    if let Some(meta) = params.get("_meta").and_then(|m| m.as_object()) {
        if meta.keys().any(|k| k.starts_with("claudecode/")) {
            return Some("claude code");
        }
    }
    if let Some(name) = params
        .get("clientInfo")
        .and_then(|c| c.get("name"))
        .and_then(|n| n.as_str())
    {
        if name == "claude-code" {
            return Some("claude code");
        }
    }
    None
}

/// For `tools/call` requests, use the tool name as the model instead of the method.
pub(crate) fn mcp_model_name(method: String, tools: &[String]) -> String {
    if method == "tools/call" && !tools.is_empty() {
        tools[0].clone()
    } else {
        method
    }
}

/// Parse SSE `event:`/`data:` line pairs from a streaming body.
/// Returns `(event_type, data)` pairs. Handles both `"data: "` and `"data:"` variants.
/// Note: requires `event:` type lines — not suitable for OpenAI Completions SSE (data-only).
pub(crate) fn iter_sse_events(body: &str) -> Vec<(String, String)> {
    let mut events = Vec::new();
    let mut current_event = String::new();
    let mut current_data = String::new();

    for line in body.lines() {
        if let Some(ev) = line.strip_prefix("event: ") {
            current_event = ev.trim().to_string();
            current_data.clear();
        } else if let Some(d) = line.strip_prefix("data: ") {
            current_data.push_str(d);
        } else if let Some(d) = line.strip_prefix("data:") {
            current_data.push_str(d);
        } else if line.is_empty() && !current_event.is_empty() {
            events.push((
                std::mem::take(&mut current_event),
                std::mem::take(&mut current_data),
            ));
        }
    }
    // Handle last event if no trailing blank line
    if !current_event.is_empty() {
        events.push((current_event, current_data));
    }

    events
}

/// Extract model name from a JSON request body. Shared by all LLM providers.
pub(crate) fn parse_request_model(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(json.get("model")?.as_str()?.to_string())
}

/// Try to parse an OpenAI-format error response.
/// Used by both `openai_completions` and `openai_responses` parsers.
pub(crate) fn try_parse_openai_error(
    exchange: &HttpExchange,
    req_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let json: serde_json::Value = serde_json::from_slice(decoded_body).ok()?;

    let error = json.get("error")?;
    let error_type = error
        .get("type")
        .and_then(|v| v.as_str())
        .or_else(|| error.get("code").and_then(|v| v.as_str()))
        .unwrap_or("unknown");

    let stop_reason = format!("error:{}", error_type);

    let detail = build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::error_from_exchange(exchange, "openai", req_model.to_string(), stop_reason),
        detail,
    ))
}

/// Full body decode pipeline: unchunk → decompress.
pub(crate) fn decode_body(body: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let unchunked = decode_chunked_if_needed(body, headers);
    decompress_if_needed(&unchunked, headers)
}

/// Decode chunked transfer encoding if present.
pub(crate) fn decode_chunked_if_needed(body: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let is_chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));

    if !is_chunked {
        return body.to_vec();
    }

    decode_chunked(body)
}

pub(crate) fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Find chunk size line
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => pos + p,
            None => break,
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        // chunk-size may have extensions after ';'
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = match usize::from_str_radix(size_hex, 16) {
            Ok(s) => s,
            Err(_) => break,
        };

        if chunk_size == 0 {
            break;
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start + chunk_size;
        if chunk_end > data.len() {
            // Incomplete chunk, take what we have
            result.extend_from_slice(&data[chunk_start..]);
            break;
        }

        result.extend_from_slice(&data[chunk_start..chunk_end]);
        pos = chunk_end + 2; // skip trailing \r\n
    }

    result
}

/// Decompress body based on content-encoding header.
fn decompress_if_needed(body: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let encoding = headers
        .iter()
        .find(|(k, _)| k == "content-encoding")
        .map(|(_, v)| v.as_str());

    match encoding {
        Some(e) if e.contains("gzip") => {
            let mut decoder = GzDecoder::new(body);
            let mut decoded = Vec::new();
            match decoder.read_to_end(&mut decoded) {
                Ok(_) => decoded,
                Err(_) if !decoded.is_empty() => decoded,
                Err(_) => body.to_vec(),
            }
        }
        Some(e) if e.contains("deflate") => {
            let mut decoder = DeflateDecoder::new(body);
            let mut decoded = Vec::new();
            match decoder.read_to_end(&mut decoded) {
                Ok(_) => decoded,
                Err(_) if !decoded.is_empty() => decoded,
                Err(_) => body.to_vec(),
            }
        }
        _ => body.to_vec(),
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::reassembly::{HttpExchange, HttpRequest, HttpResponse};

    pub fn make_exchange(host: &str, path: &str, req: &[u8], resp: &[u8]) -> HttpExchange {
        HttpExchange {
            request: HttpRequest {
                method: "POST".into(),
                path: path.into(),
                host: host.into(),
                headers: vec![],
                body: req.to_vec(),
                timestamp_ns: 1000,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![],
                body: resp.to_vec(),
                is_streaming: false,
                timestamp_ns: 2000,
                first_byte_ns: Some(1500),
            },
        }
    }

    pub fn make_streaming_exchange(host: &str, path: &str, req: &[u8], sse: &[u8]) -> HttpExchange {
        HttpExchange {
            request: HttpRequest {
                method: "POST".into(),
                path: path.into(),
                host: host.into(),
                headers: vec![],
                body: req.to_vec(),
                timestamp_ns: 1000,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
                body: sse.to_vec(),
                is_streaming: true,
                timestamp_ns: 2000,
                first_byte_ns: Some(1500),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_gzip_decompression() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original =
            b"Hello, this is a test of partial gzip decompression with enough data to verify.";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        // Truncate the gzip data to simulate a partial stream
        let truncated = &gzip_bytes[..gzip_bytes.len() - 8];
        let headers = vec![("content-encoding".into(), "gzip".into())];

        let result = decompress_if_needed(truncated, &headers);
        // Should return partial decompression, not the raw gzip bytes
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.starts_with("Hello"),
            "partial gzip should decompress to readable text, got: {:?}",
            &result[..result.len().min(20)]
        );
    }

    #[test]
    fn test_full_gzip_decompression() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"Complete gzip data";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        let headers = vec![("content-encoding".into(), "gzip".into())];
        let result = decompress_if_needed(&gzip_bytes, &headers);
        assert_eq!(result, original);
    }

    #[test]
    fn test_detect_meta_process_claude_code() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","_meta":{"claudecode/toolUseId":"abc123"}}}"#;
        assert_eq!(detect_meta_process(body), Some("claude code"));
    }

    #[test]
    fn test_detect_meta_process_none() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#;
        assert_eq!(detect_meta_process(body), None);
    }

    #[test]
    fn test_detect_meta_process_no_params() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert_eq!(detect_meta_process(body), None);
    }

    #[test]
    fn test_detect_meta_process_initialize() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}"#;
        assert_eq!(detect_meta_process(body), Some("claude code"));
    }

    #[test]
    fn test_detect_meta_process_other_client() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"other-client","version":"1.0.0"}}}"#;
        assert_eq!(detect_meta_process(body), None);
    }
}
