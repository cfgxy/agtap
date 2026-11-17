use bytes::BytesMut;
use std::collections::HashMap;
use std::time::Instant;

/// Initial capacity for request buffers.
const INITIAL_REQ_BUF_CAPACITY: usize = 8192;
/// Initial capacity for response buffers.
const INITIAL_RESP_BUF_CAPACITY: usize = 65536;
/// Maximum number of HTTP headers to parse.
const MAX_HTTP_HEADERS: usize = 64;

/// Parsed HTTP request
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timestamp_ns: u64,
}

/// Parsed HTTP response
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub is_streaming: bool,
    pub timestamp_ns: u64,
    pub first_byte_ns: Option<u64>,
}

/// Complete HTTP exchange
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ApiKind {
    Anthropic,
    Gemini,
    OpenAi,
    Mcp,
}

struct ConnState {
    req_buf: BytesMut,
    resp_buf: BytesMut,
    req_start_ns: Option<u64>,
    first_resp_byte_ns: Option<u64>,
    last_resp_byte_ns: Option<u64>,
    last_activity: Instant,
    parsed_request: Option<HttpRequest>,
    api_kind: Option<ApiKind>,
    is_streaming_response: bool,
    resp_content_length: Option<usize>,
    resp_headers_done: bool,
    resp_headers_len: usize,
    resp_chunked: bool,
    resp_status: u16,
    resp_headers: Vec<(String, String)>,
    comm: String,
}

impl ConnState {
    fn new() -> Self {
        Self {
            req_buf: BytesMut::with_capacity(INITIAL_REQ_BUF_CAPACITY),
            resp_buf: BytesMut::with_capacity(INITIAL_RESP_BUF_CAPACITY),
            req_start_ns: None,
            first_resp_byte_ns: None,
            last_resp_byte_ns: None,
            last_activity: Instant::now(),
            parsed_request: None,
            api_kind: None,
            is_streaming_response: false,
            resp_content_length: None,
            resp_headers_done: false,
            resp_headers_len: 0,
            resp_chunked: false,
            resp_status: 0,
            resp_headers: Vec::new(),
            comm: String::new(),
        }
    }
}

#[derive(Default)]
pub struct Reassembler {
    streams: HashMap<(u32, u64), ConnState>,
}

/// Reduce capture direction values to the request/response bit consumed by the reassembler.
/// TCP events carry `TCP_FLAG` in the upper bits; SSL events already use the same low bit.
pub fn actual_direction(direction: u32) -> u32 {
    direction & 1
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalize and process a captured TCP or SSL event.
    pub fn process_event(
        &mut self,
        pid: u32,
        ssl_ptr: u64,
        direction: u32,
        data: &[u8],
        timestamp_ns: u64,
        comm: &str,
    ) -> Option<(ApiKind, HttpExchange)> {
        self.process_normalized_event(
            pid,
            ssl_ptr,
            actual_direction(direction),
            data,
            timestamp_ns,
            comm,
        )
    }

    /// Process a normalized event. Returns a completed exchange with its API kind if one is ready.
    fn process_normalized_event(
        &mut self,
        pid: u32,
        ssl_ptr: u64,
        direction: u32,
        data: &[u8],
        timestamp_ns: u64,
        comm: &str,
    ) -> Option<(ApiKind, HttpExchange)> {
        let key = (pid, ssl_ptr);
        let conn = self.streams.entry(key).or_insert_with(ConnState::new);
        conn.last_activity = Instant::now();
        if conn.comm.is_empty() {
            conn.comm = comm.to_string();
        }

        if direction == 0 {
            // Write (request)
            if conn.req_start_ns.is_none() {
                conn.req_start_ns = Some(timestamp_ns);
            }
            conn.req_buf.extend_from_slice(data);
            self.try_parse_request(key);
            let conn = self.streams.get(&key).unwrap();
            log::debug!(
                "  req parse: parsed={} api_kind={}",
                conn.parsed_request.is_some(),
                conn.api_kind.is_some(),
            );
            None
        } else {
            // Read (response)
            if conn.first_resp_byte_ns.is_none() {
                conn.first_resp_byte_ns = Some(timestamp_ns);
            }
            conn.last_resp_byte_ns = Some(timestamp_ns);
            conn.resp_buf.extend_from_slice(data);

            if !conn.resp_headers_done {
                self.try_parse_response_headers(key);
            }

            let conn = self.streams.get(&key).unwrap();
            log::debug!(
                "  resp: headers_done={} api_kind={} content_length={:?} chunked={} streaming={} body_bytes={}",
                conn.resp_headers_done,
                conn.api_kind.is_some(),
                conn.resp_content_length,
                conn.resp_chunked,
                conn.is_streaming_response,
                if conn.resp_headers_done { conn.resp_buf.len() - conn.resp_headers_len } else { 0 },
            );

            if self.is_response_complete(key) {
                self.extract_exchange(key)
            } else {
                None
            }
        }
    }

    fn try_parse_request(&mut self, key: (u32, u64)) {
        let conn = self.streams.get_mut(&key).unwrap();
        if conn.parsed_request.is_some() {
            return;
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&conn.req_buf) {
            Ok(httparse::Status::Complete(body_offset)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let mut host = String::new();
                let mut parsed_headers = Vec::new();
                let mut content_length: Option<usize> = None;

                for h in req.headers.iter() {
                    let name = h.name.to_lowercase();
                    let val = String::from_utf8_lossy(h.value).to_string();
                    if name == "host" {
                        host = val.clone();
                    }
                    if name == "content-length" {
                        content_length = val.parse().ok();
                    }
                    parsed_headers.push((name, val));
                }

                // Check if body is complete
                let body_len = conn.req_buf.len() - body_offset;
                let expected = content_length.unwrap_or(0);
                if body_len < expected {
                    return; // Wait for more data
                }

                let body = conn.req_buf[body_offset..body_offset + expected].to_vec();

                let api_kind = if Self::looks_like_mcp_request(&parsed_headers, &body) {
                    Some(ApiKind::Mcp)
                } else if path.ends_with("/v1/messages") {
                    Some(ApiKind::Anthropic)
                } else if path.contains(":generateContent")
                    || path.contains(":streamGenerateContent")
                {
                    Some(ApiKind::Gemini)
                } else if path.ends_with("/v1/chat/completions") || path.ends_with("/v1/responses")
                {
                    Some(ApiKind::OpenAi)
                } else {
                    None
                };

                conn.api_kind = api_kind;
                conn.parsed_request = Some(HttpRequest {
                    method,
                    path,
                    host,
                    headers: parsed_headers,
                    body,
                    timestamp_ns: conn.req_start_ns.unwrap_or(0),
                });
            }
            Ok(httparse::Status::Partial) => {} // Need more data
            Err(_) => {
                // Not HTTP, clear buffer
                conn.req_buf.clear();
            }
        }
    }

    fn try_parse_response_headers(&mut self, key: (u32, u64)) {
        let conn = self.streams.get_mut(&key).unwrap();
        if conn.resp_headers_done {
            return;
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&conn.resp_buf) {
            Ok(httparse::Status::Complete(body_offset)) => {
                conn.resp_headers_done = true;
                conn.resp_headers_len = body_offset;
                conn.resp_status = resp.code.unwrap_or(0);

                for h in resp.headers.iter() {
                    let name = h.name.to_lowercase();
                    let val = String::from_utf8_lossy(h.value).to_string();

                    if name == "content-length" {
                        conn.resp_content_length = val.parse().ok();
                    }
                    if name == "transfer-encoding" && val.contains("chunked") {
                        conn.resp_chunked = true;
                    }
                    if name == "content-type" && val.contains("text/event-stream") {
                        conn.is_streaming_response = true;
                    }
                    conn.resp_headers.push((name, val));
                }

                // When API kind is unknown (custom path or missed request), try to infer from response headers
                if conn.api_kind.is_none() {
                    conn.api_kind = Self::infer_api_kind_from_response_headers(&conn.resp_headers);
                }
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => {
                conn.resp_buf.clear();
            }
        }
    }

    fn infer_api_kind_from_response_headers(headers: &[(String, String)]) -> Option<ApiKind> {
        let mut has_anthropic = false;
        let mut has_openai = false;
        let mut has_google = false;
        for (name, _) in headers {
            if name.starts_with("anthropic-") {
                has_anthropic = true;
            }
            if name.starts_with("openai-") {
                has_openai = true;
            }
            if name.starts_with("x-goog-") {
                has_google = true;
            }
        }
        if has_anthropic {
            return Some(ApiKind::Anthropic);
        }
        if has_openai {
            return Some(ApiKind::OpenAi);
        }
        if has_google {
            return Some(ApiKind::Gemini);
        }
        None
    }

    fn is_response_complete(&self, key: (u32, u64)) -> bool {
        let conn = match self.streams.get(&key) {
            Some(c) => c,
            None => return false,
        };

        if conn.api_kind.is_none() {
            return false;
        }

        if !conn.resp_headers_done {
            return false;
        }

        let body_bytes = conn.resp_buf.len() - conn.resp_headers_len;

        if let Some(cl) = conn.resp_content_length {
            return body_bytes >= cl;
        }

        if conn.resp_chunked || conn.is_streaming_response {
            let body = &conn.resp_buf[conn.resp_headers_len..];

            if conn.is_streaming_response {
                // Try SSE markers (Anthropic and OpenAI) in raw body.
                if body
                    .windows(b"event: message_stop".len())
                    .any(|w| w == b"event: message_stop")
                    || body
                        .windows(b"event: response.completed".len())
                        .any(|w| w == b"event: response.completed")
                    || body
                        .windows(b"data: [DONE]".len())
                        .any(|w| w == b"data: [DONE]")
                    || body
                        .windows(b"data:[DONE]".len())
                        .any(|w| w == b"data:[DONE]")
                {
                    return true;
                }

                // Gemini SSE: no [DONE] or event: type lines. Detect via finishReason
                // or blockReason (safety-blocked responses have no finishReason).
                if conn.api_kind == Some(ApiKind::Gemini)
                    && (body
                        .windows(b"\"finishReason\"".len())
                        .any(|w| w == b"\"finishReason\"")
                        || body
                            .windows(b"\"blockReason\"".len())
                            .any(|w| w == b"\"blockReason\""))
                {
                    return true;
                }

                // For gzip-compressed bodies, decompress and check for SSE markers.
                if conn
                    .resp_headers
                    .iter()
                    .any(|(k, v)| k == "content-encoding" && v.contains("gzip"))
                {
                    let unchunked =
                        crate::providers::decode_chunked_if_needed(body, &conn.resp_headers);
                    if let Some(decompressed) = try_gzip_decompress(&unchunked) {
                        if decompressed
                            .windows(b"event: message_stop".len())
                            .any(|w| w == b"event: message_stop")
                            || decompressed
                                .windows(b"event: response.completed".len())
                                .any(|w| w == b"event: response.completed")
                            || decompressed
                                .windows(b"data: [DONE]".len())
                                .any(|w| w == b"data: [DONE]")
                            || decompressed
                                .windows(b"data:[DONE]".len())
                                .any(|w| w == b"data:[DONE]")
                        {
                            return true;
                        }
                        if conn.api_kind == Some(ApiKind::Gemini)
                            && (decompressed
                                .windows(b"\"finishReason\"".len())
                                .any(|w| w == b"\"finishReason\"")
                                || decompressed
                                    .windows(b"\"blockReason\"".len())
                                    .any(|w| w == b"\"blockReason\""))
                        {
                            return true;
                        }
                    }
                }
            }

            // Chunked terminator: byte-level match (safe for gzip bodies)
            return body.ends_with(b"0\r\n\r\n") || body.windows(5).any(|w| w == b"\r\n0\r\n");
        }

        false
    }

    fn extract_exchange(&mut self, key: (u32, u64)) -> Option<(ApiKind, HttpExchange)> {
        let conn = self.streams.remove(&key)?;
        Self::extract_exchange_from_conn(conn)
    }

    fn extract_exchange_from_conn(conn: ConnState) -> Option<(ApiKind, HttpExchange)> {
        let api_kind = conn.api_kind?;

        let request = conn.parsed_request.unwrap_or(HttpRequest {
            method: "POST".into(),
            path: String::new(),
            host: String::new(),
            headers: vec![],
            body: vec![],
            // When request wasn't captured, use first response byte time so latency
            // reflects response duration rather than the full monotonic clock value.
            timestamp_ns: conn.req_start_ns.or(conn.first_resp_byte_ns).unwrap_or(0),
        });

        let body = if conn.resp_headers_len < conn.resp_buf.len() {
            conn.resp_buf[conn.resp_headers_len..].to_vec()
        } else {
            Vec::new()
        };

        let response = HttpResponse {
            status: conn.resp_status,
            headers: conn.resp_headers,
            body,
            is_streaming: conn.is_streaming_response,
            timestamp_ns: conn.last_resp_byte_ns.unwrap_or(0),
            first_byte_ns: conn.first_resp_byte_ns,
        };

        Some((api_kind, HttpExchange { request, response }))
    }

    /// Known MCP method prefixes (from the MCP specification).
    const MCP_METHOD_PREFIXES: &[&str] = &[
        "tools/",
        "resources/",
        "prompts/",
        "completion/",
        "notifications/",
        "initialize",
        "ping",
    ];

    fn looks_like_mcp_request(headers: &[(String, String)], body: &[u8]) -> bool {
        // Strong signal: Mcp-Session-Id header
        if headers.iter().any(|(k, _)| k == "mcp-session-id") {
            return true;
        }
        // Fallback: JSON-RPC 2.0 body with MCP-spec method
        let is_json = headers
            .iter()
            .any(|(k, v)| k == "content-type" && v.contains("application/json"));
        if is_json {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
                let is_jsonrpc = json.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0");
                let is_mcp_method = json
                    .get("method")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| Self::MCP_METHOD_PREFIXES.iter().any(|p| m.starts_with(p)));
                return is_jsonrpc && is_mcp_method;
            }
        }
        false
    }

    /// Clean up idle connections. Returns partial exchanges for connections that
    /// had enough data to extract (request parsed + response headers received).
    /// Uses a shorter timeout for streaming connections (SSE streams that go
    /// silent are likely dead).
    pub fn cleanup_idle(
        &mut self,
        max_idle_secs: u64,
        streaming_max_idle_secs: u64,
    ) -> Vec<(u32, String, ApiKind, HttpExchange)> {
        let now = Instant::now();
        let idle_keys: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, conn)| {
                let idle = now.duration_since(conn.last_activity).as_secs();
                let timeout = if conn.is_streaming_response {
                    streaming_max_idle_secs
                } else {
                    max_idle_secs
                };
                idle >= timeout
            })
            .map(|(k, _)| *k)
            .collect();

        let mut partials = Vec::new();
        for key in idle_keys {
            if let Some(conn) = self.streams.remove(&key) {
                if conn.api_kind.is_some() && conn.resp_headers_done {
                    let comm = conn.comm.clone();
                    if let Some((api_kind, exchange)) = Self::extract_exchange_from_conn(conn) {
                        log::warn!(
                            "Emitting partial exchange (pid={}, comm={}, streaming={}, idle)",
                            key.0,
                            comm,
                            exchange.response.is_streaming
                        );
                        partials.push((key.0, comm, api_kind, exchange));
                    }
                }
            }
        }
        partials
    }

    /// Number of tracked connections (for testing).
    #[cfg(test)]
    pub fn connection_count(&self) -> usize {
        self.streams.len()
    }
}

/// Attempt gzip decompression, returning partial results on truncated streams.
fn try_gzip_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut decoded = Vec::new();
    let _ = decoder.read_to_end(&mut decoded);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: u32 = 1234;
    const SSL_PTR: u64 = 0xdead_beef;

    /// Build a minimal HTTP/1.1 request with the given host, path, and JSON body.
    fn make_request(host: &str, path: &str, body: &str) -> Vec<u8> {
        let headers = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            path,
            host,
            body.len(),
            body,
        );
        headers.into_bytes()
    }

    /// Build a minimal HTTP/1.1 response with the given status, content-type, and body.
    fn make_response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
        let phrase = match status {
            200 => "OK",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        let headers = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            status,
            phrase,
            content_type,
            body.len(),
            body,
        );
        headers.into_bytes()
    }

    /// Build a chunked HTTP response (no Content-Length, Transfer-Encoding: chunked).
    fn make_chunked_response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
        let phrase = if status == 200 { "OK" } else { "Error" };
        let chunk = format!("{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body);
        let resp = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             {}",
            status, phrase, content_type, chunk,
        );
        resp.into_bytes()
    }

    /// Build an SSE streaming response.
    fn make_streaming_response(sse_body: &str) -> Vec<u8> {
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             {}",
            sse_body,
        );
        resp.into_bytes()
    }

    fn simple_anthropic_body() -> &'static str {
        r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}"#
    }

    fn simple_response_body() -> &'static str {
        r#"{"id":"msg_test","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hello!"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#
    }

    fn simple_sse_body() -> String {
        "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_stream\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n".to_string()
    }

    #[test]
    fn test_basic_non_streaming_exchange() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        // Send request
        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        // Send response
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.request.method, "POST");
        assert_eq!(exchange.request.path, "/v1/messages");
        assert_eq!(exchange.request.host, "api.anthropic.com");
        assert_eq!(exchange.response.status, 200);
        assert!(!exchange.response.is_streaming);
        assert_eq!(exchange.request.timestamp_ns, 1000);
        assert_eq!(exchange.response.first_byte_ns, Some(2000));
    }

    #[test]
    fn test_tcp_flag_direction_is_normalized_at_reassembly_boundary() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());
        let request_direction = agtap_common::TCP_FLAG;
        let response_direction = agtap_common::TCP_FLAG | 1;

        assert_eq!(actual_direction(request_direction), 0);
        assert_eq!(actual_direction(response_direction), 1);
        assert!(r
            .process_event(PID, SSL_PTR, request_direction, &req, 1000, "")
            .is_none());

        let result = r.process_event(PID, SSL_PTR, response_direction, &resp, 2000, "");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1.request.path, "/v1/messages");
    }

    #[test]
    fn test_basic_streaming_exchange() {
        let mut r = Reassembler::new();
        let req_body = r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.anthropic.com", "/v1/messages", req_body);
        let resp = make_streaming_response(&simple_sse_body());

        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        assert!(exchange.response.is_streaming);
        let body_str = String::from_utf8_lossy(&exchange.response.body);
        assert!(body_str.contains("event: message_stop"));
    }

    #[test]
    fn test_non_recognized_host_and_path_ignored() {
        let mut r = Reassembler::new();
        let req = make_request("api.example.com", "/v1/generate", r#"{"model":"foo"}"#);
        let resp = make_response(200, "application/json", r#"{"id":"gen-123"}"#);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none());
    }

    #[test]
    fn test_non_messages_path_ignored() {
        let mut r = Reassembler::new();
        let req = make_request(
            "api.anthropic.com",
            "/v1/complete",
            r#"{"model":"claude-2"}"#,
        );
        let resp = make_response(200, "application/json", r#"{"completion":"hi"}"#);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none());
    }

    #[test]
    fn test_openai_responses_endpoint() {
        let mut r = Reassembler::new();
        let req = make_request("api.openai.com", "/v1/responses", simple_openai_body());
        let resp = make_response(200, "application/json", simple_openai_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (api_kind, exchange) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::OpenAi));
        assert_eq!(exchange.request.path, "/v1/responses");
    }

    // ── OpenAI-compatible tests ─────────────────────────────────

    fn simple_openai_body() -> &'static str {
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#
    }

    fn simple_openai_response_body() -> &'static str {
        r#"{"id":"chatcmpl-test","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#
    }

    fn simple_openai_sse_body() -> String {
        "\
data: {\"id\":\"chatcmpl-stream\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-stream\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-stream\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
\n\
data: [DONE]\n\
\n".to_string()
    }

    #[test]
    fn test_openai_non_streaming_exchange() {
        let mut r = Reassembler::new();
        let req = make_request(
            "api.openai.com",
            "/v1/chat/completions",
            simple_openai_body(),
        );
        let resp = make_response(200, "application/json", simple_openai_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.request.path, "/v1/chat/completions");
        assert_eq!(exchange.request.host, "api.openai.com");
        assert_eq!(exchange.response.status, 200);
    }

    #[test]
    fn test_openai_streaming_exchange() {
        let mut r = Reassembler::new();
        let req_body =
            r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.openai.com", "/v1/chat/completions", req_body);
        let resp = make_streaming_response(&simple_openai_sse_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        assert!(exchange.response.is_streaming);
        let body_str = String::from_utf8_lossy(&exchange.response.body);
        assert!(body_str.contains("data: [DONE]"));
    }

    #[test]
    fn test_openai_streaming_incomplete() {
        let mut r = Reassembler::new();
        let req_body =
            r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.openai.com", "/v1/chat/completions", req_body);

        // Streaming response without [DONE]
        let partial_sse = "\
data: {\"id\":\"chatcmpl-partial\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\
\n";
        let resp = make_streaming_response(partial_sse);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none(), "should not complete without [DONE]");
    }

    #[test]
    fn test_openai_non_chat_path_ignored() {
        let mut r = Reassembler::new();
        // /v1/completions (legacy) should NOT be matched
        let req = make_request("api.openai.com", "/v1/completions", r#"{"model":"gpt-4"}"#);
        let resp = make_response(200, "application/json", r#"{"id":"cmpl-123"}"#);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none());
    }

    #[test]
    fn test_openai_prefixed_path() {
        let mut r = Reassembler::new();
        // Groq-style: /openai/v1/chat/completions
        let req = make_request(
            "api.groq.com",
            "/openai/v1/chat/completions",
            simple_openai_body(),
        );
        let resp = make_response(200, "application/json", simple_openai_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
    }

    #[test]
    fn test_anthropic_path_not_matched_as_openai() {
        let mut r = Reassembler::new();
        // /v1/messages on anthropic.com → should be Anthropic, NOT OpenAi
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.request.host, "api.anthropic.com");
        assert_eq!(exchange.request.path, "/v1/messages");
    }

    #[test]
    fn test_request_fragmented() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        // Split request into 3 fragments
        let third = req.len() / 3;
        let frag1 = &req[..third];
        let frag2 = &req[third..third * 2];
        let frag3 = &req[third * 2..];

        assert!(r.process_event(PID, SSL_PTR, 0, frag1, 1000, "").is_none());
        assert!(r.process_event(PID, SSL_PTR, 0, frag2, 1001, "").is_none());
        assert!(r.process_event(PID, SSL_PTR, 0, frag3, 1002, "").is_none());

        // Response comes in one piece
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.request.host, "api.anthropic.com");
    }

    #[test]
    fn test_response_fragmented() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");

        // Split response into 3 fragments
        let third = resp.len() / 3;
        assert!(r
            .process_event(PID, SSL_PTR, 1, &resp[..third], 2000, "")
            .is_none());
        assert!(r
            .process_event(PID, SSL_PTR, 1, &resp[third..third * 2], 2001, "")
            .is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp[third * 2..], 2002, "");
        assert!(result.is_some());
        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.first_byte_ns, Some(2000));
    }

    #[test]
    fn test_streaming_incomplete_until_stop() {
        let mut r = Reassembler::new();
        let req_body = r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.anthropic.com", "/v1/messages", req_body);

        // Streaming response without message_stop
        let partial_sse = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n";
        let resp = make_streaming_response(partial_sse);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        // Should NOT complete — no message_stop
        assert!(result.is_none());
    }

    #[test]
    fn test_chunked_terminator() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_chunked_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.response.status, 200);
    }

    #[test]
    fn test_concurrent_connections() {
        let mut r = Reassembler::new();
        let ssl_ptr_a: u64 = 0xaaaa;
        let ssl_ptr_b: u64 = 0xbbbb;

        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        // Start both requests
        r.process_event(PID, ssl_ptr_a, 0, &req, 1000, "");
        r.process_event(PID, ssl_ptr_b, 0, &req, 1100, "");
        assert_eq!(r.connection_count(), 2);

        // Complete connection A
        let result_a = r.process_event(PID, ssl_ptr_a, 1, &resp, 2000, "");
        assert!(result_a.is_some());
        assert_eq!(r.connection_count(), 1);

        // Complete connection B
        let result_b = r.process_event(PID, ssl_ptr_b, 1, &resp, 2100, "");
        assert!(result_b.is_some());
        assert_eq!(r.connection_count(), 0);
    }

    #[test]
    fn test_cleanup_idle_evicts() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert_eq!(r.connection_count(), 1);

        // cleanup_idle(0, 0) means max_idle_secs=0, evicts everything
        // Only request sent (no response headers), so no partial exchange emitted
        let partials = r.cleanup_idle(0, 0);
        assert!(partials.is_empty());
        assert_eq!(r.connection_count(), 0);
    }

    #[test]
    fn test_cleanup_idle_preserves_active() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");

        // With 60-second threshold, freshly active connection survives
        let partials = r.cleanup_idle(60, 30);
        assert!(partials.is_empty());
        assert_eq!(r.connection_count(), 1);
    }

    #[test]
    fn test_malformed_request() {
        let mut r = Reassembler::new();
        // Send garbage
        r.process_event(PID, SSL_PTR, 0, b"not http at all\xff\xfe", 1000, "");

        // Connection exists but request couldn't parse
        // Now send a valid request on a NEW ssl_ptr (old buffer was cleared)
        let ssl_ptr2: u64 = 0xbeef;
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, ssl_ptr2, 0, &req, 2000, "");
        let result = r.process_event(PID, ssl_ptr2, 1, &resp, 3000, "");
        assert!(result.is_some());
    }

    #[test]
    fn test_response_before_request_complete() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        // 1. Send only the first half of the request — no exchange yet
        let half = req.len() / 2;
        let result = r.process_event(PID, SSL_PTR, 0, &req[..half], 1000, "");
        assert!(result.is_none(), "half request should not produce exchange");

        // 2. Response arrives while request is incomplete — is_anthropic not yet set
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(
            result.is_none(),
            "response with incomplete request should not complete"
        );

        // 3. Send rest of request — completes parsing, but no new response data to trigger check
        let result = r.process_event(PID, SSL_PTR, 0, &req[half..], 1001, "");
        assert!(
            result.is_none(),
            "completing request alone should not produce exchange"
        );

        // 4. The connection is still tracked with buffered data, not lost.
        //    Completion only triggers on new response data arrival — this is expected
        //    behavior: without new response data, no re-check of is_response_complete.
        assert_eq!(
            r.connection_count(),
            1,
            "connection should still be tracked"
        );
    }

    #[test]
    fn test_oversized_payload() {
        let mut r = Reassembler::new();
        // 128KB body
        let large_body = "x".repeat(128 * 1024);
        let large_json = format!(
            r#"{{"model":"claude-haiku-4-5-20251001","max_tokens":50,"messages":[{{"role":"user","content":"{}"}}]}}"#,
            large_body
        );
        let req = make_request("api.anthropic.com", "/v1/messages", &large_json);
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        // Should handle gracefully (completes or stays buffered, but no panic/OOM)
        // Since Content-Length is set correctly, this should complete
        assert!(result.is_some());
    }

    #[test]
    fn test_connection_reuse() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        // First exchange
        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result1 = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result1.is_some());

        // Connection removed after extraction, so same key gets fresh ConnState
        // Second exchange on same (pid, ssl_ptr)
        let resp_body2 = r#"{"id":"msg_test2","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hi again!"}],"stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":6}}"#;
        let resp2 = make_response(200, "application/json", resp_body2);

        r.process_event(PID, SSL_PTR, 0, &req, 3000, "");
        let result2 = r.process_event(PID, SSL_PTR, 1, &resp2, 4000, "");
        assert!(result2.is_some());
        let (_, exchange2) = result2.unwrap();
        assert_eq!(exchange2.request.timestamp_ns, 3000);
    }

    // ── MCP detection tests ───────────────────────────────────────

    fn make_mcp_request(host: &str, path: &str, body: &str, session_header: bool) -> Vec<u8> {
        let mut buf = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n",
            path,
            host,
            body.len(),
        );
        if session_header {
            buf.push_str("Mcp-Session-Id: abc-123\r\n");
        }
        buf.push_str("\r\n");
        buf.push_str(body);
        buf.into_bytes()
    }

    fn simple_mcp_body() -> &'static str {
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}"#
    }

    fn simple_mcp_response_body() -> &'static str {
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents here"}]}}"#
    }

    #[test]
    fn test_mcp_session_header_detected() {
        let mut r = Reassembler::new();
        // Even with a non-MCP body, the session header is a strong signal
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"some/custom","params":{}}"#;
        let req = make_mcp_request("mcp.example.com", "/mcp", body, true);
        let resp = make_response(200, "application/json", simple_mcp_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Mcp));
    }

    #[test]
    fn test_mcp_jsonrpc_body_detected() {
        let mut r = Reassembler::new();
        let req = make_mcp_request("mcp.example.com", "/mcp", simple_mcp_body(), false);
        let resp = make_response(200, "application/json", simple_mcp_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Mcp));
    }

    #[test]
    fn test_mcp_non_streaming_completes() {
        let mut r = Reassembler::new();
        let req = make_mcp_request("mcp.example.com", "/mcp", simple_mcp_body(), false);
        let resp = make_response(200, "application/json", simple_mcp_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1_000_000_000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 1_045_000_000, "");
        assert!(result.is_some());
        let (_, exchange) = result.unwrap();
        assert_eq!(exchange.request.timestamp_ns, 1_000_000_000);
        assert_eq!(exchange.response.first_byte_ns, Some(1_045_000_000));
    }

    #[test]
    fn test_regular_json_api_not_detected_as_mcp() {
        let mut r = Reassembler::new();
        // Ethereum JSON-RPC — should NOT be detected as MCP
        let body =
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x123","latest"]}"#;
        let req = make_mcp_request("eth-node.example.com", "/rpc", body, false);
        let resp = make_response(
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#,
        );

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(
            result.is_none(),
            "Ethereum JSON-RPC should not be detected as MCP"
        );
    }

    #[test]
    fn test_mcp_on_anthropic_host() {
        let mut r = Reassembler::new();
        // MCP server proxied through api.anthropic.com should be MCP, not Anthropic
        let req = make_mcp_request(
            "api.anthropic.com",
            "/v1/messages",
            simple_mcp_body(),
            false,
        );
        let resp = make_response(200, "application/json", simple_mcp_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(
            matches!(api_kind, ApiKind::Mcp),
            "MCP on anthropic host should be ApiKind::Mcp"
        );
    }

    // ── Partial exchange / cleanup tests ──────────────────────────

    #[test]
    fn test_cleanup_emits_partial_streaming() {
        let mut r = Reassembler::new();
        let req_body = r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.anthropic.com", "/v1/messages", req_body);

        // Partial SSE: has message_start but no message_stop
        let partial_sse = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n";
        let resp = make_streaming_response(partial_sse);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none(), "should not complete without message_stop");

        // Non-streaming timeout=60 (won't trigger), streaming timeout=0 (will trigger)
        let partials = r.cleanup_idle(60, 0);
        assert_eq!(partials.len(), 1);

        let (pid, _comm, _api_kind, exchange) = &partials[0];
        assert_eq!(*pid, PID);
        assert!(exchange.response.is_streaming);
        let body_str = String::from_utf8_lossy(&exchange.response.body);
        assert!(body_str.contains("message_start"));
        assert_eq!(r.connection_count(), 0);
    }

    #[test]
    fn test_cleanup_streaming_shorter_timeout() {
        let mut r = Reassembler::new();
        let req_body = r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.anthropic.com", "/v1/messages", req_body);
        let partial_sse = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial2\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
\n";
        let resp = make_streaming_response(partial_sse);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");

        // non-streaming=0 but streaming=60 — streaming conn should survive
        let partials = r.cleanup_idle(0, 60);
        assert!(partials.is_empty());
        assert_eq!(r.connection_count(), 1);

        // Now both=0 — streaming conn is evicted with partial exchange
        let partials = r.cleanup_idle(0, 0);
        assert_eq!(partials.len(), 1);
        assert_eq!(r.connection_count(), 0);
    }

    #[test]
    fn test_cleanup_skips_no_response_headers() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());
        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");

        // Only request sent, no response at all
        let partials = r.cleanup_idle(0, 0);
        assert!(
            partials.is_empty(),
            "should not emit partial without response headers"
        );
        assert_eq!(
            r.connection_count(),
            0,
            "connection should still be removed"
        );
    }

    #[test]
    fn test_cleanup_emits_partial_non_streaming() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());

        // Response headers say Content-Length: 1000, but we only send partial body
        let resp_headers = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 1000\r\n\
             \r\n\
             {\"id\":\"msg_partial\",\"partial\":true}";
        let resp = resp_headers.as_bytes();

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, resp, 2000, "");
        assert!(
            result.is_none(),
            "should not complete — body shorter than Content-Length"
        );

        let partials = r.cleanup_idle(0, 0);
        assert_eq!(partials.len(), 1);
        let (_, _, _, exchange) = &partials[0];
        assert!(!exchange.response.is_streaming);
        assert_eq!(exchange.response.status, 200);
        assert_eq!(r.connection_count(), 0);
    }

    #[test]
    fn test_gzip_streaming_response_complete() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut r = Reassembler::new();
        let req_body = r#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = make_request("api.anthropic.com", "/v1/messages", req_body);

        // Build gzip-compressed SSE body
        let sse = simple_sse_body();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(sse.as_bytes()).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        // Build chunked encoding of gzip data
        let chunk = format!("{:x}\r\n", gzip_bytes.len());
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Content-Encoding: gzip\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             {}",
            chunk
        )
        .into_bytes();
        resp.extend_from_slice(&gzip_bytes);
        resp.extend_from_slice(b"\r\n0\r\n\r\n");

        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(
            result.is_some(),
            "gzip-compressed streaming response should be detected as complete"
        );
        let (_, exchange) = result.unwrap();
        assert!(exchange.response.is_streaming);
    }

    // ── Proxy / gateway detection tests ──────────────────────────

    #[test]
    fn test_anthropic_on_proxy_host() {
        let mut r = Reassembler::new();
        let req = make_request("proxy.example.com", "/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, exchange) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Anthropic));
        assert_eq!(exchange.request.host, "proxy.example.com");
    }

    #[test]
    fn test_anthropic_prefixed_path() {
        let mut r = Reassembler::new();
        let req = make_request("gateway.local", "/api/v1/messages", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Anthropic));
    }

    #[test]
    fn test_gemini_on_proxy_host() {
        let mut r = Reassembler::new();
        let req_body = r#"{"contents":[{"parts":[{"text":"hi"}]}]}"#;
        let req = make_request(
            "proxy.example.com",
            "/v1beta/models/gemini-2.5-flash:generateContent",
            req_body,
        );
        let resp_body = r#"{"candidates":[{"content":{"parts":[{"text":"Hello!"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},"modelVersion":"gemini-2.5-flash","responseId":"resp_proxy"}"#;
        let resp = make_response(200, "application/json", resp_body);

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Gemini));
    }

    // ── Response-only inference tests ─────────────────────────────

    fn make_response_with_headers(
        status: u16,
        content_type: &str,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) -> Vec<u8> {
        let phrase = match status {
            200 => "OK",
            _ => "Unknown",
        };
        let mut resp = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n",
            status,
            phrase,
            content_type,
            body.len(),
        );
        for (name, val) in extra_headers {
            resp.push_str(&format!("{}: {}\r\n", name, val));
        }
        resp.push_str("\r\n");
        resp.push_str(body);
        resp.into_bytes()
    }

    #[test]
    fn test_response_inferred_anthropic() {
        let mut r = Reassembler::new();
        // No request at all — only response with anthropic-* headers
        let resp = make_response_with_headers(
            200,
            "application/json",
            &[("anthropic-ratelimit-requests-remaining", "99")],
            simple_response_body(),
        );

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Anthropic));
    }

    #[test]
    fn test_response_inferred_openai() {
        let mut r = Reassembler::new();
        let resp = make_response_with_headers(
            200,
            "application/json",
            &[("openai-processing-ms", "123")],
            simple_openai_response_body(),
        );

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::OpenAi));
    }

    #[test]
    fn test_response_inferred_gemini() {
        let mut r = Reassembler::new();
        let gemini_resp_body = r#"{"candidates":[{"content":{"parts":[{"text":"Hello!"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},"modelVersion":"gemini-2.5-flash","responseId":"resp_goog"}"#;
        let resp = make_response_with_headers(
            200,
            "application/json",
            &[("x-goog-api-version", "v1beta")],
            gemini_resp_body,
        );

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());
        let (api_kind, _) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Gemini));
    }

    #[test]
    fn test_response_inferred_no_headers() {
        let mut r = Reassembler::new();
        // Response without distinctive headers — should NOT be inferred
        let resp = make_response(200, "application/json", r#"{"some":"data"}"#);

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none());
    }

    #[test]
    fn test_cleanup_returns_comm() {
        let mut r = Reassembler::new();
        let req = make_request("api.anthropic.com", "/v1/messages", simple_anthropic_body());

        let resp_headers = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 1000\r\n\
             \r\n\
             {\"partial\":true}";
        let resp = resp_headers.as_bytes();

        r.process_event(PID, SSL_PTR, 0, &req, 1000, "node");
        r.process_event(PID, SSL_PTR, 1, resp, 2000, "node");

        let partials = r.cleanup_idle(0, 0);
        assert_eq!(partials.len(), 1);
        let (pid, comm, _, _) = &partials[0];
        assert_eq!(*pid, PID);
        assert_eq!(comm, "node");
    }

    #[test]
    fn test_response_only_uses_last_byte_timestamp() {
        let mut r = Reassembler::new();

        // Build a response with anthropic headers, split into two chunks
        let resp_full = make_response_with_headers(
            200,
            "application/json",
            &[("anthropic-ratelimit-requests-remaining", "99")],
            simple_response_body(),
        );

        let mid = resp_full.len() / 2;
        let chunk1 = &resp_full[..mid];
        let chunk2 = &resp_full[mid..];

        let first_ts: u64 = 5_000_000_000;
        let last_ts: u64 = 8_000_000_000;

        // No request — response only, two chunks with different timestamps
        let result = r.process_event(PID, SSL_PTR, 1, chunk1, first_ts, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, chunk2, last_ts, "");
        assert!(result.is_some());

        let (_, exchange) = result.unwrap();
        // request.timestamp_ns should be first response byte time (no request was sent)
        assert_eq!(exchange.request.timestamp_ns, first_ts);
        // response.timestamp_ns should be last response byte time
        assert_eq!(exchange.response.timestamp_ns, last_ts);
        // first_byte_ns should still be the first chunk's timestamp
        assert_eq!(exchange.response.first_byte_ns, Some(first_ts));
        // Latency should be positive (last - first)
        assert!(exchange.response.timestamp_ns > exchange.request.timestamp_ns);
    }

    // ── Custom path inference tests ─────────────────────────────

    #[test]
    fn test_custom_path_inferred_from_anthropic_headers() {
        let mut r = Reassembler::new();
        let req = make_request("gateway.example.com", "/api/chat", simple_anthropic_body());
        let resp = make_response_with_headers(
            200,
            "application/json",
            &[("anthropic-ratelimit-requests-remaining", "99")],
            simple_response_body(),
        );

        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (api_kind, exchange) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::Anthropic));
        assert_eq!(exchange.request.path, "/api/chat");
        assert_eq!(exchange.request.host, "gateway.example.com");
        assert_eq!(exchange.response.status, 200);
    }

    #[test]
    fn test_custom_path_inferred_from_openai_headers() {
        let mut r = Reassembler::new();
        let req = make_request("gateway.example.com", "/api/chat", simple_openai_body());
        let resp = make_response_with_headers(
            200,
            "application/json",
            &[("openai-processing-ms", "123")],
            simple_openai_response_body(),
        );

        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_some());

        let (api_kind, exchange) = result.unwrap();
        assert!(matches!(api_kind, ApiKind::OpenAi));
        assert_eq!(exchange.request.path, "/api/chat");
        assert_eq!(exchange.request.host, "gateway.example.com");
        assert_eq!(exchange.response.status, 200);
    }

    #[test]
    fn test_custom_path_no_provider_headers_still_ignored() {
        let mut r = Reassembler::new();
        let req = make_request("gateway.example.com", "/api/chat", simple_anthropic_body());
        let resp = make_response(200, "application/json", simple_response_body());

        let result = r.process_event(PID, SSL_PTR, 0, &req, 1000, "");
        assert!(result.is_none());

        let result = r.process_event(PID, SSL_PTR, 1, &resp, 2000, "");
        assert!(result.is_none());
    }
}
