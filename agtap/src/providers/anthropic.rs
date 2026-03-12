use serde_json::Value;

use crate::reassembly::HttpExchange;

use super::{HttpDetail, LlmCall};

/// Parse an HTTP exchange into an LlmCall + HttpDetail (Anthropic format)
pub fn parse_exchange(exchange: HttpExchange) -> Option<(LlmCall, HttpDetail)> {
    let model =
        super::parse_request_model(&exchange.request.body).unwrap_or_else(|| "unknown".to_string());
    let decoded_body = super::decode_body(&exchange.response.body, &exchange.response.headers);

    if exchange.response.is_streaming {
        parse_streaming_response(&exchange, &model, &decoded_body)
    } else {
        parse_non_streaming_response(&exchange, &model, &decoded_body)
    }
    .or_else(|| try_parse_error_response(&exchange, &model, &decoded_body))
}

fn parse_non_streaming_response(
    exchange: &HttpExchange,
    req_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let json: Value = serde_json::from_slice(decoded_body).ok()?;

    let id = json.get("id")?.as_str()?.to_string();
    let model = json
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(req_model)
        .to_string();

    let usage = json.get("usage")?;
    let input_tokens = usage.get("input_tokens")?.as_u64()? as u32;
    let output_tokens = usage.get("output_tokens")?.as_u64()? as u32;
    let cache_creation = usage
        .get("cache_creation_input_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let cache_read = usage
        .get("cache_read_input_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let input_tokens = input_tokens + cache_creation.unwrap_or(0) + cache_read.unwrap_or(0);

    let stop_reason = json
        .get("stop_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let tools = collect_tool_names(json.get("content"));

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::from_exchange(
            exchange,
            id,
            "anthropic",
            model,
            Some(input_tokens),
            Some(output_tokens),
            cache_creation,
            cache_read,
            stop_reason,
            tools,
        ),
        detail,
    ))
}

/// Accumulated state from parsing SSE events in a streaming response.
struct SseState {
    id: String,
    model: String,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation: Option<u32>,
    cache_read: Option<u32>,
    stop_reason: String,
    tool_names: Vec<String>,
}

impl SseState {
    fn new(req_model: &str) -> Self {
        Self {
            id: String::new(),
            model: req_model.to_string(),
            input_tokens: 0,
            output_tokens: 0,
            cache_creation: None,
            cache_read: None,
            stop_reason: String::from("unknown"),
            tool_names: Vec::new(),
        }
    }

    fn process_event(&mut self, event_type: &str, data: &str) {
        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return,
        };

        match event_type {
            "message_start" => {
                if let Some(msg) = json.get("message") {
                    if let Some(v) = msg.get("id").and_then(|v| v.as_str()) {
                        self.id = v.to_string();
                    }
                    if let Some(v) = msg.get("model").and_then(|v| v.as_str()) {
                        self.model = v.to_string();
                    }
                    if let Some(usage) = msg.get("usage") {
                        if let Some(v) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.input_tokens = v as u32;
                        }
                        if let Some(v) = usage
                            .get("cache_creation_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.cache_creation = Some(v as u32);
                        }
                        if let Some(v) = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.cache_read = Some(v as u32);
                        }
                        self.input_tokens = self.input_tokens
                            + self.cache_creation.unwrap_or(0)
                            + self.cache_read.unwrap_or(0);
                    }
                }
            }
            "content_block_start" => {
                if let Some(cb) = json.get("content_block") {
                    let block_type = cb.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if block_type == "tool_use" {
                        let name = cb
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        self.tool_names.push(name);
                    }
                }
            }
            "message_delta" => {
                if let Some(delta) = json.get("delta") {
                    if let Some(v) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                        self.stop_reason = v.to_string();
                    }
                }
                if let Some(usage) = json.get("usage") {
                    if let Some(v) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        self.output_tokens = v as u32;
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_streaming_response(
    exchange: &HttpExchange,
    req_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let body_str = String::from_utf8_lossy(decoded_body);

    let mut state = SseState::new(req_model);
    for (event_type, data) in super::iter_sse_events(&body_str) {
        state.process_event(&event_type, &data);
    }

    if state.id.is_empty() {
        return None;
    }

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::from_exchange(
            exchange,
            state.id,
            "anthropic",
            state.model,
            Some(state.input_tokens),
            Some(state.output_tokens),
            state.cache_creation,
            state.cache_read,
            state.stop_reason,
            state.tool_names,
        ),
        detail,
    ))
}

/// Try to parse an error response (non-200 or API error body).
fn try_parse_error_response(
    exchange: &HttpExchange,
    req_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let json: Value = serde_json::from_slice(decoded_body).ok()?;

    // Anthropic error format: {"type":"error","error":{"type":"rate_limit_error","message":"..."}}
    let error_type = json
        .get("error")
        .and_then(|e| e.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Only treat as error if there's an "error" field or the top-level type is "error"
    let is_error =
        json.get("error").is_some() || json.get("type").and_then(|v| v.as_str()) == Some("error");
    if !is_error {
        return None;
    }

    let stop_reason = format!("error:{}", error_type);

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::error_from_exchange(exchange, "anthropic", req_model.to_string(), stop_reason),
        detail,
    ))
}

/// Collect tool names from non-streaming content blocks.
fn collect_tool_names(content: Option<&Value>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(arr) = content.and_then(|v| v.as_array()) {
        for item in arr {
            let block_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if block_type == "tool_use" {
                if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

#[cfg(test)]
fn parse_call_only(exchange: HttpExchange) -> Option<LlmCall> {
    parse_exchange(exchange).map(|(call, _)| call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::decode_chunked;
    use crate::providers::test_helpers::{
        make_exchange as make_exchange_raw, make_streaming_exchange as make_streaming_exchange_raw,
    };
    use crate::reassembly::{HttpExchange, HttpRequest, HttpResponse};

    fn make_exchange(req_body: &[u8], resp_body: &[u8]) -> HttpExchange {
        make_exchange_raw("api.anthropic.com", "/v1/messages", req_body, resp_body)
    }

    fn make_streaming_exchange(req_body: &[u8], sse_body: &[u8]) -> HttpExchange {
        make_streaming_exchange_raw("api.anthropic.com", "/v1/messages", req_body, sse_body)
    }

    fn default_req_body() -> &'static [u8] {
        br#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}"#
    }

    fn streaming_req_body() -> &'static [u8] {
        br#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#
    }

    #[test]
    fn test_parse_non_streaming_response() {
        let response_body = br#"{"id":"msg_123","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hello!"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;

        let exchange = make_exchange(default_req_body(), response_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "msg_123");
        assert_eq!(call.provider, "anthropic");
        assert_eq!(call.model, "claude-haiku-4-5-20251001");
        assert_eq!(call.input_tokens, Some(10));
        assert_eq!(call.output_tokens, Some(5));
        assert_eq!(call.stop_reason, "end_turn");
        assert!(!call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_parse_streaming_response() {
        let sse_body = b"\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_456\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there!\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":8}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";

        let exchange = make_streaming_exchange(streaming_req_body(), sse_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "msg_456");
        assert_eq!(call.input_tokens, Some(12));
        assert_eq!(call.output_tokens, Some(8));
        assert_eq!(call.stop_reason, "end_turn");
        assert!(call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_parse_tool_use_streaming() {
        let sse_body = b"\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_789\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":100,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"read_file\",\"input\":{}}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\": \\\"/etc\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"/passwd\\\"}\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":25}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";

        let req_body = br#"{"model":"claude-sonnet-4-20250514","max_tokens":1024,"stream":true,"messages":[{"role":"user","content":"read /etc/passwd"}]}"#;
        let exchange = make_streaming_exchange(req_body, sse_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "msg_789");
        assert_eq!(call.stop_reason, "tool_use");
        assert_eq!(call.output_tokens, Some(25));
        assert_eq!(call.tools, vec!["read_file"]);
    }

    #[test]
    fn test_decode_chunked() {
        let chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoded = decode_chunked(chunked);
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_parse_request_model() {
        let body = br#"{"model":"claude-haiku-4-5-20251001","max_tokens":50,"stream":false,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"read_file","description":"Read a file"}]}"#;
        let model = crate::providers::parse_request_model(body).unwrap();
        assert_eq!(model, "claude-haiku-4-5-20251001");
    }

    #[test]
    fn test_non_streaming_cache_tokens() {
        let resp = br#"{"id":"msg_cache","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn","usage":{"input_tokens":15,"output_tokens":8,"cache_creation_input_tokens":500,"cache_read_input_tokens":200}}"#;
        let req = br#"{"model":"claude-sonnet-4-20250514","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#;
        let exchange = make_exchange(req, resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.input_tokens, Some(715)); // 15 + 500 + 200
        assert_eq!(call.cache_creation_input_tokens, Some(500));
        assert_eq!(call.cache_read_input_tokens, Some(200));
    }

    #[test]
    fn test_non_streaming_missing_id() {
        let resp = br#"{"type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_non_streaming_missing_usage() {
        let resp = br#"{"id":"msg_no_usage","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_invalid_json() {
        let exchange = make_exchange(default_req_body(), b"{not valid json!!!");
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_request_missing_model() {
        let req = br#"{"max_tokens":50,"messages":[{"role":"user","content":"hi"}]}"#;
        let resp = br#"{"id":"msg_x","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let exchange = make_exchange(req, resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.model, "claude-haiku-4-5-20251001");
    }

    #[test]
    fn test_streaming_cache_tokens() {
        let sse_body = b"\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_sc\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0,\"cache_creation_input_tokens\":300,\"cache_read_input_tokens\":150}}}\n\
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
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.input_tokens, Some(462)); // 12 + 300 + 150
        assert_eq!(call.cache_creation_input_tokens, Some(300));
        assert_eq!(call.cache_read_input_tokens, Some(150));
    }

    #[test]
    fn test_streaming_tool_use_names() {
        let sse_body = b"\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_mixed\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":50,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_02\",\"name\":\"get_weather\",\"input\":{}}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":1}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":30}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
    }

    #[test]
    fn test_non_streaming_tool_use_names() {
        let resp = br#"{"id":"msg_tool","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Let me help"},{"type":"tool_use","id":"toolu_01","name":"read_file","input":{"path":"/tmp"}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["read_file"]);
    }

    #[test]
    fn test_streaming_no_trailing_newline() {
        let sse_body = b"\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_notrail\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-haiku-4-5-20251001\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}";
        let exchange = make_streaming_exchange(streaming_req_body(), sse_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "msg_notrail");
        assert_eq!(call.stop_reason, "end_turn");
    }

    #[test]
    fn test_streaming_missing_message_start() {
        let sse_body = b"\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse_body);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_chunked_empty_input() {
        let decoded = decode_chunked(b"");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_chunked_with_extensions() {
        let chunked = b"5;ext=val\r\nHello\r\n0\r\n\r\n";
        let decoded = decode_chunked(chunked);
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_chunked_incomplete() {
        let chunked = b"a\r\nHello";
        let decoded = decode_chunked(chunked);
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_error_response_rate_limit() {
        let resp = br#"{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.provider, "anthropic");
        assert_eq!(call.model, "claude-haiku-4-5-20251001");
        assert_eq!(call.stop_reason, "error:rate_limit_error");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_error_response_overloaded() {
        let resp =
            br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:overloaded_error");
        assert!(call.input_tokens.is_none());
    }

    #[test]
    fn test_error_response_streaming_fallback() {
        // Error returned as non-SSE body on a streaming request
        let resp_body =
            br#"{"type":"error","error":{"type":"invalid_request_error","message":"Bad request"}}"#;
        let exchange = make_streaming_exchange(streaming_req_body(), resp_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:invalid_request_error");
        assert!(call.input_tokens.is_none());
    }

    #[test]
    fn test_200_with_malformed_json_body() {
        let exchange = make_exchange(default_req_body(), b"<html>502 Bad Gateway</html>");
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_mismatched_content_length() {
        let truncated = br#"{"id":"msg_trunc","type":"mess"#;
        let exchange = make_exchange(default_req_body(), truncated);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_gzip_compressed_non_streaming() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let json_body = br#"{"id":"msg_gz","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"Hello!"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json_body).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        let exchange = HttpExchange {
            request: HttpRequest {
                method: "POST".into(),
                path: "/v1/messages".into(),
                host: "api.anthropic.com".into(),
                headers: vec![],
                body: default_req_body().to_vec(),
                timestamp_ns: 1000,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![("content-encoding".into(), "gzip".into())],
                body: gzip_bytes,
                is_streaming: false,
                timestamp_ns: 2000,
                first_byte_ns: Some(1500),
            },
        };

        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "msg_gz");
        assert_eq!(call.model, "claude-haiku-4-5-20251001");
        assert_eq!(call.input_tokens, Some(10));
        assert_eq!(call.output_tokens, Some(5));
        assert_eq!(call.stop_reason, "end_turn");
    }
}
