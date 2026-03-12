use serde_json::Value;

use crate::reassembly::HttpExchange;

use super::{HttpDetail, LlmCall};

/// Parse an HTTP exchange into an LlmCall + HttpDetail (OpenAI Responses API format)
pub fn parse_exchange(exchange: HttpExchange) -> Option<(LlmCall, HttpDetail)> {
    let model =
        super::parse_request_model(&exchange.request.body).unwrap_or_else(|| "unknown".to_string());
    let decoded_body = super::decode_body(&exchange.response.body, &exchange.response.headers);

    if exchange.response.is_streaming {
        parse_streaming_response(&exchange, &model, &decoded_body)
    } else {
        parse_non_streaming_response(&exchange, &model, &decoded_body)
    }
    .or_else(|| super::try_parse_openai_error(&exchange, &model, &decoded_body))
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

    let stop_reason = json
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Output array must exist
    let output = json.get("output")?.as_array()?;

    // Collect tool names from function_call items in output
    let mut tools = Vec::new();
    for item in output {
        if item.get("type").and_then(|v| v.as_str()) == Some("function_call") {
            if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                tools.push(name.to_string());
            }
        }
    }

    let (input_tokens, output_tokens) = match json.get("usage").filter(|v| !v.is_null()) {
        Some(usage) => (
            usage
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            usage
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        ),
        None => (None, None),
    };

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::from_exchange(
            exchange,
            id,
            "openai",
            model,
            input_tokens,
            output_tokens,
            None,
            None,
            stop_reason,
            tools,
        ),
        detail,
    ))
}

/// Accumulated state from parsing SSE events in a streaming Responses API response.
struct SseState {
    id: String,
    model: String,
    stop_reason: String,
    tools: Vec<String>,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

impl SseState {
    fn new(req_model: &str) -> Self {
        Self {
            id: String::new(),
            model: req_model.to_string(),
            stop_reason: String::from("unknown"),
            tools: Vec::new(),
            input_tokens: None,
            output_tokens: None,
        }
    }

    fn process_event(&mut self, event_type: &str, data: &str) {
        // Only parse JSON for events we care about
        match event_type {
            "response.created" | "response.output_item.added" | "response.completed" => {}
            _ => return,
        }

        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return,
        };

        match event_type {
            "response.created" => {
                if let Some(resp) = json.get("response") {
                    if let Some(v) = resp.get("id").and_then(|v| v.as_str()) {
                        self.id = v.to_string();
                    }
                    if let Some(v) = resp.get("model").and_then(|v| v.as_str()) {
                        self.model = v.to_string();
                    }
                }
            }
            "response.output_item.added" => {
                if let Some(item) = json.get("item") {
                    if item.get("type").and_then(|v| v.as_str()) == Some("function_call") {
                        if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                            self.tools.push(name.to_string());
                        }
                    }
                }
            }
            "response.completed" => {
                if let Some(resp) = json.get("response") {
                    if let Some(v) = resp.get("status").and_then(|v| v.as_str()) {
                        self.stop_reason = v.to_string();
                    }
                    if let Some(usage) = resp.get("usage") {
                        if let Some(v) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.input_tokens = Some(v as u32);
                        }
                        if let Some(v) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                            self.output_tokens = Some(v as u32);
                        }
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
            "openai",
            state.model,
            state.input_tokens,
            state.output_tokens,
            None,
            None,
            state.stop_reason,
            state.tools,
        ),
        detail,
    ))
}

#[cfg(test)]
fn parse_call_only(exchange: HttpExchange) -> Option<LlmCall> {
    parse_exchange(exchange).map(|(call, _)| call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::test_helpers::{
        make_exchange as make_exchange_raw, make_streaming_exchange as make_streaming_exchange_raw,
    };

    fn make_exchange(req_body: &[u8], resp_body: &[u8]) -> HttpExchange {
        make_exchange_raw("api.openai.com", "/v1/responses", req_body, resp_body)
    }

    fn make_streaming_exchange(req_body: &[u8], sse_body: &[u8]) -> HttpExchange {
        make_streaming_exchange_raw("api.openai.com", "/v1/responses", req_body, sse_body)
    }

    fn default_req_body() -> &'static [u8] {
        br#"{"model":"gpt-4o","input":"What is 2+2?"}"#
    }

    fn streaming_req_body() -> &'static [u8] {
        br#"{"model":"gpt-4o","stream":true,"input":"What is 2+2?"}"#
    }

    #[test]
    fn test_parse_non_streaming_response() {
        let resp = br#"{"id":"resp_123","object":"response","model":"gpt-4o-2024-08-06","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"4"}]}],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_123");
        assert_eq!(call.provider, "openai");
        assert_eq!(call.model, "gpt-4o-2024-08-06");
        assert_eq!(call.input_tokens, Some(10));
        assert_eq!(call.output_tokens, Some(5));
        assert_eq!(call.stop_reason, "completed");
        assert!(!call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_parse_streaming_response() {
        let sse = b"\
event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_456\",\"object\":\"response\",\"model\":\"gpt-4o-2024-08-06\",\"status\":\"in_progress\",\"output\":[],\"usage\":null}}\n\
\n\
event: response.output_item.added\n\
data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\
\n\
event: response.content_part.added\n\
data: {\"type\":\"response.content_part.added\",\"output_index\":0,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\"}}\n\
\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"4\"}\n\
\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_456\",\"object\":\"response\",\"model\":\"gpt-4o-2024-08-06\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"4\"}]}],\"usage\":{\"input_tokens\":12,\"output_tokens\":8,\"total_tokens\":20}}}\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_456");
        assert_eq!(call.model, "gpt-4o-2024-08-06");
        assert_eq!(call.input_tokens, Some(12));
        assert_eq!(call.output_tokens, Some(8));
        assert_eq!(call.stop_reason, "completed");
        assert!(call.streaming);
    }

    #[test]
    fn test_parse_tool_use() {
        let resp = br#"{"id":"resp_tool","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"function_call","id":"fc_1","name":"get_weather","arguments":"{\"city\":\"NYC\"}"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Let me check."}]}],"usage":{"input_tokens":50,"output_tokens":20,"total_tokens":70}}"#;
        let req = br#"{"model":"gpt-4o","input":"weather?","tools":[{"type":"function","name":"get_weather"}]}"#;
        let exchange = make_exchange(req, resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
        assert_eq!(call.stop_reason, "completed");
    }

    #[test]
    fn test_error_response() {
        let resp = br#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","code":"rate_limit"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.provider, "openai");
        assert_eq!(call.stop_reason, "error:rate_limit_error");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
    }

    #[test]
    fn test_error_response_streaming_fallback() {
        let resp_body = br#"{"error":{"message":"Server error","type":"server_error","code":"internal_error"}}"#;
        let exchange = make_streaming_exchange(streaming_req_body(), resp_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:server_error");
        assert!(call.input_tokens.is_none());
    }

    #[test]
    fn test_missing_output() {
        let resp = br#"{"id":"resp_no_out","object":"response","model":"gpt-4o","status":"completed","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_missing_id() {
        let resp = br#"{"object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}],"usage":{"input_tokens":10,"output_tokens":5}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_incomplete_with_null_usage() {
        let resp = br#"{"id":"resp_inc","object":"response","model":"gpt-4o","status":"incomplete","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}],"usage":null}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_inc");
        assert_eq!(call.stop_reason, "incomplete");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
    }

    #[test]
    fn test_usage_field_names() {
        let resp = br#"{"id":"resp_u","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}],"usage":{"input_tokens":42,"output_tokens":7,"total_tokens":49}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.input_tokens, Some(42));
        assert_eq!(call.output_tokens, Some(7));
    }
}
