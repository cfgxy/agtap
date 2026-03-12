use serde_json::Value;

use crate::reassembly::HttpExchange;

use super::{HttpDetail, LlmCall};

/// Parse an HTTP exchange into an LlmCall + HttpDetail (OpenAI-compatible format)
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

    let choices = json.get("choices")?.as_array()?;
    if choices.is_empty() {
        return None;
    }
    let choice = &choices[0];

    let stop_reason = choice
        .get("finish_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Collect tool names from response
    let mut tools = Vec::new();
    if let Some(tool_calls) = choice
        .get("message")
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
    {
        for tc in tool_calls {
            if let Some(name) = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                tools.push(name.to_string());
            }
        }
    }

    let usage = json.get("usage")?;
    let input_tokens = usage
        .get("prompt_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let output_tokens = usage
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // If neither token count is present, consider usage missing
    if input_tokens.is_none() && output_tokens.is_none() {
        return None;
    }

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

fn parse_streaming_response(
    exchange: &HttpExchange,
    req_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let body_str = String::from_utf8_lossy(decoded_body);

    let mut id = String::new();
    let mut model = req_model.to_string();
    let mut stop_reason = String::from("unknown");
    let mut tools: Vec<String> = Vec::new();
    let mut input_tokens: Option<u32> = None;
    let mut output_tokens: Option<u32> = None;

    for line in body_str.lines() {
        let data = if let Some(d) = line.strip_prefix("data: ") {
            d.trim()
        } else if let Some(d) = line.strip_prefix("data:") {
            d.trim()
        } else {
            continue;
        };

        // Skip [DONE] sentinel
        if data == "[DONE]" {
            continue;
        }

        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // First chunk typically has id and model
        if id.is_empty() {
            if let Some(v) = json.get("id").and_then(|v| v.as_str()) {
                id = v.to_string();
            }
        }
        if let Some(v) = json.get("model").and_then(|v| v.as_str()) {
            model = v.to_string();
        }

        // Process choices
        if let Some(choices) = json.get("choices").and_then(|v| v.as_array()) {
            if let Some(choice) = choices.first() {
                // finish_reason
                if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                    stop_reason = reason.to_string();
                }

                // tool_calls in delta
                if let Some(tool_calls) = choice
                    .get("delta")
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(|t| t.as_array())
                {
                    for tc in tool_calls {
                        if let Some(name) = tc
                            .get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())
                        {
                            if !name.is_empty() {
                                tools.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Usage (typically in final chunk)
        if let Some(usage) = json.get("usage") {
            if !usage.is_null() {
                if let Some(v) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
                    input_tokens = Some(v as u32);
                }
                if let Some(v) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
                    output_tokens = Some(v as u32);
                }
            }
        }
    }

    if id.is_empty() {
        return None;
    }

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
    use crate::reassembly::{HttpExchange, HttpRequest, HttpResponse};

    fn make_exchange(req_body: &[u8], resp_body: &[u8]) -> HttpExchange {
        make_exchange_raw(
            "api.openai.com",
            "/v1/chat/completions",
            req_body,
            resp_body,
        )
    }

    fn make_streaming_exchange(req_body: &[u8], sse_body: &[u8]) -> HttpExchange {
        make_streaming_exchange_raw("api.openai.com", "/v1/chat/completions", req_body, sse_body)
    }

    fn default_req_body() -> &'static [u8] {
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#
    }

    fn streaming_req_body() -> &'static [u8] {
        br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#
    }

    #[test]
    fn test_parse_non_streaming_response() {
        let resp = br#"{"id":"chatcmpl-123","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "chatcmpl-123");
        assert_eq!(call.provider, "openai");
        assert_eq!(call.model, "gpt-4o");
        assert_eq!(call.input_tokens, Some(10));
        assert_eq!(call.output_tokens, Some(5));
        assert_eq!(call.stop_reason, "stop");
        assert!(!call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_parse_streaming_response() {
        let sse = b"\
data: {\"id\":\"chatcmpl-456\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-456\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-456\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there!\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-456\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
\n\
data: {\"id\":\"chatcmpl-456\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":8,\"total_tokens\":20}}\n\
\n\
data: [DONE]\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "chatcmpl-456");
        assert_eq!(call.input_tokens, Some(12));
        assert_eq!(call.output_tokens, Some(8));
        assert_eq!(call.stop_reason, "stop");
        assert!(call.streaming);
    }

    #[test]
    fn test_parse_tool_use_non_streaming() {
        let resp = br#"{"id":"chatcmpl-tool","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"NYC\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":20,"total_tokens":70}}"#;
        let req = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather"}}]}"#;
        let exchange = make_exchange(req, resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
        assert_eq!(call.stop_reason, "tool_calls");
    }

    #[test]
    fn test_parse_tool_use_streaming() {
        let sse = b"\
data: {\"id\":\"chatcmpl-tool-s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-tool-s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\"\"}}]},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-tool-s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\": \\\"NYC\\\"}\"}}]},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-tool-s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\
\n\
data: [DONE]\n\
\n";
        let req = br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather"}}]}"#;
        let exchange = make_streaming_exchange(req, sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
        assert_eq!(call.stop_reason, "tool_calls");
    }

    #[test]
    fn test_parse_request_model() {
        let body = br#"{"model":"gpt-4o","stream":true,"messages":[],"tools":[{"type":"function","function":{"name":"search","description":"Search"}}]}"#;
        let model = crate::providers::parse_request_model(body).unwrap();
        assert_eq!(model, "gpt-4o");
    }

    #[test]
    fn test_error_response_rate_limit() {
        let resp = br#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","code":"rate_limit"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.provider, "openai");
        assert_eq!(call.model, "gpt-4o");
        assert_eq!(call.stop_reason, "error:rate_limit_error");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_error_response_invalid_api_key() {
        let resp = br#"{"error":{"message":"Incorrect API key","type":"invalid_request_error","code":"invalid_api_key"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:invalid_request_error");
    }

    #[test]
    fn test_error_response_streaming_fallback() {
        // Error returned as non-SSE body on a streaming request
        let resp_body = br#"{"error":{"message":"Server error","type":"server_error","code":"internal_error"}}"#;
        let exchange = make_streaming_exchange(streaming_req_body(), resp_body);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:server_error");
        assert!(call.input_tokens.is_none());
    }

    #[test]
    fn test_non_streaming_missing_usage() {
        let resp = br#"{"id":"chatcmpl-no-usage","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}"#;
        let exchange = make_exchange(default_req_body(), resp);
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_non_streaming_missing_choices() {
        let resp = br#"{"id":"chatcmpl-no-choices","object":"chat.completion","model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
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
        let req = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let resp = br#"{"id":"chatcmpl-123","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let exchange = make_exchange(req, resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.model, "gpt-4o");
    }

    #[test]
    fn test_streaming_no_usage() {
        let sse = b"\
data: {\"id\":\"chatcmpl-no-u\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-no-u\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-no-u\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
\n\
data: [DONE]\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "chatcmpl-no-u");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
    }

    #[test]
    fn test_streaming_with_usage() {
        let sse = b"\
data: {\"id\":\"chatcmpl-wu\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-wu\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
\n\
data: {\"id\":\"chatcmpl-wu\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}\n\
\n\
data: [DONE]\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.input_tokens, Some(100));
        assert_eq!(call.output_tokens, Some(50));
    }

    #[test]
    fn test_streaming_data_done_no_space() {
        // SSE spec: space after colon is optional → data:[DONE] should work
        let sse = b"\
data: {\"id\":\"chatcmpl-nsp\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\
\n\
data: {\"id\":\"chatcmpl-nsp\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
\n\
data:[DONE]\n\
\n";
        let exchange = make_streaming_exchange(streaming_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "chatcmpl-nsp");
        assert_eq!(call.stop_reason, "stop");
    }

    #[test]
    fn test_decode_chunked() {
        let chunked_body = b"1a\r\n{\"id\":\"chatcmpl-chunked\"}\r\n0\r\n\r\n";
        let exchange = HttpExchange {
            request: HttpRequest {
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                host: "api.openai.com".into(),
                headers: vec![],
                body: default_req_body().to_vec(),
                timestamp_ns: 1000,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![("transfer-encoding".into(), "chunked".into())],
                body: chunked_body.to_vec(),
                is_streaming: false,
                timestamp_ns: 2000,
                first_byte_ns: Some(1500),
            },
        };
        // This won't fully parse as a valid OpenAI response (missing choices/usage),
        // but it tests chunked decoding doesn't crash
        assert!(parse_call_only(exchange).is_none());
    }
}
