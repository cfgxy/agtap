use serde_json::Value;

use crate::reassembly::HttpExchange;

use super::{HttpDetail, LlmCall};

/// Parse an HTTP exchange into an LlmCall + HttpDetail (Google Gemini format)
pub fn parse_exchange(exchange: HttpExchange) -> Option<(LlmCall, HttpDetail)> {
    let model =
        extract_model_from_path(&exchange.request.path).unwrap_or_else(|| "unknown".to_string());
    let decoded_body = super::decode_body(&exchange.response.body, &exchange.response.headers);

    if exchange.response.is_streaming {
        parse_streaming_response(&exchange, &model, &decoded_body)
    } else {
        parse_non_streaming_response(&exchange, &model, &decoded_body)
    }
    .or_else(|| try_parse_error_response(&exchange, &model, &decoded_body))
}

/// Extract model name from URL path.
/// Works for both Google AI (`/v1beta/models/{model}:generateContent`)
/// and Vertex AI (`/v1/projects/.../models/{model}:generateContent`).
fn extract_model_from_path(path: &str) -> Option<String> {
    // Strip query params
    let path = path.split('?').next().unwrap_or(path);

    // Find a segment ending with :generateContent or :streamGenerateContent
    for segment in path.split('/') {
        if let Some(model) = segment
            .strip_suffix(":generateContent")
            .or_else(|| segment.strip_suffix(":streamGenerateContent"))
        {
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }
    }
    None
}

fn parse_non_streaming_response(
    exchange: &HttpExchange,
    url_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let json: Value = serde_json::from_slice(decoded_body).ok()?;

    let id = json
        .get("responseId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("gemini-{}", exchange.request.timestamp_ns));

    let model = json
        .get("modelVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(url_model)
        .to_string();

    let usage = json.get("usageMetadata")?;
    let input_tokens = usage
        .get("promptTokenCount")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let output_tokens = usage
        .get("candidatesTokenCount")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let cache_read = usage
        .get("cachedContentTokenCount")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let cache_creation = usage
        .get("cacheTokensCreated")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // Need at least one token count
    if input_tokens.is_none() && output_tokens.is_none() {
        return None;
    }

    let stop_reason = json
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("finishReason"))
        .and_then(|v| v.as_str())
        .map(map_finish_reason)
        .unwrap_or_else(|| "unknown".to_string());

    let tools = collect_tool_names(json.get("candidates"));

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::from_exchange(
            exchange,
            id,
            "google",
            model,
            input_tokens,
            output_tokens,
            cache_creation,
            cache_read,
            stop_reason,
            tools,
        ),
        detail,
    ))
}

fn parse_streaming_response(
    exchange: &HttpExchange,
    url_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let body_str = String::from_utf8_lossy(decoded_body);

    let mut id = String::new();
    let mut model = url_model.to_string();
    let mut stop_reason = String::from("unknown");
    let mut tools: Vec<String> = Vec::new();
    let mut input_tokens: Option<u32> = None;
    let mut output_tokens: Option<u32> = None;
    let mut cache_read: Option<u32> = None;
    let mut cache_creation: Option<u32> = None;
    let mut found_data = false;

    for line in body_str.lines() {
        let data = if let Some(d) = line.strip_prefix("data: ") {
            d.trim()
        } else if let Some(d) = line.strip_prefix("data:") {
            d.trim()
        } else {
            continue;
        };

        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        found_data = true;

        // responseId from any chunk
        if id.is_empty() {
            if let Some(v) = json.get("responseId").and_then(|v| v.as_str()) {
                id = v.to_string();
            }
        }

        // modelVersion from any chunk
        if let Some(v) = json.get("modelVersion").and_then(|v| v.as_str()) {
            model = v.to_string();
        }

        // finishReason from candidates
        if let Some(candidates) = json.get("candidates").and_then(|v| v.as_array()) {
            if let Some(candidate) = candidates.first() {
                if let Some(reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
                    stop_reason = map_finish_reason(reason);
                }
            }
        }

        // Tool names from candidates
        for name in collect_tool_names(json.get("candidates")) {
            if !tools.contains(&name) {
                tools.push(name);
            }
        }

        // usageMetadata — take from last chunk that has it
        if let Some(usage) = json.get("usageMetadata") {
            if let Some(v) = usage.get("promptTokenCount").and_then(|v| v.as_u64()) {
                input_tokens = Some(v as u32);
            }
            if let Some(v) = usage.get("candidatesTokenCount").and_then(|v| v.as_u64()) {
                output_tokens = Some(v as u32);
            }
            if let Some(v) = usage
                .get("cachedContentTokenCount")
                .and_then(|v| v.as_u64())
            {
                cache_read = Some(v as u32);
            }
            if let Some(v) = usage.get("cacheTokensCreated").and_then(|v| v.as_u64()) {
                cache_creation = Some(v as u32);
            }
        }
    }

    if !found_data {
        return None;
    }

    if id.is_empty() {
        id = format!("gemini-{}", exchange.request.timestamp_ns);
    }

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::from_exchange(
            exchange,
            id,
            "google",
            model,
            input_tokens,
            output_tokens,
            cache_creation,
            cache_read,
            stop_reason,
            tools,
        ),
        detail,
    ))
}

/// Try to parse a Gemini error response.
fn try_parse_error_response(
    exchange: &HttpExchange,
    url_model: &str,
    decoded_body: &[u8],
) -> Option<(LlmCall, HttpDetail)> {
    let json: Value = serde_json::from_slice(decoded_body).ok()?;

    let error = json.get("error")?;
    let status = error
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let stop_reason = format!("error:{}", status);

    let detail = super::build_http_detail(exchange, decoded_body);
    Some((
        LlmCall::error_from_exchange(exchange, "google", url_model.to_string(), stop_reason),
        detail,
    ))
}

/// Map Gemini finishReason to lowercase.
fn map_finish_reason(reason: &str) -> String {
    reason.to_lowercase()
}

/// Collect function call tool names from candidates[0].content.parts[].
fn collect_tool_names(candidates: Option<&Value>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(arr) = candidates.and_then(|v| v.as_array()) {
        if let Some(candidate) = arr.first() {
            if let Some(parts) = candidate
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(|p| p.as_array())
            {
                for part in parts {
                    if let Some(name) = part
                        .get("functionCall")
                        .and_then(|fc| fc.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        names.push(name.to_string());
                    }
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
    use crate::providers::test_helpers::{
        make_exchange as make_exchange_raw, make_streaming_exchange as make_streaming_exchange_raw,
    };

    fn make_exchange(req_body: &[u8], resp_body: &[u8]) -> HttpExchange {
        make_exchange_raw(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-flash:generateContent",
            req_body,
            resp_body,
        )
    }

    fn make_streaming_exchange(req_body: &[u8], sse_body: &[u8]) -> HttpExchange {
        make_streaming_exchange_raw(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
            req_body,
            sse_body,
        )
    }

    fn default_req_body() -> &'static [u8] {
        br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#
    }

    #[test]
    fn test_extract_model_google_ai() {
        let model = extract_model_from_path("/v1beta/models/gemini-2.5-flash:generateContent");
        assert_eq!(model.unwrap(), "gemini-2.5-flash");
    }

    #[test]
    fn test_extract_model_vertex_ai() {
        let model = extract_model_from_path(
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(model.unwrap(), "gemini-2.5-flash");
    }

    #[test]
    fn test_extract_model_with_query_params() {
        let model = extract_model_from_path(
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=abc123",
        );
        assert_eq!(model.unwrap(), "gemini-2.5-flash");
    }

    #[test]
    fn test_extract_model_stream_path() {
        let model =
            extract_model_from_path("/v1beta/models/gemini-2.0-flash:streamGenerateContent");
        assert_eq!(model.unwrap(), "gemini-2.0-flash");
    }

    #[test]
    fn test_extract_model_missing() {
        assert!(extract_model_from_path("/v1/some/other/path").is_none());
    }

    #[test]
    fn test_parse_non_streaming_response() {
        let resp = br#"{"candidates":[{"content":{"parts":[{"text":"Hello!"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},"modelVersion":"gemini-2.5-flash-preview-05-20","responseId":"resp_123"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_123");
        assert_eq!(call.provider, "google");
        assert_eq!(call.model, "gemini-2.5-flash-preview-05-20");
        assert_eq!(call.input_tokens, Some(10));
        assert_eq!(call.output_tokens, Some(5));
        assert_eq!(call.stop_reason, "stop");
        assert!(!call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_parse_streaming_response() {
        let sse = b"\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_stream_1\"}\n\
\n\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" there!\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":12,\"candidatesTokenCount\":8,\"totalTokenCount\":20},\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_stream_1\"}\n\
\n";
        let exchange = make_streaming_exchange(default_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_stream_1");
        assert_eq!(call.input_tokens, Some(12));
        assert_eq!(call.output_tokens, Some(8));
        assert_eq!(call.stop_reason, "stop");
        assert!(call.streaming);
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_non_streaming_tool_use() {
        let resp = br#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"location":"Tokyo"}}}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":50,"candidatesTokenCount":20,"totalTokenCount":70},"modelVersion":"gemini-2.5-flash-preview-05-20","responseId":"resp_tool_1"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
        assert_eq!(call.stop_reason, "stop");
    }

    #[test]
    fn test_streaming_tool_use() {
        let sse = b"\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"location\":\"Tokyo\"}}}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_tool_s\"}\n\
\n\
data: {\"candidates\":[{\"content\":{\"parts\":[],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":50,\"candidatesTokenCount\":20,\"totalTokenCount\":70},\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_tool_s\"}\n\
\n";
        let exchange = make_streaming_exchange(default_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.tools, vec!["get_weather"]);
        assert_eq!(call.stop_reason, "stop");
    }

    #[test]
    fn test_error_response() {
        let resp =
            br#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"API key not valid"}}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.provider, "google");
        assert_eq!(call.model, "gemini-2.5-flash");
        assert_eq!(call.stop_reason, "error:INVALID_ARGUMENT");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
    }

    #[test]
    fn test_error_response_streaming_fallback() {
        let resp = br#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Bad request"}}"#;
        let exchange = make_streaming_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.stop_reason, "error:INVALID_ARGUMENT");
        assert!(call.input_tokens.is_none());
    }

    #[test]
    fn test_cache_tokens() {
        let resp = br#"{"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":5,"totalTokenCount":105,"cachedContentTokenCount":80},"modelVersion":"gemini-2.5-flash-preview-05-20","responseId":"resp_cache"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.cache_read_input_tokens, Some(80));
        assert_eq!(call.cache_creation_input_tokens, None);
    }

    #[test]
    fn test_cache_creation_tokens() {
        let resp = br#"{"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":5,"totalTokenCount":105,"cachedContentTokenCount":80,"cacheTokensCreated":60},"modelVersion":"gemini-2.5-flash-preview-05-20","responseId":"resp_cc"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.cache_read_input_tokens, Some(80));
        assert_eq!(call.cache_creation_input_tokens, Some(60));
    }

    #[test]
    fn test_cache_creation_tokens_streaming() {
        let sse = b"\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hi\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":100,\"candidatesTokenCount\":5,\"totalTokenCount\":105,\"cachedContentTokenCount\":80,\"cacheTokensCreated\":60},\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_ccs\"}\n\
\n";
        let exchange = make_streaming_exchange(default_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.cache_read_input_tokens, Some(80));
        assert_eq!(call.cache_creation_input_tokens, Some(60));
    }

    #[test]
    fn test_invalid_json() {
        let exchange = make_exchange(default_req_body(), b"{not valid json!!!");
        assert!(parse_call_only(exchange).is_none());
    }

    #[test]
    fn test_model_version_override() {
        let resp = br#"{"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},"modelVersion":"gemini-2.5-flash-preview-05-20","responseId":"resp_mv"}"#;
        let exchange = make_exchange(default_req_body(), resp);
        let call = parse_call_only(exchange).unwrap();
        // modelVersion from response takes precedence over URL model
        assert_eq!(call.model, "gemini-2.5-flash-preview-05-20");
    }

    #[test]
    fn test_streaming_no_usage() {
        let sse = b"\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hi\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"modelVersion\":\"gemini-2.5-flash-preview-05-20\",\"responseId\":\"resp_no_u\"}\n\
\n";
        let exchange = make_streaming_exchange(default_req_body(), sse);
        let call = parse_call_only(exchange).unwrap();
        assert_eq!(call.id, "resp_no_u");
        assert!(call.input_tokens.is_none());
        assert!(call.output_tokens.is_none());
    }
}
