use serde_json::Value;

use crate::reassembly::HttpExchange;

use super::{HttpDetail, LlmCall};

/// Parse an HTTP exchange into an LlmCall + HttpDetail (MCP JSON-RPC format).
pub fn parse_exchange(exchange: HttpExchange) -> Option<(LlmCall, HttpDetail)> {
    let req_json: Value = serde_json::from_slice(&exchange.request.body).ok()?;
    let method = req_json.get("method")?.as_str()?.to_string();

    let tools = if method == "tools/call" {
        req_json
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(|n| vec![n.to_string()])
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Notifications have no "id" field — fire-and-forget
    if req_json.get("id").is_none() {
        let decoded_body = super::decode_body(&exchange.response.body, &exchange.response.headers);
        let detail = super::build_http_detail(&exchange, &decoded_body);
        return Some((
            LlmCall {
                id: format!("notif-{}-{}", method, exchange.request.timestamp_ns),
                provider: "mcp",
                model: method,
                input_tokens: None,
                output_tokens: None,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                stop_reason: "notification".to_string(),
                tools,
                streaming: false,
                request_timestamp_ns: exchange.request.timestamp_ns,
                first_response_byte_ns: None,
                response_complete_ns: exchange.request.timestamp_ns,
                host: exchange.request.host.clone(),
                request_bytes: exchange.request.body.len() as u32,
                response_bytes: exchange.response.body.len() as u32,
            },
            detail,
        ));
    }

    let jsonrpc_id = match req_json.get("id").unwrap() {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };

    let decoded_body = super::decode_body(&exchange.response.body, &exchange.response.headers);
    let resp_json: Value = serde_json::from_slice(&decoded_body).ok()?;

    let stop_reason = if resp_json.get("error").is_some() {
        "error".to_string()
    } else if resp_json.get("result").is_some() {
        "ok".to_string()
    } else {
        return None; // neither result nor error = not a valid JSON-RPC response
    };

    let model = super::mcp_model_name(method, &tools);

    let detail = super::build_http_detail(&exchange, &decoded_body);
    Some((
        LlmCall::from_exchange(
            &exchange,
            jsonrpc_id,
            "mcp",
            model,
            None,
            None,
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
    use crate::providers::test_helpers;
    use crate::reassembly::HttpExchange;

    fn make_mcp_exchange(req_body: &[u8], resp_body: &[u8]) -> HttpExchange {
        test_helpers::make_exchange("localhost:3000", "/mcp", req_body, resp_body)
    }

    #[test]
    fn test_tools_call() {
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}"#;
        let resp = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents here"}]}}"#;
        let call = parse_call_only(make_mcp_exchange(req, resp)).unwrap();
        assert_eq!(call.provider, "mcp");
        assert_eq!(call.model, "read_file");
        assert_eq!(call.tools, vec!["read_file"]);
        assert_eq!(call.stop_reason, "ok");
        assert_eq!(call.id, "1");
        assert_eq!(call.input_tokens, None);
        assert_eq!(call.output_tokens, None);
    }

    #[test]
    fn test_tools_list() {
        let req = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file","description":"Read a file"}]}}"#;
        let call = parse_call_only(make_mcp_exchange(req, resp)).unwrap();
        assert_eq!(call.model, "tools/list");
        assert!(call.tools.is_empty());
        assert_eq!(call.stop_reason, "ok");
    }

    #[test]
    fn test_error_response() {
        let req = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bad_tool","arguments":{}}}"#;
        let resp =
            br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}"#;
        let call = parse_call_only(make_mcp_exchange(req, resp)).unwrap();
        assert_eq!(call.stop_reason, "error");
        assert_eq!(call.tools, vec!["bad_tool"]);
    }

    #[test]
    fn test_resources_read() {
        let req = br#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///tmp/test.txt"}}"#;
        let resp = br#"{"jsonrpc":"2.0","id":4,"result":{"contents":[{"uri":"file:///tmp/test.txt","text":"hello"}]}}"#;
        let call = parse_call_only(make_mcp_exchange(req, resp)).unwrap();
        assert_eq!(call.model, "resources/read");
        assert!(call.tools.is_empty());
    }

    #[test]
    fn test_notification_emitted() {
        // Notifications have no "id" field
        let req = br#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tok","progress":50,"total":100}}"#;
        let resp = br#"{"jsonrpc":"2.0","result":{}}"#;
        let call = parse_call_only(make_mcp_exchange(req, resp)).unwrap();
        assert_eq!(call.provider, "mcp");
        assert_eq!(call.model, "notifications/progress");
        assert_eq!(call.stop_reason, "notification");
        assert!(call.input_tokens.is_none());
        assert!(call.first_response_byte_ns.is_none());
        assert!(call.id.starts_with("notif-notifications/progress-"));
    }

    #[test]
    fn test_invalid_json() {
        assert!(parse_call_only(make_mcp_exchange(b"not json", b"{}")).is_none());
    }

    #[test]
    fn test_missing_method() {
        let req = br#"{"jsonrpc":"2.0","id":1}"#;
        let resp = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert!(parse_call_only(make_mcp_exchange(req, resp)).is_none());
    }

    #[test]
    fn test_response_missing_result_and_error() {
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let resp = br#"{"jsonrpc":"2.0","id":1}"#;
        assert!(parse_call_only(make_mcp_exchange(req, resp)).is_none());
    }
}
