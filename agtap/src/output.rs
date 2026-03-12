use serde::{Deserialize, Serialize};

use crate::providers::LlmCall;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    LlmCall,
    ToolUse,
    McpCall,
}

impl CallKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LlmCall => "llm_call",
            Self::ToolUse => "tool_use",
            Self::McpCall => "mcp_call",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct AgentEvent {
    pub ts: String,
    #[serde(skip)]
    pub wall_ns: u64,
    pub id: String,
    pub pid: u32,
    #[serde(rename = "proc")]
    pub process: String,
    pub provider: String,
    pub server_address: String,
    pub kind: CallKind,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u32>,
    pub latency_ms: u64,
    pub stop_reason: String,
    pub tools: Vec<String>,
    pub streaming: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u32>,
}

pub fn format_event(
    call: &LlmCall,
    pid: u32,
    proc_name: &str,
    boot_time_ns: u64,
    body_path: Option<String>,
) -> AgentEvent {
    let kind = if call.provider == "mcp" {
        CallKind::McpCall
    } else if call.tools.is_empty() {
        CallKind::LlmCall
    } else {
        CallKind::ToolUse
    };

    let latency_ms = call
        .response_complete_ns
        .saturating_sub(call.request_timestamp_ns)
        .div_ceil(1_000_000);

    let ttft_ms = call.first_response_byte_ns.map(|first| {
        first
            .saturating_sub(call.request_timestamp_ns)
            .div_ceil(1_000_000)
    });

    // Convert ktime_ns (monotonic) to wall clock
    let wall_ns = boot_time_ns + call.request_timestamp_ns;
    let ts = chrono::DateTime::from_timestamp_nanos(wall_ns as i64)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    AgentEvent {
        ts,
        wall_ns,
        id: call.id.clone(),
        pid,
        process: proc_name.to_string(),
        provider: call.provider.to_string(),
        server_address: call.host.clone(),
        kind,
        model: call.model.clone(),
        input_tokens: call.input_tokens,
        output_tokens: call.output_tokens,
        cache_creation_input_tokens: call.cache_creation_input_tokens,
        cache_read_input_tokens: call.cache_read_input_tokens,
        latency_ms,
        stop_reason: call.stop_reason.clone(),
        tools: call.tools.clone(),
        streaming: call.streaming,
        ttft_ms,
        body_path,
        request_bytes: Some(call.request_bytes),
        response_bytes: Some(call.response_bytes),
    }
}

pub fn print_event(event: &AgentEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        println!("{}", json);
    }
}

#[cfg(test)]
impl AgentEvent {
    pub fn test_default() -> Self {
        Self {
            ts: "2025-01-01T00:00:00.000Z".into(),
            wall_ns: 0,
            id: "msg_test".into(),
            pid: 1,
            process: "test".into(),
            provider: "anthropic".into(),
            server_address: "api.anthropic.com".into(),
            kind: CallKind::LlmCall,
            model: "claude-sonnet-4-20250514".into(),
            input_tokens: Some(1000),
            output_tokens: Some(200),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            latency_ms: 500,
            stop_reason: "end_turn".into(),
            tools: vec![],
            streaming: true,
            ttft_ms: Some(100),
            body_path: None,
            request_bytes: Some(256),
            response_bytes: Some(512),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::LlmCall;

    fn make_call(
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        tools: Vec<String>,
        request_ns: u64,
        first_resp_ns: Option<u64>,
        complete_ns: u64,
    ) -> LlmCall {
        LlmCall {
            id: "msg_test".into(),
            provider: "anthropic",
            model: "claude-haiku-4-5-20251001".into(),
            input_tokens,
            output_tokens,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            stop_reason: "end_turn".into(),
            tools,
            streaming: false,
            request_timestamp_ns: request_ns,
            first_response_byte_ns: first_resp_ns,
            response_complete_ns: complete_ns,
            host: "api.anthropic.com".into(),
            request_bytes: 256,
            response_bytes: 512,
        }
    }

    #[test]
    fn test_kind_llm_call() {
        let call = make_call(Some(10), Some(5), vec![], 1000, Some(1500), 2000);
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.kind, CallKind::LlmCall);
        assert!(event.tools.is_empty());
    }

    #[test]
    fn test_kind_tool_use() {
        let call = make_call(
            Some(10),
            Some(5),
            vec!["read_file".into()],
            1000,
            Some(1500),
            2000,
        );
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.kind, CallKind::ToolUse);
        assert_eq!(event.tools, vec!["read_file"]);
    }

    #[test]
    fn test_latency_ms() {
        let call = make_call(
            Some(10),
            Some(5),
            vec![],
            1_000_000_000,
            Some(1_500_000_000),
            2_000_000_000,
        );
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.latency_ms, 1000);
    }

    #[test]
    fn test_ttft_ms() {
        let call = make_call(
            Some(10),
            Some(5),
            vec![],
            1_000_000_000,
            Some(1_500_000_000),
            2_000_000_000,
        );
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.ttft_ms, Some(500));
    }

    #[test]
    fn test_reversed_timestamps() {
        let call = make_call(
            Some(10),
            Some(5),
            vec![],
            2_000_000_000,
            Some(500_000_000),
            1_000_000_000,
        );
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.latency_ms, 0);
        assert_eq!(event.ttft_ms, Some(0));
    }

    #[test]
    fn test_json_omits_none_cache() {
        let call = make_call(Some(10), Some(5), vec![], 1000, Some(1500), 2000);
        let event = format_event(&call, 123, "curl", 0, None);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("cache_creation_input_tokens"));
        assert!(!json.contains("cache_read_input_tokens"));
    }

    #[test]
    fn test_json_omits_none_tokens() {
        let call = make_call(None, None, vec![], 1000, Some(1500), 2000);
        let event = format_event(&call, 123, "curl", 0, None);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("input_tokens"));
        assert!(!json.contains("output_tokens"));
    }

    #[test]
    fn test_provider_passthrough() {
        let mut call = make_call(Some(10), Some(5), vec![], 1000, Some(1500), 2000);
        call.provider = "openai";
        call.host = "api.openai.com".into();
        let event = format_event(&call, 123, "curl", 0, None);
        assert_eq!(event.provider, "openai");
        assert_eq!(event.server_address, "api.openai.com");
    }

    #[test]
    fn test_golden_jsonl_snapshot() {
        let mut call = make_call(
            Some(100),
            Some(25),
            vec![],
            1_000_000_000,
            Some(1_500_000_000),
            2_000_000_000,
        );
        call.id = "msg_snapshot".into();
        call.model = "claude-haiku-4-5-20251001".into();
        call.stop_reason = "end_turn".into();

        // Use a fixed boot_time_ns for reproducibility
        let boot_time_ns: u64 = 1_700_000_000_000_000_000; // ~2023-11-14
        let event = format_event(&call, 42, "python3", boot_time_ns, None);
        insta::assert_json_snapshot!(event);
    }
}
