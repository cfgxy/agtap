use bytes::BytesMut;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::pipe::{PipeDiscovery, PipeMapping};
use crate::providers::{HttpDetail, LlmCall};

const MAX_BUF_SIZE: usize = 1024 * 1024; // 1MB
const MAX_ORPHAN_BUFFER_SIZE: usize = 500;
const ORPHAN_TIMEOUT_SECS: u64 = 5;

struct PendingRequest {
    method: String,
    tools: Vec<String>,
    req_json: String,
    timestamp_ns: u64,
}

struct StdioConnection {
    write_buf: BytesMut,
    read_buf: BytesMut,
    pending: HashMap<String, PendingRequest>,
    last_activity: Instant,
}

struct OrphanEvent {
    pid: u32,
    inode: u64,
    direction: u32,
    data: Vec<u8>,
    timestamp_ns: u64,
    created: Instant,
}

#[derive(Default)]
struct InodeTracker {
    /// inode -> (set of PIDs seen, first-seen timestamp)
    inode_pids: HashMap<u64, (HashSet<u32>, Instant)>,
    /// (parent, child) where parent < child -> conn_id
    pid_pair_conns: HashMap<(u32, u32), u32>,
}

impl InodeTracker {
    fn record(&mut self, pid: u32, inode: u64) {
        let entry = self
            .inode_pids
            .entry(inode)
            .or_insert_with(|| (HashSet::new(), Instant::now()));
        entry.0.insert(pid);
        entry.1 = Instant::now(); // refresh so late-arriving second PID doesn't expire
    }

    /// If two different PIDs have been seen on this inode, return (lower, higher).
    fn find_pair(&self, inode: u64) -> Option<(u32, u32)> {
        let (pids, _) = self.inode_pids.get(&inode)?;
        if pids.len() < 2 {
            return None;
        }
        let min = *pids.iter().min().unwrap();
        let max = *pids.iter().max().unwrap();
        Some((min, max))
    }

    fn cleanup(&mut self, timeout_secs: u64) {
        let now = Instant::now();
        self.inode_pids
            .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < timeout_secs);
        self.pid_pair_conns.retain(|&(a, b), _| {
            std::fs::metadata(format!("/proc/{}", a)).is_ok()
                || std::fs::metadata(format!("/proc/{}", b)).is_ok()
        });
    }
}

#[derive(Default)]
pub struct StdioReassembler {
    connections: HashMap<u32, StdioConnection>, // keyed by connection_id
    pipe_discovery: PipeDiscovery,
    orphan_buffer: Vec<OrphanEvent>,
    inode_tracker: InodeTracker,
    pub pipe_events_received: u64,
    pub pipe_events_matched: u64,
    pub pipe_events_dropped: u64,
    pub pipe_events_deferred: u64,
}

const PIPE_FLAG: u32 = 0x80000000;

impl StdioReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_pipe_event(direction: u32) -> bool {
        direction & PIPE_FLAG != 0
    }

    pub fn process_event(
        &mut self,
        pid: u32,
        inode: u64,
        direction: u32,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Vec<(LlmCall, HttpDetail)> {
        self.pipe_events_received += 1;

        // Fast path: mapping already known (from /proc scan or previous deferred match)
        if let Some(mapping) = self.pipe_discovery.lookup(pid, inode) {
            self.pipe_events_matched += 1;
            return self.route_to_connection(mapping, data, direction, timestamp_ns);
        }

        // Deferred matching: /proc scan failed, try inode-based pairing
        // Check capacity before recording — don't track PIDs for events we'd drop
        if self.orphan_buffer.len() >= MAX_ORPHAN_BUFFER_SIZE {
            self.pipe_events_dropped += 1;
            return vec![];
        }

        self.inode_tracker.record(pid, inode);

        if let Some((parent, child)) = self.inode_tracker.find_pair(inode) {
            self.establish_deferred_mapping(parent, child, inode);
            let mut results = self.replay_orphans();
            // Route current event through the newly established mapping
            if let Some(m) = self.pipe_discovery.inode_map.get(&(pid, inode)).copied() {
                self.pipe_events_matched += 1;
                results.extend(self.route_to_connection(m, data, direction, timestamp_ns));
            }
            return results;
        }

        // No pair yet — buffer as orphan
        self.orphan_buffer.push(OrphanEvent {
            pid,
            inode,
            direction,
            data: data.to_vec(),
            timestamp_ns,
            created: Instant::now(),
        });
        self.pipe_events_deferred += 1;
        vec![]
    }

    /// Route data through an established pipe mapping to the appropriate connection buffer.
    fn route_to_connection(
        &mut self,
        mapping: PipeMapping,
        data: &[u8],
        direction: u32,
        timestamp_ns: u64,
    ) -> Vec<(LlmCall, HttpDetail)> {
        let mut actual_dir = direction & 1;
        if mapping.swap_dir {
            actual_dir ^= 1;
        }

        let conn = self
            .connections
            .entry(mapping.conn_id)
            .or_insert_with(|| StdioConnection {
                write_buf: BytesMut::with_capacity(4096),
                read_buf: BytesMut::with_capacity(4096),
                pending: HashMap::new(),
                last_activity: Instant::now(),
            });
        conn.last_activity = Instant::now();

        if actual_dir == 0 {
            // Write (request) data
            conn.write_buf.extend_from_slice(data);
            if conn.write_buf.len() > MAX_BUF_SIZE {
                conn.write_buf.clear();
                return vec![];
            }
            Self::parse_requests(conn, timestamp_ns)
        } else {
            // Read (response) data
            conn.read_buf.extend_from_slice(data);
            if conn.read_buf.len() > MAX_BUF_SIZE {
                conn.read_buf.clear();
                return vec![];
            }
            Self::match_responses(conn, timestamp_ns)
        }
    }

    /// Establish pipe mappings for a PID pair discovered via inode sharing.
    /// Lower PID = parent (swap_dir=false), higher PID = child (swap_dir=true).
    fn establish_deferred_mapping(&mut self, parent: u32, child: u32, inode: u64) {
        let conn_id = self
            .inode_tracker
            .pid_pair_conns
            .get(&(parent, child))
            .copied()
            .unwrap_or_else(|| {
                let id = self.pipe_discovery.alloc_conn_id();
                self.inode_tracker
                    .pid_pair_conns
                    .insert((parent, child), id);
                id
            });

        self.pipe_discovery
            .inode_map
            .entry((parent, inode))
            .or_insert(PipeMapping {
                conn_id,
                swap_dir: false,
            });
        self.pipe_discovery
            .inode_map
            .entry((child, inode))
            .or_insert(PipeMapping {
                conn_id,
                swap_dir: true,
            });
    }

    /// Replay buffered orphan events that now have valid pipe mappings.
    fn replay_orphans(&mut self) -> Vec<(LlmCall, HttpDetail)> {
        let orphans = std::mem::take(&mut self.orphan_buffer);
        let mut results = Vec::new();
        let mut remaining = Vec::new();

        for orphan in orphans {
            if let Some(m) = self
                .pipe_discovery
                .inode_map
                .get(&(orphan.pid, orphan.inode))
                .copied()
            {
                self.pipe_events_matched += 1;
                results.extend(self.route_to_connection(
                    m,
                    &orphan.data,
                    orphan.direction,
                    orphan.timestamp_ns,
                ));
            } else {
                remaining.push(orphan);
            }
        }

        self.orphan_buffer = remaining;
        results
    }

    /// Extract complete JSON lines from write_buf, store as pending requests.
    /// Returns any notification events (JSON-RPC messages without an `id`).
    fn parse_requests(conn: &mut StdioConnection, timestamp_ns: u64) -> Vec<(LlmCall, HttpDetail)> {
        let mut results = Vec::new();
        while let Some(pos) = conn.write_buf.iter().position(|&b| b == b'\n') {
            let line = conn.write_buf.split_to(pos + 1);
            let line = &line[..line.len() - 1]; // trim newline
            if line.is_empty() {
                continue;
            }

            let Ok(json) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            let Some(method) = json.get("method") else {
                continue;
            };
            let method_str = method.as_str().unwrap_or("").to_string();

            let Some(id) = json.get("id") else {
                // Notification: no id, fire-and-forget
                let req_json = String::from_utf8_lossy(line).into_owned();
                let req_bytes = line.len() as u32;
                results.push((
                    LlmCall {
                        id: format!("notif-{}-{}", method_str, timestamp_ns),
                        provider: "mcp",
                        model: method_str,
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                        stop_reason: "notification".to_string(),
                        tools: vec![],
                        streaming: false,
                        request_timestamp_ns: timestamp_ns,
                        first_response_byte_ns: None,
                        response_complete_ns: timestamp_ns,
                        host: "pipe".to_string(),
                        request_bytes: req_bytes,
                        response_bytes: 0,
                    },
                    HttpDetail {
                        request_method: "STDIO".to_string(),
                        request_path: String::new(),
                        request_host: "pipe".to_string(),
                        request_headers: vec![],
                        request_body: req_json,
                        response_status: 0,
                        response_headers: vec![],
                        response_body: String::new(),
                    },
                ));
                continue;
            };

            let id_str = match id {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            let tools = if method_str == "tools/call" {
                json.get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|n| vec![n.to_string()])
                    .unwrap_or_default()
            } else {
                vec![]
            };

            conn.pending.insert(
                id_str,
                PendingRequest {
                    method: method_str,
                    tools,
                    req_json: String::from_utf8_lossy(line).into_owned(),
                    timestamp_ns,
                },
            );
        }
        results
    }

    /// Extract complete JSON lines from read_buf, match against pending requests.
    fn match_responses(
        conn: &mut StdioConnection,
        timestamp_ns: u64,
    ) -> Vec<(LlmCall, HttpDetail)> {
        let mut results = Vec::new();
        while let Some(pos) = conn.read_buf.iter().position(|&b| b == b'\n') {
            let line = conn.read_buf.split_to(pos + 1);
            let line_bytes = &line[..line.len() - 1];
            if line_bytes.is_empty() {
                continue;
            }

            let Ok(resp_json) = serde_json::from_slice::<Value>(line_bytes) else {
                continue;
            };
            let Some(id) = resp_json.get("id") else {
                continue;
            };

            let id_str = match id {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            let Some(req) = conn.pending.remove(&id_str) else {
                continue;
            };

            let stop_reason = if resp_json.get("error").is_some() {
                "error"
            } else if resp_json.get("result").is_some() {
                "ok"
            } else {
                continue; // not a valid JSON-RPC response
            };

            let resp_str = String::from_utf8_lossy(line_bytes);

            let model = crate::providers::mcp_model_name(req.method, &req.tools);

            results.push((
                LlmCall {
                    id: id_str,
                    provider: "mcp",
                    model,
                    input_tokens: None,
                    output_tokens: None,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                    stop_reason: stop_reason.to_string(),
                    tools: req.tools,
                    streaming: false,
                    request_timestamp_ns: req.timestamp_ns,
                    first_response_byte_ns: Some(timestamp_ns),
                    response_complete_ns: timestamp_ns,
                    host: "pipe".to_string(),
                    request_bytes: req.req_json.len() as u32,
                    response_bytes: line_bytes.len() as u32,
                },
                HttpDetail {
                    request_method: "STDIO".to_string(),
                    request_path: String::new(),
                    request_host: "pipe".to_string(),
                    request_headers: vec![],
                    request_body: req.req_json,
                    response_status: if stop_reason == "ok" { 200 } else { 500 },
                    response_headers: vec![],
                    response_body: resp_str.into_owned(),
                },
            ));
        }
        results
    }

    /// Check if `pid` is a descendant of `ancestor`, using the parent cache.
    pub fn is_descendant_cached(&mut self, pid: u32, ancestor: u32) -> bool {
        self.pipe_discovery.is_descendant_cached(pid, ancestor)
    }

    /// Look up parent PID via cache (avoids repeated /proc reads).
    pub fn cached_parent(&mut self, pid: u32) -> Option<u32> {
        self.pipe_discovery.cached_parent(pid)
    }

    pub fn cleanup_idle(&mut self, max_idle_secs: u64) {
        let now = Instant::now();
        self.connections
            .retain(|_, conn| now.duration_since(conn.last_activity).as_secs() < max_idle_secs);

        // Expire stale orphans
        let before = self.orphan_buffer.len();
        self.orphan_buffer
            .retain(|o| now.duration_since(o.created).as_secs() < ORPHAN_TIMEOUT_SECS);
        let expired = before - self.orphan_buffer.len();
        self.pipe_events_dropped += expired as u64;

        self.inode_tracker.cleanup(ORPHAN_TIMEOUT_SECS);
        self.pipe_discovery.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::PipeMapping;

    /// Helper: create a StdioReassembler with a pre-registered pipe mapping
    /// so we don't need real /proc scanning in tests.
    fn make_test_reassembler() -> StdioReassembler {
        let mut r = StdioReassembler::new();
        // Manually inject a mapping: pid=100, inode=999 -> conn_id=0 (parent side)
        r.pipe_discovery.inode_map.insert(
            (100, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        // Also map a second inode for the read side
        r.pipe_discovery.inode_map.insert(
            (100, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        r
    }

    #[test]
    fn test_simple_request_response() {
        let mut r = make_test_reassembler();
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}"#;
        let resp =
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}"#;

        // Write request (direction=0, pipe flag set)
        let mut req_nl = req.to_vec();
        req_nl.push(b'\n');
        let results = r.process_event(100, 999, PIPE_FLAG | 0, &req_nl, 1000);
        assert!(results.is_empty()); // requests don't produce output

        // Read response (direction=1, pipe flag set)
        let mut resp_nl = resp.to_vec();
        resp_nl.push(b'\n');
        let results = r.process_event(100, 998, PIPE_FLAG | 1, &resp_nl, 2000);
        assert_eq!(results.len(), 1);

        let (call, detail) = &results[0];
        assert_eq!(call.provider, "mcp");
        assert_eq!(call.model, "read_file");
        assert_eq!(call.tools, vec!["read_file"]);
        assert_eq!(call.stop_reason, "ok");
        assert_eq!(call.id, "1");
        assert_eq!(call.request_timestamp_ns, 1000);
        assert_eq!(call.response_complete_ns, 2000);
        assert_eq!(call.host, "pipe");
        assert_eq!(detail.request_method, "STDIO");
        assert_eq!(detail.request_host, "pipe");
        assert_eq!(detail.response_status, 200);
    }

    #[test]
    fn test_fragmented_lines() {
        let mut r = make_test_reassembler();
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;

        // Send first half
        let results = r.process_event(100, 999, PIPE_FLAG | 0, &req[..30], 1000);
        assert!(results.is_empty());

        // Send second half + newline
        let mut rest = req[30..].to_vec();
        rest.push(b'\n');
        let results = r.process_event(100, 999, PIPE_FLAG | 0, &rest, 1001);
        assert!(results.is_empty()); // still no output (just a request)

        // Now send response
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "tools/list");
    }

    #[test]
    fn test_multiple_pending() {
        let mut r = make_test_reassembler();

        // Send two requests
        let req1 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let req2 = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"foo\",\"arguments\":{}}}\n";
        r.process_event(100, 999, PIPE_FLAG | 0, req1, 1000);
        r.process_event(100, 999, PIPE_FLAG | 0, req2, 1001);

        // Respond to id=2 first (out of order)
        let resp2 = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\n";
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp2, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.id, "2");
        assert_eq!(results[0].0.model, "foo");

        // Respond to id=1
        let resp1 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp1, 2001);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.id, "1");
    }

    #[test]
    fn test_notification_emitted() {
        let mut r = make_test_reassembler();
        // Notification: no "id" field
        let notif = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n";
        let results = r.process_event(100, 999, PIPE_FLAG | 0, notif, 1000);
        assert_eq!(results.len(), 1);
        let (call, detail) = &results[0];
        assert_eq!(call.provider, "mcp");
        assert_eq!(call.model, "notifications/progress");
        assert_eq!(call.stop_reason, "notification");
        assert!(call.input_tokens.is_none());
        assert!(call.first_response_byte_ns.is_none());
        assert_eq!(call.host, "pipe");
        assert!(call.id.starts_with("notif-notifications/progress-"));
        assert_eq!(detail.request_method, "STDIO");
        assert!(detail.response_body.is_empty());
    }

    #[test]
    fn test_buffer_overflow_discarded() {
        let mut r = make_test_reassembler();
        // Send > 1MB without a newline
        let big = vec![b'{'; MAX_BUF_SIZE + 1];
        let results = r.process_event(100, 999, PIPE_FLAG | 0, &big, 1000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_cleanup_idle() {
        let mut r = make_test_reassembler();
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        r.process_event(100, 999, PIPE_FLAG | 0, req, 1000);
        assert!(!r.connections.is_empty());

        // cleanup with 0 second timeout should remove everything
        r.cleanup_idle(0);
        assert!(r.connections.is_empty());
    }

    #[test]
    fn test_error_response() {
        let mut r = make_test_reassembler();
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"bad\",\"arguments\":{}}}\n";
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Not found\"}}\n";

        r.process_event(100, 999, PIPE_FLAG | 0, req, 1000);
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.stop_reason, "error");
        assert_eq!(results[0].1.response_status, 500);
    }

    #[test]
    fn test_is_pipe_event() {
        assert!(StdioReassembler::is_pipe_event(PIPE_FLAG | 0));
        assert!(StdioReassembler::is_pipe_event(PIPE_FLAG | 1));
        assert!(!StdioReassembler::is_pipe_event(0));
        assert!(!StdioReassembler::is_pipe_event(1));
    }

    #[test]
    fn test_child_events_with_swap() {
        let mut r = StdioReassembler::new();
        // Parent pid=100, child pid=200, same conn_id=0
        // Parent side: write=request, read=response (swap_dir=false)
        r.pipe_discovery.inode_map.insert(
            (100, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (100, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        // Child side: directions inverted (swap_dir=true)
        r.pipe_discovery.inode_map.insert(
            (200, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (200, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );

        // Parent writes request on inode 999 (dir=0, no swap → request)
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let results = r.process_event(100, 999, PIPE_FLAG | 0, req, 1000);
        assert!(results.is_empty());

        // Child reads response and writes it on inode 998 (dir=0 from child, swap → response)
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        // Child writes on inode 998: raw dir=0 (write), swap_dir=true → actual_dir=1 (response)
        let results = r.process_event(200, 998, PIPE_FLAG | 0, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "tools/list");
    }

    #[test]
    fn test_child_only_events() {
        // Simulates writev bypass: parent writes are missed, only child reads captured
        let mut r = StdioReassembler::new();
        // Only child-side mappings (pid=200), swap_dir=true
        r.pipe_discovery.inode_map.insert(
            (200, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (200, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );

        // Child reads request from stdin (inode 999): raw dir=1 (read), swap → actual_dir=0 (request)
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get\",\"arguments\":{}}}\n";
        let results = r.process_event(200, 999, PIPE_FLAG | 1, req, 1000);
        assert!(results.is_empty());

        // Child writes response to stdout (inode 998): raw dir=0 (write), swap → actual_dir=1 (response)
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n";
        let results = r.process_event(200, 998, PIPE_FLAG | 0, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "get");
        assert_eq!(results[0].0.tools, vec!["get"]);
    }

    #[test]
    fn test_both_parent_and_child_events() {
        // Both parent and child events share the same pending map via conn_id
        let mut r = StdioReassembler::new();
        r.pipe_discovery.inode_map.insert(
            (100, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (100, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (200, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (200, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: true,
            },
        );

        // Parent sends request (pid=100, dir=0)
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        r.process_event(100, 999, PIPE_FLAG | 0, req, 1000);

        // Child also captures the same request via read (pid=200, dir=1, swap → 0)
        // This overwrites the pending entry — harmless
        r.process_event(200, 999, PIPE_FLAG | 1, req, 1001);

        // Child sends response (pid=200, dir=0, swap → 1)
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        let results = r.process_event(200, 998, PIPE_FLAG | 0, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "tools/list");

        // Parent also captures the same response via read (pid=100, dir=1, no swap)
        // First match already removed the pending entry — this finds nothing, silently skipped
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp, 2001);
        assert!(results.is_empty());

        // Verify counters
        assert_eq!(r.pipe_events_received, 4);
        assert_eq!(r.pipe_events_matched, 4);
        assert_eq!(r.pipe_events_dropped, 0);
    }

    // ── Deferred matching tests ──────────────────────────────────────────

    #[test]
    fn test_deferred_matching() {
        let mut r = StdioReassembler::new();
        // No pre-injected mappings. PIDs 300/400 don't exist in /proc.
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";

        // PID 300 writes request on inode 5000 — buffered as orphan
        let results = r.process_event(300, 5000, PIPE_FLAG | 0, req, 1000);
        assert!(results.is_empty());
        assert_eq!(r.pipe_events_deferred, 1);

        // PID 400 writes response on inode 6000 — buffered as orphan
        let results = r.process_event(400, 6000, PIPE_FLAG | 0, resp, 2000);
        assert!(results.is_empty());
        assert_eq!(r.pipe_events_deferred, 2);

        // PID 400 reads on inode 5000 — pair (300, 400) found, mapping established
        // Orphan (300, 5000) replayed as request; orphan (400, 6000) stays (inode 6000 unmapped)
        let results = r.process_event(400, 5000, PIPE_FLAG | 1, req, 1001);
        assert!(results.is_empty()); // just requests
        assert_eq!(r.orphan_buffer.len(), 1); // (400, 6000) remains

        // PID 300 reads on inode 6000 — pair established, orphan (400, 6000) replayed as response
        let results = r.process_event(300, 6000, PIPE_FLAG | 1, resp, 2001);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "tools/list");
        assert_eq!(results[0].0.stop_reason, "ok");
        assert_eq!(r.orphan_buffer.len(), 0);
    }

    #[test]
    fn test_orphan_replay() {
        let mut r = StdioReassembler::new();

        // Buffer multiple request orphans from PID 300 on inode 5000
        let req1 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let req2 = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"foo\",\"arguments\":{}}}\n";

        r.process_event(300, 5000, PIPE_FLAG | 0, req1, 1000);
        r.process_event(300, 5000, PIPE_FLAG | 0, req2, 1001);
        assert_eq!(r.orphan_buffer.len(), 2);
        assert_eq!(r.pipe_events_deferred, 2);

        // PID 400 triggers pairing on inode 5000 — both orphans replayed as requests
        let results = r.process_event(400, 5000, PIPE_FLAG | 1, req1, 1002);
        assert!(results.is_empty()); // requests don't produce output
        assert_eq!(r.orphan_buffer.len(), 0);
        // 2 orphans replayed + 1 current event = 3 matched
        assert_eq!(r.pipe_events_matched, 3);
    }

    #[test]
    fn test_orphan_buffer_limit() {
        let mut r = StdioReassembler::new();
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"test\",\"params\":{}}\n";

        // Fill buffer with orphans — same PID 99999 (doesn't exist), different inodes
        for i in 0..MAX_ORPHAN_BUFFER_SIZE {
            r.process_event(99999, 9000 + i as u64, PIPE_FLAG | 0, data, i as u64);
        }
        assert_eq!(r.orphan_buffer.len(), MAX_ORPHAN_BUFFER_SIZE);
        assert_eq!(r.pipe_events_dropped, 0);

        // Next event exceeds limit — dropped
        r.process_event(99999, 99999, PIPE_FLAG | 0, data, 99999);
        assert_eq!(r.orphan_buffer.len(), MAX_ORPHAN_BUFFER_SIZE);
        assert_eq!(r.pipe_events_dropped, 1);
    }

    #[test]
    fn test_deferred_pid_pair_shares_conn_id() {
        let mut r = StdioReassembler::new();
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"test\",\"params\":{}}\n";

        // Establish pair on inode 5000
        r.process_event(300, 5000, PIPE_FLAG | 0, data, 1000);
        r.process_event(400, 5000, PIPE_FLAG | 0, data, 1001);

        // Establish same pair on inode 6000
        r.process_event(300, 6000, PIPE_FLAG | 0, data, 1002);
        r.process_event(400, 6000, PIPE_FLAG | 0, data, 1003);

        // Both inodes should share the same conn_id
        let m1 = r.pipe_discovery.inode_map.get(&(300, 5000)).unwrap();
        let m2 = r.pipe_discovery.inode_map.get(&(300, 6000)).unwrap();
        assert_eq!(m1.conn_id, m2.conn_id);
    }

    #[test]
    fn test_deferred_parent_child_direction() {
        let mut r = StdioReassembler::new();
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"test\",\"params\":{}}\n";

        // Trigger pair: PID 300 (parent, lower) and PID 400 (child, higher)
        r.process_event(300, 5000, PIPE_FLAG | 0, data, 1000);
        r.process_event(400, 5000, PIPE_FLAG | 0, data, 1001);

        let parent_mapping = r.pipe_discovery.inode_map.get(&(300, 5000)).unwrap();
        let child_mapping = r.pipe_discovery.inode_map.get(&(400, 5000)).unwrap();

        assert!(!parent_mapping.swap_dir); // lower PID = parent
        assert!(child_mapping.swap_dir); // higher PID = child
        assert_eq!(parent_mapping.conn_id, child_mapping.conn_id);
    }

    #[test]
    fn test_deferred_coexistence_with_preinjected() {
        let mut r = StdioReassembler::new();
        // Pre-inject mapping for PID 100 (simulating existing /proc path)
        r.pipe_discovery.inode_map.insert(
            (100, 999),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );
        r.pipe_discovery.inode_map.insert(
            (100, 998),
            PipeMapping {
                conn_id: 0,
                swap_dir: false,
            },
        );

        // Pre-injected path works as before
        let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let resp = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        r.process_event(100, 999, PIPE_FLAG | 0, req, 1000);
        let results = r.process_event(100, 998, PIPE_FLAG | 1, resp, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "tools/list");

        // Deferred path also works for different PIDs
        let req2 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\",\"params\":{}}\n";
        let resp2 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[]}}\n";
        r.process_event(300, 5000, PIPE_FLAG | 0, req2, 3000);
        r.process_event(400, 5000, PIPE_FLAG | 1, req2, 3001);
        r.process_event(400, 6000, PIPE_FLAG | 0, resp2, 4000);
        let results = r.process_event(300, 6000, PIPE_FLAG | 1, resp2, 4001);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.model, "resources/list");
    }
}
