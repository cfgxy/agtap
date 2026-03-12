use std::collections::HashMap;
use std::fs;
use std::time::Instant;

/// Maximum number of parent levels to walk when scanning for pipe pairs.
/// Handles chains like `parent → sh → npx → node`.
pub const MAX_ANCESTOR_DEPTH: usize = 3;

#[derive(Clone, Copy)]
pub struct PipeMapping {
    pub conn_id: u32,
    /// true for child-side mappings (directions are inverted relative to parent)
    pub swap_dir: bool,
}

#[derive(Default)]
pub struct PipeDiscovery {
    /// (pid, inode) -> PipeMapping. Both parent and child sides registered.
    pub(crate) inode_map: HashMap<(u32, u64), PipeMapping>,
    /// PIDs we've scanned + when (rate limiting)
    scanned_pids: HashMap<u32, Instant>,
    next_conn_id: u32,
    /// Cache pid -> parent pid (None = no parent or PID 1)
    parent_cache: HashMap<u32, Option<u32>>,
}

impl PipeDiscovery {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate and return the next connection ID.
    pub(crate) fn alloc_conn_id(&mut self) -> u32 {
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        id
    }

    /// Look up mapping for a pipe event. Returns None if not a known MCP pipe.
    /// Triggers /proc scan on first event or unknown inode (rate-limited 1/sec/PID).
    pub fn lookup(&mut self, pid: u32, inode: u64) -> Option<PipeMapping> {
        if let Some(&mapping) = self.inode_map.get(&(pid, inode)) {
            return Some(mapping);
        }

        // Rate-limit: at most one scan per second per PID
        let needs_scan = match self.scanned_pids.get(&pid) {
            None => true,
            Some(t) => t.elapsed().as_secs() >= 1,
        };
        if !needs_scan {
            return None;
        }

        self.scan_pid_bidirectional(pid);
        self.scanned_pids.insert(pid, Instant::now());
        self.inode_map.get(&(pid, inode)).copied()
    }

    /// Scan both downward (children of pid) and upward (ancestors of pid).
    /// Walks up to MAX_ANCESTOR_DEPTH parent levels to handle deep process chains.
    fn scan_pid_bidirectional(&mut self, pid: u32) {
        self.scan_as_parent(pid);
        let mut current = pid;
        for _ in 0..MAX_ANCESTOR_DEPTH {
            match find_parent(current) {
                Some(ppid) if ppid > 1 => {
                    self.scan_as_parent(ppid);
                    current = ppid;
                }
                _ => break,
            }
        }
    }

    /// Treat `parent_pid` as the parent. Find its children and discover pipe pairs.
    /// Registers both parent-side and child-side mappings so events from either
    /// process are matched.
    fn scan_as_parent(&mut self, parent_pid: u32) {
        let parent_pipes = list_pipe_fds(parent_pid);
        if parent_pipes.is_empty() {
            return;
        }
        let children = find_children(parent_pid);

        for child_pid in &children {
            let child_pipes = list_pipe_fds(*child_pid);
            let mut write_inos: Vec<u64> = Vec::new(); // parent writes to child stdin
            let mut read_inos: Vec<u64> = Vec::new(); // parent reads from child stdout/stderr

            for &(pinode, _p_is_write) in &parent_pipes {
                for &(cinode, c_is_write) in &child_pipes {
                    if pinode == cinode {
                        // Child's direction determines classification:
                        // child reads (stdin) = parent's write channel (request)
                        // child writes (stdout) = parent's read channel (response)
                        // Works for both pipes (opposite flags) and inherited sockets (same flags).
                        if c_is_write {
                            read_inos.push(pinode);
                        } else {
                            write_inos.push(pinode);
                        }
                    }
                }
            }

            // Filter out inodes already registered for a previously scanned child
            // (e.g. inherited pipe FDs shared across multiple children).
            write_inos.retain(|ino| !self.inode_map.contains_key(&(parent_pid, *ino)));
            read_inos.retain(|ino| !self.inode_map.contains_key(&(parent_pid, *ino)));

            if write_inos.is_empty() || read_inos.is_empty() {
                continue;
            }

            let conn_id = self.alloc_conn_id();

            // Register all inodes under one conn_id
            for &ino in write_inos.iter().chain(read_inos.iter()) {
                self.inode_map.insert(
                    (parent_pid, ino),
                    PipeMapping {
                        conn_id,
                        swap_dir: false,
                    },
                );
                self.inode_map.insert(
                    (*child_pid, ino),
                    PipeMapping {
                        conn_id,
                        swap_dir: true,
                    },
                );
            }
        }
    }

    /// Look up parent PID, using cache to avoid repeated /proc reads.
    pub fn cached_parent(&mut self, pid: u32) -> Option<u32> {
        if let Some(&cached) = self.parent_cache.get(&pid) {
            return cached;
        }
        let result = find_parent(pid);
        self.parent_cache.insert(pid, result);
        result
    }

    /// Check if `pid` is a descendant of `ancestor`, using the parent cache.
    pub fn is_descendant_cached(&mut self, pid: u32, ancestor: u32) -> bool {
        let mut current = pid;
        for _ in 0..MAX_ANCESTOR_DEPTH {
            match self.cached_parent(current) {
                Some(ppid) if ppid > 1 => {
                    if ppid == ancestor {
                        return true;
                    }
                    current = ppid;
                }
                _ => break,
            }
        }
        false
    }

    /// Evict entries for PIDs that no longer exist.
    pub fn cleanup(&mut self) {
        self.inode_map
            .retain(|&(pid, _), _| fs::metadata(format!("/proc/{}", pid)).is_ok());
        self.scanned_pids
            .retain(|pid, _| fs::metadata(format!("/proc/{}", pid)).is_ok());
        self.parent_cache
            .retain(|pid, _| fs::metadata(format!("/proc/{}", pid)).is_ok());
    }
}

/// Parse inode from a /proc fd symlink like "pipe:[12345]" or "socket:[67890]".
fn parse_link_inode(link: &str, prefix: &str) -> Option<u64> {
    link.strip_prefix(prefix)
        .and_then(|s| s.strip_prefix(":["))
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
}

/// List pipe and socket FDs for a process. Returns Vec<(inode, is_write_end)>.
/// Gracefully skips FDs that disappear between listing and inspection (race-safe).
fn list_pipe_fds(pid: u32) -> Vec<(u64, bool)> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return vec![];
    };
    let mut result = Vec::new();

    for entry in entries.flatten() {
        let fd_name = entry.file_name();
        let fd_str = fd_name.to_string_lossy();
        let Ok(fd_num) = fd_str.parse::<u32>() else {
            continue;
        };

        // readlink -> "pipe:[<inode>]" or "socket:[<inode>]"
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        let link_str = link.to_string_lossy();

        if let Some(inode) = parse_link_inode(&link_str, "pipe") {
            // Read /proc/<pid>/fdinfo/<fd> for direction (flags field)
            let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd_num);
            let Ok(fdinfo) = fs::read_to_string(&fdinfo_path) else {
                continue; // FD gone, skip
            };
            let is_write = fdinfo
                .lines()
                .find(|l| l.starts_with("flags:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| u32::from_str_radix(s, 8).ok())
                .map(|flags| (flags & 0x3) == 1) // O_WRONLY
                .unwrap_or(false);

            result.push((inode, is_write));
        } else if fd_num <= 1 {
            if let Some(inode) = parse_link_inode(&link_str, "socket") {
                // Direction from fd number: fd 0 = read, fd 1 = write
                // (sockets are O_RDWR so fdinfo flags can't determine direction)
                let is_write = fd_num == 1;
                result.push((inode, is_write));
            }
        }
    }
    result
}

fn find_children(parent_pid: u32) -> Vec<u32> {
    // Fast path: /proc/<pid>/task/*/children (Linux 3.5+, CONFIG_PROC_CHILDREN)
    // Must iterate ALL threads — children are attributed to the thread that forked them.
    let task_dir = format!("/proc/{}/task", parent_pid);
    if let Ok(entries) = fs::read_dir(&task_dir) {
        let mut children = Vec::new();
        let mut any_readable = false;
        for entry in entries.flatten() {
            let tid = entry.file_name();
            let path = format!(
                "/proc/{}/task/{}/children",
                parent_pid,
                tid.to_string_lossy()
            );
            if let Ok(contents) = fs::read_to_string(&path) {
                any_readable = true;
                for s in contents.split_whitespace() {
                    if let Ok(pid) = s.parse::<u32>() {
                        children.push(pid);
                    }
                }
            }
        }
        if any_readable {
            children.sort_unstable();
            children.dedup();
            return children;
        }
    }

    // Fallback: scan all of /proc (older kernels without CONFIG_PROC_CHILDREN)
    let Ok(entries) = fs::read_dir("/proc") else {
        return vec![];
    };
    let mut children = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let status_path = format!("/proc/{}/status", pid);
        let Ok(status) = fs::read_to_string(&status_path) else {
            continue;
        };
        for line in status.lines() {
            if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
                if let Ok(ppid) = ppid_str.trim().parse::<u32>() {
                    if ppid == parent_pid {
                        children.push(pid);
                    }
                }
                break;
            }
        }
    }
    children
}

pub fn find_parent(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
            return ppid_str.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Read the comm (process name) for a PID from /proc.
pub fn comm_of(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim_end().to_string())
}

/// Read /proc/<pid>/cmdline and return it as a string (NUL bytes replaced with spaces).
fn cmdline_of(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    if raw.is_empty() {
        return None;
    }
    let s: String = raw
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    Some(s.trim_end().to_string())
}

/// Identify the framework/tool behind a process by inspecting its cmdline.
/// Returns a human-friendly label (e.g., "claude-code", "mcp:filesystem") or
/// falls back to `comm`.
pub fn identify_process(pid: u32, comm: &str) -> String {
    match cmdline_of(pid) {
        Some(ref c) if !c.is_empty() => identify_from_cmdline(c, comm),
        _ => comm.to_string(),
    }
}

/// Pure pattern-matching logic: given a cmdline string and a fallback comm,
/// return a human-friendly process label.
fn identify_from_cmdline(cmdline: &str, comm: &str) -> String {
    // Extract argv[0] basename for binary matching
    let argv0 = cmdline.split(' ').next().unwrap_or("");
    let basename = argv0.rsplit('/').next().unwrap_or(argv0);
    let basename_lower = basename.to_lowercase();

    // AI coding assistants — match argv[0] basename
    const BINARY_PATTERNS: &[(&str, &str)] = &[
        ("claude", "claude-code"),
        ("aider", "aider"),
        ("cursor", "cursor"),
        ("copilot", "copilot"),
        ("codex", "codex"),
        ("goose", "goose"),
        ("gemini", "gemini-cli"),
        ("cline", "cline"),
        ("openhands", "openhands"),
        ("openclaw", "openclaw"),
    ];

    for &(pattern, label) in BINARY_PATTERNS {
        if basename_lower.contains(pattern) {
            return label.to_string();
        }
    }

    // AI agent frameworks — match full cmdline
    let cmdline_lower = cmdline.to_lowercase();

    const FRAMEWORK_PATTERNS: &[(&[&str], &str)] = &[
        (&["langchain", "langgraph"], "langchain"),
        (&["autogen"], "autogen"),
        (&["crewai"], "crewai"),
        (&["llamaindex", "llama_index"], "llamaindex"),
        (&["pydantic-ai", "pydantic_ai"], "pydantic-ai"),
        (&["smolagents"], "smolagents"),
        (&["dspy"], "dspy"),
    ];

    for &(patterns, label) in FRAMEWORK_PATTERNS {
        for &p in patterns {
            if cmdline_lower.contains(p) {
                return label.to_string();
            }
        }
    }

    // MCP servers — dynamic catch-alls (most valuable)
    // @modelcontextprotocol/server-<name>
    if let Some(pos) = cmdline.find("@modelcontextprotocol/server-") {
        let after = &cmdline[pos + "@modelcontextprotocol/server-".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if !name.is_empty() {
            return format!("mcp:{}", name);
        }
    }

    // mcp-server-<name> or mcp_server_<name>
    for prefix in &["mcp-server-", "mcp_server_"] {
        if let Some(pos) = cmdline_lower.find(prefix) {
            let after = &cmdline[pos + prefix.len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !name.is_empty() {
                return format!("mcp:{}", name);
            }
        }
    }

    comm.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn test_identify_process_nonexistent_pid() {
        // Non-existent PID should fall back to comm
        let result = identify_process(999_999_999, "node");
        assert_eq!(result, "node");
    }

    #[test]
    fn test_identify_from_cmdline_coding_assistants() {
        assert_eq!(
            identify_from_cmdline("/usr/bin/claude --model opus", "node"),
            "claude-code"
        );
        assert_eq!(
            identify_from_cmdline("/home/user/.local/bin/aider --chat", "python3"),
            "aider"
        );
        assert_eq!(identify_from_cmdline("codex run", "node"), "codex");
        assert_eq!(
            identify_from_cmdline("/usr/bin/gemini chat", "node"),
            "gemini-cli"
        );
        assert_eq!(
            identify_from_cmdline("/usr/local/bin/openclaw-gateway serve", "node"),
            "openclaw"
        );
        assert_eq!(identify_from_cmdline("openclaw chat", "node"), "openclaw");
    }

    #[test]
    fn test_identify_from_cmdline_frameworks() {
        assert_eq!(
            identify_from_cmdline("python3 -m langchain serve", "python3"),
            "langchain"
        );
        assert_eq!(
            identify_from_cmdline("python3 /app/langgraph/main.py", "python3"),
            "langchain"
        );
        assert_eq!(
            identify_from_cmdline("python3 -m crewai run", "python3"),
            "crewai"
        );
        assert_eq!(
            identify_from_cmdline("python3 /venv/lib/autogen/app.py", "python3"),
            "autogen"
        );
        assert_eq!(
            identify_from_cmdline("python3 -m pydantic_ai.serve", "python3"),
            "pydantic-ai"
        );
        assert_eq!(
            identify_from_cmdline("python3 -m dspy.teleprompt", "python3"),
            "dspy"
        );
    }

    #[test]
    fn test_identify_from_cmdline_mcp_servers() {
        assert_eq!(
            identify_from_cmdline("node /usr/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /tmp", "node"),
            "mcp:filesystem"
        );
        assert_eq!(
            identify_from_cmdline("npx mcp-server-brave-search", "node"),
            "mcp:brave-search"
        );
        assert_eq!(
            identify_from_cmdline("python3 mcp_server_sqlite --db test.db", "python3"),
            "mcp:sqlite"
        );
    }

    #[test]
    fn test_identify_from_cmdline_fallback() {
        assert_eq!(identify_from_cmdline("node /app/server.js", "node"), "node");
        assert_eq!(
            identify_from_cmdline("python3 my_script.py", "python3"),
            "python3"
        );
    }

    #[test]
    fn test_find_parent_self() {
        let my_pid = std::process::id();
        let ppid = find_parent(my_pid);
        assert!(ppid.is_some());
        assert!(ppid.unwrap() > 0);
    }

    #[test]
    fn test_list_pipe_fds_self() {
        let my_pid = std::process::id();
        let pipes = list_pipe_fds(my_pid);
        // Our own process may or may not have pipe FDs, but the function shouldn't panic
        let _ = pipes;
    }

    #[test]
    fn test_find_children_init() {
        // PID 1 should have children on any running Linux system
        let children = find_children(1);
        assert!(!children.is_empty());
    }

    #[test]
    fn test_scan_as_parent_three_pipes() {
        use std::process::{Command, Stdio};

        let child = ChildGuard(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to spawn sleep"),
        );

        let child_pid = child.0.id();
        let parent_pid = std::process::id();

        let mut disc = PipeDiscovery::new();
        disc.scan_as_parent(parent_pid);

        // Collect all child-side inodes from the child's /proc/fd
        let child_pipe_inodes: Vec<u64> = list_pipe_fds(child_pid)
            .into_iter()
            .map(|(ino, _)| ino)
            .collect();

        // Child should have at least 3 pipe FDs (stdin, stdout, stderr);
        // may have more if the test runner leaks inherited pipe FDs.
        assert!(
            child_pipe_inodes.len() >= 3,
            "expected >= 3 child pipe FDs, got {:?}",
            child_pipe_inodes
        );

        // At least 3 child-side inodes (stdin/stdout/stderr) should be registered;
        // inherited FDs may not be shared with parent at scan time.
        let registered = child_pipe_inodes
            .iter()
            .filter(|ino| disc.inode_map.contains_key(&(child_pid, **ino)))
            .count();
        assert!(
            registered >= 3,
            "expected >= 3 child inodes in inode_map, got {}",
            registered
        );

        // 3+ child-side entries
        let child_entries = disc
            .inode_map
            .keys()
            .filter(|(pid, _)| *pid == child_pid)
            .count();
        assert!(
            child_entries >= 3,
            "expected >= 3 child-side entries, got {}",
            child_entries
        );

        // 3+ parent-side entries (may have more from other test children)
        let parent_entries = disc
            .inode_map
            .keys()
            .filter(|(pid, _)| *pid == parent_pid)
            .count();
        assert!(
            parent_entries >= 3,
            "expected >= 3 parent-side entries, got {}",
            parent_entries
        );

        // All child entries share one conn_id
        let conn_ids: std::collections::HashSet<u32> = disc
            .inode_map
            .iter()
            .filter(|(&(pid, _), _)| pid == child_pid)
            .map(|(_, m)| m.conn_id)
            .collect();
        assert_eq!(
            conn_ids.len(),
            1,
            "expected 1 conn_id for child, got {:?}",
            conn_ids
        );
    }

    #[test]
    fn test_scan_as_parent_socketpair() {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::process::{Command, Stdio};

        // Create two socketpairs: one for stdin, one for stdout
        let mut sv_in = [0i32; 2];
        let mut sv_out = [0i32; 2];
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv_in.as_mut_ptr()),
                0,
                "socketpair for stdin failed"
            );
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv_out.as_mut_ptr()),
                0,
                "socketpair for stdout failed"
            );
        }

        // sv_in[0] = parent end (writes requests), sv_in[1] = child stdin
        // sv_out[0] = parent end (reads responses), sv_out[1] = child stdout
        let child_stdin = unsafe { Stdio::from(OwnedFd::from_raw_fd(sv_in[1])) };
        let child_stdout = unsafe { Stdio::from(OwnedFd::from_raw_fd(sv_out[1])) };

        // Spawn sh -c "sleep 60" so both sh and sleep inherit socket FDs at fd 0/1
        let child = ChildGuard(
            Command::new("sh")
                .arg("-c")
                .arg("sleep 60; true")
                .stdin(child_stdin)
                .stdout(child_stdout)
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn sh"),
        );

        let sh_pid = child.0.id();

        // Wait briefly for sh to fork sleep
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Close parent's copies of child ends (sv_in[1], sv_out[1] consumed by Stdio)
        // Keep parent ends open so inodes remain visible
        // sv_in[0] and sv_out[0] are the parent ends

        let mut disc = PipeDiscovery::new();
        disc.scan_as_parent(sh_pid);

        // sh's children (sleep) should share socket inodes at fd 0/1
        let sh_children = find_children(sh_pid);
        assert!(
            !sh_children.is_empty(),
            "sh should have at least one child (sleep)"
        );

        let sleep_pid = sh_children[0];

        // Collect socket inodes from sleep's fd 0 and fd 1
        let sleep_fds = list_pipe_fds(sleep_pid);
        let socket_inodes: Vec<u64> = sleep_fds.iter().map(|(ino, _)| *ino).collect();

        assert!(
            socket_inodes.len() >= 2,
            "expected >= 2 socket FDs (stdin + stdout) on sleep, got {:?}",
            sleep_fds
        );

        // At least 2 socket inodes (stdin/stdout) should be registered;
        // inherited FDs may not be shared with parent at scan time.
        let registered = socket_inodes
            .iter()
            .filter(|ino| disc.inode_map.contains_key(&(sleep_pid, **ino)))
            .count();
        assert!(
            registered >= 2,
            "expected >= 2 socket inodes in inode_map, got {}",
            registered
        );

        // All entries for this child share one conn_id
        let conn_ids: std::collections::HashSet<u32> = disc
            .inode_map
            .iter()
            .filter(|(&(pid, _), _)| pid == sleep_pid)
            .map(|(_, m)| m.conn_id)
            .collect();
        assert_eq!(
            conn_ids.len(),
            1,
            "expected 1 conn_id for sleep, got {:?}",
            conn_ids
        );

        // Clean up parent socket ends
        unsafe {
            libc::close(sv_in[0]);
            libc::close(sv_out[0]);
        }
    }

    /// Regression test: two sibling children share inherited pipe FDs.
    /// Both children's unique pipes must be discovered (not just the first's).
    #[test]
    fn test_scan_as_parent_siblings_with_shared_pipes() {
        use std::process::{Command, Stdio};

        // Create a pipe that both children will inherit (simulates CI runner pipes).
        let mut shared_fds = [0i32; 2];
        unsafe {
            assert_eq!(libc::pipe(shared_fds.as_mut_ptr()), 0, "pipe() failed");
        }

        // Spawn two children; both inherit shared_fds (no CLOEXEC).
        // Each also gets its own unique stdin/stdout/stderr pipes.
        let child_a = ChildGuard(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to spawn child_a"),
        );
        let child_b = ChildGuard(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to spawn child_b"),
        );

        let pid_a = child_a.0.id();
        let pid_b = child_b.0.id();
        let parent_pid = std::process::id();

        let mut disc = PipeDiscovery::new();
        disc.scan_as_parent(parent_pid);

        // Both children should have their unique pipe inodes registered.
        let a_entries = disc
            .inode_map
            .keys()
            .filter(|(pid, _)| *pid == pid_a)
            .count();
        let b_entries = disc
            .inode_map
            .keys()
            .filter(|(pid, _)| *pid == pid_b)
            .count();

        assert!(
            a_entries >= 3,
            "child_a: expected >= 3 child-side entries, got {}",
            a_entries
        );
        assert!(
            b_entries >= 3,
            "child_b: expected >= 3 child-side entries, got {} \
             (second sibling skipped due to shared inherited FDs?)",
            b_entries
        );

        // Each child should have its own distinct conn_id.
        let conn_a: std::collections::HashSet<u32> = disc
            .inode_map
            .iter()
            .filter(|(&(pid, _), _)| pid == pid_a)
            .map(|(_, m)| m.conn_id)
            .collect();
        let conn_b: std::collections::HashSet<u32> = disc
            .inode_map
            .iter()
            .filter(|(&(pid, _), _)| pid == pid_b)
            .map(|(_, m)| m.conn_id)
            .collect();

        assert_eq!(
            conn_a.len(),
            1,
            "child_a should have 1 conn_id, got {:?}",
            conn_a
        );
        assert_eq!(
            conn_b.len(),
            1,
            "child_b should have 1 conn_id, got {:?}",
            conn_b
        );
        assert!(
            conn_a.is_disjoint(&conn_b),
            "siblings should have different conn_ids: a={:?}, b={:?}",
            conn_a,
            conn_b
        );

        // Clean up shared pipe
        unsafe {
            libc::close(shared_fds[0]);
            libc::close(shared_fds[1]);
        }
    }
}
