use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use aya::{
    maps::{Array, HashMap as AyaHashMap},
    programs::{KProbe, TracePoint, UProbe},
};
use log::{debug, info, warn};

pub const SSL_PROBES: &[(&str, &[&str])] = &[
    ("ssl_set_fd", &["SSL_set_fd"]),
    ("ssl_write", &["SSL_write", "SSL_write_ex"]),
    ("ssl_read_entry", &["SSL_read"]),
    ("ssl_read_ret", &["SSL_read"]),
    ("ssl_read_ex_entry", &["SSL_read_ex"]),
    ("ssl_read_ex_ret", &["SSL_read_ex"]),
];

pub const LIBC_PROBES: &[(&str, &[&str])] = &[
    ("tcp_send", &["send"]),
    ("tcp_recv_entry", &["recv"]),
    ("tcp_recv_ret", &["recv"]),
];

// Amazon Linux 2023 arm64 exports these syscall wrappers. Kprobe entry programs
// receive their pt_regs pointer in x0; kretprobes receive the syscall return.
const GO_ARM64_SYSCALL_PROBES: &[(&str, &str)] = &[
    ("go_arm64_accept4_ret", "__arm64_sys_accept4"),
    ("go_arm64_read_enter", "__arm64_sys_read"),
    ("go_arm64_read_ret", "__arm64_sys_read"),
    ("go_arm64_write_enter", "__arm64_sys_write"),
    ("go_arm64_write_ret", "__arm64_sys_write"),
    ("go_arm64_close_enter", "__arm64_sys_close"),
];

const GO_TRACEPOINT_PROBES: &[(&str, &str)] = &[
    ("go_trace_accept_exit", "sys_exit_accept"),
    ("go_trace_accept_exit", "sys_exit_accept4"),
    ("go_trace_read_enter", "sys_enter_read"),
    ("go_trace_read_exit", "sys_exit_read"),
    ("go_trace_write_enter", "sys_enter_write"),
    ("go_trace_write_exit", "sys_exit_write"),
    ("go_trace_close_enter", "sys_enter_close"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoSyscallBackend {
    Arm64Kprobe,
    Tracepoint,
}

fn go_syscall_backend_for_arch(arch: &str) -> GoSyscallBackend {
    if arch == "aarch64" {
        GoSyscallBackend::Arm64Kprobe
    } else {
        GoSyscallBackend::Tracepoint
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TcpSocket {
    local_port: u16,
    state: String,
    inode: u64,
}

fn parse_tcp_socket(line: &str) -> Option<TcpSocket> {
    let fields: Vec<_> = line.split_whitespace().collect();
    let local_port = u16::from_str_radix(fields.get(1)?.rsplit_once(':')?.1, 16).ok()?;
    Some(TcpSocket {
        local_port,
        state: fields.get(3)?.to_string(),
        inode: fields.get(9)?.parse().ok()?,
    })
}

fn target_tcp_sockets(pid: i32) -> Vec<TcpSocket> {
    ["tcp", "tcp6"]
        .into_iter()
        .flat_map(|name| {
            let path = format!("/proc/{pid}/net/{name}");
            fs::read_to_string(path)
                .map(|content| {
                    content
                        .lines()
                        .skip(1)
                        .filter_map(parse_tcp_socket)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect()
}

fn server_socket_inodes(sockets: &[TcpSocket]) -> HashSet<u64> {
    let listening_ports: HashSet<_> = sockets
        .iter()
        .filter(|socket| socket.state == "0A")
        .map(|socket| socket.local_port)
        .collect();
    sockets
        .iter()
        .filter(|socket| socket.state == "01" && listening_ports.contains(&socket.local_port))
        .map(|socket| socket.inode)
        .collect()
}

fn socket_inode(link: &std::path::Path) -> Option<u64> {
    let link = fs::read_link(link).ok()?;
    let text = link.to_string_lossy();
    text.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn seed_go_server_fds(ebpf: &mut aya::Ebpf, pid: i32) -> anyhow::Result<usize> {
    let sockets = target_tcp_sockets(pid);
    let server_inodes = server_socket_inodes(&sockets);

    if server_inodes.is_empty() {
        return Ok(0);
    }

    let mut server_fds = AyaHashMap::<_, u64, u8>::try_from(
        ebpf.map_mut("GO_SERVER_FDS")
            .expect("BPF Go server FD map must exist"),
    )?;
    let mut seeded = 0;
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        let fd = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        if socket_inode(&entry.path()).is_some_and(|inode| server_inodes.contains(&inode)) {
            let key = ((pid as u64) << 32) | fd as u64;
            server_fds.insert(key, 1, 0)?;
            seeded += 1;
        }
    }
    Ok(seeded)
}

/// Attach arm64 syscall wrapper kprobes for a single statically-linked Go server.
/// `capture_max_bytes` is the configured body allowance plus a bounded HTTP
/// header allowance. The BPF-side PID map suppresses unrelated traffic.
pub fn load_and_attach_go_syscalls(
    ebpf: &mut aya::Ebpf,
    pid: i32,
    capture_max_bytes: u32,
) -> anyhow::Result<()> {
    let mut target_pid = Array::<_, u32>::try_from(
        ebpf.map_mut("TARGET_PID")
            .expect("BPF target PID map must exist"),
    )?;
    target_pid.set(0, pid as u32, 0)?;
    drop(target_pid);

    let mut capture_limit = Array::<_, u32>::try_from(
        ebpf.map_mut("GO_CAPTURE_MAX_BYTES")
            .expect("BPF Go capture limit map must exist"),
    )?;
    capture_limit.set(0, capture_max_bytes, 0)?;
    drop(capture_limit);

    match go_syscall_backend_for_arch(std::env::consts::ARCH) {
        GoSyscallBackend::Arm64Kprobe => {
            for (prog_name, symbol) in GO_ARM64_SYSCALL_PROBES {
                let prog: &mut KProbe = ebpf
                    .program_mut(prog_name)
                    .expect("BPF arm64 syscall program must exist")
                    .try_into()?;
                prog.load()?;
                prog.attach(symbol, 0)?;
            }
        }
        GoSyscallBackend::Tracepoint => {
            for prog_name in [
                "go_trace_accept_exit",
                "go_trace_read_enter",
                "go_trace_read_exit",
                "go_trace_write_enter",
                "go_trace_write_exit",
                "go_trace_close_enter",
            ] {
                let prog: &mut TracePoint = ebpf
                    .program_mut(prog_name)
                    .expect("BPF syscall tracepoint program must exist")
                    .try_into()?;
                prog.load()?;
            }
            for (prog_name, tracepoint) in GO_TRACEPOINT_PROBES {
                let prog: &mut TracePoint = ebpf
                    .program_mut(prog_name)
                    .expect("BPF syscall tracepoint program must exist")
                    .try_into()?;
                prog.attach("syscalls", tracepoint)?;
            }
        }
    }
    match seed_go_server_fds(ebpf, pid) {
        Ok(0) => debug!("No established server sockets to seed for PID {pid}"),
        Ok(count) => info!("Seeded {count} pre-existing Go server sockets for PID {pid}"),
        Err(err) => warn!(
            "Could not seed pre-existing Go server sockets for PID {pid}; new accepts remain tracked: {err}"
        ),
    }
    Ok(())
}

pub fn load_and_attach(
    ebpf: &mut aya::Ebpf,
    prog_name: &str,
    symbols: &[&str],
    lib: &str,
    pid: Option<i32>,
) -> anyhow::Result<()> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .expect("BPF program must exist")
        .try_into()?;
    prog.load()?;
    attach_to(ebpf, prog_name, symbols, lib, pid)
}

fn attach_to(
    ebpf: &mut aya::Ebpf,
    prog_name: &str,
    symbols: &[&str],
    lib: &str,
    pid: Option<i32>,
) -> anyhow::Result<()> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .expect("BPF program must exist")
        .try_into()?;
    for sym in symbols {
        prog.attach(Some(sym), 0, lib, pid)?;
    }
    debug!("Attached {} to {}", prog_name, symbols.join(" + "));
    Ok(())
}

/// Load and attach a group of kprobes. If any load fails, the entire group is skipped.
pub fn load_and_attach_kprobes(
    ebpf: &mut aya::Ebpf,
    progs: &[(&str, &str)],
    ok_msg: &str,
    load_fail_msg: &str,
    partial_msg: &str,
) {
    let load_ok = (|| -> anyhow::Result<()> {
        for (prog_name, _) in progs {
            let prog: &mut KProbe = ebpf
                .program_mut(prog_name)
                .expect("BPF program must exist")
                .try_into()?;
            prog.load()?;
        }
        Ok(())
    })();

    if let Err(e) = load_ok {
        warn!("Failed to load kprobes: {} ({})", e, load_fail_msg);
        return;
    }

    let mut all_attached = true;
    for (prog_name, fn_name) in progs {
        let prog: &mut KProbe = ebpf
            .program_mut(prog_name)
            .expect("BPF program must exist")
            .try_into()
            .expect("BPF program type mismatch");
        if let Err(e) = prog.attach(fn_name, 0) {
            warn!("Failed to attach {} to {}: {}", prog_name, fn_name, e);
            all_attached = false;
        }
    }
    if all_attached {
        eprintln!("agtap: {}", ok_msg);
    } else {
        warn!("{}", partial_msg);
    }
}

/// Find new targets via `discover`, add them to `known`, and attach probes.
pub fn discover_and_track(
    ebpf: &mut aya::Ebpf,
    known: &mut HashSet<PathBuf>,
    discover: impl FnOnce(&HashSet<PathBuf>) -> Vec<PathBuf>,
    probes: &[(&str, &[&str])],
    label: &str,
) {
    let targets = discover(known);
    for p in &targets {
        known.insert(p.clone());
    }
    attach_extra_targets(ebpf, &targets, probes, label);
}

/// Discover new SSL/libc targets by scanning /proc and attach probes to them.
pub fn discover_and_attach(
    ebpf: &mut aya::Ebpf,
    known_ssl: &mut HashSet<PathBuf>,
    known_libc: &mut HashSet<PathBuf>,
    has_libc: bool,
) {
    discover_and_track(
        ebpf,
        known_ssl,
        agtap::tls::find_extra_libssl_paths,
        SSL_PROBES,
        "SSL",
    );
    discover_and_track(
        ebpf,
        known_ssl,
        agtap::tls::find_ssl_binaries,
        SSL_PROBES,
        "SSL",
    );
    if has_libc {
        discover_and_track(
            ebpf,
            known_libc,
            agtap::tls::find_extra_libc_paths,
            LIBC_PROBES,
            "libc",
        );
    }
}

/// Attach probes to a list of new targets.
fn attach_extra_targets(
    ebpf: &mut aya::Ebpf,
    targets: &[PathBuf],
    probes: &[(&str, &[&str])],
    label: &str,
) {
    for path in targets {
        let path_str = path.to_string_lossy().to_string();
        info!("Discovered {} target: {}", label, path.display());
        let mut attached_any = false;
        for &(prog_name, symbols) in probes {
            if let Err(e) = attach_to(ebpf, prog_name, symbols, &path_str, None) {
                debug!("Skipping {} for {}: {}", prog_name, path.display(), e);
                continue;
            }
            attached_any = true;
        }
        if attached_any {
            eprintln!("agtap: attached {} probes to {}", label, path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        go_syscall_backend_for_arch, parse_tcp_socket, server_socket_inodes, GoSyscallBackend,
        TcpSocket, GO_ARM64_SYSCALL_PROBES, GO_TRACEPOINT_PROBES,
    };

    #[test]
    fn parses_established_proc_tcp_socket() {
        let socket = parse_tcp_socket(
            "  4: 0100007F:1F90 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1000 0 12345 1",
        )
        .expect("valid proc tcp record");
        assert_eq!(socket.local_port, 8080);
        assert_eq!(socket.state, "01");
        assert_eq!(socket.inode, 12345);
    }

    #[test]
    fn rejects_malformed_proc_tcp_socket() {
        assert!(parse_tcp_socket("not a tcp record").is_none());
    }

    #[test]
    fn arm64_syscall_kprobes_cover_the_production_symbols() {
        assert_eq!(
            GO_ARM64_SYSCALL_PROBES,
            [
                ("go_arm64_accept4_ret", "__arm64_sys_accept4"),
                ("go_arm64_read_enter", "__arm64_sys_read"),
                ("go_arm64_read_ret", "__arm64_sys_read"),
                ("go_arm64_write_enter", "__arm64_sys_write"),
                ("go_arm64_write_ret", "__arm64_sys_write"),
                ("go_arm64_close_enter", "__arm64_sys_close"),
            ]
        );
    }

    #[test]
    fn selects_arm64_kprobes_and_generic_tracepoints_by_architecture() {
        assert_eq!(
            go_syscall_backend_for_arch("aarch64"),
            GoSyscallBackend::Arm64Kprobe
        );
        assert_eq!(
            go_syscall_backend_for_arch("x86_64"),
            GoSyscallBackend::Tracepoint
        );
        assert!(GO_TRACEPOINT_PROBES
            .iter()
            .any(|(_, name)| *name == "sys_exit_accept4"));
    }

    #[test]
    fn selects_only_established_sockets_on_listening_ports() {
        let sockets = vec![
            TcpSocket {
                local_port: 8080,
                state: "0A".into(),
                inode: 1,
            },
            TcpSocket {
                local_port: 8080,
                state: "01".into(),
                inode: 2,
            },
            TcpSocket {
                local_port: 49152,
                state: "01".into(),
                inode: 3,
            },
        ];
        assert_eq!(server_socket_inodes(&sockets), [2].into_iter().collect());
    }
}
