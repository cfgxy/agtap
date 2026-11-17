#![no_std]
#![no_main]
#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code,
    unnecessary_transmutes
)]

use agtap_common::{
    SslEvent, SslReadArgs, SslReadExArgs, TcpRecvArgs, VfsReadArgs, MAX_EVENT_DATA_SIZE,
    MAX_SYSCALL_CAPTURE_SIZE, TCP_CLOSE_FLAG, TCP_FLAG,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_buf,
    },
    macros::{kprobe, kretprobe, map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};

mod vmlinux;
use vmlinux::{file, inode, iovec};

const MAX_EVENT_BYTES: u32 = MAX_EVENT_DATA_SIZE as u32;

#[map]
static ACTIVE_SSL_CALLS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(4096, 0);

#[map]
static ACTIVE_SSL_EX_CALLS: HashMap<u64, SslReadExArgs> = HashMap::with_max_entries(4096, 0);

#[map]
static SSL_FD_MAP: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static ACTIVE_TCP_RECV_CALLS: HashMap<u64, TcpRecvArgs> = HashMap::with_max_entries(4096, 0);

// Go's statically linked runtime invokes read(2)/write(2) directly, bypassing libc.
// The host configures this to the exact target TGID before tracepoints are attached.
#[map]
static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

// Configured from `--max-body-retain-kb`; zero disables Go syscall payload capture.
#[map]
static GO_CAPTURE_MAX_BYTES: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static ACTIVE_GO_READ_CALLS: HashMap<u64, TcpRecvArgs> = HashMap::with_max_entries(4096, 0);

#[map]
static ACTIVE_GO_WRITE_CALLS: HashMap<u64, TcpRecvArgs> = HashMap::with_max_entries(4096, 0);

// Only accepted server sockets are captured: this excludes unrelated files and
// outbound provider sockets owned by the target process.
#[map]
static GO_SERVER_FDS: HashMap<u64, u8> = HashMap::with_max_entries(16384, 0);

#[map]
static ACTIVE_VFS_READ_CALLS: HashMap<u64, VfsReadArgs> = HashMap::with_max_entries(8192, 0);

// 2 MiB body + 64 KiB header allowance fits in this map while leaving headroom
// for producer/consumer overlap. It is also below typical 8 MiB memlock limits.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// SSL_set_fd(SSL *ssl, int fd)
#[uprobe]
pub fn ssl_set_fd(ctx: ProbeContext) -> u32 {
    match try_ssl_set_fd(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_set_fd(ctx: &ProbeContext) -> Result<(), u32> {
    let ssl_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    let fd: u32 = ctx.arg::<u64>(1).ok_or(1u32)? as u32;
    SSL_FD_MAP.insert(&ssl_ptr, &fd, 0).map_err(|_| 1u32)?;
    Ok(())
}

// SSL_write(SSL *ssl, const void *buf, int num) -> int
// Also used for SSL_write_ex(ssl, buf, num, *written). We capture `num`
// (requested bytes) rather than `*written` (actual bytes). These are always
// equal on success for blocking SSL sockets, which is the common case.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write(ctx: &ProbeContext) -> Result<(), u32> {
    let ssl_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let len: u32 = ctx.arg::<u64>(2).ok_or(1u32)? as u32;

    emit_event(ssl_ptr, buf_ptr, len, 0)
}

// SSL_read entry: stash args for uretprobe
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), u32> {
    let ssl_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let key = bpf_get_current_pid_tgid();
    let args = SslReadArgs { ssl_ptr, buf_ptr };
    ACTIVE_SSL_CALLS.insert(&key, &args, 0).map_err(|_| 1u32)?;
    Ok(())
}

// SSL_read return: read the buffer using stashed args + return value as length
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_ret(ctx: &RetProbeContext) -> Result<(), u32> {
    let key = bpf_get_current_pid_tgid();
    let args = unsafe { ACTIVE_SSL_CALLS.get(&key).ok_or(1u32)? };
    let ssl_ptr = args.ssl_ptr;
    let buf_ptr = args.buf_ptr;
    let _ = ACTIVE_SSL_CALLS.remove(&key);

    let ret: i64 = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(());
    }
    let len = ret as u32;

    emit_event(ssl_ptr, buf_ptr, len, 1)
}

// SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) -> int (1=ok, 0=err)
#[uprobe]
pub fn ssl_read_ex_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_ex_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_ex_entry(ctx: &ProbeContext) -> Result<(), u32> {
    let ssl_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let readbytes_ptr: u64 = ctx.arg(3).ok_or(1u32)?;
    let key = bpf_get_current_pid_tgid();
    let args = SslReadExArgs {
        ssl_ptr,
        buf_ptr,
        readbytes_ptr,
    };
    ACTIVE_SSL_EX_CALLS
        .insert(&key, &args, 0)
        .map_err(|_| 1u32)?;
    Ok(())
}

#[uretprobe]
pub fn ssl_read_ex_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ex_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_ex_ret(ctx: &RetProbeContext) -> Result<(), u32> {
    let key = bpf_get_current_pid_tgid();
    let args = unsafe { ACTIVE_SSL_EX_CALLS.get(&key).ok_or(1u32)? };
    let ssl_ptr = args.ssl_ptr;
    let buf_ptr = args.buf_ptr;
    let readbytes_ptr = args.readbytes_ptr;
    let _ = ACTIVE_SSL_EX_CALLS.remove(&key);

    let ret: i64 = ctx.ret().ok_or(1u32)?;
    if ret != 1 {
        return Ok(()); // SSL_read_ex returns 1 on success
    }

    // Read the actual byte count from *readbytes.
    // If the probe-read fails, readbytes stays 0 and we skip the event below.
    let mut readbytes: usize = 0;
    unsafe {
        let _ = bpf_probe_read_user_buf(
            readbytes_ptr as *const u8,
            core::slice::from_raw_parts_mut(
                &mut readbytes as *mut usize as *mut u8,
                core::mem::size_of::<usize>(),
            ),
        );
    }
    if readbytes == 0 {
        return Ok(());
    }

    emit_event(ssl_ptr, buf_ptr, readbytes as u32, 1)
}

fn emit_event(ssl_ptr: u64, buf_ptr: u64, len: u32, direction: u32) -> Result<(), u32> {
    let capped_len = if len > MAX_EVENT_BYTES {
        MAX_EVENT_BYTES
    } else {
        len
    };
    // Bitmask to satisfy verifier
    let safe_len = (capped_len & 0x3FFF) as usize;

    if let Some(mut entry) = EVENTS.reserve::<SslEvent>(0) {
        let event = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).pid = (pid_tgid >> 32) as u32;
            (*event).tid = pid_tgid as u32;
            (*event).ssl_ptr = ssl_ptr;
            (*event).direction = direction;
            (*event).data_len = safe_len as u32;

            // Get fd from map
            (*event).fd = match SSL_FD_MAP.get(&ssl_ptr) {
                Some(fd) => *fd,
                None => 0,
            };

            // Get comm
            if let Ok(comm) = bpf_get_current_comm() {
                (*event).comm = comm;
            }

            // Read user buffer
            let dst = &mut (&mut (*event).data)[..safe_len];
            let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, dst);
        }
        entry.submit(0);
    }

    Ok(())
}

// ── Plain HTTP capture via glibc send()/recv() uprobes ─────────────────

fn emit_tcp_event_chunk(
    fd: u32,
    buf_ptr: u64,
    len: u32,
    direction: u32,
    filter_tls_record: bool,
) -> Result<(), u32> {
    // `len` is always bounded to MAX_EVENT_DATA_SIZE by the caller, which keeps the
    // ring-buffer reservation and verifier-visible slice bounded.
    let safe_len = (len & 0x3FFF) as usize;

    // Only inspect the first chunk. Subsequent chunks may naturally start with
    // a TLS-record-looking byte even when the HTTP message is plaintext.
    if filter_tls_record {
        let mut first_byte: u8 = 0;
        unsafe {
            let _ = bpf_probe_read_user_buf(
                buf_ptr as *const u8,
                core::slice::from_raw_parts_mut(&mut first_byte, 1),
            );
        }
        if first_byte >= 0x14 && first_byte <= 0x17 {
            return Ok(()); // Likely TLS record, skip
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<SslEvent>(0) {
        let event = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).pid = (pid_tgid >> 32) as u32;
            (*event).tid = pid_tgid as u32;
            (*event).ssl_ptr = fd as u64; // fd as connection identifier
            (*event).fd = fd;
            (*event).direction = direction | TCP_FLAG;
            (*event).data_len = safe_len as u32;
            if let Ok(comm) = bpf_get_current_comm() {
                (*event).comm = comm;
            }
            let dst = &mut (&mut (*event).data)[..safe_len];
            let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, dst);
        }
        entry.submit(0);
    }
    Ok(())
}

fn emit_tcp_event(fd: u32, buf_ptr: u64, len: u32, direction: u32) -> Result<(), u32> {
    let capped_len = if len > MAX_EVENT_BYTES {
        MAX_EVENT_BYTES
    } else {
        len
    };
    emit_tcp_event_chunk(fd, buf_ptr, capped_len, direction, true)
}

const MAX_GO_SYSCALL_CHUNKS: u32 =
    (MAX_SYSCALL_CAPTURE_SIZE as u32 + MAX_EVENT_BYTES - 1) / MAX_EVENT_BYTES;

fn emit_go_tcp_events(fd: u32, buf_ptr: u64, len: u32, direction: u32) -> Result<(), u32> {
    let configured_limit = GO_CAPTURE_MAX_BYTES.get(0).copied().unwrap_or(0);
    let mut remaining = if len > configured_limit {
        configured_limit
    } else {
        len
    };
    let mut offset = 0u32;
    let mut chunk_index = 0u32;

    // Bounded by the shared 2 MiB body + HTTP header cap, so the verifier sees
    // at most 133 fixed-size 16 KiB reservations. No event or user-memory read exceeds one
    // SslEvent payload.
    while remaining > 0 && chunk_index < MAX_GO_SYSCALL_CHUNKS {
        let chunk_len = if remaining > MAX_EVENT_BYTES {
            MAX_EVENT_BYTES
        } else {
            remaining
        };
        emit_tcp_event_chunk(
            fd,
            buf_ptr + offset as u64,
            chunk_len,
            direction,
            chunk_index == 0,
        )?;
        remaining -= chunk_len;
        offset += chunk_len;
        chunk_index += 1;
    }
    Ok(())
}

// send(int fd, const void *buf, size_t len, int flags)
#[uprobe]
pub fn tcp_send(ctx: ProbeContext) -> u32 {
    match try_tcp_send(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_send(ctx: &ProbeContext) -> Result<(), u32> {
    let fd: u32 = ctx.arg::<u64>(0).ok_or(1u32)? as u32;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let len: u32 = ctx.arg::<u64>(2).ok_or(1u32)? as u32;
    emit_tcp_event(fd, buf_ptr, len, 0) // direction=0 (write)
}

// recv(int fd, void *buf, size_t len, int flags) — entry stashes args
#[uprobe]
pub fn tcp_recv_entry(ctx: ProbeContext) -> u32 {
    match try_tcp_recv_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_recv_entry(ctx: &ProbeContext) -> Result<(), u32> {
    let fd: u32 = ctx.arg::<u64>(0).ok_or(1u32)? as u32;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let key = bpf_get_current_pid_tgid();
    ACTIVE_TCP_RECV_CALLS
        .insert(&key, &TcpRecvArgs { fd, buf_ptr }, 0)
        .map_err(|_| 1u32)?;
    Ok(())
}

// recv return: read filled buffer using stashed args + return value as length
#[uretprobe]
pub fn tcp_recv_ret(ctx: RetProbeContext) -> u32 {
    match try_tcp_recv_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_recv_ret(ctx: &RetProbeContext) -> Result<(), u32> {
    let key = bpf_get_current_pid_tgid();
    let args = unsafe { ACTIVE_TCP_RECV_CALLS.get(&key).ok_or(1u32)? };
    let fd = args.fd;
    let buf_ptr = args.buf_ptr;
    let _ = ACTIVE_TCP_RECV_CALLS.remove(&key);

    let ret: i64 = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(());
    }
    emit_tcp_event(fd, buf_ptr, ret as u32, 1) // direction=1 (read)
}

// ── Go direct-syscall HTTP capture ──────────────────────────────────────
//
// Go's net package issues read(2), write(2), accept4(2), and close(2)
// directly from its statically linked runtime.  We track only sockets accepted
// by the selected server process.  `read` therefore represents the inbound
// HTTP request and `write` the outbound HTTP response.
const SYSCALL_FD_OFFSET: usize = 16;
const SYSCALL_BUF_OFFSET: usize = 24;
const SYSCALL_RET_OFFSET: usize = 16;

fn target_pid() -> u32 {
    TARGET_PID.get(0).copied().unwrap_or(0)
}

fn is_target_process() -> bool {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target = target_pid();
    target != 0 && pid == target
}

fn tcp_connection_key(pid: u32, fd: u32) -> u64 {
    ((pid as u64) << 32) | fd as u64
}

fn is_go_server_fd(pid: u32, fd: u32) -> bool {
    unsafe { GO_SERVER_FDS.get(&tcp_connection_key(pid, fd)).is_some() }
}

fn stash_go_call(ctx: &TracePointContext, calls: &HashMap<u64, TcpRecvArgs>) -> Result<(), u32> {
    if !is_target_process() {
        return Ok(());
    }
    let fd = unsafe { ctx.read_at::<u64>(SYSCALL_FD_OFFSET).map_err(|_| 1u32)? } as u32;
    let buf_ptr = unsafe { ctx.read_at::<u64>(SYSCALL_BUF_OFFSET).map_err(|_| 1u32)? };
    let key = bpf_get_current_pid_tgid();
    calls
        .insert(&key, &TcpRecvArgs { fd, buf_ptr }, 0)
        .map_err(|_| 1u32)
}

fn emit_go_call(
    ctx: &TracePointContext,
    calls: &HashMap<u64, TcpRecvArgs>,
    direction: u32,
) -> Result<(), u32> {
    let key = bpf_get_current_pid_tgid();
    let args = unsafe { calls.get(&key).ok_or(1u32)? };
    let fd = args.fd;
    let buf_ptr = args.buf_ptr;
    let _ = calls.remove(&key);

    let ret = unsafe { ctx.read_at::<i64>(SYSCALL_RET_OFFSET).map_err(|_| 1u32)? };
    if ret <= 0 {
        return Ok(());
    }
    let pid = (key >> 32) as u32;
    if !is_go_server_fd(pid, fd) {
        return Ok(());
    }
    emit_go_tcp_events(fd, buf_ptr, ret as u32, direction)
}

#[tracepoint]
pub fn go_accept_exit(ctx: TracePointContext) -> u32 {
    if !is_target_process() {
        return 0;
    }
    let ret = match unsafe { ctx.read_at::<i64>(SYSCALL_RET_OFFSET) } {
        Ok(ret) => ret,
        Err(_) => return 1,
    };
    if ret < 0 {
        return 0;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let fd = ret as u32;
    match GO_SERVER_FDS.insert(&tcp_connection_key(pid, fd), &1, 0) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn go_read_enter(ctx: TracePointContext) -> u32 {
    match stash_go_call(&ctx, &ACTIVE_GO_READ_CALLS) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn go_read_exit(ctx: TracePointContext) -> u32 {
    match emit_go_call(&ctx, &ACTIVE_GO_READ_CALLS, 0) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn go_write_enter(ctx: TracePointContext) -> u32 {
    match stash_go_call(&ctx, &ACTIVE_GO_WRITE_CALLS) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn go_write_exit(ctx: TracePointContext) -> u32 {
    match emit_go_call(&ctx, &ACTIVE_GO_WRITE_CALLS, 1) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn emit_tcp_close(fd: u32) -> Result<(), u32> {
    if let Some(mut entry) = EVENTS.reserve::<SslEvent>(0) {
        let event = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).pid = (pid_tgid >> 32) as u32;
            (*event).tid = pid_tgid as u32;
            (*event).ssl_ptr = fd as u64;
            (*event).fd = fd;
            (*event).direction = TCP_FLAG | TCP_CLOSE_FLAG;
            (*event).data_len = 0;
            if let Ok(comm) = bpf_get_current_comm() {
                (*event).comm = comm;
            }
        }
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint]
pub fn go_close_enter(ctx: TracePointContext) -> u32 {
    if !is_target_process() {
        return 0;
    }
    let fd = match unsafe { ctx.read_at::<u64>(SYSCALL_FD_OFFSET) } {
        Ok(fd) => fd as u32,
        Err(_) => return 1,
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = tcp_connection_key(pid, fd);
    if unsafe { GO_SERVER_FDS.get(&key).is_none() } {
        return 0;
    }
    let _ = GO_SERVER_FDS.remove(&key);
    match emit_tcp_close(fd) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ── Pipe (stdio MCP) kprobes ───────────────────────────────────────────

const PIPE_FLAG: u32 = 0x80000000;
const S_IFMT: u16 = 0o170000;
const S_IFIFO: u16 = 0o010000;
const S_IFSOCK: u16 = 0o140000;

/// Match both pipes (for stdio MCP over pipe) and Unix domain sockets
/// (for stdio MCP over socketpair, as used by Claude Code).
fn is_pipe_or_socket(mode: u16) -> bool {
    let ft = mode & S_IFMT;
    ft == S_IFIFO || ft == S_IFSOCK
}

/// Extract inode number from struct file pointer. Returns None if not a FIFO or socket.
fn read_pipe_ino(file_ptr: *const file) -> Result<Option<u64>, u32> {
    let inode_ptr: *const inode =
        unsafe { bpf_probe_read_kernel(&(*file_ptr).f_inode).map_err(|_| 1u32)? };
    let i_mode: u16 = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_mode).map_err(|_| 1u32)? };
    if !is_pipe_or_socket(i_mode) {
        return Ok(None);
    }
    let i_ino: u64 = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_ino).map_err(|_| 1u32)? };
    Ok(Some(i_ino))
}

fn emit_pipe_event(ino: u64, buf_ptr: u64, len: u32, direction: u32) -> Result<(), u32> {
    let capped_len = if len > MAX_EVENT_BYTES {
        MAX_EVENT_BYTES
    } else {
        len
    };
    let safe_len = (capped_len & 0x3FFF) as usize;

    // Quick content check: first byte should be '{' for JSON
    let mut first_byte: u8 = 0;
    unsafe {
        let _ = bpf_probe_read_user_buf(
            buf_ptr as *const u8,
            core::slice::from_raw_parts_mut(&mut first_byte, 1),
        );
    }
    if first_byte != b'{' {
        return Ok(());
    }

    if let Some(mut entry) = EVENTS.reserve::<SslEvent>(0) {
        let event = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).pid = (pid_tgid >> 32) as u32;
            (*event).tid = pid_tgid as u32;
            (*event).ssl_ptr = ino;
            (*event).fd = 0;
            (*event).direction = direction | PIPE_FLAG;
            (*event).data_len = safe_len as u32;
            if let Ok(comm) = bpf_get_current_comm() {
                (*event).comm = comm;
            }
            let dst = &mut (&mut (*event).data)[..safe_len];
            let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, dst);
        }
        entry.submit(0);
    }
    Ok(())
}

// vfs_write: capture at entry (buffer is fully populated by caller)
#[kprobe]
pub fn pipe_vfs_write(ctx: ProbeContext) -> u32 {
    match try_pipe_vfs_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_write(ctx: &ProbeContext) -> Result<(), u32> {
    let file_ptr: *const file = ctx.arg(0).ok_or(1u32)?;
    let ino = match read_pipe_ino(file_ptr)? {
        Some(ino) => ino,
        None => return Ok(()),
    };
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let count: u32 = ctx.arg::<u64>(2).ok_or(1u32)? as u32;
    emit_pipe_event(ino, buf_ptr, count, 0) // direction=0 (write)
}

// vfs_read: entry stashes args, return reads filled buffer
#[kprobe]
pub fn pipe_vfs_read_entry(ctx: ProbeContext) -> u32 {
    match try_pipe_vfs_read_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_read_entry(ctx: &ProbeContext) -> Result<(), u32> {
    let file_ptr: *const file = ctx.arg(0).ok_or(1u32)?;
    let ino = match read_pipe_ino(file_ptr)? {
        Some(ino) => ino,
        None => return Ok(()),
    };
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let tid_key = bpf_get_current_pid_tgid();
    ACTIVE_VFS_READ_CALLS
        .insert(&tid_key, &VfsReadArgs { buf_ptr, ino }, 0)
        .map_err(|_| 1u32)?;
    Ok(())
}

#[kretprobe]
pub fn pipe_vfs_read_ret(ctx: RetProbeContext) -> u32 {
    match try_pipe_vfs_read_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_read_ret(ctx: &RetProbeContext) -> Result<(), u32> {
    let tid_key = bpf_get_current_pid_tgid();
    let args = unsafe { ACTIVE_VFS_READ_CALLS.get(&tid_key).ok_or(1u32)? };
    let buf_ptr = args.buf_ptr;
    let ino = args.ino;
    let _ = ACTIVE_VFS_READ_CALLS.remove(&tid_key);

    let ret: i64 = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(());
    }
    emit_pipe_event(ino, buf_ptr, ret as u32, 1) // direction=1 (read)
}

// ── Pipe (stdio MCP) writev/readv kprobes ──────────────────────────────
// Node.js/libuv uses writev() for pipe I/O, which goes through vfs_writev
// rather than vfs_write. Same pattern — read first iovec entry for the buffer.

/// Read the first iovec from a userspace iovec array, returning (iov_base, iov_len).
fn read_first_iovec(vec_ptr: u64) -> Result<(u64, u32), u32> {
    let mut iov = unsafe { core::mem::zeroed::<iovec>() };
    unsafe {
        let _ = bpf_probe_read_user_buf(
            vec_ptr as *const u8,
            core::slice::from_raw_parts_mut(
                &mut iov as *mut iovec as *mut u8,
                core::mem::size_of::<iovec>(),
            ),
        );
    }
    let base = iov.iov_base as u64;
    let len = iov.iov_len as u32;
    if base == 0 || len == 0 {
        return Err(1);
    }
    Ok((base, len))
}

// vfs_writev: capture at entry (first iovec buffer is fully populated by caller)
#[kprobe]
pub fn pipe_vfs_writev(ctx: ProbeContext) -> u32 {
    match try_pipe_vfs_writev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_writev(ctx: &ProbeContext) -> Result<(), u32> {
    let file_ptr: *const file = ctx.arg(0).ok_or(1u32)?;
    let ino = match read_pipe_ino(file_ptr)? {
        Some(ino) => ino,
        None => return Ok(()),
    };
    let vec_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let (iov_base, iov_len) = read_first_iovec(vec_ptr)?;
    emit_pipe_event(ino, iov_base, iov_len, 0) // direction=0 (write)
}

// vfs_readv: entry stashes first iovec buffer pointer, return reads filled buffer
#[kprobe]
pub fn pipe_vfs_readv_entry(ctx: ProbeContext) -> u32 {
    match try_pipe_vfs_readv_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_readv_entry(ctx: &ProbeContext) -> Result<(), u32> {
    let file_ptr: *const file = ctx.arg(0).ok_or(1u32)?;
    let ino = match read_pipe_ino(file_ptr)? {
        Some(ino) => ino,
        None => return Ok(()),
    };
    let vec_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let (iov_base, _) = read_first_iovec(vec_ptr)?;
    let tid_key = bpf_get_current_pid_tgid();
    ACTIVE_VFS_READ_CALLS
        .insert(
            &tid_key,
            &VfsReadArgs {
                buf_ptr: iov_base,
                ino,
            },
            0,
        )
        .map_err(|_| 1u32)?;
    Ok(())
}

#[kretprobe]
pub fn pipe_vfs_readv_ret(ctx: RetProbeContext) -> u32 {
    match try_pipe_vfs_readv_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pipe_vfs_readv_ret(ctx: &RetProbeContext) -> Result<(), u32> {
    let tid_key = bpf_get_current_pid_tgid();
    let args = unsafe { ACTIVE_VFS_READ_CALLS.get(&tid_key).ok_or(1u32)? };
    let buf_ptr = args.buf_ptr;
    let ino = args.ino;
    let _ = ACTIVE_VFS_READ_CALLS.remove(&tid_key);

    let ret: i64 = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(());
    }
    emit_pipe_event(ino, buf_ptr, ret as u32, 1) // direction=1 (read)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
