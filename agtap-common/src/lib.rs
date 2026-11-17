#![cfg_attr(not(feature = "user"), no_std)]

pub const MAX_DATA_SIZE: usize = 16384;
/// Largest payload safely copied into one fixed-size eBPF ring-buffer event.
/// One byte remains unused so the verifier-visible `len & 0x3fff` bound never
/// wraps a 16 KiB payload to zero.
pub const MAX_EVENT_DATA_SIZE: usize = MAX_DATA_SIZE - 1;
/// Maximum body retention configured by `--max-body-retain-kb`.
///
/// This is deliberately capped at 1 MiB: the direct Go syscall tracepoint
/// emitter must split a single syscall into fixed-size events, and this ceiling
/// keeps its statically bounded control flow below the target 5.14 verifier
/// complexity limit. The CLI rejects, rather than silently truncating, larger
/// requested values.
pub const MAX_CAPTURE_BODY_SIZE: usize = 1024 * 1024;
/// Extra bytes retained by the syscall event source for HTTP start-lines and
/// headers, which are not part of the configured body limit.
pub const MAX_HTTP_HEADER_CAPTURE_SIZE: usize = 64 * 1024;
pub const MAX_SYSCALL_CAPTURE_SIZE: usize = MAX_CAPTURE_BODY_SIZE + MAX_HTTP_HEADER_CAPTURE_SIZE;

// Direction field bit allocation:
//   bit 0:       direction (0 = write/request, 1 = read/response)
//   bits 1-29:   reserved
//   bit 29:      TCP_CLOSE_FLAG — close lifecycle event for a TCP connection
//   bit 30:      TCP_FLAG — event from libc send()/recv() uprobe or Go syscall tracepoint
//   bit 31:      PIPE_FLAG — event from vfs_write/vfs_read kprobe
pub const TCP_CLOSE_FLAG: u32 = 0x2000_0000;
pub const TCP_FLAG: u32 = 0x4000_0000;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SslEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ssl_ptr: u64,
    pub fd: u32,
    pub direction: u32,
    pub data_len: u32,
    pub comm: [u8; 16],
    pub data: [u8; MAX_DATA_SIZE],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SslReadArgs {
    pub ssl_ptr: u64,
    pub buf_ptr: u64,
}

/// Stashed args for SSL_read_ex uretprobe.
/// SSL_read_ex returns 1/0 and stores actual bytes in *readbytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SslReadExArgs {
    pub ssl_ptr: u64,
    pub buf_ptr: u64,
    pub readbytes_ptr: u64,
}

/// Stashed args for vfs_read kretprobe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VfsReadArgs {
    pub buf_ptr: u64,
    pub ino: u64,
}

/// Stashed args for recv() uretprobe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpRecvArgs {
    pub fd: u32,
    pub buf_ptr: u64,
}
