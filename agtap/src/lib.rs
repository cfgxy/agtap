use std::path::{Path, PathBuf};

pub mod body_store;
pub mod event_log;
pub mod output;
pub mod pipe;
pub mod providers;
pub mod reassembly;
pub mod socket;
pub mod stdio_reassembly;
pub mod telemetry;
pub mod tls;
pub mod tui;

/// If running under sudo, chown the given path to the real (non-root) user.
#[cfg(unix)]
pub(crate) fn chown_to_real_user(path: &Path) {
    if let Ok(uid_str) = std::env::var("SUDO_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            let gid = std::env::var("SUDO_GID")
                .ok()
                .and_then(|g| g.parse::<u32>().ok())
                .unwrap_or(uid);
            use std::os::unix::ffi::OsStrExt;
            let Some(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()).ok() else {
                return;
            };
            let _ = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        }
    }
}

/// Base runtime directory for agtap sockets and logs: /tmp/agtap/
pub fn default_runtime_dir() -> PathBuf {
    PathBuf::from("/tmp/agtap")
}
