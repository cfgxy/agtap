use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};

const LIBC_PREFIXES: &[&str] = &["libc.so", "libc-", "ld-musl", "libc.musl"];

/// Parse `ldconfig -p` output for libraries matching any of `prefixes`
/// (e.g. `&["libssl.so"]` or `&["libc.so", "libc-", "ld-musl", "libc.musl"]`).
/// Runs `ldconfig -p` once and returns paths that exist on disk, extracted from lines like:
///   `\tlibssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3`
fn parse_ldconfig(prefixes: &[&str]) -> Vec<PathBuf> {
    let output = match Command::new("ldconfig").arg("-p").output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output);
    let mut result = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !prefixes.iter().any(|prefix| trimmed.starts_with(prefix)) {
            continue;
        }
        if let Some((_left, right)) = trimmed.split_once(" => ") {
            let p = PathBuf::from(right);
            if p.exists() {
                result.push(p);
            }
        }
    }
    result
}

/// Strip the " (deleted)" suffix that Linux appends to /proc/*/exe for replaced binaries.
fn strip_deleted_suffix(path: PathBuf) -> PathBuf {
    match path.to_string_lossy().strip_suffix(" (deleted)") {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// Search `/proc/<pid>/maps` for a library matching `matcher`, returning the first existing path.
fn find_lib_in_maps(
    pid: u32,
    matcher: impl Fn(&str) -> bool,
    label: &str,
) -> anyhow::Result<PathBuf> {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps =
        fs::read_to_string(&maps_path).with_context(|| format!("Cannot read {}", maps_path))?;
    for line in maps.lines() {
        if matcher(line) {
            if let Some(path) = line.split_whitespace().last() {
                if path.starts_with('/') {
                    let p = PathBuf::from(path);
                    if p.exists() {
                        return Ok(p);
                    }
                }
            }
        }
    }
    bail!("No {} found in /proc/{}/maps", label, pid)
}

/// Find the path to libssl.so loaded by a given PID.
/// Reads /proc/<pid>/maps and looks for libssl.so entries.
pub fn find_libssl_for_pid(pid: u32) -> anyhow::Result<PathBuf> {
    find_lib_in_maps(pid, |line| line.contains("libssl.so"), "libssl.so")
}

/// Check if an ELF binary contains SSL_read in its symbol tables.
/// Checks dynamic symbols first (most common for Node.js official builds),
/// then falls back to the regular symbol table (for non-stripped custom builds).
///
/// We check for the exact name "SSL_read" — not prefixed variants like
/// BSSL_SSL_read — because uprobe attachment uses the same symbol name.
/// Prefixed BoringSSL builds would need different attach logic anyway.
pub fn has_ssl_symbols(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    // SAFETY: the file descriptor is valid (just opened above) and we only
    // read from the mapping — no concurrent mutation of the file is expected.
    let Ok(mmap) = (unsafe { memmap2::Mmap::map(&file) }) else {
        return false;
    };
    let Ok(obj) = object::File::parse(&*mmap) else {
        return false;
    };
    use object::{Object, ObjectSymbol};
    obj.dynamic_symbols()
        .chain(obj.symbols())
        .any(|sym| matches!(sym.name(), Ok("SSL_read") | Ok("SSL_read_ex")))
}

/// Find the binary containing SSL symbols for a given PID.
/// Tries libssl.so in maps first, then checks the process's own binary.
pub fn find_ssl_binary_for_pid(pid: u32) -> anyhow::Result<PathBuf> {
    // First: look for libssl.so in /proc/<pid>/maps (current behavior)
    if let Ok(path) = find_libssl_for_pid(pid) {
        return Ok(path);
    }

    // Fallback: check if the process binary itself exports SSL symbols
    // (e.g., Node.js statically links OpenSSL but exports the symbols)
    let exe_path = strip_deleted_suffix(
        fs::read_link(format!("/proc/{}/exe", pid))
            .with_context(|| format!("Cannot read /proc/{}/exe", pid))?,
    );

    if has_ssl_symbols(&exe_path) {
        return Ok(exe_path);
    }

    bail!(
        "No SSL symbols found for PID {} (no libssl.so in maps, and {} does not export SSL_read)",
        pid,
        exe_path.display()
    )
}

/// Find the system libssl.so without a target PID.
/// Tries `ldconfig -p` first for cross-distro support, then falls back to hardcoded paths.
pub fn find_system_libssl() -> anyhow::Result<PathBuf> {
    // 1. Try ldconfig (works on Debian, Fedora, Arch, ARM, etc.)
    for p in parse_ldconfig(&["libssl.so"]) {
        if has_ssl_symbols(&p) {
            return Ok(p);
        }
    }

    // 2. Hardcoded fallback (expanded with /lib/... and aarch64)
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/lib64/libssl.so.3",
        "/lib64/libssl.so.1.1",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so",
    ];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() && has_ssl_symbols(&p) {
            return Ok(p);
        }
    }

    bail!("Cannot find system libssl.so")
}

/// Find libc loaded by a given PID via /proc/<pid>/maps.
/// Looks for glibc ("libc.so", "libc-") and musl ("ld-musl", "libc.musl") entries.
pub fn find_libc_for_pid(pid: u32) -> anyhow::Result<PathBuf> {
    find_lib_in_maps(
        pid,
        |line| LIBC_PREFIXES.iter().any(|p| line.contains(p)),
        "libc",
    )
}

/// Collect libc candidates from ldconfig (single subprocess call).
/// Matches glibc soname, glibc versioned, musl loader, and musl libc.
fn ldconfig_libc_candidates() -> Vec<PathBuf> {
    parse_ldconfig(LIBC_PREFIXES)
}

/// Find the system libc (glibc or musl) without a target PID.
pub fn find_system_libc() -> anyhow::Result<PathBuf> {
    // 1. Try ldconfig (no symbol check — libc always has send/recv)
    if let Some(p) = ldconfig_libc_candidates().into_iter().next() {
        return Ok(p);
    }

    // 2. Hardcoded fallback
    let candidates = [
        // glibc
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        // musl
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
        "/usr/lib/x86_64-linux-musl/libc.so",
        "/usr/lib/aarch64-linux-musl/libc.so",
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }
    bail!("Cannot find system libc (no glibc or musl found)")
}

/// Find PIDs matching a process comm name.
pub fn find_pids_by_comm(comm: &str) -> anyhow::Result<Vec<u32>> {
    let mut pids = Vec::new();

    let entries = fs::read_dir("/proc").context("Cannot read /proc")?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            let comm_path = format!("/proc/{}/comm", pid);
            if let Ok(proc_comm) = fs::read_to_string(&comm_path) {
                if proc_comm.trim() == comm {
                    pids.push(pid);
                }
            }
        }
    }

    if pids.is_empty() {
        bail!("No processes found with comm '{}'", comm)
    } else {
        Ok(pids)
    }
}

/// Scan /proc for paths not already in `known`, using `finder` to probe each PID.
/// The `filter` is called only on genuinely new (deduped) paths.
fn find_extra_paths(
    known: &HashSet<PathBuf>,
    finder: impl Fn(u32) -> anyhow::Result<PathBuf>,
    filter: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    let mut seen = known.clone();
    let mut result = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return result;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Ok(path) = finder(pid) {
            let canon = path.canonicalize().unwrap_or(path);
            if seen.insert(canon.clone()) && filter(&canon) {
                result.push(canon);
            }
        }
    }
    result
}

/// Scan /proc/*/maps for libssl.so paths not already in `known`.
pub fn find_extra_libssl_paths(known: &HashSet<PathBuf>) -> Vec<PathBuf> {
    find_extra_paths(known, find_libssl_for_pid, |_| true)
}

/// Scan /proc/*/maps for libc paths not already in `known`.
/// Catches musl libc in containers.
pub fn find_extra_libc_paths(known: &HashSet<PathBuf>) -> Vec<PathBuf> {
    find_extra_paths(known, find_libc_for_pid, |_| true)
}

/// Deduplicate and filter a list of candidate paths against `known`.
fn find_ldconfig_paths(
    known: &HashSet<PathBuf>,
    candidates: Vec<PathBuf>,
    filter: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    let mut seen = known.clone();
    let mut result = Vec::new();
    for path in candidates {
        let canon = path.canonicalize().unwrap_or(path);
        if seen.insert(canon.clone()) && filter(&canon) {
            result.push(canon);
        }
    }
    result
}

/// Find libssl paths via ldconfig that are not already in `known`.
pub fn find_ldconfig_libssl_paths(known: &HashSet<PathBuf>) -> Vec<PathBuf> {
    find_ldconfig_paths(known, parse_ldconfig(&["libssl.so"]), has_ssl_symbols)
}

/// Find libc paths via ldconfig that are not already in `known`.
pub fn find_ldconfig_libc_paths(known: &HashSet<PathBuf>) -> Vec<PathBuf> {
    find_ldconfig_paths(known, ldconfig_libc_candidates(), |_| true)
}

/// Scan /proc/*/exe for binaries with embedded SSL symbols (e.g., Node.js).
/// Skips paths already in `known`. Deduplicates before the expensive symbol check.
pub fn find_ssl_binaries(known: &HashSet<PathBuf>) -> Vec<PathBuf> {
    find_extra_paths(
        known,
        |pid| {
            let exe_path = strip_deleted_suffix(fs::read_link(format!("/proc/{}/exe", pid))?);
            Ok(exe_path)
        },
        has_ssl_symbols,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_ssl_symbols_false_for_non_ssl_binary() {
        // /usr/bin/ls exists on any Linux and has no SSL symbols
        assert!(!has_ssl_symbols(Path::new("/usr/bin/ls")));
    }

    #[test]
    fn has_ssl_symbols_false_for_nonexistent_path() {
        assert!(!has_ssl_symbols(Path::new("/no/such/binary")));
    }

    #[test]
    fn has_ssl_symbols_true_for_libssl() {
        // Also serves as a regression test for find_system_libssl —
        // if it returns Ok, the path must be a valid ELF with SSL symbols.
        let Ok(libssl) = find_system_libssl() else {
            return;
        };
        assert!(has_ssl_symbols(&libssl));
    }

    #[test]
    fn parse_ldconfig_finds_libssl() {
        // On systems with ldconfig, this should find at least one libssl path.
        // Skip gracefully if ldconfig is not available (e.g. containers without it).
        let paths = parse_ldconfig(&["libssl.so"]);
        if paths.is_empty() {
            return; // ldconfig not available or libssl not installed
        }
        for p in &paths {
            assert!(p.exists(), "ldconfig path does not exist: {}", p.display());
            assert!(
                p.to_string_lossy().contains("libssl"),
                "unexpected path: {}",
                p.display()
            );
        }
    }

    #[test]
    fn parse_ldconfig_returns_empty_for_nonexistent_lib() {
        let paths = parse_ldconfig(&["libnosuchlib_agtap_test.so"]);
        assert!(paths.is_empty());
    }

    #[test]
    fn parse_ldconfig_finds_libc() {
        // ldconfig should find at least one libc path on most systems.
        // Skip gracefully if ldconfig is not available.
        let paths = ldconfig_libc_candidates();
        if paths.is_empty() {
            return;
        }
        for p in &paths {
            assert!(
                p.exists(),
                "ldconfig libc path does not exist: {}",
                p.display()
            );
        }
    }

    #[test]
    fn find_ldconfig_libc_paths_excludes_known() {
        let Ok(libc) = find_system_libc() else { return };
        let canon = libc.canonicalize().unwrap_or(libc);
        let mut known = HashSet::new();
        known.insert(canon.clone());
        let extras = find_ldconfig_libc_paths(&known);
        for path in &extras {
            assert_ne!(path, &canon, "primary libc in ldconfig extras list");
        }
    }

    #[test]
    fn find_ldconfig_libssl_paths_excludes_known() {
        let Ok(libssl) = find_system_libssl() else {
            return;
        };
        let canon = libssl.canonicalize().unwrap_or(libssl);
        let mut known = HashSet::new();
        known.insert(canon.clone());
        let extras = find_ldconfig_libssl_paths(&known);
        for path in &extras {
            assert_ne!(path, &canon, "primary libssl in ldconfig extras list");
        }
    }

    #[test]
    fn find_extra_libssl_paths_excludes_known() {
        let Ok(libssl) = find_system_libssl() else {
            return;
        };
        let canon = libssl.canonicalize().unwrap_or(libssl);
        let mut known = HashSet::new();
        known.insert(canon.clone());
        let extras = find_extra_libssl_paths(&known);
        for path in &extras {
            assert_ne!(path, &canon, "primary libssl in extras list");
        }
    }

    #[test]
    fn find_extra_libc_paths_excludes_known() {
        let Ok(libc) = find_system_libc() else { return };
        let canon = libc.canonicalize().unwrap_or(libc);
        let mut known = HashSet::new();
        known.insert(canon.clone());
        let extras = find_extra_libc_paths(&known);
        for path in &extras {
            assert_ne!(path, &canon, "primary libc in extras list");
        }
    }

    #[test]
    fn find_ssl_binaries_excludes_known() {
        let Ok(libssl) = find_system_libssl() else {
            return;
        };
        let canon = libssl.canonicalize().unwrap_or(libssl);
        let mut known = HashSet::new();
        known.insert(canon);
        let bins = find_ssl_binaries(&known);
        // None of the returned binaries should be the system libssl
        for path in &bins {
            assert!(
                !path.to_string_lossy().contains("libssl"),
                "found libssl in binary list: {}",
                path.display()
            );
        }
    }
}
