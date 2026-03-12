use std::collections::HashSet;
use std::path::PathBuf;

use aya::programs::{KProbe, UProbe};
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
