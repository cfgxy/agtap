fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "agtap-ebpf",
            root_dir: "../agtap-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("failed to build eBPF programs");

    // aya_build watches the directory, but Cargo only detects directory-level
    // changes (entries added/removed). Watch source files explicitly so that
    // editing them triggers a rebuild of the host binary that embeds the
    // eBPF bytecode.
    println!("cargo:rerun-if-changed=../agtap-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../agtap-ebpf/Cargo.toml");
}
