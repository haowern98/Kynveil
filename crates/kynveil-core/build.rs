//! Generates Rust Protobuf bindings from Kynveil's canonical IPC schema.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.compile_protos(&["../../proto/kynveil/ipc/v1/ipc.proto"], &["../../proto"])?;
    println!("cargo::rerun-if-changed=../../proto/kynveil/ipc/v1/ipc.proto");
    Ok(())
}
