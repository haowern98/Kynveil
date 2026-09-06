//! Generates Rust Protobuf bindings from Kynveil's canonical IPC schema.

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("KYNVEIL_SQLCIPHER_CONTROLLED").as_deref() != Ok("1")
        || std::env::var_os("SQLCIPHER_LIB_DIR").is_none()
        || std::env::var("SQLCIPHER_STATIC").as_deref() != Ok("1")
    {
        return Err("Kynveil requires the controlled SQLCipher build wrapper".into());
    }
    let native_directory = std::env::var("SQLCIPHER_LIB_DIR")?;
    let native_directory = Path::new(&native_directory);
    let target_os = std::env::var("CARGO_CFG_TARGET_OS")?;
    let (sqlcipher, crypto) = if target_os == "windows" {
        ("sqlcipher.lib", "libcrypto.lib")
    } else {
        ("libsqlcipher.a", "libcrypto.a")
    };
    if !native_directory.join(sqlcipher).is_file() || !native_directory.join(crypto).is_file() {
        return Err("controlled SQLCipher and libcrypto artifacts are required".into());
    }
    println!(
        "cargo::rustc-link-search=native={}",
        native_directory.display()
    );
    println!("cargo::rustc-link-lib=static=sqlcipher");
    println!(
        "cargo::rustc-link-lib=static={}",
        if target_os == "windows" {
            "libcrypto"
        } else {
            "crypto"
        }
    );
    if target_os == "windows" {
        for library in ["gdi32", "user32", "crypt32", "ws2_32", "advapi32"] {
            println!("cargo::rustc-link-lib=dylib={library}");
        }
    }
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.compile_protos(&["../../proto/kynveil/ipc/v1/ipc.proto"], &["../../proto"])?;
    println!("cargo::rerun-if-changed=../../proto/kynveil/ipc/v1/ipc.proto");
    Ok(())
}
