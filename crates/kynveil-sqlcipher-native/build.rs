//! Builds the reviewed `SQLCipher` source against Kynveil's vendored OpenSSL.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const SOURCE_DIGEST: &str = "31951158488fa3542f1037ff26cb203513075e793f0739975a9a9da22294a305";
const SQLITE_VERSION: &str = "3.53.4";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed=KYNVEIL_SQLCIPHER_SOURCE_DIR");
    println!("cargo::rerun-if-env-changed=KYNVEIL_SQLCIPHER_BUILD_DIR");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_INCLUDE");

    let source = verified_source_directory()?;
    let build_source = controlled_build_directory(&source)?;
    let openssl_include = PathBuf::from(env::var("DEP_OPENSSL_INCLUDE")?);
    if !openssl_include.join("openssl").join("evp.h").is_file() {
        return Err("vendored OpenSSL headers are unavailable".into());
    }

    let compiler = cc::Build::new().get_compiler();
    generate_amalgamation(&build_source, &compiler)?;

    let mut build = cc::Build::new();
    build
        .file(build_source.join("sqlite3.c"))
        .include(&build_source)
        .include(build_source.join("src"))
        .include(&openssl_include)
        .flag("-DSQLITE_CORE")
        .flag("-DSQLITE_DEFAULT_FOREIGN_KEYS=1")
        .flag("-DSQLITE_ENABLE_API_ARMOR")
        .flag("-DSQLITE_ENABLE_COLUMN_METADATA")
        .flag("-DSQLITE_ENABLE_DBSTAT_VTAB")
        .flag("-DSQLITE_ENABLE_FTS3")
        .flag("-DSQLITE_ENABLE_FTS3_PARENTHESIS")
        .flag("-DSQLITE_ENABLE_FTS5")
        .flag("-DSQLITE_ENABLE_JSON1")
        .flag("-DSQLITE_ENABLE_LOAD_EXTENSION=1")
        .flag("-DSQLITE_ENABLE_MEMORY_MANAGEMENT")
        .flag("-DSQLITE_ENABLE_RTREE")
        .flag("-DSQLITE_ENABLE_STAT4")
        .flag("-DSQLITE_SOUNDEX")
        .flag("-DSQLITE_THREADSAFE=1")
        .flag("-DSQLITE_USE_URI")
        .flag("-DSQLITE_HAS_CODEC")
        .flag("-DSQLITE_TEMP_STORE=2")
        .flag("-DSQLITE_EXTRA_INIT=sqlcipher_extra_init")
        .flag("-DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown")
        .flag("-DHAVE_STDINT_H=1")
        .flag("-DHAVE_USLEEP=1")
        .flag("-DHAVE_ISNAN")
        .flag("-D_POSIX_THREAD_SAFE_FUNCTIONS")
        .flag("-DSQLCIPHER_CRYPTO_OPENSSL")
        .warnings(false)
        .cargo_metadata(false)
        .compile("sqlcipher");

    write_artifact_manifest(&openssl_include)?;
    Ok(())
}

fn verified_source_directory() -> Result<PathBuf, Box<dyn Error>> {
    let source = PathBuf::from(env::var("KYNVEIL_SQLCIPHER_SOURCE_DIR")?);
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("cannot locate workspace root")?;
    let expected = workspace
        .join("target")
        .join("kynveil-native")
        .join("sqlcipher")
        .join("4.18.0")
        .join(format!("source-{SOURCE_DIGEST}"));
    if source.canonicalize()? != expected.canonicalize()? {
        return Err("SQLCipher source is not in Kynveil's verified build cache".into());
    }
    if fs::read_to_string(source.join("VERSION"))?.trim() != SQLITE_VERSION {
        return Err("reviewed SQLCipher source has an unexpected SQLite baseline".into());
    }
    if !source.join("LICENSE.md").is_file()
        || !source.join("Makefile.msc").is_file()
        || !source.join("configure").is_file()
        || !source.join("src").join("sqlcipher.c").is_file()
        || source.join("sqlite3.c").is_file()
    {
        return Err("reviewed SQLCipher source tree is incomplete".into());
    }
    Ok(source)
}

fn controlled_build_directory(source: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let build = PathBuf::from(env::var("KYNVEIL_SQLCIPHER_BUILD_DIR")?);
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("cannot locate workspace root")?;
    let expected_root = workspace
        .join("target")
        .join("kynveil-native")
        .join("sqlcipher")
        .join("4.18.0")
        .join("build")
        .canonicalize()?;
    let canonical_build = build.canonicalize()?;
    let target = canonical_build
        .strip_prefix(&expected_root)
        .map_err(|_| "SQLCipher build source is outside Kynveil's controlled build output")?;
    if target.components().count() != 1 || canonical_build == source.canonicalize()? {
        return Err("SQLCipher build source must be a target-specific copy".into());
    }
    if !build.join("configure").is_file() || !build.join("src").join("sqlcipher.c").is_file() {
        return Err("controlled SQLCipher build source tree is incomplete".into());
    }
    Ok(build)
}

fn generate_amalgamation(source: &Path, compiler: &cc::Tool) -> Result<(), Box<dyn Error>> {
    if source.join("sqlite3.c").is_file() {
        return Ok(());
    }
    let target = env::var("TARGET")?;
    let mut command = if target.contains("windows-msvc") {
        let compiler_directory = compiler
            .path()
            .parent()
            .ok_or("MSVC compiler path has no parent")?;
        let nmake = compiler_directory.join("nmake.exe");
        let build_tools = compiler
            .path()
            .ancestors()
            .nth(8)
            .ok_or("cannot locate Visual Studio Build Tools")?;
        let developer_command = build_tools
            .join("Common7")
            .join("Tools")
            .join("VsDevCmd.bat");
        if !nmake.is_file() || !developer_command.is_file() {
            return Err("the required MSVC nmake or developer command is unavailable".into());
        }
        let launcher = PathBuf::from(env::var("OUT_DIR")?).join("generate-sqlcipher.cmd");
        fs::write(
            &launcher,
            format!(
                "@echo off\r\ncall \"{}\" -arch=x64 -host_arch=x64 >nul || exit /b 1\r\ncd /d \"{}\" || exit /b 1\r\n\"{}\" /nologo /f Makefile.msc DEBUG=0 sqlite3.c\r\n",
                developer_command.display(),
                source.display(),
                nmake.display()
            ),
        )?;
        Command::new(launcher)
    } else {
        let mut configure = Command::new(source.join("configure"));
        configure
            .arg("--disable-shared")
            .arg("--enable-static")
            .current_dir(source);
        if !configure.status()?.success() {
            return Err("the official SQLCipher source failed to configure".into());
        }
        let mut make = Command::new("make");
        make.arg("sqlite3.c").current_dir(source);
        make
    };
    if !command.status()?.success() || !source.join("sqlite3.c").is_file() {
        return Err("the official SQLCipher source failed to generate sqlite3.c".into());
    }
    Ok(())
}

fn write_artifact_manifest(openssl_include: &Path) -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(env::var("OUT_DIR")?);
    let target = env::var("TARGET")?;
    let library_name = if target.contains("msvc") {
        "sqlcipher.lib"
    } else {
        "libsqlcipher.a"
    };
    let library = output.join(library_name);
    if !library.is_file() {
        return Err("controlled SQLCipher static library was not produced".into());
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("cannot locate workspace root")?;
    let artifact_directory = workspace
        .join("target")
        .join("kynveil-native")
        .join("sqlcipher")
        .join("4.18.0")
        .join(&target);
    fs::create_dir_all(&artifact_directory)?;
    fs::copy(&library, artifact_directory.join(library_name))?;
    let crypto_name = if target.contains("msvc") {
        "libcrypto.lib"
    } else {
        "libcrypto.a"
    };
    let openssl_install = openssl_include
        .parent()
        .ok_or("vendored OpenSSL include path has no install root")?;
    let crypto_library = openssl_install.join("lib").join(crypto_name);
    if !crypto_library.is_file() {
        return Err("vendored OpenSSL static libcrypto archive is unavailable".into());
    }
    fs::copy(crypto_library, artifact_directory.join(crypto_name))?;
    let manifest = format!(
        "{{\"libDirectory\":{},\"target\":{}}}",
        serde_json_string(&artifact_directory.display().to_string()),
        serde_json_string(&target)
    );
    fs::write(
        artifact_directory
            .parent()
            .ok_or("artifact directory has no parent")?
            .join("artifact.json"),
        manifest,
    )?;
    Ok(())
}

fn serde_json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
