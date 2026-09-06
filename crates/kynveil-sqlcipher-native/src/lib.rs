//! Kynveil's private, controlled `SQLCipher` native-build dependency.
//!
//! This crate deliberately exposes no SQL API. `rusqlite` remains the only
//! Rust-facing database API; the build script supplies its verified static
//! `SQLCipher` library and the vendored OpenSSL dependency.

#![deny(unsafe_code)]
