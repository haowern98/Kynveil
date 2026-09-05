use std::{
    ffi::c_int,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use hkdf::Hkdf;
use rusqlite::{Connection, OpenFlags, params};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::profile_path::ProfilePaths;

const CURRENT_SCHEMA_VERSION: u32 = 1;
const DATABASE_KEY_EPOCH: u64 = 1;
const DATABASE_KEY_INFO_PREFIX: &[u8] = b"kynveil/v1/local-database/";
const METADATA_MAGIC: [u8; 4] = *b"KVPM";
const METADATA_VERSION: u8 = 1;
const METADATA_LENGTH: usize = 36;
const EXPECTED_CIPHER_VERSION: &str = "4.18.0 community";

/// Non-secret lifecycle state recorded both beside and inside the encrypted profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionState {
    /// The profile has no pending storage transition.
    Stable,
}

impl TransitionState {
    fn encoded(self) -> u8 {
        match self {
            Self::Stable => 0,
        }
    }

    fn decode(value: u8) -> Result<Self, StorageError> {
        match value {
            0 => Ok(Self::Stable),
            _ => Err(StorageError::MalformedMetadata),
        }
    }
}

/// Versioned, non-secret metadata required to derive and validate the database key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProfileMetadata {
    pub(crate) profile_id: [u8; 16],
    pub(crate) db_key_epoch: u64,
    pub(crate) schema_version: u32,
    pub(crate) transition: TransitionState,
}

impl ProfileMetadata {
    pub(crate) fn initial(profile_id: [u8; 16]) -> Self {
        Self {
            profile_id,
            db_key_epoch: DATABASE_KEY_EPOCH,
            schema_version: CURRENT_SCHEMA_VERSION,
            transition: TransitionState::Stable,
        }
    }

    fn encode(self) -> [u8; METADATA_LENGTH] {
        let mut encoded = [0_u8; METADATA_LENGTH];
        encoded[..4].copy_from_slice(&METADATA_MAGIC);
        encoded[4] = METADATA_VERSION;
        encoded[5] = self.transition.encoded();
        encoded[8..24].copy_from_slice(&self.profile_id);
        encoded[24..32].copy_from_slice(&self.db_key_epoch.to_be_bytes());
        encoded[32..36].copy_from_slice(&self.schema_version.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() != METADATA_LENGTH || encoded[..4] != METADATA_MAGIC {
            return Err(StorageError::MalformedMetadata);
        }
        if encoded[4] != METADATA_VERSION {
            return Err(StorageError::UnsupportedMetadata);
        }
        if encoded[6] != 0 || encoded[7] != 0 {
            return Err(StorageError::MalformedMetadata);
        }

        let mut profile_id = [0_u8; 16];
        profile_id.copy_from_slice(&encoded[8..24]);
        let db_key_epoch = u64::from_be_bytes(
            encoded[24..32]
                .try_into()
                .map_err(|_| StorageError::MalformedMetadata)?,
        );
        let schema_version = u32::from_be_bytes(
            encoded[32..36]
                .try_into()
                .map_err(|_| StorageError::MalformedMetadata)?,
        );
        if db_key_epoch == 0 || db_key_epoch > i64::MAX as u64 {
            return Err(StorageError::MalformedMetadata);
        }

        Ok(Self {
            profile_id,
            db_key_epoch,
            schema_version,
            transition: TransitionState::decode(encoded[5])?,
        })
    }
}

/// Storage failures intentionally omit paths, SQL text, plaintext, and secret values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorageError {
    MetadataIo,
    MalformedMetadata,
    UnsupportedMetadata,
    ExistingProfile,
    DatabaseIo,
    KeyApplication,
    Configuration,
    Integrity,
    CorruptProfile,
    UnsupportedSchema,
}

/// An unlocked, verified `SQLCipher` profile database owned exclusively by Rust.
pub(crate) struct OpenedDatabase {
    connection: Connection,
}

impl OpenedDatabase {
    /// Checkpoint WAL content and close the only authoritative profile connection.
    pub(crate) fn checkpoint_and_close(self) -> Result<(), StorageError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| StorageError::DatabaseIo)?;
        self.connection
            .close()
            .map_err(|_| StorageError::DatabaseIo)
    }

    #[cfg(test)]
    fn pragma_text(&self, pragma: &str) -> Result<String, StorageError> {
        self.connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .map_err(|_| StorageError::Configuration)
    }

    #[cfg(test)]
    fn pragma_integer(&self, pragma: &str) -> Result<i64, StorageError> {
        self.connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .map_err(|_| StorageError::Configuration)
    }

    #[cfg(test)]
    fn compile_option_enabled(&self, expected: &str) -> Result<bool, StorageError> {
        let mut statement = self
            .connection
            .prepare("PRAGMA compile_options")
            .map_err(|_| StorageError::Configuration)?;
        let mut rows = statement
            .query([])
            .map_err(|_| StorageError::Configuration)?;
        while let Some(row) = rows.next().map_err(|_| StorageError::Configuration)? {
            if row
                .get::<_, String>(0)
                .map_err(|_| StorageError::Configuration)?
                == expected
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    fn set_user_version_for_test(&self, version: u32) -> Result<(), StorageError> {
        self.connection
            .pragma_update(None, "user_version", version)
            .map_err(|_| StorageError::DatabaseIo)
    }

    #[cfg(test)]
    fn insert_root_identity_for_test(&self, seed: &[u8; 32]) -> Result<(), StorageError> {
        self.connection
            .execute(
                "INSERT INTO root_identity (singleton, signing_seed, public_key) VALUES (1, ?1, ?2)",
                params![seed.as_slice(), [0x55_u8; 32].as_slice()],
            )
            .map_err(|_| StorageError::DatabaseIo)?;
        Ok(())
    }
}

/// Derive the exact 32-byte `SQLCipher` key for one profile metadata epoch.
pub(crate) fn derive_database_key(
    profile_master_secret: &Zeroizing<[u8; 32]>,
    metadata: &ProfileMetadata,
) -> Zeroizing<[u8; 32]> {
    let mut info = [0_u8; DATABASE_KEY_INFO_PREFIX.len() + std::mem::size_of::<u64>()];
    info[..DATABASE_KEY_INFO_PREFIX.len()].copy_from_slice(DATABASE_KEY_INFO_PREFIX);
    info[DATABASE_KEY_INFO_PREFIX.len()..].copy_from_slice(&metadata.db_key_epoch.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(&metadata.profile_id), profile_master_secret.as_ref());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .expect("the fixed 32-byte HKDF output length is valid for SHA-256");
    key
}

/// Read exactly one bounded profile metadata record without accepting trailing data.
pub(crate) fn read_metadata(path: &Path) -> Result<ProfileMetadata, StorageError> {
    let mut file = File::open(path).map_err(|_| StorageError::MetadataIo)?;
    if file.metadata().map_err(|_| StorageError::MetadataIo)?.len()
        != u64::try_from(METADATA_LENGTH).map_err(|_| StorageError::MetadataIo)?
    {
        return Err(StorageError::MalformedMetadata);
    }
    let mut encoded = [0_u8; METADATA_LENGTH];
    file.read_exact(&mut encoded)
        .map_err(|_| StorageError::MetadataIo)?;
    ProfileMetadata::decode(&encoded)
}

/// Create a new encrypted profile database without replacing existing profile evidence.
pub(crate) fn create_database(
    paths: &ProfilePaths,
    profile_master_secret: &Zeroizing<[u8; 32]>,
    metadata: &ProfileMetadata,
) -> Result<OpenedDatabase, StorageError> {
    if profile_evidence_exists(paths)? {
        return Err(StorageError::ExistingProfile);
    }

    let key = derive_database_key(profile_master_secret, metadata);
    let connection = open_keyed_connection(
        &paths.database,
        &key,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    create_schema(&connection, metadata)?;
    verify_runtime_security(&connection)?;
    write_metadata_atomically(&paths.metadata, metadata)?;
    Ok(OpenedDatabase { connection })
}

/// Open an existing profile only after validating its bounded external metadata.
pub(crate) fn open_database(
    paths: &ProfilePaths,
    profile_master_secret: &Zeroizing<[u8; 32]>,
) -> Result<OpenedDatabase, StorageError> {
    let metadata = read_metadata(&paths.metadata)?;
    if metadata.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema);
    }
    if metadata.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(StorageError::CorruptProfile);
    }

    let key = derive_database_key(profile_master_secret, &metadata);
    let connection =
        open_keyed_connection(&paths.database, &key, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    verify_runtime_security(&connection)?;
    verify_embedded_metadata(&connection, &metadata)?;
    Ok(OpenedDatabase { connection })
}

fn profile_evidence_exists(paths: &ProfilePaths) -> Result<bool, StorageError> {
    for path in [
        &paths.metadata,
        &paths.database,
        &paths.database_wal,
        &paths.database_shm,
    ] {
        if path.try_exists().map_err(|_| StorageError::MetadataIo)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_keyed_connection(
    path: &Path,
    key: &Zeroizing<[u8; 32]>,
    flags: OpenFlags,
) -> Result<Connection, StorageError> {
    let connection =
        Connection::open_with_flags(path, flags).map_err(|_| StorageError::DatabaseIo)?;
    enable_cipher_memory_security(&connection)?;
    apply_sqlcipher_key(&connection, key)?;
    configure_connection(&connection)?;
    Ok(connection)
}

#[allow(unsafe_code)]
fn apply_sqlcipher_key(connection: &Connection, key: &[u8; 32]) -> Result<(), StorageError> {
    if key.len() != 32 {
        return Err(StorageError::KeyApplication);
    }
    let key_length = c_int::try_from(key.len()).map_err(|_| StorageError::KeyApplication)?;
    let database_name = b"main\0";
    // SAFETY:
    //
    // - Connection::handle() obtains a raw pointer from a live rusqlite Connection;
    // - connection remains borrowed and alive for the entire FFI call;
    // - key is exactly 32 bytes, remains valid for the call, and its length fits c_int;
    // - database_name is a static NUL-terminated C string for the main database;
    // - SQLCipher consumes the key during sqlite3_key_v2() and does not retain its pointer;
    // - the returned SQLite status is checked before any SQL statement is executed.
    let connection_handle = unsafe { connection.handle() };
    if connection_handle.is_null() {
        return Err(StorageError::KeyApplication);
    }
    // SAFETY: all pointer, lifetime, length, and non-retention invariants are established
    // above. This is the sole approved project-owned SQLCipher FFI bridge.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key_v2(
            connection_handle,
            database_name.as_ptr().cast(),
            key.as_ptr().cast(),
            key_length,
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err(StorageError::KeyApplication);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), StorageError> {
    verify_sqlcipher_configuration(connection)?;
    configure_sqlite_runtime(connection)
}

fn enable_cipher_memory_security(connection: &Connection) -> Result<(), StorageError> {
    connection
        .execute_batch("PRAGMA cipher_memory_security = ON;")
        .map_err(|_| StorageError::Configuration)?;
    if pragma_text(connection, "cipher_memory_security")?.trim() != "1" {
        return Err(StorageError::Configuration);
    }
    Ok(())
}

fn verify_sqlcipher_configuration(connection: &Connection) -> Result<(), StorageError> {
    if pragma_text(connection, "cipher_version")?.trim() != EXPECTED_CIPHER_VERSION
        || pragma_text(connection, "cipher_status")?.trim() != "1"
        || pragma_text(connection, "cipher_provider")? != "openssl"
        || pragma_text(connection, "cipher_provider_version")?.is_empty()
        || pragma_text(connection, "cipher_page_size")?.trim() != "4096"
        || pragma_text(connection, "kdf_iter")?.trim() != "256000"
        || pragma_text(connection, "cipher_use_hmac")?.trim() != "1"
        || pragma_text(connection, "cipher_hmac_algorithm")? != "HMAC_SHA512"
        || pragma_text(connection, "cipher_kdf_algorithm")? != "PBKDF2_HMAC_SHA512"
        || pragma_text(connection, "cipher_plaintext_header_size")?.trim() != "0"
    {
        return Err(StorageError::Configuration);
    }
    Ok(())
}

fn configure_sqlite_runtime(connection: &Connection) -> Result<(), StorageError> {
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(|_| StorageError::Configuration)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| StorageError::Configuration)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| StorageError::Configuration)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| StorageError::Configuration)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| StorageError::Configuration)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| StorageError::Configuration)?;
    if pragma_integer(connection, "secure_delete")? != 1
        || pragma_integer(connection, "temp_store")? != 2
        || pragma_integer(connection, "foreign_keys")? != 1
        || pragma_integer(connection, "trusted_schema")? != 0
        || !journal_mode.eq_ignore_ascii_case("wal")
        || pragma_integer(connection, "synchronous")? != 2
    {
        return Err(StorageError::Configuration);
    }
    Ok(())
}

fn create_schema(connection: &Connection, metadata: &ProfileMetadata) -> Result<(), StorageError> {
    connection
        .execute_batch(
            "
            BEGIN IMMEDIATE;
            CREATE TABLE profile_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                profile_id BLOB NOT NULL CHECK (length(profile_id) = 16),
                db_key_epoch INTEGER NOT NULL CHECK (db_key_epoch > 0),
                schema_version INTEGER NOT NULL,
                transition INTEGER NOT NULL CHECK (transition = 0)
            );
            CREATE TABLE root_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                signing_seed BLOB NOT NULL CHECK (length(signing_seed) = 32),
                public_key BLOB NOT NULL CHECK (length(public_key) = 32)
            );
            CREATE TABLE device_identity (
                device_id BLOB PRIMARY KEY CHECK (length(device_id) = 16),
                signing_seed BLOB NOT NULL CHECK (length(signing_seed) = 32),
                credential BLOB NOT NULL CHECK (length(credential) = 132),
                credential_signature BLOB NOT NULL CHECK (length(credential_signature) = 64)
            );
            COMMIT;
            ",
        )
        .map_err(|_| StorageError::DatabaseIo)?;
    connection
        .execute(
            "INSERT INTO profile_metadata (singleton, profile_id, db_key_epoch, schema_version, transition) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                metadata.profile_id.as_slice(),
                i64::try_from(metadata.db_key_epoch).map_err(|_| StorageError::DatabaseIo)?,
                metadata.schema_version,
                i64::from(metadata.transition.encoded()),
            ],
        )
        .map_err(|_| StorageError::DatabaseIo)?;
    connection
        .pragma_update(None, "user_version", metadata.schema_version)
        .map_err(|_| StorageError::DatabaseIo)
}

fn verify_runtime_security(connection: &Connection) -> Result<(), StorageError> {
    connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::CorruptProfile)?;
    let provider = pragma_text(connection, "cipher_provider")?;
    let cipher_version = pragma_text(connection, "cipher_version")?;
    let cipher_status = pragma_text(connection, "cipher_status")?;
    let page_size = pragma_text(connection, "cipher_page_size")?;
    let kdf_iterations = pragma_text(connection, "kdf_iter")?;
    let hmac_algorithm = pragma_text(connection, "cipher_hmac_algorithm")?;
    let kdf_algorithm = pragma_text(connection, "cipher_kdf_algorithm")?;
    let plaintext_header_size = pragma_text(connection, "cipher_plaintext_header_size")?;
    let memory_security = pragma_text(connection, "cipher_memory_security")?;
    let secure_delete = pragma_integer(connection, "secure_delete")?;
    let foreign_keys = pragma_integer(connection, "foreign_keys")?;
    let trusted_schema = pragma_integer(connection, "trusted_schema")?;
    let journal_mode = pragma_text(connection, "journal_mode")?;
    let synchronous = pragma_integer(connection, "synchronous")?;
    let temp_store = pragma_integer(connection, "temp_store")?;
    let compiled_temp_store = compile_option_enabled(connection, "TEMP_STORE=2")?;
    if provider != "openssl"
        || cipher_version.trim() != EXPECTED_CIPHER_VERSION
        || cipher_status != "1"
        || page_size.trim() != "4096"
        || kdf_iterations.trim() != "256000"
        || hmac_algorithm != "HMAC_SHA512"
        || kdf_algorithm != "PBKDF2_HMAC_SHA512"
        || plaintext_header_size.trim() != "0"
        || memory_security.trim() != "1"
        || secure_delete != 1
        || foreign_keys != 1
        || trusted_schema != 0
        || !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || temp_store != 2
        || !compiled_temp_store
    {
        return Err(StorageError::Configuration);
    }
    verify_cipher_integrity(connection)
}

fn pragma_text(connection: &Connection, pragma: &str) -> Result<String, StorageError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| StorageError::Configuration)
}

fn pragma_integer(connection: &Connection, pragma: &str) -> Result<i64, StorageError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| StorageError::Configuration)
}

fn compile_option_enabled(connection: &Connection, expected: &str) -> Result<bool, StorageError> {
    let mut statement = connection
        .prepare("PRAGMA compile_options")
        .map_err(|_| StorageError::Configuration)?;
    let mut rows = statement
        .query([])
        .map_err(|_| StorageError::Configuration)?;
    while let Some(row) = rows.next().map_err(|_| StorageError::Configuration)? {
        if row
            .get::<_, String>(0)
            .map_err(|_| StorageError::Configuration)?
            == expected
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_cipher_integrity(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|_| StorageError::Integrity)?;
    let mut rows = statement.query([]).map_err(|_| StorageError::Integrity)?;
    if rows.next().map_err(|_| StorageError::Integrity)?.is_some() {
        return Err(StorageError::Integrity);
    }
    Ok(())
}

fn verify_embedded_metadata(
    connection: &Connection,
    expected: &ProfileMetadata,
) -> Result<(), StorageError> {
    let database_schema_version = connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
        .map_err(|_| StorageError::CorruptProfile)?;
    if database_schema_version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema);
    }
    if database_schema_version != expected.schema_version {
        return Err(StorageError::CorruptProfile);
    }

    let actual = connection
        .query_row(
            "SELECT profile_id, db_key_epoch, schema_version, transition FROM profile_metadata WHERE singleton = 1",
            [],
            |row| {
                let profile_id = row.get::<_, Vec<u8>>(0)?;
                let db_key_epoch = row.get::<_, i64>(1)?;
                let schema_version = row.get::<_, u32>(2)?;
                let transition = row.get::<_, u8>(3)?;
                Ok((profile_id, db_key_epoch, schema_version, transition))
            },
        )
        .map_err(|_| StorageError::CorruptProfile)?;
    let profile_id: [u8; 16] = actual
        .0
        .try_into()
        .map_err(|_| StorageError::CorruptProfile)?;
    let actual = ProfileMetadata {
        profile_id,
        db_key_epoch: u64::try_from(actual.1).map_err(|_| StorageError::CorruptProfile)?,
        schema_version: actual.2,
        transition: TransitionState::decode(actual.3).map_err(|_| StorageError::CorruptProfile)?,
    };
    if actual.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema);
    }
    if actual != *expected {
        return Err(StorageError::CorruptProfile);
    }
    Ok(())
}

fn write_metadata_atomically(path: &Path, metadata: &ProfileMetadata) -> Result<(), StorageError> {
    let file_name = path.file_name().ok_or(StorageError::MetadataIo)?;
    let temporary_path = path.with_file_name(format!("{}.new", file_name.to_string_lossy()));
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|_| StorageError::MetadataIo)?;
    temporary
        .write_all(&metadata.encode())
        .and_then(|()| temporary.sync_all())
        .map_err(|_| StorageError::MetadataIo)?;
    drop(temporary);
    fs::rename(&temporary_path, path).map_err(|_| StorageError::MetadataIo)?;
    sync_metadata_parent(path)
}

#[cfg(unix)]
fn sync_metadata_parent(path: &Path) -> Result<(), StorageError> {
    File::open(path.parent().ok_or(StorageError::MetadataIo)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StorageError::MetadataIo)
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "keeps the metadata durability helper signature consistent across targets"
)]
fn sync_metadata_parent(_: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::Connection;
    use zeroize::Zeroizing;

    use crate::profile_path::ProfilePaths;

    use super::{
        ProfileMetadata, StorageError, apply_sqlcipher_key, create_database, derive_database_key,
        open_database, pragma_text, read_metadata,
    };

    const TEST_PROFILE_MASTER_SECRET: [u8; 32] = [0x0b; 32];
    const TEST_PROFILE_ID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const TEST_DATABASE_KEY: [u8; 32] = [
        0x17, 0xd6, 0xd4, 0xa0, 0x4e, 0x96, 0x75, 0xaa, 0x3b, 0x2e, 0x7e, 0xbd, 0xc4, 0x09, 0x2e,
        0x12, 0x61, 0x89, 0x27, 0xa5, 0x0a, 0xf2, 0x90, 0x46, 0xa9, 0x79, 0x5c, 0xce, 0xac, 0x00,
        0xb3, 0xb1,
    ];

    struct TestProfile {
        root: PathBuf,
        paths: ProfilePaths,
    }

    impl TestProfile {
        fn new() -> Self {
            let mut nonce = [0_u8; 8];
            getrandom::fill(&mut nonce).unwrap();
            let root = std::env::temp_dir().join(format!(
                "kynveil-storage-test-{}-{}",
                std::process::id(),
                u64::from_be_bytes(nonce)
            ));
            fs::create_dir(&root).unwrap();
            let paths = ProfilePaths::from_user_data_root(&root).unwrap();
            Self { root, paths }
        }
    }

    impl Drop for TestProfile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn metadata() -> ProfileMetadata {
        ProfileMetadata::initial(TEST_PROFILE_ID)
    }

    fn test_secret() -> Zeroizing<[u8; 32]> {
        Zeroizing::new(TEST_PROFILE_MASTER_SECRET)
    }

    #[test]
    fn probes_sqlcipher_configuration_in_required_order() {
        let profile = TestProfile::new();
        let connection = Connection::open(&profile.paths.database).unwrap();

        eprintln!("CONFIG STEP 01: cipher_memory_security");
        connection
            .execute_batch("PRAGMA cipher_memory_security = ON;")
            .expect("cipher_memory_security setter");
        assert_eq!(
            pragma_text(&connection, "cipher_memory_security").unwrap(),
            "1"
        );

        eprintln!("CONFIG STEP 02: sqlite3_key_v2");
        let key = derive_database_key(&test_secret(), &metadata());
        apply_sqlcipher_key(&connection, &key).expect("sqlite3_key_v2");

        eprintln!("CONFIG STEP 03: cipher_version");
        assert_eq!(
            pragma_text(&connection, "cipher_version").unwrap().trim(),
            "4.18.0 community"
        );
        eprintln!("CONFIG STEP 04: cipher_status");
        assert_eq!(pragma_text(&connection, "cipher_status").unwrap(), "1");
        eprintln!("CONFIG STEP 05: cipher_provider");
        assert_eq!(
            pragma_text(&connection, "cipher_provider").unwrap(),
            "openssl"
        );
        eprintln!("CONFIG STEP 06: cipher_provider_version");
        assert!(
            !pragma_text(&connection, "cipher_provider_version")
                .unwrap()
                .is_empty()
        );
        eprintln!("CONFIG STEP 07: SQLCipher 4 defaults");
        assert_eq!(
            pragma_text(&connection, "cipher_page_size").unwrap().trim(),
            "4096"
        );
        assert_eq!(
            pragma_text(&connection, "kdf_iter").unwrap().trim(),
            "256000"
        );
        assert_eq!(
            pragma_text(&connection, "cipher_use_hmac").unwrap().trim(),
            "1"
        );
        assert_eq!(
            pragma_text(&connection, "cipher_hmac_algorithm").unwrap(),
            "HMAC_SHA512"
        );
        assert_eq!(
            pragma_text(&connection, "cipher_kdf_algorithm").unwrap(),
            "PBKDF2_HMAC_SHA512"
        );
        assert_eq!(
            pragma_text(&connection, "cipher_plaintext_header_size")
                .unwrap()
                .trim(),
            "0"
        );
    }

    #[test]
    fn derives_the_frozen_hkdf_sha256_database_key() {
        assert_eq!(
            *derive_database_key(&test_secret(), &metadata()),
            TEST_DATABASE_KEY
        );
    }

    #[test]
    fn round_trips_and_rejects_malformed_profile_metadata() {
        let metadata = metadata();
        let encoded = metadata.encode();

        assert_eq!(ProfileMetadata::decode(&encoded).unwrap(), metadata);
        assert_eq!(
            ProfileMetadata::decode(&encoded[..encoded.len() - 1]),
            Err(StorageError::MalformedMetadata)
        );

        let mut unsupported_version = encoded;
        unsupported_version[4] = 2;
        assert_eq!(
            ProfileMetadata::decode(&unsupported_version),
            Err(StorageError::UnsupportedMetadata)
        );

        let mut nonzero_reserved = encoded;
        nonzero_reserved[6] = 1;
        assert_eq!(
            ProfileMetadata::decode(&nonzero_reserved),
            Err(StorageError::MalformedMetadata)
        );
    }

    #[test]
    fn creates_and_reopens_an_encrypted_database() {
        let profile = TestProfile::new();
        let metadata = metadata();
        let database = create_database(&profile.paths, &test_secret(), &metadata).unwrap();
        database.checkpoint_and_close().unwrap();

        assert_eq!(read_metadata(&profile.paths.metadata).unwrap(), metadata);
        assert!(open_database(&profile.paths, &test_secret()).is_ok());
    }

    #[test]
    fn rejects_unkeyed_and_wrong_key_database_access() {
        let profile = TestProfile::new();
        let metadata = metadata();
        let database = create_database(&profile.paths, &test_secret(), &metadata).unwrap();
        database.checkpoint_and_close().unwrap();

        let unkeyed = rusqlite::Connection::open(&profile.paths.database).unwrap();
        assert!(
            unkeyed
                .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
                    .get::<_, i64>(0))
                .is_err()
        );
        drop(unkeyed);

        assert!(open_database(&profile.paths, &Zeroizing::new([0x44; 32]),).is_err());
    }

    #[test]
    fn verifies_the_required_sqlcipher_and_sqlite_runtime_settings() {
        let profile = TestProfile::new();
        let database = create_database(&profile.paths, &test_secret(), &metadata()).unwrap();

        assert_eq!(database.pragma_text("cipher_provider").unwrap(), "openssl");
        assert!(!database.pragma_text("cipher_version").unwrap().is_empty());
        assert_eq!(database.pragma_text("cipher_status").unwrap(), "1");
        assert_eq!(
            database.pragma_text("cipher_page_size").unwrap().trim(),
            "4096"
        );
        assert_eq!(database.pragma_text("kdf_iter").unwrap().trim(), "256000");
        assert_eq!(
            database.pragma_text("cipher_hmac_algorithm").unwrap(),
            "HMAC_SHA512"
        );
        assert_eq!(
            database.pragma_text("cipher_kdf_algorithm").unwrap(),
            "PBKDF2_HMAC_SHA512"
        );
        assert_eq!(
            database
                .pragma_text("cipher_plaintext_header_size")
                .unwrap(),
            "0"
        );
        assert_eq!(database.pragma_text("cipher_memory_security").unwrap(), "1");
        assert_eq!(database.pragma_integer("secure_delete").unwrap(), 1);
        assert_eq!(database.pragma_integer("foreign_keys").unwrap(), 1);
        assert_eq!(database.pragma_integer("trusted_schema").unwrap(), 0);
        assert_eq!(database.pragma_text("journal_mode").unwrap(), "wal");
        assert_eq!(database.pragma_integer("synchronous").unwrap(), 2);
        assert_eq!(database.pragma_integer("temp_store").unwrap(), 2);
        assert!(database.compile_option_enabled("TEMP_STORE=2").unwrap());
        database.checkpoint_and_close().unwrap();
    }

    #[test]
    fn rejects_corrupt_databases_and_newer_schema_versions() {
        let profile = TestProfile::new();
        let database = create_database(&profile.paths, &test_secret(), &metadata()).unwrap();
        database.set_user_version_for_test(2).unwrap();
        database.checkpoint_and_close().unwrap();

        assert!(matches!(
            open_database(&profile.paths, &test_secret()),
            Err(StorageError::UnsupportedSchema)
        ));

        let mut bytes = fs::read(&profile.paths.database).unwrap();
        let corruption_index = bytes.len() / 2;
        bytes[corruption_index] ^= 1;
        fs::write(&profile.paths.database, bytes).unwrap();
        assert!(open_database(&profile.paths, &test_secret()).is_err());
    }

    #[test]
    fn leaves_no_known_plaintext_marker_in_database_or_journal_files() {
        const MARKER: &[u8; 32] = b"KYNVEIL-STAGE3-PLAINTEXT-MARKER!";

        let profile = TestProfile::new();
        let database = create_database(&profile.paths, &test_secret(), &metadata()).unwrap();
        database.insert_root_identity_for_test(MARKER).unwrap();

        for path in [
            &profile.paths.database,
            &profile.paths.database_wal,
            &profile.paths.database_shm,
        ] {
            if let Ok(bytes) = fs::read(path) {
                assert!(
                    !bytes.windows(MARKER.len()).any(|window| window == MARKER),
                    "plaintext marker found in {}",
                    path.display()
                );
            }
        }
        database.checkpoint_and_close().unwrap();
    }
}
