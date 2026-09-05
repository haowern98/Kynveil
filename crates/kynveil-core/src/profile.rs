use crate::{
    identity::{IdentityError, create_identity},
    keyring::{ProfileMasterSecret, ProfileMasterSecretStore, ProfileMasterSecretStoreError},
    profile_path::ProfilePaths,
    storage::{OpenedDatabase, ProfileMetadata, StorageError, create_database, open_database},
};

#[cfg(test)]
use crate::identity::IdentityRecord;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProfileLifecycleError {
    Keystore(ProfileMasterSecretStoreError),
    Storage(StorageError),
    Identity(IdentityError),
    RandomnessUnavailable,
}

pub(crate) struct ProfileLifecycle {
    database: OpenedDatabase,
}

impl ProfileLifecycle {
    pub(crate) fn open_or_create(
        paths: &ProfilePaths,
        store: &impl ProfileMasterSecretStore,
        created_at: u64,
    ) -> Result<Self, ProfileLifecycleError> {
        if profile_evidence_exists(paths)? {
            let secret = store.load().map_err(ProfileLifecycleError::Keystore)?;
            let database = open_database(paths, secret.as_zeroizing())
                .map_err(ProfileLifecycleError::Storage)?;
            database
                .load_identity()
                .map_err(ProfileLifecycleError::Storage)?;
            return Ok(Self { database });
        }

        let secret = ProfileMasterSecret::generate()
            .map_err(|_| ProfileLifecycleError::RandomnessUnavailable)?;
        store
            .store(&secret)
            .map_err(ProfileLifecycleError::Keystore)?;
        let mut profile_id = [0_u8; 16];
        if getrandom::fill(&mut profile_id).is_err() {
            let _ = store.delete();
            return Err(ProfileLifecycleError::RandomnessUnavailable);
        }
        let database = match create_database(
            paths,
            secret.as_zeroizing(),
            &ProfileMetadata::initial(profile_id),
        ) {
            Ok(database) => database,
            Err(error) => {
                let _ = store.delete();
                return Err(ProfileLifecycleError::Storage(error));
            }
        };
        let identity = match create_identity(created_at) {
            Ok(identity) => identity,
            Err(error) => {
                abandon_new_profile(paths, store, database);
                return Err(ProfileLifecycleError::Identity(error));
            }
        };
        if let Err(error) = database.store_identity(&identity) {
            abandon_new_profile(paths, store, database);
            return Err(ProfileLifecycleError::Storage(error));
        }
        Ok(Self { database })
    }

    #[cfg(test)]
    fn identity(&self) -> Result<IdentityRecord, ProfileLifecycleError> {
        self.database
            .load_identity()
            .map_err(ProfileLifecycleError::Storage)
    }

    pub(crate) fn lock(self) -> Result<(), ProfileLifecycleError> {
        self.database
            .checkpoint_and_close()
            .map_err(ProfileLifecycleError::Storage)
    }
}

fn abandon_new_profile(
    paths: &ProfilePaths,
    store: &impl ProfileMasterSecretStore,
    database: OpenedDatabase,
) {
    let _ = database.checkpoint_and_close();
    for path in [
        &paths.metadata,
        &paths.database,
        &paths.database_wal,
        &paths.database_shm,
    ] {
        let _ = std::fs::remove_file(path);
    }
    let _ = store.delete();
}

fn profile_evidence_exists(paths: &ProfilePaths) -> Result<bool, ProfileLifecycleError> {
    for path in [
        &paths.metadata,
        &paths.database,
        &paths.database_wal,
        &paths.database_shm,
    ] {
        if path
            .try_exists()
            .map_err(|_| ProfileLifecycleError::Storage(StorageError::MetadataIo))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs, path::PathBuf};

    use crate::{
        keyring::{ProfileMasterSecret, ProfileMasterSecretStore, ProfileMasterSecretStoreError},
        profile_path::ProfilePaths,
    };

    use super::ProfileLifecycle;

    struct MemoryStore(RefCell<Option<String>>);

    impl ProfileMasterSecretStore for MemoryStore {
        fn load(&self) -> Result<ProfileMasterSecret, ProfileMasterSecretStoreError> {
            self.0
                .borrow()
                .as_deref()
                .ok_or(ProfileMasterSecretStoreError::Missing)
                .and_then(|value| {
                    ProfileMasterSecret::decode(value)
                        .map_err(|_| ProfileMasterSecretStoreError::Malformed)
                })
        }

        fn store(&self, secret: &ProfileMasterSecret) -> Result<(), ProfileMasterSecretStoreError> {
            self.0.replace(Some(secret.encode()));
            Ok(())
        }

        fn delete(&self) -> Result<(), ProfileMasterSecretStoreError> {
            self.0.replace(None);
            Ok(())
        }
    }

    struct UnavailableStore;

    impl ProfileMasterSecretStore for UnavailableStore {
        fn load(&self) -> Result<ProfileMasterSecret, ProfileMasterSecretStoreError> {
            Err(ProfileMasterSecretStoreError::Unavailable)
        }

        fn store(&self, _: &ProfileMasterSecret) -> Result<(), ProfileMasterSecretStoreError> {
            Err(ProfileMasterSecretStoreError::Unavailable)
        }

        fn delete(&self) -> Result<(), ProfileMasterSecretStoreError> {
            Err(ProfileMasterSecretStoreError::Unavailable)
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut nonce = [0_u8; 8];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "kynveil-profile-test-{}-{}",
                std::process::id(),
                u64::from_be_bytes(nonce)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_then_reopens_one_persisted_identity() {
        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.0).unwrap();
        let store = MemoryStore(RefCell::new(None));
        let created = ProfileLifecycle::open_or_create(&paths, &store, 1_700_000_000).unwrap();
        let root = created.identity().unwrap().root_public_key;
        created.lock().unwrap();

        let reopened = ProfileLifecycle::open_or_create(&paths, &store, 1_700_000_001).unwrap();
        assert_eq!(reopened.identity().unwrap().root_public_key, root);
    }

    #[test]
    fn existing_profile_with_a_missing_or_invalid_pms_fails_closed() {
        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.0).unwrap();
        let store = MemoryStore(RefCell::new(None));
        let profile = ProfileLifecycle::open_or_create(&paths, &store, 1_700_000_000).unwrap();
        profile.lock().unwrap();

        store.0.replace(None);
        assert!(matches!(
            ProfileLifecycle::open_or_create(&paths, &store, 1_700_000_001),
            Err(super::ProfileLifecycleError::Keystore(
                ProfileMasterSecretStoreError::Missing
            ))
        ));
        store.0.replace(Some("not-a-pms".to_owned()));
        assert!(matches!(
            ProfileLifecycle::open_or_create(&paths, &store, 1_700_000_001),
            Err(super::ProfileLifecycleError::Keystore(
                ProfileMasterSecretStoreError::Malformed
            ))
        ));
        assert!(paths.database.is_file());
    }

    #[test]
    fn unavailable_keystore_never_creates_a_profile() {
        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.0).unwrap();

        assert!(matches!(
            ProfileLifecycle::open_or_create(&paths, &UnavailableStore, 1_700_000_000),
            Err(super::ProfileLifecycleError::Keystore(
                ProfileMasterSecretStoreError::Unavailable
            ))
        ));
        assert!(!paths.metadata.exists());
        assert!(!paths.database.exists());
    }
}
