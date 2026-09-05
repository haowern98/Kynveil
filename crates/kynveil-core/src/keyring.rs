use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::OnceLock;
use zeroize::Zeroizing;

const PROFILE_MASTER_SECRET_PREFIX: &str = "v1:";
const PROFILE_MASTER_SECRET_LENGTH: usize = 32;
const KEYRING_SERVICE: &str = "org.kynveil.desktop";
const KEYRING_ACCOUNT: &str = "profile-master-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileMasterSecretError {
    Malformed,
    RandomnessUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileMasterSecretStoreError {
    Missing,
    Unavailable,
    Malformed,
}

pub(crate) trait ProfileMasterSecretStore {
    fn load(&self) -> Result<ProfileMasterSecret, ProfileMasterSecretStoreError>;
    fn store(&self, secret: &ProfileMasterSecret) -> Result<(), ProfileMasterSecretStoreError>;
    fn delete(&self) -> Result<(), ProfileMasterSecretStoreError>;
}

pub(crate) struct NativeProfileMasterSecretStore;

impl ProfileMasterSecretStore for NativeProfileMasterSecretStore {
    fn load(&self) -> Result<ProfileMasterSecret, ProfileMasterSecretStoreError> {
        install_native_store()?;
        let encoded = entry()?
            .get_password()
            .map_err(|error| map_read_error(&error))?;
        ProfileMasterSecret::decode(&encoded).map_err(|_| ProfileMasterSecretStoreError::Malformed)
    }

    fn store(&self, secret: &ProfileMasterSecret) -> Result<(), ProfileMasterSecretStoreError> {
        install_native_store()?;
        entry()?
            .set_password(&secret.encode())
            .map_err(|_| ProfileMasterSecretStoreError::Unavailable)
    }

    fn delete(&self) -> Result<(), ProfileMasterSecretStoreError> {
        install_native_store()?;
        entry()?
            .delete_credential()
            .map_err(|error| map_delete_error(&error))
    }
}

fn install_native_store() -> Result<(), ProfileMasterSecretStoreError> {
    static INSTALLED: OnceLock<Result<(), ()>> = OnceLock::new();
    match INSTALLED.get_or_init(|| {
        #[cfg(target_os = "windows")]
        let store = windows_native_keyring_store::Store::new();
        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::Store::new();
        #[cfg(target_os = "linux")]
        let store = zbus_secret_service_keyring_store::Store::new();
        store
            .map(|store| keyring_core::set_default_store(store))
            .map_err(|_| ())
    }) {
        Ok(()) => Ok(()),
        Err(()) => Err(ProfileMasterSecretStoreError::Unavailable),
    }
}

fn entry() -> Result<keyring_core::Entry, ProfileMasterSecretStoreError> {
    #[cfg(target_os = "windows")]
    {
        let modifiers = windows_entry_modifiers();
        keyring_core::Entry::new_with_modifiers(KEYRING_SERVICE, KEYRING_ACCOUNT, &modifiers)
            .map_err(|_| ProfileMasterSecretStoreError::Unavailable)
    }
    #[cfg(not(target_os = "windows"))]
    keyring_core::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|_| ProfileMasterSecretStoreError::Unavailable)
}

#[cfg(target_os = "windows")]
fn windows_entry_modifiers() -> std::collections::HashMap<&'static str, &'static str> {
    std::collections::HashMap::from([("persistence", "Local")])
}

fn map_read_error(error: &keyring_core::Error) -> ProfileMasterSecretStoreError {
    if matches!(error, keyring_core::Error::NoEntry) {
        ProfileMasterSecretStoreError::Missing
    } else {
        ProfileMasterSecretStoreError::Unavailable
    }
}

fn map_delete_error(error: &keyring_core::Error) -> ProfileMasterSecretStoreError {
    map_read_error(error)
}

/// A Rust-owned PMS decoded from the one approved keystore representation.
pub(crate) struct ProfileMasterSecret(Zeroizing<[u8; PROFILE_MASTER_SECRET_LENGTH]>);

impl ProfileMasterSecret {
    pub(crate) fn generate() -> Result<Self, ProfileMasterSecretError> {
        let mut secret = [0_u8; PROFILE_MASTER_SECRET_LENGTH];
        getrandom::fill(&mut secret)
            .map_err(|_| ProfileMasterSecretError::RandomnessUnavailable)?;
        Ok(Self(Zeroizing::new(secret)))
    }

    pub(crate) fn decode(encoded: &str) -> Result<Self, ProfileMasterSecretError> {
        let encoded = encoded
            .strip_prefix(PROFILE_MASTER_SECRET_PREFIX)
            .ok_or(ProfileMasterSecretError::Malformed)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ProfileMasterSecretError::Malformed)?;
        let secret: [u8; PROFILE_MASTER_SECRET_LENGTH] = decoded
            .try_into()
            .map_err(|_| ProfileMasterSecretError::Malformed)?;
        Ok(Self(Zeroizing::new(secret)))
    }

    pub(crate) fn encode(&self) -> String {
        format!(
            "{PROFILE_MASTER_SECRET_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.0.as_ref())
        )
    }

    pub(crate) fn as_zeroizing(&self) -> &Zeroizing<[u8; PROFILE_MASTER_SECRET_LENGTH]> {
        &self.0
    }

    #[cfg(test)]
    fn as_bytes(&self) -> &[u8; PROFILE_MASTER_SECRET_LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::ProfileMasterSecret;

    #[test]
    fn accepts_only_the_exact_versioned_32_byte_secret_encoding() {
        let secret =
            ProfileMasterSecret::decode("v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
        assert_eq!(secret.as_bytes(), &(0_u8..32).collect::<Vec<_>>()[..]);
        assert!(ProfileMasterSecret::decode("v1:not-base64").is_err());
        assert!(
            ProfileMasterSecret::decode("v2:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").is_err()
        );
        assert!(ProfileMasterSecret::decode("v1:AA").is_err());
    }

    #[test]
    fn generates_a_round_trippable_versioned_secret() {
        let generated = ProfileMasterSecret::generate().unwrap();
        let encoded = generated.encode();

        assert!(encoded.starts_with("v1:"));
        assert_eq!(
            ProfileMasterSecret::decode(&encoded).unwrap().as_bytes(),
            generated.as_bytes()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn requests_local_windows_credential_persistence() {
        assert_eq!(
            super::windows_entry_modifiers().get("persistence"),
            Some(&"Local")
        );
    }
}
