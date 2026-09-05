use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, Zeroizing};

const DEVICE_CREDENTIAL_DOMAIN: &[u8] = b"kynveil/v1/device-credential";
const DEVICE_CREDENTIAL_VERSION: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityError {
    RandomnessUnavailable,
    MalformedCredential,
    InvalidSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceCredential {
    pub(crate) version: u64,
    pub(crate) user_root_id: [u8; 32],
    pub(crate) device_id: [u8; 16],
    pub(crate) device_signing_public_key: [u8; 32],
    pub(crate) mls_signing_key_binding: [u8; 32],
    pub(crate) created_at: u64,
}

pub(crate) struct IdentityRecord {
    // Persistable secret bytes. A `SigningKey` is reconstructed only for a
    // root-authority operation and is not retained in this record.
    pub(crate) root_signing_seed: Zeroizing<[u8; 32]>,
    pub(crate) root_public_key: [u8; 32],
    pub(crate) device_signing_seed: Zeroizing<[u8; 32]>,
    pub(crate) device_credential: DeviceCredential,
    pub(crate) device_credential_signature: [u8; 64],
}

pub(crate) fn create_identity(created_at: u64) -> Result<IdentityRecord, IdentityError> {
    let root_signing_key = generate_signing_key()?;
    let root_signing_seed = Zeroizing::new(root_signing_key.to_bytes());
    let root_public_key = root_signing_key.verifying_key().to_bytes();
    drop(root_signing_key);

    let device_signing_key = generate_signing_key()?;
    let device_signing_seed = Zeroizing::new(device_signing_key.to_bytes());
    let device_public_key = device_signing_key.verifying_key().to_bytes();
    drop(device_signing_key);

    let mut device_id = [0_u8; 16];
    getrandom::fill(&mut device_id).map_err(|_| IdentityError::RandomnessUnavailable)?;
    let device_credential = DeviceCredential {
        version: DEVICE_CREDENTIAL_VERSION,
        user_root_id: root_public_key,
        device_id,
        device_signing_public_key: device_public_key,
        mls_signing_key_binding: device_public_key,
        created_at,
    };
    let device_credential_signature =
        sign_device_credential(&root_signing_seed, &device_credential)?;

    Ok(IdentityRecord {
        root_signing_seed,
        root_public_key,
        device_signing_seed,
        device_credential,
        device_credential_signature,
    })
}

fn generate_signing_key() -> Result<SigningKey, IdentityError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| IdentityError::RandomnessUnavailable)?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key)
}

pub(crate) fn encode_device_credential(
    credential: &DeviceCredential,
) -> Result<Vec<u8>, IdentityError> {
    validate_credential(credential)?;

    let mut encoder = Encoder::new(Vec::with_capacity(132));
    encoder
        .map(6)
        .map_err(|_| IdentityError::MalformedCredential)?;
    encoder
        .u64(0)
        .and_then(|encoder| encoder.u64(credential.version))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(&credential.user_root_id))
        .and_then(|encoder| encoder.u64(2))
        .and_then(|encoder| encoder.bytes(&credential.device_id))
        .and_then(|encoder| encoder.u64(3))
        .and_then(|encoder| encoder.bytes(&credential.device_signing_public_key))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.bytes(&credential.mls_signing_key_binding))
        .and_then(|encoder| encoder.u64(5))
        .and_then(|encoder| encoder.u64(credential.created_at))
        .map_err(|_| IdentityError::MalformedCredential)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_device_credential(encoded: &[u8]) -> Result<DeviceCredential, IdentityError> {
    let mut decoder = Decoder::new(encoded);
    let Some(field_count) = decoder
        .map()
        .map_err(|_| IdentityError::MalformedCredential)?
    else {
        return Err(IdentityError::MalformedCredential);
    };
    if field_count != 6 {
        return Err(IdentityError::MalformedCredential);
    }

    let mut seen = 0_u8;
    let mut version = None;
    let mut user_root_id = None;
    let mut device_id = None;
    let mut device_signing_public_key = None;
    let mut mls_signing_key_binding = None;
    let mut created_at = None;

    for _ in 0..6 {
        let field = decoder
            .u64()
            .map_err(|_| IdentityError::MalformedCredential)?;
        let bit = match field {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            4 => 16,
            5 => 32,
            _ => return Err(IdentityError::MalformedCredential),
        };
        if seen & bit != 0 {
            return Err(IdentityError::MalformedCredential);
        }
        seen |= bit;

        match field {
            0 => {
                version = Some(
                    decoder
                        .u64()
                        .map_err(|_| IdentityError::MalformedCredential)?,
                );
            }
            1 => user_root_id = Some(decode_fixed_bytes(&mut decoder)?),
            2 => device_id = Some(decode_fixed_bytes(&mut decoder)?),
            3 => device_signing_public_key = Some(decode_fixed_bytes(&mut decoder)?),
            4 => mls_signing_key_binding = Some(decode_fixed_bytes(&mut decoder)?),
            5 => {
                created_at = Some(
                    decoder
                        .u64()
                        .map_err(|_| IdentityError::MalformedCredential)?,
                );
            }
            _ => unreachable!(),
        }
    }

    if seen != 0b0011_1111 || decoder.position() != encoded.len() {
        return Err(IdentityError::MalformedCredential);
    }

    let credential = DeviceCredential {
        version: version.ok_or(IdentityError::MalformedCredential)?,
        user_root_id: user_root_id.ok_or(IdentityError::MalformedCredential)?,
        device_id: device_id.ok_or(IdentityError::MalformedCredential)?,
        device_signing_public_key: device_signing_public_key
            .ok_or(IdentityError::MalformedCredential)?,
        mls_signing_key_binding: mls_signing_key_binding
            .ok_or(IdentityError::MalformedCredential)?,
        created_at: created_at.ok_or(IdentityError::MalformedCredential)?,
    };
    validate_credential(&credential)?;
    if encode_device_credential(&credential)? != encoded {
        return Err(IdentityError::MalformedCredential);
    }
    Ok(credential)
}

fn decode_fixed_bytes<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; LENGTH], IdentityError> {
    let bytes = decoder
        .bytes()
        .map_err(|_| IdentityError::MalformedCredential)?;
    if bytes.len() != LENGTH {
        return Err(IdentityError::MalformedCredential);
    }
    let mut value = [0_u8; LENGTH];
    value.copy_from_slice(bytes);
    Ok(value)
}

pub(crate) fn sign_device_credential(
    root_signing_seed: &[u8; 32],
    credential: &DeviceCredential,
) -> Result<[u8; 64], IdentityError> {
    let signing_key = SigningKey::from_bytes(root_signing_seed);
    if signing_key.verifying_key().to_bytes() != credential.user_root_id {
        return Err(IdentityError::InvalidSignature);
    }

    let signed_bytes = device_credential_signing_bytes(credential)?;
    Ok(signing_key.sign(&signed_bytes).to_bytes())
}

pub(crate) fn verify_device_credential(
    root_public_key: &[u8; 32],
    encoded_credential: &[u8],
    signature: &[u8; 64],
) -> Result<DeviceCredential, IdentityError> {
    let credential = decode_device_credential(encoded_credential)?;
    if credential.user_root_id != *root_public_key {
        return Err(IdentityError::InvalidSignature);
    }
    let verifying_key =
        VerifyingKey::from_bytes(root_public_key).map_err(|_| IdentityError::InvalidSignature)?;
    let signature =
        Signature::try_from(signature.as_slice()).map_err(|_| IdentityError::InvalidSignature)?;
    let signed_bytes = device_credential_signing_bytes(&credential)?;
    verifying_key
        .verify_strict(&signed_bytes, &signature)
        .map_err(|_| IdentityError::InvalidSignature)?;
    Ok(credential)
}

fn device_credential_signing_bytes(
    credential: &DeviceCredential,
) -> Result<Vec<u8>, IdentityError> {
    let encoded = encode_device_credential(credential)?;
    let mut signed_bytes = Vec::with_capacity(DEVICE_CREDENTIAL_DOMAIN.len() + 1 + encoded.len());
    signed_bytes.extend_from_slice(DEVICE_CREDENTIAL_DOMAIN);
    signed_bytes.push(0);
    signed_bytes.extend_from_slice(&encoded);
    Ok(signed_bytes)
}

fn validate_credential(credential: &DeviceCredential) -> Result<(), IdentityError> {
    if credential.version != DEVICE_CREDENTIAL_VERSION
        || credential.mls_signing_key_binding != credential.device_signing_public_key
    {
        return Err(IdentityError::MalformedCredential);
    }
    Ok(())
}
