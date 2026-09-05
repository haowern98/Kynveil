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

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey};

    use super::*;

    const RFC_8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC_8032_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC_8032_SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    const GOLDEN_CREDENTIAL: [u8; 132] = [
        0xa6, 0x00, 0x01, 0x01, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x02, 0x50, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x03, 0x58, 0x20, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x04, 0x58, 0x20, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
        0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x05, 0x1a, 0x65, 0x53, 0xf1, 0x00,
    ];

    fn credential() -> DeviceCredential {
        DeviceCredential {
            version: 1,
            user_root_id: core::array::from_fn(|index| {
                u8::try_from(index).expect("fixture index fits in u8")
            }),
            device_id: core::array::from_fn(|index| {
                u8::try_from(index + 0x20).expect("fixture index fits in u8")
            }),
            device_signing_public_key: core::array::from_fn(|index| {
                u8::try_from(index + 0x30).expect("fixture index fits in u8")
            }),
            mls_signing_key_binding: core::array::from_fn(|index| {
                u8::try_from(index + 0x30).expect("fixture index fits in u8")
            }),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn matches_rfc_8032_vector_one() {
        let signing_key = SigningKey::from_bytes(&RFC_8032_SEED);

        assert_eq!(signing_key.verifying_key().to_bytes(), RFC_8032_PUBLIC_KEY);
        assert_eq!(signing_key.sign(b"").to_bytes(), RFC_8032_SIGNATURE);
        assert!(
            signing_key
                .verifying_key()
                .verify_strict(
                    b"",
                    &Signature::try_from(RFC_8032_SIGNATURE.as_slice()).unwrap()
                )
                .is_ok()
        );
    }

    #[test]
    fn generates_independent_root_and_device_identities() {
        let identity = create_identity(1_700_000_000).unwrap();

        assert_eq!(
            SigningKey::from_bytes(&identity.root_signing_seed)
                .verifying_key()
                .to_bytes(),
            identity.root_public_key
        );
        assert_eq!(
            SigningKey::from_bytes(&identity.device_signing_seed)
                .verifying_key()
                .to_bytes(),
            identity.device_credential.device_signing_public_key
        );
        assert_ne!(
            identity.root_public_key,
            identity.device_credential.device_signing_public_key
        );
        assert_eq!(
            identity.root_public_key,
            identity.device_credential.user_root_id
        );
        assert_eq!(
            identity.device_credential.device_signing_public_key,
            identity.device_credential.mls_signing_key_binding
        );
        assert_eq!(
            verify_device_credential(
                &identity.root_public_key,
                &encode_device_credential(&identity.device_credential).unwrap(),
                &identity.device_credential_signature
            )
            .unwrap(),
            identity.device_credential
        );
    }

    #[test]
    fn encodes_the_frozen_device_credential_vector() {
        let credential = credential();

        assert_eq!(
            encode_device_credential(&credential).unwrap(),
            GOLDEN_CREDENTIAL
        );
        assert_eq!(
            decode_device_credential(&GOLDEN_CREDENTIAL).unwrap(),
            credential
        );
    }

    #[test]
    fn signs_and_verifies_the_exact_domain_separated_credential_bytes() {
        let root_seed = [0x42; 32];
        let root_public_key = SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes();
        let mut credential = credential();
        credential.user_root_id = root_public_key;
        let encoded = encode_device_credential(&credential).unwrap();
        let signature = sign_device_credential(&root_seed, &credential).unwrap();
        let mut expected_signed_bytes = Vec::from(b"kynveil/v1/device-credential\0".as_slice());
        expected_signed_bytes.extend_from_slice(&encoded);

        assert_eq!(
            signature,
            SigningKey::from_bytes(&root_seed)
                .sign(&expected_signed_bytes)
                .to_bytes()
        );
        assert_eq!(
            verify_device_credential(&root_public_key, &encoded, &signature).unwrap(),
            credential
        );
    }

    #[test]
    fn rejects_altered_signatures_and_signed_payloads() {
        let root_seed = [0x42; 32];
        let root_public_key = SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes();
        let mut credential = credential();
        credential.user_root_id = root_public_key;
        let mut signature = sign_device_credential(&root_seed, &credential).unwrap();
        let encoded = encode_device_credential(&credential).unwrap();

        signature[0] ^= 1;
        assert_eq!(
            verify_device_credential(&root_public_key, &encoded, &signature),
            Err(IdentityError::InvalidSignature)
        );

        let mut altered_payload = encoded;
        altered_payload[131] ^= 1;
        let signature = sign_device_credential(&root_seed, &credential).unwrap();
        assert_eq!(
            verify_device_credential(&root_public_key, &altered_payload, &signature),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_malformed_and_non_deterministic_credential_encodings() {
        let mut duplicate_key = GOLDEN_CREDENTIAL;
        duplicate_key[3] = 0;
        assert_eq!(
            decode_device_credential(&duplicate_key),
            Err(IdentityError::MalformedCredential)
        );

        let mut unknown_key = GOLDEN_CREDENTIAL;
        unknown_key[3] = 6;
        assert_eq!(
            decode_device_credential(&unknown_key),
            Err(IdentityError::MalformedCredential)
        );

        let mut wrong_length = GOLDEN_CREDENTIAL;
        wrong_length[5] = 0x1f;
        assert_eq!(
            decode_device_credential(&wrong_length),
            Err(IdentityError::MalformedCredential)
        );

        let mut wrong_type = GOLDEN_CREDENTIAL;
        wrong_type[127] = 0x40;
        assert_eq!(
            decode_device_credential(&wrong_type),
            Err(IdentityError::MalformedCredential)
        );

        let mut missing_field = GOLDEN_CREDENTIAL[..126].to_vec();
        missing_field[0] = 0xa5;
        assert_eq!(
            decode_device_credential(&missing_field),
            Err(IdentityError::MalformedCredential)
        );

        let mut unsupported_version = GOLDEN_CREDENTIAL;
        unsupported_version[2] = 2;
        assert_eq!(
            decode_device_credential(&unsupported_version),
            Err(IdentityError::MalformedCredential)
        );

        let mut trailing_data = GOLDEN_CREDENTIAL.to_vec();
        trailing_data.push(0);
        assert_eq!(
            decode_device_credential(&trailing_data),
            Err(IdentityError::MalformedCredential)
        );

        let mut non_deterministic = Vec::from([0xa6, 0x00, 0x18, 0x01]);
        non_deterministic.extend_from_slice(&GOLDEN_CREDENTIAL[3..]);
        assert_eq!(
            decode_device_credential(&non_deterministic),
            Err(IdentityError::MalformedCredential)
        );
    }

    #[test]
    fn rejects_a_non_matching_mls_signing_key_binding() {
        let mut credential = credential();
        credential.mls_signing_key_binding[0] ^= 1;

        assert_eq!(
            encode_device_credential(&credential),
            Err(IdentityError::MalformedCredential)
        );
    }

    #[test]
    fn rejects_a_credential_claiming_a_different_root_identity() {
        let root_seed = [0x42; 32];
        let root_public_key = SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes();
        let mut credential = credential();
        credential.user_root_id[0] ^= 1;
        let encoded = encode_device_credential(&credential).unwrap();
        let signature = SigningKey::from_bytes(&root_seed)
            .sign(&device_credential_signing_bytes(&credential).unwrap())
            .to_bytes();

        assert_eq!(
            verify_device_credential(&root_public_key, &encoded, &signature),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn refuses_to_sign_a_credential_for_an_unrelated_root_identity() {
        assert_eq!(
            sign_device_credential(&[0x8A; 32], &credential()),
            Err(IdentityError::InvalidSignature)
        );
    }
}
