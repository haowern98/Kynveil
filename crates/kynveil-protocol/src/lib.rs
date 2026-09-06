//! Typed deterministic-CBOR values for the Kynveil relay protocol.

#![deny(unsafe_code)]

use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

/// The maximum accepted encoded relay message size.
pub const MAX_WIRE_BYTES: usize = 1_048_576;
/// The maximum ciphertext size accepted by the relay.
pub const MAX_CIPHERTEXT_BYTES: usize = 131_072;
/// The maximum number of recipient mailboxes in one deposit.
pub const MAX_RECIPIENTS: usize = 64;
/// The largest accepted relay TTL in seconds.
pub const MAX_TTL_SECONDS: u64 = 604_800;

const MAJOR_VERSION: u64 = 1;
const MINOR_VERSION: u64 = 0;
const PROVISION_MAILBOX_TYPE: u64 = 0;
const AUTHORIZE_DEPOSIT_TYPE: u64 = 1;
const REVOKE_DEPOSIT_TYPE: u64 = 2;
const DEPOSIT_TYPE: u64 = 3;
const RETRIEVE_TYPE: u64 = 4;
const ACKNOWLEDGE_TYPE: u64 = 5;
const DELIVERY_PAGE_TYPE: u64 = 6;
const ACCEPTED_TYPE: u64 = 7;
const ERROR_TYPE: u64 = 8;
const MAX_DELIVERIES_PER_PAGE: usize = 8;
const MAX_SEQUENCE: u64 = i64::MAX as u64;

/// An opaque 32-byte relay mailbox identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MailboxId([u8; 32]);

impl MailboxId {
    /// Constructs an identifier from its exact wire representation.
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Returns the exact opaque identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An opaque 16-byte sender-generated object identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    /// Constructs an identifier from its exact wire representation.
    #[must_use]
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }

    /// Returns the exact opaque identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Selects a permanent domain for a relay capability verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityKind {
    /// Authorizes mailbox retrieval and acknowledgement.
    Retrieve,
    /// Authorizes mailbox grant management.
    Management,
    /// Authorizes creation of a new deposit for one mailbox.
    Deposit,
}

impl CapabilityKind {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Retrieve => b"kynveil/v1/relay/retrieve-verifier",
            Self::Management => b"kynveil/v1/relay/management-verifier",
            Self::Deposit => b"kynveil/v1/relay/deposit-verifier",
        }
    }
}

/// Derives the persistent verifier for one transient 32-byte capability.
///
/// This applies the permanent V1 domain separation contract. Callers retain
/// ownership of the raw capability and must not persist or log it.
#[must_use]
pub fn capability_verifier(kind: CapabilityKind, capability: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(kind.domain());
    hash.update([0]);
    hash.update(capability);
    hash.finalize().into()
}

/// Commits to an ordered recipient snapshot without retaining raw capabilities.
///
/// The digest covers every mailbox identifier and the permanent deposit-domain
/// verifier derived from its transient capability. Callers must retain the raw
/// capabilities only for the lifetime of the request.
///
/// # Errors
///
/// Returns [`ProtocolError::Malformed`] when recipients are empty, exceed the
/// bound, duplicate an identifier, or are not already in canonical order.
pub fn canonical_recipient_snapshot_digest(
    recipients: &[DepositRecipient],
) -> Result<[u8; 32], ProtocolError> {
    validate_recipients(recipients)?;
    let mut hash = Sha256::new();
    hash.update(b"kynveil/v1/relay/recipient-snapshot");
    hash.update([0]);
    for recipient in recipients {
        hash.update(recipient.mailbox_id.as_bytes());
        hash.update(capability_verifier(
            CapabilityKind::Deposit,
            &recipient.deposit_capability,
        ));
    }
    Ok(hash.finalize().into())
}

/// One opaque recipient authorization in an immutable deposit snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositRecipient {
    /// The target mailbox.
    pub mailbox_id: MailboxId,
    /// The transient deposit capability for the target mailbox.
    pub deposit_capability: [u8; 32],
}

impl DepositRecipient {
    /// Constructs one target mailbox and its transient deposit capability.
    #[must_use]
    pub const fn new(mailbox_id: MailboxId, deposit_capability: [u8; 32]) -> Self {
        Self {
            mailbox_id,
            deposit_capability,
        }
    }
}

/// A V1 opaque ciphertext deposit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposit {
    /// The sender-generated idempotency identifier.
    pub object_id: ObjectId,
    /// The already-canonical immutable recipient list.
    pub recipients: Vec<DepositRecipient>,
    /// Opaque ciphertext; it is never interpreted by the relay.
    pub ciphertext: Vec<u8>,
    /// The explicit relay retention period in seconds.
    pub ttl_seconds: u64,
}

/// Creates one opaque mailbox and its two permanent authorization verifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionMailbox {
    /// The new opaque mailbox identifier.
    pub mailbox_id: MailboxId,
    /// The retrieve-capability verifier.
    pub retrieve_verifier: [u8; 32],
    /// The management-capability verifier.
    pub management_verifier: [u8; 32],
}

/// Grants one independently revocable deposit verifier to a mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeDeposit {
    /// The mailbox receiving the grant.
    pub mailbox_id: MailboxId,
    /// The transient management capability.
    pub management_capability: [u8; 32],
    /// The derived deposit verifier to add.
    pub deposit_verifier: [u8; 32],
}

/// Removes one independently revocable deposit verifier from a mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeDeposit {
    /// The mailbox whose grant is being removed.
    pub mailbox_id: MailboxId,
    /// The transient management capability.
    pub management_capability: [u8; 32],
    /// The derived deposit verifier to remove.
    pub deposit_verifier: [u8; 32],
}

/// Requests the next immutable page of one mailbox's unacknowledged deliveries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retrieve {
    /// The mailbox to retrieve.
    pub mailbox_id: MailboxId,
    /// The transient retrieve capability.
    pub retrieve_capability: [u8; 32],
    /// The exclusive mailbox-local sequence cursor.
    pub after_sequence: u64,
}

/// Acknowledges one recipient-specific delivery without acknowledging others.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Acknowledge {
    /// The recipient mailbox.
    pub mailbox_id: MailboxId,
    /// The shared opaque object identifier.
    pub object_id: ObjectId,
    /// The matching mailbox-local delivery sequence.
    pub delivery_sequence: u64,
    /// The transient retrieve capability.
    pub retrieve_capability: [u8; 32],
}

/// One opaque ciphertext delivery returned from a mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// The mailbox-local delivery sequence.
    pub delivery_sequence: u64,
    /// The shared opaque object identifier.
    pub object_id: ObjectId,
    /// Opaque ciphertext; it is never interpreted by the relay.
    pub ciphertext: Vec<u8>,
    /// The relay-clock Unix expiry time.
    pub expires_at_unix_seconds: u64,
}

/// A bounded, non-mutating mailbox retrieval result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryPage {
    /// Deliveries in strictly ascending mailbox-local sequence order.
    pub deliveries: Vec<Delivery>,
    /// The last returned sequence, or the caller cursor for an empty page.
    pub next_cursor: u64,
}

/// A successful operation result with no secret-bearing detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accepted;

/// A fixed coarse relay failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ErrorCode {
    /// Structural or semantic input validation failed.
    BadRequest = 1,
    /// Authentication failed or the target must not be enumerated.
    UnauthorizedOrNotFound = 2,
    /// The relay's bounded rate policy refused the operation.
    RateLimited = 3,
    /// A supported input exceeds a protocol size bound.
    TooLarge = 4,
    /// The requested protocol version is unsupported.
    VersionUnsupported = 5,
    /// A temporary relay condition prevents completion.
    TemporaryUnavailable = 6,
    /// A bounded relay resource is exhausted.
    QuotaExceeded = 7,
}

impl ErrorCode {
    fn decode(value: u64) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::BadRequest),
            2 => Ok(Self::UnauthorizedOrNotFound),
            3 => Ok(Self::RateLimited),
            4 => Ok(Self::TooLarge),
            5 => Ok(Self::VersionUnsupported),
            6 => Ok(Self::TemporaryUnavailable),
            7 => Ok(Self::QuotaExceeded),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// A coarse error result with no caller-controlled detail string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorMessage {
    /// The fixed error classification.
    pub code: ErrorCode,
}

/// A typed V1 relay message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireMessage {
    /// Creates a mailbox with retrieve and management verifiers only.
    ProvisionMailbox(ProvisionMailbox),
    /// Adds one independently revocable deposit verifier.
    AuthorizeDeposit(AuthorizeDeposit),
    /// Removes one independently revocable deposit verifier.
    RevokeDeposit(RevokeDeposit),
    /// Deposits opaque ciphertext for an immutable recipient snapshot.
    Deposit(Deposit),
    /// Requests a non-mutating mailbox page.
    Retrieve(Retrieve),
    /// Acknowledges one recipient-specific delivery.
    Acknowledge(Acknowledge),
    /// Returns one bounded non-mutating delivery page.
    DeliveryPage(DeliveryPage),
    /// Returns a successful operation result.
    Accepted(Accepted),
    /// Returns a coarse operation failure.
    Error(ErrorMessage),
}

/// A bounded protocol encoding or validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The message violates an exact structural or semantic requirement.
    Malformed,
    /// The encoded message exceeds the V1 wire limit.
    TooLarge,
    /// The message does not use the exact V1.0 version.
    UnsupportedVersion,
}

/// Deterministically encodes one validated V1 relay message.
///
/// The returned bytes are canonical RFC 8949 CBOR and never contain a raw
/// capability outside the caller-owned message buffer.
///
/// # Errors
///
/// Returns a bounded [`ProtocolError`] when a message violates the frozen
/// schema or encoded wire limit.
pub fn encode(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    match message {
        WireMessage::ProvisionMailbox(provision) => encode_provision_mailbox(provision),
        WireMessage::AuthorizeDeposit(authorize) => encode_authorize_deposit(authorize),
        WireMessage::RevokeDeposit(revoke) => encode_revoke_deposit(revoke),
        WireMessage::Deposit(deposit) => encode_deposit(deposit),
        WireMessage::Retrieve(retrieve) => encode_retrieve(retrieve),
        WireMessage::Acknowledge(acknowledgement) => encode_acknowledgement(acknowledgement),
        WireMessage::DeliveryPage(page) => encode_delivery_page(page),
        WireMessage::Accepted(accepted) => encode_accepted(*accepted),
        WireMessage::Error(error) => encode_error(*error),
    }
}

/// Decodes and strictly validates one canonical V1 relay message.
///
/// The function rejects any input whose deterministic re-encoding differs from
/// the original bytes.
///
/// # Errors
///
/// Returns a bounded [`ProtocolError`] for malformed, non-canonical,
/// oversize, or unsupported-version input.
pub fn decode(encoded: &[u8]) -> Result<WireMessage, ProtocolError> {
    if encoded.len() > MAX_WIRE_BYTES {
        return Err(ProtocolError::TooLarge);
    }

    let mut decoder = Decoder::new(encoded);
    let (field_count, message_type) = decode_header(&mut decoder)?;
    let message = match message_type {
        PROVISION_MAILBOX_TYPE if field_count == 6 => {
            WireMessage::ProvisionMailbox(decode_provision_mailbox_body(&mut decoder)?)
        }
        AUTHORIZE_DEPOSIT_TYPE if field_count == 6 => {
            WireMessage::AuthorizeDeposit(decode_authorize_deposit_body(&mut decoder)?)
        }
        REVOKE_DEPOSIT_TYPE if field_count == 6 => {
            WireMessage::RevokeDeposit(decode_revoke_deposit_body(&mut decoder)?)
        }
        DEPOSIT_TYPE if field_count == 8 => {
            WireMessage::Deposit(decode_deposit_body(&mut decoder)?)
        }
        RETRIEVE_TYPE if field_count == 6 => {
            WireMessage::Retrieve(decode_retrieve_body(&mut decoder)?)
        }
        ACKNOWLEDGE_TYPE if field_count == 7 => {
            WireMessage::Acknowledge(decode_acknowledgement_body(&mut decoder)?)
        }
        DELIVERY_PAGE_TYPE if field_count == 5 => {
            WireMessage::DeliveryPage(decode_delivery_page_body(&mut decoder)?)
        }
        ACCEPTED_TYPE if field_count == 3 => WireMessage::Accepted(Accepted),
        ERROR_TYPE if field_count == 4 => WireMessage::Error(decode_error_body(&mut decoder)?),
        _ => return Err(ProtocolError::Malformed),
    };
    if decoder.position() != encoded.len() || encode(&message)? != encoded {
        return Err(ProtocolError::Malformed);
    }
    Ok(message)
}

fn encode_provision_mailbox(provision: &ProvisionMailbox) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 6, PROVISION_MAILBOX_TYPE)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.bytes(provision.mailbox_id.as_bytes()))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.bytes(&provision.retrieve_verifier))
        .and_then(|encoder| encoder.u64(5))
        .and_then(|encoder| encoder.bytes(&provision.management_verifier))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_authorize_deposit(authorize: &AuthorizeDeposit) -> Result<Vec<u8>, ProtocolError> {
    encode_management_operation(
        AUTHORIZE_DEPOSIT_TYPE,
        authorize.mailbox_id,
        &authorize.management_capability,
        &authorize.deposit_verifier,
    )
}

fn encode_revoke_deposit(revoke: &RevokeDeposit) -> Result<Vec<u8>, ProtocolError> {
    encode_management_operation(
        REVOKE_DEPOSIT_TYPE,
        revoke.mailbox_id,
        &revoke.management_capability,
        &revoke.deposit_verifier,
    )
}

fn encode_management_operation(
    message_type: u64,
    mailbox_id: MailboxId,
    management_capability: &[u8; 32],
    deposit_verifier: &[u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 6, message_type)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.bytes(mailbox_id.as_bytes()))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.bytes(management_capability))
        .and_then(|encoder| encoder.u64(5))
        .and_then(|encoder| encoder.bytes(deposit_verifier))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_retrieve(retrieve: &Retrieve) -> Result<Vec<u8>, ProtocolError> {
    if retrieve.after_sequence > MAX_SEQUENCE {
        return Err(ProtocolError::Malformed);
    }
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 6, RETRIEVE_TYPE)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.bytes(retrieve.mailbox_id.as_bytes()))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.bytes(&retrieve.retrieve_capability))
        .and_then(|encoder| encoder.u64(5))
        .and_then(|encoder| encoder.u64(retrieve.after_sequence))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_acknowledgement(acknowledgement: &Acknowledge) -> Result<Vec<u8>, ProtocolError> {
    if !(1..=MAX_SEQUENCE).contains(&acknowledgement.delivery_sequence) {
        return Err(ProtocolError::Malformed);
    }
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 7, ACKNOWLEDGE_TYPE)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.bytes(acknowledgement.mailbox_id.as_bytes()))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.bytes(acknowledgement.object_id.as_bytes()))
        .and_then(|encoder| encoder.u64(5))
        .and_then(|encoder| encoder.u64(acknowledgement.delivery_sequence))
        .and_then(|encoder| encoder.u64(6))
        .and_then(|encoder| encoder.bytes(&acknowledgement.retrieve_capability))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_delivery_page(page: &DeliveryPage) -> Result<Vec<u8>, ProtocolError> {
    validate_delivery_page(page)?;
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 5, DELIVERY_PAGE_TYPE)?;
    let count = u64::try_from(page.deliveries.len()).map_err(|_| ProtocolError::Malformed)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.array(count))
        .map_err(|_| ProtocolError::Malformed)?;
    for delivery in &page.deliveries {
        encoder.map(5).map_err(|_| ProtocolError::Malformed)?;
        encoder
            .u64(0)
            .and_then(|encoder| encoder.u64(delivery.delivery_sequence))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.bytes(delivery.object_id.as_bytes()))
            .and_then(|encoder| encoder.u64(2))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.u64(3))
            .and_then(|encoder| encoder.bytes(&delivery.ciphertext))
            .and_then(|encoder| encoder.u64(4))
            .and_then(|encoder| encoder.u64(delivery.expires_at_unix_seconds))
            .map_err(|_| ProtocolError::Malformed)?;
    }
    encoder
        .u64(4)
        .and_then(|encoder| encoder.u64(page.next_cursor))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_accepted(_: Accepted) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 3, ACCEPTED_TYPE)?;
    finish_encoding(encoder)
}

fn encode_error(error: ErrorMessage) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 4, ERROR_TYPE)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.u64(error.code as u64))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn encode_header(
    encoder: &mut Encoder<Vec<u8>>,
    field_count: u64,
    message_type: u64,
) -> Result<(), ProtocolError> {
    encoder
        .map(field_count)
        .and_then(|encoder| encoder.u64(0))
        .and_then(|encoder| encoder.u64(MAJOR_VERSION))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.u64(MINOR_VERSION))
        .and_then(|encoder| encoder.u64(2))
        .and_then(|encoder| encoder.u64(message_type))
        .map(|_| ())
        .map_err(|_| ProtocolError::Malformed)
}

fn finish_encoding(encoder: Encoder<Vec<u8>>) -> Result<Vec<u8>, ProtocolError> {
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_WIRE_BYTES {
        Err(ProtocolError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn encode_deposit(deposit: &Deposit) -> Result<Vec<u8>, ProtocolError> {
    validate_deposit(deposit)?;
    let mut encoder = Encoder::new(Vec::new());
    encode_header(&mut encoder, 8, DEPOSIT_TYPE)?;
    let recipient_count =
        u64::try_from(deposit.recipients.len()).map_err(|_| ProtocolError::Malformed)?;
    encoder
        .u64(3)
        .and_then(|encoder| encoder.bytes(deposit.object_id.as_bytes()))
        .and_then(|encoder| encoder.u64(4))
        .and_then(|encoder| encoder.array(recipient_count))
        .map_err(|_| ProtocolError::Malformed)?;
    for recipient in &deposit.recipients {
        encoder
            .map(2)
            .and_then(|encoder| encoder.u64(0))
            .and_then(|encoder| encoder.bytes(recipient.mailbox_id.as_bytes()))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.bytes(&recipient.deposit_capability))
            .map_err(|_| ProtocolError::Malformed)?;
    }
    encoder
        .u64(5)
        .and_then(|encoder| encoder.bytes(&deposit.ciphertext))
        .and_then(|encoder| encoder.u64(6))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.u64(7))
        .and_then(|encoder| encoder.u64(deposit.ttl_seconds))
        .map_err(|_| ProtocolError::Malformed)?;
    finish_encoding(encoder)
}

fn decode_deposit_body(decoder: &mut Decoder<'_>) -> Result<Deposit, ProtocolError> {
    expect_key(decoder, 3)?;
    let object_id = ObjectId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 4)?;
    let recipient_count = decoder
        .array()
        .map_err(|_| ProtocolError::Malformed)?
        .ok_or(ProtocolError::Malformed)?;
    let recipient_count = usize::try_from(recipient_count).map_err(|_| ProtocolError::Malformed)?;
    if !(1..=MAX_RECIPIENTS).contains(&recipient_count) {
        return Err(ProtocolError::Malformed);
    }
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        let field_count = decoder
            .map()
            .map_err(|_| ProtocolError::Malformed)?
            .ok_or(ProtocolError::Malformed)?;
        if field_count != 2 {
            return Err(ProtocolError::Malformed);
        }
        expect_key(decoder, 0)?;
        let mailbox_id = MailboxId(decode_fixed_bytes(decoder)?);
        expect_key(decoder, 1)?;
        recipients.push(DepositRecipient::new(
            mailbox_id,
            decode_fixed_bytes(decoder)?,
        ));
    }
    expect_key(decoder, 5)?;
    let ciphertext = decoder
        .bytes()
        .map_err(|_| ProtocolError::Malformed)?
        .to_vec();
    expect_key(decoder, 6)?;
    if decoder.u64().map_err(|_| ProtocolError::Malformed)? != 1 {
        return Err(ProtocolError::Malformed);
    }
    expect_key(decoder, 7)?;
    let ttl_seconds = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    let deposit = Deposit {
        object_id,
        recipients,
        ciphertext,
        ttl_seconds,
    };
    validate_deposit(&deposit)?;
    Ok(deposit)
}

fn decode_provision_mailbox_body(
    decoder: &mut Decoder<'_>,
) -> Result<ProvisionMailbox, ProtocolError> {
    expect_key(decoder, 3)?;
    let mailbox_id = MailboxId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 4)?;
    let retrieve_verifier = decode_fixed_bytes(decoder)?;
    expect_key(decoder, 5)?;
    Ok(ProvisionMailbox {
        mailbox_id,
        retrieve_verifier,
        management_verifier: decode_fixed_bytes(decoder)?,
    })
}

fn decode_authorize_deposit_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorizeDeposit, ProtocolError> {
    let (mailbox_id, management_capability, deposit_verifier) =
        decode_management_operation_body(decoder)?;
    Ok(AuthorizeDeposit {
        mailbox_id,
        management_capability,
        deposit_verifier,
    })
}

fn decode_revoke_deposit_body(decoder: &mut Decoder<'_>) -> Result<RevokeDeposit, ProtocolError> {
    let (mailbox_id, management_capability, deposit_verifier) =
        decode_management_operation_body(decoder)?;
    Ok(RevokeDeposit {
        mailbox_id,
        management_capability,
        deposit_verifier,
    })
}

fn decode_management_operation_body(
    decoder: &mut Decoder<'_>,
) -> Result<(MailboxId, [u8; 32], [u8; 32]), ProtocolError> {
    expect_key(decoder, 3)?;
    let mailbox_id = MailboxId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 4)?;
    let management_capability = decode_fixed_bytes(decoder)?;
    expect_key(decoder, 5)?;
    let deposit_verifier = decode_fixed_bytes(decoder)?;
    Ok((mailbox_id, management_capability, deposit_verifier))
}

fn decode_retrieve_body(decoder: &mut Decoder<'_>) -> Result<Retrieve, ProtocolError> {
    expect_key(decoder, 3)?;
    let mailbox_id = MailboxId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 4)?;
    let retrieve_capability = decode_fixed_bytes(decoder)?;
    expect_key(decoder, 5)?;
    let after_sequence = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    if after_sequence > MAX_SEQUENCE {
        return Err(ProtocolError::Malformed);
    }
    Ok(Retrieve {
        mailbox_id,
        retrieve_capability,
        after_sequence,
    })
}

fn decode_acknowledgement_body(decoder: &mut Decoder<'_>) -> Result<Acknowledge, ProtocolError> {
    expect_key(decoder, 3)?;
    let mailbox_id = MailboxId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 4)?;
    let object_id = ObjectId(decode_fixed_bytes(decoder)?);
    expect_key(decoder, 5)?;
    let delivery_sequence = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    if !(1..=MAX_SEQUENCE).contains(&delivery_sequence) {
        return Err(ProtocolError::Malformed);
    }
    expect_key(decoder, 6)?;
    Ok(Acknowledge {
        mailbox_id,
        object_id,
        delivery_sequence,
        retrieve_capability: decode_fixed_bytes(decoder)?,
    })
}

fn decode_delivery_page_body(decoder: &mut Decoder<'_>) -> Result<DeliveryPage, ProtocolError> {
    expect_key(decoder, 3)?;
    let count = decoder
        .array()
        .map_err(|_| ProtocolError::Malformed)?
        .ok_or(ProtocolError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| ProtocolError::Malformed)?;
    if count > MAX_DELIVERIES_PER_PAGE {
        return Err(ProtocolError::Malformed);
    }
    let mut deliveries = Vec::with_capacity(count);
    for _ in 0..count {
        let field_count = decoder
            .map()
            .map_err(|_| ProtocolError::Malformed)?
            .ok_or(ProtocolError::Malformed)?;
        if field_count != 5 {
            return Err(ProtocolError::Malformed);
        }
        expect_key(decoder, 0)?;
        let delivery_sequence = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
        expect_key(decoder, 1)?;
        let object_id = ObjectId(decode_fixed_bytes(decoder)?);
        expect_key(decoder, 2)?;
        if decoder.u64().map_err(|_| ProtocolError::Malformed)? != 1 {
            return Err(ProtocolError::Malformed);
        }
        expect_key(decoder, 3)?;
        let ciphertext = decoder
            .bytes()
            .map_err(|_| ProtocolError::Malformed)?
            .to_vec();
        expect_key(decoder, 4)?;
        let expires_at_unix_seconds = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
        deliveries.push(Delivery {
            delivery_sequence,
            object_id,
            ciphertext,
            expires_at_unix_seconds,
        });
    }
    expect_key(decoder, 4)?;
    let next_cursor = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    let page = DeliveryPage {
        deliveries,
        next_cursor,
    };
    validate_delivery_page(&page)?;
    Ok(page)
}

fn decode_error_body(decoder: &mut Decoder<'_>) -> Result<ErrorMessage, ProtocolError> {
    expect_key(decoder, 3)?;
    Ok(ErrorMessage {
        code: ErrorCode::decode(decoder.u64().map_err(|_| ProtocolError::Malformed)?)?,
    })
}

fn decode_header(decoder: &mut Decoder<'_>) -> Result<(u64, u64), ProtocolError> {
    let field_count = decoder
        .map()
        .map_err(|_| ProtocolError::Malformed)?
        .ok_or(ProtocolError::Malformed)?;
    expect_key(decoder, 0)?;
    let major = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    expect_key(decoder, 1)?;
    let minor = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    expect_key(decoder, 2)?;
    let message_type = decoder.u64().map_err(|_| ProtocolError::Malformed)?;
    if major != MAJOR_VERSION || minor != MINOR_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok((field_count, message_type))
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.u64().map_err(|_| ProtocolError::Malformed)? == expected {
        Ok(())
    } else {
        Err(ProtocolError::Malformed)
    }
}

fn decode_fixed_bytes<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; LENGTH], ProtocolError> {
    let bytes = decoder.bytes().map_err(|_| ProtocolError::Malformed)?;
    if bytes.len() != LENGTH {
        return Err(ProtocolError::Malformed);
    }
    let mut value = [0_u8; LENGTH];
    value.copy_from_slice(bytes);
    Ok(value)
}

fn validate_deposit(deposit: &Deposit) -> Result<(), ProtocolError> {
    if deposit.ciphertext.is_empty()
        || deposit.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || !(1..=MAX_TTL_SECONDS).contains(&deposit.ttl_seconds)
    {
        return Err(ProtocolError::Malformed);
    }
    validate_recipients(&deposit.recipients)
}

fn validate_recipients(recipients: &[DepositRecipient]) -> Result<(), ProtocolError> {
    if !(1..=MAX_RECIPIENTS).contains(&recipients.len())
        || recipients
            .windows(2)
            .any(|pair| pair[0].mailbox_id >= pair[1].mailbox_id)
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

fn validate_delivery_page(page: &DeliveryPage) -> Result<(), ProtocolError> {
    if page.deliveries.len() > MAX_DELIVERIES_PER_PAGE || page.next_cursor > MAX_SEQUENCE {
        return Err(ProtocolError::Malformed);
    }
    let mut previous_sequence = 0;
    for delivery in &page.deliveries {
        if !(1..=MAX_SEQUENCE).contains(&delivery.delivery_sequence)
            || delivery.delivery_sequence <= previous_sequence
            || delivery.ciphertext.is_empty()
            || delivery.ciphertext.len() > MAX_CIPHERTEXT_BYTES
            || delivery.expires_at_unix_seconds == 0
        {
            return Err(ProtocolError::Malformed);
        }
        previous_sequence = delivery.delivery_sequence;
    }
    if let Some(delivery) = page.deliveries.last()
        && page.next_cursor != delivery.delivery_sequence
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}
