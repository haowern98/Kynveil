//! In-process SQLite-backed blind relay service.

#![deny(unsafe_code)]

use std::path::Path;

use kynveil_protocol::{
    Accepted, Acknowledge, AuthorizeDeposit, CapabilityKind, Delivery, DeliveryPage, Deposit,
    ErrorCode, ErrorMessage, MailboxId, ProvisionMailbox, Retrieve, RevokeDeposit, WireMessage,
    canonical_recipient_snapshot_digest, capability_verifier, encode,
};
use kynveil_sqlcipher_native as _;
use openssl_sys as _;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAX_SEQUENCE: u64 = i64::MAX as u64;
const MAX_DEPOSIT_VERIFIERS: i64 = 256;

/// A transactionally consistent, in-process blind relay.
///
/// Callers are responsible for decoding untrusted transport data before calling
/// [`Relay::handle`]. The relay receives transient capabilities but persists
/// only derived verifiers, opaque ciphertext, and bounded delivery metadata.
pub struct Relay {
    connection: Connection,
}

/// A fail-closed local `SQLite` failure with no diagnostic detail for callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// `SQLite` could not safely complete the requested operation.
    Storage,
}

impl Relay {
    /// Opens a durable `SQLite` relay database at a caller-controlled service path.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Storage`] when opening or initializing the database fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RelayError> {
        Self::from_connection(Connection::open(path).map_err(|_| RelayError::Storage)?)
    }

    /// Opens an isolated in-memory `SQLite` relay for deterministic integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Storage`] when initializing the database fails.
    pub fn open_in_memory() -> Result<Self, RelayError> {
        Self::from_connection(Connection::open_in_memory().map_err(|_| RelayError::Storage)?)
    }

    /// Applies one validated request at the supplied relay-clock Unix second.
    ///
    /// The operation is one `SQLite` transaction. User-controlled malformed
    /// requests return a coarse protocol error; local database failures return
    /// [`RelayError`] and commit no partial state.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Storage`] when `SQLite` cannot complete the transaction.
    pub fn handle(
        &mut self,
        request: &WireMessage,
        now_unix_seconds: u64,
    ) -> Result<WireMessage, RelayError> {
        if now_unix_seconds > MAX_SEQUENCE || encode(request).is_err() {
            return Ok(error(ErrorCode::BadRequest));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| RelayError::Storage)?;
        purge_expired(&transaction, now_unix_seconds)?;
        let response = match request {
            WireMessage::ProvisionMailbox(request) => provision(&transaction, request)?,
            WireMessage::AuthorizeDeposit(request) => authorize(&transaction, request)?,
            WireMessage::RevokeDeposit(request) => revoke(&transaction, request)?,
            WireMessage::Deposit(request) => deposit(&transaction, request, now_unix_seconds)?,
            WireMessage::Retrieve(request) => retrieve(&transaction, request, now_unix_seconds)?,
            WireMessage::Acknowledge(request) => {
                acknowledge(&transaction, request, now_unix_seconds)?
            }
            WireMessage::DeliveryPage(_) | WireMessage::Accepted(_) | WireMessage::Error(_) => {
                error(ErrorCode::BadRequest)
            }
        };
        transaction.commit().map_err(|_| RelayError::Storage)?;
        Ok(response)
    }

    fn from_connection(connection: Connection) -> Result<Self, RelayError> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA trusted_schema = OFF;
                 CREATE TABLE IF NOT EXISTS mailboxes (
                   mailbox_id BLOB PRIMARY KEY NOT NULL,
                   retrieve_verifier BLOB NOT NULL,
                   management_verifier BLOB NOT NULL,
                   next_sequence INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS deposit_verifiers (
                   mailbox_id BLOB NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
                   verifier BLOB NOT NULL,
                   PRIMARY KEY (mailbox_id, verifier)
                 );
                 CREATE TABLE IF NOT EXISTS objects (
                   object_id BLOB PRIMARY KEY NOT NULL,
                   ciphertext BLOB NOT NULL,
                   ciphertext_digest BLOB NOT NULL,
                   delivery_class INTEGER NOT NULL,
                   ttl_seconds INTEGER NOT NULL,
                   snapshot_digest BLOB NOT NULL,
                   expires_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS deliveries (
                   mailbox_id BLOB NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
                   object_id BLOB NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
                   delivery_sequence INTEGER NOT NULL,
                   acknowledged INTEGER NOT NULL,
                   PRIMARY KEY (mailbox_id, object_id),
                   UNIQUE (mailbox_id, delivery_sequence)
                 );
                 CREATE TABLE IF NOT EXISTS object_tombstones (
                   object_id BLOB PRIMARY KEY NOT NULL,
                   ciphertext_digest BLOB NOT NULL,
                   delivery_class INTEGER NOT NULL,
                   ttl_seconds INTEGER NOT NULL,
                   snapshot_digest BLOB NOT NULL,
                   expires_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS ack_tombstones (
                   mailbox_id BLOB NOT NULL,
                   object_id BLOB NOT NULL,
                   delivery_sequence INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   PRIMARY KEY (mailbox_id, object_id, delivery_sequence)
                 );",
            )
            .map_err(|_| RelayError::Storage)?;
        Ok(Self { connection })
    }
}

fn provision(
    transaction: &Transaction<'_>,
    request: &ProvisionMailbox,
) -> Result<WireMessage, RelayError> {
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO mailboxes
             (mailbox_id, retrieve_verifier, management_verifier, next_sequence)
             VALUES (?1, ?2, ?3, 1)",
            params![
                request.mailbox_id.as_bytes().as_slice(),
                request.retrieve_verifier.as_slice(),
                request.management_verifier.as_slice()
            ],
        )
        .map_err(|_| RelayError::Storage)?;
    Ok(if inserted == 1 {
        accepted()
    } else {
        error(ErrorCode::UnauthorizedOrNotFound)
    })
}

fn authorize(
    transaction: &Transaction<'_>,
    request: &AuthorizeDeposit,
) -> Result<WireMessage, RelayError> {
    if !verify_single(
        transaction,
        "management_verifier",
        request.mailbox_id,
        &request.management_capability,
    )? {
        return Ok(error(ErrorCode::UnauthorizedOrNotFound));
    }
    let exists: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM deposit_verifiers WHERE mailbox_id = ?1 AND verifier = ?2",
            params![
                request.mailbox_id.as_bytes().as_slice(),
                request.deposit_verifier.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RelayError::Storage)?;
    if exists.is_some() {
        return Ok(accepted());
    }
    let count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM deposit_verifiers WHERE mailbox_id = ?1",
            params![request.mailbox_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::Storage)?;
    if count >= MAX_DEPOSIT_VERIFIERS {
        return Ok(error(ErrorCode::QuotaExceeded));
    }
    transaction
        .execute(
            "INSERT INTO deposit_verifiers (mailbox_id, verifier) VALUES (?1, ?2)",
            params![
                request.mailbox_id.as_bytes().as_slice(),
                request.deposit_verifier.as_slice()
            ],
        )
        .map_err(|_| RelayError::Storage)?;
    Ok(accepted())
}

fn revoke(
    transaction: &Transaction<'_>,
    request: &RevokeDeposit,
) -> Result<WireMessage, RelayError> {
    if !verify_single(
        transaction,
        "management_verifier",
        request.mailbox_id,
        &request.management_capability,
    )? {
        return Ok(error(ErrorCode::UnauthorizedOrNotFound));
    }
    transaction
        .execute(
            "DELETE FROM deposit_verifiers WHERE mailbox_id = ?1 AND verifier = ?2",
            params![
                request.mailbox_id.as_bytes().as_slice(),
                request.deposit_verifier.as_slice()
            ],
        )
        .map_err(|_| RelayError::Storage)?;
    Ok(accepted())
}

fn deposit(
    transaction: &Transaction<'_>,
    request: &Deposit,
    now: u64,
) -> Result<WireMessage, RelayError> {
    let digest = sha256(&request.ciphertext);
    let snapshot = canonical_recipient_snapshot_digest(&request.recipients)
        .map_err(|_| RelayError::Storage)?;
    if let Some(existing) = object_semantics(transaction, request.object_id.as_bytes())? {
        return Ok(
            if existing.matches(&digest, request.ttl_seconds, &snapshot) {
                accepted()
            } else {
                error(ErrorCode::BadRequest)
            },
        );
    }
    let expires_at = now
        .checked_add(request.ttl_seconds)
        .filter(|value| *value <= MAX_SEQUENCE);
    let Some(expires_at) = expires_at else {
        return Ok(error(ErrorCode::TemporaryUnavailable));
    };
    for recipient in &request.recipients {
        if !verify_deposit(
            transaction,
            recipient.mailbox_id,
            &recipient.deposit_capability,
        )? {
            return Ok(error(ErrorCode::UnauthorizedOrNotFound));
        }
        if next_sequence(transaction, recipient.mailbox_id)? == 0 {
            return Ok(error(ErrorCode::TemporaryUnavailable));
        }
    }
    transaction.execute("INSERT INTO objects (object_id, ciphertext, ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)", params![request.object_id.as_bytes().as_slice(), &request.ciphertext, digest.as_slice(), i64::try_from(request.ttl_seconds).map_err(|_| RelayError::Storage)?, snapshot.as_slice(), i64::try_from(expires_at).map_err(|_| RelayError::Storage)?]).map_err(|_| RelayError::Storage)?;
    for recipient in &request.recipients {
        let sequence = allocate_sequence(transaction, recipient.mailbox_id)?;
        transaction.execute("INSERT INTO deliveries (mailbox_id, object_id, delivery_sequence, acknowledged) VALUES (?1, ?2, ?3, 0)", params![recipient.mailbox_id.as_bytes().as_slice(), request.object_id.as_bytes().as_slice(), i64::try_from(sequence).map_err(|_| RelayError::Storage)?]).map_err(|_| RelayError::Storage)?;
    }
    Ok(accepted())
}

fn retrieve(
    transaction: &Transaction<'_>,
    request: &Retrieve,
    now: u64,
) -> Result<WireMessage, RelayError> {
    if !verify_single(
        transaction,
        "retrieve_verifier",
        request.mailbox_id,
        &request.retrieve_capability,
    )? {
        return Ok(error(ErrorCode::UnauthorizedOrNotFound));
    }
    let mut statement = transaction.prepare(
        "SELECT d.delivery_sequence, d.object_id, o.ciphertext, o.expires_at
         FROM deliveries d JOIN objects o ON o.object_id = d.object_id
         WHERE d.mailbox_id = ?1 AND d.acknowledged = 0 AND d.delivery_sequence > ?2 AND o.expires_at > ?3
         ORDER BY d.delivery_sequence ASC LIMIT 8",
    ).map_err(|_| RelayError::Storage)?;
    let mut rows = statement
        .query(params![
            request.mailbox_id.as_bytes().as_slice(),
            i64::try_from(request.after_sequence).map_err(|_| RelayError::Storage)?,
            i64::try_from(now).map_err(|_| RelayError::Storage)?
        ])
        .map_err(|_| RelayError::Storage)?;
    let mut page = DeliveryPage {
        deliveries: Vec::new(),
        next_cursor: request.after_sequence,
    };
    while let Some(row) = rows.next().map_err(|_| RelayError::Storage)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(|_| RelayError::Storage)?)
            .map_err(|_| RelayError::Storage)?;
        let object = fixed::<16>(row.get::<_, Vec<u8>>(1).map_err(|_| RelayError::Storage)?)?;
        let ciphertext = row.get(2).map_err(|_| RelayError::Storage)?;
        let expires_at = u64::try_from(row.get::<_, i64>(3).map_err(|_| RelayError::Storage)?)
            .map_err(|_| RelayError::Storage)?;
        let delivery = Delivery {
            delivery_sequence: sequence,
            object_id: kynveil_protocol::ObjectId::new(object),
            ciphertext,
            expires_at_unix_seconds: expires_at,
        };
        let mut candidate = page.clone();
        candidate.next_cursor = sequence;
        candidate.deliveries.push(delivery);
        if encode(&WireMessage::DeliveryPage(candidate.clone())).is_err() {
            break;
        }
        page = candidate;
    }
    Ok(WireMessage::DeliveryPage(page))
}

fn acknowledge(
    transaction: &Transaction<'_>,
    request: &Acknowledge,
    now: u64,
) -> Result<WireMessage, RelayError> {
    if !verify_single(
        transaction,
        "retrieve_verifier",
        request.mailbox_id,
        &request.retrieve_capability,
    )? {
        return Ok(error(ErrorCode::UnauthorizedOrNotFound));
    }
    let present: Option<i64> = transaction.query_row("SELECT acknowledged FROM deliveries WHERE mailbox_id = ?1 AND object_id = ?2 AND delivery_sequence = ?3", params![request.mailbox_id.as_bytes().as_slice(), request.object_id.as_bytes().as_slice(), i64::try_from(request.delivery_sequence).map_err(|_| RelayError::Storage)?], |row| row.get(0)).optional().map_err(|_| RelayError::Storage)?;
    if let Some(acknowledged) = present {
        if acknowledged == 0 {
            transaction.execute("UPDATE deliveries SET acknowledged = 1 WHERE mailbox_id = ?1 AND object_id = ?2 AND delivery_sequence = ?3", params![request.mailbox_id.as_bytes().as_slice(), request.object_id.as_bytes().as_slice(), i64::try_from(request.delivery_sequence).map_err(|_| RelayError::Storage)?]).map_err(|_| RelayError::Storage)?;
        }
        let pending: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM deliveries WHERE object_id = ?1 AND acknowledged = 0",
                params![request.object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| RelayError::Storage)?;
        if pending == 0 {
            transaction.execute("INSERT OR REPLACE INTO object_tombstones SELECT object_id, ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at FROM objects WHERE object_id = ?1", params![request.object_id.as_bytes().as_slice()]).map_err(|_| RelayError::Storage)?;
            transaction.execute("INSERT OR REPLACE INTO ack_tombstones SELECT mailbox_id, object_id, delivery_sequence, (SELECT expires_at FROM objects WHERE object_id = ?1) FROM deliveries WHERE object_id = ?1", params![request.object_id.as_bytes().as_slice()]).map_err(|_| RelayError::Storage)?;
            transaction
                .execute(
                    "DELETE FROM objects WHERE object_id = ?1",
                    params![request.object_id.as_bytes().as_slice()],
                )
                .map_err(|_| RelayError::Storage)?;
        }
        return Ok(accepted());
    }
    let retained: Option<i64> = transaction.query_row("SELECT 1 FROM ack_tombstones WHERE mailbox_id = ?1 AND object_id = ?2 AND delivery_sequence = ?3 AND expires_at > ?4", params![request.mailbox_id.as_bytes().as_slice(), request.object_id.as_bytes().as_slice(), i64::try_from(request.delivery_sequence).map_err(|_| RelayError::Storage)?, i64::try_from(now).map_err(|_| RelayError::Storage)?], |row| row.get(0)).optional().map_err(|_| RelayError::Storage)?;
    Ok(if retained.is_some() {
        accepted()
    } else {
        error(ErrorCode::UnauthorizedOrNotFound)
    })
}

fn purge_expired(transaction: &Transaction<'_>, now: u64) -> Result<(), RelayError> {
    let now = i64::try_from(now).map_err(|_| RelayError::Storage)?;
    transaction.execute("INSERT OR IGNORE INTO object_tombstones SELECT object_id, ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at FROM objects WHERE expires_at <= ?1", [now]).map_err(|_| RelayError::Storage)?;
    transaction
        .execute("DELETE FROM objects WHERE expires_at <= ?1", [now])
        .map_err(|_| RelayError::Storage)?;
    transaction
        .execute("DELETE FROM object_tombstones WHERE expires_at < ?1", [now])
        .map_err(|_| RelayError::Storage)?;
    transaction
        .execute("DELETE FROM ack_tombstones WHERE expires_at <= ?1", [now])
        .map_err(|_| RelayError::Storage)?;
    Ok(())
}

fn verify_single(
    transaction: &Transaction<'_>,
    column: &str,
    mailbox_id: MailboxId,
    capability: &[u8; 32],
) -> Result<bool, RelayError> {
    let query = if column == "retrieve_verifier" {
        "SELECT retrieve_verifier FROM mailboxes WHERE mailbox_id = ?1"
    } else {
        "SELECT management_verifier FROM mailboxes WHERE mailbox_id = ?1"
    };
    let stored: Option<Vec<u8>> = transaction
        .query_row(query, [mailbox_id.as_bytes().as_slice()], |row| row.get(0))
        .optional()
        .map_err(|_| RelayError::Storage)?;
    let kind = if column == "retrieve_verifier" {
        CapabilityKind::Retrieve
    } else {
        CapabilityKind::Management
    };
    Ok(stored.is_some_and(|value| {
        fixed::<32>(value)
            .is_ok_and(|value| bool::from(value.ct_eq(&capability_verifier(kind, capability))))
    }))
}

fn verify_deposit(
    transaction: &Transaction<'_>,
    mailbox_id: MailboxId,
    capability: &[u8; 32],
) -> Result<bool, RelayError> {
    let expected = capability_verifier(CapabilityKind::Deposit, capability);
    let mut statement = transaction
        .prepare("SELECT verifier FROM deposit_verifiers WHERE mailbox_id = ?1")
        .map_err(|_| RelayError::Storage)?;
    let mut rows = statement
        .query([mailbox_id.as_bytes().as_slice()])
        .map_err(|_| RelayError::Storage)?;
    let mut found = false;
    while let Some(row) = rows.next().map_err(|_| RelayError::Storage)? {
        let value = fixed::<32>(row.get::<_, Vec<u8>>(0).map_err(|_| RelayError::Storage)?)?;
        found |= bool::from(value.ct_eq(&expected));
    }
    Ok(found)
}

fn next_sequence(transaction: &Transaction<'_>, mailbox_id: MailboxId) -> Result<u64, RelayError> {
    let value: Option<i64> = transaction
        .query_row(
            "SELECT next_sequence FROM mailboxes WHERE mailbox_id = ?1",
            [mailbox_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RelayError::Storage)?;
    value
        .map(|value| u64::try_from(value).map_err(|_| RelayError::Storage))
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn allocate_sequence(
    transaction: &Transaction<'_>,
    mailbox_id: MailboxId,
) -> Result<u64, RelayError> {
    let sequence = next_sequence(transaction, mailbox_id)?;
    if sequence == 0 {
        return Err(RelayError::Storage);
    }
    let successor = if sequence == MAX_SEQUENCE {
        0
    } else {
        sequence + 1
    };
    transaction
        .execute(
            "UPDATE mailboxes SET next_sequence = ?2 WHERE mailbox_id = ?1",
            params![
                mailbox_id.as_bytes().as_slice(),
                i64::try_from(successor).map_err(|_| RelayError::Storage)?
            ],
        )
        .map_err(|_| RelayError::Storage)?;
    Ok(sequence)
}

fn object_semantics(
    transaction: &Transaction<'_>,
    object_id: &[u8; 16],
) -> Result<Option<ObjectSemantics>, RelayError> {
    let query = "SELECT ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at FROM objects WHERE object_id = ?1 UNION ALL SELECT ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at FROM object_tombstones WHERE object_id = ?1 LIMIT 1";
    transaction
        .query_row(query, [object_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .optional()
        .map_err(|_| RelayError::Storage)?
        .map(
            |(ciphertext_digest, delivery_class, ttl_seconds, snapshot_digest, expires_at)| {
                Ok(ObjectSemantics {
                    ciphertext_digest: fixed(ciphertext_digest)?,
                    delivery_class,
                    ttl_seconds: u64::try_from(ttl_seconds).map_err(|_| RelayError::Storage)?,
                    snapshot_digest: fixed(snapshot_digest)?,
                    expires_at: u64::try_from(expires_at).map_err(|_| RelayError::Storage)?,
                })
            },
        )
        .transpose()
}

struct ObjectSemantics {
    ciphertext_digest: [u8; 32],
    delivery_class: i64,
    ttl_seconds: u64,
    snapshot_digest: [u8; 32],
    expires_at: u64,
}
impl ObjectSemantics {
    fn matches(&self, digest: &[u8; 32], ttl_seconds: u64, snapshot: &[u8; 32]) -> bool {
        self.delivery_class == 1
            && self.ttl_seconds == ttl_seconds
            && self.ciphertext_digest == *digest
            && self.snapshot_digest == *snapshot
            && self.expires_at > 0
    }
}
fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RelayError> {
    value.try_into().map_err(|_| RelayError::Storage)
}
fn accepted() -> WireMessage {
    WireMessage::Accepted(Accepted)
}
fn error(code: ErrorCode) -> WireMessage {
    WireMessage::Error(ErrorMessage { code })
}
