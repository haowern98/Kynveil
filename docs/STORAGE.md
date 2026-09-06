# Kynveil Storage and Recovery Specification

**Status:** Approved  
**Scope:** Local encrypted persistence, relay temporary persistence, transactions, plaintext handling, deletion, backup, and recovery

Kynveil clients own delivered history and cryptographic state. The relay owns neither and retains only temporary ciphertext plus operational delivery state.

## Storage Boundaries

| Store | May contain | Must not contain |
|---|---|---|
| OS secure keystore | One random ProfileMasterSecret and minimal version metadata | Message history, MLS transcripts, media plaintext, server passwords |
| SQLCipher client database | Identity keys, MLS state, capabilities, encrypted metadata/history indexes, outbox and transaction state | Data outside SQLCipher pages or secrets exposed to Electron |
| Client media directory | Authenticated encrypted media blobs named by opaque object IDs | Original filenames or plaintext media |
| Relay persistence | Ciphertext blobs, opaque mailbox routing, TTL, ACK and bounded abuse state | Plaintext, client private keys, MLS secrets, human account/password database |
| Renderer memory | Plaintext currently needed for display/edit | Reusable cryptographic secrets or intentional persistence |

## Local Profile

V1 supports one Kynveil profile per OS user and application-data directory. Rust creates, unlocks, locks, migrates, and closes the profile. Electron receives only task-level results.

Electron Main passes `app.getPath('userData')` exactly once at sidecar launch as
the trusted bootstrap argument `--user-data-root=<absolute path>`. Rust validates
that root, then owns the fixed immutable subtree `<userData>/core/` for the
process lifetime. The renderer never supplies a storage path, selects a profile
directory, receives a resolved database path, or invokes filesystem operations.
There is no `SetProfilePath`, `OpenDatabaseAt`, or `ChangeStorageRoot` IPC
operation. Rust accepts only absolute paths, creates/uses only its fixed child,
and rejects unsafe symlink or reparse-point substitution for Kynveil-owned paths.

The default unlock flow uses one random ProfileMasterSecret protected by the operating-system secure keystore. Rust derives the SQLCipher database key from it; there is no Kynveil password by default.

If the keystore is unavailable or locked, profile creation and unlock fail closed with an actionable error. Linux V1 requires an approved Secret Service implementation; it does not fall back to a plaintext file, environment variable, hard-coded secret, or silent unencrypted database.

On startup, Rust creates a profile only when no evidence of an existing
Kynveil profile is present. It generates and stores the ProfileMasterSecret,
creates the encrypted database, and transitions to `UNLOCKED`. An existing
profile is opened only through its OS-keystore secret and validated SQLCipher
state. Any existing-profile keystore, metadata, authentication, migration, or
storage failure is fail-closed: Rust never silently creates a replacement
identity.

## Operating-System Keystore

Rust uses `keyring-core` 1.0.0 with explicit native providers, rather than the
all-in-one `keyring` defaults:

- macOS: `apple-native-keyring-store` 1.0.2 with only its `keychain` backend;
- Windows: `windows-native-keyring-store` 1.1.0 with Credential Manager
  persistence explicitly set to `Local`, never its default `Enterprise` mode;
- Linux: `zbus-secret-service-keyring-store` 1.0.1 with `crypto-rust`, using
  the user's default/login Secret Service collection.

Kynveil does not request iCloud synchronization or use Apple's Protected Data
backend in V1. On Linux, a missing, unreachable, locked, or non-persistent
Secret Service fails profile creation and unlock closed. There is no fallback to
plaintext files, environment variables, kernel keyutils, a Kynveil password
file, or an Electron credential store.

V1 stores exactly one secret: a 32-byte CSPRNG-generated `ProfileMasterSecret`,
encoded as `v1:<base64url>`. It is generated and returned only inside Rust.
The stable, non-PII labels are `service = org.kynveil.desktop` and
`entry = profile-master-v1`. Logs and crash reports never contain the record
value.

## SQLCipher Database

Use SQLCipher-backed SQLite exclusively through Rust: `rusqlite` 0.40.2 and
`libsqlite3-sys` 0.38.2 are the Rust-facing API/bindings, while Kynveil builds
and statically links the reviewed native archives itself. Node/Electron SQLite
modules, `sqlx`, database daemons, dynamically discovered libraries, and a
Kynveil wrapper abstraction are not used.

Q150 closes only when the required cross-platform regression evidence for the
commit under review is collected. The frozen native-build provenance is:

| Component | Reviewed source and integrity control |
|---|---|
| SQLCipher | Official 4.18.0 Community source at commit `63697beb0fafcb61faa7a3e6fd267036548ab11b`; SHA-256 `31951158488fa3542f1037ff26cb203513075e793f0739975a9a9da22294a305`; SQLite baseline 3.53.4 |
| OpenSSL | Vendored `openssl-src` 300.6.1+3.6.3 source package, which contains OpenSSL 3.6.3; crates.io package SHA-256 `46eb8fb9fb3b61ce1c0f8a026c4c1a0714d3a9e138e7fbde78753ce2babc3846`; consumed by `openssl-sys` 0.9.117 |
| Rust database API | `rusqlite` 0.40.2, checksum `23f2a97da3e3873c73cb2a2e71b35c40ff95e0b1eefa8d72d8499a6928c3b5b3`; `libsqlite3-sys` 0.38.2, checksum `f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8` |
| Toolchain | Rust 1.97.0; platform-native compiler selected by `cc` |

The controlled build generates SQLCipher's official amalgamation, compiles it
with `SQLITE_HAS_CODEC`, `SQLCIPHER_CRYPTO_OPENSSL`, `SQLITE_EXTRA_INIT`,
`SQLITE_EXTRA_SHUTDOWN`, `SQLITE_TEMP_STORE=2`, SQLite API-armoring, and the
reviewed SQLite feature flags in `crates/kynveil-sqlcipher-native/build.rs`.
It stages `libsqlcipher.a`/`sqlcipher.lib` and the exact matching
`libcrypto.a`/`libcrypto.lib` beneath
`target/kynveil-native/sqlcipher/4.18.0/<target>/`. Rust links only that
controlled directory and fails if either archive is absent. It removes all
user-supplied OpenSSL discovery variables before building; system SQLCipher,
system OpenSSL, `PATH`-based library discovery, `pkg-config`, vcpkg, Homebrew,
and runtime `libcrypto`, `libssl`, `libsqlcipher`, or `libsqlite3`
dependencies are prohibited.

Rust is the sole owner of the authoritative writable connection/worker per
unlocked profile, derived database key, SQL execution, migrations, and future rekeying.
Electron receives domain-level results only. There is no arbitrary-SQL IPC API.

The storage initialization sequence must:

1. obtain the random database key from the OS keystore inside Rust;
2. open the database and apply the key before reading schema content;
3. apply and verify the frozen SQLCipher security parameters;
4. run authenticated schema/version checks and bounded migrations;
5. reject a wrong key, corrupt header, failed integrity check, or unsupported version;
6. require non-empty `PRAGMA cipher_version` and `PRAGMA cipher_status = 1`;
7. record non-secret compiled SQLCipher, SQLite baseline, and OpenSSL version diagnostics;
8. expose no raw connection, SQL execution, or database key through IPC.

Q152 remains unchanged: `cipher_memory_security = ON` is applied before keying
and positively verified after keying. The runtime gate normalizes
`PRAGMA cipher_version` and requires exactly `4.18.0 community`; it also
requires the OpenSSL provider, a non-empty provider version, `cipher_status =
1`, and all approved SQLCipher 4 settings. This is defense in depth over the
pinned source, checksum verification, controlled build, and static linkage.

### Q150 regression evidence

| Target | Result | Evidence required before Q150 closure |
|---|---|---|
| Windows x86_64 | Required | Controlled static archives; storage regressions, correct/wrong/unkeyed access, integrity, WAL, restart, and PE-import rejection of prohibited dynamic DLLs |
| Linux x86_64 | Required | Controlled-build storage suite; runtime `cipher_version`/provider and Q152 assertions; `ldd` rejection of prohibited runtime libraries |
| macOS x86_64 | Required | Controlled-build storage suite; runtime `cipher_version`/provider and Q152 assertions; `otool -L` rejection of prohibited runtime libraries |
| macOS arm64 | Required | Controlled-build storage suite; runtime `cipher_version`/provider and Q152 assertions; `otool -L` rejection of prohibited runtime libraries |

The CI `storage` matrix runs those four pending targets on GitHub-hosted
`windows-2025`, `ubuntu-24.04`, `macos-15-intel`, and `macos-15` runners,
asserts
the expected native architecture, executes the Stage 3 storage tests through
the controlled wrapper, verifies the artifact target, and rejects unexpected
runtime dependencies. Q150 cannot close until all rows report a passing run.

### SQLCipher settings and journal behavior

Kynveil uses SQLCipher compatibility 4, a 4096-byte cipher page size,
PBKDF2-HMAC-SHA512 with 256000 iterations, page authentication with HMAC-SHA512,
a zero-byte plaintext header, `cipher_memory_security = ON`, and
`secure_delete = ON`. SQLCipher supplies its normal random database salt;
Kynveil supplies no custom salt. The key is applied with `sqlite3_key_v2()`, not
a secret-bearing SQL statement. Release builds do not enable SQLCipher debugging
or logging.

Project-owned Rust denies unsafe code by default. Unsafe exception 001 permits
one private, item-scoped bridge to `sqlite3_key_v2()` in the storage
implementation because the reviewed dependency exposes that required SQLCipher
API only through raw FFI. The adjacent safety comment must cover connection and
pointer lifetime, exact 32-byte key length, checked C-integer conversion,
SQLCipher's non-retention of the key pointer, and mandatory return-code handling.
The bridge exposes neither raw SQLite pointers nor generic FFI or arbitrary-key
APIs.

Unsafe exception 002 is limited to one private Windows profile-security module.
It invokes only the approved `windows` bindings required to apply and inspect a
current-user, SYSTEM, and Administrators DACL and to reject reparse-point
substitution. Every unsafe block is individually documented, checks return
values and nullable pointers, releases allocations and handles through their
matching APIs, and treats a NULL DACL as insecure. If applying or later
verifying the intended descriptor fails, profile opening fails closed. Its
Windows tests inspect the resulting security descriptor and ACL; API success
alone is insufficient. No other project-owned unsafe code is approved.

Every open also enables `foreign_keys = ON`, `trusted_schema = OFF`,
`journal_mode = WAL`, `synchronous = FULL`, and `temp_store = MEMORY` before
accepting profile work. The selected bundled build compiles with
`SQLITE_TEMP_STORE=2`; the runtime setting prevents Kynveil temporary storage
from using disk. SQLCipher protects WAL database pages. `profile.db`,
`profile.db-wal`, and `profile.db-shm` all receive the same ownership and access
controls; the shared-memory file is sensitive coordination metadata and is not
claimed to contain encrypted user content.

On a clean lock or shutdown, after active database work ends, Rust attempts
`wal_checkpoint(TRUNCATE)`. Confidentiality must not depend on that clean
shutdown: a crash-left WAL must still contain only SQLCipher-protected pages.

Acceptance requires real encrypted read/write execution on Windows x86_64,
macOS x86_64, macOS arm64, and Linux x86_64. Each target proves unkeyed access
cannot read the database, correct-key reopening works, wrong keys fail,
`cipher_status` is `1`, the expected `cipher_version` is reported, and SQLCipher
integrity verification succeeds.

Database encryption primarily protects stolen disks, powered-off machines, copied profile directories, offline filesystem access, and backups. It does not protect plaintext from an attacker controlling the unlocked OS session.

## Local Key Hierarchy

Rust generates a random 256-bit `ProfileMasterSecret` (PMS) and stores it only
in the OS keystore. It generates a random 128-bit `profile_id` in non-secret
profile metadata. The database key is exactly:

```text
HKDF-SHA256(
  IKM  = PMS,
  salt = profile_id,
  info = "kynveil/v1/local-database/" || db_key_epoch
) -> 32 bytes
```

The initial `db_key_epoch` is 1. The database embeds both `profile_id` and
`db_key_epoch`; after unlock they must match external metadata. User-root and
device private keys are independently generated and stored inside SQLCipher;
they are never derived from PMS. The root private key is loaded only for an
operation needing root authority. Stage 3 creates neither a permanent media key
nor a backup key.

## Filesystem Access Controls

On macOS and Linux, the profile directory is `0700` and Kynveil state files are
`0600`. Every profile open verifies current-UID ownership, no prohibited
group/other access, and no symlink substitution for sensitive paths. Permission
repair is allowed only when current-user ownership is unambiguous; otherwise the
profile fails closed.

On Windows, the current-user application-data profile directory receives an
explicit DACL through the Microsoft `windows` bindings. Only the current user,
`SYSTEM`, and `Administrators` are allowed; broad `Everyone`, `Users`, and
`Authenticated Users` access is rejected. Inherited permissions are disabled
where practical. These controls are defense in depth and do not protect against
the same unlocked user, an administrator/root, malware, or OS compromise.

## Logical Data Ownership

The client database owns:

- root and device identity records;
- community genesis and signed control chains;
- channel and membership state;
- MLS operational state;
- inbox replay and processing records;
- outbox ciphertext and submission state;
- delivered message history and encrypted search index;
- mailbox/invite capabilities;
- encrypted media metadata and blob references;
- schema and security migration state.

The relay is never the authoritative source for these records after delivery.

## Atomic Transactions

Security-sensitive state uses one local transactional boundary wherever possible.

### Inbound MLS application message

Atomically commit:

- new MLS group state;
- consumed generation/epoch and replay state;
- validated application message or control event;
- local inbox processing record;
- any required media/key reference.

Only after that durable commit may the client issue a delivery ACK.

### Outbound MLS application message

Atomically commit:

- advanced MLS group state;
- immutable ciphertext bytes and object ID;
- local message/history record;
- outbox submission state and idempotency data.

Network submission begins after commit. Ambiguous transport failure retries the same immutable object rather than regenerating MLS ciphertext.

### Control and membership transition

Where a signed control event and MLS membership change jointly define one user action, the implementation must define a recoverable staged transaction. It must never report success with governance and MLS state silently disagreeing. The exact strategy is frozen before Stage 8.

### Crash injection

Tests must interrupt every boundary before preparation, after candidate cryptographic processing, before commit, after commit, during ACK creation, and during retry. Restart must produce either the complete old state or complete new state, never a hybrid.

## Local Media

Media is stored as authenticated encrypted files under an application-controlled directory. Paths derive from local opaque object identifiers, never remote filenames.

```text
media/
├── 9f/
│   └── 9f2c...blob
└── a1/
    └── a123...blob
```

Original names, MIME claims, dimensions, sender, channel, parent message, content-key record, and other sensitive metadata remain inside encrypted application state.

Inbound media is eligible for ACK only after the complete stream authenticates and both the ciphertext/local state are durably persisted. Partial or unauthenticated plaintext is never rendered as successful content.

V1 transfer resume is excluded. Partial transfer state may be deleted and the transfer restarted without reusing unsafe cryptographic state.

## Plaintext Handling

Never intentionally persist plaintext messages or media in:

- operating-system temp directories;
- renderer web storage, IndexedDB, caches, or persisted state;
- application, relay, Tor, or analytics logs;
- crash reports, traces, fixtures, snapshots, or diagnostic bundles;
- filenames derived from remote metadata.

Plaintext necessarily exists in Rust and renderer memory while the user views or edits it. JavaScript memory cannot be reliably zeroized. Renderer state should retain only the bounded visible working set and release references promptly.

An explicit user-selected export is the only normal plaintext-file path. Rust validates the chosen destination, applies overwrite policy explicitly, and never derives the destination from a remote filename. The UI warns that exported plaintext is no longer protected by Kynveil storage encryption.

## Search

Search indexes and snippets reside only inside the unlocked SQLCipher database. The relay performs no plaintext search. The renderer requests bounded result pages and must not persist them.

## Manual Lock

`Lock Kynveil` performs, in order:

1. stop accepting privileged renderer operations;
2. finish or safely cancel active local transactions;
3. close the unlocked database;
4. discard in-memory decrypted application state and secret buffers where practical;
5. lock the Rust profile;
6. destroy and recreate the renderer context;
7. require another OS-keystore unlock.

Automatic inactivity locking is not enabled in V1. A later configurable policy may be added without weakening manual lock or secret ownership.

The only Stage 3 profile IPC operations are `getProfileStatus`, `lockProfile`,
and `unlockProfile`. `unlockProfile` accepts no input and only asks Rust to retry
the configured OS-keystore unlock. The bounded profile state is one of
`UNLOCKED`, `LOCKED`, `KEYSTORE_UNAVAILABLE`, `CORRUPT`, or `ERROR`; detailed failure information stays
inside Rust or sanitized diagnostics. `lockProfile` returns only after Rust stops
profile work, finishes or safely aborts transactions, closes SQLCipher, clears
profile-dependent state and secret buffers where practical, and becomes
logically locked. Electron then recreates its renderer context.

## Corruption and Rollback

Wrong keys, modified pages, unsupported migrations, corrupt cryptographic records, rollback indicators, and inconsistent MLS/application state fail closed.

The client must not reset counters, restore an older MLS epoch, regenerate
identity secrets, skip an unknown migration, salvage SQLite content, or silently
discard the inconsistent record. It locks the affected profile or channel and
offers only an authenticated rejoin, explicit encrypted diagnostic export, or a
future supported recovery flow.

Schema migrations are forward-only. A database with a schema version newer than
the binary refuses to open; Kynveil never automatically downgrades. Fully
transactional changes run in one SQLite transaction. Fundamental storage or
cryptographic changes use copy, verify, and atomic swap, with explicit
`not_started`, `prepared`, `verified`, and `committed` states. After a committed
migration, Kynveil never automatically restores an older copy.

Database-key rotation is not scheduled. An explicit security response or
storage-policy upgrade increments `db_key_epoch` and uses copy-and-swap, not
`PRAGMA rekey`: lock mutations, checkpoint, verify the old database, reject any
schema not exactly known to be complete, create the successor database keyed for
the new epoch, copy the approved identity state, run SQLCipher and SQLite
integrity checks, flush, atomically replace, update metadata, reopen, and verify. A
rotation marker in the bounded external metadata records `normal`,
`rotation-prepared`, `replacement-verified`, or `swap-completed`; the encrypted
database remains marked `normal` so it can independently prove either
candidate. Startup may attempt the recorded epoch and one successor only if
that marker proves an interrupted rotation; it never searches arbitrary old
keys. Before swap completion, recovery retains the verified old database; after
swap completion, it verifies the successor before deleting the old copy.

Stage 3 diagnostics contain only schema version, database-key epoch, and the
SQLCipher version/provider observed after a successful unlock. They exclude
paths, profile identifiers, errors from external libraries, database contents,
and every secret. An explicit encrypted-profile export copies only the
non-secret metadata plus encrypted database and journal artifacts currently
owned by Stage 3; it never includes the PMS, database key, private keys,
decrypted content, keystore data, or raw IPC. The export remains unreadable
without the original keystore secret and may disclose storage structure and
file sizes.

## Relay Persistence

Relay persistence survives process restart for:

- undelivered ciphertext and encrypted media blobs;
- opaque mailbox delivery records;
- object IDs, expiration, bounded size/class metadata, and ACK state;
- capability verifiers where possible;
- bounded single-use invite/bootstrap state;
- the relay's own persistent onion-service identity outside application storage.

The relay need not persist presence, connections, or disposable rate counters. It must enforce storage and object limits before allocation and use crash-safe updates for deposit, retrieval cursor, ACK, expiry, and deletion eligibility.

After every intended recipient has validly acknowledged an object, its relay ciphertext becomes eligible for deletion. Undelivered objects expire by TTL. Deletion is operational cleanup, not cryptographic erasure from recipients or storage media.

Relay host-volume encryption is recommended defense in depth but is not required for Kynveil's E2EE confidentiality claim because only ciphertext and opaque operational state may be stored.

## Backup Policy

### MVP client

There is no supported identity or history backup. Copying live profile files is not a supported recovery mechanism and must not be advertised as one.

### Future client backup

Before Stage 10, decide whether history backup is included. If included, use a versioned authenticated encrypted archive distinct from identity recovery. Never restore stale MLS operational state; history-only import into fresh membership is the default candidate.

### Self-hosted relay

Operator backup is optional and may contain only relay configuration, onion-service key material, temporary ciphertext, and opaque queue state. Documentation must state restoration staleness and the effect of an expired or already-acknowledged queue snapshot. It never contains client keys or plaintext.

## Recovery Policy

The MVP has no recovery and no server escrow.

If a device is permanently lost:

- its identity and unbacked local history are lost;
- a new installation creates a new root/device identity;
- the new identity must be invited normally;
- an authorized owner or moderator may revoke the old identity;
- stale MLS group state is not restored;
- the new identity receives only content allowed by new-member policy.

Identity recovery is required before a production 1.0 claim. Its design must preserve root authenticity, support loss and revocation, and keep recovery material outside the relay. Identity recovery and message-history recovery remain separate problems.

## Retention and Deletion

- Default relay TTL: seven days for text ciphertext and seven days for media ciphertext.
- ACKed relay objects are deleted when all intended recipients have acknowledged, subject only to bounded crash-safe cleanup.
- Locally delivered history remains until the user deletes it or a future explicit retention policy applies.
- A moderation deletion event may cause compliant clients to hide/delete local content but cannot guarantee other members forgot plaintext.
- Profile deletion must explicitly remove database, encrypted media, keystore record, and app-owned Tor state after exact paths are resolved and confirmed.

Individual deletion uses authenticated SQLCipher deletion with `secure_delete =
ON`; Kynveil may checkpoint/truncate WAL afterward where practical. Media
deletion removes its active record, retained local key material, ciphertext file,
and temporary application references. Stage 3 full-profile deletion locks the profile,
closes storage, removes only the fixed empty Stage 3 media directory plus database,
WAL, shared-memory, and non-secret metadata, then requests PMS deletion from the
OS keystore. Unknown root content or media causes deletion to fail closed rather
than widening the deletion scope. A later media implementation must extend this
exact-path deletion routine before it permits profile media. This does not guarantee physical forensic erasure from wear-leveling,
journals, swap, caches, snapshots, backups, crash dumps, or external copies.

Consumer wording is deliberately limited to: “Kynveil removes the selected data
from its active local storage and uses encrypted storage plus secure-delete
measures to reduce recoverability. It cannot guarantee physical forensic erasure
from SSD wear-leveling, filesystem journals, swap, operating-system caches,
snapshots, backups, crash dumps, or copies made outside Kynveil.” Full profile
deletion may add that Kynveil requests deletion of the local unlock secret to
make retained encrypted profile data inaccessible, while retaining the same
operating-system, backup, and hardware disclaimer. Kynveil never claims data is
permanently unrecoverable, forensically erased, or securely wiped.

## Required Verification

- Database file and backups are unreadable without the correct key.
- Each supported desktop target executes encrypted read/write, unkeyed rejection,
  wrong-key rejection, `cipher_version`, `cipher_status = 1`, and integrity checks.
- Wrong key, modified database, corrupt record, and unsupported migration fail closed.
- Keystore operations use each selected provider; unavailable/locked Linux Secret
  Service, wrong Windows persistence, and unexpected backend selection fail closed.
- Required SQLCipher settings, SQLite defensive settings, WAL mode, full
  synchronization, memory-only temporary storage, and bundled `TEMP_STORE=2`
  are asserted after opening.
- Known plaintext markers are absent from intentionally retained `.db`, `-wal`,
  and `-shm` test files.
- Unsafe ownership, permissions, ACLs, and symlink replacements are rejected;
  only safe current-user permission repairs are allowed.
- Forced interruption at every rotation and migration marker leaves one verified
  authoritative encrypted database and no unlimited historical-key search.
- Diagnostics and encrypted-profile export contain no plaintext or reusable
  secret; profile deletion makes its retained encrypted database inaccessible
  when the keystore successfully removes the PMS.
- No raw key reaches TypeScript, logs, crash reports, temp files, fixtures, or snapshots.
- Manual lock closes storage and destroys the renderer context.
- Inbound and outbound MLS crash matrices never split cryptographic and application state.
- Retried outbound operations reuse the persisted immutable ciphertext and object ID.
- Media ACK occurs only after authentication and durable local persistence.
- Remote filenames cannot escape the media root or select export destinations.
- Relay restart preserves undelivered ciphertext and ACK state but no plaintext.
- Valid ACK and expiry make relay data eligible for deletion idempotently.
- Destroying the relay does not remove client identities or delivered history.

## Explicit Deferrals

| Decision | Deadline | Acceptance summary | Why safe now |
|---|---|---|---|
| MLS persistence representation and transaction API | Before Stage 6 | Atomic state/result commit and crash recovery | MLS implementation does not exist |
| Relay persistence engine | Before Stage 4 | Single-process embedded durability, TTL/ACK transactions, bounds | Relay implementation does not exist |
| Identity recovery | Before production 1.0 in Stage 10 | No escrow, authenticity, revocation and loss analysis | MVP explicitly has no recovery |
| History backup and archive format | Before Stage 10 if included | Authenticated encryption and no stale MLS restore | Backup is absent |
| Self-host relay backup scope | Before Stage 10 | No client secrets/plaintext and defined restoration semantics | Deployment packaging is absent |

## Primary References

- [SQLCipher design](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Microsoft Credential Locker](https://learn.microsoft.com/windows/apps/develop/security/credential-locker)
- [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)
