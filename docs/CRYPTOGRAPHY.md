# Kynveil Cryptography Specification

**Status:** Approved  
**Scope:** Implementation-independent requirements for identities, MLS, media protection, key lifecycle, and cryptographic state

This document defines Kynveil's cryptographic boundary. It does not select a crate where that choice is deliberately deferred. Protocol serialization and relay delivery are specified in `PROTOCOL.md`; persistence mechanics are specified in `STORAGE.md`.

## Governing Rules

- Use established protocols and maintained implementations; do not invent primitives or ratchets.
- Rust owns every private identity key, database key, MLS secret, media key, and key-derivation intermediate.
- TypeScript never receives raw private keys, channel secrets, MLS secrets, database keys, or reusable bearer capabilities.
- Authentication or integrity failure is terminal for the affected object. Never repair, downgrade, or accept it silently.
- Every signed Kynveil object uses an explicit domain separator and RFC 8949 deterministic CBOR bytes.
- Random identifiers, capabilities, and keys come from an operating-system cryptographically secure random source through reviewed Rust APIs.
- Cryptographic state is versioned, bounded, and persisted atomically with the application state derived from it.

## Identity Hierarchy

```text
User Root Identity
      |
      | signs
      v
Device Identity
      |
      | represented by
      v
MLS Credential

Community Identity = SHA-256(deterministic signed genesis object)
Display Identity   = untrusted profile metadata
```

### User root identity

The user root is a long-lived Ed25519 signing identity. It authorizes device credentials and rare root-level actions such as ownership transfer. Routine messages do not use the root private key. V1 has no root-key rotation; a compromised or lost root requires a new identity and rejoin.

Stage 3 implements Ed25519 with `ed25519-dalek` 3.0.0 using its default
`fast` and `zeroize` features. Rust generates exactly 32 seed bytes with
`getrandom::fill`, constructs `SigningKey::from_bytes`, derives the
`VerifyingKey` from that signing key, and immediately zeroizes the temporary
seed. The `rand_core`, `hazmat`, `legacy_compatibility`, and private-key
serialization features are not enabled. Signing keys and seed bytes never
cross IPC or enter Electron.

The root public key, together with its algorithm and format version, forms the cryptographic user identifier. Display names and avatars are not authentication.

### Device identity

Each installation generates an independent Ed25519 device signing key. A versioned device credential binds the device public key to the user root and is signed by the user root under the `kynveil/v1/device-credential` domain.

Stage 3 freezes the V1 device-credential payload as a six-entry, definite-length,
integer-keyed CBOR map using RFC 8949 Core Deterministic Encoding. `minicbor`
2.3.0 is used manually with only its `alloc` feature; derive support is not
enabled. The keys, emitted in this exact order, are: `0` version, `1` 32-byte
user-root ID, `2` 16-byte device ID, `3` 32-byte device signing public key,
`4` 32-byte MLS signing-key binding, and `5` unsigned Unix `created_at`
seconds. V1 requires key `4` to equal key `3`. The root signature is outside
the CBOR payload and covers exactly
`b"kynveil/v1/device-credential" || [0x00] || deterministic_cbor`.

Decoders reject indefinite or malformed maps, wrong field types or lengths,
duplicate, missing, or unknown fields, unsupported versions, trailing bytes,
and a binding that differs from the device public key. They deterministically
re-encode an accepted value and require a byte-for-byte match before signature
verification. Fixed byte vectors guard this signed representation.

V1 permits one active device per user, but the user/device distinction is mandatory. Device credentials do not expire automatically and remain valid until a root-signed revocation. Revocation also removes the device from applicable MLS groups and future capabilities. Revoking or replacing a device does not redefine the user's root identity.

Users can compare a fingerprint or QR representation derived from the root identity. Display identity never substitutes for this verification.

### MLS credential

V1 uses an MLS `BasicCredential`. Its identity field contains a stable hash/identifier of the root-signed device credential, and its MLS signature key matches the signing material authorized by that credential. It is not the permanent Kynveil user identity. Exact byte encoding and extension use must be frozen before Stage 6 without changing this mapping.

### Community identity

A community has no required secret identity key. Its identifier is the SHA-256 digest of the deterministic bytes of its creator-signed genesis object. The genesis object binds its version, random nonce, creator root and device identities, initial owner, initial policy, and initial relay descriptor.

Changing a relay address does not change the community identifier.

## Signature Domains

Each signed object prepends or structurally binds one exact ASCII domain. At minimum:

| Object | Domain |
|---|---|
| Device credential | `kynveil/v1/device-credential` |
| Community genesis | `kynveil/v1/community-genesis` |
| Control event | `kynveil/v1/control-event` |
| Ownership transfer | `kynveil/v1/ownership-transfer` |
| Invite | `kynveil/v1/invite` |
| Relay update | `kynveil/v1/relay-update` |

Signatures cover the domain, schema version, and deterministic CBOR representation of every security-relevant field. Parsers reject a valid signature used under the wrong domain or schema.

## Messaging Layer Security

Kynveil uses MLS as standardized by RFC 9420. Stage 6 begins with a two-member MLS group for the Alice-to-Bob production-shaped text path. It must not introduce a temporary custom two-party protocol.

The V1 ciphersuite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` unless the Stage 6 OpenMLS/provider review establishes a concrete interoperability or security blocker and records a replacement decision. Experimental post-quantum or draft ciphersuites are excluded from V1.

Stage 8 generalizes the proven model to communities. Each encrypted channel is an independent MLS group, including private channels. This contains membership changes and key evolution to the affected channel.

```text
Community
├── general   -> MLS Group A
├── gaming    -> MLS Group B
└── staff     -> MLS Group C
```

### Implementation freeze

OpenMLS is the primary implementation candidate. The exact OpenMLS version and crypto provider must be frozen before Stage 6, after confirming:

- RFC 9420 conformance and applicable test vectors;
- active security maintenance and current advisory review;
- Windows, macOS, and Linux support;
- acceptable licensing and transitive dependency surface;
- persistence APIs that support Kynveil's transaction boundary;
- add, remove, Welcome, Commit, rejoin, and interoperability behavior;
- no sensitive release logging or debugging features.

This deferral is safe because no MLS implementation exists before Stage 6.

### Bootstrap material

- The joining Rust core generates each KeyPackage locally; the relay never generates one.
- KeyPackages are one-time, have a bounded lifetime targeted in days rather than months, and consumed references persist locally.
- The exact lifetime freezes before Stage 6.
- The inviter validates the root-signed device credential, BasicCredential binding, KeyPackage signature, and expected invite/community context.
- Each MLS GroupID is 32 random bytes from a CSPRNG and is not derived from a name.
- A Welcome travels inside the recipient's opaque temporary mailbox envelope.

### Group and epoch rules

- Application content uses MLS `PrivateMessage` protection.
- Welcome, Proposal, and Commit handling follows RFC 9420 validation and sequencing.
- The Kynveil transport treats MLS messages as opaque ciphertext.
- An add or removal becomes effective only through a valid committed epoch transition.
- Removed members cannot decrypt future-epoch traffic; content they already decrypted cannot be revoked.
- New members receive content from their join epoch onward. V1 does not re-encrypt prior history.
- Stale, replayed, conflicting, or context-mismatched Welcome and Commit messages fail closed. Rejection includes a consumed KeyPackage or invite, unexpected GroupID, invalid signed membership state, stale bootstrap generation, or a locally completed join.
- Application object IDs supplement, but never replace, MLS generation and epoch validation.
- A bounded future-epoch queue may briefly await a missing Commit. If required state cannot be obtained before its limits, the group is desynchronized and must rejoin; Kynveil never guesses missed MLS state.

### Forward secrecy and post-compromise security

Kynveil inherits only the properties provided by the selected, correctly operated RFC 9420 cipher suite and implementation. Secure deletion of obsolete state is required where the library exposes it. The application must define an update cadence before Stage 8 and test that removed or refreshed members advance to new epochs.

Kynveil does not claim recovery from a currently compromised endpoint, protection from a malicious authorized member, or retroactive erasure of plaintext already observed.

### Removal and rejoin acceptance sequence

1. Alice and Bob share a functioning two-member MLS group.
2. Alice removes Bob and commits the change.
3. Both current states advance and persist atomically.
4. Bob cannot decrypt application messages created after removal.
5. Replayed pre-removal application, Welcome, or Commit objects are rejected.
6. A fresh authenticated invitation authorizes Bob's return.
7. Bob presents a fresh valid KeyPackage bound to his authenticated device.
8. The authorized member commits the add and delivers the corresponding Welcome.
9. Bob creates fresh group state without restoring stale operational state.
10. Post-rejoin messages work; excluded-epoch messages remain unavailable.

## Atomic Cryptographic State

No operation may expose a state transition externally before its durable transaction is ready.

OpenMLS state and the application records derived from it live in the same SQLCipher database and participate in a Kynveil-owned backing-store transaction. A storage-provider integration that cannot participate in that boundary is rejected.

Inbound transaction:

```text
validate object and replay state
process MLS message into candidate state
derive application/control result
commit new MLS state + replay state + derived result
then permit acknowledgement
```

Outbound transaction:

```text
create MLS message and candidate state
commit new MLS state + ciphertext + object ID + outbox/history row + delivery target snapshot
then permit relay submission
```

The design must prevent generation reuse, old-epoch restoration, a committed epoch without its application result, an application result without its corresponding epoch, and unprotected repetition of state-changing operations after a crash. The concrete OpenMLS persistence format and database transaction strategy are Stage 6 freeze decisions.

## Media Cryptography

Large media is not placed inside MLS application messages. Each object receives a fresh random content key and is encrypted as a bounded stream. MLS transports and authenticates the content key plus encrypted metadata and bindings.

```text
plaintext media -> streaming encryption -> ciphertext blob -> relay
media key + metadata + blob binding -> MLS PrivateMessage -> relay
```

The primary construction to evaluate before Stage 7 is a maintained Rust implementation with libsodium-compatible `crypto_secretstream_xchacha20poly1305` semantics, or another approved established construction providing authenticated order and finalization.

Required properties:

- 256 KiB initial plaintext chunk size;
- unique random key per media object;
- bounded-memory encryption and decryption;
- authenticated chunk order and explicit final chunk;
- rejection of truncation, reordering, duplication, appending, and cross-object splicing;
- authenticated binding among media object ID, channel, parent message, sender, key, encrypted metadata, and ciphertext blob;
- no V1 blob deduplication or key reuse;
- no V1 resumable upload or download; interrupted transfers restart.

The library, container, rekey policy, and exact binding format must be frozen before Stage 7. The 100 MiB object cap makes restart-only transfer acceptable for V1; resume must be reconsidered during Kynveil 1.1 planning or before increasing that cap.

## Local Storage Cryptography

Rust generates one random 256-bit ProfileMasterSecret (PMS) and stores it in the
approved OS keystore. Electron never sees it. A random 128-bit non-secret
`profile_id` and `db_key_epoch` derive the 32-byte database key with
HKDF-SHA256 using the exact info string `kynveil/v1/local-database/ || epoch`.
The initial epoch is 1. The approved integration is `rusqlite` 0.40.2 with
`bundled-sqlcipher-vendored-openssl`, resolving `libsqlite3-sys` 0.38.2 from the
reviewed lockfile. System or dynamically discovered SQLite, SQLCipher, and
OpenSSL are prohibited.

SQLCipher uses compatibility 4, 4096-byte pages, PBKDF2-HMAC-SHA512 at 256000
iterations, page HMAC-SHA512, no plaintext header, `cipher_memory_security =
ON`, and `secure_delete = ON`. Rust applies the derived key with
`sqlite3_key_v2()` and never logs a secret-bearing key statement. A database
merely opening is not proof of correct encryption: after keying, Rust requires a
non-empty `PRAGMA cipher_version`, `PRAGMA cipher_status = 1`, expected settings,
SQLCipher integrity verification, and unreadability without the key. Stage 3
diagnostics expose only the observed SQLCipher version/provider plus non-secret
schema and key-epoch values.

User-root and device private keys are independently generated and stored inside
SQLCipher; they are never derived from PMS. Routine messaging uses device and
MLS state, and the root key is loaded only for root-authorized work. Stage 3
creates neither a permanent media key nor a backup key; Stage 7 uses a new random
content key per media object.

## Key Lifecycle

| Material | Created | Stored | Rotated/replaced | Destroyed or invalidated |
|---|---|---|---|---|
| User root key | Profile creation in Rust | Encrypted local database, unlocked through OS-keystore-held master key | Only through a future approved recovery/replacement design | Profile destruction or explicit identity abandonment |
| Device key | Installation/profile creation | Encrypted local database | Device replacement or revocation | Revocation plus secure local deletion where practical |
| ProfileMasterSecret | Profile creation from CSPRNG | OS secure keystore | Never scheduled; retained while database-key epochs rotate | Profile destruction or keystore deletion |
| Derived database key | HKDF-SHA256 from PMS, profile ID, and epoch | Rust memory only | Guarded copy-and-swap database-key rotation; refuse schemas it cannot copy completely | Profile lock, process exit, or epoch replacement |
| MLS private state | Group creation/join/epoch transitions | Encrypted local database | Every applicable MLS state transition | Obsolete secrets erased when implementation permits |
| Media content key | Once per media object | Encrypted local application state only as needed | Never reused; replacement means a new encrypted object | After retention/export needs end |
| Mailbox capability | Mailbox provisioning | Encrypted local database; relay keeps verifier where possible | Compromise, membership change, or descriptor rotation | Revoked verifier and local secret deletion |
| Invite secret | Invite creation | Encrypted local state and bounded relay bootstrap state | Never reused | Consumption, revocation, or expiry |

Secret buffers use `zeroize` or an established equivalent where practical. Kynveil does not promise perfect erasure from garbage-collected memory, OS paging, allocator internals, CPU registers, crash dumps, or third-party libraries.

## Recovery Policy

The MVP deliberately has no identity or history recovery. There is no server escrow, recovery email, password reset, or relay-held decryption key.

Permanent device loss means the old identity and unbacked local history are lost. A new installation creates a new cryptographic identity and must be invited again. The old identity may be revoked by authorized community governance. Stale MLS operational state must never be restored from backup.

Before production 1.0, identity recovery must be designed separately from optional history backup. Any approved design must preserve root authenticity, exclude server-side escrow, define revocation, and prevent MLS epoch or generation rollback.

## Randomness and Derivation

- All long-term keys, ephemeral keys, nonces requiring randomness, capabilities, invite tokens, and object IDs use a reviewed OS-backed CSPRNG.
- No security decision relies on timestamps, counters alone, display names, or relay-generated randomness.
- Domain-separated KDF contexts are mandatory wherever application-level derivation is introduced.
- The selected MLS and media implementations own their standardized nonce and key schedules; Kynveil must not override them casually.
- Test fixtures use published vectors or clearly marked non-production deterministic material and never production secrets.

## Failure Behavior

On invalid signatures, ciphertexts, tags, epochs, credentials, or state:

1. do not emit plaintext or advance durable cryptographic state;
2. do not acknowledge the object as successfully delivered;
3. record only a bounded, non-sensitive diagnostic classification;
4. lock the affected channel/profile when continued operation could reuse or roll back state;
5. use an authenticated rejoin or supported recovery path rather than silent reset.

## Required Verification

- RFC 8032 Ed25519 vectors.
- Altered-signature and altered-signed-payload rejection for every Stage 3
  identity signing path.
- RFC 9420 and applicable OpenMLS interoperability vectors.
- Deterministic serialization golden vectors for every signed object.
- Signature-domain substitution and malformed-credential rejection.
- Modified, replayed, reordered, and stale MLS object rejection.
- The two-member offline delivery and restart acceptance path.
- The ten-step removal/rejoin sequence above.
- Crash injection before and after every durable MLS transition boundary.
- Media fixed vectors plus truncation, append, duplicate, reorder, and splice failures.
- Database unreadability without its key and rejection of modified storage.
- Encrypted read/write, unkeyed rejection, wrong-key rejection, `cipher_status = 1`, expected `cipher_version`, and integrity verification on every supported desktop target.
- Domain-separation and epoch test vectors for the local HKDF derivation, plus
  proof that root/device keys are independently random rather than PMS-derived.
- No plaintext markers in intentionally retained database, WAL, or shared-memory
  files; no secret in diagnostics or encrypted-profile export.
- Automated checks that no raw secret crosses into TypeScript or logs.

## Explicit Deferrals

| Decision | Deadline | Acceptance summary | Why safe now |
|---|---|---|---|
| OpenMLS version and crypto provider | Before Stage 6 | RFC 9420, maintenance, platform, persistence, vectors, advisory review | MLS code does not yet exist |
| BasicCredential byte encoding and MLS persistence format | Before Stage 6 | Preserve the approved device-credential hash/signing-key binding and atomic recovery | MLS code does not yet exist |
| Epoch update cadence and multi-epoch catch-up | Before Stage 8 | Bounded catch-up, PCS rationale, deterministic rejoin | Multi-member channels do not yet exist |
| Media streaming implementation/container/rekey policy | Before Stage 7 | Authenticated order/finalization, bounds, vectors, platform support | Media code does not yet exist |
| Report-recipient keying | Before Stage 9 | Least privilege and rotation after moderator removal | Moderation reports do not yet exist |
| Identity recovery | Before production 1.0 in Stage 10 | No escrow, root authenticity, loss/revocation analysis | MVP explicitly discloses no recovery |
| Backup treatment of MLS state | Before Stage 10 | No stale operational-state restore | Backups do not exist |
| Update signing hierarchy and revocation | Before Stage 10 | Offline/delegated trust, rollback and compromise recovery | Updater does not exist |
| Test-secret policy details | Before Stage 2 and refined per stage | Non-production fixtures and secret scanning | Test fixtures do not yet exist |

## Primary References

- [RFC 9420 — The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9750 — The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750.html)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8949 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html)
- [libsodium secretstream documentation](https://doc.libsodium.org/secret-key_cryptography/secretstream)
- [OpenMLS documentation](https://openmls.tech/)
