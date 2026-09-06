# Kynveil Protocol Specification

**Status:** Approved V1.0 relay contract  
**Scope:** Stage 4 typed local protocol and blind-relay persistence. Transport is intentionally excluded until the Tor transport work in Stage 5.

## Encoding and Validation

Every message is RFC 8949 deterministic CBOR. A receiver accepts a value only when decoding it into the exact typed schema and deterministically re-encoding it produces byte-for-byte identical input. Maps and arrays are definite length; map keys are unsigned integers in ascending order. Duplicate, unknown, missing, indefinite-length, non-canonical, malformed, oversized, and over-nested values are rejected. The maximum encoded message is 1 MiB and the maximum nesting depth is four.

Every top-level map contains exactly keys `0`, `1`, and `2` plus the fields listed below. `0` is major version `1`; `1` is minor version `0`; `2` is the numeric message type. V1 accepts exactly version 1.0.

| Type | Numeric value |
|---|---:|
| `ProvisionMailbox` | 0 |
| `AuthorizeDeposit` | 1 |
| `RevokeDeposit` | 2 |
| `Deposit` | 3 |
| `Retrieve` | 4 |
| `Acknowledge` | 5 |
| `DeliveryPage` | 6 |
| `Accepted` | 7 |
| `Error` | 8 |

Mailbox IDs are exactly 32 bytes, object IDs exactly 16 bytes, and capabilities/verifiers exactly 32 bytes. Object IDs are CSPRNG-generated and never reused by senders. The relay does not retain permanent object-ID history.

## Mailbox Operations

```text
ProvisionMailbox = { 0: 1, 1: 0, 2: 0,
  3: mailbox_id: bstr .size 32,
  4: retrieve_verifier: bstr .size 32,
  5: management_verifier: bstr .size 32 }

AuthorizeDeposit = { 0: 1, 1: 0, 2: 1,
  3: mailbox_id: bstr .size 32,
  4: management_capability: bstr .size 32,
  5: deposit_verifier: bstr .size 32 }

RevokeDeposit = { 0: 1, 1: 0, 2: 2,
  3: mailbox_id: bstr .size 32,
  4: management_capability: bstr .size 32,
  5: deposit_verifier: bstr .size 32 }
```

Provisioning is create-only; collision never changes existing state and returns `UNAUTHORIZED_OR_NOT_FOUND`. A mailbox has one retrieve verifier, one management verifier, and at most 256 independent deposit verifiers. Authorization and revocation are management-authorized and idempotent: authorizing an existing verifier or revoking an absent verifier returns `Accepted`. The relay learns no sender, device, community, or channel meaning.

## Deposits and Delivery

```text
Deposit = { 0: 1, 1: 0, 2: 3,
  3: object_id: bstr .size 16,
  4: recipients: [ { 0: mailbox_id: bstr .size 32,
                      1: deposit_capability: bstr .size 32 }, ... ],
  5: ciphertext: bstr .size 1..131072,
  6: delivery_class: 1,
  7: ttl_seconds: uint .size 1..604800 }

Retrieve = { 0: 1, 1: 0, 2: 4,
  3: mailbox_id: bstr .size 32,
  4: retrieve_capability: bstr .size 32,
  5: after_sequence: uint .size 0..9223372036854775807 }

Acknowledge = { 0: 1, 1: 0, 2: 5,
  3: mailbox_id: bstr .size 32,
  4: object_id: bstr .size 16,
  5: delivery_sequence: uint .size 1..9223372036854775807,
  6: retrieve_capability: bstr .size 32 }

DeliveryPage = { 0: 1, 1: 0, 2: 6,
  3: deliveries: [ { 0: delivery_sequence: uint .size 1..9223372036854775807,
                     1: object_id: bstr .size 16,
                     2: delivery_class: 1,
                     3: ciphertext: bstr .size 1..131072,
                     4: expires_at_unix_seconds: uint .size 1..9223372036854775807 }, ... ],
  4: next_cursor: uint .size 0..9223372036854775807 }
```

A deposit has 1–64 recipients. Their mailbox IDs are unique and already in strict ascending bytewise order; receivers reject rather than sort invalid input. Each supplied deposit capability must currently authorize its target mailbox for a new object. Delivery class `1` is the sole V1 class. The client normal TTL is 604800 seconds; the relay calculates expiry from its receive clock plus the explicit supplied TTL.

Each recipient receives an immutable ordered snapshot. The relay stores a snapshot of mailbox IDs and derived deposit verifiers, never raw capabilities. An exact retry matches object ID, `SHA-256(ciphertext)`, class, TTL, and a digest of the complete canonical snapshot. It returns `Accepted`, does not extend TTL, create deliveries, or revive acknowledged state. Later deposit-cap revocation does not invalidate this no-op retry. A reused object ID with any changed semantic field is `BAD_REQUEST`.

Sequences are mailbox-local, start at one, and are strictly monotonic through `2^63 - 1`; allocation beyond that maximum fails closed. Retrieval returns unacknowledged, unexpired deliveries with sequence strictly greater than `after_sequence`, in ascending order, and changes no state. A page holds at most eight deliveries within the 1 MiB total bound. `next_cursor` is always present: it is the final returned sequence, or the unchanged requested cursor when the page is empty.

An acknowledgement is authorized with the retrieve capability, is scoped to the matching mailbox/object/sequence, and is idempotent. It cannot acknowledge another recipient's delivery.

## Capabilities and Persistence

The relay derives capability verifiers exactly as:

```text
SHA-256(ASCII_DOMAIN || 0x00 || capability)
```

The permanent V1 domains are:

```text
kynveil/v1/relay/retrieve-verifier
kynveil/v1/relay/management-verifier
kynveil/v1/relay/deposit-verifier
```

Raw capabilities are transient and never logged or persisted. Comparisons use a constant-time safe API.

The relay logically deletes shared ciphertext when every recipient in its immutable snapshot has acknowledged, or when the TTL expires. Logical deletion does not claim forensic erasure from SQLite, WAL, journals, SSDs, backups, snapshots, swap, or other storage layers.

Until the original expiry, an acknowledged-object tombstone retains only: object ID, ciphertext SHA-256, class, TTL, canonical recipient-snapshot digest, and original expiry. It retains no ciphertext. It permits an exact retry to return `Accepted` without resurrection and rejects changed semantics with `BAD_REQUEST`. Tombstones may be purged after original expiry. Consequently, permanent object-ID replay detection is intentionally unavailable and object-ID non-reuse is a sender/client invariant.

## Results

```text
Accepted = { 0: 1, 1: 0, 2: 7 }
Error = { 0: 1, 1: 0, 2: 8, 3: error_code: uint }
```

| Error | Numeric value |
|---|---:|
| `BAD_REQUEST` | 1 |
| `UNAUTHORIZED_OR_NOT_FOUND` | 2 |
| `RATE_LIMITED` | 3 |
| `TOO_LARGE` | 4 |
| `VERSION_UNSUPPORTED` | 5 |
| `TEMPORARY_UNAVAILABLE` | 6 |
| `QUOTA_EXCEEDED` | 7 |

Errors have no free-form detail, path, identifier, or secret-derived field. The relay is SQLite-backed, in-process, and transport-neutral in Stage 4. It does not expose HTTP, TCP, WebSocket, LAN, or clearnet listeners. Stage 5 owns the Tor/WebSocket transport boundary.

