# Kynveil IPC Security

**Status:** Approved  
**Boundary:** Electron renderer and main process to bundled Rust security core

## Objective

IPC must let the Electron interface request narrowly scoped Kynveil actions without exposing reusable cryptographic secrets, arbitrary native functionality, or a general-purpose decryption/signing oracle.

The boundary is:

```text
Potentially compromised renderer
        |
        | allowlisted preload API
        v
Partially trusted Electron Main
        |
        | framed Protobuf over inherited stdin/stdout
        v
Rust security core
```

Possession of a valid IPC channel is never authorization by itself.

## Process Model

Electron launches one bundled Rust child process using an absolute packaged path. The child terminates with the application. V1 does not use localhost HTTP, localhost WebSocket, a persistent daemon, PATH-based executable discovery, or a Node native addon for the core.

The Rust process owns:

- User-root, device, MLS, media, and database secrets.
- Cryptographic and signed-state transitions.
- Authorization decisions.
- SQLCipher and encrypted-media persistence.
- Tor lifecycle and all Kynveil networking.

Electron owns presentation, user intent, lifecycle coordination, and bounded plaintext display.

## Threat Assumptions

- Treat the renderer as potentially compromised.
- Treat every Rust request as potentially malicious, even if Electron Main forwarded it correctly.
- A fully compromised Electron Main is an endpoint compromise and can request plaintext available to the legitimate local user.
- The boundary protects raw keys, unrelated cryptographic material, arbitrary signing/decryption, unauthorized state transitions, and escalation beyond stored local authority.
- The boundary does not protect plaintext currently displayed to a compromised endpoint.

## Transport

IPC uses a schema-defined Protobuf format with explicit length framing:

```text
4-byte unsigned big-endian frame length
encoded IpcEnvelope
```

Stage 2 uses `prost` 0.14.4 in Rust and `@bufbuild/protobuf` plus
`@bufbuild/protoc-gen-es` 2.14.0 in TypeScript. One canonical `.proto` schema
generates both language bindings locally and reproducibly; CI regenerates them
and rejects drift. Generated output is not committed. Kynveil does not require
canonical Protobuf wire serialization because IPC frames are not signed
objects. The initial schema uses no Protobuf map fields and does not introduce
Buf RPC or Connect.

### Stream ownership

- Rust stdout contains framed protocol bytes only.
- Rust stderr contains bounded, redacted diagnostics only.
- Electron never attempts to recover framing from diagnostic text.
- A stdout framing violation terminates the IPC session.
- Secrets, plaintext content, capabilities, full identifiers, and raw frames must not be written to stderr.

## Envelope Model

Every request contains at least:

```text
protocol_major
protocol_minor
sidecar_session_id
request_id
operation
payload
```

Every response contains at least:

```text
protocol_major
protocol_minor
sidecar_session_id
request_id
status
payload
```

The Stage 3 schema contains exactly `Hello`, `GetStatus`, `GetProfileStatus`,
`LockProfile`, `UnlockProfile`, and `Shutdown`.
The schema must not expose generic byte-signing, arbitrary verification,
encryption, decryption, key retrieval, SQL, shell, network, or filesystem
primitives.

## Session and Request Identity

Each Rust process launch creates a random sidecar session identifier. Request IDs are monotonically increasing unsigned 64-bit values scoped to that session.

- A restart creates a new session identifier.
- Duplicate request IDs within one session are rejected.
- Responses and causally related events carry the originating request identity where applicable.
- Wraparound terminates the session rather than reusing an identifier.
- Transport retry of a state-changing operation preserves its durable Kynveil operation/object ID; a new IPC request ID does not create a new cryptographic action.

## Hard Limits

Initial maximums are:

```text
control frame       1 MiB
queued requests     256
aggregate IPC queue 16 MiB
```

All limits apply before large allocation. Nested objects, collections, strings, and byte arrays also obey the protocol-specific limits defined in `PROTOCOL.md`.

Stage 2 uses one serialized FIFO. Reaching either queue ceiling rejects the new
request with a bounded `BUSY` response. The queue continues normally after it
drains. Stage 2 has no streaming or cancellation API and no concurrent
state-changing operation. Media streaming remains owned by Stage 7.

## Validation Order

Rust processes each frame in this order:

1. Read exactly the four-byte length prefix.
2. Reject zero, oversized, or otherwise invalid length before allocating the body.
3. Read the bounded body.
4. Decode using the negotiated schema.
5. Validate required semantic fields and allowed enum values.
6. Validate protocol version and sidecar session identity.
7. Reject duplicate request identity.
8. Validate operation availability for current profile/application state.
9. Validate resource, membership, capability, ownership, and path constraints.
10. Execute the contextual operation.

Protobuf's unknown-field behavior is not treated as security validation. Security-critical fields are checked explicitly after decoding. Unknown operation values are rejected unless a versioned extension defines their behavior.

Malformed framing terminates the session. A semantically invalid but correctly framed request returns a coarse bounded error and does not mutate state.

## Allowed API Shape

The Stage 2 operation allowlist is:

```text
Hello
GetStatus
Shutdown
```

Stage 3 adds only `GetProfileStatus`, `LockProfile`, and `UnlockProfile`.
`UnlockProfile` has no request fields. The renderer never supplies a storage
path, password, ProfileMasterSecret, database key, identity key, or arbitrary
filesystem request. Electron Main alone passes `--user-data-root` to the Rust
sidecar at process launch; Rust resolves the fixed Kynveil-owned child directory.

Adding an operation requires documented purpose, input/output limits,
authorization checks, plaintext behavior, errors, security consequences, and
approval in its owning stage.

Prohibited API shapes include:

```text
Execute
Call
Sign
VerifyArbitrary
Encrypt
Decrypt
ReadFile
WriteFile
RunSql
OpenSocket
FetchUrl
GetPrivateKey
GetSecret
```

## Rust Authorization

Rust independently checks, as applicable:

- Profile unlocked state.
- Operation validity for the current lifecycle state.
- Community and channel membership.
- Owner, moderator, and member capability scope.
- Object existence and ownership.
- Current signed control head and MLS epoch.
- Replay and idempotency state.
- Path provenance and authorization.
- Input size and resource budgets.
- Whether the requested plaintext is legitimately displayable by the local user.

IPC sender validation in Electron is defense in depth and does not replace these checks.

## Renderer and Preload Security

Electron configuration requires:

```text
nodeIntegration = false
contextIsolation = true
sandbox = true
webSecurity = true
```

The preload bridge:

- Exposes only individually named typed methods.
- Does not expose raw `ipcRenderer`, Electron modules, Node primitives, generic invoke, filesystem, shell, or networking access.
- Validates input shape and bounds before forwarding.
- Does not retain secrets or plaintext beyond the operation lifetime.

Electron Main validates the sender frame and allowed application origin for every privileged call.

## Renderer Network Denial

All Kynveil protocol and built-in update traffic follows:

```text
Renderer -> narrow IPC -> Rust core -> Tor -> approved onion service
```

The following path is forbidden:

```text
Renderer -> fetch/XHR/WebSocket -> Internet
```

Stage 2 enforces and tests the precise invariant that renderer content cannot
initiate arbitrary application-controlled network traffic. Enforcement uses:

- Restrictive CSP with no arbitrary `connect-src`.
- Electron session and `webRequest` controls.
- No remote application UI.
- No arbitrary navigation or unexpected windows.
- Deny-by-default permission handling.
- No Node or generic Electron networking in preload.
- DNS prefetch, remote spellcheck services, telemetry, preconnect, and similar incidental traffic disabled where applicable.
- No external-link API in Stage 2.

CSP alone is not claimed to disable every internal Chromium network behavior.
Kynveil disables unnecessary background networking, spellcheck, telemetry,
remote crash reporting, remote resources, previews, and speculative connections
where practical. Any residual Chromium behavior is documented rather than
described as impossible.

An automated test must prove the renderer cannot contact a clearnet test endpoint directly.

## Plaintext Handling

TypeScript may receive only plaintext required for immediate presentation:

- Visible message text.
- Bounded search snippets.
- Display names and permitted metadata.
- Bounded decrypted image or media streams.

TypeScript never receives root/device private keys, MLS secrets, channel secrets, media content keys, mailbox capability secrets, or SQLCipher keys.

Plaintext restrictions:

- No `localStorage`, IndexedDB, persisted Redux/Zustand state, logs, analytics, or remote crash reports.
- Keep only the visible conversation window and bounded virtualization buffer.
- Release references on channel change.
- Revoke media object URLs immediately when unmounted.
- Destroy and recreate the renderer on manual lock.
- Do not promise reliable JavaScript memory zeroization.

## Media IPC

Outbound media begins from an explicit user selection. Stage 7 chooses between a validated path with file identity/stat checks and a safer platform file-handle mechanism. Rust rejects traversal, unauthorized paths, symlink/replacement races where detectable, and non-file inputs.

Inbound media uses a bounded stream or custom application protocol supplied from Rust without plaintext temporary files. The exact mechanism and interface are frozen before Stage 7; Stage 2 does not reserve or expose a streaming API.

Each chunk is bounded to 256 KiB at IPC. Cancellation and backpressure must never leave advanced cryptographic state ambiguous.

## Concurrency, Cancellation, and Ordering

Stage 2 executes all requests through one bounded serialized FIFO. At most 256
requests and 16 MiB of encoded request bodies may wait. Queue exhaustion returns
a bounded `BUSY` response. There is no cancellation API. Later stages may add
carefully scoped concurrency or cancellation only after defining the affected
transaction and cryptographic-state rules.

## Sidecar Lifecycle

Startup begins with a `Hello` exchange containing protocol major/minor versions, sidecar session identity, and build version.

- Unsupported major versions refuse startup.
- Minor compatibility is negotiated only when explicitly defined.
- Until the handshake completes, no profile or cryptographic operation is allowed.
- Unexpected exit locks security-sensitive UI immediately.
- No TypeScript cryptographic or clearnet fallback exists.
- The handshake deadline is five seconds, an ordinary Stage 2 request timeout is
  ten seconds, and shutdown grace is two seconds. Later operations define their
  own deadlines rather than inheriting these values.
- One automatic restart is allowed only before a successful handshake. After a
  successful handshake, a crash, hang, or protocol failure locks the
  security-sensitive UI and is never transparently restarted.
- Repeated failure requires full application restart or explicit recovery.
- Clean shutdown asks Rust to quiesce, close storage, stop Tor, clear owned temporary secrets where practical, and exit.

## Sidecar Authenticity and Launch Hardening

Electron directly spawns the sidecar from the expected absolute packaged
application location with `shell` disabled, a controlled working directory, an
explicit environment allowlist, hidden Windows console, and piped standard
streams. It never uses PATH lookup, a command shell, current-working-directory
discovery, configuration, or user content to select the executable.

Stage 2 prevents casual launch-path substitution. Full signed package and
update-chain enforcement belongs to Stage 10. The sidecar runs as the same OS
user without an additional Stage 2 sandbox; the process boundary separates
memory ownership but is not a separate OS security principal.

## Error Model

IPC errors are typed, bounded, and non-sensitive. They distinguish actionable local states such as invalid request, profile locked, unauthorized operation, unsupported version, resource limit, unavailable storage, Tor unavailable, relay unavailable, and internal failure.

Errors must not include secrets, raw cryptographic material, SQL, arbitrary filesystem paths, full protocol frames, or unnecessary identifiers.

## Stage 2 Security Evidence

The Stage 2 implementation provides automated checks demonstrating:

- Unknown, malformed, oversized, truncated, and invalid-version frames fail safely.
- Size is rejected before large allocation.
- Duplicate and wrong-session request IDs are rejected.
- Semantic and state validation run after decoding.
- Unknown operations cannot reach dispatch.
- Unauthorized operations cannot invoke Rust behavior.
- Raw secrets and generic crypto/filesystem/network/SQL APIs are absent.
- Renderer sender/origin validation is enforced.
- Renderer direct clearnet access fails.
- Stdout diagnostics cannot desynchronize framing.
- Queue limits and backpressure are bounded.
- Timeout, cancellation, crash, restart, and shutdown behavior cannot trigger insecure fallback or duplicate mutation.

The sandboxed preload is emitted as CommonJS because Electron's sandboxed
preload environment does not support arbitrary ESM imports. The renderer uses
a non-persistent session partition, disables DNS prefetching, and exposes only
`window.kynveil.getStatus()`. Sidecar stderr is discarded after enforcing a
64-KiB diagnostic ceiling; stdout remains protocol-only.

Local completion verification passed deterministic generation, TypeScript
lint/type-check/build, 28 desktop tests, the real renderer network-denial
harness, the full preload-to-Rust smoke path, Rust formatting/Clippy/rustdoc,
seven Rust workspace tests, and the high-severity dependency audit.

Tests use runtime-generated, obviously synthetic values. They contain no
production profiles, realistic reusable keys, sensitive payload logs, or
plaintext payload snapshots. Media-stream and file-handoff security evidence is
completed in Stage 7.

## Deferred Decisions

Questions 134–147 are frozen above. Media streaming and user-selected file
handoff remain deferred to Stage 7 under Questions 148–149.
