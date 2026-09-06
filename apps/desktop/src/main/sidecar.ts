import { create, fromBinary, toBinary } from '@bufbuild/protobuf'
import { spawn } from 'node:child_process'
import type { Readable, Writable } from 'node:stream'
import { dirname, isAbsolute, resolve } from 'node:path'

import {
  CoreState,
  EnvelopeSchema,
  GetProfileStatusRequestSchema,
  GetStatusRequestSchema,
  HelloRequestSchema,
  LockProfileRequestSchema,
  ProfileState,
  ShutdownRequestSchema,
  UnlockProfileRequestSchema,
  type Envelope
} from '../generated/kynveil/ipc/v1/ipc_pb.js'

const PROTOCOL_MAJOR = 1
const PROTOCOL_MINOR = 0
const SESSION_ID_LENGTH = 16
const MAX_FRAME_LENGTH = 1024 * 1024
const MAX_QUEUED_FRAMES = 256
const MAX_QUEUED_BYTES = 16 * 1024 * 1024
const MAX_BUFFERED_BYTES = MAX_QUEUED_BYTES + MAX_QUEUED_FRAMES * 4
const MAX_DIAGNOSTIC_BYTES = 64 * 1024

export type ProfileStatus =
  | 'unlocked'
  | 'locked'
  | 'keystore-unavailable'
  | 'corrupt'
  | 'error'

export interface ProcessHandle {
  readonly stdin: Writable
  readonly stdout: Readable
  readonly stderr: Readable
  kill(): boolean
  on(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this
  on(event: 'error', listener: (error: Error) => void): this
}

interface Deadlines {
  readonly handshakeMs: number
  readonly requestMs: number
  readonly shutdownMs: number
}

type SupervisorState = 'stopped' | 'starting' | 'ready' | 'locked' | 'stopping'
interface Pending {
  readonly bytes: number
  readonly expectedCase: Envelope['body']['case']
  readonly reject: (error: Error) => void
  readonly resolve: (envelope: Envelope) => void
  readonly timer: NodeJS.Timeout
}

/** Incrementally decodes bounded length-framed Protobuf envelopes. */
export class FrameDecoder {
  #buffer = Buffer.alloc(0)

  push(chunk: Uint8Array): Envelope[] {
    if (this.#buffer.length + chunk.byteLength > MAX_BUFFERED_BYTES) {
      throw new Error('invalid frame')
    }
    this.#buffer = Buffer.concat([this.#buffer, chunk])
    const envelopes: Envelope[] = []

    while (this.#buffer.length >= 4) {
      const length = this.#buffer.readUInt32BE(0)
      if (length === 0 || length > MAX_FRAME_LENGTH) throw new Error('invalid frame')
      if (this.#buffer.length < length + 4) break
      if (envelopes.length === MAX_QUEUED_FRAMES) throw new Error('IPC queue exhausted')
      const body = this.#buffer.subarray(4, length + 4)
      envelopes.push(fromBinary(EnvelopeSchema, body))
      this.#buffer = this.#buffer.subarray(length + 4)
    }

    return envelopes
  }
}

/** Encodes one bounded IPC envelope with its big-endian length prefix. */
export function frameEnvelope(envelope: Envelope): Buffer {
  const body = toBinary(EnvelopeSchema, envelope)
  if (body.byteLength === 0 || body.byteLength > MAX_FRAME_LENGTH) {
    throw new Error('invalid frame')
  }
  const frame = Buffer.allocUnsafe(body.byteLength + 4)
  frame.writeUInt32BE(body.byteLength, 0)
  frame.set(body, 4)
  return frame
}

/** Resolves the fixed sidecar location for packaged or workspace execution. */
export function resolveSidecarPath(
  packaged: boolean,
  resourcesPath: string,
  applicationPath: string
): string {
  const executable = process.platform === 'win32' ? 'kynveil-core.exe' : 'kynveil-core'
  return packaged
    ? resolve(resourcesPath, 'bin', executable)
    : resolve(applicationPath, '..', '..', 'target', 'debug', executable)
}

/** Builds the explicit environment allowlist passed to the Rust process. */
export function sanitizedEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {}
  for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL']) {
    const value = source[key]
    if (value !== undefined) result[key] = value
  }
  return result
}

/** Builds the only bootstrap argument that selects the Electron-owned profile root. */
export function userDataRootArgument(userDataRoot: string): string {
  if (!isAbsolute(userDataRoot)) throw new Error('user data root must be absolute')
  return `--user-data-root=${userDataRoot}`
}

/** Owns one Rust sidecar session and locks on any post-handshake ambiguity. */
export class SidecarSupervisor {
  #child: ProcessHandle | undefined
  readonly #deadlines: Deadlines
  readonly #factory: () => ProcessHandle
  #decoder = new FrameDecoder()
  #diagnosticBytes = 0
  #greeting: { reject(error: Error): void; resolve(envelope: Envelope): void } | undefined
  #exit: Promise<void> | undefined
  #resolveExit: (() => void) | undefined
  #nextRequestId = 1n
  readonly #pending = new Map<bigint, Pending>()
  #pendingBytes = 0
  #sessionId: Uint8Array | undefined
  state: SupervisorState = 'stopped'

  constructor(
    factory: () => ProcessHandle,
    deadlines: Deadlines = { handshakeMs: 5000, requestMs: 10_000, shutdownMs: 2000 }
  ) {
    this.#factory = factory
    this.#deadlines = deadlines
  }

  async start(): Promise<void> {
    if (this.state !== 'stopped') throw new Error('sidecar already started')
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await this.#startOnce()
        return
      } catch (error) {
        this.#child?.kill()
        this.#resetAttempt()
        if (attempt === 1) {
          this.state = 'locked'
          throw error
        }
      }
    }
  }

  async getStatus(): Promise<'ready' | 'locked'> {
    this.#requireReady()
    const response = await this.#request(
      { case: 'getStatusRequest', value: create(GetStatusRequestSchema) },
      'getStatusResponse',
      this.#deadlines.requestMs,
      'request timed out'
    )
    if (response.body.case !== 'getStatusResponse') {
      this.#lock('invalid status response')
      throw new Error('invalid status response')
    }
    if (response.body.value.state === CoreState.READY) return 'ready'
    if (response.body.value.state === CoreState.LOCKED) return 'locked'
    this.#lock('invalid status response')
    throw new Error('invalid status response')
  }

  async getProfileStatus(): Promise<ProfileStatus> {
    return this.#profileRequest(
      { case: 'getProfileStatusRequest', value: create(GetProfileStatusRequestSchema) },
      'getProfileStatusResponse'
    )
  }

  async lockProfile(): Promise<ProfileStatus> {
    return this.#profileRequest(
      { case: 'lockProfileRequest', value: create(LockProfileRequestSchema) },
      'lockProfileResponse'
    )
  }

  async unlockProfile(): Promise<ProfileStatus> {
    return this.#profileRequest(
      { case: 'unlockProfileRequest', value: create(UnlockProfileRequestSchema) },
      'unlockProfileResponse'
    )
  }

  async #profileRequest(
    body: Envelope['body'],
    expectedCase: 'getProfileStatusResponse' | 'lockProfileResponse' | 'unlockProfileResponse'
  ): Promise<ProfileStatus> {
    this.#requireReady()
    const response = await this.#request(body, expectedCase, this.#deadlines.requestMs, 'request timed out')
    if (response.body.case !== expectedCase) throw new Error('invalid profile response')
    return profileStatus(response.body.value.state)
  }

  async shutdown(): Promise<void> {
    this.#requireReady()
    this.state = 'stopping'
    try {
      await this.#request(
        { case: 'shutdownRequest', value: create(ShutdownRequestSchema) },
        'shutdownResponse',
        this.#deadlines.shutdownMs,
        'shutdown timed out'
      )
      this.#child?.stdin.end()
      await this.#waitForExit()
      this.state = 'stopped'
    } catch (error) {
      this.#child?.kill()
      this.state = 'stopped'
      throw error
    }
  }

  async #startOnce(): Promise<void> {
    this.state = 'starting'
    const child = this.#factory()
    this.#child = child
    this.#exit = new Promise((resolveExit) => {
      this.#resolveExit = resolveExit
    })
    child.stdout.on('data', (chunk: Buffer) => {
      if (child !== this.#child) return
      try {
        for (const envelope of this.#decoder.push(chunk)) this.#receive(envelope)
      } catch {
        this.#lock('IPC protocol failure')
      }
    })
    child.stderr.on('data', (chunk: Buffer) => {
      if (child !== this.#child) return
      this.#diagnosticBytes += chunk.byteLength
      if (this.#diagnosticBytes > MAX_DIAGNOSTIC_BYTES) this.#lock('sidecar diagnostics exceeded limit')
    })
    child.on('exit', () => {
      if (child !== this.#child) return
      this.#resolveExit?.()
      if (this.state === 'starting') this.#greeting?.reject(new Error('sidecar exited'))
      else if (this.state === 'ready') this.#lock('sidecar exited')
    })
    child.on('error', (error) => {
      if (child !== this.#child) return
      if (this.state === 'starting') this.#greeting?.reject(error)
      else if (this.state === 'ready') this.#lock('sidecar failed')
    })

    const greeting = await new Promise<Envelope>((resolveGreeting, rejectGreeting) => {
      const timer = setTimeout(() => {
        rejectGreeting(new Error('handshake timed out'))
      }, this.#deadlines.handshakeMs)
      this.#greeting = {
        reject: (error) => {
          clearTimeout(timer)
          rejectGreeting(error)
        },
        resolve: (envelope) => {
          clearTimeout(timer)
          resolveGreeting(envelope)
        }
      }
    })
    this.#validateGreeting(greeting)
    await this.#request(
      {
        case: 'helloRequest',
        value: create(HelloRequestSchema, { clientBuild: 'kynveil-desktop/0.0.0' })
      },
      'helloResponse',
      this.#deadlines.handshakeMs,
      'handshake timed out'
    )
    this.state = 'ready'
  }

  #receive(envelope: Envelope): void {
    if (this.#sessionId === undefined && envelope.requestId === 0n) {
      this.#greeting?.resolve(envelope)
      return
    }
    if (
      envelope.protocolMajor !== PROTOCOL_MAJOR ||
      envelope.protocolMinor !== PROTOCOL_MINOR ||
      !Buffer.from(envelope.sessionId).equals(Buffer.from(this.#sessionId ?? []))
    ) {
      this.#lock('IPC protocol failure')
      return
    }
    const pending = this.#pending.get(envelope.requestId)
    if (pending === undefined || envelope.body.case !== pending.expectedCase) {
      this.#lock('IPC protocol failure')
      return
    }
    clearTimeout(pending.timer)
    this.#pendingBytes -= pending.bytes
    this.#pending.delete(envelope.requestId)
    pending.resolve(envelope)
  }

  #validateGreeting(envelope: Envelope): void {
    if (
      envelope.protocolMajor !== PROTOCOL_MAJOR ||
      envelope.protocolMinor !== PROTOCOL_MINOR ||
      envelope.requestId !== 0n ||
      envelope.sessionId.byteLength !== SESSION_ID_LENGTH ||
      envelope.body.case !== 'helloResponse'
    ) {
      throw new Error('invalid sidecar greeting')
    }
    this.#sessionId = envelope.sessionId
  }

  #request(
    body: Envelope['body'],
    expectedCase: Envelope['body']['case'],
    timeoutMs: number,
    timeoutMessage: string
  ): Promise<Envelope> {
    const child = this.#child
    const sessionId = this.#sessionId
    if (child === undefined || sessionId === undefined) return Promise.reject(new Error('sidecar unavailable'))
    if (this.#pending.size >= MAX_QUEUED_FRAMES) return Promise.reject(new Error('IPC busy'))
    const requestId = this.#nextRequestId
    if (requestId === 0xffff_ffff_ffff_ffffn) return Promise.reject(new Error('request identity exhausted'))
    this.#nextRequestId += 1n
    const frame = frameEnvelope(
      create(EnvelopeSchema, {
        protocolMajor: PROTOCOL_MAJOR,
        protocolMinor: PROTOCOL_MINOR,
        sessionId,
        requestId,
        body
      })
    )
    const bytes = frame.byteLength - 4
    if (this.#pendingBytes + bytes > MAX_QUEUED_BYTES) {
      return Promise.reject(new Error('IPC busy'))
    }

    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        this.#pendingBytes -= bytes
        this.#pending.delete(requestId)
        this.#lock(timeoutMessage)
        rejectRequest(new Error(timeoutMessage))
      }, timeoutMs)
      this.#pendingBytes += bytes
      this.#pending.set(requestId, {
        bytes,
        expectedCase,
        reject: rejectRequest,
        resolve: resolveRequest,
        timer
      })
      child.stdin.write(frame)
    })
  }

  #lock(message: string): void {
    if (this.state !== 'stopping') this.state = 'locked'
    this.#child?.kill()
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer)
      pending.reject(new Error(message))
    }
    this.#pending.clear()
    this.#pendingBytes = 0
  }

  #requireReady(): void {
    if (this.state !== 'ready') throw new Error('sidecar unavailable')
  }

  async #waitForExit(): Promise<void> {
    const exit = this.#exit
    if (exit === undefined) throw new Error('sidecar unavailable')
    await new Promise<void>((resolveExit, rejectExit) => {
      const timer = setTimeout(() => {
        rejectExit(new Error('shutdown timed out'))
      }, this.#deadlines.shutdownMs)
      void exit.then(() => {
        clearTimeout(timer)
        resolveExit()
      })
    })
  }

  #resetAttempt(): void {
    this.#child = undefined
    this.#decoder = new FrameDecoder()
    this.#diagnosticBytes = 0
    this.#greeting = undefined
    this.#exit = undefined
    this.#resolveExit = undefined
    this.#sessionId = undefined
    this.#nextRequestId = 1n
    this.#pendingBytes = 0
  }
}

function profileStatus(state: ProfileState): ProfileStatus {
  switch (state) {
    case ProfileState.UNLOCKED:
      return 'unlocked'
    case ProfileState.LOCKED:
      return 'locked'
    case ProfileState.KEYSTORE_UNAVAILABLE:
      return 'keystore-unavailable'
    case ProfileState.CORRUPT:
      return 'corrupt'
    default:
      return 'error'
  }
}

/** Creates the production supervisor with a direct, fixed-path child launch. */
export function createSidecarSupervisor(
  packaged: boolean,
  resourcesPath: string,
  applicationPath: string,
  userDataRoot: string
): SidecarSupervisor {
  const binary = resolveSidecarPath(packaged, resourcesPath, applicationPath)
  const bootstrapArgument = userDataRootArgument(userDataRoot)
  return new SidecarSupervisor(() => {
    const child = spawn(binary, [bootstrapArgument], {
      cwd: dirname(binary),
      env: sanitizedEnvironment(process.env),
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    })
    return child
  })
}
