import { create, fromBinary } from '@bufbuild/protobuf'
import { randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { isAbsolute, resolve, sep } from 'node:path'
import { PassThrough } from 'node:stream'
import { describe, expect, it } from 'vitest'

import {
  CoreState,
  EnvelopeSchema,
  GetProfileStatusResponseSchema,
  GetStatusResponseSchema,
  HelloResponseSchema,
  LockProfileResponseSchema,
  ProfileState,
  ShutdownResponseSchema,
  UnlockProfileResponseSchema,
  type Envelope
} from '../generated/kynveil/ipc/v1/ipc_pb.js'
import {
  FrameDecoder,
  SidecarSupervisor,
  frameEnvelope,
  resolveSidecarPath,
  sanitizedEnvironment,
  userDataRootArgument,
  type ProcessHandle
} from './sidecar.js'

const SESSION = randomBytes(16)

function response(request: Envelope): Envelope {
  let body: Envelope['body']
  switch (request.body.case) {
    case 'helloRequest':
      body = { case: 'helloResponse', value: create(HelloResponseSchema, { coreBuild: 'test' }) }
      break
    case 'getStatusRequest':
      body = {
        case: 'getStatusResponse',
        value: create(GetStatusResponseSchema, { state: CoreState.READY })
      }
      break
    case 'shutdownRequest':
      body = { case: 'shutdownResponse', value: create(ShutdownResponseSchema) }
      break
    case 'getProfileStatusRequest':
      body = {
        case: 'getProfileStatusResponse',
        value: create(GetProfileStatusResponseSchema, { state: ProfileState.UNLOCKED })
      }
      break
    case 'lockProfileRequest':
      body = {
        case: 'lockProfileResponse',
        value: create(LockProfileResponseSchema, { state: ProfileState.LOCKED })
      }
      break
    case 'unlockProfileRequest':
      body = {
        case: 'unlockProfileResponse',
        value: create(UnlockProfileResponseSchema, { state: ProfileState.UNLOCKED })
      }
      break
    default:
      throw new Error('unexpected synthetic request')
  }
  return create(EnvelopeSchema, { ...request, body })
}

class SyntheticProcess extends EventEmitter implements ProcessHandle {
  readonly stdin = new PassThrough()
  readonly stdout = new PassThrough()
  readonly stderr = new PassThrough()
  readonly #decoder = new FrameDecoder()
  #handshaken = false
  readonly mode:
    | 'healthy'
    | 'crash-before-handshake'
    | 'error-before-handshake'
    | 'hang-before-handshake'
    | 'hang-after-handshake'
    | 'hang-shutdown'
    | 'respond-shutdown-without-exit'

  constructor(mode: SyntheticProcess['mode']) {
    super()
    this.mode = mode
    this.stdin.on('data', (chunk: Buffer) => {
      for (const request of this.#decoder.push(chunk)) {
        if (request.body.case === 'helloRequest') this.#handshaken = true
        if (this.mode === 'hang-after-handshake' && request.body.case === 'getStatusRequest') continue
        if (this.mode === 'hang-shutdown' && request.body.case === 'shutdownRequest') continue
        this.stdout.write(frameEnvelope(response(request)))
        if (
          request.body.case === 'shutdownRequest' &&
          this.mode !== 'respond-shutdown-without-exit'
        ) {
          queueMicrotask(() => this.emit('exit', 0, null))
        }
      }
    })

    queueMicrotask(() => {
      if (this.mode === 'error-before-handshake') {
        this.emit('error', new Error('synthetic launch failure'))
        return
      }
      if (this.mode === 'hang-before-handshake') return
      if (this.mode === 'crash-before-handshake') {
        this.emit('exit', 1, null)
        return
      }
      this.stdout.write(
        frameEnvelope(
          create(EnvelopeSchema, {
            protocolMajor: 1,
            protocolMinor: 0,
            requestId: 0n,
            sessionId: SESSION,
            body: {
              case: 'helloResponse',
              value: create(HelloResponseSchema, { coreBuild: 'synthetic-test-core' })
            }
          })
        )
      )
    })
  }

  kill(): boolean {
    queueMicrotask(() => this.emit('exit', 1, null))
    return true
  }

  crash(): void {
    this.emit('exit', this.#handshaken ? 1 : 2, null)
  }

  contaminateStdout(): void {
    this.stdout.write(Buffer.from('not a framed response'))
  }

  floodStderr(): void {
    this.stderr.write(Buffer.alloc(65_537, 120))
  }
}

describe('sidecar transport', () => {
  it('resolves only the fixed absolute application path', () => {
    const packaged = resolveSidecarPath(true, 'synthetic-install/resources', 'ignored')
    const development = resolveSidecarPath(false, 'ignored', 'synthetic-root/apps/desktop')

    expect(isAbsolute(packaged)).toBe(true)
    expect(packaged).toMatch(new RegExp(`bin\\${sep}kynveil-core(?:\\.exe)?$`))
    expect(development).toMatch(new RegExp(`target\\${sep}debug\\${sep}kynveil-core(?:\\.exe)?$`))
  })

  it('passes only explicitly allowed environment variables', () => {
    const result = sanitizedEnvironment({
      SystemRoot: 'C:\\Windows',
      TEMP: 'C:\\Temp',
      NODE_OPTIONS: '--inspect',
      HTTPS_PROXY: 'http://127.0.0.1:9999',
      ELECTRON_RUN_AS_NODE: '1'
    })

    expect(result).toEqual({ SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp' })
  })

  it('passes the trusted Electron user-data root as the only profile bootstrap argument', () => {
    const root = resolve('synthetic-user-data')

    expect(userDataRootArgument(root)).toBe(`--user-data-root=${root}`)
    expect(() => userDataRootArgument('relative-user-data')).toThrow('must be absolute')
  })

  it('decodes fragmented and coalesced frames and rejects contamination', () => {
    const envelope = create(EnvelopeSchema, {
      protocolMajor: 1,
      sessionId: SESSION,
      requestId: 1n,
      body: { case: 'helloResponse', value: create(HelloResponseSchema) }
    })
    const framed = frameEnvelope(envelope)
    const decoder = new FrameDecoder()

    expect(decoder.push(framed.subarray(0, 3))).toEqual([])
    expect(decoder.push(Buffer.concat([framed.subarray(3), framed]))).toHaveLength(2)
    expect(() => new FrameDecoder().push(Buffer.from([0, 0, 0, 0]))).toThrow('invalid frame')
    expect(() => new FrameDecoder().push(Buffer.from([255, 255, 255, 255]))).toThrow(
      'invalid frame'
    )
    expect(() => fromBinary(EnvelopeSchema, Buffer.from([0x80]))).toThrow()
  })

  it('accepts coalesced valid frames up to the aggregate queue ceiling', () => {
    const large = create(EnvelopeSchema, {
      protocolMajor: 1,
      sessionId: SESSION,
      requestId: 1n,
      body: {
        case: 'helloResponse',
        value: create(HelloResponseSchema, { coreBuild: 'x'.repeat(600_000) })
      }
    })
    const frame = frameEnvelope(large)

    expect(new FrameDecoder().push(Buffer.concat([frame, frame]))).toHaveLength(2)
  })

  it('rejects the 257th coalesced frame', () => {
    const envelope = create(EnvelopeSchema, {
      protocolMajor: 1,
      sessionId: SESSION,
      requestId: 1n,
      body: { case: 'helloResponse', value: create(HelloResponseSchema) }
    })
    const frames = Buffer.concat(Array.from({ length: 257 }, () => frameEnvelope(envelope)))

    expect(() => new FrameDecoder().push(frames)).toThrow('IPC queue exhausted')
  })
})

describe('sidecar lifecycle', () => {
  const deadlines = { handshakeMs: 25, requestMs: 25, shutdownMs: 25 }

  it('restarts once before handshake and completes the typed API', async () => {
    let launches = 0
    const supervisor = new SidecarSupervisor(() => {
      launches += 1
      return new SyntheticProcess(launches === 1 ? 'crash-before-handshake' : 'healthy')
    }, deadlines)

    await supervisor.start()
    await expect(supervisor.getStatus()).resolves.toBe('ready')
    await expect(supervisor.getProfileStatus()).resolves.toBe('unlocked')
    await expect(supervisor.lockProfile()).resolves.toBe('locked')
    await expect(supervisor.unlockProfile()).resolves.toBe('unlocked')
    await supervisor.shutdown()
    expect(launches).toBe(2)
    expect(supervisor.state).toBe('stopped')
  })

  it.each(['error-before-handshake', 'hang-before-handshake'] as const)(
    'retries once then locks on %s',
    async (mode) => {
      let launches = 0
      const supervisor = new SidecarSupervisor(() => {
        launches += 1
        return new SyntheticProcess(mode)
      }, deadlines)

      await expect(supervisor.start()).rejects.toThrow()
      expect(launches).toBe(2)
      expect(supervisor.state).toBe('locked')
    }
  )

  it('locks without restarting after a post-handshake crash', async () => {
    let launches = 0
    const child = new SyntheticProcess('healthy')
    const supervisor = new SidecarSupervisor(() => {
      launches += 1
      return child
    }, deadlines)

    await supervisor.start()
    child.crash()
    await new Promise((resolve) => setImmediate(resolve))

    expect(supervisor.state).toBe('locked')
    expect(launches).toBe(1)
  })

  it.each(['stdout', 'stderr'] as const)('locks on invalid %s output', async (stream) => {
    const child = new SyntheticProcess('healthy')
    const supervisor = new SidecarSupervisor(() => child, deadlines)
    await supervisor.start()

    if (stream === 'stdout') child.contaminateStdout()
    else child.floodStderr()
    await new Promise((resolve) => setImmediate(resolve))

    expect(supervisor.state).toBe('locked')
  })

  it('locks and rejects when an ordinary request times out', async () => {
    const supervisor = new SidecarSupervisor(
      () => new SyntheticProcess('hang-after-handshake'),
      deadlines
    )
    await supervisor.start()

    await expect(supervisor.getStatus()).rejects.toThrow('request timed out')
    expect(supervisor.state).toBe('locked')
  })

  it('rejects the 257th outstanding call without growing the queue', async () => {
    const child = new SyntheticProcess('hang-after-handshake')
    const supervisor = new SidecarSupervisor(() => child, {
      ...deadlines,
      requestMs: 1000
    })
    await supervisor.start()
    const queued = Array.from({ length: 256 }, () => supervisor.getStatus())
    const settled = Promise.allSettled(queued)

    await expect(supervisor.getStatus()).rejects.toThrow('IPC busy')
    child.crash()
    await settled
  })

  it('kills a sidecar that exceeds shutdown grace', async () => {
    const child = new SyntheticProcess('hang-shutdown')
    const supervisor = new SidecarSupervisor(() => child, deadlines)
    await supervisor.start()

    await expect(supervisor.shutdown()).rejects.toThrow('shutdown timed out')
    expect(supervisor.state).toBe('stopped')
  })

  it('requires the sidecar to exit after acknowledging shutdown', async () => {
    const child = new SyntheticProcess('respond-shutdown-without-exit')
    const supervisor = new SidecarSupervisor(() => child, deadlines)
    await supervisor.start()

    await expect(supervisor.shutdown()).rejects.toThrow('shutdown timed out')
    expect(supervisor.state).toBe('stopped')
  })

})
