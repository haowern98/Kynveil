import { create, fromBinary, toBinary } from '@bufbuild/protobuf'
import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import { EnvelopeSchema, GetStatusRequestSchema } from '../generated/kynveil/ipc/v1/ipc_pb.js'

describe('Stage 3 IPC schema', () => {
  it('round-trips an allowlisted GetStatus request', () => {
    const envelope = create(EnvelopeSchema, {
      protocolMajor: 1,
      protocolMinor: 0,
      requestId: 2n,
      sessionId: randomBytes(16),
      body: {
        case: 'getStatusRequest',
        value: create(GetStatusRequestSchema)
      }
    })

    const decoded = fromBinary(EnvelopeSchema, toBinary(EnvelopeSchema, envelope))

    expect(decoded.protocolMajor).toBe(1)
    expect(decoded.requestId).toBe(2n)
    expect(decoded.body.case).toBe('getStatusRequest')
  })

  it('contains no generic privileged operation', () => {
    const forbidden = /execute|call|sign|verifyArbitrary|encrypt|decrypt|readFile|writeFile|runSql|openSocket|fetchUrl|getPrivateKey|getSecret/i
    const operationNames = Object.values(EnvelopeSchema.fields)
      .map((field) => field.localName)
      .filter((name) => name.endsWith('Request'))

    expect(operationNames).toEqual([
      'helloRequest',
      'getStatusRequest',
      'shutdownRequest',
      'getProfileStatusRequest',
      'lockProfileRequest',
      'unlockProfileRequest'
    ])
    expect(operationNames.join(' ')).not.toMatch(forbidden)
  })
})
