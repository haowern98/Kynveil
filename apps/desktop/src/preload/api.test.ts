import { describe, expect, it, vi } from 'vitest'

import { createKynveilApi } from './api.js'

describe('preload API allowlist', () => {
  it('exposes only getStatus and invokes its individually named channel', async () => {
    const invoke = vi.fn().mockResolvedValue('ready')
    const api = createKynveilApi(invoke)

    await expect(api.getStatus()).resolves.toBe('ready')
    expect(Object.keys(api)).toEqual(['getStatus'])
    expect(invoke).toHaveBeenCalledWith('kynveil:get-status')
  })

  it('contains no generic privileged primitive', () => {
    const names = Object.keys(createKynveilApi(vi.fn()))
    expect(names.join(' ')).not.toMatch(
      /execute|call|sign|verify|encrypt|decrypt|key|secret|file|sql|socket|fetch|network/i
    )
  })
})
