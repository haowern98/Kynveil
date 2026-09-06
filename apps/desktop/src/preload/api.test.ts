import { describe, expect, it, vi } from 'vitest'

import { createKynveilApi } from './api.js'

describe('preload API allowlist', () => {
  it('exposes only bounded profile operations on individually named channels', async () => {
    const invoke = vi.fn((channel: string) =>
      Promise.resolve(channel === 'kynveil:get-status' ? 'ready' : 'locked')
    )
    const api = createKynveilApi(invoke)

    await expect(api.getStatus()).resolves.toBe('ready')
    await expect(api.getProfileStatus()).resolves.toBe('locked')
    await expect(api.lockProfile()).resolves.toBe('locked')
    await expect(api.unlockProfile()).resolves.toBe('locked')
    expect(Object.keys(api)).toEqual(['getStatus', 'getProfileStatus', 'lockProfile', 'unlockProfile'])
    expect(invoke).toHaveBeenCalledWith('kynveil:get-status')
    expect(invoke).toHaveBeenCalledWith('kynveil:get-profile-status')
    expect(invoke).toHaveBeenCalledWith('kynveil:lock-profile')
    expect(invoke).toHaveBeenCalledWith('kynveil:unlock-profile')
  })

  it('contains no generic privileged primitive', () => {
    const names = Object.keys(createKynveilApi(vi.fn()))
    expect(names).not.toContain('execute')
    expect(names).not.toContain('call')
    expect(names).not.toContain('sign')
    expect(names).not.toContain('decrypt')
    expect(names).not.toContain('readFile')
    expect(names).not.toContain('runSql')
  })
})
