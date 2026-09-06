export interface KynveilApi {
  /** Returns the non-sensitive lifecycle state reported by the Rust core. */
  getStatus(): Promise<'ready' | 'locked'>
  /** Returns the bounded local-profile state without exposing secrets or paths. */
  getProfileStatus(): Promise<ProfileStatus>
  /** Closes the Rust-owned encrypted profile and clears its loaded secrets. */
  lockProfile(): Promise<ProfileStatus>
  /** Retries unlock through the configured OS keystore without caller-supplied secrets. */
  unlockProfile(): Promise<ProfileStatus>
}

export type ProfileStatus = 'unlocked' | 'locked' | 'keystore-unavailable' | 'corrupt' | 'error'

type Channel =
  | 'kynveil:get-status'
  | 'kynveil:get-profile-status'
  | 'kynveil:lock-profile'
  | 'kynveil:unlock-profile'
type Invoke = (channel: Channel) => Promise<unknown>

/** Creates the complete Stage 2 renderer API allowlist. */
export function createKynveilApi(invoke: Invoke): KynveilApi {
  return {
    async getStatus() {
      const status = await invoke('kynveil:get-status')
      if (status !== 'ready' && status !== 'locked') throw new Error('invalid core status')
      return status
    },
    getProfileStatus: () => profileStatus(invoke('kynveil:get-profile-status')),
    lockProfile: () => profileStatus(invoke('kynveil:lock-profile')),
    unlockProfile: () => profileStatus(invoke('kynveil:unlock-profile'))
  }
}

async function profileStatus(result: Promise<unknown>): Promise<ProfileStatus> {
  const status = await result
  if (
    status !== 'unlocked' &&
    status !== 'locked' &&
    status !== 'keystore-unavailable' &&
    status !== 'corrupt' &&
    status !== 'error'
  ) {
    throw new Error('invalid profile status')
  }
  return status
}
