export interface KynveilApi {
  /** Returns the non-sensitive lifecycle state reported by the Rust core. */
  getStatus(): Promise<'ready'>
}

type Invoke = (channel: 'kynveil:get-status') => Promise<unknown>

/** Creates the complete Stage 2 renderer API allowlist. */
export function createKynveilApi(invoke: Invoke): KynveilApi {
  return {
    async getStatus() {
      const status = await invoke('kynveil:get-status')
      if (status !== 'ready') throw new Error('invalid core status')
      return status
    }
  }
}
