import { describe, expect, it } from 'vitest'

import { createWindowOptions } from './window-options'

describe('desktop window security', () => {
  it('keeps the renderer sandboxed and isolated from Node.js', () => {
    const options = createWindowOptions('preload.js')

    expect(options.webPreferences).toMatchObject({
      allowRunningInsecureContent: false,
      contextIsolation: true,
      experimentalFeatures: false,
      nodeIntegration: false,
      nodeIntegrationInSubFrames: false,
      nodeIntegrationInWorker: false,
      partition: 'kynveil-renderer',
      sandbox: true,
      webviewTag: false,
      webSecurity: true
    })
  })
})
