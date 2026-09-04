import { describe, expect, it } from 'vitest'

import { createWindowOptions } from './window-options'

describe('desktop window security', () => {
  it('keeps the renderer sandboxed and isolated from Node.js', () => {
    const options = createWindowOptions('preload.js')

    expect(options.webPreferences).toMatchObject({
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    })
  })
})
