import { app, BrowserWindow } from 'electron'
import { join } from 'node:path'

import { createWindowOptions } from './window-options'

const smokeTest = process.argv.includes('kynveil-smoke-test')

async function createWindow(): Promise<void> {
  const window = new BrowserWindow(
    createWindowOptions(join(import.meta.dirname, '../preload/index.mjs'))
  )

  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  window.webContents.on('will-navigate', (event) => {
    event.preventDefault()
  })

  if (smokeTest) {
    const loaded = new Promise<void>((resolve, reject) => {
      window.webContents.once('did-finish-load', () => {
        resolve()
      })
      window.webContents.once('did-fail-load', (_event, code, description) => {
        reject(new Error(`Renderer load failed (${String(code)}): ${description}`))
      })
    })

    await window.loadFile(join(import.meta.dirname, '../renderer/index.html'))
    await loaded
    app.exit(0)
    return
  }

  if (process.env.ELECTRON_RENDERER_URL === undefined) {
    await window.loadFile(join(import.meta.dirname, '../renderer/index.html'))
  } else {
    await window.loadURL(process.env.ELECTRON_RENDERER_URL)
  }

  window.show()
}

void app
  .whenReady()
  .then(createWindow)
  .catch(() => {
    console.error('Kynveil desktop failed to start')
    app.exit(1)
  })

app.on('window-all-closed', () => {
  app.quit()
})
