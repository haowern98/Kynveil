import { app, BrowserWindow, ipcMain } from 'electron'
import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { installRendererSecurity, isTrustedSender } from './security'
import {
  createSidecarSupervisor,
  resolveSidecarPath,
  type SidecarSupervisor
} from './sidecar'
import { createWindowOptions } from './window-options'

const smokeTest = process.argv.includes('kynveil-smoke-test')
let sidecar: SidecarSupervisor | undefined
let startupStep = 'application readiness'

app.commandLine.appendSwitch('disable-background-networking')

async function createWindow(): Promise<void> {
  startupStep = 'sidecar handshake'
  const applicationPath = app.isPackaged
    ? app.getAppPath()
    : resolve(import.meta.dirname, '..', '..')
  if (!existsSync(resolveSidecarPath(app.isPackaged, process.resourcesPath, applicationPath))) {
    startupStep = 'sidecar binary lookup'
    throw new Error('sidecar unavailable')
  }
  sidecar = createSidecarSupervisor(
    app.isPackaged,
    process.resourcesPath,
    applicationPath,
    app.getPath('userData')
  )
  await sidecar.start()
  startupStep = 'window creation'
  const window = new BrowserWindow(
    createWindowOptions(join(import.meta.dirname, '../preload/index.cjs'))
  )
  installRendererSecurity(window)
  startupStep = 'renderer load'
  await window.loadFile(join(import.meta.dirname, '../renderer/index.html'))
  const rendererUrl = window.webContents.getURL()
  ipcMain.handle('kynveil:get-status', async (event, ...arguments_: unknown[]) => {
    if (
      arguments_.length !== 0 ||
      !isTrustedSender(event, window.webContents, rendererUrl) ||
      sidecar?.state !== 'ready'
    ) {
      throw new Error('core unavailable')
    }
    return sidecar.getStatus()
  })
  for (const [channel, operation] of [
    ['kynveil:get-profile-status', () => sidecar?.getProfileStatus()],
    ['kynveil:lock-profile', () => sidecar?.lockProfile()],
    ['kynveil:unlock-profile', () => sidecar?.unlockProfile()]
  ] as const) {
    ipcMain.handle(channel, async (event, ...arguments_: unknown[]) => {
      if (
        arguments_.length !== 0 ||
        !isTrustedSender(event, window.webContents, rendererUrl) ||
        sidecar?.state !== 'ready'
      ) {
        throw new Error('core unavailable')
      }
      const result = await operation()
      if (result === undefined) throw new Error('core unavailable')
      if (channel === 'kynveil:lock-profile' && result === 'locked') {
        setTimeout(() => {
          window.webContents.reload()
        }, 0)
      }
      return result
    })
  }

  if (smokeTest) {
    const bridgeReady = (await window.webContents.executeJavaScript(
      "typeof window.kynveil?.getStatus === 'function'"
    )) as unknown
    if (bridgeReady !== true) {
      startupStep = 'preload bridge'
      throw new Error('preload unavailable')
    }
    startupStep = 'sidecar status'
    const status = (await window.webContents.executeJavaScript(
      'window.kynveil.getStatus()'
    )) as unknown
    if (status !== 'ready' && status !== 'locked') throw new Error('invalid core status')
    startupStep = 'sidecar shutdown'
    await sidecar.shutdown()
    app.exit(0)
    return
  }

  window.show()
}

void app
  .whenReady()
  .then(createWindow)
  .catch(async () => {
    console.error(`Kynveil desktop failed to start: ${startupStep}`)
    const current = sidecar
    sidecar = undefined
    if (current?.state === 'ready') {
      try {
        await current.shutdown()
      } catch {
        // The supervisor kills an unresponsive sidecar during shutdown.
      }
    }
    app.exit(1)
  })

app.on('window-all-closed', () => {
  ipcMain.removeHandler('kynveil:get-status')
  ipcMain.removeHandler('kynveil:get-profile-status')
  ipcMain.removeHandler('kynveil:lock-profile')
  ipcMain.removeHandler('kynveil:unlock-profile')
  const current = sidecar
  sidecar = undefined
  if (current?.state === 'ready') {
    void current.shutdown().finally(() => {
      app.quit()
    })
  } else {
    app.quit()
  }
})
