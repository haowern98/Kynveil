import type { BrowserWindowConstructorOptions } from 'electron'

/** Creates the locked-down browser-window options for Kynveil's renderer. */
export function createWindowOptions(preload: string): BrowserWindowConstructorOptions {
  return {
    height: 800,
    show: false,
    webPreferences: {
      allowRunningInsecureContent: false,
      contextIsolation: true,
      experimentalFeatures: false,
      nodeIntegration: false,
      nodeIntegrationInSubFrames: false,
      nodeIntegrationInWorker: false,
      partition: 'kynveil-renderer',
      preload,
      sandbox: true,
      webviewTag: false,
      webSecurity: true
    },
    width: 1200
  }
}
