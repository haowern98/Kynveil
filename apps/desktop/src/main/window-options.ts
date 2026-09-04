import type { BrowserWindowConstructorOptions } from 'electron'

/** Creates the locked-down browser-window options for Kynveil's renderer. */
export function createWindowOptions(preload: string): BrowserWindowConstructorOptions {
  return {
    height: 800,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload,
      sandbox: true,
      webSecurity: true
    },
    width: 1200
  }
}
