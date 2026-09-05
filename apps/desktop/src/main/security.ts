import type { BrowserWindow, Session } from 'electron'

interface SenderFrame {
  readonly url: string
}

interface ExpectedContents {
  readonly mainFrame: SenderFrame
}

interface SenderEvent {
  readonly sender: unknown
  readonly senderFrame: SenderFrame | null
}

/** Verifies object identity, top-level frame identity, and exact local renderer URL. */
export function isTrustedSender(
  event: SenderEvent,
  expectedContents: ExpectedContents,
  expectedUrl: string
): boolean {
  return (
    event.sender === expectedContents &&
    event.senderFrame === expectedContents.mainFrame &&
    event.senderFrame.url === expectedUrl
  )
}

/** Returns whether a renderer request uses a forbidden network protocol. */
export function shouldBlockRendererRequest(url: string): boolean {
  try {
    return ['http:', 'https:', 'ws:', 'wss:', 'ftp:'].includes(new URL(url).protocol)
  } catch {
    return true
  }
}

/** Applies network, permission, navigation, and new-window denial to one renderer. */
export function installRendererSecurity(window: BrowserWindow): void {
  const rendererSession: Session = window.webContents.session
  rendererSession.setSpellCheckerEnabled(false)
  rendererSession.setPermissionCheckHandler(() => false)
  rendererSession.setPermissionRequestHandler((_contents, _permission, callback) => {
    callback(false)
  })
  rendererSession.webRequest.onBeforeRequest(
    { urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*', 'ftp://*/*'] },
    (_details, callback) => {
      callback({ cancel: true })
    }
  )
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  window.webContents.on('will-navigate', (event) => {
    event.preventDefault()
  })
}
