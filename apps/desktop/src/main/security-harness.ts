import { app, BrowserWindow } from 'electron'
import { createServer } from 'node:http'
import { join } from 'node:path'

import { installRendererSecurity } from './security.js'
import { createWindowOptions } from './window-options.js'

app.commandLine.appendSwitch('disable-background-networking')

async function run(): Promise<void> {
  const server = createServer((_request, response) => {
    hits += 1
    response.end('unexpected')
  })
  let hits = 0
  server.on('upgrade', (request) => {
    hits += 1
    request.destroy()
  })
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', resolveListen)
  })
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('test server unavailable')
  const target = `http://127.0.0.1:${String(address.port)}/blocked`

  const window = new BrowserWindow(
    createWindowOptions(join(import.meta.dirname, '../preload/index.cjs'))
  )
  installRendererSecurity(window)
  await window.loadFile(join(import.meta.dirname, '../renderer/index.html'))
  const rendererUrl = window.webContents.getURL()
  const result = (await window.webContents.executeJavaScript(`
    (async () => {
      const target = ${JSON.stringify(target)};
      const fetchBlocked = await fetch(target).then(() => false, () => true);
      const xhrBlocked = await new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.onload = () => resolve(false);
        xhr.onerror = () => resolve(true);
        xhr.open('GET', target);
        xhr.send();
      });
      const webSocketBlocked = await new Promise((resolve) => {
        const socket = new WebSocket(target.replace('http:', 'ws:'));
        socket.onopen = () => resolve(false);
        socket.onerror = () => resolve(true);
      });
      const windowOpenBlocked = window.open(target) === null;
      location.assign(target);
      return { fetchBlocked, xhrBlocked, webSocketBlocked, windowOpenBlocked };
    })()
  `)) as Record<string, boolean>

  await new Promise((resolveDelay) => setTimeout(resolveDelay, 100))
  const passed =
    result.fetchBlocked === true &&
    result.xhrBlocked === true &&
    result.webSocketBlocked === true &&
    result.windowOpenBlocked === true &&
    window.webContents.getURL() === rendererUrl &&
    hits === 0

  window.destroy()
  await new Promise<void>((resolveClose) =>
    server.close(() => {
      resolveClose()
    })
  )
  app.exit(passed ? 0 : 1)
}

void app
  .whenReady()
  .then(run)
  .catch(() => {
    app.exit(1)
  })
