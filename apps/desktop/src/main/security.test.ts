import { describe, expect, it } from 'vitest'

import { isTrustedSender, shouldBlockRendererRequest } from './security.js'

describe('privileged IPC sender validation', () => {
  const expectedContents = { mainFrame: { url: 'file:///synthetic/kynveil/index.html' } }
  const expectedUrl = expectedContents.mainFrame.url

  it('accepts only the expected webContents main frame and exact URL', () => {
    expect(
      isTrustedSender(
        { sender: expectedContents, senderFrame: expectedContents.mainFrame },
        expectedContents,
        expectedUrl
      )
    ).toBe(true)
    expect(
      isTrustedSender(
        { sender: {}, senderFrame: expectedContents.mainFrame },
        expectedContents,
        expectedUrl
      )
    ).toBe(false)
    expect(
      isTrustedSender(
        { sender: expectedContents, senderFrame: { url: expectedUrl } },
        expectedContents,
        expectedUrl
      )
    ).toBe(false)
    expect(
      isTrustedSender(
        { sender: expectedContents, senderFrame: expectedContents.mainFrame },
        expectedContents,
        'file:///unexpected/index.html'
      )
    ).toBe(false)
  })
})

describe('renderer network policy', () => {
  it.each([
    'http://127.0.0.1:3000/',
    'https://example.invalid/',
    'ws://127.0.0.1:3000/',
    'wss://example.invalid/',
    'ftp://example.invalid/file'
  ])('blocks %s', (url) => {
    expect(shouldBlockRendererRequest(url)).toBe(true)
  })

  it('does not block the packaged local file', () => {
    expect(shouldBlockRendererRequest('file:///synthetic/kynveil/index.html')).toBe(false)
  })
})
