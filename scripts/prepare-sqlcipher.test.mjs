import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  SQLCIPHER_SOURCE,
  prepareSqlcipherBuildSource,
  sha256Hex,
  validateArchiveEntries
} from './prepare-sqlcipher.mjs'

test('pins the reviewed SQLCipher 4.18.0 source', () => {
  assert.deepEqual(SQLCIPHER_SOURCE, {
    archiveSha256: '31951158488fa3542f1037ff26cb203513075e793f0739975a9a9da22294a305',
    commit: '63697beb0fafcb61faa7a3e6fd267036548ab11b',
    version: '4.18.0'
  })
})

test('calculates SHA-256 and rejects a different digest', () => {
  const digest = sha256Hex(Buffer.from('kynveil sqlcipher source'))
  assert.equal(digest, '7d3e2a7dee4642d00e7d4b637b4bc0fa4ed803fbfea0b4c6041f610169c85341')
  assert.notEqual(digest, SQLCIPHER_SOURCE.archiveSha256)
})

test('accepts only the pinned archive root and rejects traversal', () => {
  const root = `sqlcipher-${SQLCIPHER_SOURCE.commit}`
  assert.doesNotThrow(() => validateArchiveEntries([
    `${root}/`,
    `${root}/LICENSE.md`,
    `${root}/VERSION`,
    `${root}/Makefile.msc`,
    `${root}/configure`,
    `${root}/src/sqlcipher.c`
  ]))
  assert.throws(() => validateArchiveEntries([`${root}/../outside`]))
  assert.throws(() => validateArchiveEntries(['other-root/VERSION']))
  assert.throws(() => validateArchiveEntries([
    `${root}/`,
    `${root}/LICENSE.md`,
    `${root}/VERSION`,
    `${root}/Makefile.msc`,
    `${root}/configure`,
    `${root}/src/sqlcipher.c`,
    `${root}/sqlite3.c`
  ]))
})

test('creates an isolated native build copy without mutating verified source', async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), 'kynveil-sqlcipher-'))
  const sourceDirectory = join(temporaryDirectory, 'verified-source')
  const buildDirectory = join(temporaryDirectory, 'build-source')

  try {
    await mkdir(join(sourceDirectory, 'src'), { recursive: true })
    await writeFile(join(sourceDirectory, 'VERSION'), '3.53.4\n')
    await writeFile(join(sourceDirectory, 'src', 'sqlcipher.c'), 'verified source\n')
    await prepareSqlcipherBuildSource({ sourceDirectory, buildDirectory })
    await writeFile(join(buildDirectory, 'sqlite3.c'), 'generated build artifact\n')

    assert.equal(await readFile(join(sourceDirectory, 'src', 'sqlcipher.c'), 'utf8'), 'verified source\n')
    await assert.rejects(readFile(join(sourceDirectory, 'sqlite3.c'), 'utf8'))
    assert.equal(await readFile(join(buildDirectory, 'sqlite3.c'), 'utf8'), 'generated build artifact\n')
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true })
  }
})
