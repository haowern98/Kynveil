import { createHash } from 'node:crypto'
import { access, cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

export const SQLCIPHER_SOURCE = Object.freeze({
  archiveSha256: '31951158488fa3542f1037ff26cb203513075e793f0739975a9a9da22294a305',
  commit: '63697beb0fafcb61faa7a3e6fd267036548ab11b',
  version: '4.18.0'
})

const SQLITE_VERSION = '3.53.4'
const archiveUrl = `https://github.com/sqlcipher/sqlcipher/archive/${SQLCIPHER_SOURCE.commit}.tar.gz`
const archiveRoot = `sqlcipher-${SQLCIPHER_SOURCE.commit}`
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const sourceCacheDirectory = join(repositoryRoot, 'target', 'kynveil-native', 'sqlcipher', SQLCIPHER_SOURCE.version)

/** Returns the SHA-256 digest of in-memory bytes as lowercase hexadecimal. */
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

/** Rejects archive layouts that cannot be the reviewed SQLCipher source tree. */
export function validateArchiveEntries(entries) {
  const required = new Set([
    `${archiveRoot}/LICENSE.md`,
    `${archiveRoot}/Makefile.msc`,
    `${archiveRoot}/VERSION`,
    `${archiveRoot}/configure`,
    `${archiveRoot}/src/sqlcipher.c`
  ])

  for (const entry of entries) {
    if (typeof entry !== 'string') throw new Error('SQLCipher archive entry is not a string')
    const normalized = entry.replaceAll('\\', '/')
    const path = normalized.endsWith('/') ? normalized.slice(0, -1) : normalized
    if (path === archiveRoot && normalized.endsWith('/')) continue
    const components = path.split('/')
    if (
      path.length === 0 ||
      components.some((component) => component.length === 0 || component === '.' || component === '..') ||
      !path.startsWith(`${archiveRoot}/`)
    ) {
      throw new Error(`SQLCipher archive contains an unexpected path: ${entry}`)
    }
    if (path === `${archiveRoot}/sqlite3.c`) {
      throw new Error('reviewed SQLCipher source archive must not contain a generated sqlite3.c')
    }
    required.delete(path)
  }

  if (required.size !== 0) {
    throw new Error(`SQLCipher archive is missing required files: ${[...required].join(', ')}`)
  }
}

async function sha256File(path) {
  return sha256Hex(await readFile(path))
}

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

function tarEntries(archive) {
  const result = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8' })
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(`unable to inspect the SQLCipher archive with tar: ${result.error?.message ?? result.stderr}`)
  }
  return result.stdout.split(/\r?\n/u).filter(Boolean)
}

function extractArchive(archive, destination) {
  const result = spawnSync('tar', ['-xzf', archive, '-C', destination], { encoding: 'utf8' })
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(`unable to extract the SQLCipher archive with tar: ${result.error?.message ?? result.stderr}`)
  }
}

async function validateSourceTree(sourceDirectory) {
  const expectedFiles = ['LICENSE.md', 'Makefile.msc', 'configure', 'src/sqlcipher.c']
  await Promise.all(expectedFiles.map(async (file) => {
    await stat(join(sourceDirectory, file))
  }))
  try {
    await stat(join(sourceDirectory, 'sqlite3.c'))
    throw new Error('reviewed SQLCipher source cache was modified with a generated sqlite3.c')
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
  const sqliteVersion = (await readFile(join(sourceDirectory, 'VERSION'), 'utf8')).trim()
  if (sqliteVersion !== SQLITE_VERSION) {
    throw new Error(`reviewed SQLCipher source must contain SQLite ${SQLITE_VERSION}, found ${sqliteVersion}`)
  }
}

/**
 * Copies verified source into an isolated build directory before native tools
 * generate platform-specific files such as the SQLite amalgamation.
 */
export async function prepareSqlcipherBuildSource({ sourceDirectory, buildDirectory }) {
  const source = resolve(sourceDirectory)
  const build = resolve(buildDirectory)
  const buildFromSource = relative(source, build)
  const sourceFromBuild = relative(build, source)
  if (
    buildFromSource === '' ||
    sourceFromBuild === '' ||
    (!isAbsolute(buildFromSource) && !buildFromSource.startsWith('..')) ||
    (!isAbsolute(sourceFromBuild) && !sourceFromBuild.startsWith('..'))
  ) {
    throw new Error('SQLCipher build directory must be separate from the verified source')
  }

  await rm(build, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
  await mkdir(dirname(build), { recursive: true })
  await cp(source, build, { recursive: true, force: false, errorOnExist: true })
}

async function downloadVerifiedArchive(archive) {
  const response = await fetch(archiveUrl, { redirect: 'follow' })
  if (!response.ok) throw new Error(`official SQLCipher download failed with HTTP ${response.status}`)
  const finalUrl = new URL(response.url)
  if (
    finalUrl.protocol !== 'https:' ||
    finalUrl.hostname !== 'codeload.github.com' ||
    finalUrl.pathname !== `/sqlcipher/sqlcipher/tar.gz/${SQLCIPHER_SOURCE.commit}`
  ) {
    throw new Error(`official SQLCipher download redirected to an unreviewed location: ${response.url}`)
  }

  await writeFile(archive, Buffer.from(await response.arrayBuffer()), { flag: 'wx' })
  const digest = await sha256File(archive)
  if (digest !== SQLCIPHER_SOURCE.archiveSha256) {
    throw new Error(`official SQLCipher archive SHA-256 mismatch: ${digest}`)
  }
}

/**
 * Obtains and validates only the reviewed SQLCipher source archive.
 *
 * The returned directory is inside Kynveil's build output and never accepts a
 * caller-provided source location, preventing accidental system-library use.
 */
export async function prepareSqlcipherSource({ allowDownload = true } = {}) {
  const cacheDirectory = resolve(sourceCacheDirectory)
  const archive = join(cacheDirectory, `sqlcipher-${SQLCIPHER_SOURCE.commit}.tar.gz`)
  const sourceDirectory = join(cacheDirectory, `source-${SQLCIPHER_SOURCE.archiveSha256}`)
  await mkdir(cacheDirectory, { recursive: true })

  if (await exists(archive)) {
    const digest = await sha256File(archive)
    if (digest !== SQLCIPHER_SOURCE.archiveSha256) {
      throw new Error(`cached SQLCipher archive SHA-256 mismatch: ${digest}`)
    }
  } else if (allowDownload) {
    await downloadVerifiedArchive(archive)
  } else {
    throw new Error('reviewed SQLCipher archive is not prepared')
  }

  validateArchiveEntries(tarEntries(archive))
  let sourceNeedsExtraction = !(await exists(sourceDirectory))
  if (!sourceNeedsExtraction) {
    try {
      await validateSourceTree(sourceDirectory)
    } catch {
      await rm(sourceDirectory, { recursive: true, force: true })
      sourceNeedsExtraction = true
    }
  }
  if (sourceNeedsExtraction) {
    const stagingDirectory = join(cacheDirectory, `.source-${process.pid}-${Date.now()}`)
    await mkdir(stagingDirectory)
    extractArchive(archive, stagingDirectory)
    const extractedDirectory = join(stagingDirectory, archiveRoot)
    await validateSourceTree(extractedDirectory)
    // Windows Node.js can reject a directory rename here with EPERM even though
    // the destination parent permits the operation. A copied tree is never
    // trusted until the complete source validation below succeeds.
    await cp(extractedDirectory, sourceDirectory, { recursive: true, force: false, errorOnExist: true })
    await validateSourceTree(sourceDirectory)
    await rm(stagingDirectory, { recursive: true, force: true })
  }

  return { archive, sourceDirectory }
}

async function main() {
  const allowDownload = !process.argv.slice(2).includes('--check')
  const prepared = await prepareSqlcipherSource({ allowDownload })
  process.stdout.write(`${JSON.stringify({
    ...SQLCIPHER_SOURCE,
    sqliteVersion: SQLITE_VERSION,
    ...prepared
  })}\n`)
}

if (resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1] ?? '')) {
  await main()
}
