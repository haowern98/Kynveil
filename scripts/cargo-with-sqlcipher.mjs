import { readFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

import { prepareSqlcipherSource } from './prepare-sqlcipher.mjs'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const controlledRoot = resolve(repositoryRoot, 'target', 'kynveil-native', 'sqlcipher', '4.18.0')

/** Rejects native link artifacts outside the Kynveil-controlled build output. */
export function validateNativeArtifact(artifact, root = controlledRoot) {
  if (typeof artifact?.libDirectory !== 'string' || typeof artifact.target !== 'string') {
    throw new Error('controlled SQLCipher artifact metadata is malformed')
  }
  const artifactDirectory = resolve(artifact.libDirectory)
  const relation = relative(resolve(root), artifactDirectory)
  if (
    relation === '' ||
    relation === '..' ||
    isAbsolute(relation) ||
    relation.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
  ) {
    throw new Error('controlled SQLCipher artifact is outside Kynveil build output')
  }
  return artifactDirectory
}

function run(command, arguments_, environment) {
  const result = spawnSync(command, arguments_, {
    cwd: repositoryRoot,
    env: environment,
    stdio: 'inherit'
  })
  if (result.error !== undefined) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
}

function helperBuildArguments(arguments_) {
  const helperArguments = ['build', '--package', 'kynveil-sqlcipher-native']
  if (arguments_.includes('--release')) helperArguments.push('--release')
  const targetIndex = arguments_.indexOf('--target')
  if (targetIndex !== -1 && arguments_[targetIndex + 1] !== undefined) {
    helperArguments.push('--target', arguments_[targetIndex + 1])
  }
  return helperArguments
}

async function main() {
  const arguments_ = process.argv.slice(2)
  if (arguments_.length === 0) throw new Error('cargo arguments are required')
  const prepared = await prepareSqlcipherSource()
  const environment = { ...process.env, KYNVEIL_SQLCIPHER_SOURCE_DIR: prepared.sourceDirectory }
  delete environment.OPENSSL_DIR
  delete environment.OPENSSL_INCLUDE_DIR
  delete environment.OPENSSL_LIB_DIR
  delete environment.OPENSSL_NO_VENDOR
  run(process.platform === 'win32' ? 'cargo.exe' : 'cargo', helperBuildArguments(arguments_), environment)

  const artifact = JSON.parse(await readFile(resolve(controlledRoot, 'artifact.json'), 'utf8'))
  const libDirectory = validateNativeArtifact(artifact)
  run(process.platform === 'win32' ? 'cargo.exe' : 'cargo', arguments_, {
    ...environment,
    KYNVEIL_SQLCIPHER_CONTROLLED: '1',
    SQLCIPHER_LIB_DIR: libDirectory,
    SQLCIPHER_STATIC: '1'
  })
}

if (resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1] ?? '')) {
  await main()
}
