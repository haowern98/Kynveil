import { readFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

import { prepareSqlcipherBuildSource, prepareSqlcipherSource } from './prepare-sqlcipher.mjs'

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

/** Resolves the target triple used to isolate controlled native build inputs. */
export function resolveCargoTarget(arguments_, rustcVersion) {
  const targetIndex = arguments_.indexOf('--target')
  const explicitTarget = targetIndex === -1 ? undefined : arguments_[targetIndex + 1]
  const inlineTarget = arguments_.find((argument) => argument.startsWith('--target='))?.slice('--target='.length)
  const target = explicitTarget ?? inlineTarget ?? /^host:\s+([^\s]+)$/mu.exec(rustcVersion)?.[1]
  if (target === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(target)) {
    throw new Error('Cargo target must be a valid target triple')
  }
  return target
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

function rustcVersion() {
  const result = spawnSync(process.platform === 'win32' ? 'rustc.exe' : 'rustc', ['-vV'], {
    cwd: repositoryRoot,
    encoding: 'utf8'
  })
  if (result.error !== undefined) throw result.error
  if (result.status !== 0) throw new Error(`unable to identify the Rust host target: ${result.stderr}`)
  return result.stdout
}

export function helperBuildArguments(arguments_) {
  const helperArguments = ['build', '--package', 'kynveil-sqlcipher-native']
  for (const lockControl of ['--locked', '--offline', '--frozen']) {
    if (arguments_.includes(lockControl)) helperArguments.push(lockControl)
  }
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
  const target = resolveCargoTarget(arguments_, rustcVersion())
  const buildDirectory = resolve(controlledRoot, 'build', target)
  await prepareSqlcipherBuildSource({
    sourceDirectory: prepared.sourceDirectory,
    buildDirectory
  })
  const environment = {
    ...process.env,
    KYNVEIL_SQLCIPHER_BUILD_DIR: buildDirectory,
    KYNVEIL_SQLCIPHER_SOURCE_DIR: prepared.sourceDirectory
  }
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
