import assert from 'node:assert/strict'
import test from 'node:test'

import { helperBuildArguments, resolveCargoTarget, validateNativeArtifact } from './cargo-with-sqlcipher.mjs'

test('accepts only a SQLCipher artifact inside the controlled build output', () => {
  const controlledRoot = 'E:/Kynveil/target/kynveil-native/sqlcipher/4.18.0'
  assert.doesNotThrow(() => validateNativeArtifact({
    libDirectory: `${controlledRoot}/x86_64-pc-windows-msvc/lib`,
    target: 'x86_64-pc-windows-msvc'
  }, controlledRoot))
  assert.throws(() => validateNativeArtifact({
    libDirectory: 'C:/system/sqlcipher',
    target: 'x86_64-pc-windows-msvc'
  }, controlledRoot))
})

test('uses an explicit Cargo target or the Rust host for native build isolation', () => {
  const rustcVersion = 'rustc 1.97.0\nhost: aarch64-apple-darwin\nrelease: 1.97.0\n'
  assert.equal(resolveCargoTarget(['test'], rustcVersion), 'aarch64-apple-darwin')
  assert.equal(resolveCargoTarget(['test', '--target', 'x86_64-apple-darwin'], rustcVersion), 'x86_64-apple-darwin')
  assert.throws(() => resolveCargoTarget(['test', '--target', '../outside'], rustcVersion))
})

test('preserves Cargo lockfile and target controls for the native helper build', () => {
  assert.deepEqual(
    helperBuildArguments(['test', '--locked', '--target', 'aarch64-apple-darwin']),
    ['build', '--package', 'kynveil-sqlcipher-native', '--locked', '--target', 'aarch64-apple-darwin']
  )
})
