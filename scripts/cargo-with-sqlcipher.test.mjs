import assert from 'node:assert/strict'
import test from 'node:test'

import { validateNativeArtifact } from './cargo-with-sqlcipher.mjs'

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
