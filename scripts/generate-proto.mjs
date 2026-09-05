import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const wrapper = join(
  root,
  'apps',
  'desktop',
  'node_modules',
  '@bufbuild',
  'buf',
  'bin',
  'buf'
)

if (!existsSync(wrapper)) {
  throw new Error('Pinned Buf executable is missing; run pnpm install')
}

function runBuf(command) {
  const result = spawnSync(process.execPath, [wrapper, command], {
    cwd: root,
    encoding: 'utf8'
  })

  if (result.status !== 0) {
    process.stderr.write(result.stderr)
    process.exit(result.status ?? 1)
  }
}

runBuf('lint')
runBuf('generate')
const generated = join(
  root,
  'apps',
  'desktop',
  'src',
  'generated',
  'kynveil',
  'ipc',
  'v1',
  'ipc_pb.ts'
)
const first = readFileSync(generated)
runBuf('generate')
if (!first.equals(readFileSync(generated))) throw new Error('Protobuf generation drift detected')
