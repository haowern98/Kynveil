import { spawnSync } from 'node:child_process'

const pnpm = process.env.npm_execpath
if (pnpm === undefined) throw new Error('pnpm must run verify')

const environment = { ...process.env }
delete environment.ELECTRON_RUN_AS_NODE
delete environment.CHROME_CRASHPAD_PIPE_NAME
const commands = [
  [process.execPath, [pnpm, 'lint']],
  [process.execPath, [pnpm, 'typecheck']],
  [process.execPath, [pnpm, 'test']],
  [process.execPath, ['scripts/cargo-with-sqlcipher.mjs', 'fmt', '--check']],
  [process.execPath, ['scripts/cargo-with-sqlcipher.mjs', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']],
  [process.execPath, ['scripts/cargo-with-sqlcipher.mjs', 'test', '--workspace']],
  [process.execPath, ['scripts/cargo-with-sqlcipher.mjs', 'doc', '--workspace', '--no-deps'], { RUSTDOCFLAGS: '-D warnings' }],
  [process.execPath, [pnpm, 'security-test']],
  [process.execPath, [pnpm, 'smoke']]
]

for (const [command, arguments_, additions = {}] of commands) {
  const result = spawnSync(command, arguments_, {
    cwd: process.cwd(),
    env: { ...environment, ...additions },
    stdio: 'inherit'
  })
  if (result.error !== undefined) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
}
