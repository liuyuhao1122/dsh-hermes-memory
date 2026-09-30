// Read-only consistency audit. Prints counts only; never prints memory content or key.
import { createReadStream } from 'node:fs'
import { readFile, readdir, stat } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { decodeRow } from '../src/journal.mjs'

const root = resolve(process.argv[2] || '')
if (!process.argv[2]) throw new Error('Usage: node scripts/audit.mjs <memory directory>')
const state = JSON.parse(await readFile(join(root, 'state.json'), 'utf8'))
const key = Buffer.from((await readFile(join(root, 'memory.key'), 'utf8')).trim(), 'hex')
if (key.length !== 32) throw new Error('Invalid memory.key')
const report = {
  sessions: Object.keys(state.sessions || {}).length,
  pendingSessions: Object.values(state.sessions || {}).filter((s) => s.capturedSeq > s.distilledSeq).length,
  version: state.version,
  markdownFiles: 0,
  journalFiles: 0,
  journalRows: 0,
  unreadableRows: 0,
  plaintextRows: 0,
  oldLongValueMasks: 0,
  malformedMasks: 0,
  affectedMarkdownFiles: 0,
  affectedJournalRows: 0,
  pendingRollups: 0,
  quarantinedRollups: Array.isArray(state.quarantinedRollups) ? state.quarantinedRollups.length : 0,
  badCursors: 0
}
function checkText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  const old = (text.match(/\[REDACTED LONG VALUE\]/g) || []).length
  const malformed = (text.match(/\[REDACTED\]\s*(?:TOKEN|SECRET|LONG VALUE)\]/g) || []).length
  report.oldLongValueMasks += old
  report.malformedMasks += malformed
  return old + malformed > 0
}
async function files(directory) {
  return (await readdir(directory, { withFileTypes: true }).catch(() => []))
    .filter((entry) => entry.isFile()).map((entry) => join(directory, entry.name))
}
for (const file of [join(root, 'USER.md'), join(root, 'MEMORY.md'), join(root, 'PROCEDURES.md'),
  ...(await files(join(root, 'projects'))).filter((p) => p.endsWith('.md'))]) {
  try {
    if (checkText(await readFile(file, 'utf8'))) report.affectedMarkdownFiles += 1
    report.markdownFiles += 1
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
}
const journals = [
  ...(await files(root)).filter((p) => p.endsWith('withdrawals.jsonl')),
  ...(await files(root)).filter((p) => /rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(p)),
  ...(await files(join(root, 'sessions'))).filter((p) => p.endsWith('.jsonl')),
  ...(await files(join(root, 'archive', 'rollups'))).filter((p) => p.endsWith('.jsonl')),
  ...(await files(join(root, 'archive', 'sessions'))).filter((p) => p.endsWith('.jsonl'))
]
for (const file of journals) {
  report.journalFiles += 1
  if (file === join(root, state.rollupFile) && state.rollupOffset > (await stat(file)).size) report.badCursors += 1
  for (const [sid, info] of Object.entries(state.sessions || {})) {
    if (file === join(root, 'sessions', info.file || `${sid}.jsonl`) && info.distilledOffset > (await stat(file)).size) report.badCursors += 1
  }
  const input = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity })
  let offset = 0
  for await (const line of input) {
    if (!line) continue
    offset += Buffer.byteLength(line) + 1
    try {
      const envelope = JSON.parse(line)
      if (envelope?.v !== 1) report.plaintextRows += 1
      const row = decodeRow(line, key)
      if (checkText(row)) report.affectedJournalRows += 1
      report.journalRows += 1
      if (file === join(root, state.rollupFile) && offset > state.rollupOffset) report.pendingRollups += 1
    } catch { report.unreadableRows += 1 }
  }
}
console.log(JSON.stringify(report, null, 2))
