import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { appendFile, mkdir, readFile, readdir, rename, stat, unlink, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { encodeRow, encryptLegacyJournal, fileSize, journalIsEncrypted, loadJournalKey, readRows } from './journal.mjs'

export const LIMITS = Object.freeze({ user: 1375, global: 2200, project: 1600, procedure: 1800 })
const EMPTY_STATE = () => ({
  sessions: {}, rollupFile: 'rollups.jsonl', rollupOffset: 0, rollupFailures: {},
  quarantinedRollups: [], withdrawalsMigrated: false, version: 0, compaction: {}
})
const SOURCE_REF_PATTERN = /〔((?:s:[0-9a-f]{16}:\d+)|(?:m:[0-9a-f]{8}))〕/gu
const SEGMENT_BYTES = 256 * 1024
const DAY_MS = 24 * 60 * 60 * 1000
const isRollupJournalPath = (value) => typeof value === 'string' &&
  /^(?:rollups(?:-\d+-[\w-]+)?\.jsonl|archive[\\/]rollups[\\/]rollups(?:-\d+-[\w-]+)?\.jsonl)$/.test(value)

export function keyFor(value) {
  return createHash('sha256').update(String(value || '').toLowerCase().replaceAll('\\', '/')).digest('hex').slice(0, 16)
}

export function projectKey(cwd) {
  if (typeof cwd !== 'string' || !cwd.trim()) return 'unknown'
  let directory = resolve(cwd)
  while (true) {
    if (existsSync(join(directory, '.git'))) return keyFor(directory)
    const parent = dirname(directory)
    if (parent === directory) return keyFor(resolve(cwd))
    directory = parent
  }
}

export function redact(text) {
  return String(text)
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
    // Handle labeled values before bare tokens. Stopping at '[' makes this
    // idempotent when a previously redacted value is processed again.
    .replace(/(\b(?:api[_-]?key|access[_-]?token|secret|password|passwd)\b\s*[:=]\s*['"]?)[^\s,'"}\[\]]+/gi, '$1[REDACTED SECRET]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[opusr]_[A-Za-z0-9_]{20,})\b/g, '[REDACTED TOKEN]')
    .replace(/(\bAuthorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/-]+/gi, '$1[REDACTED]')
    .replace(/(?<!\d)1[3-9]\d{9}(?!\d)/g, '[REDACTED PHONE]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED EMAIL]')
    .replace(/(?<!\d)\d{17}[\dXx](?!\d)/g, '[REDACTED ID]')
    .replace(/(?<!\d)\d{16,19}(?!\d)/g, '[REDACTED NUMBER]')
}

export function bounded(text, max) {
  const value = String(text || '').trim()
  if (value.length <= max) return value
  const lines = value.split('\n')
  const kept = []
  let count = 0
  for (const line of lines) {
    if (count + line.length + 1 > max) break
    kept.push(line)
    count += line.length + 1
  }
  return kept.length ? kept.join('\n').trim() : value.slice(0, max)
}

function normalizeSearchText(value) {
  return String(value || '').normalize('NFKC').toLowerCase()
}

function searchTerms(query) {
  const normalized = normalizeSearchText(query).trim()
  const chunks = normalized.match(/[\p{Script=Han}]+|[\p{L}\p{N}_-]+/gu) || []
  const terms = []
  for (const chunk of chunks) {
    if (/^[\p{Script=Han}]+$/u.test(chunk) && chunk.length > 2) {
      for (let i = 0; i < chunk.length - 1; i += 1) terms.push(chunk.slice(i, i + 2))
    } else {
      terms.push(chunk)
    }
  }
  return [...new Set(terms)].slice(0, 24)
}

function matchScore(content, terms, query) {
  const text = normalizeSearchText(content)
  const hits = terms.filter((term) => text.includes(term)).length
  if (!hits || hits / terms.length < 0.35) return 0
  return hits / terms.length * 4 + (text.includes(normalizeSearchText(query).trim()) ? 4 : 0)
}

function normalizedFact(value) {
  return normalizeSearchText(value).replace(/[\s\p{P}\p{S}]/gu, '')
}

function withdrawalKey(candidate, project) {
  const fact = normalizedFact(candidate.fact)
  if (!fact) return ''
  const scopeProject = candidate.layer === 'project' ? project : '*'
  return `${candidate.layer}\u0000${scopeProject}\u0000${fact}`
}

function isWithdrawn(text, project, withdrawals, layer) {
  const normalized = normalizedFact(text)
  if (!normalized) return false
  for (const item of withdrawals.values()) {
    if (layer && item.layer !== layer) continue
    if (item.layer === 'project' && item.project !== project) continue
    if (normalized.includes(item.normalized)) return true
  }
  return false
}

function isSourceWithdrawn(ref, withdrawals) {
  if (!ref) return false
  for (const item of withdrawals.values()) {
    if (item.sourceRefs?.includes(ref)) return true
  }
  return false
}

function snippet(content, terms, max = 500) {
  const text = String(content || '')
  const normalized = normalizeSearchText(text)
  const positions = terms.map((term) => normalized.indexOf(term)).filter((index) => index >= 0)
  const start = positions.length ? Math.max(0, Math.min(...positions) - 100) : 0
  const slice = text.slice(start, start + max)
  return `${start ? '…' : ''}${slice}${start + max < text.length ? '…' : ''}`
}

async function atomicWrite(path, content) {
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`
  await mkdir(dirname(path), { recursive: true })
  try {
    await writeFile(temp, content, 'utf8')
    await rename(temp, path)
  } catch (error) {
    try { await unlink(temp) } catch {}
    throw error
  }
}

async function readText(path) {
  return readFile(path, 'utf8').catch((error) => {
    if (error.code === 'ENOENT') return ''
    throw error
  })
}

export class MemoryStore {
  constructor(root, options = {}) {
    this.root = resolve(root)
    this.rawRetentionDays = Number.isFinite(options.rawRetentionDays) ? Math.max(1, options.rawRetentionDays) : 30
    this.rollupRetentionDays = Number.isFinite(options.rollupRetentionDays) ? Math.max(1, options.rollupRetentionDays) : 365
    this.state = EMPTY_STATE()
    this.chain = Promise.resolve()
    this.lastMaintenanceAt = 0
    this.ready = this.init()
  }

  path(...parts) { return join(this.root, ...parts) }
  layerPath(layer, project = 'unknown') {
    if (layer === 'user') return this.path('USER.md')
    if (layer === 'global') return this.path('MEMORY.md')
    if (layer === 'procedure') return this.path('PROCEDURES.md')
    if (layer === 'project') return this.path('projects', `${project}.md`)
    throw new Error('Unknown memory layer')
  }

  async init() {
    await mkdir(this.root, { recursive: true })
    await mkdir(this.path('projects'), { recursive: true })
    await mkdir(this.path('sessions'), { recursive: true })
    await mkdir(this.path('history'), { recursive: true })
    await mkdir(this.path('archive', 'sessions'), { recursive: true })
    await mkdir(this.path('archive', 'rollups'), { recursive: true })
    const saved = await readText(this.path('state.json'))
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        if (parsed && typeof parsed === 'object') {
          this.state = {
            sessions: parsed.sessions && typeof parsed.sessions === 'object' ? parsed.sessions : {},
            rollupFile: typeof parsed.rollupFile === 'string' && /^[\w.-]+\.jsonl$/.test(parsed.rollupFile) ? parsed.rollupFile : 'rollups.jsonl',
            rollupOffset: Number.isSafeInteger(parsed.rollupOffset) ? parsed.rollupOffset : 0,
            rollupFailures: parsed.rollupFailures && typeof parsed.rollupFailures === 'object' && !Array.isArray(parsed.rollupFailures)
              ? parsed.rollupFailures : {},
            quarantinedRollups: Array.isArray(parsed.quarantinedRollups)
              ? parsed.quarantinedRollups.filter((item) => item && typeof item.id === 'string' &&
                typeof item.file === 'string' && Number.isSafeInteger(item.startOffset) && Number.isSafeInteger(item.endOffset))
              : [],
            withdrawalsMigrated: parsed.withdrawalsMigrated === true,
            version: Number.isSafeInteger(parsed.version) ? parsed.version : 0,
            compaction: parsed.compaction && typeof parsed.compaction === 'object' && !Array.isArray(parsed.compaction)
              ? parsed.compaction : {}
          }
        }
      } catch {}
    }
    this.key = await loadJournalKey(this.root)
    await this.recoverMigration()
    await this.migrateLegacyJournals()
    await this.migrateWithdrawals()
    for (const [layer, title] of [['user', '# USER'], ['global', '# MEMORY'], ['procedure', '# PROCEDURES']]) {
      const file = this.layerPath(layer)
      if (!existsSync(file)) await atomicWrite(file, `${title}\n`)
    }
  }

  withLock(task) {
    const work = this.chain.then(async () => { await this.ready; return task() })
    this.chain = work.catch(() => {})
    return work
  }

  async saveState() {
    await atomicWrite(this.path('state.json'), JSON.stringify(this.state, null, 2) + '\n')
  }

  sessionFile(sid) {
    return this.state.sessions[sid]?.file || `${sid}.jsonl`
  }

  async recoverMigration() {
    const markerPath = this.path('migration.json')
    const saved = await readText(markerPath)
    if (!saved) return
    const marker = JSON.parse(saved)
    if (marker?.kind !== 'rollup' && marker?.kind !== 'session') throw new Error('Invalid migration marker')
    const target = marker.kind === 'rollup'
      ? this.path(marker.file)
      : this.path('sessions', marker.file)
    if ((await fileSize(target)) > 0 && await journalIsEncrypted(target)) {
      if (marker.kind === 'rollup') this.state.rollupOffset = marker.newOffset
      else if (this.state.sessions[marker.sid]) this.state.sessions[marker.sid].distilledOffset = marker.newOffset
      await this.saveState()
    }
    await unlink(markerPath)
  }

  async migrateLegacyJournals() {
    const markerPath = this.path('migration.json')
    const migrate = async (kind, file, oldOffset, sid) => {
      const path = kind === 'rollup' ? this.path(file) : this.path('sessions', file)
      const result = await encryptLegacyJournal(path, this.key, oldOffset, async (newOffset) => {
        await atomicWrite(markerPath, JSON.stringify({ kind, file, sid, newOffset }) + '\n')
      })
      if (!result.changed) return
      if (kind === 'rollup') this.state.rollupOffset = result.offset
      else this.state.sessions[sid].distilledOffset = result.offset
      await this.saveState()
      await unlink(markerPath)
    }
    await migrate('rollup', this.state.rollupFile, this.state.rollupOffset)
    for (const [sid, info] of Object.entries(this.state.sessions)) {
      if (typeof info.file !== 'string' || !/^[\w.-]+\.jsonl$/.test(info.file)) info.file = `${sid}.jsonl`
      await migrate('session', info.file, info.distilledOffset || 0, sid)
    }
    const activeSessions = new Set(Object.values(this.state.sessions).map((info) => info.file))
    for (const file of await readdir(this.path('sessions'))) {
      if (!file.endsWith('.jsonl') || activeSessions.has(file)) continue
      await encryptLegacyJournal(this.path('sessions', file), this.key)
    }
    for (const file of await readdir(this.root)) {
      if (!/^rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(file) || file === this.state.rollupFile) continue
      await encryptLegacyJournal(this.path(file), this.key)
    }
    for (const kind of ['sessions', 'rollups']) {
      const directory = this.path('archive', kind)
      for (const file of await readdir(directory)) {
        if (file.endsWith('.jsonl')) await encryptLegacyJournal(this.path('archive', kind, file), this.key)
      }
    }
  }

  async migrateWithdrawals() {
    if (this.state.withdrawalsMigrated) return
    const path = this.path('withdrawals.jsonl')
    const knownIds = new Set()
    let cursor = 0
    while (cursor < await fileSize(path)) {
      const rows = await readRows(path, cursor, 128 * 1024, this.key)
      if (!rows.length) break
      for (const row of rows) knownIds.add(row.value.id)
      cursor = rows.at(-1).endOffset
    }
    const files = []
    for (const directory of [this.root, this.path('archive', 'rollups')]) {
      for (const name of await readdir(directory).catch(() => [])) {
        if (/^rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(name)) files.push(join(directory, name))
      }
    }
    for (const file of files) {
      let offset = 0
      while (offset < await fileSize(file)) {
        const rows = await readRows(file, offset, 128 * 1024, this.key)
        if (!rows.length) break
        for (const { value } of rows) {
          const withdrawal = (value.candidates || []).some((candidate) =>
            candidate?.action === 'remove' || (value.session === 'manual' && candidate?.action !== 'remove'))
          if (!withdrawal || !value.id || knownIds.has(value.id)) continue
          await appendFile(path, encodeRow(value, this.key), 'utf8')
          knownIds.add(value.id)
        }
        offset = rows.at(-1).endOffset
      }
    }
    this.state.withdrawalsMigrated = true
    await this.saveState()
  }

  async maintainJournals(force = false) {
    return this.withLock(async () => {
      const now = Date.now()
      if (!force && now - this.lastMaintenanceAt < 5 * 60 * 1000) return
      const rollup = this.path(this.state.rollupFile)
      const rollupSize = await fileSize(rollup)
      if (rollupSize && this.state.rollupOffset >= rollupSize) {
        const modified = (await stat(rollup)).mtimeMs
        if (rollupSize >= SEGMENT_BYTES || now - modified > 7 * DAY_MS) {
          const oldFile = this.state.rollupFile
          const archivedFile = join('archive', 'rollups', oldFile)
          for (const item of this.state.quarantinedRollups) {
            if (!item.filePath && item.file === oldFile || item.filePath === oldFile) item.filePath = archivedFile
          }
          this.state.rollupFile = `rollups-${now}-${randomUUID().slice(0, 8)}.jsonl`
          this.state.rollupOffset = 0
          await this.saveState()
          await rename(this.path(oldFile), this.path('archive', 'rollups', oldFile))
        }
      }
      for (const [sid, info] of Object.entries(this.state.sessions)) {
        if (info.capturedSeq !== info.distilledSeq) continue
        const oldFile = this.sessionFile(sid)
        const path = this.path('sessions', oldFile)
        const size = await fileSize(path)
        if (!size) continue
        const modified = (await stat(path)).mtimeMs
        if (size < SEGMENT_BYTES && now - modified <= DAY_MS) continue
        info.file = `${sid}-${now}-${randomUUID().slice(0, 8)}.jsonl`
        info.distilledOffset = 0
        await this.saveState()
        await rename(path, this.path('archive', 'sessions', oldFile))
      }
      // Finish moves interrupted after the state changed but before rename.
      const activeSessions = new Set(Object.entries(this.state.sessions).map(([sid]) => this.sessionFile(sid)))
      for (const file of await readdir(this.path('sessions'))) {
        if (!file.endsWith('.jsonl') || activeSessions.has(file)) continue
        await rename(this.path('sessions', file), this.path('archive', 'sessions', file))
      }
      for (const file of await readdir(this.root)) {
        if (!/^rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(file) || file === this.state.rollupFile) continue
        let stateChanged = false
        for (const item of this.state.quarantinedRollups) {
          if (!item.filePath && item.file === file || item.filePath === file) {
            item.filePath = join('archive', 'rollups', file)
            stateChanged = true
          }
        }
        if (stateChanged) await this.saveState()
        await rename(this.path(file), this.path('archive', 'rollups', file))
      }
      for (const [kind, retentionDays] of [['sessions', this.rawRetentionDays], ['rollups', this.rollupRetentionDays]]) {
        const directory = this.path('archive', kind)
        for (const file of await readdir(directory)) {
          if (!/\.jsonl$/.test(file)) continue
          if (kind === 'rollups' && this.state.quarantinedRollups.some((item) =>
            item.filePath === join('archive', 'rollups', file) || (!item.filePath && item.file === file))) continue
          const target = this.path('archive', kind, file)
          if (now - (await stat(target)).mtimeMs > retentionDays * DAY_MS) await unlink(target)
        }
      }
      await this.compactWithdrawalJournal(now)
      this.lastMaintenanceAt = now
    })
  }

  async compactWithdrawalJournal(now = Date.now()) {
    const path = this.path('withdrawals.jsonl')
    const events = await this.withdrawalEvents()
    if (!events.length) return
    const retentionDays = Math.max(this.rawRetentionDays, this.rollupRetentionDays) + 1
    const cutoff = now - retentionDays * DAY_MS
    const activeEvents = events.filter((event) => event.at >= cutoff)
    const active = this.buildWithdrawalMap(activeEvents)
    const shouldCompact = activeEvents.length !== events.length || active.size !== events.length ||
      (await fileSize(path)) >= SEGMENT_BYTES
    if (!shouldCompact) return
    const rows = [...active.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => ({
      id: createHash('sha256').update(key).digest('hex').slice(0, 32),
      at: new Date(item.at).toISOString(),
      session: 'withdrawal-index',
      project: item.project,
      summary: '',
      candidates: [{ layer: item.layer, action: 'remove', fact: item.fact }],
      suppressedSources: item.sourceRefs
    }))
    await atomicWrite(path, rows.map((row) => encodeRow(row, this.key)).join(''))
  }

  async writeDiagnostic(status, detail = '') {
    return this.withLock(async () => {
      await atomicWrite(this.path('diagnostics.json'), JSON.stringify({
        at: new Date().toISOString(),
        status,
        detail: bounded(redact(detail), 500),
        version: this.state.version,
        sessions: Object.keys(this.state.sessions).length,
        quarantinedRollups: this.state.quarantinedRollups.length
      }, null, 2) + '\n')
    })
  }

  async writeFatalDiagnostic(detail) {
    await atomicWrite(this.path('diagnostics.json'), JSON.stringify({
      at: new Date().toISOString(),
      status: 'startup-error',
      detail: bounded(redact(detail), 500)
    }, null, 2) + '\n')
  }

  readLayerSync(layer, project) {
    try { return readFileSync(this.layerPath(layer, project), 'utf8') } catch { return '' }
  }
  async readLayer(layer, project) { return readText(this.layerPath(layer, project)) }

  async capture(sessionId, cwd, events) {
    return this.withLock(async () => {
      const sid = keyFor(sessionId)
      const info = this.state.sessions[sid] || { capturedSeq: 0, distilledSeq: 0, distilledOffset: 0, project: projectKey(cwd) }
      const fresh = events.filter((item) => item.seq > info.capturedSeq)
      if (!fresh.length) return { sid, pending: false }
      const lastSeq = Math.max(...fresh.map((item) => item.seq))
      let previousSeq = info.capturedSeq
      let captured = false
      for (const item of fresh) {
        if (item.text) {
          const row = {
            id: randomUUID(), at: new Date().toISOString(), sessionId,
            project: info.project, cwd: typeof cwd === 'string' ? cwd : '',
            fromSeq: previousSeq, toSeq: item.seq,
            messages: [{ role: item.role, text: bounded(redact(item.text), 14000) }]
          }
          await appendFile(this.path('sessions', this.sessionFile(sid)), encodeRow(row, this.key), 'utf8')
          captured = true
        }
        previousSeq = item.seq
      }
      if (!captured && info.distilledSeq === info.capturedSeq) {
        info.distilledSeq = lastSeq
      }
      info.capturedSeq = lastSeq
      this.state.sessions[sid] = info
      await this.saveState()
      return { sid, pending: info.capturedSeq > info.distilledSeq }
    })
  }

  async pendingSession(sid) {
    await this.ready
    const info = this.state.sessions[sid]
    if (!info || info.capturedSeq <= info.distilledSeq) return null
    const rows = await readRows(this.path('sessions', this.sessionFile(sid)), info.distilledOffset || 0, 128 * 1024, this.key)
    const pending = rows.filter((item) => item.value.toSeq > info.distilledSeq)
    if (!pending.length) return null
    return { info, rows: pending }
  }

  async appendRollup(rollup, sid, toSeq, endOffset) {
    return this.withLock(async () => {
      const info = this.state.sessions[sid]
      if (!info || toSeq <= info.distilledSeq) return
      const removals = (rollup.candidates || []).filter((candidate) => candidate?.action === 'remove')
      if (removals.length) {
        const sourceRefs = [rollup.sourceRef].filter(Boolean)
        for (const candidate of removals) {
          const current = await this.readLayer(candidate.layer, rollup.project)
          for (const line of current.split('\n')) {
            if (!normalizedFact(line).includes(normalizedFact(candidate.fact))) continue
            sourceRefs.push(...[...line.matchAll(SOURCE_REF_PATTERN)].map((match) => match[1]))
          }
        }
        await appendFile(this.path('withdrawals.jsonl'), encodeRow({
          ...rollup,
          summary: '',
          candidates: removals,
          suppressedSources: [...new Set(sourceRefs)]
        }, this.key), 'utf8')
      }
      await appendFile(this.path(this.state.rollupFile), encodeRow(rollup, this.key), 'utf8')
      info.distilledSeq = toSeq
      info.distilledOffset = endOffset
      await this.saveState()
    })
  }

  async appendManual(candidate, project, forget = false) {
    return this.withLock(async () => {
      let current = ''
      let next = ''
      let suppressedSources = []
      if (forget) {
        const needle = normalizedFact(candidate.fact)
        current = await this.readLayer(candidate.layer, project)
        const lines = current.split('\n')
        for (const line of lines) {
          if (line.trim().startsWith('#') || !normalizedFact(line).includes(needle)) continue
          suppressedSources.push(...[...line.matchAll(SOURCE_REF_PATTERN)].map((match) => match[1]))
        }
        next = lines.filter((line) => line.trim().startsWith('#') || !normalizedFact(line).includes(needle))
          .join('\n').replace(/\n*$/, '\n')
        suppressedSources = [...new Set(suppressedSources)]
      }
      const row = {
        id: randomUUID(), at: new Date().toISOString(), session: 'manual',
        project, summary: '', candidates: [candidate],
        ...(forget ? { suppressedSources } : {})
      }
      row.sourceRef = `m:${row.id.slice(0, 8)}`
      // Keep tombstones in their own encrypted journal so they remain effective
      // after old rollup segments age out of the normal search window.
      let updateWithdrawalIndex = forget
      if (!forget) {
        const key = withdrawalKey(candidate, project)
        const active = this.buildWithdrawalMap(await this.withdrawalEvents())
        updateWithdrawalIndex = Boolean(key && active.has(key))
      }
      if (updateWithdrawalIndex) {
        await appendFile(this.path('withdrawals.jsonl'), encodeRow(row, this.key), 'utf8')
      }
      await appendFile(this.path(this.state.rollupFile), encodeRow(row, this.key), 'utf8')
      if (forget) {
        const target = this.layerPath(candidate.layer, project)
        const needle = normalizedFact(candidate.fact)
        if (next !== current && needle) {
          // Do not make a fresh plaintext history copy of content the user just
          // asked to forget. Existing history and encrypted source logs retain
          // their documented retention behavior.
          await atomicWrite(target, next)
          this.state.version += 1
          await this.saveState()
        }
      }
      return row.id
    })
  }

  async pendingRollups(max = 8) {
    await this.ready
    const rows = await readRows(this.path(this.state.rollupFile), this.state.rollupOffset, 128 * 1024, this.key)
    if (!rows.length) return []
    const project = rows[0].value.project
    const same = []
    for (const row of rows) {
      if (row.value.project !== project || same.length >= max) break
      same.push(row)
    }
    same[0].startOffset = this.state.rollupOffset
    return same
  }

  async advanceRollups(endOffset, firstId, retryIds = []) {
    return this.withLock(async () => {
      if (endOffset > this.state.rollupOffset) {
        this.state.rollupOffset = endOffset
        if (firstId) delete this.state.rollupFailures[firstId]
        if (retryIds.length) {
          const resolved = new Set(retryIds)
          this.state.quarantinedRollups = this.state.quarantinedRollups.filter((item) => !resolved.has(item.id))
        }
        await this.saveState()
      }
    })
  }

  async noteRollupFailure(rows, error, maxAttempts = 3) {
    if (!rows.length) return { quarantined: false, attempts: 0 }
    return this.withLock(async () => {
      const first = rows[0]
      const firstId = String(first.value.id || `${this.state.rollupFile}:${first.startOffset}`)
      if (this.state.rollupOffset !== first.startOffset) return { quarantined: false, attempts: 0 }
      const attempts = (Number(this.state.rollupFailures[firstId]) || 0) + 1
      this.state.rollupFailures[firstId] = attempts
      if (attempts < maxAttempts) {
        await this.saveState()
        return { quarantined: false, attempts }
      }
      const item = {
        id: randomUUID(),
        file: this.state.rollupFile,
        filePath: this.state.rollupFile,
        startOffset: first.startOffset,
        endOffset: rows.at(-1).endOffset,
        project: String(first.value.project || 'unknown'),
        sourceIds: rows.map((row) => String(row.value.id || '')).filter(Boolean),
        sourceRefs: rows.map((row) => row.value.sourceRef).filter((ref) => typeof ref === 'string'),
        reason: bounded(redact(String(error?.message || error)), 240),
        attempts,
        at: new Date().toISOString(),
        retryCount: 0,
        retryPending: false
      }
      this.state.quarantinedRollups.push(item)
      const retriedIds = new Set(rows.map((row) => row.value.retryOf).filter((id) => typeof id === 'string'))
      if (retriedIds.size) this.state.quarantinedRollups = this.state.quarantinedRollups.filter((entry) => !retriedIds.has(entry.id))
      this.state.rollupOffset = item.endOffset
      delete this.state.rollupFailures[firstId]
      await this.saveState()
      return { quarantined: true, attempts, item: { ...item } }
    })
  }

  async listQuarantinedRollups() {
    await this.ready
    return this.state.quarantinedRollups.map(({ id, project, sourceRefs, reason, attempts, at, retryCount, lastRetryAt, retryPending }) => ({
      id, project, sourceRefs, reason, attempts, at, retryCount, lastRetryAt, retryPending
    }))
  }

  async retryQuarantinedRollup(id) {
    return this.withLock(async () => {
      const item = this.state.quarantinedRollups.find((entry) => entry.id === id)
      if (!item) throw new Error('Quarantined rollup not found')
      const sources = await this.journalFiles('rollups')
      const exactSource = isRollupJournalPath(item.filePath)
        ? sources.filter((file) => file.path === this.path(item.filePath))
        : []
      const candidates = exactSource.length ? exactSource : sources.filter((file) => file.name === item.file)
      let source
      let originalRows
      for (const candidate of candidates) {
        const selectedRows = []
        let offset = item.startOffset
        while (offset < item.endOffset) {
          const rows = await readRows(candidate.path, offset, Math.min(128 * 1024, item.endOffset - offset), this.key)
          if (!rows.length) break
          const selected = rows.filter((row) => row.endOffset <= item.endOffset)
          if (!selected.length) break
          selectedRows.push(...selected)
          offset = selected.at(-1).endOffset
        }
        if (!selectedRows.length || selectedRows.at(-1).endOffset !== item.endOffset) continue
        if (item.sourceIds?.length && selectedRows.map((row) => String(row.value.id || '')).join('\0') !== item.sourceIds.join('\0')) continue
        source = candidate
        originalRows = selectedRows
        break
      }
      if (!source || !originalRows?.length) throw new Error('Quarantined source journal is no longer available or does not match its recorded rows')
      const alreadyQueued = new Set()
      for (const file of await this.journalFiles('rollups')) {
        let cursor = 0
        while (cursor < file.size) {
          const queuedRows = await readRows(file.path, cursor, 128 * 1024, this.key)
          if (!queuedRows.length) break
          for (const row of queuedRows) {
            if (row.value.retryOf === item.id && typeof row.value.retrySourceId === 'string') {
              alreadyQueued.add(row.value.retrySourceId)
            }
          }
          cursor = queuedRows.at(-1).endOffset
        }
      }
      item.retryPending = true
      await this.saveState()
      let queued = 0
      for (const row of originalRows) {
        const value = row.value
        if (alreadyQueued.has(String(value.id))) continue
        const retry = {
          ...value,
          id: randomUUID(),
          at: new Date().toISOString(),
          session: 'retry',
          project: item.project,
          retryOf: item.id,
          retrySourceId: String(value.id)
        }
        await appendFile(this.path(this.state.rollupFile), encodeRow(retry, this.key), 'utf8')
        queued += 1
      }
      item.retryCount = (Number(item.retryCount) || 0) + 1
      item.lastRetryAt = new Date().toISOString()
      await this.saveState()
      return queued
    })
  }

  async commitLayers(project, expected, next, endOffset, firstId, retryIds = []) {
    return this.withLock(async () => {
      for (const layer of ['user', 'global', 'procedure', 'project']) {
        if ((await this.readLayer(layer, project)) !== expected[layer]) return false
      }
      const stamp = new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-')
      for (const layer of ['user', 'global', 'procedure', 'project']) {
        const content = next[layer]
        if (content === expected[layer]) continue
        const target = this.layerPath(layer, project)
        if (expected[layer]) {
          const filename = layer === 'project' ? `project-${project}` : layer
          await atomicWrite(this.path('history', `${filename}-${stamp}.md`), expected[layer])
          const versions = (await readdir(this.path('history')))
            .filter((name) => name.startsWith(`${filename}-`) && name.endsWith('.md'))
            .sort()
          for (const old of versions.slice(0, Math.max(0, versions.length - 5))) {
            await unlink(this.path('history', old)).catch(() => {})
          }
        }
        await atomicWrite(target, content)
      }
      this.state.rollupOffset = endOffset
      if (firstId) delete this.state.rollupFailures[firstId]
      if (retryIds.length) {
        const resolved = new Set(retryIds)
        this.state.quarantinedRollups = this.state.quarantinedRollups.filter((item) => !resolved.has(item.id))
      }
      this.state.version += 1
      await this.saveState()
      return true
    })
  }

  async compactionTargets() {
    await this.ready
    const targets = [
      { layer: 'user', project: 'unknown' },
      { layer: 'global', project: 'unknown' },
      { layer: 'procedure', project: 'unknown' }
    ]
    for (const file of await readdir(this.path('projects'))) {
      if (/^[0-9a-f]{16}\.md$/.test(file)) targets.push({ layer: 'project', project: file.slice(0, -3) })
    }
    return targets
  }

  compactionDue(layer, project, fingerprint) {
    const key = layer === 'project' ? `project:${project}` : layer
    const previous = this.state.compaction[key]
    if (previous?.policyVersion !== 3 || previous.fingerprint !== fingerprint) return true
    if (previous.status === 'rejected' || previous.status === 'complete' || previous.status === 'skipped') return false
    return Date.now() - previous.at >= 6 * 60 * 60 * 1000
  }

  async noteCompaction(layer, project, fingerprint, status, detail = '') {
    return this.withLock(async () => {
      const key = layer === 'project' ? `project:${project}` : layer
      this.state.compaction[key] = { policyVersion: 3, fingerprint, at: Date.now(), status, detail: bounded(detail, 160) }
      await this.saveState()
    })
  }

  async commitCompaction(layer, project, expected, content, fingerprint) {
    return this.withLock(async () => {
      const target = this.layerPath(layer, project)
      if ((await this.readLayer(layer, project)) !== expected) return false
      const stamp = new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-')
      const filename = layer === 'project' ? `project-${project}` : layer
      await atomicWrite(this.path('history', `${filename}-${stamp}-${randomUUID().slice(0, 8)}.md`), expected)
      const versions = (await readdir(this.path('history')))
        .filter((name) => name.startsWith(`${filename}-`) && name.endsWith('.md'))
        .sort()
      for (const old of versions.slice(0, Math.max(0, versions.length - 5))) {
        await unlink(this.path('history', old)).catch(() => {})
      }
      await atomicWrite(target, content)
      const key = layer === 'project' ? `project:${project}` : layer
      this.state.compaction[key] = { policyVersion: 3, fingerprint, at: Date.now(), status: 'complete', detail: '' }
      this.state.version += 1
      await this.saveState()
      return true
    })
  }

  async journalFiles(kind) {
    await this.ready
    const directories = kind === 'sessions'
      ? [this.path('sessions'), this.path('archive', 'sessions')]
      : [this.root, this.path('archive', 'rollups')]
    const files = []
    for (const directory of directories) {
      for (const name of await readdir(directory).catch(() => [])) {
        if (!name.endsWith('.jsonl')) continue
        if (kind === 'rollups' && !/^rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(name)) continue
        const path = join(directory, name)
        const metadata = await stat(path).catch(() => null)
        if (metadata?.isFile()) files.push({ path, name, size: metadata.size, modified: metadata.mtimeMs })
      }
    }
    return files.sort((a, b) => b.modified - a.modified)
  }

  async withdrawalEvents() {
    const path = this.path('withdrawals.jsonl')
    const events = []
    let offset = 0
    let order = 0
    while (offset < await fileSize(path)) {
      const rows = await readRows(path, offset, 128 * 1024, this.key)
      if (!rows.length) break
      for (const row of rows) {
        for (const candidate of row.value.candidates || []) {
          if (!candidate?.fact || !['user', 'global', 'project', 'procedure'].includes(candidate.layer)) continue
          events.push({
            at: Date.parse(row.value.at) || 0,
            order: order++,
            session: row.value.session,
            project: row.value.project || 'unknown',
            sourceRefs: row.value.suppressedSources || [],
            candidate
          })
        }
      }
      offset = rows.at(-1).endOffset
    }
    return events
  }

  buildWithdrawalMap(events) {
    events.sort((a, b) => a.at - b.at || a.order - b.order)
    const withdrawals = new Map()
    for (const event of events) {
      const key = withdrawalKey(event.candidate, event.project)
      if (!key) continue
      if (event.candidate.action === 'remove') {
        const previous = withdrawals.get(key)
        withdrawals.set(key, {
          layer: event.candidate.layer,
          project: event.project,
          normalized: normalizedFact(event.candidate.fact),
          fact: event.candidate.fact,
          at: Math.max(previous?.at || 0, event.at),
          sourceRefs: [...new Set([...(previous?.sourceRefs || []), ...event.sourceRefs])]
        })
      } else if (event.session === 'manual') {
        withdrawals.delete(key)
      }
    }
    return withdrawals
  }

  async search(query, project, limit = 8) {
    await this.ready
    const terms = searchTerms(query)
    if (!terms.length) return []
    const rollups = []
    const withdrawalEvents = await this.withdrawalEvents()
    const rollupFiles = (await this.journalFiles('rollups')).slice(0, 50)
    for (const file of rollupFiles) {
      const rows = await readRows(file.path, Math.max(0, file.size - 512 * 1024), 512 * 1024, this.key)
      rollups.push(...rows.map((row) => row.value))
    }
    const withdrawals = this.buildWithdrawalMap(withdrawalEvents)
    const hits = []
    for (const layer of ['user', 'global', 'project', 'procedure']) {
      const content = await this.readLayer(layer, project)
      for (const line of content.split('\n')) {
        if (isWithdrawn(line, project, withdrawals, layer)) continue
        const score = matchScore(line, terms, query)
        if (score) hits.push({ source: layer, score: score + 2, text: snippet(line, terms) })
      }
    }
    if (/(过程记忆|procedures?|流程|步骤|做法|操作)/iu.test(query)) {
      const procedure = await this.readLayer('procedure', project)
      if (procedure.trim() !== '# PROCEDURES') {
        hits.push({
          source: 'procedure:index', score: 5,
          text: '可用 hermes_memory_read({layer:"procedure"}) 查看完整过程记忆。'
        })
      }
    }
    for (const file of (await this.journalFiles('sessions')).slice(0, 50)) {
      const rows = await readRows(file.path, Math.max(0, file.size - 512 * 1024), 512 * 1024, this.key)
      for (const { value } of rows) {
        const ref = `s:${file.name.slice(0, 16)}:${value.toSeq}`
        if (isSourceWithdrawn(ref, withdrawals)) continue
        for (const message of value.messages || []) {
          if (isWithdrawn(message.text, value.project || 'unknown', withdrawals)) continue
          const score = matchScore(message.text, terms, query)
          if (score) hits.push({
            source: ref,
            score: score + (value.project === project ? 1 : 0),
            text: snippet(message.text, terms)
          })
        }
      }
    }
    for (const value of rollups) {
      for (const candidate of value.candidates || []) {
        if (isWithdrawn(candidate.fact, value.project || 'unknown', withdrawals, candidate.layer)) continue
        if (isSourceWithdrawn(value.sourceRef, withdrawals)) continue
        const score = matchScore(candidate.fact, terms, query)
        if (score) hits.push({
          source: value.sourceRef || 'rollup', score: score + 1,
          text: snippet(candidate.fact, terms)
        })
      }
    }
    return hits.sort((a, b) => b.score - a.score).slice(0, Math.min(20, Math.max(1, limit)))
  }

  async source(ref) {
    await this.ready
    const withdrawals = this.buildWithdrawalMap(await this.withdrawalEvents())
    const manual = /^m:([0-9a-f]{8})$/.exec(String(ref || '').trim())
    const session = /^s:([0-9a-f]{16}):(\d+)$/.exec(String(ref || '').trim())
    if (!manual && !session) throw new Error('Invalid source reference')
    if (isSourceWithdrawn(String(ref).trim(), withdrawals)) return '该来源包含已撤回记忆，已隐藏。'
    const files = await this.journalFiles(manual ? 'rollups' : 'sessions')
    for (const file of files) {
      if (session && !file.name.startsWith(session[1])) continue
      let offset = 0
      const recent = []
      while (offset < file.size) {
        const rows = await readRows(file.path, offset, 128 * 1024, this.key)
        if (!rows.length) break
        for (const row of rows) {
          if (manual && row.value.session === 'manual' && String(row.value.id).startsWith(manual[1])) {
            return row.value.candidates
              .filter((item) => !isWithdrawn(item.fact, row.value.project || 'unknown', withdrawals, item.layer))
              .map((item) => `[${item.action}] ${item.fact}`).join('\n')
          }
          if (session) {
            recent.push(row.value)
            if (recent.length > 8) recent.shift()
            if (row.value.toSeq === Number(session[2])) {
              const messages = recent.flatMap((item) => (item.messages || [])
                .filter((message) => !isWithdrawn(message.text, item.project || 'unknown', withdrawals))
                .map((message) => `[${message.role}] ${message.text}`))
              return bounded(messages.length ? messages.join('\n') : '原文包含已撤回记忆，已隐藏。', 5000)
            }
          }
        }
        offset = rows.at(-1).endOffset
      }
    }
    if (session) {
      for (const file of await this.journalFiles('rollups')) {
        let offset = 0
        while (offset < file.size) {
          const rows = await readRows(file.path, offset, 128 * 1024, this.key)
          if (!rows.length) break
          const found = rows.find((row) => row.value.sourceRef === ref)
          if (found) {
            const summary = isWithdrawn(found.value.summary || '', found.value.project || 'unknown', withdrawals)
              ? '已隐藏'
              : found.value.summary || '无'
            return `原文归档已过保留期；提炼摘要：${summary}`
          }
          offset = rows.at(-1).endOffset
        }
      }
    }
    return ''
  }
}
