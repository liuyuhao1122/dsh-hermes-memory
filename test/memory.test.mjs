import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { apply } from '../src/index.mjs'
import { compactionPlan, validateCompaction } from '../src/compaction.mjs'
import { decodeRow, encodeRow, loadJournalKey, readRows } from '../src/journal.mjs'
import { resolveModelRoute } from '../src/model-route.mjs'
import { MemoryStore, keyFor, projectKey, redact } from '../src/store.mjs'

test('compaction starts near capacity and sizes its target to the trigger', () => {
  const header = '# PROJECT'
  const line = '- 一条独立且需要保留的事实。〔s:0123456789abcdef:10〕\n'
  const below = header + '\n' + Array.from({ length: 20 }, (_, index) =>
    `- 第 ${index + 1} 条独立且需要保留的事实。〔s:0123456789abcdef:10〕\n`).join('')
  assert.equal(compactionPlan(below, header, below.length * 1.2), null)
  const nearLimit = Math.ceil(below.length / 0.95)
  const plan = compactionPlan(below, header, nearLimit)
  assert.equal(plan.reason, 'size')
  assert.equal(plan.minSavings, 1)
  assert.equal(plan.targetSavings, Math.max(48, Math.ceil(nearLimit * 0.05)))
  assert.equal(plan.target, below.length - plan.targetSavings)
  const forced = compactionPlan(header + '\n' + line, header, 1600, true)
  assert.equal(forced.reason, 'overflow')
  assert.equal(forced.minSavings, 1)
})

test('safe positive reduction is accepted even below the model target', () => {
  const source = '〔s:0123456789abcdef:10〕'
  const original = `# USER\n- 用户喜欢使用本地 Markdown 文档。${source}\n`
  const shorter = `# USER\n- 用户喜欢本地 Markdown 文档。${source}\n`
  const limit = original.length + 1
  const plan = compactionPlan(original, '# USER', limit)
  assert.ok(original.length - shorter.length < plan.targetSavings)
  assert.equal(validateCompaction({ content: shorter, coverage: [{ old: 1, new: 1 }] },
    original, '# USER', limit, plan), shorter)
  assert.throws(() => validateCompaction({ content: original, coverage: [{ old: 1, new: 1 }] },
    original, '# USER', limit, plan), /saved too little/)
})

test('unchanged rejected content is retried once after a policy update', async (t) => {
  const root = await temporaryRoot(t)
  const store = new MemoryStore(root)
  await store.ready
  const fingerprint = 'a'.repeat(64)
  assert.equal(store.compactionDue('project', 'example', fingerprint), true)
  await store.noteCompaction('project', 'example', fingerprint, 'rejected', 'Dense unique facts')
  assert.equal(store.compactionDue('project', 'example', fingerprint), false)
  assert.equal(store.compactionDue('project', 'example', 'b'.repeat(64)), true)
  store.state.compaction['project:example'].policyVersion = 2
  assert.equal(store.compactionDue('project', 'example', fingerprint), true)
  await store.noteCompaction('project', 'example', fingerprint, 'model-error')
  assert.equal(store.compactionDue('project', 'example', fingerprint), false)
  store.state.compaction['project:example'].at -= 6 * 60 * 60 * 1000 + 1
  assert.equal(store.compactionDue('project', 'example', fingerprint), true)
})

async function temporaryRoot(t) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-hermes-test-'))
  t.after(async () => {
    const allowed = join(resolve(tmpdir()), 'dsh-hermes-test-')
    assert.ok(resolve(root).startsWith(allowed))
    await rm(root, { recursive: true, force: true })
  })
  return root
}

async function until(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs
  do {
    if (await predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 20))
  } while (Date.now() < deadline)
  throw new Error('Timed out waiting for background memory work')
}

test('redaction keeps identifiers and is idempotent', () => {
  const sha = '4f2a9c8e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f1a'
  const folder = 'dsh-hermes-memory-research-notes-2026'
  const original = `commit ${sha}; use ${folder}; api_key=sk-abcdefghijklmnopqrstuvwx`
  const result = redact(original)
  assert.ok(result.includes(sha))
  assert.ok(result.includes(folder))
  assert.ok(result.includes('api_key=[REDACTED SECRET]'))
  assert.ok(!result.includes('sk-abcdefghijklmnopqrstuvwx'))
  assert.equal(redact(result), result)
  assert.equal(redact('Authorization: Bearer abcdefghijklmnopqrstuvwxyz'), 'Authorization: Bearer [REDACTED]')
})

test('encrypted journal roundtrip, authentication and partial row handling', async (t) => {
  const root = await temporaryRoot(t)
  const key = randomBytes(32)
  const row = { text: '中文秘密内容', seq: 1 }
  const line = encodeRow(row, key)
  assert.ok(!line.includes(row.text))
  assert.deepEqual(decodeRow(line, key), row)
  assert.throws(() => decodeRow(line, randomBytes(32)))
  const path = join(root, 'journal.jsonl')
  await writeFile(path, line + line.slice(0, 12))
  const rows = await readRows(path, 0, 20, key)
  assert.equal(rows.length, 1)
  assert.deepEqual(rows[0].value, row)
  assert.equal(rows[0].endOffset, Buffer.byteLength(line))
})

test('forget remains effective through search and source lookup after restart without a plaintext backup', async (t) => {
  const root = await temporaryRoot(t)
  const store = new MemoryStore(root)
  await store.ready
  const project = projectKey(root)
  const fact = '项目使用的测试主题是深蓝色'
  const captured = await store.capture('forget-source-session', root, [
    { seq: 1, role: 'user', text: fact }
  ])
  const source = `s:${captured.sid}:1`
  await writeFile(store.layerPath('project', project), `# PROJECT\n- ${fact} 〔${source}〕\n`)
  const id = await store.appendManual({ layer: 'project', action: 'remove', fact }, project, true)
  assert.equal(await readFile(store.layerPath('project', project), 'utf8'), '# PROJECT\n')
  assert.deepEqual(await store.search('测试主题深蓝色', project), [])
  assert.ok((await store.source(source)).includes('已撤回'))
  assert.deepEqual(await readdir(join(root, 'history')), [])
  const ledger = await readFile(join(root, 'withdrawals.jsonl'), 'utf8')
  assert.ok(!ledger.includes(fact))
  assert.equal((await store.source(`m:${id.slice(0, 8)}`)).trim(), '')

  const restarted = new MemoryStore(root)
  await restarted.ready
  assert.deepEqual(await restarted.search('测试主题深蓝色', project), [])
  assert.ok((await restarted.source(source)).includes('已撤回'))
})

test('missing key is not regenerated when only an encrypted withdrawal journal remains', async (t) => {
  const root = await temporaryRoot(t)
  const key = randomBytes(32)
  await writeFile(join(root, 'withdrawals.jsonl'), encodeRow({ id: 'withdrawal-1', candidates: [] }, key))
  await assert.rejects(loadJournalKey(root), /memory\.key is missing but encrypted journals exist/)
  await assert.rejects(readFile(join(root, 'memory.key')),
    (error) => error.code === 'ENOENT')
})

test('poison rollups quarantine, let later projects proceed and retry from the correct archived segment', async (t) => {
  const root = await temporaryRoot(t)
  const store = new MemoryStore(root)
  await store.ready
  const rows = [
    { id: 'a1', project: 'project-a', sourceRef: 's:aaaaaaaaaaaaaaaa:1', candidates: [{ layer: 'project', fact: '项目甲事实一' }] },
    { id: 'a2', project: 'project-a', sourceRef: 's:aaaaaaaaaaaaaaaa:2', candidates: [{ layer: 'project', fact: '项目甲事实二' }] },
    { id: 'b1', project: 'project-b', sourceRef: 's:bbbbbbbbbbbbbbbb:1', candidates: [{ layer: 'project', fact: '项目乙事实' }] }
  ]
  await writeFile(store.path(store.state.rollupFile), rows.map((row) => encodeRow(row, store.key)).join(''))
  const poison = await store.pendingRollups()
  assert.equal(poison.length, 2)
  await store.noteRollupFailure(poison, new Error('model failure'))
  await store.noteRollupFailure(poison, new Error('model failure'))
  const quarantined = await store.noteRollupFailure(poison, new Error('model failure'))
  assert.equal(quarantined.quarantined, true)
  assert.equal((await store.pendingRollups())[0].value.project, 'project-b')

  const later = await store.pendingRollups()
  await store.advanceRollups(later.at(-1).endOffset, later[0].value.id)
  const past = new Date(Date.now() - 8 * 86400000)
  await utimes(store.path('rollups.jsonl'), past, past)
  await store.maintainJournals(true)
  assert.equal(store.state.quarantinedRollups[0].filePath, join('archive', 'rollups', 'rollups.jsonl'))

  assert.equal(await store.retryQuarantinedRollup(quarantined.item.id), 2)
  const retryRows = await store.pendingRollups()
  assert.equal(retryRows.length, 2)
  assert.ok(retryRows.every((row) => row.value.retryOf === quarantined.item.id))
  assert.deepEqual(retryRows.map((row) => row.value.retrySourceId), ['a1', 'a2'])
})

test('legacy migration preserves both processed and pending cursors', async (t) => {
  const root = await temporaryRoot(t)
  const sid = keyFor('old-session')
  const first = JSON.stringify({ toSeq: 1, messages: [{ role: 'user', text: '记忆系统安装' }] }) + '\n'
  const second = JSON.stringify({ toSeq: 2, messages: [{ role: 'user', text: '第二条待整理' }] }) + '\n'
  const r1 = JSON.stringify({ project: 'p', candidates: [{ layer: 'global', fact: '已处理的事实' }] }) + '\n'
  const r2 = JSON.stringify({ project: 'p', candidates: [{ layer: 'global', fact: '待处理的事实' }] }) + '\n'
  await writeFile(join(root, 'state.json'), JSON.stringify({
    sessions: { [sid]: { capturedSeq: 2, distilledSeq: 1, distilledOffset: Buffer.byteLength(first), project: 'p' } },
    rollupFile: 'rollups.jsonl', rollupOffset: Buffer.byteLength(r1), version: 0
  }))
  await mkdir(join(root, 'sessions'))
  await writeFile(join(root, 'sessions', `${sid}.jsonl`), first + second)
  await writeFile(join(root, 'rollups.jsonl'), r1 + r2)
  const store = new MemoryStore(root)
  await store.ready
  assert.equal((await store.pendingSession(sid)).rows[0].value.toSeq, 2)
  assert.equal((await store.pendingRollups())[0].value.candidates[0].fact, '待处理的事实')
  assert.ok(!(await readFile(join(root, 'sessions', `${sid}.jsonl`), 'utf8')).includes('记忆系统安装'))
  assert.ok(!(await readFile(join(root, 'rollups.jsonl'), 'utf8')).includes('待处理的事实'))
})

test('Chinese retrieval, procedure discovery, rotation and source fallback', async (t) => {
  const root = await temporaryRoot(t)
  const store = new MemoryStore(root, { rawRetentionDays: 30, rollupRetentionDays: 365 })
  await store.ready
  await writeFile(store.layerPath('procedure'), '# PROCEDURES\n- 安装记忆系统时先检查插件配置。\n')
  const result = await store.capture('session-A', root, [{ seq: 1, role: 'user', text: '记忆系统安装完成。' }])
  assert.equal(result.pending, true)
  assert.ok((await store.search('记忆系统安装', 'unknown')).some((hit) => hit.text.includes('记忆系统安装')))
  assert.ok((await store.search('流程', 'unknown')).some((hit) => hit.source === 'procedure:index'))
  const row = (await store.pendingSession(result.sid)).rows[0]
  const ref = `s:${result.sid}:1`
  await store.appendRollup({ id: 'r1', project: 'unknown', sourceRef: ref, summary: '完成安装', candidates: [] }, result.sid, 1, row.endOffset)
  await store.advanceRollups((await store.pendingRollups())[0].endOffset)
  assert.ok((await store.source(ref)).includes('记忆系统安装完成'))
  const past = new Date(Date.now() - 9 * 86400000)
  await utimes(store.path('sessions', store.sessionFile(result.sid)), past, past)
  await utimes(store.path('rollups.jsonl'), past, past)
  await store.maintainJournals(true)
  assert.ok((await readdir(store.path('archive', 'sessions'))).length === 1)
  assert.ok((await readdir(store.path('archive', 'rollups'))).length === 1)
  const archived = join(store.path('archive', 'sessions'), (await readdir(store.path('archive', 'sessions')))[0])
  await utimes(archived, past, past)
  store.rawRetentionDays = 1
  await store.maintainJournals(true)
  assert.equal((await readdir(store.path('archive', 'sessions'))).length, 0)
  assert.ok((await store.source(ref)).includes('完成安装'))
})

test('fake DSH host captures, extracts, consolidates and exposes five tools', async (t) => {
  const root = await temporaryRoot(t)
  const registered = new Map()
  const hooks = new Map()
  const disposers = []
  let contextProvider
  let llmCalls = 0
  const signals = []
  const sha = '4f2a9c8e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f1a'
  const llm = {
    async *stream(options) {
      llmCalls += 1
      signals.push(options.signal)
      assert.equal(options.signal.aborted, false)
      if (llmCalls === 1) {
        const error = new Error('UNSUPPORTED_REASONING_EFFORT')
        error.code = 'UNSUPPORTED_REASONING_EFFORT'
        throw error
      }
      let response
      if (options.system.includes('后台记忆提炼器')) {
        response = JSON.stringify({ summary: '保存提交记录', candidates: [{ layer: 'project', fact: `项目提交为 ${sha}` }] })
      } else {
        const source = /s:[0-9a-f]{16}:\d+/.exec(options.messages[0].content[0].text)?.[0]
        response = JSON.stringify({ user: '# USER', global: '# MEMORY', project: `# PROJECT\n- 项目提交为 ${sha} 〔${source}〕`, procedure: '# PROCEDURES' })
      }
      yield { type: 'text-delta', index: 0, text: response }
      yield { type: 'finish', reason: { kind: 'stop' } }
    }
  }
  const ctx = {
    logger: { info() {}, warn() {} },
    get(name) { return name === 'systemPrompt' ? { context(spec) { contextProvider = spec; return () => {} } } : undefined },
    inject(deps, callback) {
      if (deps.includes('tools')) callback({ tools: { register(def) { registered.set(def.name, def); return () => {} } } })
      if (deps.includes('llm')) callback({ llm })
    },
    on(name, callback) { hooks.set(name, callback); return () => {} },
    effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root, provider: 'fake', model: 'fake', consolidateEvery: 1, consolidateDelayMs: 1000 })
  assert.equal(registered.size, 5)
  assert.ok(contextProvider)
  const session = {
    id: 'session-1', header: { cwd: root },
    snapshotEvents() { return [{ type: 'user/message', seq: 1, data: { content: [{ type: 'text', text: `记住项目提交 ${sha}` }] } }] }
  }
  hooks.get('agent/turn-stopping')({ agent: { session } })
  await until(async () => {
    try { return JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).version >= 1 } catch { return false }
  })
  const project = projectKey(root)
  const content = await readFile(join(root, 'projects', `${project}.md`), 'utf8')
  assert.ok(content.includes(sha))
  assert.ok(!content.includes('[REDACTED'))
  const search = await registered.get('hermes_memory_search').execute({ query: '项目提交' }, { agent: { session } })
  assert.ok(search.results.some((hit) => hit.text.includes(sha)))
  assert.ok((await registered.get('hermes_memory_source').execute({ ref: `s:${keyFor(session.id)}:1` })).content.includes(sha))
  assert.ok((await registered.get('hermes_memory_read').execute({ layer: 'project' }, { agent: { session } })).content.includes(sha))
  const manual = await registered.get('hermes_memory_remember').execute({
    layer: 'procedure', fact: '安装项目时从环境变量读取 api_key=sk-abcdefghijklmnopqrstuvwx 再启动服务。'
  }, { agent: { session } })
  const sanitized = (await registered.get('hermes_memory_source').execute({ ref: `m:${manual.id.slice(0, 8)}` })).content
  assert.ok(sanitized.includes('[REDACTED SECRET]'))
  assert.ok(!sanitized.includes('sk-abcdefghijklmnopqrstuvwx'))
  assert.ok(!sanitized.includes('[REDACTED] SECRET]'))
  assert.ok(llmCalls >= 3)
  assert.notEqual(signals[0], signals[1])
  assert.ok(contextProvider.text({ scope: { session } }).includes(sha))
  await writeFile(join(root, 'PROCEDURES.md'), '# PROCEDURES\n- 安装记忆系统前核对插件配置。\n')
  assert.ok(contextProvider.text({ scope: { session } }).includes('hermes_memory_read({layer:"procedure"})'))
  assert.equal(JSON.parse(await readFile(join(root, 'diagnostics.json'), 'utf8')).status, 'ready')
})

test('one rejected tool registration leaves the others available and reports error', async (t) => {
  const root = await temporaryRoot(t)
  const registered = []
  const disposers = []
  const ctx = {
    logger: { info() {}, warn() {} }, get() { return undefined },
    inject(deps, callback) {
      if (deps.includes('tools')) callback({ tools: { register(def) {
        if (def.name === 'hermes_memory_search') throw new Error('Rejected schema')
        registered.push(def.name)
        return () => {}
      } } })
    },
    on() { return () => {} },
    effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root })
  await until(async () => {
    try {
      const diagnostic = JSON.parse(await readFile(join(root, 'diagnostics.json'), 'utf8'))
      return diagnostic.status === 'error' && diagnostic.detail.includes('failed to load')
    } catch { return false }
  })
  assert.equal(registered.length, 4)
  const diagnostic = JSON.parse(await readFile(join(root, 'diagnostics.json'), 'utf8'))
  assert.ok(diagnostic.detail.includes('failed to load'))
})

test('model route follows the live DSH selection and falls back only when absent', () => {
  const fallback = { provider: 'fallback', model: 'old-model' }
  const live = { get(name) {
    return name === 'agentDefaultModel' ? { currentSelection: () => ({ provider: 'live', model: 'current-model' }) } : undefined
  } }
  assert.deepEqual(resolveModelRoute(live, fallback), { provider: 'live', model: 'current-model' })
  assert.deepEqual(resolveModelRoute({ get: () => undefined }, fallback), fallback)
})

test('compaction rejects missing facts, sources and protected values', () => {
  const source = '〔s:0123456789abcdef:10〕'
  const original = `# USER\n- 使用版本 \`v1.2\` ${source}\n- 使用版本 \`v1.2\` ${source}\n`
  const plan = { lines: original.trim().split('\n').slice(1), target: 300 }
  const coverage = [{ old: 1, new: 1 }, { old: 2, new: 1 }]
  assert.throws(() => validateCompaction({ content: '# USER\n- 使用版本 `v1.2`', coverage }, original, '# USER', 300, plan), /source/)
  assert.throws(() => validateCompaction({ content: `# USER\n- 使用版本 ${source} ${source}`, coverage }, original, '# USER', 300, plan), /protected/)
  assert.throws(() => validateCompaction({ content: `# USER\n- 使用版本 \`v1.2\` ${source} ${source}`, coverage: coverage.slice(0, 1) }, original, '# USER', 300, plan), /omitted/)
  const expanded = `# USER\n- 使用版本 \`v1.2\` ${source}，并保留完整的详细过程说明。\n- 使用版本 \`v1.2\` ${source}，并保留完整的详细过程说明。\n`
  assert.throws(() => validateCompaction({
    content: `# USER\n- 使用版本 \`v1.2\` ${source} ${source}\n- 新事实`, coverage
  }, expanded, '# USER', 300, { ...plan, lines: expanded.trim().split('\n').slice(1) }), /unmapped/)
  assert.throws(() => validateCompaction({
    content: `# USER\n- 使用版本 \`v1.2\` ${source} ${source} api_key=sk-abcdefghijklmnopqrstuvwx`, coverage
  }, original, '# USER', 300, plan), /sensitive/)
  const safeReduction = `# USER\n- 使用版本 \`v1.2\` ${source} ${source}`
  assert.equal(validateCompaction({ content: safeReduction, coverage }, original, '# USER', 300,
    { ...plan, target: 40 }), safeReduction + '\n')
})

test('idle compaction uses current DSH model, preserves sources and keeps history', async (t) => {
  const root = await temporaryRoot(t)
  const source = '〔s:0123456789abcdef:10〕'
  const line = `- 用户更偏好将可重复流程保存在本地 Markdown 文档中。${source}`
  const oldContent = '# USER\n' + Array(24).fill(line).join('\n') + '\n'
  assert.ok(compactionPlan(oldContent, '# USER', 1375))
  await writeFile(join(root, 'USER.md'), oldContent)
  const disposers = []
  const routes = []
  const ctx = {
    logger: { info() {}, warn() {} },
    get(name) {
      return name === 'agentDefaultModel'
        ? { currentSelection: () => ({ provider: 'current-provider', model: 'current-model' }) }
        : undefined
    },
    inject(deps, callback) {
      if (deps.includes('llm')) callback({ llm: { async *stream(options) {
        routes.push({ provider: options.provider, model: options.model })
        const compacted = '# USER\n- 用户更偏好将可重复流程保存在本地 Markdown 文档中。' + Array(24).fill(source).join(' ') + '\n'
        const response = JSON.stringify({ content: compacted, coverage: Array.from({ length: 24 }, (_, index) => ({ old: index + 1, new: 1 })) })
        yield { type: 'text-delta', index: 0, text: response }
        yield { type: 'finish', reason: { kind: 'stop' } }
      } } })
      if (deps.includes('tools')) callback({ tools: { register() { return () => {} } } })
    },
    on() { return () => {} },
    effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root, provider: 'fallback', model: 'old-model' })
  await until(async () => {
    try { return JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).compaction.user?.status === 'complete' } catch { return false }
  })
  const next = await readFile(join(root, 'USER.md'), 'utf8')
  assert.ok(next.length < oldContent.length * 0.9)
  assert.equal((next.match(/〔s:0123456789abcdef:10〕/g) || []).length, 24)
  assert.deepEqual(routes[0], { provider: 'current-provider', model: 'current-model' })
  const history = await readdir(join(root, 'history'))
  assert.ok(history.some((name) => name.startsWith('user-')))
  assert.equal(await readFile(join(root, 'history', history.find((name) => name.startsWith('user-'))), 'utf8'), oldContent)
})

test('invalid model compaction leaves the Markdown untouched', async (t) => {
  const root = await temporaryRoot(t)
  const original = '# USER\n' + Array(24).fill('- 用户偏好保留具体事实及来源引用。〔s:0123456789abcdef:10〕').join('\n') + '\n'
  await writeFile(join(root, 'USER.md'), original)
  const disposers = []
  const ctx = {
    logger: { info() {}, warn() {} }, get() { return undefined },
    inject(deps, callback) {
      if (deps.includes('llm')) callback({ llm: { async *stream() {
        yield { type: 'text-delta', index: 0, text: JSON.stringify({ content: '# USER\n- 内容丢失', coverage: [] }) }
        yield { type: 'finish', reason: { kind: 'stop' } }
      } } })
      if (deps.includes('tools')) callback({ tools: { register() { return () => {} } } })
    },
    on() { return () => {} }, effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root, provider: 'fake', model: 'fake' })
  await until(async () => {
    try { return JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).compaction.user?.status === 'rejected' } catch { return false }
  })
  assert.equal(await readFile(join(root, 'USER.md'), 'utf8'), original)
  assert.deepEqual(await readdir(join(root, 'history')), [])
})

test('oversize consolidation compacts the old layer and retries without truncation', async (t) => {
  const root = await temporaryRoot(t)
  const source = '〔s:0123456789abcdef:10〕'
  const oldLines = [
    `- 用户偏好本地可编辑的记忆文档。${source}`,
    `- 用户更喜欢保存在本地且能编辑的记忆文档。${source}`,
    `- 对记忆文档，用户倾向本地存储并可直接修改。${source}`
  ]
  const original = '# USER\n' + oldLines.join('\n') + '\n'
  const compacted = '# USER\n- 用户偏好本地可编辑的记忆文档。' + Array(3).fill(source).join(' ') + '\n'
  assert.equal(compactionPlan(original, '# USER', 1375), null)
  await writeFile(join(root, 'USER.md'), original)
  const registered = new Map()
  const disposers = []
  let consolidations = 0
  let provideLlm
  const ctx = {
    logger: { info() {}, warn() {} }, get() { return undefined },
    inject(deps, callback) {
      if (deps.includes('tools')) callback({ tools: { register(def) { registered.set(def.name, def); return () => {} } } })
      if (deps.includes('llm')) provideLlm = () => callback({ llm: { async *stream(options) {
        let response
        if (options.system.includes('长期记忆压缩器')) {
          response = { content: compacted, coverage: Array.from({ length: 3 }, (_, index) => ({ old: index + 1, new: 1 })) }
        } else {
          consolidations += 1
          response = {
            user: consolidations === 1
              ? original + Array(150).fill('- 新增可复用的事实。').join('\n') + '\n'
              : compacted + '- 新增可复用的事实。\n',
            global: '# MEMORY', project: '# PROJECT', procedure: '# PROCEDURES'
          }
        }
        yield { type: 'text-delta', index: 0, text: JSON.stringify(response) }
        yield { type: 'finish', reason: { kind: 'stop' } }
      } } })
    },
    on() { return () => {} }, effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root, provider: 'fake', model: 'fake', consolidateEvery: 1, consolidateDelayMs: 1000 })
  await registered.get('hermes_memory_remember').execute({ layer: 'user', fact: '新增可复用的事实' }, { agent: { session: { header: { cwd: root } } } })
  provideLlm()
  await until(async () => {
    try { return JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).version >= 2 } catch { return false }
  }, 4000)
  assert.equal(consolidations, 2)
  const next = await readFile(join(root, 'USER.md'), 'utf8')
  assert.ok(next.includes('新增可复用的事实'))
  assert.equal((next.match(/〔s:0123456789abcdef:10〕/g) || []).length, 3)
})

test('empty extraction rollups are consumed so idle compaction is not blocked', async (t) => {
  const root = await temporaryRoot(t)
  const hooks = new Map()
  const disposers = []
  const ctx = {
    logger: { info() {}, warn() {} }, get() { return undefined },
    inject(deps, callback) {
      if (deps.includes('llm')) callback({ llm: { async *stream() {
        yield { type: 'text-delta', index: 0, text: JSON.stringify({ summary: '普通闲聊', candidates: [] }) }
        yield { type: 'finish', reason: { kind: 'stop' } }
      } } })
      if (deps.includes('tools')) callback({ tools: { register() { return () => {} } } })
    },
    on(name, callback) { hooks.set(name, callback); return () => {} },
    effect(callback) { disposers.push(callback()) }
  }
  t.after(() => disposers.forEach((dispose) => dispose()))
  apply(ctx, { memoryDir: root, provider: 'fake', model: 'fake', consolidateEvery: 3, consolidateDelayMs: 1000 })
  const session = {
    id: 'empty-session', header: { cwd: root },
    snapshotEvents() { return [{ type: 'user/message', seq: 1, data: { content: [{ type: 'text', text: '你好' }] } }] }
  }
  hooks.get('agent/turn-stopping')({ agent: { session } })
  await until(async () => {
    try { return JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).rollupOffset > 0 } catch { return false }
  }, 4000)
  const state = JSON.parse(await readFile(join(root, 'state.json'), 'utf8'))
  assert.equal(state.version, 0)
  assert.equal(state.sessions[keyFor(session.id)].capturedSeq, state.sessions[keyFor(session.id)].distilledSeq)
})
