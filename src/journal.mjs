import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, open, readFile, readdir, rename, stat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { gunzipSync, gzipSync } from 'node:zlib'

const MAX_ROW_BYTES = 1024 * 1024

async function hasEncryptedRow(path) {
  const stream = createReadStream(path, { encoding: 'utf8' })
  const input = createInterface({ input: stream, crlfDelay: Infinity })
  try {
    for await (const line of input) {
      if (!line) continue
      const row = JSON.parse(line)
      if (row?.v === 1 && typeof row.c === 'string') return true
    }
    return false
  } finally {
    stream.destroy()
  }
}

async function hasEncryptedJournals(root) {
  const directories = [
    root,
    join(root, 'sessions'),
    join(root, 'archive', 'sessions'),
    join(root, 'archive', 'rollups')
  ]
  for (const directory of directories) {
    for (const name of await readdir(directory).catch(() => [])) {
      const isRollup = /^rollups(?:-\d+-[\w-]+)?\.jsonl$/.test(name) || name === 'withdrawals.jsonl'
      const isSession = name.endsWith('.jsonl')
      if (!isRollup && !isSession) continue
      const path = join(directory, name)
      if ((await fileSize(path)) > 0 && await hasEncryptedRow(path)) return true
    }
  }
  return false
}

export async function loadJournalKey(root) {
  const path = join(root, 'memory.key')
  await mkdir(root, { recursive: true })
  try {
    const key = Buffer.from((await readFile(path, 'utf8')).trim(), 'hex')
    if (key.length !== 32) throw new Error('Invalid memory.key; restore it from backup')
    return key
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (await hasEncryptedJournals(root)) {
    throw new Error('memory.key is missing but encrypted journals exist; restore the original key from backup')
  }
  const generated = randomBytes(32)
  try {
    const handle = await open(path, 'wx', 0o600)
    try { await handle.writeFile(generated.toString('hex') + '\n', 'utf8') }
    finally { await handle.close() }
    return generated
  } catch (error) {
    if (error.code !== 'EEXIST') throw error
    const key = Buffer.from((await readFile(path, 'utf8')).trim(), 'hex')
    if (key.length !== 32) throw new Error('Invalid memory.key; restore it from backup')
    return key
  }
}

export function encodeRow(value, key) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  const compressed = gzipSync(Buffer.from(JSON.stringify(value)), { level: 6 })
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()])
  return JSON.stringify({
    v: 1,
    n: nonce.toString('base64'),
    t: cipher.getAuthTag().toString('base64'),
    c: ciphertext.toString('base64')
  }) + '\n'
}

export function decodeRow(line, key) {
  const value = JSON.parse(line)
  if (value?.v !== 1 || !value.n || !value.t || !value.c) return value
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.n, 'base64'))
  decipher.setAuthTag(Buffer.from(value.t, 'base64'))
  const compressed = Buffer.concat([decipher.update(Buffer.from(value.c, 'base64')), decipher.final()])
  return JSON.parse(gunzipSync(compressed).toString('utf8'))
}

export async function journalIsEncrypted(path) {
  let stream
  try {
    if ((await stat(path)).size === 0) return true
    stream = createReadStream(path, { encoding: 'utf8' })
    const input = createInterface({ input: stream, crlfDelay: Infinity })
    for await (const line of input) {
      if (!line) continue
      const row = JSON.parse(line)
      if (row?.v !== 1 || typeof row.c !== 'string') return false
    }
    return true
  } catch (error) {
    if (error.code === 'ENOENT') return true
    throw error
  } finally {
    stream?.destroy()
  }
}

export async function readRows(path, offset = 0, maxBytes = 128 * 1024, key) {
  let handle
  try {
    handle = await open(path, 'r')
    const { size } = await handle.stat()
    if (offset >= size) return []
    let capacity = Math.min(maxBytes, size - offset)
    let buffer
    let lastNewline = -1
    while (capacity <= MAX_ROW_BYTES) {
      buffer = Buffer.alloc(capacity)
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset)
      buffer = buffer.subarray(0, bytesRead)
      lastNewline = buffer.lastIndexOf(10)
      if (lastNewline >= 0 || offset + bytesRead >= size) break
      capacity = Math.min(MAX_ROW_BYTES, size - offset, capacity * 2)
      if (capacity === buffer.length) break
    }
    if (lastNewline < 0) return []
    const rows = []
    let cursor = offset
    let skipPartial = false
    if (offset > 0) {
      const prior = Buffer.alloc(1)
      await handle.read(prior, 0, 1, offset - 1)
      skipPartial = prior[0] !== 10
    }
    for (const line of buffer.subarray(0, lastNewline + 1).toString('utf8').split('\n')) {
      if (!line) continue
      cursor += Buffer.byteLength(line) + 1
      if (skipPartial) {
        skipPartial = false
        continue
      }
      rows.push({ value: decodeRow(line, key), endOffset: cursor })
    }
    return rows
  } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  } finally {
    await handle?.close()
  }
}

export async function encryptLegacyJournal(path, key, oldOffset = 0, beforeRename = async () => {}) {
  if (await journalIsEncrypted(path)) return { changed: false, offset: oldOffset }
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`
  let target
  let oldCursor = 0
  let newCursor = 0
  let newOffset = 0
  try {
    target = await open(temp, 'wx', 0o600)
    const input = createInterface({ input: createReadStream(path, { encoding: 'utf8' }), crlfDelay: Infinity })
    for await (const line of input) {
      if (!line) {
        oldCursor += 1
        continue
      }
      const encoded = encodeRow(decodeRow(line, key), key)
      await target.writeFile(encoded)
      oldCursor += Buffer.byteLength(line) + 1
      newCursor += Buffer.byteLength(encoded)
      if (oldCursor <= oldOffset) newOffset = newCursor
    }
    await target.close()
    target = null
    await beforeRename(newOffset)
    await rename(temp, path)
    return { changed: true, offset: newOffset }
  } catch (error) {
    await target?.close().catch(() => {})
    await unlink(temp).catch(() => {})
    throw error
  }
}

export async function fileSize(path) {
  try { return (await stat(path)).size }
  catch (error) {
    if (error.code === 'ENOENT') return 0
    throw error
  }
}
