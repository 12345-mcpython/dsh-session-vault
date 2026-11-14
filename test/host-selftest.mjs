/**
 * 宿主半侧自检（不需要 DSH 在跑）：`node test/host-selftest.mjs`
 *
 * 用假 ctx 把 index.js 装起来，覆盖：
 *   - 每条会话独立口令（scrypt 派生值，不存明文，没有全局口令）
 *   - 会话锁登记 + 内存授权 + 空闲过期
 *   - 磁盘锁：原地加密、`.header` 旁路、锁定时 list 仍能读头、解锁状态追加事件后仍是密文
 *   - 锁定时拒绝写打开
 *   - 上一版遗留密文：启动补登 + 用文件自己的口令救回
 *   - WALLBK 容器：往返、错口令、篡改
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { zstdCompressSync, zstdDecompressSync } from 'node:zlib'
import { scryptSync } from 'node:crypto'

const mod = await import(new URL('../index.js', import.meta.url).href)
const stateMod = await import(new URL('../lib/state.mjs', import.meta.url).href)
const diskMod = await import(new URL('../lib/disk.mjs', import.meta.url).href)
const routesMod = await import(new URL('../lib/routes.mjs', import.meta.url).href)
const secretMod = await import(new URL('../lib/secret.mjs', import.meta.url).href)

let failures = 0
const check = (label, cond, extra = '') => {
  if (cond) console.log(`  ok   ${label}`)
  else { failures += 1; console.log(`  FAIL ${label} ${extra}`) }
}

/** Node 的 zstd 只解第一帧，DSH 后端自己扫帧；这里补一个按帧切开的解压。 */
function decodeAllFrames(buf) {
  const FRAME_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])
  const starts = []
  let i = 0
  while (i < buf.length) {
    const at = buf.indexOf(FRAME_MAGIC, i)
    if (at < 0) break
    starts.push(at)
    i = at + 4
  }
  let out = ''
  for (let k = 0; k < starts.length; k += 1) {
    const part = buf.subarray(starts[k], k + 1 < starts.length ? starts[k + 1] : buf.length)
    out += zstdDecompressSync(part).toString('utf8')
  }
  return out
}

/** 造一条和 DSH 一模一样的会话日志（header 帧 + 事件帧）。 */
function makeSessionFile(file, id, cwd) {
  const headerLine = JSON.stringify({ type: 'session', version: 4, id, createdAt: Date.now(), cwd })
  const eventLine = JSON.stringify({ type: 'turn/end', seq: 1, at: Date.now(), detail: { policy: 'ask' } })
  writeFileSync(file, Buffer.concat([zstdCompressSync(headerLine + '\n'), zstdCompressSync(eventLine + '\n')]))
  return { header: headerLine, text: `${headerLine}\n${eventLine}\n` }
}

// ---- 临时 DSH home ------------------------------------------------------
const home = join(tmpdir(), `session-vault-selftest-${process.pid}-${Date.now()}`)
const sessions = join(home, 'sessions')
const cwd = 'E:\\SelfTest'
const id = 'session-11111111-2222-3333-4444-555555555555'
const dir = join(sessions, '--E-SelfTest--', id)
mkdirSync(dir, { recursive: true })
const logFile = join(dir, 'session.v4.jsonl.zstd')
const { header: originalHeader, text: originalText } = makeSessionFile(logFile, id, cwd)
const originalBytes = readFileSync(logFile)

// ---- 假后端 -------------------------------------------------------------
const backendProto = {
  async readFirstZstdLine(path, signal) {
    void signal
    const text = zstdDecompressSync(readFileSync(path)).toString('utf8')
    return text.slice(0, text.indexOf('\n'))
  },
  async decodeStoredLog(path, expectedId, buffer) {
    return { path, id: expectedId, bytes: buffer.length, text: decodeAllFrames(buffer) }
  },
  async appendLines() { throw new Error('appendLines 不应被直接调用') },
  async repair() { throw new Error('repair 不应被直接调用') },
  async open() { return { closed: true } },
  async encodeEventBatch() { return zstdCompressSync(Buffer.from('{"type":"probe"}\n')) },
  async stat() { return {} },
  async list() { return [] },
}
const backend = Object.create(backendProto)
const PROBE_FRAME = Buffer.from('{"type":"probe"}\n')

// ---- 假 ctx -------------------------------------------------------------
function makeCtx(routes) {
  const effects = []
  const ctx = {
    logger: { info: () => {}, warn: () => {} },
    get(name) {
      if (name === 'dshHomePath') return (...segments) => join(home, ...segments)
      if (name === 'sessionPersistence') return backend
      if (name === 'connection') {
        return { fetch: { register: (route) => { routes.set(route.path, route); return async () => { routes.delete(route.path) } } } }
      }
      return undefined
    },
    effect(cb) {
      const dispose = cb()
      effects.push(dispose)
      return () => { if (typeof dispose === 'function') dispose() }
    },
    tools: { register: () => () => {} },
  }
  return { ctx, effects }
}

const routes = new Map()
const { ctx, effects } = makeCtx(routes)
mod.apply(ctx, { dest: join(home, 'backup'), keep: 5, autoLockMinutes: 10, diskLock: true })

const route = routes.get('/api/session.vault')
const call = async (action, body) => {
  const init = body === undefined
    ? { method: 'GET', headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
  const res = await route.fetch(new Request(`http://dsh.internal/api/session.vault?action=${action}`, init))
  return { status: res.status, ...(await res.json()) }
}

console.log('\n[1] 路由 / 状态 / 每条会话自己的口令')
check('注册了 /api/session.vault 路由', Boolean(route))
let status = await call('status')
check('初始没有锁', status.locks.length === 0)
check('status 没有任何口令字段', !('password' in status) && !JSON.stringify(status).includes('"password"'))
check('setup 路由已删除', (await call('setup', { password: 'correct horse' })).status === 404)
let res = await call('lock', { sessionId: id, password: '123', disk: false })
check('拒绝过短口令', res.status === 400)
res = await call('lock', { sessionId: id, disk: false })
check('没有现成口令时上锁被拒', res.status === 409)
const stateFile = join(home, 'session-vault', 'state.json')
let persisted = JSON.parse(readFileSync(stateFile, 'utf8'))
check('新装 state.json 没有全局 password 字段', !('password' in persisted))
check('新装 state.json 里没有明文口令', !readFileSync(stateFile, 'utf8').includes('correct horse'))
const migrated = stateMod.normalizeState({
  version: 1,
  password: { alg: 'scrypt', N: 32768, salt: 'AAAAAAAAAAAAAAAAAAAAAA==', hash: 'AAAAAAAAAAA=' },
  locks: {},
  policy: { autoLockMinutes: 10, diskLock: true },
})
check('旧版顶层 password 字段读入后被丢弃', !('password' in migrated), JSON.stringify(migrated))
check('旧版状态读出后版本变成 2', migrated.version === 2)

console.log('\n[2] 磁盘锁：加密 / 读头 / 正文 / 解锁')
res = await call('lock', { sessionId: id, title: '自检会话', disk: true, password: 'correct horse' })
check('上锁成功并加密磁盘', res.ok === true && res.disk?.encrypted === true, JSON.stringify(res.disk))
persisted = JSON.parse(readFileSync(stateFile, 'utf8'))
check('state.json 只存这条锁的 scrypt 派生值', Boolean(persisted.locks[id]?.password?.hash && persisted.locks[id]?.password?.salt))
check('state.json 里没有明文口令', !readFileSync(stateFile, 'utf8').includes('correct horse'))
check('state.json 仍没有全局 password 字段', !('password' in persisted))
check('文件变成 WALLBK 密文', readFileSync(logFile).subarray(0, 8).toString('hex') === '57414c4c424b0100')
check('密文比明文长（头部 + tag）', readFileSync(logFile).length > originalBytes.length)
check('写了明文 .header 旁路', existsSync(`${logFile}.header`))
check('.header 就是会话第一行', readFileSync(`${logFile}.header`, 'utf8') === originalHeader)
check('锁定时 list 仍能读到会话头', (await backendProto.readFirstZstdLine.call(backend, logFile)) === originalHeader)
const lockedRead = await backendProto.decodeStoredLog.call(backend, logFile, id, readFileSync(logFile))
  .then(() => 'readable', (error) => error.code || error.message)
check('锁定时 decodeStoredLog 拒绝读正文', lockedRead === 'SESSION_LOCKED', String(lockedRead))
status = await call('status')
check('status 记录磁盘锁', status.locks.length === 1 && status.locks[0].disk === true)
check('上锁后没有临时授权', !status.grants.sessions.includes(id))
check('status 不返回口令记录 / 盐', !('password' in status.locks[0]) && !JSON.stringify(status).includes(persisted.locks[id].password.salt))
check('错口令 401', (await call('verify', { password: 'wrong', sessionId: id })).status === 401)
res = await call('verify', { password: 'correct horse', sessionId: id })
check('对口令放行', res.ok === true && res.grants.sessions.includes(id))
check('解锁后正文可读', (await backendProto.decodeStoredLog.call(backend, logFile, id, readFileSync(logFile))).text === originalText)
res = await call('unlock-session', { password: 'correct horse', sessionId: id })
check('永久解除成功', res.ok === true && res.locks.length === 0)
check('磁盘解回明文', readFileSync(logFile).equals(originalBytes))
check('.header 已清理', !existsSync(`${logFile}.header`))
check('解除后 state.json 里没有这条锁', !JSON.parse(readFileSync(stateFile, 'utf8')).locks[id])

console.log('\n[3] 解锁状态追加：写回必须仍是密文')
const id2 = 'session-22222222-3333-4444-5555-666666666666'
const cwd2 = 'E:\\SelfTest2'
const dir2 = join(sessions, '--E-SelfTest2--', id2)
mkdirSync(dir2, { recursive: true })
const file2 = join(dir2, 'session.v4.jsonl.zstd')
const fixture2 = makeSessionFile(file2, id2, cwd2)
res = await call('lock', { sessionId: id2, title: '追加测试', disk: true, password: 'correct horse' })
check('第二条上锁并加密', res.ok === true && res.disk?.encrypted === true)
await call('verify', { password: 'correct horse', sessionId: id2 })
const beforeAppend = readFileSync(file2)
await backendProto.appendLines.call(backend, { id: id2, cwd: cwd2 }, [{ type: 'probe' }])
const afterAppend = readFileSync(file2)
check('追加后磁盘仍是 WALLBK 密文', afterAppend.subarray(0, 8).toString('hex') === '57414c4c424b0100')
check('追加确实改了文件', !afterAppend.equals(beforeAppend))
check('追加后正文 = 原文 + 新事件',
  (await backendProto.decodeStoredLog.call(backend, file2, id2, afterAppend)).text === fixture2.text + PROBE_FRAME.toString())
await call('relock', {})
const writeAttempt = await backendProto.open.call(backend, id2, 'write').then(() => 'opened', (e) => e.code || e.message)
check('锁定后 write 打开被拒绝', writeAttempt === 'SESSION_LOCKED', String(writeAttempt))
res = await call('unlock-session', { password: 'correct horse', sessionId: id2 })
check('追加测试会话可永久解除', res.ok === true && res.restored?.restored === true)

console.log('\n[4] 界面锁 / 策略 / 改口令 / 清除')
res = await call('lock', { sessionId: id, title: '只锁界面', disk: false, password: 'correct horse' })
check('只锁界面成功', res.ok === true && res.locks[0].disk === false)
check('文件仍是明文', readFileSync(logFile).equals(originalBytes))
res = await call('policy', { autoLockMinutes: 0, diskLock: false })
check('策略保存成功（不需要口令）', res.ok === true && res.policy.autoLockMinutes === 0 && res.policy.diskLock === false)
res = await call('password', { sessionId: id, currentPassword: 'correct horse', newPassword: 'next password' })
check('界面锁状态下可以改这条会话的口令', res.ok === true)
check('改口令成功后 state.json 里没有 passwordPrevious',
  !('passwordPrevious' in JSON.parse(readFileSync(stateFile, 'utf8')).locks[id]))
check('旧口令不再可用', (await call('verify', { password: 'correct horse', sessionId: id })).status === 401)
check('新口令可以解锁', (await call('verify', { password: 'next password', sessionId: id })).ok === true)
res = await call('clear', {})
check('清除全部锁（不需要口令）', res.ok === true && res.locks.length === 0)
check('清除后 state.json 仍没有全局 password 字段', !('password' in JSON.parse(readFileSync(stateFile, 'utf8'))))
check('清除后 state.json 没有 plain 口令', !readFileSync(stateFile, 'utf8').includes('next password'))


console.log('\n[4b] 口令记录里存的校验值不是 AES 密钥')

{
  const rec = secretMod.makePasswordRecord('domain-test-123')
  const salt = Buffer.from(rec.salt, 'base64')
  const hashBuf = Buffer.from(rec.hash, 'base64')
  const key = secretMod.deriveDiskKey(rec, 'domain-test-123')
  check('verifyPassword 认对的口令', secretMod.verifyPassword(rec, 'domain-test-123') === true)
  check('verifyPassword 拒错的口令', secretMod.verifyPassword(rec, 'nope') === false)
  check('hash 的前 32 字节不是 AES 钥匙', !hashBuf.subarray(0, 32).equals(key))
  check('scrypt(pw,salt,32) 不是 AES 钥匙（没加 KEY_DOMAIN）',
    !scryptSync('domain-test-123', salt, 32, { N: rec.n, r: rec.r, p: rec.p, maxmem: 512 * 1024 * 1024 }).equals(key))
  check('scrypt(pw,salt,64)[0..32) 也不是 AES 钥匙',
    !scryptSync('domain-test-123', salt, 64, { N: rec.n, r: rec.r, p: rec.p, maxmem: 512 * 1024 * 1024 }).subarray(0, 32).equals(key))
}


console.log('\n[5] WALLBK 容器')
const plain = Buffer.from('hello 会话 内容'.repeat(500), 'utf8')
const sealed = mod.encryptBuffer(plain, 'pw-123456')
check('magic 正确', sealed.subarray(0, 8).toString('hex') === '57414c4c424b0100')
check('口令往返', mod.decryptBuffer(sealed, 'pw-123456').equals(plain))
check('错口令失败', (() => { try { mod.decryptBuffer(sealed, 'nope'); return false } catch { return true } })())
const tampered = Buffer.from(sealed)
tampered[tampered.length - 20] ^= 0xff
check('篡改被 GCM 拒绝', (() => { try { mod.decryptBuffer(tampered, 'pw-123456'); return false } catch { return true } })())

console.log('\n[6] 上一版遗留密文：补登 + 用文件自己的口令救回')
// cordis 卸载时按注册的**逆序**跑 disposer，这里照做，否则会留下半截补丁。
for (const dispose of [...effects].reverse()) { try { if (typeof dispose === 'function') await dispose() } catch { /* ignore */ } }
writeFileSync(logFile, mod.encryptBuffer(originalBytes, 'old secret'))
writeFileSync(`${logFile}.header`, originalHeader, 'utf8')

const routes2 = new Map()
const second = makeCtx(routes2)
mod.apply(second.ctx, { dest: join(home, 'backup'), keep: 5, diskLock: true })
const route2 = routes2.get('/api/session.vault')
const call2 = async (action, body) => {
  const init = body === undefined
    ? { method: 'GET', headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
  const res = await route2.fetch(new Request(`http://dsh.internal/api/session.vault?action=${action}`, init))
  return { status: res.status, ...(await res.json()) }
}
status = await call2('status')
check('遗留密文被补登成磁盘锁',
  status.locks.length === 1 && status.locks[0].disk === true && status.locks[0].orphan === true,
  JSON.stringify(status.locks))
check('orphan 标记写进 state.json', JSON.parse(readFileSync(stateFile, 'utf8')).locks[id]?.orphan === true)
res = await call2('verify', { password: 'new password', sessionId: id })
check('新口令开不了老文件（401 且说清楚）', res.status === 401 && /老版本/.test(res.error || ''), JSON.stringify(res))
res = await call2('verify', { password: 'old secret', sessionId: id })
check('文件自己的口令可以解锁', res.ok === true)
check('解锁后正文可读',
  (await backendProto.decodeStoredLog.call(backend, logFile, id, readFileSync(logFile))).text === originalText)
res = await call2('unlock-session', { password: 'old secret', sessionId: id })
check('可以永久解回明文', res.ok === true && readFileSync(logFile).equals(originalBytes), JSON.stringify(res))
check('.header 已清理', !existsSync(`${logFile}.header`))

for (const dispose of [...second.effects].reverse()) { try { if (typeof dispose === 'function') await dispose() } catch { /* ignore */ } }

console.log('\n[7] 每条会话独立口令')
const routes3 = new Map()
const third = makeCtx(routes3)
mod.apply(third.ctx, { dest: join(home, 'backup'), keep: 5, diskLock: true })
const route3 = routes3.get('/api/session.vault')
const call3 = async (action, body) => {
  const init = body === undefined
    ? { method: 'GET', headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
  const res = await route3.fetch(new Request(`http://dsh.internal/api/session.vault?action=${action}`, init))
  return { status: res.status, ...(await res.json()) }
}

/** 造一条独立的新会话（文件 + 目录）。 */
function newSession(tag) {
  const sid = `session-${tag}`
  const sdir = join(sessions, `--E-${tag}--`, sid)
  mkdirSync(sdir, { recursive: true })
  const file = join(sdir, 'session.v4.jsonl.zstd')
  const fixture = makeSessionFile(file, sid, `E:\\${tag}`)
  return { sid, file, fixture, bytes: readFileSync(file) }
}
const A = newSession('aaaaaaaa-0000-0000-0000-000000000001')
const B = newSession('bbbbbbbb-0000-0000-0000-000000000002')
const N = newSession('eeeeeeee-0000-0000-0000-000000000005')

// 1) 给 A / B 各设一条独立口令（带 password 的 lock）。
res = await call3('lock', { sessionId: A.sid, title: '会话 A', disk: true, password: 'aaaaaa' })
check('A 用自己的口令上锁并加密', res.ok === true && res.disk?.encrypted === true, JSON.stringify(res.disk))
const rowA0 = res.locks.find((r) => r.sessionId === A.sid)
check('A 的锁没有 legacy 字段', Boolean(rowA0) && !('legacy' in rowA0))
res = await call3('lock', { sessionId: B.sid, title: '会话 B', disk: true, password: 'bbbbbb' })
check('B 用自己的口令上锁并加密', res.ok === true && res.disk?.encrypted === true)
check('B 的锁没有 legacy 字段', !('legacy' in res.locks.find((r) => r.sessionId === B.sid)))
check('响应里没有 password 记录', !JSON.stringify(res).includes('"password"'), JSON.stringify(res).slice(0, 120))

// 2) 用 B 的口令验 A → 失败；3) 用 A 的口令验 A → 成功。
check('用 bbbbbb 验 A 被拒', (await call3('verify', { password: 'bbbbbb', sessionId: A.sid })).status === 401)
res = await call3('verify', { password: 'aaaaaa', sessionId: A.sid })
check('用 aaaaaa 验 A 成功', res.ok === true && res.grants.sessions.includes(A.sid))
check('A 解出的正文正确',
  (await backendProto.decodeStoredLog.call(backend, A.file, A.sid, readFileSync(A.file))).text === A.fixture.text)
check('A 的密文用 B 的口令开不了', (function () {
  try { mod.decryptBuffer(readFileSync(A.file), 'bbbbbb'); return false } catch { return true }
})())

// 4) state.json 里 A / B 各有独立盐与派生值。
let st = JSON.parse(readFileSync(stateFile, 'utf8'))
check('state.json 版本是 2', st.version === 2, String(st.version))
check('state.json 没有全局 password 字段', !('password' in st))
check('A / B 都写了自己的 scrypt 记录',
  Boolean(st.locks[A.sid]?.password?.hash && st.locks[A.sid]?.password?.salt) &&
  Boolean(st.locks[B.sid]?.password?.hash && st.locks[B.sid]?.password?.salt))
check('A / B 的盐不同', st.locks[A.sid].password.salt !== st.locks[B.sid].password.salt)
check('A / B 的派生值不同', st.locks[A.sid].password.hash !== st.locks[B.sid].password.hash)
check('state.json 不落明文口令', !JSON.stringify(st).includes('"aaaaaa"') && !JSON.stringify(st).includes('"bbbbbb"'))
check('A / B 锁记录里没有 legacy 字段', !('legacy' in st.locks[A.sid]) && !('legacy' in st.locks[B.sid]))

// 5) status 的 locks[] 绝不出 password / salt / hash / legacy。
status = await call3('status')
const sRowA = status.locks.find((r) => r.sessionId === A.sid)
check('status 的每个 lock 都不带 password / legacy',
  status.locks.length === 2 && status.locks.every((r) => !('password' in r) && !('legacy' in r)), JSON.stringify(status.locks))
check('status 响应里没有盐 / 派生值', !JSON.stringify(status).includes(st.locks[A.sid].password.salt))
check('status 响应里没有口令记录', !JSON.stringify(status).includes('"password"'))

// 独立口令会话改口令也要验旧口令，并且不能影响别的会话。
res = await call3('password', { sessionId: A.sid, currentPassword: 'bbbbbb', newPassword: 'aaaaaa2' })
check('改独立口令要验旧口令', res.status === 401)
res = await call3('password', { sessionId: A.sid, currentPassword: 'aaaaaa', newPassword: 'aaaaaa2' })
check('独立口令可以改成新的', res.ok === true)
check('磁盘锁改口令成功后 state.json 里没有 passwordPrevious',
  !('passwordPrevious' in JSON.parse(readFileSync(stateFile, 'utf8')).locks[A.sid]))
check('旧口令不再可用', (await call3('verify', { password: 'aaaaaa', sessionId: A.sid })).status === 401)
check('新口令可以解锁', (await call3('verify', { password: 'aaaaaa2', sessionId: A.sid })).ok === true)
check('改 A 的口令不影响 B',
  (await call3('verify', { password: 'bbbbbb', sessionId: B.sid })).ok === true)
  check('改口令后 A 的磁盘文件仍可读',
    (await backendProto.decodeStoredLog.call(backend, A.file, A.sid, readFileSync(A.file))).text === A.fixture.text)
  check('改口令后 A 的磁盘文件仍是 WALLBK 密文（换钥匙不走明文落盘）',
    readFileSync(A.file).subarray(0, 8).toString('hex') === '57414c4c424b0100')
  check('改口令后 A 的明文一次都没出现在磁盘上',
    !readFileSync(A.file).includes(Buffer.from(A.fixture.text.slice(0, 24))))

// 给重启测试准备一条独立口令 + 磁盘锁的会话。
res = await call3('lock', { sessionId: N.sid, title: '重启测试', disk: true, password: 'nnnnnn' })
check('N 用自己的口令上锁并加密', res.ok === true && res.disk?.encrypted === true)
res = await call3('verify', { password: 'nnnnnn', sessionId: N.sid })
check('N 的口令可以解锁', res.ok === true && res.grants.sessions.includes(N.sid))
check('N 的正文可读',
  (await backendProto.decodeStoredLog.call(backend, N.file, N.sid, readFileSync(N.file))).text === N.fixture.text)

for (const dispose of [...third.effects].reverse()) { try { if (typeof dispose === 'function') await dispose() } catch { /* ignore */ } }

// 8) 「重启」：换一个实例重新读 state.json，独立口令与磁盘锁必须还能用。
const routes4 = new Map()
const fourth = makeCtx(routes4)
mod.apply(fourth.ctx, { dest: join(home, 'backup'), keep: 5, diskLock: true })
const route4 = routes4.get('/api/session.vault')
const call4 = async (action, body) => {
  const init = body === undefined
    ? { method: 'GET', headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
  const res = await route4.fetch(new Request(`http://dsh.internal/api/session.vault?action=${action}`, init))
  return { status: res.status, ...(await res.json()) }
}
status = await call4('status')
const sN = status.locks.find((r) => r.sessionId === N.sid)
check('重启后独立口令锁仍是 disk=true 且没有 legacy 字段',
  Boolean(sN) && sN.disk === true && !('legacy' in sN) && !('password' in sN), JSON.stringify(sN))
check('重启后 status 仍不返回口令', !JSON.stringify(status).includes('"password"'))
check('重启后 state.json 仍没有全局 password 字段', !('password' in JSON.parse(readFileSync(stateFile, 'utf8'))))
res = await call4('verify', { password: 'nnnnnn', sessionId: N.sid })
check('重启后独立口令可解锁', res.ok === true && res.grants.sessions.includes(N.sid))
check('重启后正文可读',
  (await backendProto.decodeStoredLog.call(backend, N.file, N.sid, readFileSync(N.file))).text === N.fixture.text)
check('重启后别的口令开不了独立口令会话',
  (await call4('verify', { password: 'aaaaaa2', sessionId: N.sid })).status === 401)
res = await call4('unlock-session', { password: 'nnnnnn', sessionId: N.sid })
check('重启后仍可永久解除并解回明文', res.ok === true && readFileSync(N.file).equals(N.bytes))

for (const dispose of [...fourth.effects].reverse()) { try { if (typeof dispose === 'function') await dispose() } catch { /* ignore */ } }

console.log('\n[8] 改口令崩溃窗口：passwordPrevious')
/*
 * 路由层直接注入一个可控的假磁盘锁：keyOpens 只认当前 openKey，rekey 可以按需抛错。
 * 这样才能精确模拟「换钥匙成功但清理 previous 失败」和「rekey 抛错」两个窗口。
 */
const rd = join(home, 'route-state')
mkdirSync(rd, { recursive: true })
const crashId = 'session-crash-window-0000'

/** 建一个只测路由的 handler：状态真写 state.json，磁盘锁是假的。 */
function makeRouteHarness(initial, diskFace, hooks = {}) {
  let current = stateMod.normalizeState(initial)
  stateMod.saveState(rd, current)
  const grants = new secretMod.Grants()
  const handler = routesMod.makeHandler({
    getState: () => current,
    setState: (next) => {
      if (typeof hooks.beforeSetState === 'function') hooks.beforeSetState(next)
      current = stateMod.normalizeState(next)
      stateMod.saveState(rd, current)
    },
    grants,
    disk: diskFace,
    keys: { set() {}, clear() {}, clearAll() {} },
    log: () => {},
    version: 'selftest',
    onChanged: () => {},
  })
  const call = async (action, body) => {
    const res = await handler(new Request(`http://dsh.internal/api/session.vault?action=${action}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }))
    return { status: res.status, ...(await res.json()) }
  }
  const persisted = () => JSON.parse(readFileSync(join(rd, 'state.json'), 'utf8'))
  return { call, grants, persisted }
}

/** 假磁盘锁：只认当前 openKey；failRekey=true 时 rekey 必抛。 */
function fakeDisk(openKey, options = {}) {
  return {
    available: true,
    openKey,
    failRekey: options.failRekey === true,
    keyOpens(_id, key) { return Boolean(key) && key.equals(this.openKey) },
    async rekey(_id, oldKey, newKey) {
      if (this.failRekey) throw new Error('模拟换钥匙失败')
      if (!oldKey || !oldKey.equals(this.openKey)) throw new Error('旧钥匙打不开当前文件')
      this.openKey = newKey
      return { rekeyed: true, bytes: 1 }
    },
    async unlock() { return { restored: true } },
  }
}

const recOld = secretMod.makePasswordRecord('old password')
const recNew = secretMod.makePasswordRecord('new password')
const keyOf = (rec, password) => secretMod.deriveDiskKey(rec, password)

const lockRow = (extra) => ({
  title: '',
  lockedAt: Date.now(),
  disk: extra.disk === true,
  ...extra,
})
const baseState = (row) => ({ ...stateMod.emptyState(), locks: { [crashId]: row } })

// 2a) 不涉及磁盘：两条记录分别用各自的密码都能解锁（最直接的「新旧都能开」）。
{
  const h = makeRouteHarness(baseState(lockRow({ disk: false, password: recNew, passwordPrevious: recOld })), fakeDisk(null))
  const s = await h.call('status')
  check('status 只暴露 hasPrevious，不带任何记录字段',
    s.locks[0].hasPrevious === true &&
    !('password' in s.locks[0]) && !('passwordPrevious' in s.locks[0]) &&
    !JSON.stringify(s).includes(recOld.salt),
    JSON.stringify(s.locks[0]))
  check('界面锁状态：旧口令（previous）可解锁',
    (await h.call('verify', { password: 'old password', sessionId: crashId })).ok === true)
  check('界面锁状态：新口令（current）可解锁',
    (await h.call('verify', { password: 'new password', sessionId: crashId })).ok === true)
  check('界面锁状态：错口令仍 401',
    (await h.call('verify', { password: 'neither password', sessionId: crashId })).status === 401)
}

// 2b) 「换钥匙前崩溃」：state 是新记录，文件还是旧钥匙 → 旧口令能开，新口令不能假解锁。
{
  const oldKey = keyOf(recOld, 'old password')
  const disk = fakeDisk(oldKey)
  const h = makeRouteHarness(baseState(lockRow({ disk: true, password: recNew, passwordPrevious: recOld })), disk)
  check('窗口①（文件仍是旧钥匙）：旧口令可解锁',
    (await h.call('verify', { password: 'old password', sessionId: crashId })).ok === true)
  const r = await h.call('verify', { password: 'new password', sessionId: crashId })
  check('窗口①：新口令不会「假解锁」（409 且提示换口令）',
    r.status === 409 && /换用另一个口令/.test(r.error || ''), JSON.stringify(r))
  const r2 = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'newest password' })
  check('窗口①：仍可用旧口令再改口令并收敛', r2.ok === true, JSON.stringify(r2))
  const saved = h.persisted().locks[crashId]
  check('窗口①：改完 state.json 里没有 passwordPrevious', Boolean(saved) && !('passwordPrevious' in saved))
  check('窗口①：文件钥匙已换成新记录的钥匙',
    disk.openKey.equals(keyOf(saved.password, 'newest password')))
}

// 2c) 「换钥匙成功但清理 previous 失败」：文件是新钥匙 → 新口令能开，旧口令不能假解锁。
{
  const newKey = keyOf(recNew, 'new password')
  const disk = fakeDisk(newKey)
  const h = makeRouteHarness(baseState(lockRow({ disk: true, password: recNew, passwordPrevious: recOld })), disk)
  check('窗口②（文件已是新钥匙）：新口令可解锁',
    (await h.call('verify', { password: 'new password', sessionId: crashId })).ok === true)
  const r = await h.call('verify', { password: 'old password', sessionId: crashId })
  check('窗口②：旧口令不会「假解锁」（409 且提示换口令）',
    r.status === 409 && /换用另一个口令/.test(r.error || ''), JSON.stringify(r))
  check('窗口②：旧口令不能永久解除',
    (await h.call('unlock-session', { password: 'old password', sessionId: crashId })).status === 409)
  check('窗口②：新口令可以永久解除',
    (await h.call('unlock-session', { password: 'new password', sessionId: crashId })).ok === true)
  check('窗口②：解除后 state.json 里没有这条锁', !h.persisted().locks[crashId])
}

// 2d) 新旧两条记录碰巧是同一个口令：第一条钥匙打不开时，必须继续试第二条。
{
  const recA = secretMod.makePasswordRecord('same password')
  const recB = secretMod.makePasswordRecord('same password')
  const disk = fakeDisk(keyOf(recA, 'same password'))
  const h = makeRouteHarness(baseState(lockRow({ disk: true, password: recB, passwordPrevious: recA })), disk)
  check('同一口令的两条记录：仍能解锁（逐条试到能开的那条）',
    (await h.call('verify', { password: 'same password', sessionId: crashId })).ok === true)
}

// 2e) 路由真实走到「换钥匙成功、清理 previous 写盘失败」：不崩、不锁死。
{
  const oldKey = keyOf(recOld, 'old password')
  const disk = fakeDisk(oldKey)
  let writes = 0
  const h = makeRouteHarness(
    baseState(lockRow({ disk: true, password: recOld })),
    disk,
    { beforeSetState() { writes += 1; if (writes === 2) throw new Error('模拟清理 previous 写盘失败') } },
  )
  const r = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'new password' })
  check('清理 previous 写盘失败不影响改口令成功', r.ok === true, JSON.stringify(r))
  const saved = h.persisted().locks[crashId]
  check('清理失败后 state.json 仍留着 passwordPrevious', Boolean(saved?.passwordPrevious?.hash))
  check('清理失败后新口令可解锁（文件已是新钥匙）',
    (await h.call('verify', { password: 'new password', sessionId: crashId })).ok === true)
  /*
   * 清理写盘失败时，本进程内存已经按「清理成功」处理（文件确实是新钥匙）；
   * 磁盘上仍留着 previous。模拟重启后再验：新口令能开，旧口令不会假解锁。
   */
  const restarted = makeRouteHarness(h.persisted(), disk)
  check('清理失败后重启：新口令仍可解锁',
    (await restarted.call('verify', { password: 'new password', sessionId: crashId })).ok === true)
  check('清理失败后重启：旧口令不会假解锁',
    (await restarted.call('verify', { password: 'old password', sessionId: crashId })).status === 409)
}

// 2f) 第一步写 state 就失败：rekey 绝不能发生，旧文件必须原样可开。
{
  const oldKey = keyOf(recOld, 'old password')
  const disk = fakeDisk(oldKey)
  const h = makeRouteHarness(
    baseState(lockRow({ disk: true, password: recOld })),
    disk,
    { beforeSetState() { throw new Error('模拟状态写盘失败') } },
  )
  const r = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'new password' })
  check('第一步写 state 失败 → 500', r.status === 500, JSON.stringify(r))
  check('第一步失败后 rekey 没有被调用（文件钥匙没变）', disk.openKey.equals(oldKey))
  check('第一步失败后旧口令仍可解锁',
    (await h.call('verify', { password: 'old password', sessionId: crashId })).ok === true)
}

// 3) rekey 抛错：state.json 必须保留 passwordPrevious，旧口令仍然能解锁。
{
  const oldKey = keyOf(recOld, 'old password')
  const disk = fakeDisk(oldKey, { failRekey: true })
  const h = makeRouteHarness(baseState(lockRow({ disk: true, password: recOld })), disk)
  const r = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'new password' })
  check('rekey 抛错 → 500 且说明旧口令可用', r.status === 500 && /旧口令仍然可用/.test(r.error || ''), JSON.stringify(r))
  const saved = h.persisted().locks[crashId]
  check('rekey 抛错后 state.json 里仍有 passwordPrevious', Boolean(saved?.passwordPrevious?.hash))
  check('rekey 抛错后文件钥匙没变（仍是旧钥匙）', disk.openKey.equals(oldKey))
  check('rekey 抛错后旧口令仍可解锁',
    (await h.call('verify', { password: 'old password', sessionId: crashId })).ok === true)
  check('rekey 抛错后新口令不会假解锁',
    (await h.call('verify', { password: 'new password', sessionId: crashId })).status === 409)
  disk.failRekey = false
  const r2 = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'newest password' })
  check('失败之后下一次改口令可以收敛（previous 被清掉）',
    r2.ok === true && !('passwordPrevious' in h.persisted().locks[crashId]))
}

// 3b) 磁盘锁后端不可用：换不了钥匙，必须保留 previous，否则后端恢复后旧密文打不开。
{
  const unavailable = { available: false, keyOpens() { return false }, async rekey() { throw new Error('不应被调用') } }
  const h = makeRouteHarness(baseState(lockRow({ disk: true, password: recOld })), unavailable)
  const r = await h.call('password', { sessionId: crashId, currentPassword: 'old password', newPassword: 'new password' })
  check('磁盘锁不可用时改口令仍成功（只改记录）', r.ok === true, JSON.stringify(r))
  check('磁盘锁不可用时保留 passwordPrevious（避免丢失旧钥匙）',
    Boolean(h.persisted().locks[crashId]?.passwordPrevious?.hash))
  check('磁盘锁不可用时旧口令仍可验证',
    (await h.call('verify', { password: 'old password', sessionId: crashId })).ok === true)
  check('磁盘锁不可用时新口令也可验证（没有磁盘可核对）',
    (await h.call('verify', { password: 'new password', sessionId: crashId })).ok === true)
}

// 坏记录降级：passwordPrevious 坏了只丢它，不能让整份 state 加载失败。
{
  const degraded = stateMod.normalizeState({
    version: 2,
    locks: { [crashId]: { title: '', lockedAt: Date.now(), disk: false, password: recOld, passwordPrevious: { salt: '', hash: '' } } },
  })
  check('坏 passwordPrevious 被丢弃，主记录照常加载',
    Boolean(degraded.locks[crashId]?.password?.hash) && !('passwordPrevious' in degraded.locks[crashId]))
}

console.log('\n[9] 残留 *.vault-tmp 清理')
const sweepRoot = join(home, 'sweep-sessions')
const sweepDir = join(sweepRoot, '--proj--', 'session-sweep')
mkdirSync(sweepDir, { recursive: true })
const sweepTmp = join(sweepDir, 'session.v4.jsonl.zstd.deadbeef.vault-tmp')
const sweepNormal = join(sweepDir, 'session.v4.jsonl.zstd')
const outsideTmp = join(home, 'sweep-outside.vault-tmp')
writeFileSync(sweepTmp, 'half-written')
writeFileSync(sweepNormal, 'normal session file')
writeFileSync(outsideTmp, 'outside')
const swept = diskMod.sweepTempFiles(sweepRoot)
check('sweepTempFiles 删掉 *.vault-tmp', swept === 1 && !existsSync(sweepTmp), `removed=${swept}`)
check('sweepTempFiles 不删正常 session.v4.jsonl.zstd', existsSync(sweepNormal))
check('sweepTempFiles 不碰会话根目录之外的 tmp', existsSync(outsideTmp))

// 启动清理接进 apply()：数量写进 _diagnostics.json，也写一行日志。
const strayTmp = join(dir2, 'stray.deadbeef.vault-tmp')
writeFileSync(strayTmp, 'stray')
const routes5 = new Map()
const fifth = makeCtx(routes5)
mod.apply(fifth.ctx, { dest: join(home, 'backup'), keep: 5, diskLock: true })
const diag = JSON.parse(readFileSync(join(home, 'session-vault', '_diagnostics.json'), 'utf8'))
check('apply() 启动清理：tmp 已删且数量写进 _diagnostics.json',
  diag.disk?.sweptTempFiles >= 1 && !existsSync(strayTmp), JSON.stringify(diag.disk))
const logText = readFileSync(join(home, 'session-vault', 'session-vault.log'), 'utf8')
check('apply() 启动清理写进日志行',
  /启动清理：删除 [1-9]\d* 个残留 \*\.vault-tmp 文件/.test(logText))
for (const dispose of [...fifth.effects].reverse()) { try { if (typeof dispose === 'function') await dispose() } catch { /* ignore */ } }

rmSync(home, { recursive: true, force: true })
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
