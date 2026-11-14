/**
 * session-vault —— 会话锁（界面锁 + 磁盘锁）+ 会话加密导出。
 * ============================================================================
 * 方向说明（这是这一版最重要的东西）
 * ============================================================================
 * 「给会话加密」不等于「把会话文件换成密文」。DSH 启动要读会话文件才能列出
 * 侧边栏，文件读不出来 = 会话从列表里消失 = 用户把自己锁在门外。
 *
 * 所以这里有两件事，各自独立：
 *
 *  A. **界面锁（会话锁）**：侧栏给会话上锁，打开时正文模糊 + 弹口令框。
 *     会话记录本身照常可读 —— 它必须在，否则列表就没了。口令只存 scrypt 派生值，
 *     「已解锁」只活在内存里，进程重启即失效，空闲超时自动重新上锁。
 *
 *  B. **磁盘锁（真加密）**：把会话日志文件换成 `WALLBK` 密文，并 patch
 *     `session-persistence-jsonl` 后端的方法，让 DSH 自己在内存里透明解密。
 *     patch 后端而不是 `node:fs`，是因为后端用 `import { open } from 'node:fs/promises'`
 *     拿到的是 CJS 导出的**快照**，改 fs 对后端不可见；而类的方法每次走原型查找。
 *     锁定时 `list()` 靠同目录的 `.header` 明文旁路拿到会话头，所以会话始终在侧边栏。
 *
 *  C. **加密导出**：`session_vault_encrypt` 工具把当前会话打成 `.enc`（同样的
 *     WALLBK 容器，和 wall/tools/backup_crypt.py 互通），这是备份，不是锁。
 *
 * ---------------------------------------------------------------------------
 * WALLBK 容器格式（导出备份与磁盘锁共用，Python 侧能解）
 * ---------------------------------------------------------------------------
 *     magic   8 字节   "WALLBK" 0x01 0x00
 *     version 1 字节   0x01
 *     n       4 字节   big-endian（scrypt N，默认 131072）
 *     r       4 字节   big-endian（默认 8）
 *     p       4 字节   big-endian（默认 1）
 *     salt   16 字节
 *     nonce  12 字节
 *     密文    AES-256-GCM 正文 + 16 字节 tag
 *
 * 附加认证数据（AAD）是 `magic || version`。用 GCM 而不是 CBC：文件被篡改会
 * 解密失败，不会产出看起来正常实则损坏的内容。
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import {
  closeSync,
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import { createDiskLock, sweepTempFiles } from './lib/disk.mjs'
import { makeHandler } from './lib/routes.mjs'
import { Grants, MIN_PASSWORD_LENGTH, forgetAllDiskKeys } from './lib/secret.mjs'
import { DEFAULT_POLICY, STATE_VERSION, loadState, normalizeState, saveState, stateDir } from './lib/state.mjs'
import { clearKey as backendClearKey, keyIds as backendKeyIds, patchBackend, setKey as backendSetKey } from './backend-patch.js'
import { SCRYPT, scryptKeyOptions } from './lib/scrypt.mjs'

/** 插件版本（客户端设置区会显示）。 */
const VERSION = '2.0.0'

const MAGIC = Buffer.from([0x57, 0x41, 0x4c, 0x4c, 0x42, 0x4b, 0x01, 0x00]) // "WALLBK\1\0"
const VERSION_BYTE = 1
const SCRYPT_N = SCRYPT.N
const SCRYPT_R = SCRYPT.r
const SCRYPT_P = SCRYPT.p
const SALT_LEN = 16
const NONCE_LEN = 12
/** magic + version + N/r/p + salt + nonce */
const HEADER_LEN = MAGIC.length + 1 + 12 + SALT_LEN + NONCE_LEN
const TAG_LEN = 16

/**
 * output 必须同时给 schema 和 render。
 *
 * dsh-tools 的 defineTool 内部会执行 valueSchemaSpecToJsonSchema(options.output.schema)，
 * 只给 render 会让 schema 是 undefined，激活时报
 * `unsupported JSON schema: schema must be a value schema object`。
 */
const TEXT_OUTPUT = {
  schema: { type: 'string' },
  render: (_args, value) => [{ type: 'text', text: String(value) }],
}

// ============================================================================
// 会话文件定位
// ============================================================================

/** 会话根目录。DSH 把每个项目放在 `--<cwd 转义>--` 下。 */
let sessionsRootOverride = null
function sessionsRoot() {
  return sessionsRootOverride
    ?? path.join(process.env.DSH_HOME || path.join(homedir(), '.dsh'), 'sessions')
}

/** 把工作目录转成 DSH 的项目目录名，例如 E:\Download -> --E-Download--（与 DSH 的 projectKey 一致）。 */
function projectDirName(cwd) {
  let readable = ''
  let separatorRun = false
  for (const ch of String(cwd)) {
    const code = ch.charCodeAt(0)
    if (ch === '/' || ch === '\\' || ch === ':') {
      if (!separatorRun) readable += '-'
      separatorRun = true
      continue
    }
    separatorRun = false
    if (ch !== '~' && /^[A-Za-z0-9._-]$/.test(ch)) readable += ch
    else readable += '~' + code.toString(16).toUpperCase().padStart(4, '0')
  }
  const trimmed = readable.replace(/^-+/, '') || 'root'
  return '--' + trimmed.slice(0, 251) + '--'
}

/** 目录里最新的会话文件（session.vN.jsonl.zstd）。 */
function newestFile(dir) {
  let best = null
  let bestTime = -Infinity
  let names
  try {
    names = readdirSync(dir)
  } catch {
    return null
  }
  for (const name of names) {
    if (!name.startsWith('session.') || !name.endsWith('.zstd')) continue
    const p = path.join(dir, name)
    try {
      const st = statSync(p)
      if (st.mtimeMs > bestTime) {
        bestTime = st.mtimeMs
        best = p
      }
    } catch { /* ignore */ }
  }
  return best
}

/** 在某个项目目录下按 id 前缀找会话目录。 */
function findSessionDir(sessionId) {
  const root = sessionsRoot()
  if (!existsSync(root)) return null
  const id = String(sessionId || '')
  let projects
  try {
    projects = readdirSync(root)
  } catch {
    return null
  }
  for (const project of projects) {
    const pdir = path.join(root, project)
    let entries
    try {
      entries = readdirSync(pdir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (!name.startsWith('session-')) continue
      if (id && !name.includes(id)) continue
      const dir = path.join(pdir, name)
      try {
        if (statSync(dir).isDirectory() && newestFile(dir)) return dir
      } catch { /* ignore */ }
    }
  }
  return null
}

/** 按 sessionId / cwd 定位要备份的会话文件。 */
function resolveSessionFile(sessionId, cwd) {
  if (sessionId) {
    const dir = findSessionDir(sessionId)
    if (dir) {
      const f = newestFile(dir)
      if (f) return f
    }
  }
  if (cwd) {
    const pdir = path.join(sessionsRoot(), projectDirName(cwd))
    if (existsSync(pdir)) {
      let newestDir = null
      let newestTime = -Infinity
      let names
      try {
        names = readdirSync(pdir)
      } catch {
        return null
      }
      for (const name of names) {
        const dir = path.join(pdir, name)
        const f = newestFile(dir)
        if (!f) continue
        const t = statSync(f).mtimeMs
        if (t > newestTime) {
          newestTime = t
          newestDir = dir
        }
      }
      if (newestDir) return newestFile(newestDir)
    }
  }
  return null
}

/** 找到会话目录（不要求里面有明文文件）。 */
function findSessionDirAny(sessionId) {
  const base = findSessionDir(sessionId)
  if (base) return base
  const root = sessionsRoot()
  if (!existsSync(root)) return null
  const id = String(sessionId || '')
  let projects
  try {
    projects = readdirSync(root)
  } catch {
    return null
  }
  for (const project of projects) {
    const pdir = path.join(root, project)
    let entries
    try {
      entries = readdirSync(pdir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (id && !name.includes(id)) continue
      const dir = path.join(pdir, name)
      try {
        if (statSync(dir).isDirectory()) return dir
      } catch { /* ignore */ }
    }
  }
  return null
}

/** 解码 DSH 的路径段转义（`~XXXX`）。 */
function decodeSegment(raw) {
  return String(raw).replace(/~([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
}

/** 从会话日志路径反推会话 id（会话目录名就是 id 的转义形式）。 */
function sessionIdFromPath(file) {
  try {
    return decodeSegment(path.basename(path.dirname(file)))
  } catch {
    return ''
  }
}

/** 会话目录下的日志文件绝对路径（可选 cwd 更快）。 */
function logFileFor(id, cwd) {
  if (!id) return null
  if (cwd) {
    const dir = path.join(sessionsRoot(), projectDirName(cwd), String(id))
    const direct = newestFile(dir)
    if (direct) return direct
  }
  const dir = findSessionDirAny(id)
  return dir ? newestFile(dir) : null
}

/** 列出所有会话日志文件（给孤儿密文补登用）。 */
function listLogFiles() {
  const root = sessionsRoot()
  if (!existsSync(root)) return []
  const out = []
  let projects
  try {
    projects = readdirSync(root)
  } catch {
    return out
  }
  for (const project of projects) {
    const pdir = path.join(root, project)
    let entries
    try {
      entries = readdirSync(pdir)
    } catch {
      continue
    }
    for (const name of entries) {
      const dir = path.join(pdir, name)
      let isDir = false
      try {
        isDir = statSync(dir).isDirectory()
      } catch { /* ignore */ }
      if (!isDir) continue
      const file = newestFile(dir)
      if (!file) continue
      out.push({ id: decodeSegment(name), file })
    }
  }
  return out
}

// ============================================================================
// WALLBK 容器
// ============================================================================

function deriveKey(password, salt) {
  // maxmem 必须显式放大：Node 默认上限 32 MiB，而 N=131072,r=8 需要 128 MiB，
  return scryptSync(password, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: scryptKeyOptions().maxmem,
  })
}

/** 拼一个 WALLBK 头部。 */
function buildHeader({ n, r, p, salt, nonce }) {
  const header = Buffer.alloc(HEADER_LEN)
  let off = 0
  MAGIC.copy(header, off); off += MAGIC.length
  header.writeUInt8(VERSION_BYTE, off); off += 1
  header.writeUInt32BE(n, off); off += 4
  header.writeUInt32BE(r, off); off += 4
  header.writeUInt32BE(p, off); off += 4
  salt.copy(header, off); off += SALT_LEN
  nonce.copy(header, off)
  return header
}

/** 解析 WALLBK 头部。 */
function parseHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < HEADER_LEN + TAG_LEN) {
    throw new Error('文件太短，不是有效备份')
  }
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('magic 不匹配，不是本工具生成的备份')
  }
  let off = MAGIC.length
  const ver = buf.readUInt8(off); off += 1
  if (ver !== VERSION_BYTE) throw new Error(`不支持的版本: ${ver}`)
  const n = buf.readUInt32BE(off); off += 4
  const r = buf.readUInt32BE(off); off += 4
  const p = buf.readUInt32BE(off); off += 4
  const salt = buf.subarray(off, off + SALT_LEN); off += SALT_LEN
  const nonce = buf.subarray(off, off + NONCE_LEN); off += NONCE_LEN
  return { n, r, p, salt, nonce, body: buf.subarray(off) }
}

/** 用一把 32 字节钥匙封装明文。 */
function sealWithKey(plain, key, saltInput) {
  const salt = Buffer.isBuffer(saltInput) ? saltInput : Buffer.from(String(saltInput), 'base64')
  if (salt.length !== SALT_LEN) throw new Error('salt 长度必须是 16 字节')
  const nonce = randomBytes(NONCE_LEN)
  const header = buildHeader({ n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt, nonce })
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.concat([MAGIC, Buffer.from([VERSION_BYTE])]))
  const body = Buffer.concat([cipher.update(plain), cipher.final()])
  return Buffer.concat([header, body, cipher.getAuthTag()])
}

/** 用一把 32 字节钥匙解开密文。 */
function openWithKey(buf, key) {
  const { nonce, body } = parseHeader(buf)
  const tag = body.subarray(body.length - TAG_LEN)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(Buffer.concat([MAGIC, Buffer.from([VERSION_BYTE])]))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body.subarray(0, body.length - TAG_LEN)), decipher.final()])
}

/** 文件是不是我们加密过的（前 8 字节是 WALLBK magic）。 */
function isVaultFile(filePath) {
  try {
    const fd = openSync(filePath, 'r')
    try {
      const buf = Buffer.alloc(MAGIC.length)
      const n = readSync(fd, buf, 0, MAGIC.length, 0)
      return n === MAGIC.length && buf.equals(MAGIC)
    } finally {
      closeSync(fd)
    }
  } catch {
    return false
  }
}

/** 内存里的 Buffer 是不是 WALLBK 容器。 */
function isVaultBuffer(buf) {
  return Buffer.isBuffer(buf) && buf.length >= HEADER_LEN + TAG_LEN && buf.subarray(0, MAGIC.length).equals(MAGIC)
}

/** 读容器头部里的盐（写回密文时沿用同一把盐）。 */
function readSalt(buf) {
  return Buffer.from(parseHeader(buf).salt)
}

/** 用明文口令封装一段内容（盐随机，和导出备份的格式完全一致）。 */
function encryptBuffer(plain, password, saltInput) {
  const salt = saltInput ? (Buffer.isBuffer(saltInput) ? saltInput : Buffer.from(String(saltInput), 'base64')) : randomBytes(SALT_LEN)
  const key = deriveKey(String(password), salt)
  return sealWithKey(plain, key, salt)
}

/** 用明文口令解开一段内容。 */
function decryptBuffer(buf, password) {
  const { n, r, p, salt } = parseHeader(buf)
  const key = scryptSync(String(password), salt, 32, { N: n, r, p, maxmem: scryptKeyOptions(n, r, p).maxmem })
  return openWithKey(buf, key)
}

/** 按**文件自己头里的参数和盐**派生钥匙（老版本按每个文件随机盐加密，只能这么开）。 */
function deriveFileKey(buf, password) {
  const { n, r, p, salt } = parseHeader(buf)
  return scryptSync(String(password), salt, 32, { N: n, r, p, maxmem: scryptKeyOptions(n, r, p).maxmem })
}

/** 流式加密文件：不把整个会话读进内存（会话可能有上百 MB）。 */
async function encryptFile(srcPath, dstPath, password) {
  const salt = randomBytes(SALT_LEN)
  const nonce = randomBytes(NONCE_LEN)
  const key = deriveKey(password, salt)
  const header = buildHeader({ n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt, nonce })

  const aad = Buffer.concat([MAGIC, Buffer.from([VERSION_BYTE])])
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)

  const tmpPath = dstPath + '.part'
  const out = createWriteStream(tmpPath)
  out.write(header)
  await pipeline(createReadStream(srcPath), cipher, out)

  const tag = cipher.getAuthTag()
  await new Promise((resolve, reject) => {
    const tail = createWriteStream(tmpPath, { flags: 'a' })
    tail.on('error', reject)
    tail.on('finish', resolve)
    tail.end(tag)
  })

  renameSync(tmpPath, dstPath)
  return { headerBytes: header.length, tagBytes: tag.length, bytes: statSync(dstPath).size }
}

/** 解密一个 .enc 到 dst。和 encryptFile 严格对称。 */
async function decryptFile(srcPath, dstPath, password) {
  const buf = readFileSync(srcPath)
  const plain = decryptBuffer(buf, password)
  writeFileSync(dstPath, plain)
  return plain.length
}

// ============================================================================
// 导出备份的杂项
// ============================================================================

/** 只保留最近 keep 份。 */
function pruneOld(dest, keep) {
  let names
  try {
    names = readdirSync(dest).filter((n) => n.startsWith('chat-session-') && n.endsWith('.enc'))
  } catch {
    return []
  }
  const withTime = names
    .map((n) => {
      const p = path.join(dest, n)
      let t = 0
      try {
        t = statSync(p).mtimeMs
      } catch { /* ignore */ }
      return { p, n, t }
    })
    .sort((a, b) => b.t - a.t)
  const removed = []
  for (const item of withTime.slice(keep)) {
    try {
      unlinkSync(item.p)
      removed.push(item.n)
    } catch { /* ignore */ }
  }
  return removed
}

function stamp() {
  const d = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    '-' +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  )
}

// ============================================================================
// 插件
// ============================================================================

// 用 ctx.tools / ctx.connection 必须声明 inject，否则激活时报
// `cannot get property "tools" without inject`。
export const inject = ['tools', 'connection', 'sessionPersistence']

export function apply(ctx, config) {
  const dest = config?.dest || 'D:\\backup\\chat'
  const keep = Number.isInteger(config?.keep) ? config.keep : 20

  // 会话根目录优先问宿主（dshHomePath 是 DSH 的官方路径服务），拿不到才退回环境变量。
  try {
    const homePath = ctx.get('dshHomePath')
    if (typeof homePath === 'function') sessionsRootOverride = homePath('sessions')
  } catch { /* 保持默认 */ }

  const dir = stateDir(ctx)
  const stateFile = path.join(dir, 'state.json')
  const freshInstall = !existsSync(stateFile)

  /** 写一行日志：文件 + 宿主 logger，两个都失败也不致命。 */
  const log = (message) => {
    const line = `${new Date().toISOString()}  ${message}`
    try { writeFileSync(path.join(dir, 'session-vault.log'), line + '\n', { flag: 'a' }) } catch { /* ignore */ }
    try { ctx.logger?.info?.(`[session-vault] ${message}`) } catch { /* 没有 logger 就算了 */ }
  }

  // ---- 残留临时文件清理 -----------------------------------------------------
  /*
   * 上次进程死在 writeAtomic 的 tmp + rename 之间会留下 *.vault-tmp（里面可能是
   * 完整明文或完整密文）。启动时清一次；只扫会话根目录、不跟符号链接、删不掉的
   * 跳过，清理失败绝不阻断插件加载。
   */
  let sweptTemps = 0
  try {
    sweptTemps = sweepTempFiles(sessionsRoot())
  } catch (error) {
    log(`清理残留临时文件失败：${error?.message ?? error}`)
  }
  log(`启动清理：删除 ${sweptTemps} 个残留 *.vault-tmp 文件`)

  // ---- 状态 ---------------------------------------------------------------
  let state = loadState(dir)
  if (state.__loadError) {
    log(`状态文件损坏已重建：${state.__loadError}`)
    delete state.__loadError
    saveState(dir, state)
  }
  if (state.__migrated) {
    // 旧结构归一化后回写（多余的顶层字段会被丢掉）。
    delete state.__migrated
    saveState(dir, state)
    log(`状态已升级到 v${STATE_VERSION}`)
  }
  if (freshInstall) {
    // 首次安装：配置文件里的默认值生效，之后以 state.json 为准（GUI 可改）。
    if (Number.isFinite(Number(config?.autoLockMinutes))) {
      state.policy.autoLockMinutes = Math.max(0, Math.min(24 * 60, Math.floor(Number(config.autoLockMinutes))))
    }
    if (typeof config?.diskLock === 'boolean') state.policy.diskLock = config.diskLock
    saveState(dir, state)
  }
  const getState = () => state
  const setState = (next) => {
    state = normalizeState(next)
    saveState(dir, state)
  }

  // ---- 授权 / 磁盘锁 -------------------------------------------------------
  const grants = new Grants()

  const cryptoFace = {
    isVaultBuffer,
    isVaultFile,
    readSalt,
    decryptWithKey: openWithKey,
    decryptBuffer,
    deriveFileKey,
    encryptWithKey: sealWithKey,
  }

  const paths = { logFileFor, sessionIdFromPath, listLogFiles }

  /*
   * 口令表要**同步两份**：
   *   ① 我们自己的 Grants（有效期、空闲过期、磁盘钥匙都在这）
   *   ② backend-patch.js 的全局表（它负责 readFirstZstdLine 解密，只认口令）
   * 只有 ② 没有 ① 会让空闲超时锁不住；只有 ① 没有 ② 会让会话头解不出来。
   * 会话 id 有两种历史写法（`session-<uuid>` 与裸 `<uuid>`），两个都记。
   */
  const keyAliases = (sessionId) => {
    const id = String(sessionId || '')
    const bare = id.replace(/^session-/, '')
    return bare && bare !== id ? [id, bare] : [id]
  }
  const vaultKeys = {
    set(sessionId, password) {
      for (const id of keyAliases(sessionId)) backendSetKey(id, password)
    },
    clear(sessionId) {
      for (const id of keyAliases(sessionId)) backendClearKey(id)
    },
    clearAll() {
      for (const id of backendKeyIds()) backendClearKey(id)
    },
  }

  const disk = createDiskLock({ getState, setState, grants, log, paths, crypto: cryptoFace })

  // 先让 backend-patch 接管「读 header / 读正文」，我们的磁盘锁再在它外面补旁路与写保护。
  let backendInfo = { ok: false, methods: [] }
  try {
    backendInfo = patchBackend(ctx, {
      onLocked: (id) => log(`读取被拦下（会话 ${id} 仍锁在磁盘上）`),
    })
    log(`backend-patch：ok=${backendInfo.ok} 方法=${backendInfo.methods.join(',') || '(无)'}${backendInfo.error ? ` 备注=${backendInfo.error}` : ''}`)
  } catch (error) {
    backendInfo = { ok: false, methods: [], error: String(error?.message ?? error) }
    log(`backend-patch 安装失败：${backendInfo.error}`)
  }

  /** 把「到底装上了什么」写成文件，Desktop 的 console 看不到时靠它排查。 */
  const writeDiagnostics = (extra) => {
    const snapshot = getState()
    const diag = {
      at: new Date().toISOString(),
      version: VERSION,
      backend: backendInfo,
      disk: { available: disk.available, sweptTempFiles: sweptTemps, ...extra },
      sessionsRoot: sessionsRoot(),
      policy: snapshot.policy,
      locks: Object.entries(snapshot.locks).map(([id, row]) => ({
        id,
        disk: row.disk === true,
        orphan: row.orphan === true,
      })),
      unlocked: grants.snapshot(),
      backendKeyCount: backendKeyIds().length,
    }
    try {
      writeFileSync(path.join(dir, '_diagnostics.json'), JSON.stringify(diag, null, 2), 'utf8')
    } catch { /* 写不进去也不影响功能 */ }
  }

  // 启动就先落一份诊断：后端一直没装上时，_diagnostics.json 里也能看到清理数量。
  writeDiagnostics({ startup: true })

  // 后端可能在插件之后才挂上来：先试一次，没挂上就补几次。
  ctx.effect(() => {
    let installed = false
    let tries = 0
    const tryInstall = () => {
      if (installed) return
      let sp = null
      try { sp = ctx.get('sessionPersistence') } catch { sp = null }
      if (!sp) return
      // 服务晚到一步时补装 backend-patch（重复调用是幂等的，它自带 PATCH_FLAG）。
      if (!backendInfo.ok) {
        try {
          backendInfo = patchBackend(ctx, { onLocked: (id) => log(`读取被拦下（会话 ${id} 仍锁在磁盘上）`) })
          log(`backend-patch 补装：ok=${backendInfo.ok} 方法=${backendInfo.methods.join(',') || '(无)'}`)
        } catch (error) {
          log(`backend-patch 补装失败：${error?.message ?? error}`)
        }
      }
      if (!disk.install(sp)) {
        // 方法不齐是版本差异，不是「还没起来」：别再重试，界面锁照常。
        installed = true
        return
      }
      installed = true
      try {
        const adopted = disk.adopt()
        if (adopted > 0) log(`已补登 ${adopted} 个未登记的密文会话`)
      } catch (error) {
        log(`补登密文会话失败：${error?.message ?? error}`)
      }
      writeDiagnostics({ installed: true })
    }
    tryInstall()
    const timer = setInterval(() => {
      tries += 1
      tryInstall()
      if (installed || tries > 40) clearInterval(timer)
    }, 500)
    try { timer.unref?.() } catch { /* 无关紧要 */ }
    return () => {
      clearInterval(timer)
      disk.dispose()
    }
  }, 'session-vault: session-persistence 磁盘锁补丁')

  // ---- 路由 ---------------------------------------------------------------
  const handler = makeHandler({
    getState,
    setState,
    grants,
    disk,
    keys: vaultKeys,
    log,
    version: VERSION,
    onChanged: () => writeDiagnostics({}),
  })

  const registerRoutes = () => {
    let connection = null
    try { connection = ctx.get('connection') } catch { connection = null }
    if (!connection?.fetch?.register) {
      log('没有 connection.fetch，会话锁的 HTTP 路由跳过（纯 CLI 部署）')
      return () => {}
    }
    return connection.fetch.register({
      path: '/api/session.vault',
      methods: ['GET', 'POST'],
      requestBody: 'buffered',
      fetch: (request) => handler(request),
    })
  }
  ctx.effect(registerRoutes, 'session-vault: /api/session.vault 路由')

  // ---- 空闲自动重新上锁 ----------------------------------------------------
  /**
   * 授权到期 = 磁盘钥匙一起蒸发，所以「重新上锁」不需要再写一次磁盘：
   * 那些文件本来就只有密文，读不出正文只是因为内存里没有钥匙了。
   */
  ctx.effect(() => {
    const timer = setInterval(() => {
      const minutes = getState().policy.autoLockMinutes
      if (grants.expireIdle(minutes)) {
        // 两本账一起清：只清 Grants 的话，backend-patch 还留着口令，会话头照样能解。
        vaultKeys.clearAll()
        forgetAllDiskKeys()
        log(`空闲超过 ${minutes} 分钟，已自动重新上锁`)
        writeDiagnostics({ autoLocked: true })
      }
    }, 30_000)
    try { timer.unref?.() } catch { /* 无关紧要 */ }
    return () => clearInterval(timer)
  }, 'session-vault: 空闲自动上锁')

  // ---- 导出加密备份的工具 --------------------------------------------------
  //
  // 手工构造工具定义，而不是用 `defineTool()`。
  //
  // 原因：bundle 是以**链接目录**方式安装的，Node 从包自身的 node_modules
  // 解析依赖，而 `@deepseek-ai/dsh-tools` 只在 dsh 安装目录（asar 内），
  // 于是 `import { defineTool } from '@deepseek-ai/dsh-tools'` 直接报
  // ERR_MODULE_NOT_FOUND。
  ctx.tools.register({
    name: 'session_vault_encrypt',
    description:
      'Encrypt the current conversation log into a password-protected .enc archive and store it in the configured backup folder. The archive is compatible with wall/tools/backup_crypt.py.',
    parameters: {
      type: 'object',
      properties: {
        password: {
          type: 'string',
          description:
            'Passphrase for the archive. It is not stored anywhere; losing it makes the archive unreadable.',
        },
        session_id: {
          type: 'string',
          description:
            'Session id or id prefix to back up. Omit for the most recently modified session of the current working directory.',
        },
      },
      required: ['password'],
    },
    output: TEXT_OUTPUT,
    isConcurrencySafe: () => false,
    execute: async (args, exec) => {
      const password = String(args?.password || '')
      if (!password) return '错误：需要提供口令。'

      const cwd = exec?.cwd || exec?.session?.cwd || process.cwd()
      const sessionId = args?.session_id || exec?.session?.id || exec?.sessionId || ''

      const src = resolveSessionFile(sessionId, cwd)
      if (!src) {
        return (
          `找不到会话文件（session_id=${sessionId || '(未指定)'}，cwd=${cwd}）。\n` +
          `会话根目录：${sessionsRoot()}`
        )
      }

      mkdirSync(dest, { recursive: true })
      const base = path.basename(path.dirname(src))
      const outFile = path.join(dest, `chat-${base}-${stamp()}.enc`)

      const r = await encryptFile(src, outFile, password)
      const removed = pruneOld(dest, keep)

      const lines = [
        `已加密：${outFile}`,
        `源文件：${src}`,
        `大小：${r.bytes} B（头部 ${r.headerBytes} B + tag ${r.tagBytes} B）`,
        `恢复：python tools\\backup_crypt.py decrypt "${path.basename(outFile)}" session.v4.jsonl.zstd`,
      ]
      if (removed.length) lines.push(`已清理旧备份：${removed.join(', ')}`)
      return lines.join('\n')
    },
  })

  log(
    `已加载 v${VERSION}；状态目录 ${dir}；` +
    `已锁会话 ${Object.keys(state.locks).length} 个（磁盘锁 ${Object.values(state.locks).filter((r) => r.disk).length} 个）；` +
    `最短口令 ${MIN_PASSWORD_LENGTH} 位；默认策略 ${JSON.stringify({ ...DEFAULT_POLICY, ...state.policy })}`,
  )
}

// 给单元/手工排查留的出口（不参与运行时）。
export { decryptBuffer, decryptFile, encryptBuffer, encryptFile, isVaultBuffer, isVaultFile, MAGIC }
