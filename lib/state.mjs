/**
 * lib/state.mjs —— 会话锁状态的读 / 写 / 归一化。
 *
 * 为什么不放进 profile 的 settings 命名空间：口令哈希、每个会话的锁标记都不该
 * 躺在给人手改的 YAML 里，而且我们要在**没有任何 GUI 写入**的情况下原子更新它。
 *
 * 落点：`<dshHome>/session-vault/state.json`，权限 0600。
 * Windows 上 chmod 基本无效，所以真正的保护靠「哈希 + 只活在内存里的解锁授权」，
 * 而不是「文件读不到」。
 *
 * ---------------------------------------------------------------------------
 * 每条会话一把独立口令
 * ---------------------------------------------------------------------------
 * 只有一种口令记录，写在 `locks[id].password`：
 *
 *     locks[id].password = { algo:'scrypt', salt, hash, n, r, p, keylen }
 *
 * 每个会话独立盐、独立派生值，明文口令绝不落盘。没有全局口令，也没有
 * 「回退到全局记录」这回事。
 *
 * ---------------------------------------------------------------------------
 * 改口令的崩溃窗口：passwordPrevious
 * ---------------------------------------------------------------------------
 * 改口令分三步：① 把「新旧两条记录」写进 state；② 换磁盘钥匙；③ 删掉旧记录。
 * ①②之间崩掉时文件还是旧钥匙，②③之间崩掉时文件已经是新钥匙 —— 两种窗口里
 * 都只有**其中一条**记录能真正打开文件，所以验口令时必须逐条试、并用
 * `disk.keyOpens()` 确认这条记录派生出的钥匙真能开文件。`passwordPrevious`
 * 只是这个窗口里的临时第二条记录，正常完成后必须被清掉。
 */
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** 版本号；v2 起 = 每条会话独立口令。 */
export const STATE_VERSION = 2

/** 口令哈希参数（scrypt）。参数和 maxmem 统一在 ./scrypt.mjs 里定义。 */
export { SCRYPT } from './scrypt.mjs'

/** 策略默认值：10 分钟无操作自动重新上锁。 */
export const DEFAULT_POLICY = {
  autoLockMinutes: 10,
  /** 上锁时是否同时把会话文件加密到磁盘（真磁盘加密，解锁后才能读）。 */
  diskLock: true,
}

/**
 * 定位插件状态目录。
 * @param ctx - host 侧 cordis context（可能取不到 dshHomePath，兜底用 DSH_HOME/HOME）。
 * @returns 已创建的绝对目录。
 */
export function stateDir(ctx) {
  let dir = ''
  try {
    const p = ctx?.get?.('dshHomePath')
    if (typeof p === 'function') {
      const v = p('session-vault')
      if (v) dir = String(v)
    } else if (typeof p === 'string' && p) {
      dir = join(p, 'session-vault')
    }
  } catch { /* 拿不到就走兜底 */ }
  if (!dir) dir = join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'session-vault')
  mkdirSync(dir, { recursive: true })
  return dir
}

/** 空状态。 */
export function emptyState() {
  return {
    version: STATE_VERSION,
    policy: { ...DEFAULT_POLICY },
    /** sessionId -> { title, lockedAt, disk, orphan, password? } */
    locks: {},
    createdAt: Date.now(),
    updatedAt: Date.now(),
  }
}

function clampInt(value, min, max, fallback) {
  const n = Math.floor(Number(value))
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, n))
}

/**
 * 归一化一条 scrypt 口令记录（每条锁一份）。
 * @param raw - 磁盘上读到的原始对象。
 * @returns 规范化记录；不合法返回 null。
 */
export function normalizePasswordRecord(raw) {
  if (!raw || typeof raw !== 'object') return null
  if (typeof raw.hash !== 'string' || typeof raw.salt !== 'string') return null
  if (!raw.hash || !raw.salt) return null
  const salt = raw.salt
  const hash = raw.hash
  // base64 解出来必须是 16 字节盐 + 非空哈希，否则这条记录不能用来验口令。
  try {
    if (Buffer.from(salt, 'base64').length === 0) return null
    if (Buffer.from(hash, 'base64').length === 0) return null
  } catch {
    return null
  }
  return {
    algo: 'scrypt',
    salt,
    hash,
    n: Number(raw.n) || SCRYPT.N,
    r: Number(raw.r) || SCRYPT.r,
    p: Number(raw.p) || SCRYPT.p,
    keylen: Number(raw.keylen) || SCRYPT.keylen,
    createdAt: Number(raw.createdAt) || Date.now(),
  }
}

/**
 * 一条锁的全部候选口令记录：当前记录在前，改口令窗口里的上一条在后。
 *
 * 改口令中途崩溃会留下「当前 + previous」两条记录，其中只有一条的钥匙能打开
 * 磁盘文件。验口令的调用方必须**逐条试**，并用 `disk.keyOpens()` 确认。
 *
 * @param row - state.locks[id]。
 * @returns 去重后的口令记录数组；没有可用记录时是空数组。
 */
export function passwordCandidates(row) {
  if (!row || typeof row !== 'object') return []
  const out = []
  for (const rec of [row.password, row.passwordPrevious]) {
    if (!rec || typeof rec !== 'object') continue
    // 已经被 normalizeState 归一化过；这里只做最小校验，避免把坏记录当口令用。
    if (typeof rec.hash !== 'string' || typeof rec.salt !== 'string' || !rec.hash || !rec.salt) continue
    if (out.some((seen) => seen.salt === rec.salt && seen.hash === rec.hash)) continue
    out.push(rec)
  }
  return out
}

/**
 * 取一条锁的主口令记录（保留给只关心「当前记录」的调用方）。
 * @param row - state.locks[id]。
 * @returns 口令记录或 null（没有记录的只可能是待救回的老密文）。
 */
export function lockPasswordOf(row) {
  return passwordCandidates(row)[0] ?? null
}

/** 把任意读到的 JSON 收敛成合法状态（缺字段补默认，坏类型 / 多余字段丢掉）。 */
export function normalizeState(raw) {
  const base = emptyState()
  if (!raw || typeof raw !== 'object') return base
  const out = {
    version: STATE_VERSION,
    policy: { ...DEFAULT_POLICY },
    locks: {},
    createdAt: Number(raw.createdAt) || base.createdAt,
    updatedAt: Date.now(),
  }

  const pol = raw.policy && typeof raw.policy === 'object' ? raw.policy : {}
  out.policy = {
    autoLockMinutes: clampInt(pol.autoLockMinutes, 0, 24 * 60, DEFAULT_POLICY.autoLockMinutes),
    diskLock: typeof pol.diskLock === 'boolean' ? pol.diskLock : DEFAULT_POLICY.diskLock,
  }

  const locks = {}
  if (raw.locks && typeof raw.locks === 'object') {
    for (const [id, row] of Object.entries(raw.locks)) {
      if (typeof id !== 'string' || !id) continue
      const r = row && typeof row === 'object' ? row : {}
      const own = normalizePasswordRecord(r.password)
      const prev = normalizePasswordRecord(r.passwordPrevious)
      const next = {
        title: typeof r.title === 'string' ? r.title : '',
        lockedAt: Number(r.lockedAt) || Date.now(),
        disk: r.disk === true,
        /** 上一版「原地加密」遗留的密文：钥匙是当初那个口令，只有它能救回来。 */
        orphan: r.orphan === true,
      }
      // 只有自己的口令记录才会写进锁；没有记录的 orphan 密文不伪造记录。
      if (own) {
        next.password = own
        // previous 只在主记录有效时保留；坏记录直接丢掉，绝不让整份 state 加载失败。
        if (prev && (prev.salt !== own.salt || prev.hash !== own.hash)) next.passwordPrevious = prev
      } else if (prev) {
        // 主记录坏了、previous 还能用：降级成主记录，别让用户平白被锁在门外。
        next.password = prev
      }
      locks[id] = next
    }
  }
  out.locks = locks

  out.version = STATE_VERSION
  out.updatedAt = Date.now()
  return out
}

/**
 * 读状态。文件不存在 / 坏掉都不抛 —— 锁插件自己挂掉比锁不上更糟。
 * @param dir - stateDir() 的返回值。
 * @returns 归一化后的状态（旧版文件会带 `__migrated` 标记，提醒调用方回写）。
 */
export function loadState(dir) {
  const file = join(dir, 'state.json')
  if (!existsSync(file)) return emptyState()
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8'))
    const state = normalizeState(raw)
    if (Number(raw?.version) !== STATE_VERSION) state.__migrated = true
    return state
  } catch (error) {
    // 坏文件留个证据再重建，别静默丢掉用户的锁配置却毫无线索。
    try {
      renameSync(file, join(dir, `state.corrupt-${Date.now()}.json`))
    } catch { /* 改名失败也继续 */ }
    const fresh = emptyState()
    fresh.__loadError = String(error?.message ?? error)
    return fresh
  }
}

/**
 * 把刚写完的文件刷到盘上（fsync），再允许 rename 覆盖正式文件。
 *
 * 没有 fsync 时，rename 可能先被持久化、数据块还没有 —— 断电后会得到一个
 * 「文件名对、内容是 0 字节或半截」的 state.json，比直接丢失更糟。
 * 某些网络盘 / 虚拟盘不支持 fsync：静默跳过，不能因此拒绝正常写入。
 * @param file - 要同步的临时文件。
 */
function syncFile(file) {
  let fd = null
  try {
    fd = openSync(file, 'r+')
    fsyncSync(fd)
  } catch { /* 文件系统不支持就继续 */ } finally {
    if (fd !== null) {
      try { closeSync(fd) } catch { /* ignore */ }
    }
  }
}

/**
 * 原子写状态（tmp + rename），并尽量把权限收紧到 0600。
 * @param dir - stateDir() 的返回值。
 * @param state - 完整状态对象。
 */
export function saveState(dir, state) {
  const file = join(dir, 'state.json')
  const tmp = join(dir, `state.${process.pid}.${Date.now()}.tmp`)
  const body = JSON.stringify({ ...state, version: STATE_VERSION, updatedAt: Date.now() }, null, 2)
  writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 })
  try { chmodSync(tmp, 0o600) } catch { /* Windows 上通常无效 */ }
  syncFile(tmp)
  renameSync(tmp, file)
  try { chmodSync(file, 0o600) } catch { /* 同上 */ }
  try { return statSync(file).size } catch { return body.length }
}
