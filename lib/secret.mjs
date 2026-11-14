/**
 * lib/secret.mjs —— 口令哈希与「已解锁」授权表。
 *
 * 两条规矩：
 *  1. 口令**永不落盘**，只存 scrypt 派生值 + 每条独立的盐；比较用 timingSafeEqual。
 *  2. 「已解锁」只活在内存里 —— 进程一重启就全灭，这也是最可靠的一把自动锁。
 */
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

/**
 * 为什么校验值和加密钥匙必须分成两条派生路径
 * --------------------------------------------------
 * scrypt 的最后一步是 PBKDF2-HMAC-SHA256，而 PBKDF2 的输出是**流式前缀**：
 * scrypt(pw, salt, 64)[0..32) 与 scrypt(pw, salt, 32) 完全相同（实测确认）。
 *
 * 所以如果 state.json 里存的校验值是 scrypt(pw, salt, 64)，它的前 32 字节
 * 就是 AES 密钥本身 —— 拿到 state.json 的人可以直接解密，不需要猜口令。
 *
 * 修法：两条路径用**不同的盐前缀**，输出落在不同的 256 位空间里。
 * 从存储的校验值推不出钥匙。
 */
const CHECK_DOMAIN = Buffer.from('session-vault:check:')
const KEY_DOMAIN = Buffer.from('session-vault:aes-key:')
import { SCRYPT, scryptMaxMem } from './scrypt.mjs'

/** 允许的最短口令长度。太短的锁等于没锁，这里直接挡住。 */
export const MIN_PASSWORD_LENGTH = 6

// 实际值由 SCRYPT.N / r 推出来（需求量的两倍），改 N 时不需要手动同步。
const MAXMEM = scryptMaxMem()
/** 口令记录里的 scrypt 参数。 */
function scryptParams(record) {
  return {
    N: Number(record?.n) || SCRYPT.N,
    r: Number(record?.r) || SCRYPT.r,
    p: Number(record?.p) || SCRYPT.p,
  }
}

/**
 * 生成一条新的口令记录（每条会话一份）。
 * @param password - 明文口令。
 * @returns 可写进 state.locks[id].password 的对象。
 */
export function makePasswordRecord(password) {
  const salt = randomBytes(16)
  // 校验值的盐前面加 CHECK_DOMAIN，和加密钥匙的派生路径分开。
  // 见文件顶部关于 PBKDF2 输出是流式前缀的说明。
  const checkSalt = Buffer.concat([CHECK_DOMAIN, salt])
  const hash = scryptSync(String(password), checkSalt, SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: MAXMEM,
  })
  return {
    algo: 'scrypt',
    salt: salt.toString('base64'),
    hash: hash.toString('base64'),
    n: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    keylen: SCRYPT.keylen,
    createdAt: Date.now(),
  }
}

/**
 * 校验口令。任何参数问题都返回 false（失败即拒绝，绝不「因为没配置就放行」）。
 * @param record - 某条会话的口令记录。
 * @param password - 待校验明文。
 * @returns 是否匹配。
 */
export function verifyPassword(record, password) {
  if (!record || typeof record.hash !== 'string' || typeof record.salt !== 'string') return false
  if (typeof password !== 'string' || password.length === 0) return false
  try {
    const salt = Buffer.from(record.salt, 'base64')
    const expected = Buffer.from(record.hash, 'base64')
    const actual = scryptSync(password, Buffer.concat([CHECK_DOMAIN, salt]), record.keylen || SCRYPT.keylen, {
      ...scryptParams(record),
      maxmem: MAXMEM,
    })
    if (actual.length !== expected.length) return false
    return timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

/**
 * 已派生过的磁盘钥匙，只活在内存里。
 *
 * 钥匙从「明文口令 + 记录自己的盐」派生。缓存只按记录（salt+hash）索引，
 * **不落盘**：进程重启后必须重新验一次口令；这样做是为了满足「上锁时不一定
 * 手上还有明文口令」这条路径，同时不把钥匙的派生材料写进 state.json。
 * @type {Map<string, Buffer>}
 */
const diskKeys = new Map()

const diskKeyId = (record) => `${record.salt}|${record.hash}`

/**
 * 从一条口令记录派生磁盘锁用的密钥（32 字节 AES-256）。
 *
 * 每条会话用自己的记录（`lock.password`）；盐也来自记录本身，所以不同会话的
 * 钥匙互不相干。
 *
 * @param record - 口令记录（lock.password）。
 * @param password - 明文口令；省略时用本进程里已经派生并缓存的钥匙。
 * @returns 32 字节密钥。
 */
export function deriveDiskKey(record, password) {
  if (!record || typeof record !== 'object' || typeof record.salt !== 'string' || !record.salt) {
    throw new Error('没有可用的口令记录，无法派生磁盘钥匙')
  }
  // 只缓存能对上记录的钥匙：调用方必须先 verifyPassword 再调这里。
  if (typeof password === 'string' && password.length > 0) {
    const key = scryptSync(password, Buffer.concat([KEY_DOMAIN, Buffer.from(record.salt, 'base64')]), 32, {
      ...scryptParams(record),
      maxmem: MAXMEM,
    })
    diskKeys.set(diskKeyId(record), key)
    return key
  }
  const cached = diskKeys.get(diskKeyId(record))
  if (cached) return cached
  throw new Error('本进程还没有验过这条口令，无法派生磁盘钥匙')
}

/** 丢掉一条记录对应的缓存钥匙（改口令 / 撤销授权时调用）。 */
export function forgetDiskKey(record) {
  if (record && typeof record.salt === 'string' && typeof record.hash === 'string') {
    diskKeys.delete(diskKeyId(record))
  }
}

/** 丢掉全部缓存钥匙（清除口令 / 空闲自动上锁时调用）。 */
export function forgetAllDiskKeys() {
  diskKeys.clear()
}

/**
 * 解锁授权表：谁在什么时刻被临时放行。
 *
 * 按会话授权：只放行被验过口令的那一条，其它锁着的照旧弹窗。有效期由
 * policy.autoLockMinutes 控制（0 = 不过期，直到进程退出）。
 *
 * 磁盘锁的钥匙（32 字节）也挂在这里：授权到期 = 钥匙一起消失 = 会话文件重新变回
 * 「读不出来」，不需要再写一次磁盘。明文口令**从不**进这张表。
 */
export class Grants {
  constructor() {
    /** @type {Map<string, { until: number, key: Buffer | null }>} sessionId -> 授权 */
    this.sessions = new Map()
    /** 最近一次用户活动时间，用于 auto-lock 判定。 */
    this.lastActivity = Date.now()
  }

  /** 记一次活动（客户端节流后调用）。 */
  touch() {
    this.lastActivity = Date.now()
  }

  /**
   * 只给某一条会话发授权（钥匙只对这条会话有效）。
   * @param sessionId - 会话 id。
   * @param minutes - 有效分钟数；0 表示到进程结束。
   * @param key - 这条会话自己的钥匙。
   */
  grantSession(sessionId, minutes, key) {
    const until = minutes > 0 ? Date.now() + minutes * 60_000 : 0
    this.touch()
    this.sessions.set(String(sessionId), { until: until || Number.MAX_SAFE_INTEGER, key: key ?? null })
  }

  /**
   * 撤销。
   * @param scope - 'all' | sessionId。
   */
  revoke(scope) {
    if (scope === 'all') {
      this.sessions.clear()
      return
    }
    this.sessions.delete(String(scope))
  }

  /** 撤掉全部（锁屏按钮 / 空闲超时）。 */
  clear() {
    this.sessions.clear()
  }

  /** 某个会话的授权是否还活着。 */
  #alive(entry) {
    if (!entry) return false
    if (entry.until === 0 || entry.until === Number.MAX_SAFE_INTEGER) return true
    return entry.until > Date.now()
  }

  /**
   * 该会话当前是否被放行。
   * @param sessionId - 会话 id。
   * @returns 是否已授权。
   */
  allows(sessionId) {
    const entry = this.sessions.get(String(sessionId))
    if (this.#alive(entry)) return true
    if (entry) this.sessions.delete(String(sessionId))
    return false
  }

  /**
   * 磁盘锁钥匙：该会话自己那把（授权必须还活着）。
   * @param sessionId - 会话 id。
   * @returns 32 字节钥匙；没有授权时 undefined。
   */
  keyFor(sessionId) {
    if (!this.allows(sessionId)) return undefined
    const entry = this.sessions.get(String(sessionId))
    return entry && entry.key ? entry.key : undefined
  }

  /**
   * 空闲超时检查：超过 autoLockMinutes 没有活动就把授权全撤。
   * @param minutes - 策略里的分钟数；0 表示不自动锁。
   * @returns 是否刚刚发生了自动锁。
   */
  expireIdle(minutes) {
    if (!minutes || minutes <= 0) return false
    if (Date.now() - this.lastActivity < minutes * 60_000) return false
    if (this.sessions.size === 0) return false
    this.clear()
    return true
  }

  /** 给客户端看的快照（不含时间细节）。 */
  snapshot() {
    const now = Date.now()
    const alive = (until) => until === 0 || until === Number.MAX_SAFE_INTEGER || until > now
    const sessions = [...this.sessions.entries()]
      .filter(([, entry]) => alive(entry.until))
      .map(([id]) => id)
    return {
      sessions,
      idleMs: now - this.lastActivity,
    }
  }
}
