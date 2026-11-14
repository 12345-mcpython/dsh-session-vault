/**
 * lib/disk.mjs —— 真·磁盘锁：给会话日志文件套 WALLBK 密文，并 patch DSH 的
 * session-persistence-jsonl 后端，让「读」这条链路在内存里透明解密。
 *
 * ============================================================================
 * 为什么 patch 后端方法，而不是 patch node:fs（上一版的失败点）
 * ============================================================================
 * 后端写的是 `import { open } from 'node:fs/promises'`。ESM 从 CJS 里取具名导出是
 * **快照**：`fs.promises.open = ...` 之后，后端手里的 `open` 仍指向老函数，
 * 所以上一版怎么改都「看起来没生效」。
 *
 * 但**类的方法不是快照**：实例上 `this.readFirstZstdLine(...)` 每次都走原型查找，
 * 改原型立即生效。这是这一版唯一的拦截面。
 *
 * ============================================================================
 * 拦截点（读自 dsh-session-persistence-jsonl/lib/index.js）
 * ============================================================================
 *  - `readFirstZstdLine(path)`   ← `list()` → `listArtifacts()` → `readGenerationHeader()`
 *      都走它；`stat()` 也走它。锁定时返回同目录明文 `.header`，所以**会话始终在侧边栏**。
 *  - `decodeStoredLog(path, id, buffer, ...)` ← 正文解码的唯一入口
 *      （`requireStoredLog` 与 `readStoredLog` 都汇到这里）。密文先解成 zstd 字节流，
 *      再交给原方法解码 —— 原方法的 zstd 逻辑一个字都不用改。
 *  - `appendLines(meta, events)` ← 追加事件。密文文件先解、追加、再整体加密回去。
 *  - `repair(meta, offset)`      ← 截断撕裂尾，偏移量按明文算。
 *  - `open(id, 'write')`         ← 锁定时直接拒绝写入，避免往密文里掺明文。
 *
 * 文件格式沿用 `WALLBK`（magic + version + scrypt 参数 + salt + nonce + GCM），
 * 和导出的 .enc 备份是同一套容器。
 */
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { zstdDecompressSync } from 'node:zlib'

/** 明文头旁路文件的后缀：`session.v4.jsonl.zstd.header`。 */
export const HEADER_SUFFIX = '.header'

/** 一次读进内存的上限：再大就拒绝（会话日志正常是几 MB，加密整套是字节级操作）。 */
const MAX_BYTES = 512 * 1024 * 1024

/** 后端原型上必须存在的方法；缺一个就降级成纯界面锁，绝不猜。 */
const HOOKS = ['readFirstZstdLine', 'decodeStoredLog', 'appendLines', 'repair', 'open']

const PATCH_FLAG = Symbol.for('@local/dsh-session-vault/disk-patched')

/** 锁定的会话被读正文时抛的错（客户端 gate 会盖住它）。 */
function lockedError(id) {
  const error = new Error(`会话 ${id} 已锁定：磁盘上只有密文，先输入口令解锁`)
  error.code = 'SESSION_LOCKED'
  error.sessionId = id
  return error
}

/** 临时文件后缀：`session.v4.jsonl.zstd.<hex>.vault-tmp`。 */
const TEMP_SUFFIX = '.vault-tmp'

/**
 * 本进程正在写的临时文件。启动清理时不能删它们 —— Windows 上打开的文件删不掉，
 * 而且删掉正在写的 tmp 会让这次写到一半的 rename 永远失败。
 * @type {Set<string>}
 */
const activeTemps = new Set()

/**
 * 在 rename 之前把 tmp 的内容刷到盘上。
 *
 * 没有 fsync 时，rename 可能先落盘、数据块还没落盘 —— 断电后留下一个「文件名对、
 * 内容截断」的会话文件，AES-GCM 会直接判定它损坏。某些网络盘 / 虚拟盘不支持
 * fsync：静默跳过，绝不能因此拒绝正常写入（否则等于「盘不支持就不给用」）。
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
 * 原子写：tmp + fsync + rename，避免中途崩出一个半截文件。
 * Windows 上目标文件可能正被杀软/索引器短暂占用（EPERM/EBUSY），所以重试几次。
 * @param file - 目标路径。
 * @param bytes - 要写入的完整内容。
 */
async function writeAtomic(file, bytes) {
  const tmp = `${file}.${randomBytes(6).toString('hex')}${TEMP_SUFFIX}`
  // 先登记再写：启动清理与写操作并发时，清理方必须能看见这个路径。
  activeTemps.add(tmp)
  try {
    writeFileSync(tmp, bytes)
    syncFile(tmp)
    let lastError = null
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        renameSync(tmp, file)
        return
      } catch (error) {
        lastError = error
        await new Promise((resolve) => setTimeout(resolve, 25 * (attempt + 1)))
      }
    }
    try { unlinkSync(tmp) } catch { /* ignore */ }
    throw new Error(`写回 ${file} 失败：${lastError?.message ?? lastError}`)
  } finally {
    activeTemps.delete(tmp)
  }
}

/**
 * 清理上次进程崩溃留下的 `*.vault-tmp`。
 *
 * 约束：
 *  - 只删**文件**，且文件名必须以 `.vault-tmp` 结尾；
 *  - 只从 `sessionsRoot` 往下走，跳过符号链接（不会顺着链接跑到会话目录之外）；
 *  - 本进程正在写的 tmp 跳过；
 *  - 删不掉就跳过，绝不抛错（清理失败不能影响插件加载）。
 *
 * @param sessionsRoot - 会话根目录。
 * @returns 实际删掉的个数。
 */
export function sweepTempFiles(sessionsRoot) {
  const root = sessionsRoot ? String(sessionsRoot) : ''
  if (!root || !existsSync(root)) return 0
  let removed = 0
  /** 会话文件实际只到 `root/项目/会话/文件`，深度上限只是防御异常目录结构。 */
  const MAX_DEPTH = 4
  const walk = (dir, depth) => {
    if (depth > MAX_DEPTH) return
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      // 符号链接一律不跟：否则可能删到会话目录以外的东西。
      if (entry.isSymbolicLink()) continue
      const p = join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(p, depth + 1)
        continue
      }
      if (!entry.isFile()) continue
      if (!entry.name.endsWith(TEMP_SUFFIX)) continue
      if (activeTemps.has(p)) continue
      try {
        unlinkSync(p)
        removed += 1
      } catch { /* 被占用 / 没权限就跳过 */ }
    }
  }
  walk(root, 0)
  return removed
}

/** 明文 header 旁路文件路径。 */
export function headerPathOf(file) {
  return file + HEADER_SUFFIX
}

/** 从一整段 zstd 明文里切出第一行（没有换行就整段）。 */
function firstLineOf(text) {
  const nl = text.indexOf('\n')
  return nl === -1 ? text : text.slice(0, nl)
}

/**
 * 解压一段 zstd 字节流并取第一行；只用于「密文文件没有 .header 旁路」的兜底。
 * @returns 第一行字符串；解不开返回 ''。
 */
function firstLineOfZstd(bytes) {
  try {
    const plain = zstdDecompressSync(bytes, { maxOutputLength: 1024 * 1024 })
    return firstLineOf(plain.toString('utf8'))
  } catch {
    return ''
  }
}

/**
 * 构建磁盘锁。
 * @param deps - `{ getState, setState, grants, log, paths, crypto }`
 *   - `getState()`/`setState()` 状态读写（判断 locks[id].disk / 补登孤儿）
 *   - `grants` 内存授权表（磁盘钥匙 / 内存口令）
 *   - `paths` 会话文件定位工具
 *   - `crypto` WALLBK 容器操作
 * @returns 磁盘锁门面。
 */
export function createDiskLock(deps) {
  const { getState, setState, grants, log, paths, crypto } = deps

  let proto = null
  let saved = null
  let service = null
  let available = false

  /** 这条会话是不是被登记成磁盘锁。 */
  const isDiskLocked = (id) => {
    const row = id ? getState().locks[id] : undefined
    return Boolean(row && row.disk === true)
  }

  /** 文件是不是我们加密过的（只看 8 字节 magic）。 */
  const isSealed = (file) => {
    try {
      return crypto.isVaultFile(file)
    } catch {
      return false
    }
  }

  /** 读明文 header 旁路（不存在返回 undefined）。 */
  const readHeader = (file) => {
    try {
      const p = headerPathOf(file)
      if (!existsSync(p)) return undefined
      const text = readFileSync(p, 'utf8').trim()
      return text.length > 0 ? text : undefined
    } catch {
      return undefined
    }
  }

  /** 写明文 header 旁路。 */
  const writeHeader = (file, line) => {
    try {
      writeFileSync(headerPathOf(file), line, 'utf8')
      return true
    } catch (error) {
      log(`写明文 header 失败 ${file}：${error?.message ?? error}`)
      return false
    }
  }

  const removeHeader = (file) => {
    try { unlinkSync(headerPathOf(file)) } catch { /* 没有就算了 */ }
  }

  /**
   * 解一把密文：只用内存里的磁盘钥匙（授权到期 = 钥匙没了 = 读不出来）。
   * @returns 明文（zstd 字节流）Buffer；拿不到钥匙返回 null。
   */
  const decryptAny = (id, buffer) => {
    const diskKey = grants.keyFor(id)
    if (!diskKey) return null
    try {
      return crypto.decryptWithKey(buffer, diskKey)
    } catch {
      return null
    }
  }

  /**
   * 写回密文要用的钥匙 + 盐：沿用文件头自己的盐，保证继续追加不会改钥匙。
   * @returns `{ key, salt }`；没有可用钥匙返回 null。
   */
  const sealKeyFor = (id, buffer) => {
    const diskKey = grants.keyFor(id)
    if (!diskKey) return null
    try {
      crypto.decryptWithKey(buffer, diskKey)
      return { key: diskKey, salt: crypto.readSalt(buffer) }
    } catch {
      return null
    }
  }

  /** 取一段明文 zstd 的第一行（给 header 旁路用）。 */
  const headerLineFrom = async (file) => {
    // 文件此刻还是明文：直接借后端的原方法读（最准，且不重复实现 zstd 帧扫描）。
    if (proto && typeof saved?.readFirstZstdLine === 'function') {
      try {
        const line = await saved.readFirstZstdLine.call(service, file)
        if (typeof line === 'string' && line) return line
      } catch { /* 继续用兜底 */ }
    }
    try {
      return firstLineOfZstd(readFileSync(file))
    } catch {
      return ''
    }
  }

  // ------------------------------------------------------------------ 门面 --

  const disk = {
    /** 后端方法齐不齐（缺就只做界面锁）。 */
    get available() { return available },

    /**
     * 把会话日志加密到磁盘，并留下明文 header 旁路。
     *
     * 盐用**这条会话自己的口令记录**里的盐：密文头和 state 里的记录对得上。
     *
     * @param id - 会话 id。
     * @param key - 32 字节磁盘钥匙。
     * @param salt - 这条会话口令记录的 base64 盐（或 16 字节 Buffer）。
     * @returns `{ encrypted, bytes, header }`。
     */
    async lock(id, key, salt) {
      const file = paths.logFileFor(id)
      if (!file) throw new Error(`找不到会话文件：${id}`)
      const raw = readFileSync(file)
      if (raw.length > MAX_BYTES) throw new Error(`会话文件太大（${raw.length} B），不做磁盘加密`)
      if (crypto.isVaultBuffer(raw)) {
        // 已经是密文：只补 header 旁路，绝不重复加密。
        if (!readHeader(file)) {
          const plain = decryptAny(id, raw)
          if (plain) writeHeader(file, firstLineOfZstd(plain))
        }
        return { encrypted: true, already: true, bytes: raw.length, header: true }
      }

      // 明文阶段先把第一行存下来：锁定时 list() 只能读它。
      const headerLine = await headerLineFrom(file)
      if (headerLine) writeHeader(file, headerLine)

      if (!salt) throw new Error('缺少这条会话口令记录里的盐，不做磁盘加密')
      const sealed = crypto.encryptWithKey(raw, key, salt)
      // 写完立刻解一遍核对长度：绝不把「解不开的密文」留在磁盘上。
      const check = crypto.decryptWithKey(sealed, key)
      if (check.length !== raw.length) throw new Error('加密后自检失败，已放弃（原文件未改动）')
      await writeAtomic(file, sealed)
      return { encrypted: true, bytes: sealed.length, header: Boolean(headerLine) }
    },

    /**
     * 换钥匙：旧钥匙在内存里解开，新钥匙重新加密，只把密文写回磁盘。
     *
     * 改口令时**绝不能**走 unlock() + lock()：unlock() 会先 writeAtomic(file, plain)，
     * 那几百毫秒磁盘上是完整明文。这里解密、换钥匙、加密都在一次 writeAtomic 之前完成，
     * 磁盘上从头到尾只有密文。
     *
     * @param id - 会话 id。
     * @param oldKey - 打开当前密文的 32 字节钥匙。
     * @param newKey - 新记录派生出的 32 字节钥匙。
     * @param newSalt - 新记录的盐（写进密文头，下次靠它派钥匙）。
     * @returns `{ rekeyed, bytes }`。
     */
    async rekey(id, oldKey, newKey, newSalt) {
      const file = paths.logFileFor(id)
      if (!file) throw new Error(`找不到会话文件：${id}`)
      if (!oldKey || !newKey) throw new Error('缺少钥匙，无法换钥匙')
      if (!newSalt) throw new Error('缺少新记录里的盐，无法换钥匙')

      const raw = readFileSync(file)
      // 已经是明文（没勾磁盘锁）：不用换，只保证 header 旁路在。
      if (!crypto.isVaultBuffer(raw)) {
        if (!readHeader(file)) {
          const line = firstLineOfZstd(raw)
          if (line) writeHeader(file, line)
        }
        return { rekeyed: false, alreadyPlain: true, bytes: raw.length }
      }

      const plain = crypto.decryptWithKey(raw, oldKey)
      const sealed = crypto.encryptWithKey(plain, newKey, newSalt)
      // 先用新钥匙解自己刚加密的字节，确认这把钥匙真能打开它。
      const check = crypto.decryptWithKey(sealed, newKey)
      if (check.length !== plain.length) throw new Error('换钥匙自检失败，已放弃（原文件未改动）')

      await writeAtomic(file, sealed)
      return { rekeyed: true, bytes: sealed.length }
    },

    /**
     * 这把钥匙能不能打开这条会话的密文（不是密文就算能开）。
     * 用来挡住「口令对、但文件是老版本别一把钥匙」这种「解了锁却读不出内容」。
     * @param id - 会话 id。
     * @param key - 32 字节钥匙。
     * @returns 能否打开。
     */
    keyOpens(id, key) {
      if (!key) return false
      const file = paths.logFileFor(id)
      if (!file) return true
      try {
        const raw = readFileSync(file)
        if (!crypto.isVaultBuffer(raw)) return true
        crypto.decryptWithKey(raw, key)
        return true
      } catch {
        return false
      }
    },

    /**
     * 用一串口令试开某个密文文件（老版本遗留文件用：钥匙按文件自己的盐派生）。
     * @param id - 会话 id。
     * @param password - 待试口令。
     * @returns 32 字节钥匙；开不了返回 null。
     */
    keyForPassword(id, password) {
      if (!password) return null
      const file = paths.logFileFor(id)
      if (!file) return null
      try {
        const raw = readFileSync(file)
        if (!crypto.isVaultBuffer(raw)) return null
        const key = crypto.deriveFileKey(raw, password)
        crypto.decryptWithKey(raw, key)
        return key
      } catch {
        return null
      }
    },

    /**
     * 把会话日志解回明文（永久解锁）。
     * @param id - 会话 id。
     * @param key - 磁盘钥匙（可能为空，老格式文件用口令）。
     * @param password - 明文口令，用于老格式文件。
     */
    async unlock(id, key, password) {
      const file = paths.logFileFor(id)
      if (!file) throw new Error(`找不到会话文件：${id}`)
      const raw = readFileSync(file)
      if (!crypto.isVaultBuffer(raw)) {
        removeHeader(file)
        return { restored: false, alreadyPlain: true, bytes: raw.length }
      }
      let plain = null
      if (key) {
        try { plain = crypto.decryptWithKey(raw, key) } catch { plain = null }
      }
      if (!plain && password) {
        try {
          plain = crypto.decryptWithKey(raw, crypto.deriveFileKey(raw, password))
        } catch { plain = null }
      }
      if (!plain) throw new Error('口令不对，解不开这个会话文件')
      await writeAtomic(file, plain)
      removeHeader(file)
      return { restored: true, bytes: plain.length }
    },

    /** 启动时把「已经是密文但没登记」的会话补登进来（上一版留下的坑）。 */
    adopt() {
      const state = getState()
      let added = 0
      for (const { id, file } of paths.listLogFiles()) {
        if (!id || state.locks[id]) continue
        if (!isSealed(file)) continue
        state.locks[id] = { title: '', lockedAt: Date.now(), disk: true, orphan: true }
        added += 1
        log(`发现未登记的密文会话 ${id}（.header ${readHeader(file) ? '有' : '缺失'}），已登记为磁盘锁`)
      }
      if (added > 0) setState(state)
      return added
    },

    /**
     * 装上后端补丁。幂等；取不到后端就返回 false（插件照常做界面锁）。
     * @param persistence - `ctx.get('sessionPersistence')`。
     * @returns 是否装上。
     */
    install(persistence) {
      if (available) return true
      service = persistence ?? null
      if (!service) {
        log('拿不到 sessionPersistence，磁盘锁不可用（界面锁照常）')
        return false
      }
      let instanceProto
      try {
        instanceProto = Object.getPrototypeOf(service)
      } catch {
        instanceProto = null
      }
      if (!instanceProto || instanceProto[PATCH_FLAG] === true) {
        // 后端补丁已被同一进程里的另一个插件实例占着。不重复包一层（会双解密），
        // 本实例也就不能安全地做磁盘锁 —— 降级成只做界面锁，别把文件写成没人能读的密文。
        if (instanceProto && instanceProto[PATCH_FLAG] === true) {
          log('session-persistence 后端补丁已被另一个实例安装，本实例降级为仅界面锁')
        }
        return false
      }
      const missing = HOOKS.filter((name) => typeof instanceProto[name] !== 'function')
      if (missing.length > 0) {
        log(`session-persistence 后端缺少方法 ${missing.join(', ')}，磁盘锁不可用（界面锁照常）`)
        return false
      }

      proto = instanceProto
      /*
       * 读 header 这一层由 `backend-patch.js` 负责（它按口令解密后返回 header 行）。
       * 这里**只加一层兜底**，不重复实现解密：
       *   - 锁定时 backend-patch 没有口令 → 返回 undefined → list() 会把会话跳过，
       *     会话就从侧边栏消失了（这正是上一版被投诉的现象）。所以密文文件优先
       *     读同目录的明文 `.header` 旁路：它是锁定时唯一还能读的东西。
       */
      const readFirstZstdLineBefore = instanceProto.readFirstZstdLine
      saved = {
        readFirstZstdLine: readFirstZstdLineBefore,
        decodeStoredLog: instanceProto.decodeStoredLog,
        appendLines: instanceProto.appendLines,
        repair: instanceProto.repair,
        open: instanceProto.open,
        encodeEventBatch: instanceProto.encodeEventBatch,
      }

      // ① 会话头：密文文件优先用明文旁路，其它情况交给 backend-patch 的版本。
      instanceProto.readFirstZstdLine = async function patchedReadFirstZstdLine(path, signal) {
        if (path && isSealed(path)) {
          const head = readHeader(path)
          if (head !== undefined) return head
          try {
            const line = await readFirstZstdLineBefore.call(this, path, signal)
            if (line !== undefined) return line
          } catch (error) {
            log(`读会话头失败 ${path}：${error?.message ?? error}`)
          }
          return undefined
        }
        return readFirstZstdLineBefore.call(this, path, signal)
      }

      // ② 正文：密文先解成 zstd 字节流，再交给原方法解码。
      instanceProto.decodeStoredLog = async function patchedDecodeStoredLog(path, expectedId, buffer, revision, signal) {
        if (buffer && crypto.isVaultBuffer(buffer)) {
          const id = expectedId || paths.sessionIdFromPath(path) || ''
          const plain = decryptAny(id, buffer)
          if (!plain) throw lockedError(id || String(path))
          return saved.decodeStoredLog.call(this, path, expectedId, plain, revision, signal)
        }
        return saved.decodeStoredLog.call(this, path, expectedId, buffer, revision, signal)
      }

      // ③ 追加：解 → 追加 → 重新整体加密。写完磁盘上仍是密文。
      instanceProto.appendLines = async function patchedAppendLines(meta, events) {
        const id = meta?.id ? String(meta.id) : ''
        const file = id ? paths.logFileFor(id, meta?.cwd) : null
        if (!file || !isSealed(file)) return saved.appendLines.call(this, meta, events)
        const buffer = readFileSync(file)
        const plain = decryptAny(id, buffer)
        if (!plain) throw lockedError(id)
        const seal = sealKeyFor(id, buffer)
        if (!seal) throw lockedError(id)
        // encodeEventBatch 没被我们替换，取实例上的原方法即可。
        const encode = typeof this.encodeEventBatch === 'function' ? this.encodeEventBatch : saved.encodeEventBatch
        if (typeof encode !== 'function') throw new Error('session-persistence 后端没有 encodeEventBatch，无法追加')
        const content = await encode.call(this, events)
        await writeAtomic(file, crypto.encryptWithKey(Buffer.concat([plain, content]), seal.key, seal.salt))
      }

      // ④ 截断撕裂尾：偏移量按明文算，再整体加密回去。
      instanceProto.repair = async function patchedRepair(meta, offset) {
        const id = meta?.id ? String(meta.id) : ''
        const file = id ? paths.logFileFor(id, meta?.cwd) : null
        if (!file || !isSealed(file)) return saved.repair.call(this, meta, offset)
        const buffer = readFileSync(file)
        const plain = decryptAny(id, buffer)
        if (!plain) throw lockedError(id)
        const seal = sealKeyFor(id, buffer)
        if (!seal) throw lockedError(id)
        const cut = Math.max(0, Math.min(Number(offset) || 0, plain.length))
        await writeAtomic(file, crypto.encryptWithKey(plain.subarray(0, cut), seal.key, seal.salt))
      }

      // ⑤ 锁定时拒绝写打开：否则会往密文里掺明文，把文件彻底弄坏。
      instanceProto.open = async function patchedOpen(id, access, options) {
        if (access === 'write' && isDiskLocked(id) && !grants.keyFor(id)) {
          throw lockedError(id)
        }
        return saved.open.call(this, id, access, options)
      }

      instanceProto[PATCH_FLAG] = true
      available = true
      log('session-persistence 后端补丁已挂上（readFirstZstdLine / decodeStoredLog / appendLines / repair / open）')
      return true
    },

    /** 卸载时还原原型，不留痕迹。 */
    dispose() {
      if (!proto || !saved) return
      for (const [name, original] of Object.entries(saved)) {
        try { proto[name] = original } catch { /* 服务可能已经销毁 */ }
      }
      try { delete proto[PATCH_FLAG] } catch { /* ignore */ }
      saved = null
      proto = null
      available = false
    },
  }

  return disk
}
