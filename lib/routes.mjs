/**
 * lib/routes.mjs —— `/api/session.vault` 路由族（会话锁）。
 *
 * 设计规则（别改，改之前先看这条）：
 *  - 这条路由注册在 DSH 自己的 `/api` 精确路由表里，所以它**天然**继承了
 *    宿主那道信任栅栏 + 浏览器签名 cookie 鉴权；不像自己挂 `/api/xxx` 前缀那样
 *    还得手写一遍回环检查。
 *  - 上锁（lock）必须带这条会话的口令；磁盘加密本来就需要钥匙，没有口令就
 *    建不了锁记录（不存在全局兜底）。
 *  - 所有**解锁 / 改口令**动作都必须带这条会话的口令，且口令只从请求体读、不落日志。
 *  - 清除 / 策略只是本地维护动作，收紧权限或改偏好不需要再验口令。
 *  - **每条会话独立口令**：口令记录只存在 `locks[id].password` 里，没有全局口令。
 *    `status` 永远不回记录本身（盐 / 派生值都不回）。
 */
import {
  MIN_PASSWORD_LENGTH,
  deriveDiskKey,
  forgetAllDiskKeys,
  forgetDiskKey,
  makePasswordRecord,
  verifyPassword,
} from './secret.mjs'
import { lockPasswordOf, passwordCandidates } from './state.mjs'

/** 请求体上限：本路由族最大的请求是「口令 + 一两个 id」，64KB 足够。 */
const MAX_BODY_BYTES = 64 * 1024

/** 读 JSON 请求体。 */
export async function readJson(request) {
  try {
    const text = await request.text()
    if (!text || text.length > MAX_BODY_BYTES) return {}
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

/** 写一个 JSON 响应。 */
export function sendJson(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    },
  })
}

/** 已经磁盘锁定的会话数量（清除之前要先处理掉它们）。 */
function diskLocked(state) {
  return Object.entries(state.locks).filter(([, row]) => row.disk === true)
}

/**
 * 构建路由处理器。
 *
 * @param deps - 由 host 半侧注入的依赖：
 *   `getState`/`setState` 状态读写、`grants` 授权表、`disk` 磁盘锁、
 *   `log` 日志、`version` 版本号。
 * @returns {(request: Request) => Promise<Response>} 一个 Fetch 路由处理器。
 */
export function makeHandler(deps) {
  const { getState, setState, grants, disk, keys, log, version, onChanged } = deps

  const statusBody = () => {
    const state = getState()
    if (grants.expireIdle(state.policy.autoLockMinutes)) {
      // 两本账一起清：backend-patch 的表里还留着口令的话，会话头照样能解出来。
      try { keys?.clearAll() } catch { /* ignore */ }
      forgetAllDiskKeys()
      log('空闲超时，已撤销全部临时解锁')
    }
    return {
      ok: true,
      version,
      policy: state.policy,
      locks: Object.entries(state.locks).map(([id, row]) => ({
        sessionId: id,
        title: row.title || '',
        lockedAt: row.lockedAt,
        disk: row.disk === true,
        orphan: row.orphan === true,
        // 只暴露「有没有改口令留下的旧记录」这一个布尔值；盐 / 派生值一律不出。
        hasPrevious: passwordCandidates(row).length > 1,
      })),
      grants: grants.snapshot(),
      minPasswordLength: MIN_PASSWORD_LENGTH,
      diskAvailable: Boolean(disk && disk.available),
    }
  }

  const handlers = {
    /** 只读状态：客户端每次切换会话 / 周期轮询都打这条。 */
    status: async () => ({ body: statusBody() }),

    /**
     * 改一条会话的口令（并重新加密它的磁盘文件）。
     *
     * 三步顺序不能反（这是「两个口令都打不开」那条崩溃问题的修法）：
     *   ① 先把「新旧两条记录」写进 state —— 此刻文件还是旧钥匙，写失败就原地返回；
     *   ② 再换钥匙 —— 失败时 state 里还有 passwordPrevious，旧口令照样能开；
     *   ③ 换钥匙成功后才删 previous —— 这次写失败无所谓，下次改口令 / 验口令会再处理。
     */
    password: async (body) => {
      const state = getState()
      const sessionId = String(body.sessionId ?? '')
      if (!sessionId) return { status: 400, body: { ok: false, error: '缺少 sessionId' } }
      const next = String(body.newPassword ?? '')
      if (next.length < MIN_PASSWORD_LENGTH) {
        return { status: 400, body: { ok: false, error: `口令至少 ${MIN_PASSWORD_LENGTH} 位` } }
      }
      const currentPassword = String(body.currentPassword ?? body.password ?? '')
      const row = state.locks[sessionId]
      if (!row) return { status: 404, body: { ok: false, error: '这个会话没有锁，无法改口令' } }
      const candidates = passwordCandidates(row)
      if (candidates.length === 0) {
        return { status: 409, body: { ok: false, error: '这个会话没有口令记录' } }
      }
      // 一次验完所有候选：改口令窗口里最多两条，别在下面的循环里重复跑 scrypt。
      const verified = candidates.filter((rec) => verifyPassword(rec, currentPassword))
      if (verified.length === 0) {
        return { status: 401, body: { ok: false, error: '口令不对' } }
      }

      const needsDisk = row.disk === true && Boolean(disk && disk.available)
      /*
       * 上次改口令如果在「换钥匙成功、清理 previous」之间崩过，state 里会有两条记录，
       * 但只有一条的钥匙能打开现在的文件。必须找出那一条：既要用它派生旧钥匙，
       * 也要把它留作新的 passwordPrevious —— 否则这次再崩一次就真的锁死了。
       */
      let opening = null
      let oldKey = null
      if (needsDisk) {
        for (const cand of verified) {
          let key = null
          try { key = deriveDiskKey(cand, currentPassword) } catch { key = null }
          if (key && disk.keyOpens(sessionId, key)) {
            opening = cand
            oldKey = key
            break
          }
        }
        if (!opening) {
          log(`改口令被拒 ${sessionId}：口令对得上记录，但打不开磁盘文件`)
          return {
            status: 409,
            body: {
              ok: false,
              needsPassword: true,
              error: '这个口令对得上记录，但打不开磁盘文件：上一次换钥匙可能只完成了一半，请换用另一个口令再试',
            },
          }
        }
      } else {
        opening = verified[0]
      }

      // 换盐 = 换钥匙。用 disk.rekey() 在内存里解密-重加密，
      // **不经过明文落盘**：unlock() + lock() 那条路会先写一份明文再加密回来。
      const rec = makePasswordRecord(next)

      // ① 新旧两条记录一起落盘；文件此刻还没动。
      state.locks[sessionId] = { ...row, password: rec, passwordPrevious: opening, disk: row.disk === true }
      try {
        setState(state)
      } catch (error) {
        log(`改口令写状态失败 ${sessionId}：${error?.message ?? error}`)
        return {
          status: 500,
          body: { ok: false, error: `状态写入失败，会话文件没有改动：${error?.message ?? error}` },
        }
      }

      // ② 换钥匙。失败就把 state 留在「新旧都能试」的样子，旧口令仍然可用。
      let diskOk = row.disk === true
      if (needsDisk) {
        try {
          const out = await disk.rekey(sessionId, oldKey, deriveDiskKey(rec, next), rec.salt)
          diskOk = out?.alreadyPlain ? false : true
        } catch (error) {
          forgetDiskKey(rec)
          log(`改口令后换钥匙失败 ${sessionId}（旧口令仍可解锁）：${error?.message ?? error}`)
          return {
            status: 500,
            body: { ok: false, error: `换钥匙失败，旧口令仍然可用：${error?.message ?? error}` },
          }
        }
      }

      // ③ 换钥匙成功，清掉 previous。这一步失败不影响解锁：留下的两条记录里，
      //    能打开文件的那条照样能开，下次改口令时会被重新收敛。
      //
      //    唯一例外：这条会话标着磁盘锁，但磁盘锁后端现在不可用（needsDisk=false，
      //    根本没换钥匙）。这时删掉 previous 会让新记录配上一份旧钥匙的密文 ——
      //    等后端恢复就再也打不开了。保留 previous，等能换钥匙时再收敛。
      const keepPrevious = row.disk === true && !needsDisk
      const latest = getState()
      const current = latest.locks[sessionId]
      if (current) {
        const done = { ...current, disk: diskOk }
        if (keepPrevious) {
          log(`磁盘锁后端不可用，改口令时保留 passwordPrevious ${sessionId}（等能换钥匙时再清）`)
        } else {
          delete done.passwordPrevious
        }
        latest.locks[sessionId] = done
        try {
          setState(latest)
        } catch (error) {
          log(`改口令后清理 passwordPrevious 失败 ${sessionId}（不影响解锁）：${error?.message ?? error}`)
        }
      }

      for (const cand of candidates) forgetDiskKey(cand)
      grants.revoke(sessionId)
      try { keys?.clear(sessionId) } catch { /* ignore */ }
      log(`会话 ${sessionId} 的口令已修改，临时授权已撤销`)
      return { body: { ok: true, ...statusBody() } }
    },

    /**
     * 验口令 → 放行一条会话。
     *
     * 没有口令记录的锁只可能是上一版「原地加密」留下的 orphan 密文：
     * 它的钥匙按文件自己的盐派生，只能拿当初加密时那串口令试开。
     */
    verify: async (body) => {
      const state = getState()
      const password = String(body.password ?? '')
      const sessionId = typeof body.sessionId === 'string' && body.sessionId ? body.sessionId : ''
      if (!sessionId) return { status: 400, body: { ok: false, error: '缺少 sessionId' } }
      const row = state.locks[sessionId]
      if (!row) return { status: 404, body: { ok: false, error: '这个会话没有锁' } }
      const minutes = state.policy.autoLockMinutes

      const accept = (key) => {
        grants.grantSession(sessionId, minutes, key)
        // backend-patch 那边也要拿到口令（它按口令自己派生钥匙）。
        try { keys?.set(sessionId, password) } catch { /* ignore */ }
      }
      /** orphan 老密文：用文件自己的盐试开这串口令。 */
      const rescue = () => {
        if (row.orphan !== true || !disk || !disk.available || !password) return null
        return disk.keyForPassword(sessionId, password)
      }

      const candidates = passwordCandidates(row)
      if (candidates.length === 0) {
        const rescued = rescue()
        if (rescued) {
          accept(rescued)
          log(`会话 ${sessionId} 用文件自己的口令解锁（老版本密文）`)
          return { body: { ok: true, ...statusBody() } }
        }
        return {
          status: 401,
          body: { ok: false, error: '这个会话是老版本加密的：要用当初加密时那个口令才能打开' },
        }
      }

      /*
       * 逐条候选试：口令对**且**这条记录派生出的钥匙真能打开文件，才算解锁。
       *
       * 改口令中途崩溃会留下「当前 + passwordPrevious」两条记录，只有其中一条的
       * 钥匙能打开现在的文件。不能只看「口令对」就放行 —— 否则用户会看到解锁成功、
       * 正文却还是读不出来；也不能因为第一条打不开就直接判定口令错。
       */
      let matchedButLocked = false
      for (const rec of candidates) {
        if (!verifyPassword(rec, password)) continue
        let key = null
        try { key = deriveDiskKey(rec, password) } catch { key = null }
        if (row.disk === true && disk && disk.available && (!key || !disk.keyOpens(sessionId, key))) {
          matchedButLocked = true
          continue
        }
        accept(key)
        log(`已解锁会话 ${sessionId}`)
        return { body: { ok: true, ...statusBody() } }
      }

      // 记录都对不上时，最后再试「老版本密文用文件自己的盐」这条路。
      const rescued = rescue()
      if (rescued) {
        accept(rescued)
        log(`会话 ${sessionId} 用文件自己的口令解锁（老版本密文）`)
        return { body: { ok: true, ...statusBody() } }
      }
      if (matchedButLocked) {
        return {
          status: 409,
          body: {
            ok: false,
            needsPassword: true,
            error: '口令对得上记录，但打不开磁盘文件：上一次换钥匙可能只完成了一半，请换用另一个口令再试',
          },
        }
      }
      return { status: 401, body: { ok: false, error: '口令不对' } }
    },

    /** 心跳：客户端有操作就报一声，服务端据此判断空闲超时。 */
    touch: async () => {
      grants.touch()
      return { body: { ok: true } }
    },

    /**
     * 上锁。disk=true 时顺手加密磁盘文件。
     *
     * 口令来源：
     *   ① 请求里带 password —— 新锁就用它写一条**自己的**口令记录；
     *      已经是这个口令的锁则复用原记录（盐不变，钥匙不变）。
     *   ② 这条锁本来就有自己的口令记录 —— 沿用。
     *   ③ 都没有 —— 拒绝：没有现成口令就无从加密，也不存在全局兜底。
     *
     * 磁盘钥匙优先用记录现算；没有明文时用本进程里已经派生过的钥匙（验过一次/
     * 刚设完口令），所以「侧栏一键上锁」不用再输一遍口令。
     */
    lock: async (body) => {
      const state = getState()
      const sessionId = String(body.sessionId ?? '')
      if (!sessionId) return { status: 400, body: { ok: false, error: '缺少 sessionId' } }
      const previous = state.locks[sessionId]
      const previousOwn = lockPasswordOf(previous)
      const title = typeof body.title === 'string' ? body.title : (previous?.title ?? '')
      const wantDisk = body.disk === undefined ? state.policy.diskLock : body.disk === true
      const bodyPassword = typeof body.password === 'string' && body.password ? body.password : ''
      if (bodyPassword && bodyPassword.length < MIN_PASSWORD_LENGTH) {
        return { status: 400, body: { ok: false, error: `口令至少 ${MIN_PASSWORD_LENGTH} 位` } }
      }

      /** 这条会话自己的记录。 */
      let own = previousOwn
      let plain = ''
      let rotated = false
      if (bodyPassword) {
        // 带了口令：这条会话从此用自己的记录。
        if (previousOwn && verifyPassword(previousOwn, bodyPassword)) {
          own = previousOwn
        } else {
          own = makePasswordRecord(bodyPassword)
          rotated = true
        }
        plain = bodyPassword
      }
      if (!own) {
        return { status: 409, body: { ok: false, error: '先给这个会话设一条口令，再上锁' } }
      }
      /*
       * 一条已经加密到磁盘的会话，如果这次要换一把新钥匙（新盐），就必须同时
       * 重新加密它的文件；只锁界面地换记录会把密文的钥匙弄丢。
       */
      if (rotated && previous?.disk === true && !wantDisk) {
        return {
          status: 409,
          body: { ok: false, error: '这个会话已经加密到磁盘：换口令时要带 disk:true 一起重新加密' },
        }
      }
      const record = own

      let diskResult = null
      if (wantDisk && disk && disk.available) {
        let key = null
        try { key = deriveDiskKey(record, plain || undefined) } catch { key = null }
        if (!key) {
          return {
            status: 401,
            body: { ok: false, error: '把会话加密到磁盘需要口令（本进程里还没有验过）', needsPassword: true },
          }
        }
        /*
         * 文件已经是密文但这把钥匙开不了：可能是老版本的 orphan 密文。
         * 有明文就按文件自己的盐救回明文，再用新钥匙重新加密；救不回就拒绝，
         * 绝不把一条读不出来的密文和一条新记录配在一起。
         */
        if (plain && !disk.keyOpens(sessionId, key)) {
          try {
            await disk.unlock(sessionId, null, plain)
          } catch {
            return {
              status: 401,
              body: { ok: false, error: '口令不对，解不开这个会话文件', needsPassword: true },
            }
          }
        }
        try {
          diskResult = await disk.lock(sessionId, key, record.salt)
        } catch (error) {
          // 磁盘加密失败就退化成「只锁界面」并如实报告，绝不留下半截密文。
          log(`磁盘加密失败 ${sessionId}：${error?.message ?? error}`)
          diskResult = { skipped: String(error?.message ?? error) }
        }
      }

      const row = {
        title: title || previous?.title || '',
        lockedAt: Date.now(),
        // 没有做磁盘操作时保留原来的 disk 标记：一条已经加密到磁盘的会话被
        // 「只锁界面」重锁后，文件仍是密文，标成 false 会让永久解锁漏掉解密。
        disk: diskResult ? Boolean(diskResult.encrypted) : Boolean(previous?.disk === true),
        // 老密文重锁时保留 orphan 标记，否则「用文件自己的口令救回」这条路就断了。
        orphan: Boolean(previous?.orphan && (!diskResult || diskResult.already)),
        password: own,
      }
      state.locks[sessionId] = row
      setState(state)
      grants.revoke(sessionId)
      try { keys?.clear(sessionId) } catch { /* ignore */ }
      log(`已锁定会话 ${sessionId}${diskResult?.encrypted ? '（磁盘已加密）' : ''}`)
      return { body: { ok: true, disk: diskResult, ...statusBody() } }
    },

    /** 解除某会话的锁（要口令）。磁盘锁会先把文件解回明文，再删掉锁记录。 */
    'unlock-session': async (body) => {
      const state = getState()
      const sessionId = String(body.sessionId ?? '')
      if (!sessionId) return { status: 400, body: { ok: false, error: '缺少 sessionId' } }
      const row = state.locks[sessionId]
      const password = String(body.password ?? '')
      const candidates = passwordCandidates(row)
      if (candidates.length === 0) {
        // 老版本遗留密文：允许用「加密时那个口令」把它解回明文，这是唯一的救回路径。
        if (row && row.orphan === true && disk && disk.available && password) {
          try {
            const restored = await disk.unlock(sessionId, null, password)
            delete state.locks[sessionId]
            setState(state)
            grants.revoke(sessionId)
            try { keys?.clear(sessionId) } catch { /* ignore */ }
            log(`已用文件自己的口令救回老版本密文会话 ${sessionId}`)
            return { body: { ok: true, restored, ...statusBody() } }
          } catch {
            return { status: 401, body: { ok: false, error: '口令不对，解不开这个会话文件' } }
          }
        }
        return { status: 409, body: { ok: false, error: '这个会话没有口令记录' } }
      }

      // 同 verify：改口令窗口里可能有两记录，只有一条的钥匙能打开文件。
      let chosen = null
      let key = null
      let matchedButLocked = false
      for (const rec of candidates) {
        if (!verifyPassword(rec, password)) continue
        let candidateKey = null
        try { candidateKey = deriveDiskKey(rec, password) } catch { candidateKey = null }
        if (row && row.disk === true && disk && disk.available &&
            (!candidateKey || !disk.keyOpens(sessionId, candidateKey))) {
          matchedButLocked = true
          continue
        }
        chosen = rec
        key = candidateKey
        break
      }
      if (!chosen) {
        if (matchedButLocked) {
          return {
            status: 409,
            body: {
              ok: false,
              needsPassword: true,
              error: '口令对得上记录，但打不开磁盘文件：上一次换钥匙可能只完成了一半，请换用另一个口令再试',
            },
          }
        }
        return { status: 401, body: { ok: false, error: '口令不对' } }
      }
      let restored = null
      if (row && row.disk === true && disk && disk.available) {
        try {
          restored = await disk.unlock(sessionId, key, password)
        } catch (error) {
          return { status: 500, body: { ok: false, error: `磁盘解密失败：${error?.message ?? error}` } }
        }
      }
      if (row) delete state.locks[sessionId]
      setState(state)
      grants.revoke(sessionId)
      try { keys?.clear(sessionId) } catch { /* ignore */ }
      for (const cand of candidates) forgetDiskKey(cand)
      log(`已解除会话 ${sessionId} 的锁`)
      return { body: { ok: true, restored, ...statusBody() } }
    },

    /** 撤销临时授权（不需要口令 —— 收紧权限永远安全）。 */
    relock: async (body) => {
      const scope = typeof body.sessionId === 'string' && body.sessionId ? body.sessionId : 'all'
      grants.revoke(scope)
      try {
        if (scope === 'all') keys?.clearAll()
        else keys?.clear(scope)
      } catch { /* ignore */ }
      log(`已撤销授权：${scope}`)
      return { body: { ok: true, ...statusBody() } }
    },

    /** 策略（纯本地偏好，不需要口令）。 */
    policy: async (body) => {
      const state = getState()
      const minutes = Number(body.autoLockMinutes)
      if (Number.isFinite(minutes)) {
        state.policy.autoLockMinutes = Math.max(0, Math.min(24 * 60, Math.floor(minutes)))
      }
      if (typeof body.diskLock === 'boolean') state.policy.diskLock = body.diskLock
      setState(state)
      log(`策略已更新：自动锁定 ${state.policy.autoLockMinutes} 分钟，磁盘锁 ${state.policy.diskLock ? '开' : '关'}`)
      return { body: { ok: true, ...statusBody() } }
    },

    /**
     * 清空：删所有锁。
     * 磁盘上还锁着会话时必须先逐条解除，否则文件会留在没人有钥匙的密文状态。
     */
    clear: async (body) => {
      const state = getState()
      const still = diskLocked(state)
      if (still.length > 0) {
        return { status: 409, body: { ok: false, error: `还有 ${still.length} 个会话锁在磁盘上，请先解除它们的锁` } }
      }
      state.locks = {}
      setState(state)
      forgetAllDiskKeys()
      grants.clear()
      try { keys?.clearAll() } catch { /* ignore */ }
      log('已清除全部锁')
      return { body: { ok: true, ...statusBody() } }
    },
  }

  return async function handle(request) {
    const url = new URL(request.url)
    const action = (url.searchParams.get('action') || 'status').trim()
    const method = (request.method || 'GET').toUpperCase()

    // GET 只读：status；其余一律 POST，避免被 <img>/链接顺手触发。
    if (method === 'GET') {
      if (action !== 'status') {
        return sendJson(405, { ok: false, error: `未知的会话锁 GET 动作: ${action}` })
      }
      return sendJson(200, statusBody())
    }
    if (method !== 'POST') {
      return sendJson(405, { ok: false, error: `不支持的方法: ${method}` })
    }

    const handler = handlers[action]
    if (!handler) {
      return sendJson(404, { ok: false, error: `未知的会话锁动作: ${action}` })
    }
    try {
      const body = await readJson(request)
      const result = await handler(body)
      try { onChanged?.() } catch { /* 诊断写不进去不影响功能 */ }
      return sendJson(result?.status ?? 200, result?.body ?? { ok: true })
    } catch (error) {
      log(`路由失败 ${action}: ${error?.message ?? error}`)
      return sendJson(500, { ok: false, error: String(error?.message ?? error) })
    }
  }
}
