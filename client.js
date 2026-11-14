/**
 * session-vault —— 浏览器半侧：会话锁（界面锁）
 * ============================================================================
 * 挂了五个位置，全部是 **list 类 slot**（single slot 一个都不能碰，否则整个
 * web boot 会崩：`single slot "conversation.session" already has a registration`）：
 *
 *   1. `shell.overlay`                          —— 口令弹窗 / 会话锁设置（核心）
 *   2. `sidebar.workspaces.session.row.action`  —— 侧栏悬停时的「上锁」按钮
 *   3. `sidebar.session.row.trailing`           —— 已锁会话的小锁标记（非交互）
 *   4. `conversation.session.header.utilities`  —— 空探针，只为了拿当前会话 id
 *   5. `settings.section`                       —— 设置页（宿主没开设置时不会有 owner）
 *
 * 纪律：apply 里任何一处挂载失败都只记日志，**绝不向上抛** —— 一个外部插件
 * 不该让整个 Web 壳起不来。
 * ============================================================================
 */
window.__ModuleLoader__.load({
  id: '@local/dsh-session-vault',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useCallback, useEffect, useRef, useState, useSyncExternalStore } = React

    const API = '/api/session.vault'
    const CSS_TAG = '@local/dsh-session-vault/css'

    // ---------------------------------------------------------------- API --
    const api = async (action, body) => {
      const init = body === undefined
        ? { method: 'GET', credentials: 'same-origin', headers: { accept: 'application/json' } }
        : {
            method: 'POST',
            credentials: 'same-origin',
            headers: { accept: 'application/json', 'content-type': 'application/json' },
            body: JSON.stringify(body || {}),
          }
      const res = await fetch(`${API}?action=${encodeURIComponent(action)}`, init)
      let data = null
      try { data = await res.json() } catch { data = null }
      if (!res.ok || (data && data.ok === false)) {
        const error = new Error((data && data.error) || `HTTP ${res.status}`)
        error.status = res.status
        error.data = data
        throw error
      }
      return data || {}
    }

    /**
     * 口令类失败一律只说「口令不对」：不区分「这条没设过口令」和「输错了」，
     * 否则这个提示本身就在告诉别人「这条会话有没有独立口令」。
     */
    const passwordErrorText = (error) => {
      const status = Number(error && error.status)
      if (status === 401 || status === 409) return '口令不对'
      return String((error && error.message) || error)
    }

    // --------------------------------------------------------------- store --
    const initial = {
      phase: 'loading',
      error: '',
      policy: { autoLockMinutes: 10, diskLock: true },
      locks: [],
      lockMap: {},
      grants: { sessions: [], idleMs: 0 },
      minPasswordLength: 6,
      version: '',
      diskAvailable: false,
      currentSessionId: '',
      /** 当前打开的对话框（同一时刻最多一个）。 */
      dialog: null,
      /** 一次性的短提示（解锁成功等），由 showToast 写入、几秒后自己清掉。 */
      toast: null,
      lastSync: 0,
    }

    // -------------------------------------------------------------- toast --
    // 一次只挂一条：新的顶掉旧的，计时器跟着 store 走（store 是模块级单例）。
    const TOAST_MS = 3000
    let toastTimer = null

    /** 磁盘锁解锁会整页重载，提示得跨过这次刷新 —— sessionStorage 存一下。 */
    const PENDING_TOAST_KEY = 'dsv.pending-toast'
    const toastStorage = () => {
      try {
        if (typeof window === 'undefined' || !window) return null
        const storage = window.sessionStorage
        if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') return null
        return storage
      } catch {
        return null
      }
    }
    const rememberToastAcrossReload = (text) => {
      try {
        const storage = toastStorage()
        if (storage && text) storage.setItem(PENDING_TOAST_KEY, String(text))
      } catch { /* 隐私模式禁了存储也不能影响解锁 */ }
    }
    const takeToastAcrossReload = () => {
      try {
        const storage = toastStorage()
        if (!storage) return ''
        const text = storage.getItem(PENDING_TOAST_KEY) || ''
        if (text) storage.removeItem(PENDING_TOAST_KEY)
        return typeof text === 'string' ? text : ''
      } catch {
        return ''
      }
    }

    /** 「10 分钟后自动上锁」/「不会自动上锁」。 */
    const autoLockLabel = (value) => {
      const minutes = Number(value && value.policy ? value.policy.autoLockMinutes : 0)
      if (!Number.isFinite(minutes) || minutes <= 0) return '不会自动上锁'
      return `${Math.floor(minutes)} 分钟后自动上锁`
    }
    const unlockedToastText = (value) => `已解锁 · ${autoLockLabel(value)}`

    const store = {
      value: initial,
      listeners: new Set(),
      busy: false,
      pendingRefresh: false,
      subscribe(listener) {
        store.listeners.add(listener)
        return () => store.listeners.delete(listener)
      },
      getSnapshot() {
        return store.value
      },
      set(patch) {
        store.value = { ...store.value, ...patch }
        for (const listener of store.listeners) {
          try { listener() } catch { /* 单个订阅者出错不影响其它人 */ }
        }
      },
      applyStatus(data) {
        if (!data || data.ok === false) return
        const rows = Array.isArray(data.locks) ? data.locks : []
        const lockMap = {}
        for (const row of rows) {
          if (row && typeof row.sessionId === 'string' && row.sessionId) lockMap[row.sessionId] = row
        }
        // 授权表：真实字段叫 grants（lib/routes.mjs 的 statusBody → grants.snapshot()）；
        // 顺手兼容 unlocked 这个别名，字段缺了也降级成「没解锁」而不是崩。
        const raw = data.grants && typeof data.grants === 'object'
          ? data.grants
          : (data.unlocked && typeof data.unlocked === 'object' ? data.unlocked : null)
        const grants = raw
          ? {
              sessions: Array.isArray(raw.sessions)
                ? raw.sessions.filter((id) => typeof id === 'string' && id)
                : [],
              idleMs: Number(raw.idleMs) || 0,
            }
          : initial.grants
        store.set({
          phase: 'ready',
          error: '',
          policy: data.policy || initial.policy,
          locks: rows,
          lockMap,
          grants,
          minPasswordLength: data.minPasswordLength || 6,
          version: data.version || '',
          diskAvailable: Boolean(data.diskAvailable),
          lastSync: Date.now(),
        })
      },
      /**
       * 拉一次状态。
       * @param options.force - 正在轮询时不要默默丢掉，等这一轮回来后再补一轮，
       *   免得「解锁后立刻刷新」被一个刚发出的轮询请求吞掉、界面上还锁着。
       */
      async refresh(options) {
        const force = Boolean(options && options.force)
        if (store.busy) {
          if (force) store.pendingRefresh = true
          return
        }
        store.busy = true
        try {
          store.applyStatus(await api('status'))
        } catch (error) {
          store.set({
            phase: store.value.phase === 'loading' ? 'error' : store.value.phase,
            error: String(error?.message || error),
          })
        } finally {
          store.busy = false
          if (store.pendingRefresh) {
            store.pendingRefresh = false
            store.refresh({ force: true }).catch(() => {})
          }
        }
      },
      /** 显示一条短提示（2~3 秒后自己消失）。 */
      showToast(text) {
        const message = String(text == null ? '' : text)
        if (!message) return
        if (toastTimer) {
          try { clearTimeout(toastTimer) } catch { /* ignore */ }
          toastTimer = null
        }
        store.set({ toast: { text: message, at: Date.now() } })
        toastTimer = setTimeout(() => {
          toastTimer = null
          const current = store.value.toast
          if (current && current.text === message) store.set({ toast: null })
        }, TOAST_MS)
      },
      dismissToast() {
        if (toastTimer) {
          try { clearTimeout(toastTimer) } catch { /* ignore */ }
          toastTimer = null
        }
        if (store.value.toast) store.set({ toast: null })
      },
      /** 有操作就报一声，服务端据此判断「是不是该自动锁了」。 */
      touchThrottled() {
        const now = Date.now()
        if (now - (store.lastTouch || 0) < 20_000) return
        store.lastTouch = now
        api('touch', {}).catch(() => {})
      },
      openDialog(dialog) {
        store.set({ dialog })
      },
      closeDialog() {
        store.set({ dialog: null })
      },
      setCurrentSessionId(sessionId) {
        if (store.value.currentSessionId === sessionId) return
        store.set({ currentSessionId: sessionId })
      },
      clearCurrentSessionId(sessionId) {
        if (store.value.currentSessionId !== sessionId) return
        store.set({ currentSessionId: '' })
      },
    }

    const useStore = () => useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot)

    /** 这个会话当前是否被临时放行（status 里的 grants：按会话列出）。 */
    const isGranted = (value, sessionId) => {
      if (!value || !sessionId) return false
      const grants = value.grants || {}
      return Array.isArray(grants.sessions) && grants.sessions.includes(sessionId)
    }

    /** 该会话在锁名单里 + 没被临时放行 = 需要拦。 */
    const isSessionLocked = (value, sessionId) => {
      if (!value || !sessionId) return false
      const lockMap = value.lockMap || {}
      if (!lockMap[sessionId]) return false
      return !isGranted(value, sessionId)
    }

    // ----------------------------------------------------------------- CSS --
    /* 配色只用主题里**成对存在**的 token（两套主题都核过）：
       主按钮 = button-primary-fill + label-primary-foreground；
       文字 = label-primary / label-tertiary；
       面 = bg-layer-1/2/3 + border-l2。
       不写死 #fff —— --dsw-alias-brand-primary 在暗色主题里是近白色，写死就是白底白字。 */
    const CSS = `
[data-dsv-locked="1"] [data-conversation-content]{filter:blur(16px) saturate(.7);pointer-events:none;user-select:none;}
[data-dsv-veil]{position:fixed;inset:0;z-index:40;pointer-events:none;
  background:color-mix(in srgb, var(--dsw-alias-bg-base,#151517) 34%, transparent);}
[data-dsv-card]{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:41;
  width:min(392px,calc(100vw - 48px));box-sizing:border-box;padding:20px 20px 16px;border-radius:16px;
  display:flex;flex-direction:column;gap:12px;pointer-events:auto;
  background:var(--dsw-alias-bg-layer-1,#232324);color:var(--dsw-alias-label-primary,#f9fafb);
  border:1px solid var(--dsw-alias-border-l2,rgba(255,255,255,.12));
  box-shadow:0 18px 48px rgba(0,0,0,.42);}
[data-dsv-card] h3{margin:0;font-size:15px;font-weight:600;line-height:22px;display:flex;align-items:center;gap:8px;
  color:var(--dsw-alias-label-primary,#f9fafb);}
[data-dsv-card] p{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary,#979da6);}
[data-dsv-input]{width:100%;box-sizing:border-box;padding:8px 10px;border-radius:9px;font-size:13px;font-family:inherit;
  background:var(--dsw-alias-bg-layer-2,#2c2c2e);color:var(--dsw-alias-label-primary,#f9fafb);
  border:1px solid var(--dsw-alias-border-l2,rgba(255,255,255,.12));}
[data-dsv-input]::placeholder{color:var(--dsw-alias-label-tertiary,#979da6);}
[data-dsv-input]:focus{outline:none;border-color:var(--dsw-alias-brand-primary,#4c8dff);
  box-shadow:0 0 0 2px var(--dsw-alias-interactive-bg-hover-accent,rgba(76,141,255,.22));}
[data-dsv-row]{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
[data-dsv-btn]{padding:7px 12px;border-radius:9px;font-size:12.5px;cursor:pointer;font-family:inherit;white-space:nowrap;
  border:1px solid var(--dsw-alias-border-l2,rgba(255,255,255,.12));
  background:var(--dsw-alias-bg-layer-3,#353638);color:var(--dsw-alias-label-primary,#f9fafb);}
[data-dsv-btn]:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.08));}
[data-dsv-btn][data-primary]{background:var(--dsw-alias-button-primary-fill,#0f1115);
  border-color:transparent;color:var(--dsw-alias-label-primary-foreground,#ffffff);font-weight:600;}
[data-dsv-btn][data-primary]:hover{background:var(--dsw-alias-button-primary-hover,#3c3c3d);}
[data-dsv-btn][data-danger]{background:transparent;color:#f87171;border-color:rgba(248,113,113,.45);}
[data-dsv-btn][data-danger]:hover{background:var(--dsw-alias-interactive-bg-hover-danger,rgba(239,68,68,.08));}
[data-dsv-btn][disabled]{opacity:.45;cursor:default;}
[data-dsv-err]{font-size:11.5px;line-height:17px;color:#f87171;min-height:17px;}
[data-dsv-ok]{font-size:11.5px;line-height:17px;color:#34d399;min-height:17px;}
[data-dsv-hint]{font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary,#979da6);}
[data-dsv-caption]{font-size:12.5px;font-weight:600;color:var(--dsw-alias-label-primary,#f9fafb);}
[data-dsv-item]{display:flex;gap:8px;align-items:center;padding:7px 9px;border-radius:9px;font-size:12.5px;
  background:var(--dsw-alias-bg-layer-2,#2c2c2e);color:var(--dsw-alias-label-primary,#f9fafb);}
[data-dsv-item] [data-dsv-grow]{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
[data-dsv-tag]{font-size:10.5px;padding:1px 7px;border-radius:999px;border:1px solid currentColor;opacity:.9;}
[data-dsv-tag][data-disk]{color:#fbbf24;}
[data-dsv-tag][data-open]{color:#34d399;}
[data-dsv-tag][data-own]{color:var(--dsw-alias-brand-primary,#4c8dff);}
[data-dsv-hint][data-warn]{color:var(--dsw-alias-brand-primary,#4c8dff);}
[data-dsv-glyph]{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;flex:none;
  color:var(--dsw-alias-label-tertiary,#979da6);}
[data-dsv-glyph][data-on]{color:#fbbf24;}
[data-dsv-action]{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;
  border:0;border-radius:6px;background:transparent;color:inherit;cursor:pointer;opacity:.75;}
[data-dsv-action]:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(127,127,127,.18));opacity:1;}
[data-dsv-action][data-on]{color:#fbbf24;opacity:1;}
[data-dsv-page]{display:flex;flex-direction:column;gap:16px;padding:2px 2px 12px;max-width:640px;}
[data-dsv-cardbox]{display:flex;flex-direction:column;gap:10px;padding:14px 15px;border-radius:12px;
  background:var(--dsw-alias-bg-layer-2,#2c2c2e);border:1px solid var(--dsw-alias-border-l2,rgba(255,255,255,.1));}
[data-dsv-cardbox] h4{margin:0;font-size:13px;font-weight:600;color:var(--dsw-alias-label-primary,#f9fafb);}
[data-dsv-glyph][data-dsv-unlocked]{color:var(--dsw-alias-label-tertiary,#979da6);opacity:.85;}
[data-dsv-action][data-dsv-unlocked]{color:var(--dsw-alias-label-tertiary,#979da6);opacity:.8;}

/* 解锁成功等一次性提示：右上角浮一条，3 秒后由 store 撤掉。
   配色严格用主题里成对的主按钮 token，不写死白/黑。 */
[data-dsv-toast]{position:fixed;top:16px;right:16px;z-index:60;display:flex;align-items:center;gap:8px;
  box-sizing:border-box;max-width:min(360px,calc(100vw - 32px));padding:9px 13px;border-radius:10px;
  font-size:12.5px;line-height:18px;font-weight:500;pointer-events:none;
  background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground);
  box-shadow:0 10px 30px rgba(0,0,0,.28);animation:dsv-toast-in .18s ease-out both;}
[data-dsv-toast] [data-dsv-toast-icon]{display:inline-flex;align-items:center;justify-content:center;flex:none;}
[data-dsv-toast] [data-dsv-toast-text]{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
@keyframes dsv-toast-in{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:none;}}
@media (prefers-reduced-motion:reduce){[data-dsv-toast]{animation:none;}}
`

    const ensureCss = () => {
      if (typeof document === 'undefined') return
      if (document.querySelector(`style[data-dsv-css]`)) return
      const style = document.createElement('style')
      style.dataset.dsvCss = '1'
      style.textContent = CSS
      document.head.appendChild(style)
    }

    // --------------------------------------------------------------- icons --
    const IconLock = (props) => h('svg', {
      viewBox: '0 0 16 16', width: 14, height: 14, fill: 'none', 'aria-hidden': true, style: { display: 'block' },
      ...props,
    },
    h('path', {
      d: 'M4.5 7V5.4a3.5 3.5 0 1 1 7 0V7',
      stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round',
    }),
    h('rect', { x: 3, y: 7, width: 10, height: 6.2, rx: 1.6, stroke: 'currentColor', strokeWidth: 1.4 }))

    const IconUnlock = (props) => h('svg', {
      viewBox: '0 0 16 16', width: 14, height: 14, fill: 'none', 'aria-hidden': true, style: { display: 'block' },
      ...props,
    },
    h('path', {
      d: 'M4.5 7V5.4a3.5 3.5 0 0 1 6.8-1.2',
      stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round',
    }),
    h('rect', { x: 3, y: 7, width: 10, height: 6.2, rx: 1.6, stroke: 'currentColor', strokeWidth: 1.4 }))

    // ------------------------------------------------------- current session --
    /**
     * 拿「当前打开的会话 id」，两条来源互为兜底：
     *  ① 会话作用域的探针 slot —— 标准 props 里就有 `sessionId`，最可靠；
     *  ② 会话正文根节点上的 `data-conversation-session` 属性 —— 宿主没渲染
     *     header utilities 时（窄窗口、嵌入视图）还能兜住。
     */
    function useCurrentSessionId() {
      const value = useStore()
      useEffect(() => {
        if (typeof document === 'undefined') return undefined
        const sync = () => {
          if (store.value.currentSessionId) return
          const el = document.querySelector('[data-conversation-content]')
          const id = el ? el.getAttribute('data-conversation-session') : ''
          if (id) store.set({ currentSessionId: id })
        }
        sync()
        const timer = setInterval(sync, 900)
        return () => clearInterval(timer)
      }, [])
      return value.currentSessionId
    }

    /** 空组件：只为了把「当前会话 id」送进 store。 */
    function SessionProbe(props) {
      const sessionId = typeof props?.sessionId === 'string' ? props.sessionId : ''
      useEffect(() => {
        if (!sessionId) return undefined
        store.setCurrentSessionId(sessionId)
        return () => store.clearCurrentSessionId(sessionId)
      }, [sessionId])
      return null
    }

    // --------------------------------------------------------------- 卡片 --
    const field = (props) => h('input', { 'data-dsv-input': '', ...props })

    function Card({ title, children, onClose }) {
      return h('div', { 'data-dsv-card': '', role: 'dialog', 'aria-modal': 'false', 'aria-label': title },
        h('h3', null, title),
        ...children,
        h('div', { 'data-dsv-row': '', style: { justifyContent: 'flex-end' } },
          h('button', {
            'data-dsv-btn': '', type: 'button',
            disabled: typeof onClose !== 'function',
            onClick: onClose,
          }, '关闭')),
      )
    }

    // --------------------------------------------------------------- 口令 --

    /** 输入口令解锁某个会话（不解除锁登记，只是本进程内放行）。 */
    function UnlockDialog({ value, onClose }) {
      const dialog = value.dialog || {}
      const sessionId = dialog.sessionId || ''
      const row = value.lockMap[sessionId]
      /** 从「已锁定的会话」列表进来时，只做永久解除。 */
      const removeOnly = dialog.remove === true
      const [pw, setPw] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [done, setDone] = useState('')
      const inputRef = useRef(null)
      /** 提交时读这里而不是闭包里的 state —— 手速快/回车紧跟输入时不会拿到旧值。 */
      const pwRef = useRef('')

      useEffect(() => {
        const timer = setTimeout(() => { try { inputRef.current?.focus() } catch { /* 无焦点 */ } }, 30)
        return () => clearTimeout(timer)
      }, [])

      const run = async (alsoRemove) => {
        if (busy || !sessionId) return
        const password = String(pwRef.current == null ? '' : pwRef.current)
        if (!password) { setError('请输入口令'); return }
        setBusy(true)
        setError('')
        try {
          const verified = await api('verify', { password, sessionId })
          const removed = alsoRemove ? await api('unlock-session', { password, sessionId }) : null
          /*
           * verify / unlock-session 的响应体本身就是一份完整 status —— 先就地应用，
           * 侧栏图标和锁屏立刻跟着变，不用干等下一轮 5 秒轮询；随后再强制刷一次对账。
           */
          if (removed && removed.grants) store.applyStatus(removed)
          else if (verified && verified.grants) store.applyStatus(verified)
          await store.refresh({ force: true })
          setDone(alsoRemove ? '已解除这个会话的锁。' : '已解锁。')
          pwRef.current = ''
          setPw('')
          store.showToast(alsoRemove ? '已解除这个会话的锁' : unlockedToastText(store.getSnapshot()))
          if (!alsoRemove && row && row.disk === true) {
            setDone('已解锁，正在重新加载会话…')
            // 下面会整页重载，提示得先存起来，重载后再补一次。
            rememberToastAcrossReload(unlockedToastText(store.getSnapshot()))
            setTimeout(() => { try { window.location.reload() } catch { /* ignore */ } }, 500)
          } else {
            setTimeout(() => {
              if (dialog.back === 'manage') store.openDialog({ kind: 'manage' })
              else store.closeDialog()
            }, 700)
          }
        } catch (err) {
          // 「没设过口令」和「输错了」不分开说 —— 这个区别本身就是线索。
          setError(passwordErrorText(err))
        } finally {
          setBusy(false)
        }
      }

      return h(Card, {
        title: removeOnly ? '解除这个会话的锁' : '输入口令解锁（只作用于这条会话）',
        onClose: busy ? undefined : onClose,
      },
        h('p', null,
          row && row.title ? `「${row.title}」已锁定。` : '这个会话已锁定。',
          row && row.disk ? ' 磁盘上只有密文，解锁后会自动重新加载。' : ''),
        h('div', { 'data-dsv-hint': '' }, '这是这条会话自己的口令。'),
        field({
          ref: inputRef, type: 'password', autoComplete: 'off', placeholder: '这条会话的口令',
          value: pw,
          onChange: (e) => {
            pwRef.current = e.target.value
            setPw(pwRef.current)
            setError('')
          },
          onKeyDown: (e) => { if (e.key === 'Enter') run(removeOnly) },
        }),
        h('div', { 'data-dsv-err': '' }, error),
        done ? h('div', { 'data-dsv-ok': '' }, done) : null,
        h('div', { 'data-dsv-row': '' },
          h('button', {
            'data-dsv-btn': '', 'data-primary': '', type: 'button',
            disabled: busy || !pw,
            onClick: () => run(removeOnly),
          }, busy ? '校验中…' : (removeOnly ? '解除' : '解锁')),
          removeOnly
            ? null
            : h('button', {
                'data-dsv-btn': '', type: 'button', disabled: busy || !pw,
                title: '这次输的口令同时用于永久解除这个会话的锁（磁盘密文会解回明文）',
                onClick: () => run(true),
              }, '解锁并永久解除'),
        ),
        h('div', { 'data-dsv-hint': '' },
          `自动重新上锁：${value.policy.autoLockMinutes > 0 ? `${value.policy.autoLockMinutes} 分钟无操作` : '关闭'}`),
      )
    }

    /**
     * 给**一条会话**上锁 / 设口令（这条会话的口令只作用于它自己）。
     *  - 还没有锁记录：两次输入，≥ minPasswordLength，两次必须一致。
     *  - 已经有锁记录：一次输入，沿用已存记录。
     */
    function LockDialog({ value, onClose }) {
      const dialog = value.dialog || {}
      const sessionId = dialog.sessionId || ''
      const row = sessionId ? value.lockMap[sessionId] : undefined
      const ownRecord = Boolean(row)
      const min = value.minPasswordLength || 6
      const title = dialog.title || (row && row.title) || ''

      const [pw, setPw] = useState('')
      const [pw2, setPw2] = useState('')
      const [disk, setDisk] = useState(
        dialog.disk !== undefined
          ? dialog.disk === true
          : Boolean(value.diskAvailable && (row ? row.disk : value.policy.diskLock)),
      )
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      /** 提交时读 ref —— hook 桩 / 快速回车都不会拿到旧值。 */
      const pwRef = useRef('')
      const pw2Ref = useRef('')
      const diskRef = useRef(disk)

      const submit = async () => {
        if (busy || !sessionId) return
        const typed = String(pwRef.current || '')
        const typed2 = String(pw2Ref.current || '')
        if (!typed) { setError('请输入这条会话的口令'); return }
        if (typed.length < min) { setError(`口令至少 ${min} 位`); return }
        if (!ownRecord && typed !== typed2) { setError('两次输入不一致'); return }
        setBusy(true)
        setError('')
        try {
          await api('lock', {
            sessionId,
            password: typed,
            title,
            disk: diskRef.current === true,
          })
          await store.refresh()
          store.closeDialog()
          store.showToast(ownRecord ? '已上锁 · 沿用这条会话自己的口令' : '已上锁 · 这条会话用自己的口令')
        } catch (err) {
          setError(String(err?.message || err))
        } finally {
          setBusy(false)
        }
      }

      const ownedField = field({
        type: 'password', autoComplete: 'current-password', autoFocus: true,
        placeholder: '这条会话现有的口令',
        value: pw,
        onChange: (e) => { pwRef.current = e.target.value; setPw(pwRef.current); setError('') },
        onKeyDown: (e) => { if (e.key === 'Enter') submit() },
      })
      const newFields = [
        field({
          type: 'password', autoComplete: 'new-password', autoFocus: true,
          placeholder: `给这条会话设口令（至少 ${min} 位）`,
          value: pw,
          onChange: (e) => { pwRef.current = e.target.value; setPw(pwRef.current); setError('') },
        }),
        field({
          type: 'password', autoComplete: 'new-password',
          placeholder: '再输一次',
          value: pw2,
          onChange: (e) => { pw2Ref.current = e.target.value; setPw2(pw2Ref.current); setError('') },
          onKeyDown: (e) => { if (e.key === 'Enter') submit() },
        }),
      ]

      return h(Card, { title: '给这个会话设口令', onClose: busy ? undefined : onClose },
        h('p', null,
          title ? `「${title}」将用一条只属于它的口令上锁。` : '这条会话将用一条只属于它的口令上锁。'),
        h('div', { 'data-dsv-hint': '' },
          '这条会话的口令只用于它自己，不影响别的会话。'),
        ownRecord
          ? h('div', { 'data-dsv-hint': '' },
              '它已经有独立口令，输一次沿用原口令即可；要换新口令请到「会话锁设置 › 已锁定的会话」。')
          : null,
        ...(ownRecord ? [ownedField] : newFields),
        h('label', { 'data-dsv-row': '', style: { cursor: 'pointer', fontSize: '12.5px' } },
          h('input', {
            type: 'checkbox', checked: disk, disabled: !value.diskAvailable || busy,
            onChange: (e) => { diskRef.current = e.target.checked; setDisk(diskRef.current) },
          }),
          h('span', null,
            value.diskAvailable
              ? '同时加密到磁盘（文件变密文，解锁后才能读）'
              : '磁盘加密在本机不可用，只做界面锁')),
        h('div', { 'data-dsv-err': '' }, error),
        h('div', { 'data-dsv-row': '', style: { justifyContent: 'flex-end' } },
          h('button', { 'data-dsv-btn': '', type: 'button', disabled: busy, onClick: onClose }, '取消'),
          h('button', {
            'data-dsv-btn': '', 'data-primary': '', type: 'button',
            disabled: busy || !pw || (!ownRecord && !pw2),
            onClick: submit,
          }, busy ? '上锁中…' : '上锁')),
      )
    }

    /**
     * 改一条会话的口令（当前口令 + 新口令）。
     */
    function ChangePasswordDialog({ value, onClose }) {
      const dialog = value.dialog || {}
      const sessionId = dialog.sessionId || ''
      const row = sessionId ? value.lockMap[sessionId] : undefined
      const min = value.minPasswordLength || 6
      const [current, setCurrent] = useState('')
      const [next, setNext] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const currentRef = useRef('')
      const nextRef = useRef('')

      const submit = async () => {
        if (busy || !sessionId) return
        const currentPassword = String(currentRef.current || '')
        const newPassword = String(nextRef.current || '')
        if (!currentPassword) { setError('请输入这条会话现在的口令'); return }
        if (newPassword.length < min) { setError(`新口令至少 ${min} 位`); return }
        setBusy(true)
        setError('')
        try {
          const result = await api('password', { sessionId, currentPassword, newPassword })
          await store.refresh()
          // 从设置页进来的，办完回到列表。
          if (dialog.back === 'manage') store.openDialog({ kind: 'manage' })
          else store.closeDialog()
          store.showToast('这条会话的口令已修改')
        } catch (err) {
          setError(passwordErrorText(err))
        } finally {
          setBusy(false)
        }
      }

      return h(Card, {
        title: '修改这条会话的口令',
        onClose: busy ? undefined : onClose,
      },
      h('p', null,
        row && row.title ? `会话「${row.title}」` : '这条会话',
        ' 用的是它自己的口令。'),
      field({
        type: 'password', autoComplete: 'current-password', autoFocus: true,
        placeholder: '当前口令（这条会话的）',
        value: current,
        onChange: (e) => { currentRef.current = e.target.value; setCurrent(currentRef.current); setError('') },
      }),
      field({
        type: 'password', autoComplete: 'new-password',
        placeholder: `新口令（至少 ${min} 位，只用于这条会话）`,
        value: next,
        onChange: (e) => { nextRef.current = e.target.value; setNext(nextRef.current); setError('') },
        onKeyDown: (e) => { if (e.key === 'Enter') submit() },
      }),
      h('div', { 'data-dsv-err': '' }, error),
      h('div', { 'data-dsv-row': '', style: { justifyContent: 'flex-end' } },
        h('button', { 'data-dsv-btn': '', type: 'button', disabled: busy, onClick: onClose }, '取消'),
        h('button', {
          'data-dsv-btn': '', 'data-primary': '', type: 'button',
          disabled: busy || !current || next.length < min,
          onClick: submit,
        }, busy ? '保存中…' : '保存新口令')),
      )
    }

    /** 会话锁设置：自动锁定、已锁清单、清除。 */
    function ManageDialog({ value, onClose }) {
      const [minutes, setMinutes] = useState(String(value.policy.autoLockMinutes))
      const [diskLock, setDiskLock] = useState(Boolean(value.policy.diskLock))
      const [confirm, setConfirm] = useState('')
      const [busy, setBusy] = useState('')
      const [msg, setMsg] = useState({ kind: '', text: '' })

      const say = (kind, text) => setMsg({ kind, text })

      const run = async (label, fn, okText) => {
        setBusy(label)
        setMsg({ kind: '', text: '' })
        try {
          const result = await fn()
          await store.refresh()
          say('ok', okText)
          return result
        } catch (error) {
          say('err', String(error?.message || error))
          return null
        } finally {
          setBusy('')
        }
      }

      const section = (title, children, note) => h('div', { 'data-dsv-cardbox': '' },
        h('h4', null, title),
        note ? h('div', { 'data-dsv-hint': '' }, note) : null,
        ...children)

      const feedback = msg.text
        ? h('div', { [msg.kind === 'err' ? 'data-dsv-err' : 'data-dsv-ok']: '' }, msg.text)
        : null

      return h(Card, { title: '会话锁设置', onClose: busy ? undefined : onClose },
        h('p', null,
          `版本 ${value.version || '—'} · 已锁 ${value.locks.length} 个会话 · `
          + `磁盘锁 ${value.diskAvailable ? '可用' : '不可用'}`),
        feedback,

        section('自动锁定与磁盘锁', [
          h('div', { 'data-dsv-row': '' },
            h('span', { 'data-dsv-hint': '' }, '空闲'),
            field({
              type: 'number', min: 0, max: 1440, value: minutes,
              style: { width: '78px', textAlign: 'center' },
              onChange: (e) => setMinutes(e.target.value),
            }),
            h('span', { 'data-dsv-hint': '' }, '分钟无操作自动重新上锁（0 = 关）'),
            h('button', {
              'data-dsv-btn': '',
              disabled: busy === 'policy',
              onClick: () => run('policy', () => api('policy', { autoLockMinutes: Number(minutes) }), '自动锁定时间已保存。'),
            }, '保存')),
          h('label', { 'data-dsv-row': '', style: { cursor: 'pointer', fontSize: '12.5px' } },
            h('input', {
              type: 'checkbox', checked: diskLock, disabled: busy === 'policy' || !value.diskAvailable,
              onChange: (e) => {
                const next = e.target.checked
                setDiskLock(next)
                run('policy', () => api('policy', { diskLock: next }), next ? '已开启磁盘锁。' : '已关闭磁盘锁。')
              },
            }),
            h('span', null, '上锁时把会话文件也加密到磁盘')),
        ], '磁盘锁：锁定时日志文件变成 WALLBK 密文，DSH 读的时候在内存里解密；侧栏始终能看到这条会话。'),

        section('已锁定的会话', [
          value.locks.length === 0
            ? h('div', { 'data-dsv-hint': '' }, '还没有锁定的会话。把鼠标移到侧栏的会话上，点那个小锁，给这条会话设一个口令。')
            : h('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
                ...value.locks.map((row) => h('div', { 'data-dsv-item': '', key: row.sessionId },
                  h('span', { 'data-dsv-glyph': '', 'data-on': '' }, h(IconLock)),
                  h('span', { 'data-dsv-grow': '', title: row.sessionId },
                    row.title || row.sessionId),
                  h('span', {
                    'data-dsv-tag': '', 'data-own': '',
                    title: '这条有只属于它自己的口令',
                  }, '独立口令'),
                  h('span', {
                    'data-dsv-tag': '', [row.disk ? 'data-disk' : 'data-open']: '',
                    title: row.disk ? '磁盘上是密文' : '只锁界面，磁盘仍是明文',
                  }, row.disk ? '磁盘密文' : '界面锁'),
                  h('button', {
                    'data-dsv-btn': '',
                    onClick: () => store.openDialog({
                      kind: 'change-password',
                      sessionId: row.sessionId,
                      back: 'manage',
                    }),
                  }, '改口令'),
                  h('button', {
                    'data-dsv-btn': '',
                    title: '用这条会话自己的口令解除它（磁盘密文同时解回明文）',
                    onClick: () => store.openDialog({
                      kind: 'unlock', sessionId: row.sessionId, remove: true, back: 'manage',
                    }),
                  }, '解除'),
                ))),
        ], '「改口令」只动这一条会话；「解除」要输这条会话自己的口令。'),

        section('危险操作', [
          h('div', { 'data-dsv-row': '' },
            h('button', {
              'data-dsv-btn': '',
              disabled: busy === 'relock',
              onClick: () => run('relock', () => api('relock', {}), '已撤销全部临时解锁。'),
            }, '立即重新上锁'),
            h('button', {
              'data-dsv-btn': '', 'data-danger': '',
              disabled: busy === 'clear' || confirm !== 'CLEAR',
              onClick: () => run('clear', async () => {
                const r = await api('clear', {})
                setConfirm('')
                return r
              }, '已清除全部锁。'),
            }, '清除全部锁'),
            field({
              placeholder: '输入 CLEAR 确认', value: confirm,
              onChange: (e) => setConfirm(e.target.value), style: { width: '150px' },
            })),
        ], '清除后所有会话不再需要口令。磁盘上还锁着会话时不允许清除。'),
      )
    }

    // ------------------------------------------------------------- 门 / 遮罩 --
    /**
     * 核心：锁屏卡片 + 正文模糊。
     * 模糊靠 `<html data-dsv-locked="1">` + CSS 打在那层会话正文上 —— 遮罩只是
     * 第一层观感，模糊才是真正挡住内容的那一层。
     */
    function LockGate({ value, onUnlock }) {
      const sessionId = useCurrentSessionId()
      const locked = isSessionLocked(value, sessionId)
      const row = sessionId ? value.lockMap[sessionId] : undefined

      useEffect(() => {
        if (typeof document === 'undefined') return undefined
        const root = document.documentElement
        if (locked) root.setAttribute('data-dsv-locked', '1')
        else root.removeAttribute('data-dsv-locked')
        return () => {
          if (!isSessionLocked(store.getSnapshot(), sessionId)) root.removeAttribute('data-dsv-locked')
        }
      }, [locked, sessionId])

      if (!locked) return null

      // 已经有对话框（解锁 / 设置）时不再叠一张，避免两个口令框抢焦点。
      if (value.dialog) return h('div', { 'data-dsv-veil': '' })

      return h(React.Fragment, null,
        h('div', { 'data-dsv-veil': '' }),
        h('div', { 'data-dsv-card': '', role: 'dialog', 'aria-modal': 'true', 'aria-label': '会话已锁定' },
          h('h3', null, h('span', { 'data-dsv-glyph': '', 'data-on': '' }, h(IconLock)), '这个会话已锁定'),
          h('p', null,
            row && row.title ? `「${row.title}」需要口令才能查看。` : '需要口令才能查看这个会话。',
            row && row.disk ? ' 磁盘上是密文。' : ''),
          h('div', { 'data-dsv-row': '' },
            h('button', {
              'data-dsv-btn': '', 'data-primary': '', type: 'button',
              onClick: () => onUnlock(sessionId),
            }, '输入口令'),
            h('button', {
              'data-dsv-btn': '', type: 'button',
              onClick: () => store.openDialog({ kind: 'manage' }),
            }, '会话锁设置'),
          ),
          h('div', { 'data-dsv-hint': '' },
            `自动重新上锁：${value.policy.autoLockMinutes > 0 ? `${value.policy.autoLockMinutes} 分钟无操作` : '关闭'}`),
        ),
      )
    }

    /** 一次性提示条：由 store.toast 驱动，3 秒后自己消失。 */
    function ToastHost() {
      const value = useStore()
      const toast = value.toast
      if (!toast || typeof toast.text !== 'string' || !toast.text) return null
      return h('div', {
        'data-dsv-toast': '',
        role: 'status',
        'aria-live': 'polite',
        'aria-label': toast.text,
      },
      h('span', { 'data-dsv-toast-icon': '' }, h(IconUnlock)),
      h('span', { 'data-dsv-toast-text': '', title: toast.text }, toast.text))
    }

    /** 所有弹窗的宿主。 */
    function Overlay() {
      const value = useStore()
      const sessionId = useCurrentSessionId()
      const onUnlock = useCallback((id) => {
        store.openDialog({ kind: 'unlock', sessionId: id || sessionId })
      }, [sessionId])

      const dialog = value.dialog
      /** 从设置页打开的子弹窗，关掉后回到设置页。 */
      const closeTo = (target) => {
        if (target && target.back === 'manage') store.openDialog({ kind: 'manage' })
        else store.closeDialog()
      }
      let card = null
      if (dialog && dialog.kind === 'unlock') card = h(UnlockDialog, { value, onClose: () => closeTo(dialog) })
      else if (dialog && dialog.kind === 'lock') card = h(LockDialog, { value, onClose: () => store.closeDialog() })
      else if (dialog && dialog.kind === 'change-password') card = h(ChangePasswordDialog, { value, onClose: () => closeTo(dialog) })
      else if (dialog && dialog.kind === 'manage') card = h(ManageDialog, { value, onClose: () => store.closeDialog() })

      // 加载中也要能显示提示（重载后补上的那条就是在 loading 阶段弹出的）。
      if (value.phase === 'loading') return value.toast ? h(ToastHost) : null

      return h(React.Fragment, null,
        h(LockGate, { value, onUnlock }),
        card,
        h(ToastHost),
      )
    }

    // ------------------------------------------------------------ 动作封装 --
    /**
     * 给一条会话上锁：**一定要先问这条会话自己的口令**（两次）。
     * 口令只属于这条会话 —— 点小锁直接弹出上锁框。
     *
     * @param sessionId - 会话 id。
     * @param title - 侧栏标题（弹窗里显示用）。
     * @param disk - 预设「同时加密到磁盘」。
     */
    async function lockSession(sessionId, title, disk) {
      if (!sessionId) return
      store.openDialog({
        kind: 'lock',
        sessionId,
        title: title || '',
        disk: disk === true,
      })
    }

    // ------------------------------------------------------- sidebar action --
    /**
     * 侧栏悬停时出现的小锁：
     *   未锁 → 上锁；已锁未解锁 → 打开解锁弹窗；已临时解锁 → 收回授权（重新上锁）。
     */
    function SidebarLockAction(props) {
      const value = useStore()
      const sessionId = typeof props?.sessionId === 'string' ? props.sessionId : ''
      const displayTitle = typeof props?.displayTitle === 'string' ? props.displayTitle : ''
      const [busy, setBusy] = useState(false)

      const lockMap = value.lockMap || {}
      const row = sessionId ? lockMap[sessionId] : undefined
      const locked = Boolean(row)
      const granted = locked && isGranted(value, sessionId)

      const click = async (event) => {
        if (event && typeof event.preventDefault === 'function') event.preventDefault()
        if (event && typeof event.stopPropagation === 'function') event.stopPropagation()
        if (!sessionId || busy) return
        if (granted) {
          // 已经临时解锁：再点就是收回（relock 不需要口令，收紧权限永远安全）。
          setBusy(true)
          try {
            await api('relock', { sessionId })
            await store.refresh({ force: true })
            store.showToast('已重新上锁 · 需要口令才能查看')
          } catch (error) {
            console.warn('[session-vault] 重新上锁失败：', error)
          } finally {
            setBusy(false)
          }
          return
        }
        if (locked) {
          store.openDialog({ kind: 'unlock', sessionId })
          return
        }
        setBusy(true)
        try {
          await lockSession(sessionId, displayTitle, value.policy.diskLock)
        } finally {
          setBusy(false)
        }
      }

      if (!sessionId) return null

      const tip = !locked
        ? (value.policy.diskLock ? '点小锁给这个会话设独立口令（并加密到磁盘）' : '点小锁给这个会话设独立口令')
        : (granted
            ? `已解锁（临时授权） · ${autoLockLabel(value)} · 点击重新上锁`
            : '这个会话已锁定，点击解锁')

      return h('button', {
        type: 'button',
        'data-dsv-action': '',
        'data-on': locked && !granted ? '' : undefined,
        'data-dsv-unlocked': granted ? '' : undefined,
        title: tip,
        'aria-label': !locked ? '锁定会话' : (granted ? '重新上锁' : '解锁会话'),
        disabled: busy,
        onClick: click,
      }, locked && !granted ? h(IconLock) : h(IconUnlock))
    }

    // ------------------------------------------------------ sidebar trailing --
    /**
     * 会话行尾部那格：锁着的显示小锁（非交互，hover 时宿主会隐藏这一格）。
     * 有临时授权时换成开着的锁 —— 解锁后图标必须跟着变，否则看起来还是锁着。
     */
    function SidebarLockGlyph(props) {
      const value = useStore()
      const sessionId = typeof props?.sessionId === 'string' ? props.sessionId : ''
      const lockMap = value.lockMap || {}
      const row = sessionId ? lockMap[sessionId] : undefined
      if (!row) return null

      const granted = isGranted(value, sessionId)
      const label = granted
        ? `会话已解锁（临时授权） · ${autoLockLabel(value)}`
        : (row.disk ? '会话已锁定（磁盘密文），需要口令才能查看' : '会话已锁定（界面锁），需要口令才能查看')

      return h('span', {
        'data-dsv-glyph': '',
        'data-on': granted ? undefined : '',
        'data-dsv-unlocked': granted ? '' : undefined,
        role: 'img',
        title: label,
        'aria-label': label,
        style: { justifyContent: 'center' },
      }, granted ? h(IconUnlock) : h(IconLock))
    }

    // ----------------------------------------------------------- 设置页 --
    function SettingsSection() {
      const value = useStore()
      if (value.phase === 'loading') return h('div', { 'data-dsv-hint': '' }, '正在读取会话锁状态…')
      return h('div', { 'data-dsv-page': '' },
        h('div', { 'data-dsv-cardbox': '' },
          h('h4', null, '会话锁'),
          h('div', { 'data-dsv-hint': '' },
            value.locks.length > 0
              ? `已启用 · 版本 ${value.version || '—'} · 已锁 ${value.locks.length} 个会话 · 磁盘锁${value.diskAvailable ? '可用' : '不可用'}`
              : '还没有锁定的会话。把鼠标移到侧栏的会话上，点那个小锁，给这条会话设一个口令。'),
          h('div', { 'data-dsv-row': '' },
            h('button', {
              'data-dsv-btn': '', 'data-primary': '',
              onClick: () => store.openDialog({ kind: 'manage' }),
            }, '打开会话锁设置')),
        ),
      )
    }

    // --------------------------------------------------------------- plugin --
    const inject = ['slots', 'contextMenus']

    function apply(ctx) {
      try {
        applyInner(ctx)
      } catch (error) {
        try { console.warn('[session-vault] apply 失败：', error) } catch { /* 无 console */ }
      }
    }

    function applyInner(ctx) {
      ensureCss()

      const safe = (label, fn) => {
        try {
          return fn()
        } catch (error) {
          try { console.warn(`[session-vault] ${label} 挂载失败：`, error) } catch { /* 无 console */ }
          return null
        }
      }

      // 状态轮询：一次启动，随插件 fiber 一起销毁。
      ctx.effect(() => {
        // 磁盘锁解锁后整页重载：把上一页存下的「已解锁」提示补出来。
        const carried = takeToastAcrossReload()
        store.refresh()
        if (carried) store.showToast(carried)
        const timer = setInterval(() => { store.refresh() }, 5000)
        const onActivity = () => {
          store.touchThrottled()
        }
        for (const event of ['pointerdown', 'keydown']) window.addEventListener(event, onActivity, { passive: true })
        return () => {
          clearInterval(timer)
          for (const event of ['pointerdown', 'keydown']) window.removeEventListener(event, onActivity)
        }
      }, 'session-vault: 状态轮询')

      // ① 弹窗 / 遮罩
      ctx.effect(() => ctx.slots.inject('shell.overlay', () => ctx.slots.register({
        name: 'shell.overlay',
        id: 'session-vault-overlay',
        order: 900,
        inject: () => ({}),
      }, Overlay)), 'session-vault: 锁屏弹窗')

      // ② 侧栏上锁按钮（hover 出现）
      ctx.effect(() => ctx.slots.inject('sidebar.workspaces.session.row.action', () => ctx.slots.register({
        name: 'sidebar.workspaces.session.row.action',
        id: 'session-vault-lock',
        order: 150,
        inject: () => ({}),
      }, (props) => h(SidebarLockAction, { sessionId: props?.sessionId, displayTitle: props?.displayTitle }))),
        'session-vault: 侧栏上锁按钮')

      // ③ 侧栏锁标（非交互）
      ctx.effect(() => ctx.slots.inject('sidebar.session.row.trailing', () => ctx.slots.register({
        name: 'sidebar.session.row.trailing',
        id: 'session-vault-glyph',
        order: 90,
        inject: () => ({}),
      }, (props) => h(SidebarLockGlyph, { sessionId: props?.sessionId }))),
        'session-vault: 侧栏锁标')

      // ④ 当前会话探针（会话作用域，标准 props 里有 sessionId）
      ctx.effect(() => ctx.slots.inject('conversation.session.header.utilities', () => ctx.slots.register({
        name: 'conversation.session.header.utilities',
        id: 'session-vault-probe',
        order: 900,
        inject: () => ({}),
      }, SessionProbe)), 'session-vault: 当前会话探针')

      // ⑤ 设置页（宿主禁用设置时没有 owner，注册会一直等着，不报错）
      safe('settings section', () => ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: 'session-vault',
        order: 43,
        label: '会话锁',
        inject: () => ({}),
      }, SettingsSection)), 'session-vault: 设置页'))

      // ⑥ 会话行的右键菜单：覆盖「没有 hover」的场景，也给磁盘锁一个明确入口
      safe('context menu', () => ctx.effect(() => ctx.contextMenus.register({
        id: 'session-vault.session',
        target: 'session',
        order: 120,
        resolve: (target) => {
          const sessionId = target?.sessionId
          const title = target?.displayTitle || sessionId
          const value = store.getSnapshot()
          if (!sessionId) return []
          const locked = Boolean(value.lockMap[sessionId])
          if (locked) {
            return [
              {
                id: 'session-vault-unlock',
                label: '解锁这个会话…',
                separatorBefore: true,
                failureLabel: '解锁失败',
                run: () => { store.openDialog({ kind: 'unlock', sessionId }) },
              },
              {
                id: 'session-vault-manage',
                label: '会话锁设置…',
                run: () => { store.openDialog({ kind: 'manage' }) },
              },
            ]
          }
          return [
            {
              id: 'session-vault-lock-ui',
              label: value.policy.diskLock ? '锁定会话（界面锁）' : '锁定会话',
              separatorBefore: true,
              failureLabel: '上锁失败',
              run: () => lockSession(sessionId, title, false),
            },
            {
              id: 'session-vault-lock-disk',
              label: '锁定会话（并加密到磁盘）',
              disabled: !value.diskAvailable,
              failureLabel: '磁盘加密失败',
              run: () => lockSession(sessionId, title, true),
            },
            {
              id: 'session-vault-manage',
              label: '会话锁设置…',
              run: () => { store.openDialog({ kind: 'manage' }) },
            },
          ]
        },
      }), 'session-vault: 会话行菜单'))
    }

    const plugin = { apply, inject }
    return plugin
  },
})
