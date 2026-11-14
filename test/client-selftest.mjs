/**
 * 浏览器半侧自检（不需要浏览器）：`node test/client-selftest.mjs`
 *
 * 用最小 React 打桩把 client.js 装起来，覆盖：
 *   - 自注册 / 导出 inject+apply / 五个 slot + 会话行菜单都注册上
 *   - 已锁会话 → 锁屏卡片；解锁 / 设置 / 设置口令三种弹窗都能渲染
 *   - 会话行菜单在「未配置 / 未锁 / 已锁」三种状态下的条目
 *
 * 它不能替代真机，只能证明「组件不抛错、插槽写对了、文案出来了」。
 */
import { readFileSync } from 'node:fs'

let failures = 0
const check = (label, cond, extra = '') => {
  if (cond) console.log(`  ok   ${label}`)
  else { failures += 1; console.log(`  FAIL ${label} ${extra}`) }
}

// ---- 最小 React ----------------------------------------------------------
const Fragment = Symbol('Fragment')
const realSetTimeout = globalThis.setTimeout
const effects = []
let hookSlots = []
let hookIndex = 0
const React = {
  Fragment,
  createElement(type, props, ...children) {
    const kids = children.length <= 1 ? children[0] : children
    if (type === Fragment) return kids
    if (typeof type === 'function') return type({ ...(props || {}), children: kids })
    return { type, props: props || {}, children: kids }
  },
  useState(initial) {
    // 每次 render 从 0 开始数 hook 位置；只有 rerender 会保留上一次的值，
    // 这样 setState 之后能看到错误文案（真 React 的重渲染）。
    const index = hookIndex
    hookIndex += 1
    if (index >= hookSlots.length) hookSlots.push(initial)
    return [hookSlots[index], (next) => { hookSlots[index] = typeof next === 'function' ? next(hookSlots[index]) : next }]
  },
  useEffect(fn) { effects.push(fn) },
  useRef(value) { return { current: value } },
  useCallback(fn) { return fn },
  useSyncExternalStore(_subscribe, getSnapshot) { return getSnapshot() },
}

// ---- 服务端状态 / fetch 打桩 --------------------------------------------
const baseStatus = {
  ok: true,
  version: '2.0.0',
  policy: { autoLockMinutes: 10, diskLock: true },
  locks: [{ sessionId: 'session-abc', title: '私密会话', lockedAt: Date.now(), disk: true }],
  grants: { sessions: [], idleMs: 0 },
  minPasswordLength: 6,
  diskAvailable: true,
}
let serverState = baseStatus
const fetchCalls = []

globalThis.fetch = async (url, init) => {
  fetchCalls.push({ url: String(url), init })
  const action = new URL(String(url), 'http://x').searchParams.get('action')
  if (action === 'verify') {
    const sent = JSON.parse(init.body)
    if (sent.password === 'never-set') {
      // 服务端在「这条还没有口令记录」时回 409；客户端不该把这个区别露出来。
      return { ok: false, status: 409, json: async () => ({ ok: false, error: '还没有设置口令' }) }
    }
    if (sent.password !== 'good') {
      return { ok: false, status: 401, json: async () => ({ ok: false, error: '口令不对' }) }
    }
    serverState = { ...serverState, grants: { ...serverState.grants, sessions: [sent.sessionId] } }
    return { ok: true, status: 200, json: async () => ({ ok: true, ...serverState }) }
  }
  if (action === 'relock') {
    const sent = init && init.body ? JSON.parse(init.body) : {}
    const drop = sent.sessionId
    const sessions = (serverState.grants.sessions || []).filter((id) => id !== drop)
    serverState = { ...serverState, grants: { ...serverState.grants, sessions, global: drop ? serverState.grants.global : false } }
    return { ok: true, status: 200, json: async () => ({ ok: true, ...serverState }) }
  }
  // 上锁：带 password 就是给这条会话写一条自己的记录（lib/routes.mjs 的 lock 分支）。
  if (action === 'lock') {
    const sent = init && init.body ? JSON.parse(init.body) : {}
    if (!sent.sessionId) {
      return { ok: false, status: 400, json: async () => ({ ok: false, error: '缺少 sessionId' }) }
    }
    const previous = (serverState.locks || []).find((row) => row.sessionId === sent.sessionId)
    const row = {
      sessionId: sent.sessionId,
      title: sent.title || (previous && previous.title) || '',
      lockedAt: Date.now(),
      disk: sent.disk === true,
      orphan: false,
    }
    serverState = {
      ...serverState,
      locks: [...(serverState.locks || []).filter((item) => item.sessionId !== sent.sessionId), row],
    }
    return { ok: true, status: 200, json: async () => ({ ok: true, ...serverState }) }
  }
  // 改一条会话的口令。
  if (action === 'password') {
    const sent = init && init.body ? JSON.parse(init.body) : {}
    if (!sent.sessionId) {
      return { ok: false, status: 400, json: async () => ({ ok: false, error: '缺少 sessionId' }) }
    }
    const row = (serverState.locks || []).find((item) => item.sessionId === sent.sessionId)
    if (!row) {
      return { ok: false, status: 404, json: async () => ({ ok: false, error: '这个会话没有锁，无法改口令' }) }
    }
    if (sent.currentPassword !== 'good') {
      return { ok: false, status: 401, json: async () => ({ ok: false, error: '口令不对' }) }
    }
    return { ok: true, status: 200, json: async () => ({ ok: true, ...serverState }) }
  }
  return { ok: true, status: 200, json: async () => ({ ok: true, ...serverState }) }
}

// ---- sessionStorage 打桩（提示条跨整页重载的兜底） -----------------------
const toastStorageMap = new Map()

// ---- DOM / window 打桩 ---------------------------------------------------
const styleEl = { dataset: {}, textContent: '', setAttribute() {} }
globalThis.document = {
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => styleEl,
  head: { appendChild() {} },
  documentElement: { setAttribute() {}, removeAttribute() {} },
}
const windowStub = {
  location: { reload() {} },
  addEventListener() {},
  removeEventListener() {},
  sessionStorage: {
    getItem: (key) => (toastStorageMap.has(key) ? toastStorageMap.get(key) : null),
    setItem: (key, value) => { toastStorageMap.set(key, String(value)) },
    removeItem: (key) => { toastStorageMap.delete(key) },
  },
}
globalThis.window = windowStub
const realSetInterval = globalThis.setInterval
const realClearInterval = globalThis.clearInterval
const realClearTimeout = globalThis.clearTimeout
globalThis.setInterval = () => 1
globalThis.clearInterval = () => {}
globalThis.setTimeout = () => 1
globalThis.clearTimeout = () => {}
globalThis.requestAnimationFrame = (fn) => { void fn; return 1 }
globalThis.cancelAnimationFrame = () => {}

// ---- 加载 client.js ------------------------------------------------------
const source = readFileSync(new URL('../client.js', import.meta.url), 'utf8')
const loadClient = () => {
  let captured = null
  windowStub.__ModuleLoader__ = { load: (def) => { captured = def } }
  new Function('window', 'document', 'fetch', 'setInterval', 'clearInterval', 'setTimeout', 'clearTimeout', 'console', source)(
    windowStub, globalThis.document, globalThis.fetch, globalThis.setInterval, globalThis.clearInterval,
    globalThis.setTimeout, globalThis.clearTimeout, console,
  )
  if (!captured) throw new Error('client.js 没有自注册')
  return captured
}

const captured = loadClient()
check('client.js 自注册', captured.id === '@local/dsh-session-vault')
const plugin = captured.factory((name) => {
  if (name === 'react') return React
  throw new Error(`unexpected require: ${name}`)
})
check('导出 inject/apply', Array.isArray(plugin.inject) && typeof plugin.apply === 'function')
check('inject 含 slots + contextMenus', plugin.inject.includes('slots') && plugin.inject.includes('contextMenus'))

/** 装一个假 ctx，返回注册表。 */
function boot(statusPatch) {
  if (statusPatch) serverState = { ...baseStatus, ...statusPatch }
  const client = loadClient()
  const instance = client.factory((name) => (name === 'react' ? React : null))
  const registrations = []
  const menuContribs = []
  const services = {
    slots: {
      inject: (_name, cb) => { const d = cb(); return () => { if (typeof d === 'function') d() } },
      register: (options, component) => { registrations.push({ options, component }); return () => {} },
    },
    contextMenus: { register: (contribution) => { menuContribs.push(contribution); return () => {} } },
  }
  let applyError = null
  try {
    instance.apply({
      slots: services.slots,
      contextMenus: services.contextMenus,
      get: (name) => services[name],
      effect: (cb) => { const d = cb(); return () => { if (typeof d === 'function') d() } },
    })
  } catch (error) {
    applyError = error
  }
  const entry = (name) => registrations.find((r) => r.options.name === name)
  const render = (name, props = {}) => {
    hookSlots = []
    hookIndex = 0
    effects.length = 0
    const target = entry(name)
    if (!target) return null
    const out = target.component(props)
    // 只跑 effect 本体，不立刻跑清理函数（那会马上把刚写进去的状态撤掉）
    for (const fn of effects.splice(0)) { try { fn() } catch { /* ignore */ } }
    return out
  }
  return { registrations, menuContribs, entry, render, applyError }
}

/**
 * 保留 hook 状态的重新渲染：真 React 里 setState 会触发重渲染，
 * 这个桩没有调度器，只能不重置 hookSlots 再跑一次组件，才能看到错误文案。
 */
const rerender = (app, name, props = {}) => {
  const target = app.entry(name)
  if (!target) return null
  hookIndex = 0
  const out = target.component(props)
  for (const fn of effects.splice(0)) { try { fn() } catch { /* ignore */ } }
  return out
}

/** 把渲染树摊平成一串文本，用来断言哪张卡片出来了。 */
const textOf = (node) => {
  if (node === null || node === undefined || node === false) return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(textOf).join(' ')
  if (typeof node === 'object' && node.children !== undefined) return textOf(node.children)
  return ''
}

/** 在渲染树里找所有满足条件的节点（只递归 children，不碰 props 里的函数）。 */
const findAll = (node, predicate, out = []) => {
  if (node === null || node === undefined || node === false) return out
  if (Array.isArray(node)) { for (const item of node) findAll(item, predicate, out); return out }
  if (typeof node !== 'object') return out
  try { if (predicate(node)) out.push(node) } catch { /* 谓词出错就当没匹配 */ }
  findAll(node.children, predicate, out)
  return out
}

/** 取图标的第一个 path 的 d，用来区分「闭合的锁」和「打开的锁」。 */
const glyphShape = (glyph) => {
  const svg = glyph && (Array.isArray(glyph.children) ? glyph.children[0] : glyph.children)
  const kids = svg && svg.children
  const first = Array.isArray(kids) ? kids[0] : kids
  return first && first.props ? String(first.props.d || '') : ''
}

console.log('\n[1] 插槽 / 菜单注册')
const app = boot()
check('apply 不抛错', !app.applyError, String(app.applyError))
const names = app.registrations.map((r) => r.options.name)
for (const expected of [
  'shell.overlay',
  'sidebar.workspaces.session.row.action',
  'sidebar.session.row.trailing',
  'conversation.session.header.utilities',
  'settings.section',
]) {
  check(`注册到 ${expected}`, names.includes(expected), names.join(','))
}
check('每个 slot 注册都有 id', app.registrations.every((r) => typeof r.options.id === 'string' && r.options.id.length > 0))
check('注册了一个会话行右键菜单', app.menuContribs.length === 1 && app.menuContribs[0].target === 'session')

console.log('\n[2] 渲染：锁屏 / 各弹窗')
await new Promise((resolve) => realSetTimeout(resolve, 60))
check('状态拉取打了 status', fetchCalls.some((c) => c.url.includes('action=status')))
app.render('conversation.session.header.utilities', { sessionId: 'session-abc' })
app.render('sidebar.workspaces.session.row.action', { sessionId: 'session-abc', displayTitle: '私密会话' })
app.render('sidebar.session.row.trailing', { sessionId: 'session-abc' })
app.render('settings.section', {})
const overlay = app.render('shell.overlay', {})
check('overlay 渲染出节点', Boolean(overlay))
check('当前会话已锁 → 出现锁屏卡片', textOf(overlay).includes('这个会话已锁定'), textOf(overlay).slice(0, 120))

const menu = app.menuContribs[0]
const unlockedMenu = menu.resolve.call(menu, { sessionId: 'session-other', displayTitle: '别的会话' })
check('未锁会话菜单：界面锁 + 磁盘锁 + 设置',
  Array.isArray(unlockedMenu) && unlockedMenu.length === 3
  && unlockedMenu.some((a) => a.label.includes('界面锁'))
  && unlockedMenu.some((a) => a.label.includes('磁盘')),
  JSON.stringify(unlockedMenu.map((a) => a.label)))

const lockedMenu = menu.resolve.call(menu, { sessionId: 'session-abc', displayTitle: '私密会话' })
check('已锁会话菜单含解锁项', lockedMenu.some((a) => a.label.includes('解锁')), JSON.stringify(lockedMenu.map((a) => a.label)))

lockedMenu.find((a) => a.label.includes('解锁'))?.run()
const unlockView = app.render('shell.overlay', {})
check('解锁弹窗可渲染', textOf(unlockView).includes('输入口令解锁'), textOf(unlockView).slice(0, 120))

menu.resolve.call(menu, { sessionId: 'session-abc', displayTitle: '私密会话' })
  .find((a) => a.label.includes('设置'))?.run()
const manageView = app.render('shell.overlay', {})
check('会话锁设置弹窗可渲染', textOf(manageView).includes('会话锁设置'), textOf(manageView).slice(0, 120))
check('设置弹窗里有磁盘锁说明', textOf(manageView).includes('磁盘锁'), textOf(manageView).slice(0, 200))

const sleep = (ms) => new Promise((resolve) => realSetTimeout(resolve, ms))
const passwordInputs = (node) => findAll(node, (n) => n.type === 'input' && n.props && n.props.type === 'password')
const buttonsWith = (node, text) => findAll(node, (n) => n.type === 'button' && textOf(n) === text)

console.log('\n[3] 新用户第一次点侧栏小锁 → 直接弹「给这个会话设口令」')
const fresh = boot({ locks: [], grants: { sessions: [], idleMs: 0 } })
await sleep(60)
const action = fresh.render('sidebar.workspaces.session.row.action', { sessionId: 'session-xyz', displayTitle: '新会话' })
check('没有任何锁时侧栏按钮存在', Boolean(action) && action.type === 'button')
action.props.onClick({ preventDefault() {}, stopPropagation() {} })
await sleep(20)
const setupView = fresh.render('shell.overlay', {})
check('不需要先设全局口令，直接弹上锁框', textOf(setupView).includes('给这个会话设口令'), textOf(setupView).slice(0, 120))
check('上锁框要求输两次口令', passwordInputs(setupView).length === 2)
check('全程没有调用 setup 路由', !fetchCalls.some((call) => call.url.includes('action=setup')))

console.log('\n[4] 解锁失败 / 成功：提示条与侧栏图标状态')
const vault = boot({
  locks: baseStatus.locks,
  grants: { sessions: [], idleMs: 0 },
})
await sleep(80)

const lockedGlyph = vault.render('sidebar.session.row.trailing', { sessionId: 'session-abc' })
check('未解锁：锁标是闭合的锁 + 有状态说明',
  Boolean(lockedGlyph) && String(lockedGlyph.props.title).includes('已锁定')
  && lockedGlyph.props['aria-label'] === lockedGlyph.props.title
  && lockedGlyph.props['data-dsv-unlocked'] === undefined,
  JSON.stringify(lockedGlyph && lockedGlyph.props))
check('没被锁的会话：不显示任何锁标',
  vault.render('sidebar.session.row.trailing', { sessionId: 'session-free' }) === null)

vault.menuContribs[0].resolve.call(vault.menuContribs[0], { sessionId: 'session-abc', displayTitle: '私密会话' })
  .find((a) => a.label.includes('解锁'))?.run()
const unlockCard = vault.render('shell.overlay', {})
const pwInput = findAll(unlockCard, (n) => n.type === 'input' && n.props && n.props.type === 'password')[0]
const unlockButton = findAll(unlockCard, (n) => n.type === 'button').find((n) => textOf(n) === '解锁')
check('解锁弹窗里有口令框和「解锁」按钮', Boolean(pwInput) && Boolean(unlockButton))

pwInput.props.onChange({ target: { value: 'bad' } })
unlockButton.props.onClick()
await sleep(80)
const afterFail = vault.render('shell.overlay', {})
check('口令不对：不显示成功提示', !textOf(afterFail).includes('已解锁 ·'), textOf(afterFail).slice(0, 160))
check('口令不对：锁标仍是闭合的锁',
  vault.render('sidebar.session.row.trailing', { sessionId: 'session-abc' }).props['data-dsv-unlocked'] === undefined)

pwInput.props.onChange({ target: { value: 'good' } })
unlockButton.props.onClick()
await sleep(150)
const afterOk = vault.render('shell.overlay', {})
const okText = textOf(afterOk)
check('解锁成功：出现「已解锁 · 10 分钟后自动上锁」提示', okText.includes('已解锁 · 10 分钟后自动上锁'), okText.slice(0, 200))
const toastNode = findAll(afterOk, (n) => n.props && n.props['data-dsv-toast'] === '')[0]
check('提示条是可访问的 status（aria-live + aria-label）',
  Boolean(toastNode) && toastNode.props.role === 'status'
  && toastNode.props['aria-live'] === 'polite'
  && String(toastNode.props['aria-label']).includes('已解锁'),
  JSON.stringify(toastNode && toastNode.props))

const openGlyph = vault.render('sidebar.session.row.trailing', { sessionId: 'session-abc' })
check('解锁后：侧栏锁标变成打开的锁',
  Boolean(openGlyph) && openGlyph.props['data-dsv-unlocked'] === ''
  && String(openGlyph.props.title).includes('已解锁')
  && String(openGlyph.props['aria-label']).includes('已解锁')
  && openGlyph.props.role === 'img',
  JSON.stringify(openGlyph && openGlyph.props))
check('开锁图标与闭锁图标确实不同',
  glyphShape(openGlyph) !== glyphShape(lockedGlyph) && glyphShape(openGlyph).length > 10,
  `${glyphShape(openGlyph)} vs ${glyphShape(lockedGlyph)}`)

const actionOpen = vault.render('sidebar.workspaces.session.row.action', { sessionId: 'session-abc', displayTitle: '私密会话' })
check('解锁后：侧栏按钮变成「重新上锁」',
  Boolean(actionOpen) && actionOpen.props['aria-label'] === '重新上锁'
  && actionOpen.props['data-dsv-unlocked'] === ''
  && String(actionOpen.props.title).includes('已解锁'),
  JSON.stringify(actionOpen && actionOpen.props))

await actionOpen.props.onClick({ preventDefault() {}, stopPropagation() {} })
await sleep(150)
const relockText = textOf(vault.render('shell.overlay', {}))
check('重新上锁：出现「已重新上锁」提示', relockText.includes('已重新上锁'), relockText.slice(0, 200))
check('重新上锁：锁标恢复闭合的锁',
  vault.render('sidebar.session.row.trailing', { sessionId: 'session-abc' }).props['data-dsv-unlocked'] === undefined)

console.log('\n[5] 磁盘锁解锁后整页重载：提示跨页补出')
toastStorageMap.set('dsv.pending-toast', '已解锁 · 10 分钟后自动上锁')
const reloaded = boot({
  locks: baseStatus.locks,
  grants: { sessions: ['session-abc'], idleMs: 0 },
})
await sleep(80)
check('重载后从 sessionStorage 补出提示',
  textOf(reloaded.render('shell.overlay', {})).includes('已解锁 · 10 分钟后自动上锁'))
check('补完即清掉，不会残留到下一页', toastStorageMap.get('dsv.pending-toast') === undefined)

console.log('\n[6] 提示条配色只用主题变量')
const css = String(styleEl.textContent || '')
const toastRule = (css.match(/\[data-dsv-toast\]\s*\{[^}]*\}/) || [''])[0]
check('提示条样式已注入', toastRule.length > 0)
check('背景用主按钮填充 token', toastRule.includes('background:var(--dsw-alias-button-primary-fill)'), toastRule)
check('文字用主按钮前景 token', toastRule.includes('color:var(--dsw-alias-label-primary-foreground)'), toastRule)
check('没有写死白 / 黑', !/#(?:fff|ffffff|000|000000)\b/i.test(toastRule), toastRule)

console.log('\n[7] 每条会话独立口令：上锁 / 改口令')
const lockCallsFor = (sessionId) => fetchCalls.filter((call) => {
  if (!call.url.includes('action=lock')) return false
  const sent = call.init && call.init.body ? JSON.parse(call.init.body) : {}
  return sent.sessionId === sessionId
})

// —— 1) 点小锁必须先输两次「这条会话自己的」口令 ——
const lockApp = boot({
  locks: [],
  grants: { sessions: [], idleMs: 0 },
})
await sleep(80)
const newLockAction = lockApp.render('sidebar.workspaces.session.row.action', { sessionId: 'session-new', displayTitle: '新会话' })
newLockAction.props.onClick({ preventDefault() {}, stopPropagation() {} })
await sleep(20)
const lockCard = lockApp.render('shell.overlay', {})
check('点小锁先弹「给这个会话设口令」', textOf(lockCard).includes('给这个会话设口令'), textOf(lockCard).slice(0, 140))
check('上锁弹窗要求输入两次口令', passwordInputs(lockCard).length === 2,
  `password inputs=${passwordInputs(lockCard).length}`)
check('上锁弹窗写明口令只用于这条会话', textOf(lockCard).includes('只用于它自己'), textOf(lockCard).slice(0, 200))
check('上锁弹窗不再提全局口令', !textOf(lockCard).includes('全局口令'), textOf(lockCard).slice(0, 220))

const lockInputs = passwordInputs(lockCard)
const lockButton = buttonsWith(lockCard, '上锁')[0]
check('上锁弹窗有一个「上锁」按钮', Boolean(lockButton))
lockInputs[0].props.onChange({ target: { value: 'secret-one' } })
lockInputs[1].props.onChange({ target: { value: 'secret-two' } })
lockButton.props.onClick()
await sleep(30)
const mismatchView = rerender(lockApp, 'shell.overlay', {})
check('两次输入不一致时报错', textOf(mismatchView).includes('两次输入不一致'), textOf(mismatchView).slice(0, 200))
check('两次不一致时不发上锁请求', lockCallsFor('session-new').length === 0)

lockInputs[0].props.onChange({ target: { value: 'abc' } })
lockInputs[1].props.onChange({ target: { value: 'abc' } })
lockButton.props.onClick()
await sleep(30)
const shortView = rerender(lockApp, 'shell.overlay', {})
check('口令太短时报错', textOf(shortView).includes('口令至少 6 位'), textOf(shortView).slice(0, 200))
check('口令太短时不发上锁请求', lockCallsFor('session-new').length === 0)

lockInputs[0].props.onChange({ target: { value: 'new-session-pw' } })
lockInputs[1].props.onChange({ target: { value: 'new-session-pw' } })
lockButton.props.onClick()
await sleep(100)
const afterLock = lockApp.render('shell.overlay', {})
const lockBody = lockCallsFor('session-new')[0] ? JSON.parse(lockCallsFor('session-new')[0].init.body) : null
check('确认后 POST lock 带 { sessionId, password, disk }',
  Boolean(lockBody) && lockBody.sessionId === 'session-new'
  && lockBody.password === 'new-session-pw' && typeof lockBody.disk === 'boolean',
  JSON.stringify(lockBody))
check('上锁成功后弹窗关闭', !textOf(afterLock).includes('给这个会话设口令'), textOf(afterLock).slice(0, 160))

// —— 2) 解锁弹窗：只说明这是这条会话的口令 ——
const errApp = boot({
  locks: [{ sessionId: 'session-err', title: '错误测试', lockedAt: Date.now(), disk: false, orphan: false }],
  grants: { sessions: [], idleMs: 0 },
})
await sleep(80)
errApp.menuContribs[0].resolve.call(errApp.menuContribs[0], { sessionId: 'session-err', displayTitle: '错误测试' })
  .find((item) => item.label.includes('解锁')).run()
const errUnlockCard = errApp.render('shell.overlay', {})
check('解锁弹窗写明这是这条会话的口令', textOf(errUnlockCard).includes('这是这条会话自己的口令'), textOf(errUnlockCard).slice(0, 220))
check('解锁弹窗不再提旧版全局口令', !textOf(errUnlockCard).includes('旧版全局口令'), textOf(errUnlockCard).slice(0, 220))

const errUnlockInput = passwordInputs(errUnlockCard)[0]
errUnlockInput.props.onChange({ target: { value: 'nope' } })
buttonsWith(errUnlockCard, '解锁')[0].props.onClick()
await sleep(80)
const badUnlockView = rerender(errApp, 'shell.overlay', {})
check('输错只报「口令不对」，不区分「没设过」',
  textOf(badUnlockView).includes('口令不对') && !textOf(badUnlockView).includes('还没有设置口令'),
  textOf(badUnlockView).slice(0, 200))

errUnlockInput.props.onChange({ target: { value: 'never-set' } })
buttonsWith(errUnlockCard, '解锁')[0].props.onClick()
await sleep(80)
const neverSetView = rerender(errApp, 'shell.overlay', {})
check('服务端回「还没设过口令」时也统一显示「口令不对」',
  textOf(neverSetView).includes('口令不对') && !textOf(neverSetView).includes('还没有设置口令'),
  textOf(neverSetView).slice(0, 200))

// —— 3) 设置页「已锁定的会话」：标签 + 按钮 + 改口令 ——
const manageApp = boot({
  locks: [
    { sessionId: 'session-own', title: '独立会话', lockedAt: Date.now(), disk: true, orphan: false },
  ],
  grants: { sessions: [], idleMs: 0 },
})
await sleep(80)
manageApp.menuContribs[0].resolve.call(manageApp.menuContribs[0], { sessionId: 'session-own', displayTitle: '独立会话' })
  .find((item) => item.label.includes('设置')).run()
const manageRowsView = manageApp.render('shell.overlay', {})
const manageTags = findAll(manageRowsView, (n) => n.props && n.props['data-dsv-tag'] !== undefined).map((n) => textOf(n))
check('设置页每行标签是「独立口令」', manageTags.includes('独立口令'), JSON.stringify(manageTags))
check('设置页不再有「旧口令」标签', !manageTags.includes('旧口令'), JSON.stringify(manageTags))
check('设置页行按钮是「改口令」', Boolean(buttonsWith(manageRowsView, '改口令')[0]), JSON.stringify(manageTags))
check('设置页不再有「改用独立口令」按钮', buttonsWith(manageRowsView, '改用独立口令').length === 0)
check('设置页不再有全局口令区块', !textOf(manageRowsView).includes('全局口令'), textOf(manageRowsView).slice(0, 240))

buttonsWith(manageRowsView, '改口令')[0].props.onClick()
await sleep(20)
const changeCard = manageApp.render('shell.overlay', {})
check('改口令弹窗有当前口令 + 新口令两个输入框',
  passwordInputs(changeCard).length === 2, `password inputs=${passwordInputs(changeCard).length}`)
const changeInputs = passwordInputs(changeCard)
changeInputs[0].props.onChange({ target: { value: 'good' } })
changeInputs[1].props.onChange({ target: { value: 'brand-new-pw' } })
const changeSubmit = buttonsWith(changeCard, '保存新口令')[0]
check('改口令弹窗有提交按钮', Boolean(changeSubmit))
changeSubmit.props.onClick()
await sleep(100)
const sentPasswords = fetchCalls
  .filter((call) => call.url.includes('action=password'))
  .map((call) => JSON.parse(call.init.body))
check('改口令请求带 { sessionId, currentPassword, newPassword }',
  sentPasswords.some((body) => body.sessionId === 'session-own'
    && body.currentPassword === 'good' && body.newPassword === 'brand-new-pw'),
  JSON.stringify(sentPasswords))
check('改口令成功后提示「这条会话的口令已修改」',
  textOf(manageApp.render('shell.overlay', {})).includes('这条会话的口令已修改'))

// —— 4) 源码里不允许再出现 legacy / 全局口令 / setup 路由 ——
check('client.js 源码不再含 legacy', !/legacy/i.test(source))
check('client.js 源码不再含全局口令 / SetupDialog', !/全局口令|SetupDialog/.test(source))
check('client.js 源码不再引用 setup 动作', !/['"]setup['"]/.test(source))
check('整个客户端流程没有调用 setup', !fetchCalls.some((call) => call.url.includes('action=setup')))

globalThis.clearInterval = realClearInterval
globalThis.clearTimeout = realClearTimeout
void realSetInterval
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
