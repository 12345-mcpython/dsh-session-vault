# 设计说明（给自己看的，别删）

## 一句话

会话加密 = **界面锁**；磁盘加密是**另一层**，靠 patch 后端的方法实现，
不是 patch `node:fs`。

## 上一版为什么错

1. 直接把 `session.vN.jsonl.zstd` 换成密文。
   DSH 的 `list()` 读不到会话头 → 会话从侧边栏消失 → 用户找不到、也就解不开。
2. 试图 patch `node:fs` 让读透明解密。
   后端写的是 `import { open } from 'node:fs/promises'`，ESM 从 CJS 取具名导出是
   **快照**，改 `fs.promises.open` 对后端完全不可见 —— 所以怎么改都「没生效」。

## 这一版的三层

### 1. 界面锁（默认，最可靠）

- `sidebar.workspaces.session.row.action`：悬停出现的小锁（加锁 / 解锁）
- `sidebar.session.row.trailing`：已锁会话的小锁标记（非交互）
- `shell.overlay`：锁屏卡片；同时给 `<html>` 打 `data-dsv-locked="1"`，
  CSS 把 `[data-conversation-content]` 模糊并断掉指针事件（真正挡住内容的那层）
- `conversation.session.header.utilities`：空探针，只为拿当前会话 id
- `settings.section`：设置页（宿主禁用设置时没有 owner，注册就一直等着，不报错）

状态：

- 口令 → `state.json` 里**每条锁自己的** `locks[id].password`（scrypt N=32768, r=8, p=1, keylen=64 + 16B 盐）
- 已解锁 → 进程内存里的 `Grants` + `backend-patch.js` 的按会话口令表
- 空闲超时 → 30s 定时器 + 每次 `status` 顺手过期；两本账一起清

### 2. 磁盘锁（可选）

分成两个文件，各管一段：

**`backend-patch.js`**（读 header / 读正文的入口）

| 方法 | 作用 |
|---|---|
| `readFirstZstdLine(path, signal)` | 密文 + 有口令 → 解密后返回 header 行 |
| `readFirstLine(path, signal)` | 未压缩会话的同条路径 |
| `open(id, access, opts)` | 定义上想换掉 handle 的读，但见下面的「实测差异」 |

**`lib/disk.mjs`**（补它补不了的三件事）

| 方法 | 为什么必须补 |
|---|---|
| `readFirstZstdLine` 外包一层 | 锁定时 backend-patch 返回 `undefined`，`list()` 会把会话跳过 → 又从侧边栏消失。所以密文文件优先读同目录的明文 `.header` 旁路 |
| `decodeStoredLog(path, id, buffer, …)` | **正文真正的解码入口**（`requireStoredLog` 与 `readStoredLog` 都汇到这里）。密文先解成 zstd 字节流再交给原方法；没口令抛 `SESSION_LOCKED` |
| `appendLines(meta, events)` | 解锁状态下继续聊天时，追加必须「解 → 追加 → 整体重新加密」，否则会往密文里掺明文，把文件彻底弄坏 |
| `repair(meta, offset)` | 截断撕裂尾，偏移按明文算 |
| `open(id, 'write')` | 锁定时拒绝写打开 |

**实测差异（0.2.2-rc.2）**：`JsonlSessionHandle` **没有 `location` 属性**，
`read(offset, length, options)` 是「逻辑事件读」而不是字节读。所以
`backend-patch.js` 里换 `handle.read` 那段对本版本是空转；正文必须从
`decodeStoredLog` 拦。这不是谁写错了，是版本差异，两条都留着向前兼容。

文件布局：

```
session.v4.jsonl.zstd         WALLBK 密文（正文）
session.v4.jsonl.zstd.header  明文第一行（id / createdAt / cwd）—— list() 用
```

取舍：正文是密文，元数据明文。要连元数据一起藏，会话就没法出现在侧边栏 ——
用户已经明确「会话必须看得见」。

### 3. 加密导出（不动原文件）

`session_vault_encrypt` 工具 → `encryptFile()` 流式写出 `.enc`，和
`wall/tools/backup_crypt.py` 同一个容器格式。

## 钥匙从哪来

```
口令 --scrypt(password, 盐)--> 32B 钥匙（只在内存）
```

- 每条会话的磁盘锁文件共用**它自己**口令记录里的盐
- 老格式（1.x）：每个文件随机盐，钥匙 = `scrypt(password, 文件自己的盐)`；
  启动扫描时补登为 `orphan`，解锁时允许「拿当初那个口令」试开

换口令 = 换钥匙：`password` 路由会先把这条会话的密文解回明文，再用新盐重新加密。

## 两本账为什么都要清

`Grants`（我们）和 `keys`（backend-patch 的按会话口令表）任意一本没清，都会让
「已上锁」变成假的：只清 Grants 时，header 还能被 backend-patch 解出来；
只清 keys 时，正文还能被我们的 `decodeStoredLog` 解密。所以上锁 / 撤销授权 /
空闲过期 / 清除，四处都同时清两本账。

## 已知窗口

- 写入瞬间：文件先解成明文、写完立刻原子加密回去（tmp + rename，带重试）。
  崩溃最多留下明文，不会留下半截密文。
- 进程被强杀：没有清理钩子。磁盘锁文件本来就是密文；界面锁的「已解锁」随进程消失。
- **不要给正在跑的会话上锁**：锁上之后写打开会被拒绝，那一轮会报错。

## 调试

- 插件日志：`~/.dsh/session-vault/session-vault.log`
- 状态：`~/.dsh/session-vault/state.json`
- 装了什么：`~/.dsh/session-vault/_diagnostics.json`（backend-patch 的方法清单、
  磁盘锁是否可用、两本账的解锁数量）
- 判断一个会话文件是不是密文：前 8 字节是 `57414c4c424b0100`（`WALLBK\1\0`）
- 自检：`node test/host-selftest.mjs` / `node test/client-selftest.mjs`
