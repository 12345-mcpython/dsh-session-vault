/**
 * backend-patch.js —— 直接改 DSH 会话持久化后端的方法，让磁盘密文也能被读到。
 *
 * 为什么 patch 方法而不是 patch fs
 * --------------------------------
 * `dsh-session-persistence-jsonl` 用的是
 *
 *     import { open, readFile, stat } from "node:fs/promises";
 *
 * `node:fs/promises` 是 CJS 模块，ESM 导入它的具名导出时 Node 会**复制快照**，
 * 不是活绑定。所以 `fs.promises.open = ...` 对后端完全不可见（实测加日志
 * 一次都没被调用）。而**类方法**是原型上的属性查找，改了立刻生效。
 *
 * 改哪几个方法
 * ------------
 *   readFirstZstdLine(path, signal)   list() 读 header 走这里
 *   readFirstLine(path, signal)       未压缩会话的同类路径
 *   open(id, access, opts)            读正文 / 追加写入
 *
 * 工作方式
 * --------
 *   磁盘密文 + 内存有口令  -> 解密后交给下游（会话可见、可读）
 *   磁盘密文 + 内存无口令  -> readFirst* 返回 undefined（list 跳过）；
 *                            open 抛 SESSION_LOCKED（弹密码框）
 *   磁盘明文              -> 原样放行
 *
 * 卸载时把原方法全部还原（ctx.effect 拥有生命周期）。
 */

import fsp from "node:fs/promises";
import zlib from "node:zlib";
import path from "node:path";
import { createDecipheriv, createCipheriv, randomBytes, scryptSync } from "node:crypto";
import { SCRYPT, scryptKeyOptions } from "./lib/scrypt.mjs";

const MAGIC = Buffer.from([0x57, 0x41, 0x4c, 0x4c, 0x42, 0x4b, 0x01, 0x00]); // WALLBK\1\0
const VERSION = 1;
const SCRYPT_N = SCRYPT.N;
const SCRYPT_R = SCRYPT.r;
const SCRYPT_P = SCRYPT.p;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const HEADER_LEN = MAGIC.length + 1 + 12 + SALT_LEN + NONCE_LEN;

const PATCH_FLAG = Symbol.for("dsh-session-vault.backendPatched");

/** sessionId -> password。挂 globalThis，避免模块多实例导致查不到。 */
const GLOBAL_KEYS = Symbol.for("dsh-session-vault.keys");
const keys = globalThis[GLOBAL_KEYS] instanceof Map
  ? globalThis[GLOBAL_KEYS]
  : (globalThis[GLOBAL_KEYS] = new Map());

export function setKey(sessionId, password) {
  keys.set(sessionId, password);
}
export function clearKey(sessionId) {
  keys.delete(sessionId);
}
export function hasKey(sessionId) {
  return keys.has(sessionId);
}
export function keyIds() {
  return [...keys.keys()];
}

// ---------------------------------------------------------------- 加密格式

function isEncrypted(buf) {
  return buf.length >= HEADER_LEN + 16 && buf.subarray(0, MAGIC.length).equals(MAGIC);
}

export function decryptBuffer(buf, password) {
  let off = MAGIC.length;
  const ver = buf.readUInt8(off); off += 1;
  if (ver !== VERSION) throw new Error(`不支持的版本: ${ver}`);
  const n = buf.readUInt32BE(off); off += 4;
  const r = buf.readUInt32BE(off); off += 4;
  const p = buf.readUInt32BE(off); off += 4;
  const salt = buf.subarray(off, off + SALT_LEN); off += SALT_LEN;
  const nonce = buf.subarray(off, off + NONCE_LEN); off += NONCE_LEN;
  const body = buf.subarray(off);
  const key = scryptSync(password, salt, 32, { N: n, r, p, maxmem: scryptKeyOptions(n, r, p).maxmem });
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(Buffer.concat([MAGIC, Buffer.from([ver])]));
  d.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]);
}

export function encryptBuffer(plain, password) {
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const key = scryptSync(password, salt, 32, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: scryptKeyOptions().maxmem,
  });
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.concat([MAGIC, Buffer.from([VERSION])]));
  // GCM 的 final() 返回空，认证 tag 必须单独取并拼在末尾
  const body = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const header = Buffer.alloc(HEADER_LEN);
  let off = 0;
  MAGIC.copy(header, off); off += MAGIC.length;
  header.writeUInt8(VERSION, off); off += 1;
  header.writeUInt32BE(SCRYPT_N, off); off += 4;
  header.writeUInt32BE(SCRYPT_R, off); off += 4;
  header.writeUInt32BE(SCRYPT_P, off); off += 4;
  salt.copy(header, off); off += SALT_LEN;
  nonce.copy(header, off);
  return Buffer.concat([header, body]);
}

// ---------------------------------------------------------------- 路径 → 口令

/** ...\sessions\--<项目>--\session-<uuid>\session.v4.jsonl.zstd -> uuid */
function sessionIdOf(filePath) {
  const m = /[\\/]session-([0-9a-fA-F-]{36})[\\/]session\.[^\\/]+$/.exec(String(filePath));
  return m ? m[1] : null;
}

async function readRaw(filePath) {
  try {
    return await fsp.readFile(filePath);
  } catch {
    return null;
  }
}

/** 解出第一行（header）。压缩/未压缩都能处理。 */
function firstLineOf(buf, compressed) {
  let text;
  if (compressed) {
    try {
      text = zlib.zstdDecompressSync(buf).toString("utf8");
    } catch {
      return undefined;
    }
  } else {
    text = buf.toString("utf8");
  }
  const nl = text.indexOf("\n");
  return nl === -1 ? text : text.slice(0, nl);
}

// ---------------------------------------------------------------- 打补丁

/**
 * @param ctx cordis Context
 * @param opts { onLocked?: (id) => void }
 * @returns 解析出的服务信息（给诊断用）
 */
export function patchBackend(ctx, opts = {}) {
  const info = { ok: false, proto: null, methods: [] };
  const sp = typeof ctx.get === "function" ? ctx.get("sessionPersistence") : ctx.sessionPersistence;
  if (!sp) {
    info.error = "sessionPersistence 不可用";
    return info;
  }
  const proto = Object.getPrototypeOf(sp);
  if (!proto) {
    info.error = "拿不到原型";
    return info;
  }
  info.proto = proto.constructor?.name || "?";
  if (proto[PATCH_FLAG]) {
    info.ok = true;
    info.error = "已打过补丁";
    return info;
  }

  const orig = {
    readFirstZstdLine: proto.readFirstZstdLine,
    readFirstLine: proto.readFirstLine,
    open: proto.open,
  };

  // ---- 读 header（zstd 会话）----
  if (typeof orig.readFirstZstdLine === "function") {
    proto.readFirstZstdLine = async function patchedReadFirstZstdLine(filePath, signal) {
      const raw = await readRaw(filePath);
      if (raw && isEncrypted(raw)) {
        const id = sessionIdOf(filePath);
        const pw = id ? keys.get(id) : null;
        if (!pw) {
          // 没口令 —— 返回 undefined，list() 会跳过这条会话
          return undefined;
        }
        const zstd = decryptBuffer(raw, pw);
        return firstLineOf(zstd, true);
      }
      return orig.readFirstZstdLine.call(this, filePath, signal);
    };
    info.methods.push("readFirstZstdLine");
  }

  // ---- 读 header（未压缩会话）----
  if (typeof orig.readFirstLine === "function") {
    proto.readFirstLine = async function patchedReadFirstLine(filePath, signal) {
      const raw = await readRaw(filePath);
      if (raw && isEncrypted(raw)) {
        const id = sessionIdOf(filePath);
        const pw = id ? keys.get(id) : null;
        if (!pw) return undefined;
        return firstLineOf(decryptBuffer(raw, pw), false);
      }
      return orig.readFirstLine.call(this, filePath, signal);
    };
    info.methods.push("readFirstLine");
  }

  // ---- 读/写正文 ----
  if (typeof orig.open === "function") {
    proto.open = async function patchedOpen(id, access, ...rest) {
      const handle = await orig.open.call(this, id, access, ...rest);
      const location = handle?.location?.path;
      if (!location) return handle;

      const raw = await readRaw(location);
      if (!raw || !isEncrypted(raw)) return handle;   // 明文，原样返回

      const pw = keys.get(id);
      if (!pw) {
        try { await handle.close(); } catch { /* ignore */ }
        const err = new Error(`SESSION_LOCKED:${id}`);
        err.code = "SESSION_LOCKED";
        err.sessionId = id;
        if (typeof opts.onLocked === "function") {
          try { opts.onLocked(id); } catch { /* ignore */ }
        }
        throw err;
      }

      // 有口令：把 handle 的 read 换成从解密后的内容返回
      const plain = decryptBuffer(raw, pw);
      const origRead = handle.read.bind(handle);
      handle.read = async (buffer, offset, length, position) => {
        const pos = position ?? 0;
        const n = Math.max(0, Math.min(length, plain.length - pos));
        plain.copy(buffer, offset, pos, pos + n);
        return { bytesRead: n, buffer };
      };
      handle.__vaultOrigRead = origRead;
      return handle;
    };
    info.methods.push("open");
  }

  proto[PATCH_FLAG] = true;
  proto[Symbol.for("dsh-session-vault.backendRestore")] = () => {
    if (orig.readFirstZstdLine) proto.readFirstZstdLine = orig.readFirstZstdLine;
    if (orig.readFirstLine) proto.readFirstLine = orig.readFirstLine;
    if (orig.open) proto.open = orig.open;
    delete proto[PATCH_FLAG];
  };

  if (typeof ctx.effect === "function") {
    ctx.effect(() => () => {
      const restore = proto[Symbol.for("dsh-session-vault.backendRestore")];
      if (typeof restore === "function") restore();
    }, "session-vault: backend patch");
  }

  info.ok = true;
  return info;
}

export function unpatchBackend(ctx) {
  const sp = typeof ctx.get === "function" ? ctx.get("sessionPersistence") : ctx?.sessionPersistence;
  const proto = sp ? Object.getPrototypeOf(sp) : null;
  const restore = proto?.[Symbol.for("dsh-session-vault.backendRestore")];
  if (typeof restore === "function") restore();
}
