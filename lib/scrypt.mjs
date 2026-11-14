/**
 * scrypt 参数的唯一来源。
 *
 * 为什么单独抽一个文件
 * --------------------
 * 之前四份代码各自硬编码了 N / maxmem：
 *
 *     lib/state.mjs        N: 32768
 *     lib/secret.mjs       MAXMEM = 256 MiB
 *     index.js             SCRYPT_N = 1 << 15, maxmem: 128 MiB
 *     backend-patch.js     SCRYPT_N = 1 << 15, maxmem: 128 MiB
 *
 * 提 N 的时候必须同时抬 maxmem，散在四处就一定会漏。实测漏了会直接抛
 * `Invalid scrypt params: MEMORY_LIMIT_EXCEEDED`，而且是在**用户输口令的那一刻**
 * 才炸，不会在启动时被发现。
 *
 * 内存需求
 * --------
 *     scrypt 需要 128 * N * r 字节
 *
 *     N=2^17 (131072), r=8  ->  128 MiB
 *
 * Node 要求 `maxmem` **严格大于**这个值，等于也不行（实测 maxmem=128 MiB
 * 直接 MEMORY_LIMIT_EXCEEDED）。所以这里取 2 倍余量。
 *
 * 改 N 的正确姿势
 * --------------
 * 只改下面的 N，然后跑 `node test/host-selftest.mjs`。
 * MAXMEM 会根据 N 自动放大到「需求的 2 倍」，不需要手动同步。
 */

/** OWASP 对 scrypt 的建议下限是 N = 2^17。 */
export const SCRYPT = {
  N: 1 << 17,
  r: 8,
  p: 1,
  keylen: 64,
};

/** 单次派生需要的内存量（字节）。 */
export function scryptMemoryNeed(n = SCRYPT.N, r = SCRYPT.r) {
  return 128 * n * r;
}

/**
 * 给 crypto.scryptSync / crypto.scrypt 用的 maxmem。
 * 取需求量的两倍，留出余量。
 */
export function scryptMaxMem(n = SCRYPT.N, r = SCRYPT.r) {
  return scryptMemoryNeed(n, r) * 2;
}

/**
 * 派生一个 32 字节密钥（WALLBK 容器和磁盘锁都用这个）。
 * 注意：口令记录的 keylen 是 64（存哈希用），这里固定 32 是给加密用的。
 */
export function scryptKeyOptions(n = SCRYPT.N, r = SCRYPT.r, p = SCRYPT.p) {
  return { N: n, r, p, maxmem: scryptMaxMem(n, r) };
}
