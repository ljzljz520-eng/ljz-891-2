// 基于内存的固定窗口限流器（单进程足够；多实例可替换为 Redis）
const buckets = new Map();

// 定期清理过期条目，防止内存无限增长
const sweepTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, b] of buckets) {
    if (now >= b.resetAt) buckets.delete(key);
  }
}, 5 * 60 * 1000);
sweepTimer.unref();

/**
 * 检查是否允许通过
 * @param {string} key 限流键
 * @param {number} limit 窗口内最大次数
 * @param {number} windowMs 窗口时长（毫秒）
 * @returns {{allowed:boolean, remaining:number, resetAt:number}}
 */
export function consume(key, limit, windowMs) {
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;
  return {
    allowed: bucket.count <= limit,
    remaining: Math.max(0, limit - bucket.count),
    resetAt: bucket.resetAt,
  };
}

/** 读取当前状态（不计数） */
export function peek(key, limit, windowMs) {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    return { count: 0, remaining: limit, resetAt: now + windowMs };
  }
  return { count: bucket.count, remaining: Math.max(0, limit - bucket.count), resetAt: bucket.resetAt };
}

/** 手动增加计数 */
export function bump(key, windowMs) {
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;
  return bucket;
}
