'use strict';

const crypto = require('crypto');

/** 生成随机 ID */
function randomId(prefix = '') {
  return prefix + crypto.randomBytes(12).toString('hex');
}

/** scrypt 密码哈希，格式 scrypt:<salt>:<hash> */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

/** 校验密码（恒定时间比较） */
function verifyPassword(password, stored) {
  try {
    const [scheme, salt, hash] = String(stored).split(':');
    if (scheme !== 'scrypt' || !salt || !hash) return false;
    const candidate = crypto.scryptSync(String(password), salt, 64);
    const expected = Buffer.from(hash, 'hex');
    return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
  } catch {
    return false;
  }
}

/** 密码强度校验，返回错误信息或 null */
function passwordError(pw) {
  if (typeof pw !== 'string' || pw.length < 8 || pw.length > 72) return '密码长度需为 8-72 位';
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return '密码需同时包含字母和数字';
  return null;
}

/** 验证码只做哈希存储，不存明文 */
function hashCode(code) {
  return crypto.createHash('sha256').update(String(code)).digest('hex');
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CERT_NO_RE = /^[A-Za-z0-9-]{4,32}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isValidEmail(s) {
  return typeof s === 'string' && s.length <= 254 && EMAIL_RE.test(s);
}

function isValidCertNo(s) {
  return typeof s === 'string' && CERT_NO_RE.test(s);
}

function isValidDate(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

function isValidName(s) {
  return typeof s === 'string' && s.trim().length >= 1 && s.trim().length <= 64;
}

/** 邮箱打码：ab***@example.com */
function maskEmail(email) {
  if (!email) return '';
  const at = email.indexOf('@');
  if (at < 0) return '***';
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  return `${local.slice(0, Math.min(2, local.length))}***@${domain}`;
}

/** 本地业务日期 YYYY-MM-DD */
function todayStr() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** 简单内存滑动窗口限流器 */
class RateLimiter {
  constructor() {
    this.hits = new Map();
  }
  /** 在 windowMs 内允许 limit 次，返回是否放行 */
  take(key, limit, windowMs) {
    const now = Date.now();
    let arr = this.hits.get(key);
    if (!arr) {
      arr = [];
      this.hits.set(key, arr);
    }
    while (arr.length && arr[0] <= now - windowMs) arr.shift();
    if (arr.length >= limit) return false;
    arr.push(now);
    return true;
  }
  /** 清理空桶，避免内存膨胀 */
  sweep() {
    for (const [k, v] of this.hits) {
      if (!v.length) this.hits.delete(k);
    }
  }
}

module.exports = {
  randomId,
  hashPassword,
  verifyPassword,
  passwordError,
  hashCode,
  isValidEmail,
  isValidCertNo,
  isValidDate,
  isValidName,
  maskEmail,
  todayStr,
  RateLimiter,
};
