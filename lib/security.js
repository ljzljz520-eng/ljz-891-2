// 安全相关工具：密码哈希、HMAC 签名、随机数、常量时间比较
import { randomBytes, pbkdf2, timingSafeEqual, createHmac, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(pbkdf2);
const PBKDF2_ITERATIONS = 120_000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';

/**
 * 使用 PBKDF2 对密码做加盐哈希
 * 返回 pbkdf2$iterations$saltHex$hashHex
 */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await pbkdf2Async(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

/**
 * 校验密码（常量时间比较）
 */
export async function verifyPassword(password, stored) {
  try {
    const [scheme, iterStr, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'pbkdf2') return false;
    const iterations = Number(iterStr);
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await pbkdf2Async(password, salt, iterations, expected.length, PBKDF2_DIGEST);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/** 生成密码学安全的随机 ID（不暴露数据库顺序） */
export function generateId(len = 16) {
  return randomBytes(len).toString('hex');
}

/** 生成 6 位数字验证码 */
export function generateDigitCode() {
  // 避免高位 0 丢失：取 1000000 以内随机数后左侧补零
  const n = randomBytes(4).readUInt32BE(0) % 1_000_000;
  return String(n).padStart(6, '0');
}

/** 对验证码/令牌做 SHA-256 后存储，避免明文泄露即可冒用 */
export function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

/** HMAC-SHA256 签名 */
export function hmac(secret, data) {
  return createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * 生成可离线校验的签名令牌： payloadBase64.signature
 * payload 为 JSON 字符串
 */
export function signToken(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${hmac(secret, body)}`;
}

/** 校验签名令牌，通过且未过期则返回 payload，否则 null */
export function verifySignedToken(secret, token) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(secret, body);
  if (!safeEqualStr(expected, sig)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof payload !== 'object' || payload === null) return null;
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export function safeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * 邮箱脱敏：保留首字符与域名
 * zhangsan@example.com -> z***@example.com
 * ab@example.com -> a*@example.com
 */
export function maskEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) return '';
  const [local, domain] = email.split('@');
  if (local.length <= 1) return `${local}*@${domain}`;
  return `${local[0]}${'*'.repeat(Math.min(local.length - 1, 4))}@${domain}`;
}

const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export function isValidEmail(email) {
  return EMAIL_RE.test(email) && email.length <= 254;
}
