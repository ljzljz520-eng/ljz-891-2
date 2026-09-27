// 培训证书核验系统 —— HTTP 服务入口（零外部依赖）
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as store from './lib/store.js';
import {
  hashPassword,
  verifyPassword,
  generateId,
  generateDigitCode,
  sha256,
  signToken,
  verifySignedToken,
  safeEqualStr,
  maskEmail,
  normalizeEmail,
  isValidEmail,
} from './lib/security.js';
import { consume, peek, bump } from './lib/rate-limit.js';
import { createMailer, verificationCodeEmail, emailChangedNotifyEmail } from './lib/mailer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// 邮箱验证码参数
const CODE_TTL_MS = 10 * 60 * 1000; // 10 分钟有效
const CODE_TTL_MIN = 10;
const CODE_RESEND_MS = 60 * 1000; // 60 秒重发冷却
const CODE_MAX_ATTEMPTS = 5;
const VERIFY_TOKEN_TTL_MS = 30 * 60 * 1000; // 核验令牌 30 分钟
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 登录会话 8 小时

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// ---------- 初始化 ----------
const initInfo = await store.initStore(DATA_FILE);
const TOKEN_SECRET = store.getTokenSecret();
const mailer = createMailer({
  smtpUrl: process.env.SMTP_URL || '',
  fromName: process.env.MAIL_FROM_NAME || '培训证书核验平台',
  fromEmail: process.env.MAIL_FROM_EMAIL || 'noreply@cert.local',
  logDir: DATA_DIR,
});

// 管理员会话（内存）： sid -> { adminId, csrf, createdAt, lastAccess }
const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.lastAccess > SESSION_TTL_MS) sessions.delete(sid);
  }
}, 10 * 60 * 1000).unref?.();

// 登录失败计数： key -> {count, resetAt}
const loginFails = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of loginFails) if (now >= v.resetAt) loginFails.delete(k);
}, 5 * 60 * 1000).unref?.();

// 定时清理过期验证码记录（每 15 分钟）
setInterval(() => {
  store.pruneEmailCodes().catch((e) => console.warn('清理验证码失败:', e.message));
}, 15 * 60 * 1000).unref?.();

// ---------- HTTP 工具 ----------
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function ok(res, data = {}) {
  sendJson(res, 200, { ok: true, ...data });
}

function fail(res, status, code, message, extra = {}) {
  sendJson(res, status, { ok: false, error: { code, message }, ...extra });
}

async function readBody(req, max = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > max) {
        reject(new HttpError(413, 'PAYLOAD_TOO_LARGE', '请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'BAD_JSON', '请求数据格式错误'));
      }
    });
    req.on('error', reject);
  });
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || '';
}

function requireFields(obj, fields) {
  const missing = [];
  for (const f of fields) {
    if (obj[f] === undefined || obj[f] === null || String(obj[f]).trim() === '') missing.push(f);
  }
  if (missing.length) {
    throw new HttpError(400, 'MISSING_FIELDS', `缺少必填项：${missing.join('、')}`);
  }
}

function isString(v) {
  return typeof v === 'string';
}

function isValidDateStr(v) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const t = Date.parse(`${v}T00:00:00`);
  if (!Number.isFinite(t)) return false;
  const [y, m, d] = v.split('-').map(Number);
  const dt = new Date(t);
  return dt.getUTCFullYear() === y && dt.getUTCMonth() + 1 === m && dt.getUTCDate() === d;
}

function parsePagination(query) {
  let page = Number(query.get('page')) || 1;
  let pageSize = Number(query.get('pageSize')) || 20;
  page = Math.min(Math.max(page, 1), 1000);
  pageSize = Math.min(Math.max(pageSize, 1), 100);
  return { page, pageSize };
}

async function audit({ admin, action, targetType = '', targetId = '', detail = {}, ip = '' }) {
  await store.addAuditLog({
    id: 'log_' + generateId(12),
    adminId: admin?.id || null,
    adminName: admin?.username || '',
    action,
    targetType,
    targetId,
    detail,
    ip,
    at: new Date().toISOString(),
  });
}

// ---------- 会话 ----------
function createSession(admin) {
  const sid = generateId(24);
  const csrf = generateId(24);
  sessions.set(sid, { adminId: admin.id, csrf, createdAt: Date.now(), lastAccess: Date.now() });
  return { sid, csrf };
}

function destroySession(sid) {
  sessions.delete(sid);
}

function getSessionAdmin(req) {
  const cookies = parseCookies(req);
  const sid = cookies.cv_session;
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.lastAccess > SESSION_TTL_MS) {
    sessions.delete(sid);
    return null;
  }
  const admin = store.findAdminById(s.adminId);
  if (!admin || !admin.active) {
    sessions.delete(sid);
    return null;
  }
  s.lastAccess = Date.now();
  return { admin, session: s, sid };
}

function sessionCookie(sid) {
  const attrs = [
    `cv_session=${encodeURIComponent(sid)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (IS_PROD) attrs.push('Secure');
  return attrs.join('; ');
}

function clearSessionCookie() {
  const attrs = ['cv_session=', 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0'];
  if (IS_PROD) attrs.push('Secure');
  return attrs.join('; ');
}

/** 来源校验（基础 CSRF 防御） */
function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return; // 同源 GET/旧浏览器可能不带
  const host = req.headers.host;
  try {
    const o = new URL(origin);
    if (o.host !== host) {
      throw new HttpError(403, 'ORIGIN_FORBIDDEN', '请求来源不被允许');
    }
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(403, 'ORIGIN_FORBIDDEN', '请求来源不被允许');
  }
}

// ---------- 序列化 ----------
function publicCertificate(cert) {
  return {
    certNo: cert.certNo,
    studentName: cert.studentName,
    courseName: cert.courseName,
    issueDate: cert.issueDate,
    validUntil: cert.validUntil,
    longTerm: !!cert.longTerm,
    institution: cert.institution,
    status: store.computeStatus(cert),
    contactEmailMasked: cert.contactEmail ? maskEmail(cert.contactEmail) : '',
    revokedReason: cert.revoked ? cert.revokedReason || '' : '',
  };
}

function adminView(admin) {
  return {
    id: admin.id,
    username: admin.username,
    displayName: admin.displayName,
    role: admin.role,
    active: admin.active,
    mustChangePassword: !!admin.mustChangePassword,
    createdAt: admin.createdAt,
  };
}

function adminCertificate(cert) {
  return {
    ...publicCertificate(cert),
    id: cert.id,
    contactEmail: cert.contactEmail || '',
    revoked: !!cert.revoked,
    revokedReason: cert.revokedReason || '',
    createdBy: cert.createdBy || '',
    createdAt: cert.createdAt,
    updatedAt: cert.updatedAt || cert.createdAt,
  };
}

// ---------- 校验 ----------
function validateCertificateInput(input, { partial = false } = {}) {
  const out = {};
  const get = (k) => input[k];

  if (!partial || get('certNo') !== undefined) {
    const v = String(get('certNo') ?? '').trim();
    if (!v) throw new HttpError(400, 'VALIDATION_ERROR', '证书编号不能为空');
    if (v.length < 3 || v.length > 64) throw new HttpError(400, 'VALIDATION_ERROR', '证书编号长度应为 3-64 个字符');
    if (!/^[A-Za-z0-9][A-Za-z0-9-_/]*$/.test(v)) {
      throw new HttpError(400, 'VALIDATION_ERROR', '证书编号仅支持字母、数字及 - _ / 符号');
    }
    out.certNo = v;
  }

  if (!partial || get('studentName') !== undefined) {
    const v = String(get('studentName') ?? '').trim();
    if (!v) throw new HttpError(400, 'VALIDATION_ERROR', '学员姓名不能为空');
    if (v.length > 50) throw new HttpError(400, 'VALIDATION_ERROR', '学员姓名过长');
    out.studentName = v;
  }

  if (!partial || get('courseName') !== undefined) {
    const v = String(get('courseName') ?? '').trim();
    if (!v) throw new HttpError(400, 'VALIDATION_ERROR', '课程名称不能为空');
    if (v.length > 120) throw new HttpError(400, 'VALIDATION_ERROR', '课程名称过长');
    out.courseName = v;
  }

  if (!partial || get('institution') !== undefined) {
    const v = String(get('institution') ?? '').trim();
    if (!v) throw new HttpError(400, 'VALIDATION_ERROR', '培训机构不能为空');
    if (v.length > 120) throw new HttpError(400, 'VALIDATION_ERROR', '培训机构名称过长');
    out.institution = v;
  }

  if (!partial || get('issueDate') !== undefined) {
    const v = String(get('issueDate') ?? '').trim();
    if (!isValidDateStr(v)) throw new HttpError(400, 'VALIDATION_ERROR', '发证日期格式应为 YYYY-MM-DD');
    out.issueDate = v;
  }

  if (!partial || get('longTerm') !== undefined) {
    out.longTerm = !!get('longTerm');
  }

  if (!partial || get('validUntil') !== undefined) {
    if (get('validUntil')) {
      const v = String(get('validUntil')).trim();
      if (!isValidDateStr(v)) throw new HttpError(400, 'VALIDATION_ERROR', '有效期截止日格式应为 YYYY-MM-DD');
      const issue = out.issueDate ?? null;
      if (issue && Date.parse(`${v}T00:00:00`) < Date.parse(`${issue}T00:00:00`)) {
        throw new HttpError(400, 'VALIDATION_ERROR', '有效期截止日不能早于发证日期');
      }
      out.validUntil = v;
    } else {
      out.validUntil = '';
    }
  }

  if (out.longTerm) out.validUntil = '';

  if (!partial || get('contactEmail') !== undefined) {
    const raw = get('contactEmail');
    if (raw === undefined || raw === null || String(raw).trim() === '') {
      out.contactEmail = '';
    } else {
      const v = normalizeEmail(raw);
      if (!isValidEmail(v)) throw new HttpError(400, 'VALIDATION_ERROR', '联系邮箱格式不正确');
      out.contactEmail = v;
    }
  }

  if (!partial || get('revoked') !== undefined) {
    out.revoked = !!get('revoked');
  }
  if (get('revokedReason') !== undefined) {
    out.revokedReason = String(get('revokedReason') ?? '').trim().slice(0, 200);
  }

  return out;
}

// ============================================================
// 公开接口（学员）
// ============================================================
async function publicApi(req, res, url) {
  const route = url.pathname;
  const ip = getClientIp(req);

  // 证书核验
  if (route === '/api/verify' && req.method === 'POST') {
    const rl = consume(`verify:${ip}`, 20, 10 * 60 * 1000);
    if (!rl.allowed) throw new HttpError(429, 'RATE_LIMITED', '核验尝试过于频繁，请稍后再试');

    const body = await readBody(req);
    requireFields(body, ['certNo', 'studentName']);
    const certNo = String(body.certNo).trim();
    const studentName = String(body.studentName).trim();
    if (certNo.length > 64 || studentName.length > 50) {
      throw new HttpError(400, 'VALIDATION_ERROR', '输入信息长度不正确');
    }

    const cert = store.findCertificateByNo(certNo);
    // 编号与姓名同时匹配才返回信息，避免枚举
    const matched = cert && cert.studentName === studentName;
    if (!matched) {
      return ok(res, { matched: false });
    }

    const token = signToken(TOKEN_SECRET, {
      cid: cert.id,
      name: cert.studentName,
      exp: Date.now() + VERIFY_TOKEN_TTL_MS,
    });
    return ok(res, {
      matched: true,
      certificate: publicCertificate(cert),
      token,
      expiresIn: VERIFY_TOKEN_TTL_MS / 1000,
    });
  }

  // 申请邮箱更正验证码
  if (route === '/api/email/request-code' && req.method === 'POST') {
    const rl = consume(`emailreq:${ip}`, 10, 15 * 60 * 1000);
    if (!rl.allowed) throw new HttpError(429, 'RATE_LIMITED', '请求过于频繁，请稍后再试');

    const body = await readBody(req);
    requireFields(body, ['token', 'newEmail']);
    const payload = verifySignedToken(TOKEN_SECRET, body.token);
    if (!payload?.cid) throw new HttpError(400, 'INVALID_TOKEN', '核验会话已失效，请重新核验证书');

    const cert = store.findCertificateById(payload.cid);
    if (!cert || cert.studentName !== payload.name) {
      throw new HttpError(404, 'CERT_NOT_FOUND', '证书不存在或信息已变更');
    }

    const newEmail = normalizeEmail(body.newEmail);
    if (!isValidEmail(newEmail)) throw new HttpError(400, 'VALIDATION_ERROR', '邮箱格式不正确');
    if (cert.contactEmail && newEmail === cert.contactEmail) {
      throw new HttpError(400, 'SAME_EMAIL', '新邮箱与当前联系邮箱相同，无需更正');
    }

    // 同一证书 60 秒冷却
    const existing = store
      .listEmailCodes()
      .filter((c) => c.certId === cert.id && !c.consumed)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
    if (existing) {
      const elapsed = Date.now() - new Date(existing.createdAt).getTime();
      if (elapsed < CODE_RESEND_MS) {
        const wait = Math.ceil((CODE_RESEND_MS - elapsed) / 1000);
        return fail(res, 429, 'COOLDOWN', `验证码发送后 ${wait} 秒内不可重复获取`, { retryAfter: wait });
      }
    }

    const code = generateDigitCode();
    const record = {
      id: 'emc_' + generateId(12),
      certId: cert.id,
      certNo: cert.certNo,
      newEmail,
      oldEmail: cert.contactEmail || '',
      codeHash: sha256(code),
      attempts: 0,
      consumed: false,
      ip,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + CODE_TTL_MS).toISOString(),
    };
    const tpl = verificationCodeEmail(code, CODE_TTL_MIN);
    try {
      await mailer.send({ to: newEmail, ...tpl });
    } catch (e) {
      console.error('验证码邮件发送失败:', e.message);
      throw new HttpError(502, 'MAIL_SEND_FAILED', `验证码邮件发送失败，请稍后重试（${e.message}）`);
    }
    await store.createEmailCode(record);

    const result = { sent: true, cooldown: CODE_RESEND_MS / 1000 };
    // 仅开发/控制台模式返回验证码，方便联调；生产 SMTP 模式不返回
    if (mailer.mode === 'console') result.devCode = code;
    return ok(res, result);
  }

  // 校验验证码并更正邮箱
  if (route === '/api/email/confirm' && req.method === 'POST') {
    const rl = consume(`emailconfirm:${ip}`, 15, 15 * 60 * 1000);
    if (!rl.allowed) throw new HttpError(429, 'RATE_LIMITED', '尝试过于频繁，请稍后再试');

    const body = await readBody(req);
    requireFields(body, ['token', 'code']);
    const payload = verifySignedToken(TOKEN_SECRET, body.token);
    if (!payload?.cid) throw new HttpError(400, 'INVALID_TOKEN', '核验会话已失效，请重新核验证书');

    const cert = store.findCertificateById(payload.cid);
    if (!cert || cert.studentName !== payload.name) {
      throw new HttpError(404, 'CERT_NOT_FOUND', '证书不存在或信息已变更');
    }

    const code = String(body.code).trim();
    if (!/^\d{6}$/.test(code)) throw new HttpError(400, 'VALIDATION_ERROR', '请输入 6 位数字验证码');

    const rec = store
      .listEmailCodes()
      .filter((c) => c.certId === cert.id && !c.consumed)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];

    if (!rec) throw new HttpError(400, 'NO_CODE', '请先获取验证码');
    if (Date.now() > new Date(rec.expiresAt).getTime()) {
      throw new HttpError(400, 'CODE_EXPIRED', '验证码已过期，请重新获取');
    }
    if (rec.attempts >= CODE_MAX_ATTEMPTS) {
      throw new HttpError(429, 'TOO_MANY_ATTEMPTS', '验证错误次数过多，请重新获取验证码');
    }
    if (!safeEqualStr(rec.codeHash, sha256(code))) {
      const used = rec.attempts + 1;
      await store.updateEmailCode(rec.id, { attempts: used });
      const left = CODE_MAX_ATTEMPTS - used;
      throw new HttpError(400, 'BAD_CODE', `验证码不正确${left > 0 ? `，还可尝试 ${left} 次` : '，请重新获取验证码'}`);
    }

    // 二次确认新邮箱仍与当前不同
    if (cert.contactEmail && rec.newEmail === cert.contactEmail) {
      await store.updateEmailCode(rec.id, { consumed: true, consumedAt: new Date().toISOString() });
      throw new HttpError(400, 'SAME_EMAIL', '新邮箱与当前联系邮箱相同，无需更正');
    }

    const oldEmail = cert.contactEmail || '';
    await store.updateCertificate(cert.id, { contactEmail: rec.newEmail });
    await store.updateEmailCode(rec.id, { consumed: true, consumedAt: new Date().toISOString() });

    await audit({
      admin: null,
      action: 'email.corrected',
      targetType: 'certificate',
      targetId: cert.id,
      detail: { certNo: cert.certNo, oldEmail, newEmail: rec.newEmail, via: 'self-service', ip },
      ip,
    });

    // 向新邮箱发送更正成功通知（best effort）
    mailer
      .send({
        to: rec.newEmail,
        ...emailChangedNotifyEmail(oldEmail ? maskEmail(oldEmail) : '（未登记）', rec.newEmail),
      })
      .catch((e) => console.warn('邮箱更正通知发送失败:', e.message));

    const updated = store.findCertificateById(cert.id);
    return ok(res, { contactEmailMasked: maskEmail(updated.contactEmail) });
  }

  throw new HttpError(404, 'NOT_FOUND', '接口不存在');
}

// ============================================================
// 管理接口
// ============================================================
async function adminApi(req, res, url) {
  const route = url.pathname;
  const ip = getClientIp(req);
  const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  if (isMutation) checkOrigin(req);

  // ---- 登录 / 登出 / 当前会话（无需鉴权） ----
  if (route === '/api/admin/login' && req.method === 'POST') {
    const rl = consume(`login:${ip}`, 12, 15 * 60 * 1000);
    if (!rl.allowed) throw new HttpError(429, 'RATE_LIMITED', '登录尝试过于频繁，请稍后再试');

    const body = await readBody(req);
    requireFields(body, ['username', 'password']);
    const username = String(body.username).trim();
    const password = String(body.password);
    if (username.length > 64 || password.length > 200) {
      throw new HttpError(400, 'VALIDATION_ERROR', '用户名或密码格式不正确');
    }

    const failKey = `loginfail:${username.toLowerCase()}:${ip}`;
    const f = loginFails.get(failKey);
    if (f && Date.now() < f.resetAt && f.count >= 8) {
      throw new HttpError(429, 'TOO_MANY_FAILURES', '该账号登录失败次数过多，请 15 分钟后再试');
    }

    const admin = store.findAdminByUsername(username);
    const passed = admin && admin.active && (await verifyPassword(password, admin.passwordHash));
    if (!passed) {
      const now = Date.now();
      const entry = loginFails.get(failKey);
      if (!entry || now >= entry.resetAt) {
        loginFails.set(failKey, { count: 1, resetAt: now + 15 * 60 * 1000 });
      } else {
        entry.count += 1;
      }
      await audit({
        admin: admin || null,
        action: 'admin.login_failed',
        detail: { username, reason: admin ? (!admin.active ? 'disabled' : 'bad_password') : 'not_found' },
        ip,
      });
      throw new HttpError(401, 'BAD_CREDENTIALS', '用户名或密码错误');
    }

    loginFails.delete(failKey);
    const { sid, csrf } = createSession(admin);
    res.setHeader('Set-Cookie', sessionCookie(sid));
    await audit({ admin, action: 'admin.login', ip });
    return ok(res, { admin: adminView(admin), csrf });
  }

  // 以下接口均需登录
  const ctx = getSessionAdmin(req);
  if (!ctx) throw new HttpError(401, 'UNAUTHORIZED', '未登录或会话已过期');
  const { admin, session } = ctx;

  if (route === '/api/admin/logout' && req.method === 'POST') {
    if (isMutation) verifyCsrf(req, session);
    destroySession(ctx.sid);
    res.setHeader('Set-Cookie', clearSessionCookie());
    await audit({ admin, action: 'admin.logout', ip });
    return ok(res);
  }

  if (route === '/api/admin/me' && req.method === 'GET') {
    return ok(res, { admin: adminView(admin), csrf: session.csrf });
  }

  // 修改自己的密码
  if (route === '/api/admin/me/password' && req.method === 'POST') {
    verifyCsrf(req, session);
    const body = await readBody(req);
    requireFields(body, ['oldPassword', 'newPassword']);
    if (!(await verifyPassword(String(body.oldPassword), admin.passwordHash))) {
      throw new HttpError(400, 'BAD_PASSWORD', '原密码不正确');
    }
    assertPasswordPolicy(body.newPassword);
    admin.passwordHash = await hashPassword(String(body.newPassword));
    admin.mustChangePassword = false;
    await store.updateAdmin(admin.id, {
      passwordHash: admin.passwordHash,
      mustChangePassword: false,
    });
    await audit({ admin, action: 'admin.password_self_changed', ip });
    return ok(res);
  }

  // 证书管理（编辑角色及以上）
  if (route === '/api/admin/certificates' && req.method === 'GET') {
    const { page, pageSize } = parsePagination(url.searchParams);
    const keyword = String(url.searchParams.get('keyword') || '').trim().slice(0, 100);
    const status = String(url.searchParams.get('status') || '').trim();
    const { items, total } = store.listCertificates({ keyword, status, page, pageSize });
    return ok(res, {
      items: items.map(adminCertificate),
      total,
      page,
      pageSize,
    });
  }

  if (route === '/api/admin/certificates' && req.method === 'POST') {
    verifyCsrf(req, session);
    const body = await readBody(req);
    const data = validateCertificateInput(body);
    if (store.findCertificateByNo(data.certNo)) {
      throw new HttpError(409, 'CERT_NO_EXISTS', '该证书编号已存在');
    }
    const now = new Date().toISOString();
    const cert = {
      id: 'cer_' + generateId(12),
      ...data,
      revokedReason: data.revokedReason || '',
      createdBy: admin.id,
      createdAt: now,
      updatedAt: now,
    };
    await store.createCertificate(cert);
    await audit({ admin, action: 'cert.created', targetType: 'certificate', targetId: cert.id, detail: { certNo: cert.certNo }, ip });
    return sendJson(res, 201, { ok: true, certificate: adminCertificate(cert) });
  }

  const certMatch = url.pathname.match(/^\/api\/admin\/certificates\/([A-Za-z0-9_]+)$/);
  if (certMatch) {
    const certId = certMatch[1];
    const cert = store.findCertificateById(certId);
    if (!cert) throw new HttpError(404, 'CERT_NOT_FOUND', '证书不存在');

    if (req.method === 'GET') {
      return ok(res, { certificate: adminCertificate(cert) });
    }
    if (req.method === 'PUT') {
      verifyCsrf(req, session);
      const body = await readBody(req);
      const data = validateCertificateInput(body);
      const dup = store.findCertificateByNo(data.certNo);
      if (dup && dup.id !== cert.id) {
        throw new HttpError(409, 'CERT_NO_EXISTS', '该证书编号已被其他证书占用');
      }
      const before = adminCertificate(cert);
      await store.updateCertificate(cert.id, data);
      await audit({
        admin,
        action: 'cert.updated',
        targetType: 'certificate',
        targetId: cert.id,
        detail: { before, after: data },
        ip,
      });
      return ok(res, { certificate: adminCertificate(store.findCertificateById(cert.id)) });
    }
    if (req.method === 'DELETE') {
      verifyCsrf(req, session);
      await store.deleteCertificate(cert.id);
      await audit({
        admin,
        action: 'cert.deleted',
        targetType: 'certificate',
        targetId: cert.id,
        detail: { certNo: cert.certNo, studentName: cert.studentName },
        ip,
      });
      return ok(res);
    }
  }

  // 吊销 / 恢复
  const revokeMatch = url.pathname.match(/^\/api\/admin\/certificates\/([A-Za-z0-9_]+)\/revoke$/);
  if (revokeMatch && req.method === 'POST') {
    verifyCsrf(req, session);
    const cert = store.findCertificateById(revokeMatch[1]);
    if (!cert) throw new HttpError(404, 'CERT_NOT_FOUND', '证书不存在');
    const body = await readBody(req);
    const revoked = body.revoked !== false; // 默认吊销
    const reason = String(body.reason || '').trim().slice(0, 200);
    await store.updateCertificate(cert.id, {
      revoked,
      revokedReason: revoked ? reason : '',
    });
    await audit({
      admin,
      action: revoked ? 'cert.revoked' : 'cert.restored',
      targetType: 'certificate',
      targetId: cert.id,
      detail: { certNo: cert.certNo, reason },
      ip,
    });
    return ok(res, { certificate: adminCertificate(store.findCertificateById(cert.id)) });
  }

  // ---- 管理员账号管理（仅超级管理员） ----
  if (route === '/api/admin/admins' && req.method === 'GET') {
    requireSuper(admin);
    return ok(res, { admins: store.listAdmins().map(adminView) });
  }

  if (route === '/api/admin/admins' && req.method === 'POST') {
    requireSuper(admin);
    verifyCsrf(req, session);
    const body = await readBody(req);
    requireFields(body, ['username', 'password', 'displayName', 'role']);
    const username = String(body.username).trim();
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      throw new HttpError(400, 'VALIDATION_ERROR', '用户名需为 3-32 位字母、数字或 . _ -');
    }
    if (store.findAdminByUsername(username)) {
      throw new HttpError(409, 'USERNAME_EXISTS', '用户名已存在');
    }
    if (!['super', 'editor'].includes(body.role)) {
      throw new HttpError(400, 'VALIDATION_ERROR', '角色不合法');
    }
    assertPasswordPolicy(body.password);
    const displayName = String(body.displayName).trim();
    if (!displayName || displayName.length > 50) {
      throw new HttpError(400, 'VALIDATION_ERROR', '显示姓名长度应为 1-50 个字符');
    }
    const newAdmin = {
      id: 'adm_' + generateId(12),
      username,
      passwordHash: await hashPassword(String(body.password)),
      displayName,
      role: body.role,
      mustChangePassword: body.mustChangePassword !== false,
      active: body.active !== false,
      createdAt: new Date().toISOString(),
      createdBy: admin.id,
    };
    await store.createAdmin(newAdmin);
    await audit({ admin, action: 'admin.created', targetType: 'admin', targetId: newAdmin.id, detail: { username, role: newAdmin.role }, ip });
    return sendJson(res, 201, { ok: true, admin: adminView(newAdmin) });
  }

  const adminMatch = url.pathname.match(/^\/api\/admin\/admins\/([A-Za-z0-9_]+)$/);
  if (adminMatch) {
    requireSuper(admin);
    const target = store.findAdminById(adminMatch[1]);
    if (!target) throw new HttpError(404, 'ADMIN_NOT_FOUND', '管理员不存在');

    if (req.method === 'PATCH') {
      verifyCsrf(req, session);
      const body = await readBody(req);
      const patch = {};
      if (body.displayName !== undefined) {
        const v = String(body.displayName).trim();
        if (!v || v.length > 50) throw new HttpError(400, 'VALIDATION_ERROR', '显示姓名长度应为 1-50 个字符');
        patch.displayName = v;
      }
      if (body.role !== undefined) {
        if (!['super', 'editor'].includes(body.role)) throw new HttpError(400, 'VALIDATION_ERROR', '角色不合法');
        // 防止撤销最后一个启用的超级管理员
        if (target.role === 'super' && body.role !== 'super' && target.active) {
          if (store.countSuperAdmins() <= 1) throw new HttpError(400, 'LAST_SUPER', '至少保留一个启用的超级管理员');
        }
        patch.role = body.role;
      }
      if (body.active !== undefined) {
        const active = !!body.active;
        if (!active && target.id === admin.id) throw new HttpError(400, 'SELF_ACTION', '不能停用自己的账号');
        if (!active && target.role === 'super' && store.countSuperAdmins() <= 1) {
          throw new HttpError(400, 'LAST_SUPER', '至少保留一个启用的超级管理员');
        }
        patch.active = active;
      }
      await store.updateAdmin(target.id, patch);
      await audit({ admin, action: 'admin.updated', targetType: 'admin', targetId: target.id, detail: patch, ip });
      return ok(res, { admin: adminView(store.findAdminById(target.id)) });
    }
    if (req.method === 'DELETE') {
      verifyCsrf(req, session);
      if (target.id === admin.id) throw new HttpError(400, 'SELF_ACTION', '不能删除自己的账号');
      if (target.role === 'super' && target.active && store.countSuperAdmins() <= 1) {
        throw new HttpError(400, 'LAST_SUPER', '至少保留一个启用的超级管理员');
      }
      await store.deleteAdmin(target.id);
      sessions.forEach((s, sid) => {
        if (s.adminId === target.id) sessions.delete(sid);
      });
      await audit({ admin, action: 'admin.deleted', targetType: 'admin', targetId: target.id, detail: { username: target.username }, ip });
      return ok(res);
    }
  }

  // 重置其他管理员密码
  const pwdMatch = url.pathname.match(/^\/api\/admin\/admins\/([A-Za-z0-9_]+)\/reset-password$/);
  if (pwdMatch && req.method === 'POST') {
    requireSuper(admin);
    verifyCsrf(req, session);
    const target = store.findAdminById(pwdMatch[1]);
    if (!target) throw new HttpError(404, 'ADMIN_NOT_FOUND', '管理员不存在');
    const body = await readBody(req);
    requireFields(body, ['newPassword']);
    assertPasswordPolicy(body.newPassword);
    await store.updateAdmin(target.id, {
      passwordHash: await hashPassword(String(body.newPassword)),
      mustChangePassword: true,
    });
    await audit({ admin, action: 'admin.password_reset', targetType: 'admin', targetId: target.id, ip });
    return ok(res);
  }

  // 审计日志（仅超级管理员）
  if (route === '/api/admin/audit-logs' && req.method === 'GET') {
    requireSuper(admin);
    const { page, pageSize } = parsePagination(url.searchParams);
    const action = String(url.searchParams.get('action') || '').trim();
    const { items, total } = store.listAuditLogs({ page, pageSize, action });
    return ok(res, { items, total, page, pageSize });
  }

  throw new HttpError(404, 'NOT_FOUND', '接口不存在');
}

function requireSuper(admin) {
  if (admin.role !== 'super') throw new HttpError(403, 'FORBIDDEN', '需要超级管理员权限');
}

function verifyCsrf(req, session) {
  const token = req.headers['x-csrf-token'];
  if (!token || !safeEqualStr(String(token), session.csrf)) {
    throw new HttpError(403, 'CSRF_FAILED', '安全令牌无效，请刷新页面后重试');
  }
}

function assertPasswordPolicy(pwd) {
  const p = String(pwd ?? '');
  if (p.length < 10) throw new HttpError(400, 'WEAK_PASSWORD', '密码至少 10 个字符');
  if (p.length > 200) throw new HttpError(400, 'WEAK_PASSWORD', '密码过长');
  let kinds = 0;
  if (/[a-z]/.test(p)) kinds += 1;
  if (/[A-Z]/.test(p)) kinds += 1;
  if (/\d/.test(p)) kinds += 1;
  if (/[^A-Za-z0-9]/.test(p)) kinds += 1;
  if (kinds < 3) throw new HttpError(400, 'WEAK_PASSWORD', '密码需包含大写字母、小写字母、数字、特殊字符中的至少 3 种');
}

// ---------- 静态文件 ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

async function serveStatic(req, res, url) {
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/index.html';
  if (pathname === '/admin') pathname = '/admin.html';

  // 防目录穿越
  const filePath = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep) && filePath !== PUBLIC_DIR) {
    return fail(res, 403, 'FORBIDDEN', '禁止访问');
  }
  if (!existsSync(filePath) || !statSync(filePath).isFile()) {
    return fail(res, 404, 'NOT_FOUND', '页面不存在');
  }
  const data = await readFile(filePath);
  const ext = path.extname(filePath).toLowerCase();
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
  });
  res.end(data);
}

// ---------- 主服务 ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    // 安全响应头
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; base-uri 'none'; frame-ancestors 'none'");

    if (url.pathname.startsWith('/api/email/') || url.pathname === '/api/verify') {
      return await publicApi(req, res, url);
    }
    if (url.pathname.startsWith('/api/admin/')) {
      return await adminApi(req, res, url);
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      return await serveStatic(req, res, url);
    }
    return fail(res, 405, 'METHOD_NOT_ALLOWED', '请求方法不被允许');
  } catch (e) {
    if (e instanceof HttpError) {
      return fail(res, e.status, e.code, e.message, e.code === 'COOLDOWN' ? e.extra : undefined);
    }
    console.error('服务器错误:', e);
    return fail(res, 500, 'INTERNAL_ERROR', '服务器内部错误');
  }
});

server.listen(PORT, HOST, () => {
  console.log('==========================================================');
  console.log('  培训证书核验系统已启动');
  console.log(`  地址: http://localhost:${PORT}`);
  console.log(`  学员核验: /    管理后台: /admin`);
  console.log(`  邮件传输: ${mailer.mode === 'smtp' ? 'SMTP' : '控制台模式（验证码输出到日志/data/mail.log）'}`);
  if (initInfo.firstRun) {
    console.log('----------------------------------------------------------');
    console.log('  首次启动：已创建默认超级管理员（请尽快登录并修改密码）');
    console.log(`    用户名: ${initInfo.defaultAdmin.username}`);
    console.log(`    密码:   ${initInfo.defaultAdmin.password}`);
    console.log('  已写入 5 张示例证书（学员页可直接核验，例如 张伟 / PX-2026-000127）');
  }
  console.log('==========================================================');
});
