'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const db = require('./db');
const auth = require('./auth');
const mailer = require('./mailer');
const util = require('./util');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const DEV = process.env.NODE_ENV !== 'production';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const limiter = new util.RateLimiter();
setInterval(() => limiter.sweep(), 10 * 60 * 1000).unref();

/* ---------------- 基础工具 ---------------- */

function sendJson(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 64 * 1024) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

/** 证书状态：吊销 > 过期 > 有效（按业务日期动态计算） */
function certStatus(cert) {
  if (cert.revoked) return '已吊销';
  if (cert.valid_until < util.todayStr()) return '已过期';
  return '有效';
}

/** 对外展示的证书字段（邮箱打码） */
function publicCert(cert) {
  return {
    cert_no: cert.cert_no,
    name: cert.name,
    course_name: cert.course_name,
    issue_date: cert.issue_date,
    valid_until: cert.valid_until,
    org: cert.org,
    status: certStatus(cert),
    contact_email_masked: util.maskEmail(cert.contact_email),
  };
}

function findCert(certNo, name) {
  const no = String(certNo || '').trim().toUpperCase();
  const nm = String(name || '').trim();
  return db.data.certs.find((c) => c.cert_no.toUpperCase() === no && c.name === nm);
}

function requireAdmin(req, res) {
  const sid = auth.parseCookies(req)['sid'];
  const session = sid && auth.getSession(sid);
  if (!session) {
    sendJson(res, 401, { ok: false, error: '未登录或会话已过期' });
    return null;
  }
  const admin = db.data.admins.find((a) => a.id === session.adminId && a.active !== false);
  if (!admin) {
    sendJson(res, 401, { ok: false, error: '账号不可用' });
    return null;
  }
  return admin;
}

/** CSRF 缓解：所有写操作要求自定义头（配合 SameSite=Lax Cookie） */
function checkCsrf(req, res) {
  if ((req.headers['x-requested-with'] || '') !== 'fetch') {
    sendJson(res, 403, { ok: false, error: '非法请求' });
    return false;
  }
  return true;
}

/* ---------------- 路由表 ---------------- */

const routes = [];
function route(method, pattern, handler) {
  const keys = [];
  const rx = new RegExp(
    '^' + pattern.replace(/:[^/]+/g, (m) => {
      keys.push(m.slice(1));
      return '([^/]+)';
    }) + '$'
  );
  routes.push({ method, rx, keys, handler });
}

function matchRoute(method, pathname) {
  for (const r of routes) {
    if (r.method !== method) continue;
    const m = r.rx.exec(pathname);
    if (m) {
      const params = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      return { handler: r.handler, params };
    }
  }
  return null;
}

/* ---------------- 学员公开接口 ---------------- */

// 证书核验：证书编号 + 姓名
route('POST', '/api/public/verify', async (req, res) => {
  const ip = clientIp(req);
  if (!limiter.take(`verify:${ip}`, 30, 10 * 60 * 1000)) {
    return sendJson(res, 429, { ok: false, error: '查询过于频繁，请稍后再试' });
  }
  const body = await readBody(req);
  const certNo = String(body.cert_no || '').trim();
  const name = String(body.name || '').trim();
  if (!util.isValidCertNo(certNo) || !util.isValidName(name)) {
    return sendJson(res, 400, { ok: false, error: '请输入正确的证书编号与姓名' });
  }
  const cert = findCert(certNo, name);
  if (!cert) {
    // 统一提示，不暴露“编号存在但姓名不符”
    return sendJson(res, 404, { ok: false, error: '未查询到匹配的证书，请核对证书编号与姓名' });
  }
  return sendJson(res, 200, { ok: true, cert: publicCert(cert) });
});

// 邮箱更正：发送验证码到新邮箱
route('POST', '/api/public/email-change/request', async (req, res) => {
  const ip = clientIp(req);
  if (!limiter.take(`ecreq:${ip}`, 20, 60 * 60 * 1000)) {
    return sendJson(res, 429, { ok: false, error: '请求过于频繁，请稍后再试' });
  }
  const body = await readBody(req);
  const certNo = String(body.cert_no || '').trim();
  const name = String(body.name || '').trim();
  const newEmail = String(body.new_email || '').trim().toLowerCase();
  if (!util.isValidCertNo(certNo) || !util.isValidName(name) || !util.isValidEmail(newEmail)) {
    return sendJson(res, 400, { ok: false, error: '请填写正确的证书编号、姓名与新邮箱' });
  }
  const cert = findCert(certNo, name);
  if (!cert) {
    return sendJson(res, 404, { ok: false, error: '未查询到匹配的证书，请核对证书编号与姓名' });
  }
  if (!limiter.take(`ecreq:cert:${cert.id}`, 5, 60 * 60 * 1000)) {
    return sendJson(res, 429, { ok: false, error: '验证码发送过于频繁，请 1 小时后再试' });
  }
  if (cert.contact_email && cert.contact_email === newEmail) {
    return sendJson(res, 400, { ok: false, error: '新邮箱与当前联系邮箱相同' });
  }
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  // 同一证书只保留最新一条验证码记录
  db.data.email_codes = db.data.email_codes.filter((e) => e.cert_id !== cert.id);
  db.data.email_codes.push({
    id: util.randomId('ec_'),
    cert_id: cert.id,
    new_email: newEmail,
    code_hash: util.hashCode(code),
    expires_at: Date.now() + 10 * 60 * 1000,
    attempts: 0,
    created_at: new Date().toISOString(),
  });
  db.save();
  await mailer.sendMail({
    to: newEmail,
    subject: '【培训证书核验平台】邮箱更正验证码',
    text: `您正在为证书 ${cert.cert_no}（${cert.name}）申请更正联系邮箱。\n验证码：${code}（10 分钟内有效）。\n如非本人操作，请忽略本邮件。`,
  });
  const resp = { ok: true, message: `验证码已发送至 ${util.maskEmail(newEmail)}，10 分钟内有效` };
  if (mailer.DEV) resp.dev_code = code; // 开发/演示模式回传，生产不返回
  return sendJson(res, 200, resp);
});

// 邮箱更正：校验验证码并生效
route('POST', '/api/public/email-change/confirm', async (req, res) => {
  const body = await readBody(req);
  const certNo = String(body.cert_no || '').trim();
  const name = String(body.name || '').trim();
  const newEmail = String(body.new_email || '').trim().toLowerCase();
  const code = String(body.code || '').trim();
  if (!util.isValidCertNo(certNo) || !util.isValidName(name) || !util.isValidEmail(newEmail) || !/^\d{6}$/.test(code)) {
    return sendJson(res, 400, { ok: false, error: '请填写完整且格式正确的信息' });
  }
  const cert = findCert(certNo, name);
  if (!cert) {
    return sendJson(res, 404, { ok: false, error: '未查询到匹配的证书，请核对证书编号与姓名' });
  }
  const entry = db.data.email_codes.find((e) => e.cert_id === cert.id && e.new_email === newEmail);
  if (!entry) {
    return sendJson(res, 400, { ok: false, error: '请先获取验证码' });
  }
  if (entry.expires_at < Date.now()) {
    db.data.email_codes = db.data.email_codes.filter((e) => e.id !== entry.id);
    db.save();
    return sendJson(res, 400, { ok: false, error: '验证码已过期，请重新获取' });
  }
  if (entry.attempts >= 5) {
    db.data.email_codes = db.data.email_codes.filter((e) => e.id !== entry.id);
    db.save();
    return sendJson(res, 429, { ok: false, error: '尝试次数过多，请重新获取验证码' });
  }
  if (util.hashCode(code) !== entry.code_hash) {
    entry.attempts += 1;
    db.save();
    return sendJson(res, 400, { ok: false, error: `验证码不正确（剩余 ${5 - entry.attempts} 次机会）` });
  }
  const old = cert.contact_email;
  cert.contact_email = newEmail;
  cert.updated_at = new Date().toISOString();
  db.data.email_codes = db.data.email_codes.filter((e) => e.cert_id !== cert.id);
  db.audit('email_change', `cert:${cert.cert_no}`, `学员自助更正联系邮箱 ${util.maskEmail(old)} -> ${util.maskEmail(newEmail)}`);
  db.save();
  return sendJson(res, 200, { ok: true, message: '联系邮箱已更正' });
});

/* ---------------- 管理员接口 ---------------- */

route('POST', '/api/admin/login', async (req, res) => {
  const ip = clientIp(req);
  if (!limiter.take(`login:${ip}`, 10, 10 * 60 * 1000)) {
    return sendJson(res, 429, { ok: false, error: '尝试过于频繁，请稍后再试' });
  }
  const body = await readBody(req);
  const username = String(body.username || '').trim();
  const admin = db.data.admins.find((a) => a.username === username && a.active !== false);
  if (!admin || !util.verifyPassword(String(body.password || ''), admin.password_hash)) {
    return sendJson(res, 401, { ok: false, error: '用户名或密码错误' });
  }
  const sid = auth.createSession(admin);
  res.setHeader('Set-Cookie', `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${auth.SESSION_TTL / 1000}`);
  db.audit('admin_login', admin.username, '');
  db.save();
  return sendJson(res, 200, { ok: true, admin: { username: admin.username } });
});

route('POST', '/api/admin/logout', async (req, res) => {
  const sid = auth.parseCookies(req)['sid'];
  if (sid) auth.destroySession(sid);
  res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  return sendJson(res, 200, { ok: true });
});

route('GET', '/api/admin/me', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  return sendJson(res, 200, { ok: true, admin: { id: admin.id, username: admin.username } });
});

// 证书列表（支持关键字搜索 + 分页）
route('GET', '/api/admin/certs', async (req, res, params, query) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const q = String(query.q || '').trim().toLowerCase();
  let list = db.data.certs.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  if (q) {
    list = list.filter((c) =>
      [c.cert_no, c.name, c.course_name, c.org, c.contact_email].some((f) => String(f || '').toLowerCase().includes(q))
    );
  }
  const size = 20;
  const total = list.length;
  const pages = Math.max(1, Math.ceil(total / size));
  let page = Math.max(1, parseInt(query.page || '1', 10) || 1);
  if (page > pages) page = pages;
  const items = list.slice((page - 1) * size, page * size).map((c) => ({ ...c, status: certStatus(c) }));
  return sendJson(res, 200, { ok: true, total, page, pages, items });
});

function validateCertInput(body) {
  const v = {
    cert_no: String(body.cert_no || '').trim(),
    name: String(body.name || '').trim(),
    course_name: String(body.course_name || '').trim(),
    org: String(body.org || '').trim(),
    issue_date: String(body.issue_date || '').trim(),
    valid_until: String(body.valid_until || '').trim(),
    contact_email: String(body.contact_email || '').trim().toLowerCase(),
  };
  if (!util.isValidCertNo(v.cert_no)) return { error: '证书编号格式不正确（4-32 位字母、数字或短横线）' };
  if (!util.isValidName(v.name)) return { error: '请填写学员姓名（1-64 字）' };
  if (!v.course_name || v.course_name.length > 128) return { error: '请填写课程名称（1-128 字）' };
  if (!v.org || v.org.length > 128) return { error: '请填写培训机构（1-128 字）' };
  if (!util.isValidDate(v.issue_date)) return { error: '发证日期格式应为 YYYY-MM-DD' };
  if (!util.isValidDate(v.valid_until)) return { error: '有效期格式应为 YYYY-MM-DD' };
  if (v.valid_until < v.issue_date) return { error: '有效期不能早于发证日期' };
  if (v.contact_email && !util.isValidEmail(v.contact_email)) return { error: '联系邮箱格式不正确' };
  return { value: v };
}

// 新增证书
route('POST', '/api/admin/certs', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const body = await readBody(req);
  const { error, value } = validateCertInput(body);
  if (error) return sendJson(res, 400, { ok: false, error });
  const no = value.cert_no.toUpperCase();
  if (db.data.certs.some((c) => c.cert_no.toUpperCase() === no)) {
    return sendJson(res, 409, { ok: false, error: '证书编号已存在' });
  }
  const now = new Date().toISOString();
  const cert = {
    id: util.randomId('cert_'),
    ...value,
    cert_no: no,
    revoked: false,
    revoked_at: null,
    revoke_reason: '',
    created_at: now,
    updated_at: now,
    created_by: admin.username,
  };
  db.data.certs.push(cert);
  db.audit('cert_create', admin.username, `新增证书 ${no}（${cert.name} / ${cert.course_name}）`);
  db.save();
  return sendJson(res, 201, { ok: true, cert: { ...cert, status: certStatus(cert) } });
});

// 更新证书（证书编号不可修改）
route('PUT', '/api/admin/certs/:id', async (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const cert = db.data.certs.find((c) => c.id === params.id);
  if (!cert) return sendJson(res, 404, { ok: false, error: '证书不存在' });
  const body = await readBody(req);
  const { error, value } = validateCertInput(body);
  if (error) return sendJson(res, 400, { ok: false, error });
  if (value.cert_no.toUpperCase() !== cert.cert_no.toUpperCase()) {
    return sendJson(res, 400, { ok: false, error: '证书编号不可修改' });
  }
  Object.assign(cert, {
    name: value.name,
    course_name: value.course_name,
    org: value.org,
    issue_date: value.issue_date,
    valid_until: value.valid_until,
    contact_email: value.contact_email,
    updated_at: new Date().toISOString(),
  });
  db.audit('cert_update', admin.username, `更新证书 ${cert.cert_no}（${cert.name}）`);
  db.save();
  return sendJson(res, 200, { ok: true, cert: { ...cert, status: certStatus(cert) } });
});

// 吊销证书
route('POST', '/api/admin/certs/:id/revoke', async (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const cert = db.data.certs.find((c) => c.id === params.id);
  if (!cert) return sendJson(res, 404, { ok: false, error: '证书不存在' });
  const body = await readBody(req);
  cert.revoked = true;
  cert.revoked_at = new Date().toISOString();
  cert.revoke_reason = String(body.reason || '').slice(0, 200);
  cert.updated_at = new Date().toISOString();
  db.audit('cert_revoke', admin.username, `吊销证书 ${cert.cert_no}（${cert.name}）${cert.revoke_reason ? '：' + cert.revoke_reason : ''}`);
  db.save();
  return sendJson(res, 200, { ok: true, cert: { ...cert, status: certStatus(cert) } });
});

// 恢复证书
route('POST', '/api/admin/certs/:id/restore', async (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const cert = db.data.certs.find((c) => c.id === params.id);
  if (!cert) return sendJson(res, 404, { ok: false, error: '证书不存在' });
  cert.revoked = false;
  cert.revoked_at = null;
  cert.revoke_reason = '';
  cert.updated_at = new Date().toISOString();
  db.audit('cert_restore', admin.username, `恢复证书 ${cert.cert_no}（${cert.name}）`);
  db.save();
  return sendJson(res, 200, { ok: true, cert: { ...cert, status: certStatus(cert) } });
});

// 管理员列表
route('GET', '/api/admin/admins', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const items = db.data.admins.map((a) => ({ id: a.id, username: a.username, active: a.active !== false, created_at: a.created_at }));
  return sendJson(res, 200, { ok: true, items });
});

// 新增管理员（任何在册管理员均可添加，实现多人维护）
route('POST', '/api/admin/admins', async (req, res) => {
  const me = requireAdmin(req, res);
  if (!me) return;
  const body = await readBody(req);
  const uname = String(body.username || '').trim();
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(uname)) {
    return sendJson(res, 400, { ok: false, error: '用户名需为 3-32 位字母、数字或 _ . -' });
  }
  if (db.data.admins.some((a) => a.username.toLowerCase() === uname.toLowerCase())) {
    return sendJson(res, 409, { ok: false, error: '用户名已存在' });
  }
  const perr = util.passwordError(body.password);
  if (perr) return sendJson(res, 400, { ok: false, error: perr });
  const admin = {
    id: util.randomId('adm_'),
    username: uname,
    password_hash: util.hashPassword(String(body.password)),
    active: true,
    created_at: new Date().toISOString(),
  };
  db.data.admins.push(admin);
  db.audit('admin_create', me.username, `新增管理员 ${uname}`);
  db.save();
  return sendJson(res, 201, { ok: true, admin: { id: admin.id, username: admin.username, active: true, created_at: admin.created_at } });
});

// 启用 / 禁用管理员
route('POST', '/api/admin/admins/:id/toggle', async (req, res, params) => {
  const me = requireAdmin(req, res);
  if (!me) return;
  const target = db.data.admins.find((a) => a.id === params.id);
  if (!target) return sendJson(res, 404, { ok: false, error: '管理员不存在' });
  if (target.id === me.id) return sendJson(res, 400, { ok: false, error: '不能禁用自己的账号' });
  if (target.active === false) {
    target.active = true;
  } else {
    const activeCount = db.data.admins.filter((a) => a.active !== false).length;
    if (activeCount <= 1) return sendJson(res, 400, { ok: false, error: '至少保留一个可用管理员' });
    target.active = false;
  }
  db.audit('admin_toggle', me.username, `${target.active ? '启用' : '禁用'}管理员 ${target.username}`);
  db.save();
  return sendJson(res, 200, { ok: true, admin: { id: target.id, username: target.username, active: target.active } });
});

// 修改自己的密码
route('POST', '/api/admin/password', async (req, res) => {
  const me = requireAdmin(req, res);
  if (!me) return;
  const body = await readBody(req);
  if (!util.verifyPassword(String(body.old_password || ''), me.password_hash)) {
    return sendJson(res, 400, { ok: false, error: '原密码不正确' });
  }
  const perr = util.passwordError(body.new_password);
  if (perr) return sendJson(res, 400, { ok: false, error: perr });
  me.password_hash = util.hashPassword(String(body.new_password));
  db.audit('password_change', me.username, '');
  db.save();
  return sendJson(res, 200, { ok: true, message: '密码已更新' });
});

// 操作日志
route('GET', '/api/admin/audit', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  return sendJson(res, 200, { ok: true, items: db.data.audit.slice(0, 100) });
});

/* ---------------- 静态资源 ---------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serveStatic(res, pathname) {
  if (pathname === '/') pathname = '/verify.html';
  if (pathname === '/admin') pathname = '/admin.html';
  if (pathname.includes('..') || pathname.includes('\0')) {
    res.writeHead(403);
    return res.end();
  }
  const file = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!file.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end();
  }
  fs.readFile(file, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not Found');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(content);
  });
}

/* ---------------- 种子数据 ---------------- */

function seed() {
  const d = db.data;
  if (!d.admins.length) {
    d.admins.push({
      id: util.randomId('adm_'),
      username: 'admin',
      password_hash: util.hashPassword(process.env.ADMIN_PASSWORD || 'Admin@123456'),
      active: true,
      created_at: new Date().toISOString(),
    });
    console.log('[seed] 已创建默认管理员 admin（默认密码 Admin@123456，可用 ADMIN_PASSWORD 覆盖，请尽快修改）');
  }
  if (!d.certs.length && process.env.SEED_DEMO !== '0') {
    const now = new Date().toISOString();
    const base = { revoked: false, revoked_at: null, revoke_reason: '', created_at: now, updated_at: now, created_by: 'seed' };
    d.certs.push(
      { id: util.randomId('cert_'), cert_no: 'CERT-2025-0001', name: '张三', course_name: '安全生产培训（初级）', org: '华信职业培训学院', issue_date: '2025-03-15', valid_until: '2028-03-14', contact_email: 'zhangsan@example.com', ...base },
      { id: util.randomId('cert_'), cert_no: 'CERT-2024-0002', name: '李四', course_name: '高处作业操作证培训', org: '华信职业培训学院', issue_date: '2024-01-10', valid_until: '2026-01-09', contact_email: 'lisi@example.com', ...base },
      { id: util.randomId('cert_'), cert_no: 'CERT-xxxx-0003'.toUpperCase(), name: '王五', course_name: '焊工特种作业培训', org: '中培技能鉴定中心', issue_date: '2025-06-01', valid_until: '2027-05-31', contact_email: 'wangwu@example.com', ...base, revoked: true, revoked_at: now, revoke_reason: '学员信息登记错误，待重新发证' }
    );
    console.log('[seed] 已写入 3 条演示证书（CERT-2025-0001/张三、CERT-2024-0002/李四、CERT-XXXX-0003/王五）');
  }
  db.save();
}

/* ---------------- 启动 ---------------- */

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  const u = new URL(req.url, 'http://localhost');
  const pathname = u.pathname;

  try {
    if (pathname.startsWith('/api/')) {
      res.setHeader('Content-Security-Policy', "default-src 'none'");
      if (req.method !== 'GET' && req.method !== 'HEAD' && !checkCsrf(req, res)) return;
      const m = matchRoute(req.method, pathname);
      if (!m) return sendJson(res, 404, { ok: false, error: '接口不存在' });
      const query = Object.fromEntries(u.searchParams.entries());
      return await m.handler(req, res, m.params, query);
    }
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:");
    return serveStatic(res, pathname);
  } catch (err) {
    if (err && err.message === 'invalid json') return sendJson(res, 400, { ok: false, error: '请求体格式错误' });
    if (err && err.message === 'payload too large') return sendJson(res, 413, { ok: false, error: '请求体过大' });
    console.error(err);
    if (!res.headersSent) return sendJson(res, 500, { ok: false, error: '服务器内部错误' });
    res.end();
  }
});

seed();
server.listen(PORT, HOST, () => {
  console.log(`listening on http://${HOST}:${PORT} (${DEV ? 'development' : 'production'})`);
});
