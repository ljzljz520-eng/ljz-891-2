'use strict';

// 极简内存限流：按 IP 计数
function rateLimit({ windowMs, max, message }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) {
      if (now - v.resetAt > windowMs) hits.delete(k);
    }
  }, 60 * 1000).unref?.();

  return function (req, res, next) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let rec = hits.get(ip);
    if (!rec || now - rec.resetAt > windowMs) {
      rec = { count: 0, resetAt: now };
      hits.set(ip, rec);
    }
    rec.count += 1;
    if (rec.count > max) {
      const retry = Math.ceil((rec.resetAt + windowMs - now) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).json({ ok: false, error: message || `操作过于频繁，请 ${retry} 秒后重试` });
    }
    next();
  };
}

function requireLogin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(401).json({ ok: false, error: '未登录或会话已过期' });
}

// 简单校验工具
function str(v) {
  return typeof v === 'string' ? v.trim() : '';
}
function isEmail(v) {
  return typeof v === 'string' && /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v.trim()) && v.length <= 200;
}
function isDate(v) {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(new Date(`${v}T00:00:00Z`).getTime());
}
function isUsername(v) {
  return typeof v === 'string' && /^[A-Za-z0-9_]{3,32}$/.test(v);
}
function isCertNo(v) {
  return typeof v === 'string' && /^[A-Za-z0-9-]{3,40}$/.test(v.trim());
}
function badRequest(msg) {
  const err = new Error(msg);
  err.status = 400;
  return err;
}

module.exports = { rateLimit, requireLogin, str, isEmail, isDate, isUsername, isCertNo, badRequest };
