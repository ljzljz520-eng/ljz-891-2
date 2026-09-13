'use strict';

const crypto = require('crypto');
const config = require('./config');
const mailer = require('./mailer');

/**
 * 邮箱验证码内存存储：
 * key = certId，value = { email, codeHash, createdAt, attempts, lastSentAt }
 * 服务重启后未完成的验证流程作废（可接受）。
 */
const store = new Map();

// 周期清理过期记录
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of store) {
    if (now - v.createdAt > config.CODE_TTL_MS) store.delete(k);
  }
}, 60 * 1000).unref?.();

function genCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function getPending(certId) {
  const rec = store.get(certId);
  if (!rec) return null;
  if (Date.now() - rec.createdAt > config.CODE_TTL_MS) {
    store.delete(certId);
    return null;
  }
  return rec;
}

function resendCooldownRemain(rec) {
  const elapsed = Date.now() - rec.lastSentAt;
  return Math.max(0, Math.ceil((config.CODE_RESEND_MS - elapsed) / 1000));
}

/**
 * 发送更正邮箱验证码。
 * @param {object} cert 证书对象
 * @param {string} newEmail 学员填写的新邮箱
 */
async function sendChangeCode(cert, newEmail) {
  // 生产环境必须配置真实 SMTP，避免验证码只落到服务器日志/outbox
  if (config.isProd && !config.smtp) {
    const err = new Error('邮箱服务未配置（SMTP_URL），暂时无法发送验证码，请联系管理员');
    err.status = 503;
    throw err;
  }
  const existing = getPending(cert.id);
  if (existing && existing.email === newEmail) {
    const wait = resendCooldownRemain(existing);
    if (wait > 0) {
      const err = new Error(`发送过于频繁，请 ${wait} 秒后重试`);
      err.status = 429;
      throw err;
    }
  }

  const code = genCode();
  const rec = {
    email: newEmail,
    codeHash: sha256(code),
    createdAt: Date.now(),
    attempts: 0,
    lastSentAt: Date.now(),
  };
  store.set(cert.id, rec);

  const subject = '【培训证书平台】联系邮箱更正验证码';
  const text = [
    `您好，${cert.studentName}：`,
    '',
    `您正在申请更正证书 ${cert.certNo}（${cert.courseName}）的联系邮箱。`,
    `您的邮箱验证码为：${code}`,
    '',
    `验证码 ${Math.round(config.CODE_TTL_MS / 60000)} 分钟内有效，请勿泄露给他人。`,
    '如非本人操作，请忽略本邮件，证书信息不会被更改。',
    '',
    '培训证书平台',
  ].join('\n');

  const result = await mailer.sendMail({
    to: newEmail,
    subject,
    text,
    devPayload: { code },
  });
  return result;
}

/**
 * 校验验证码。成功返回 true；失败次数超限抛错。
 */
function verifyChangeCode(certId, email, code) {
  const rec = getPending(certId);
  if (!rec) return { ok: false, reason: '验证码不存在或已过期，请重新获取' };
  if (rec.email !== email) return { ok: false, reason: '验证码与申请邮箱不匹配，请重新获取' };

  const input = String(code || '').trim();
  const ok = input.length === 6 && crypto.timingSafeEqual(
    Buffer.from(sha256(input)),
    Buffer.from(rec.codeHash)
  );
  if (!ok) {
    rec.attempts += 1;
    if (rec.attempts >= config.CODE_MAX_ATTEMPTS) {
      store.delete(certId);
      return { ok: false, reason: '错误次数过多，验证码已失效，请重新获取' };
    }
    const left = config.CODE_MAX_ATTEMPTS - rec.attempts;
    return { ok: false, reason: `验证码不正确，还可尝试 ${left} 次` };
  }
  store.delete(certId);
  return { ok: true };
}

module.exports = { sendChangeCode, verifyChangeCode };
