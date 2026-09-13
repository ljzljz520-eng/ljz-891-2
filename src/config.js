'use strict';

const path = require('path');
const crypto = require('crypto');

// 优先读取 .env（极简解析，不引入 dotenv 依赖）
try {
  require('fs').readFileSync(path.join(__dirname, '..', '.env'), 'utf8')
    .split(/\r?\n/)
    .forEach((line) => {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m) return;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    });
} catch (_) {
  // 没有 .env 时使用默认值/系统环境变量
}

function parseSmtpUrl(url) {
  if (!url) return null;
  const u = new URL(url);
  const implicitTls = u.protocol === 'smtps:';
  return {
    host: u.hostname,
    port: Number(u.port) || (implicitTls ? 465 : 587),
    username: decodeURIComponent(u.username || ''),
    password: decodeURIComponent(u.password || ''),
    implicitTls,
  };
}

const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (NODE_ENV === 'production'
    ? null
    : crypto.randomBytes(32).toString('hex'));

if (NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  // 生产环境必须显式配置会话密钥，防止重启后所有会话失效
  throw new Error('生产环境请在 .env 中设置 SESSION_SECRET（长随机字符串）');
}

module.exports = {
  PORT,
  NODE_ENV,
  isProd: NODE_ENV === 'production',
  SESSION_SECRET,
  DATA_DIR: path.join(__dirname, '..', 'data'),
  DB_FILE: path.join(__dirname, '..', 'data', 'db.json'),
  OUTBOX_FILE: path.join(__dirname, '..', 'data', 'outbox.json'),
  smtp: parseSmtpUrl(process.env.SMTP_URL),
  mailFrom: process.env.MAIL_FROM || '培训证书平台 <no-reply@example.com>',
  // 验证码有效期 10 分钟；同一邮箱 60 秒发送间隔；最多尝试 5 次
  CODE_TTL_MS: 10 * 60 * 1000,
  CODE_RESEND_MS: 60 * 1000,
  CODE_MAX_ATTEMPTS: 5,
  // 同 IP 限流：验证码/核验接口
  RATE_LIMITS: {
    codeSendPerIp: { windowMs: 60 * 1000, max: 10 },
    verifyPerIp: { windowMs: 60 * 1000, max: 30 },
    loginPerIp: { windowMs: 15 * 60 * 1000, max: 20 },
  },
};
