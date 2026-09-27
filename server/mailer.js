'use strict';

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const OUTBOX = path.join(DATA_DIR, 'outbox.log');

// 开发/演示模式：邮件写入 data/outbox.log，接口同时回传 dev_code 便于联调。
// 生产模式（NODE_ENV=production）：不回传 dev_code。
// 接入真实邮件通道（SMTP / 服务商 SDK）时，仅需替换本文件的 sendMail 实现。
const DEV = process.env.NODE_ENV !== 'production';

async function sendMail({ to, subject, text }) {
  const line = `[${new Date().toISOString()}] TO=${to} SUBJECT=${subject}\n${text}\n---\n`;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.appendFileSync(OUTBOX, line);
  return { dev: DEV };
}

module.exports = { sendMail, DEV };
