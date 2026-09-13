'use strict';

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const config = require('./config');

/**
 * 极简 SMTP 客户端：
 *  - smtps:// → 465 隐式 TLS
 *  - smtp://  → 587 STARTTLS
 *  - AUTH LOGIN（用户名/授权码）
 * 不配置 SMTP_URL 时进入开发模式：邮件写入 data/outbox.json 并在控制台打印。
 */

function parseAddressList(header) {
  // MAIL_FROM 形如：培训证书平台 <no-reply@example.com>
  const m = String(header).match(/<([^>]+)>/);
  return m ? m[1].trim() : header.trim();
}

function encodeUtf8Header(s) {
  return `=?UTF-8?B?${Buffer.from(String(s), 'utf8').toString('base64')}?=`;
}

function buildMime({ fromName, fromEmail, to, subject, text }) {
  const lines = [
    `From: ${encodeUtf8Header(fromName)} <${fromEmail}>`,
    `To: ${to}`,
    `Subject: ${encodeUtf8Header(subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
  ];
  return lines.join('\r\n');
}

class SmtpSession {
  constructor(cfg) {
    this.cfg = cfg;
    this.sock = null;
    this.debug = !config.isProd;
  }

  log(...args) {
    if (this.debug) console.log('[smtp]', ...args);
  }

  connect() {
    return new Promise((resolve, reject) => {
      const { host, port, implicitTls } = this.cfg;
      const onConnect = () => resolve();
      const onErr = (e) => reject(new Error(`SMTP 连接失败 ${host}:${port}：${e.message}`));
      if (implicitTls) {
        this.sock = tls.connect({ host, port, servername: host }, () => {
          if (!this.sock.authorized) {
            this.log('TLS 证书警告：', this.sock.authorizationError && this.sock.authorizationError.message);
          }
          onConnect();
        });
      } else {
        this.sock = net.connect({ host, port }, onConnect);
      }
      this.sock.setTimeout(15000);
      this.sock.once('error', onErr);
      this.sock.once('timeout', () => reject(new Error('SMTP 连接超时')));
    });
  }

  // 读取一条（或多行）应答，返回 { code, text }
  readReply() {
    return new Promise((resolve, reject) => {
      let buf = '';
      const onData = (chunk) => {
        buf += chunk.toString('utf8');
        let idx;
        // SMTP 多行应答：每一行 "code-text"，最后一行 "code text"
        while ((idx = buf.indexOf('\r\n')) !== -1) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (/^\d{3} /.test(line)) {
            cleanup();
            const code = Number(line.slice(0, 3));
            resolve({ code, text: line.slice(4) });
            return;
          }
        }
      };
      const onErr = (e) => {
        cleanup();
        reject(e);
      };
      const cleanup = () => {
        this.sock.removeListener('data', onData);
        this.sock.removeListener('error', onErr);
      };
      this.sock.on('data', onData);
      this.sock.once('error', onErr);
    });
  }

  async cmd(command, expectOk = true) {
    if (command != null) {
      this.log('>', command.replace(/^AUTH PLAIN.*/i, 'AUTH PLAIN ***'));
      this.sock.write(command + '\r\n');
    }
    const reply = await this.readReply();
    this.log('<', reply.code, reply.text);
    if (expectOk && reply.code >= 400) {
      throw new Error(`SMTP 错误 ${reply.code} ${reply.text}`);
    }
    return reply;
  }

  async startTls() {
    await this.cmd('STARTTLS');
    await new Promise((resolve, reject) => {
      this.sock.removeAllListeners('data');
      const sock = tls.connect({ socket: this.sock, servername: this.cfg.host }, () => resolve());
      sock.once('error', reject);
      this.sock = sock;
    });
  }

  async authenticate() {
    const { username, password } = this.cfg;
    if (!username) return;
    await this.cmd('EHLO localhost');
    // 优先 AUTH PLAIN（一步完成，含编码后的用户名密码）
    const creds = Buffer.from(`\0${username}\0${password}`, 'binary').toString('base64');
    let reply = await this.cmd(`AUTH PLAIN ${creds}`, false);
    if (reply.code === 504 || reply.code === 502) {
      // 服务器不支持 PLAIN，回退 AUTH LOGIN
      reply = await this.cmd('AUTH LOGIN', false);
      if (reply.code !== 334) throw new Error(`SMTP 认证失败：${reply.code} ${reply.text}`);
      reply = await this.cmd(Buffer.from(username, 'utf8').toString('base64'), false);
      if (reply.code !== 334) throw new Error(`SMTP 用户名被拒：${reply.code} ${reply.text}`);
      reply = await this.cmd(Buffer.from(password, 'utf8').toString('base64'), false);
    }
    if (reply.code >= 400) throw new Error(`SMTP 认证失败：${reply.code} ${reply.text}`);
  }

  async send({ to, subject, text }) {
    const fromHeader = config.mailFrom;
    const fromEmail = parseAddressList(fromHeader);
    const fromName = fromHeader.includes('<')
      ? fromHeader.slice(0, fromHeader.indexOf('<')).trim()
      : '培训证书平台';

    await this.connect();
    let greeting = await this.cmd(null); // 读取服务端 220 问候
    if (greeting.code !== 220) throw new Error(`SMTP 握手失败：${greeting.code} ${greeting.text}`);

    if (this.cfg.implicitTls) {
      await this.cmd('EHLO localhost');
    } else {
      await this.cmd('EHLO localhost');
      await this.startTls();
      await this.cmd('EHLO localhost');
    }
    await this.authenticate();

    await this.cmd(`MAIL FROM:<${fromEmail}>`);
    await this.cmd(`RCPT TO:<${to}>`);
    await this.cmd('DATA');
    const mime = buildMime({ fromName, fromEmail, to, subject, text });
    // DATA 内容结束于 <CRLF>.<CRLF>；正文里以点开头的行需转义
    const escaped = mime.replace(/\r\n\./g, '\r\n..');
    const reply = await new Promise((resolve, reject) => {
      this.sock.write(escaped + '\r\n.\r\n', () => {
        this.readReply().then(resolve, reject);
      });
    });
    if (reply.code >= 400) throw new Error(`投递失败：${reply.code} ${reply.text}`);
    try {
      await this.cmd('QUIT', false);
    } catch (_) {}
    this.sock.end();
  }
}

// ---------- 开发模式 outbox ----------
function appendOutbox(record) {
  let box = [];
  try {
    box = JSON.parse(fs.readFileSync(config.OUTBOX_FILE, 'utf8'));
  } catch (_) {}
  box.push(record);
  if (box.length > 500) box = box.slice(-500);
  fs.mkdirSync(config.DATA_DIR, { recursive: true });
  fs.writeFileSync(config.OUTBOX_FILE, JSON.stringify(box, null, 2));
}

/**
 * 发送邮件。返回 { delivered, dev, code }
 * 开发模式下不真正发送，且把验证码回传给调用方（方便联调）。
 */
async function sendMail({ to, subject, text, devPayload = null }) {
  const at = new Date().toISOString();
  if (!config.smtp) {
    const record = { at, to, subject, text, devPayload };
    appendOutbox(record);
    console.log(`\n[mail:dev] 收件人=${to} 主题=${subject}`);
    console.log(text);
    console.log('（未配置 SMTP_URL，邮件已写入 data/outbox.json）\n');
    return { delivered: false, dev: true, devPayload };
  }
  const session = new SmtpSession(config.smtp);
  await session.send({ to, subject, text });
  return { delivered: true, dev: false, devPayload: null };
}

module.exports = { sendMail };
