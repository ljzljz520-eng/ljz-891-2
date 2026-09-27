// 邮件发送：
//  - 配置 SMTP_URL 时使用原生 SMTP（支持 465 隐式 TLS / 587 STARTTLS / 明文）
//  - 未配置时使用控制台传输（开发模式：验证码打印到服务端日志）
import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

const SMTP_TIMEOUT = 15_000;

/**
 * 解析 SMTP_URL
 * smtps://user:pass@smtp.example.com:465   隐式 TLS
 * smtp://user:pass@smtp.example.com:587    先明文，再尝试 STARTTLS
 */
export function parseSmtpUrl(urlStr) {
  if (!urlStr) return null;
  const u = new URL(urlStr);
  const protocol = u.protocol.replace(':', '');
  const implicitTls = protocol === 'smtps' || protocol === 'smtp+ssl';
  const port = u.port ? Number(u.port) : implicitTls ? 465 : 587;
  return {
    host: u.hostname,
    port,
    user: u.username ? decodeURIComponent(u.username) : '',
    pass: u.password ? decodeURIComponent(u.password) : '',
    implicitTls,
    fromEmail: u.searchParams.get('from') || '',
  };
}

// ---------- 基础行读取器 ----------
class LineReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    this.error = null;
    this.ended = false;

    this._onData = (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this._pump();
    };
    this._onError = (err) => {
      this.error = err;
      const ws = this.waiters.splice(0);
      ws.forEach((w) => w.reject(err));
    };
    this._onEnd = () => {
      this.ended = true;
      const ws = this.waiters.splice(0);
      ws.forEach((w) => w.reject(new Error('SMTP 连接已关闭')));
    };
    socket.on('data', this._onData);
    socket.once('error', this._onError);
    socket.once('end', this._onEnd);
  }

  _pump() {
    // SMTP 行以 CRLF 结束
    let idx;
    while ((idx = this.buffer.indexOf('\n')) !== -1 && this.waiters.length > 0) {
      const lineBuf = this.buffer.subarray(0, idx);
      this.buffer = this.buffer.subarray(idx + 1);
      const line = lineBuf.toString('utf8').replace(/\r$/, '');
      const waiter = this.waiters.shift();
      waiter.resolve(line);
    }
  }

  readLine() {
    return new Promise((resolve, reject) => {
      if (this.error) return reject(this.error);
      this.waiters.push({ resolve, reject });
      this._pump();
    });
  }

  /** 读取一条完整 SMTP 应答（多行时以 "code-" 延续） */
  async readResponse() {
    const lines = [];
    let line;
    do {
      line = await this.readLine();
      lines.push(line);
    } while (line.length >= 4 && line[3] === '-');
    const code = Number(lines[0].slice(0, 3));
    return { code, text: lines.join('\n') };
  }

  detach() {
    this.socket.removeListener('data', this._onData);
    this.socket.removeListener('error', this._onError);
    this.socket.removeListener('end', this._onEnd);
  }
}

async function openSocket({ host, port, implicitTls }, tlsOptions = {}) {
  if (implicitTls) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host, port, servername: host, ...tlsOptions },
        () => {
          if (!socket.authorized) {
            socket.destroy();
            return reject(new Error(`SMTP TLS 证书校验失败: ${socket.authorizationError?.message || ''}`));
          }
          resolve(socket);
        }
      );
      socket.setTimeout(SMTP_TIMEOUT, () => socket.destroy(new Error('SMTP 连接超时')));
      socket.once('error', reject);
    });
  }
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port }, () => resolve(socket));
    socket.setTimeout(SMTP_TIMEOUT, () => socket.destroy(new Error('SMTP 连接超时')));
    socket.once('error', reject);
  });
}

async function smtpSend(cfg, { from, to, subject, text, html }) {
  let socket = await openSocket(cfg);
  let reader = new LineReader(socket);
  let greeting = await reader.readResponse();
  if (greeting.code !== 220) throw new Error(`SMTP 握手失败: ${greeting.text}`);

  const ehloDomain = extractEhlo(from) || 'localhost';
  const ehlo = async () => {
    socket.write(`EHLO ${ehloDomain}\r\n`);
    const res = await reader.readResponse();
    if (res.code !== 250) throw new Error(`EHLO 失败: ${res.text}`);
    return res.text;
  };

  let caps = await ehlo();

  // 明文连接：如果服务器支持 STARTTLS，则升级
  if (!cfg.implicitTls && /STARTTLS/i.test(caps)) {
    socket.write('STARTTLS\r\n');
    const res = await reader.readResponse();
    if (res.code !== 220) throw new Error(`STARTTLS 失败: ${res.text}`);
    reader.detach();
    socket.removeAllListeners('timeout');
    await new Promise((resolve, reject) => {
      const tlsSocket = tls.connect(
        { socket, servername: cfg.host },
        () => {
          if (!tlsSocket.authorized) {
            tlsSocket.destroy();
            return reject(new Error(`SMTP STARTTLS 证书校验失败: ${tlsSocket.authorizationError?.message || ''}`));
          }
          resolve();
        }
      );
      tlsSocket.once('error', reject);
      // 替换外层 socket 引用
      socket = tlsSocket;
    });
    socket.setTimeout(SMTP_TIMEOUT, () => socket.destroy(new Error('SMTP 超时')));
    reader = new LineReader(socket);
    caps = await ehlo();
  }

  // 认证
  if (cfg.user) {
    const authMech = /AUTH=LOGIN|AUTH LOGIN|AUTH=PLAIN|AUTH PLAIN/i.test(caps);
    if (!authMech) throw new Error('SMTP 服务器不支持登录认证');

    const useLogin = /AUTH[^\n]*LOGIN/i.test(caps);
    if (useLogin) {
      socket.write('AUTH LOGIN\r\n');
      let r = await reader.readResponse();
      if (r.code !== 334) throw new Error(`AUTH LOGIN 失败: ${r.text}`);
      socket.write(Buffer.from(cfg.user).toString('base64') + '\r\n');
      r = await reader.readResponse();
      if (r.code !== 334) throw new Error(`SMTP 用户名被拒绝: ${r.text}`);
      socket.write(Buffer.from(cfg.pass).toString('base64') + '\r\n');
      r = await reader.readResponse();
      if (r.code !== 235) throw new Error(`SMTP 认证失败: ${r.text}`);
    } else {
      const plain = Buffer.from(`\0${cfg.user}\0${cfg.pass}`).toString('base64');
      socket.write(`AUTH PLAIN ${plain}\r\n`);
      const r = await reader.readResponse();
      if (r.code !== 235) throw new Error(`SMTP 认证失败: ${r.text}`);
    }
  }

  const cmd = async (command) => {
    socket.write(command + '\r\n');
    const r = await reader.readResponse();
    if (r.code >= 400) throw new Error(`SMTP 命令失败 (${command.split(' ')[0]}): ${r.text}`);
    return r;
  };

  await cmd(`MAIL FROM:<${stripBrackets(from)}>`);
  await cmd(`RCPT TO:<${stripBrackets(to)}>`);
  const dataRes = await cmd('DATA');
  if (dataRes.code !== 354) throw new Error(`DATA 失败: ${dataRes.text}`);

  const message = buildMime({ from, to, subject, text, html });
  socket.write(message);
  socket.write('\r\n.\r\n');
  const queued = await reader.readResponse();
  if (queued.code !== 250) throw new Error(`邮件被拒绝: ${queued.text}`);

  try {
    socket.write('QUIT\r\n');
    await reader.readResponse();
  } catch {
    // 忽略 QUIT 异常
  }
  socket.end();
}

function stripBrackets(addr) {
  return String(addr).replace(/^<|>$/g, '');
}

function extractEhlo(email) {
  const m = /@(.+)$/.exec(String(email || ''));
  return m ? m[1] : '';
}

// ---------- MIME 构建（支持中文） ----------
function buildMime({ from, to, subject, text, html }) {
  const encodedSubject = `=?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`;
  const boundary = '----certmail' + Date.now() + Math.random().toString(16).slice(2);
  const lines = [];
  lines.push(`Date: ${new Date().toUTCString()}`);
  lines.push(`From: ${from}`);
  lines.push(`To: ${to}`);
  lines.push(`Subject: ${encodedSubject}`);
  lines.push('MIME-Version: 1.0');
  if (html) {
    lines.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    lines.push('');
    lines.push(`--${boundary}`);
    lines.push('Content-Type: text/plain; charset=UTF-8');
    lines.push('Content-Transfer-Encoding: base64');
    lines.push('');
    lines.push(foldBase64(Buffer.from(text || '', 'utf8').toString('base64')));
    lines.push('');
    lines.push(`--${boundary}`);
    lines.push('Content-Type: text/html; charset=UTF-8');
    lines.push('Content-Transfer-Encoding: base64');
    lines.push('');
    lines.push(foldBase64(Buffer.from(html, 'utf8').toString('base64')));
    lines.push('');
    lines.push(`--${boundary}--`);
  } else {
    lines.push('Content-Type: text/plain; charset=UTF-8');
    lines.push('Content-Transfer-Encoding: base64');
    lines.push('');
    lines.push(foldBase64(Buffer.from(text || '', 'utf8').toString('base64')));
  }
  return lines.join('\r\n');
}

/** RFC 5322 base64 每 76 个字符折行 */
function foldBase64(b64) {
  const out = [];
  for (let i = 0; i < b64.length; i += 76) {
    out.push(b64.slice(i, i + 76));
  }
  return out.join('\r\n');
}

// ---------- 控制台传输（开发环境） ----------
function formatFrom(fromName, fromEmail) {
  return fromName ? `=?UTF-8?B?${Buffer.from(fromName).toString('base64')}?= <${fromEmail}>` : fromEmail;
}

function createConsoleTransport({ logDir, fromName, fromEmail }) {
  return {
    mode: 'console',
    async send({ to, subject, text, html }) {
      const stamp = new Date().toISOString();
      const record = [
        '==================== 邮件（控制台模式）====================',
        `时间: ${stamp}`,
        `发件人: ${formatFrom(fromName, fromEmail)}`,
        `收件人: ${to}`,
        `主题: ${subject}`,
        '------------------------------------------------------------',
        text,
        '============================================================',
        '',
      ].join('\n');
      console.log(record);
      try {
        await mkdir(logDir, { recursive: true });
        await appendFile(path.join(logDir, 'mail.log'), record, 'utf8');
      } catch (e) {
        console.warn('邮件日志写入失败:', e.message);
      }
      return { accepted: [to], mode: 'console' };
    },
  };
}

function createSmtpTransport(cfg, { fromName, fromEmail }) {
  return {
    mode: 'smtp',
    async send({ to, subject, text, html }) {
      await smtpSend(cfg, {
        from: formatFrom(fromName, fromEmail),
        to,
        subject,
        text,
        html,
      });
      return { accepted: [to], mode: 'smtp' };
    },
  };
}

export function createMailer({ smtpUrl, fromName = '培训证书核验平台', fromEmail = 'noreply@localhost', logDir }) {
  const cfg = parseSmtpUrl(smtpUrl);
  if (cfg && cfg.host) {
    if (cfg.fromEmail) fromEmail = cfg.fromEmail;
    return createSmtpTransport(cfg, { fromName, fromEmail });
  }
  return createConsoleTransport({ logDir, fromName, fromEmail });
}

// ---------- 邮件模板 ----------
export function verificationCodeEmail(code, ttlMinutes) {
  const subject = '【证书核验】邮箱更正验证码';
  const text = [
    '您好：',
    '',
    `您正在申请更正培训证书的联系邮箱，验证码为：${code}`,
    '',
    `验证码 ${ttlMinutes} 分钟内有效，请勿向任何人泄露。`,
    '如非本人操作，请忽略本邮件。',
    '',
    '培训证书核验平台',
  ].join('\n');
  const html = `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e9f2">
    <h2 style="margin:0 0 16px;color:#1f3b73;font-size:20px">邮箱更正验证码</h2>
    <p style="color:#475569;line-height:1.7">您正在申请更正培训证书的联系邮箱，请使用以下验证码完成操作：</p>
    <div style="text-align:center;margin:24px 0">
      <span style="display:inline-block;font-size:34px;letter-spacing:10px;font-weight:700;color:#1d4ed8;background:#eff6ff;border:1px dashed #93b4f5;border-radius:10px;padding:14px 26px">${code}</span>
    </div>
    <p style="color:#64748b;font-size:13px;line-height:1.7">验证码 ${ttlMinutes} 分钟内有效，请勿向任何人泄露。如非本人操作，请忽略本邮件。</p>
    <hr style="border:none;border-top:1px solid #e5e9f2;margin:24px 0"/>
    <p style="color:#94a3b8;font-size:12px;margin:0">培训证书核验平台（系统邮件，请勿直接回复）</p>
  </div></body></html>`;
  return { subject, text, html };
}

export function emailChangedNotifyEmail(oldMasked, newEmail) {
  const subject = '【证书核验】联系邮箱已更正';
  const text = [
    '您好：',
    '',
    '您的培训证书联系邮箱已被更正。',
    `原邮箱：${oldMasked}`,
    `新邮箱：${newEmail}`,
    '',
    '如非本人操作，请立即联系培训机构处理。',
    '',
    '培训证书核验平台',
  ].join('\n');
  const html = `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e9f2">
    <h2 style="margin:0 0 16px;color:#1f3b73;font-size:20px">联系邮箱已更正</h2>
    <p style="color:#475569;line-height:1.7">您的培训证书联系邮箱已被更正：</p>
    <table style="margin:12px 0;color:#334155;line-height:2">
      <tr><td style="padding-right:16px;color:#64748b">原邮箱</td><td>${oldMasked}</td></tr>
      <tr><td style="padding-right:16px;color:#64748b">新邮箱</td><td><strong>${newEmail}</strong></td></tr>
    </table>
    <p style="color:#b91c1c;font-size:13px;line-height:1.7">如非本人操作，请立即联系培训机构处理。</p>
    <hr style="border:none;border-top:1px solid #e5e9f2;margin:24px 0"/>
    <p style="color:#94a3b8;font-size:12px;margin:0">培训证书核验平台（系统邮件，请勿直接回复）</p>
  </div></body></html>`;
  return { subject, text, html };
}
