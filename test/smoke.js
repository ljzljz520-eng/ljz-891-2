'use strict';

/**
 * 冒烟测试：启动独立实例（临时数据目录），跑通核心流程。
 * 运行：npm test
 */

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PORT = 3100;
const BASE = `http://127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;

function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}${extra !== undefined ? ' -> ' + JSON.stringify(extra) : ''}`);
  }
}

async function api(pathname, { method = 'GET', body, cookie, csrf = true } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (csrf) headers['X-Requested-With'] = 'fetch';
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(BASE + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await res.json(); } catch { /* 非 JSON */ }
  return { status: res.status, json, setCookie: res.headers.get('set-cookie') || '' };
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'certdb-'));
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: { ...process.env, PORT: String(PORT), DATA_DIR: tmp, NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write(d));
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('服务启动超时')), 10000);
    child.stdout.on('data', (d) => {
      if (String(d).includes('listening')) { clearTimeout(to); resolve(); }
    });
  });

  try {
    console.log('\n[1] 页面可访问');
    {
      const res = await fetch(BASE + '/');
      const html = await res.text();
      check('GET / 返回核验页', res.status === 200 && html.includes('证书核验'));
      const res2 = await fetch(BASE + '/admin');
      const html2 = await res2.text();
      check('GET /admin 返回后台页', res2.status === 200 && html2.includes('管理员登录'));
    }

    console.log('\n[2] 证书核验');
    {
      const r = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2025-0001', name: '张三' } });
      check('核验成功返回证书信息', r.status === 200 && r.json.ok && r.json.cert.course_name === '安全生产培训（初级）', r.json);
      check('状态为 有效', r.json.cert.status === '有效');
      check('包含发证日期/有效期/培训机构', r.json.cert.issue_date === '2025-03-15' && r.json.cert.valid_until === '2028-03-14' && r.json.cert.org === '华信职业培训学院');
      check('邮箱已打码', r.json.cert.contact_email_masked === 'zh***@example.com', r.json.cert.contact_email_masked);

      const bad = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2025-0001', name: '张三三' } });
      check('姓名不符返回 404 统一提示', bad.status === 404 && bad.json.ok === false);

      const expired = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2024-0002', name: '李四' } });
      check('过期证书状态为 已过期', expired.json.cert && expired.json.cert.status === '已过期');

      const revoked = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-XXXX-0003', name: '王五' } });
      check('吊销证书状态为 已吊销', revoked.json.cert && revoked.json.cert.status === '已吊销');
    }

    console.log('\n[3] 邮箱验证码更正流程');
    {
      const req1 = await api('/api/public/email-change/request', {
        method: 'POST',
        body: { cert_no: 'CERT-2025-0001', name: '张三', new_email: 'new.zhangsan@example.com' },
      });
      check('发送验证码成功且返回 dev_code', req1.json.ok && /^\d{6}$/.test(req1.json.dev_code || ''), req1.json);
      const code = req1.json.dev_code;
      const wrong = code === '000000' ? '000001' : '000000';

      const badConfirm = await api('/api/public/email-change/confirm', {
        method: 'POST',
        body: { cert_no: 'CERT-2025-0001', name: '张三', new_email: 'new.zhangsan@example.com', code: wrong },
      });
      check('错误验证码被拒绝', badConfirm.status === 400 && !badConfirm.json.ok);

      const okConfirm = await api('/api/public/email-change/confirm', {
        method: 'POST',
        body: { cert_no: 'CERT-2025-0001', name: '张三', new_email: 'new.zhangsan@example.com', code },
      });
      check('正确验证码更正成功', okConfirm.status === 200 && okConfirm.json.ok, okConfirm.json);

      const after = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2025-0001', name: '张三' } });
      check('核验页显示新邮箱（打码）', after.json.cert.contact_email_masked === 'ne***@example.com', after.json.cert.contact_email_masked);

      const reused = await api('/api/public/email-change/confirm', {
        method: 'POST',
        body: { cert_no: 'CERT-2025-0001', name: '张三', new_email: 'new.zhangsan@example.com', code },
      });
      check('验证码不可重复使用', !reused.json.ok);

      const outbox = fs.readFileSync(path.join(tmp, 'outbox.log'), 'utf8');
      check('邮件已写入 outbox.log', outbox.includes('new.zhangsan@example.com') && outbox.includes(code));
    }

    console.log('\n[4] 安全基线');
    {
      const noCsrf = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2025-0001', name: '张三' }, csrf: false });
      check('缺少防 CSRF 头的写请求被拒绝', noCsrf.status === 403);
      const unauth = await api('/api/admin/certs');
      check('未登录访问后台接口返回 401', unauth.status === 401);
    }

    console.log('\n[5] 管理员：登录与证书维护');
    let cookie;
    {
      const bad = await api('/api/admin/login', { method: 'POST', body: { username: 'admin', password: 'wrong-pass-1' } });
      check('错误密码登录失败', bad.status === 401);

      const ok = await api('/api/admin/login', { method: 'POST', body: { username: 'admin', password: 'Admin@123456' } });
      check('管理员登录成功并下发 Cookie', ok.status === 200 && /sid=/.test(ok.setCookie));
      cookie = ok.setCookie.split(';')[0];

      const create = await api('/api/admin/certs', {
        method: 'POST', cookie,
        body: { cert_no: 'CERT-2026-1001', name: '赵六', course_name: '电工特种作业培训', org: '中培技能鉴定中心', issue_date: '2026-02-01', valid_until: '2029-01-31', contact_email: 'zhaoliu@example.com' },
      });
      check('新增证书成功', create.status === 201 && create.json.ok, create.json);
      const certId = create.json.cert && create.json.cert.id;

      const dup = await api('/api/admin/certs', {
        method: 'POST', cookie,
        body: { cert_no: 'CERT-2026-1001', name: '赵六', course_name: 'x', org: 'y', issue_date: '2026-02-01', valid_until: '2029-01-31' },
      });
      check('重复编号返回 409', dup.status === 409);

      const pub = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2026-1001', name: '赵六' } });
      check('新证书可公开核验', pub.json.ok && pub.json.cert.status === '有效');

      const upd = await api(`/api/admin/certs/${certId}`, {
        method: 'PUT', cookie,
        body: { cert_no: 'CERT-2026-1001', name: '赵六', course_name: '电工特种作业培训（复审）', org: '中培技能鉴定中心', issue_date: '2026-02-01', valid_until: '2029-01-31', contact_email: 'zhaoliu@example.com' },
      });
      check('编辑证书成功', upd.status === 200 && upd.json.cert.course_name.includes('复审'), upd.json);

      const revoke = await api(`/api/admin/certs/${certId}/revoke`, { method: 'POST', cookie, body: { reason: '测试吊销' } });
      check('吊销证书成功', revoke.json.ok && revoke.json.cert.status === '已吊销');
      const pub2 = await api('/api/public/verify', { method: 'POST', body: { cert_no: 'CERT-2026-1001', name: '赵六' } });
      check('吊销后公开状态为 已吊销', pub2.json.cert.status === '已吊销');

      const restore = await api(`/api/admin/certs/${certId}/restore`, { method: 'POST', cookie });
      check('恢复证书成功', restore.json.ok && restore.json.cert.status === '有效');

      const list = await api('/api/admin/certs?q=赵六', { cookie });
      check('列表搜索生效', list.json.ok && list.json.items.some((c) => c.name === '赵六'));
    }

    console.log('\n[6] 多管理员');
    {
      const add = await api('/api/admin/admins', { method: 'POST', cookie, body: { username: 'reviewer1', password: 'Review@2026' } });
      check('创建第二个管理员', add.status === 201 && add.json.ok, add.json);
      const admin2Id = add.json.admin && add.json.admin.id;

      const login2 = await api('/api/admin/login', { method: 'POST', body: { username: 'reviewer1', password: 'Review@2026' } });
      check('新管理员可登录', login2.status === 200);
      const cookie2 = login2.setCookie.split(';')[0];

      const list2 = await api('/api/admin/certs', { cookie: cookie2 });
      check('新管理员可维护证书', list2.status === 200 && list2.json.ok);

      const toggle = await api(`/api/admin/admins/${admin2Id}/toggle`, { method: 'POST', cookie });
      check('禁用第二个管理员', toggle.json.ok && toggle.json.admin.active === false);

      const login3 = await api('/api/admin/login', { method: 'POST', body: { username: 'reviewer1', password: 'Review@2026' } });
      check('被禁用管理员无法登录', login3.status === 401);

      const audit = await api('/api/admin/audit', { cookie });
      check('操作日志包含邮箱更正与吊销记录',
        audit.json.items.some((a) => a.action === 'email_change') &&
        audit.json.items.some((a) => a.action === 'cert_revoke'));
    }
  } finally {
    child.kill();
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log(`\n结果：${passed} 通过，${failed} 失败`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
