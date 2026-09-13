'use strict';

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function showAlert(el, type, msg) {
  el.className = `alert alert-${type} show`;
  el.textContent = msg;
}
function hideAlert(el) {
  el.className = 'alert';
  el.textContent = '';
}
function toast(type, msg) {
  showAlert($('globalAlert'), type, msg);
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (type === 'success') setTimeout(() => hideAlert($('globalAlert')), 4000);
}

async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  let data;
  try { data = await resp.json(); } catch (_) { throw new Error('服务器响应异常'); }
  if (resp.status === 401 && !url.endsWith('/login')) {
    showLogin();
    throw new Error(data.error || '会话已过期，请重新登录');
  }
  if (!resp.ok && !data.error) throw new Error(`请求失败（${resp.status}）`);
  return data;
}

function openModal(id) { $(id).classList.add('show'); }
function closeModal(id) { $(id).classList.remove('show'); }
document.querySelectorAll('[data-close]').forEach((btn) => {
  btn.addEventListener('click', () => closeModal(btn.dataset.close + 'Modal'));
});
document.querySelectorAll('.modal-mask').forEach((m) => {
  m.addEventListener('click', (e) => { if (e.target === m) m.classList.remove('show'); });
});

// ---------- 登录 ----------
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert($('loginAlert'));
  const btn = $('loginBtn');
  btn.disabled = true;
  btn.textContent = '登录中…';
  try {
    const data = await api('POST', '/api/admin/login', {
      username: $('loginUser').value.trim(),
      password: $('loginPwd').value,
    });
    if (!data.ok) return showAlert($('loginAlert'), 'error', data.error);
    enterApp(data.admin);
  } catch (err) {
    showAlert($('loginAlert'), 'error', err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '登 录';
  }
});

$('logoutBtn').addEventListener('click', async () => {
  await api('POST', '/api/admin/logout');
  showLogin();
});

function showLogin() {
  $('appView').classList.add('hidden');
  $('loginView').classList.remove('hidden');
  $('loginPwd').value = '';
}

async function boot() {
  const data = await api('GET', '/api/admin/me');
  if (data.ok) {
    $('whoami').textContent = `${data.admin.displayName}（${data.admin.username}）`;
    $('appView').classList.remove('hidden');
    $('loginView').classList.add('hidden');
    switchTab('dash');
  } else {
    showLogin();
  }
}

function enterApp(admin) {
  $('whoami').textContent = `${admin.displayName}（${admin.username}）`;
  $('appView').classList.remove('hidden');
  $('loginView').classList.add('hidden');
  $('loginPwd').value = '';
  switchTab('dash');
}

// ---------- Tab ----------
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('[data-panel]').forEach((p) =>
    p.classList.toggle('hidden', p.dataset.panel !== name)
  );
  if (name === 'dash') loadStats();
  if (name === 'certs') loadCerts();
  if (name === 'admins') loadAdmins();
  if (name === 'logs') loadLogs();
}

// ---------- 概览 ----------
async function loadStats() {
  const data = await api('GET', '/api/admin/stats');
  if (!data.ok) return;
  const s = data.stats;
  const cards = [
    ['证书总数', s.total, '#1a5fb4'],
    ['有效', s.valid, '#15803d'],
    ['即将到期(90天内)', s.expireSoon, '#b45309'],
    ['已过期', s.expired, '#b45309'],
    ['已吊销', s.revoked, '#b91c1c'],
    ['启用管理员', s.admins, '#334155'],
  ];
  $('statsBox').innerHTML = cards
    .map(([label, num, color]) =>
      `<div class="stat"><div class="num" style="color:${color}">${num}</div><div class="label">${label}</div></div>`)
    .join('');
}

// ---------- 证书管理 ----------
let certs = [];
let editingCertId = null;
let revokingCertId = null;

async function loadCerts() {
  const q = $('certSearch').value.trim();
  const data = await api('GET', '/api/admin/certificates' + (q ? `?q=${encodeURIComponent(q)}` : ''));
  if (!data.ok) return;
  certs = data.items;
  renderCerts();
}

function statusBadge(c) {
  const map = {
    valid: ['badge-valid', c.status.expireSoon ? `有效（${c.status.daysLeft}天后到期）` : '有效'],
    expired: ['badge-expired', '已过期'],
    revoked: ['badge-revoked', '已吊销'],
  };
  const [cls, label] = map[c.status.code] || ['badge-valid', c.status.label];
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

function renderCerts() {
  if (!certs.length) {
    $('certTbody').innerHTML = '<tr><td colspan="9" style="text-align:center;color:#6b7280;padding:30px;">暂无证书数据</td></tr>';
    return;
  }
  $('certTbody').innerHTML = certs.map((c) => `
    <tr>
      <td><strong>${esc(c.certNo)}</strong></td>
      <td>${esc(c.studentName)}</td>
      <td>${esc(c.courseName)}</td>
      <td>${esc(c.issuedAt)}</td>
      <td>${esc(c.validUntil)}</td>
      <td>${esc(c.organization)}</td>
      <td>${c.email ? esc(c.email) : '<span class="muted">未登记</span>'}</td>
      <td>${statusBadge(c)}</td>
      <td class="actions-cell">
        <button class="btn btn-secondary btn-sm" onclick="editCert('${c.id}')">编辑</button>
        ${c.revoked
          ? `<button class="btn btn-secondary btn-sm" onclick="restoreCert('${c.id}')">恢复</button>`
          : `<button class="btn btn-outline-danger btn-sm" onclick="openRevoke('${c.id}')">吊销</button>`}
        <button class="btn btn-outline-danger btn-sm" onclick="deleteCert('${c.id}')">删除</button>
      </td>
    </tr>
  `).join('');
}

window.editCert = function (id) {
  const c = certs.find((x) => x.id === id);
  if (!c) return;
  editingCertId = id;
  $('certModalTitle').textContent = '编辑证书';
  $('f_certNo').value = c.certNo;
  $('f_studentName').value = c.studentName;
  $('f_courseName').value = c.courseName;
  $('f_issuedAt').value = c.issuedAt;
  $('f_validUntil').value = c.validUntil;
  $('f_organization').value = c.organization;
  $('f_email').value = c.email || '';
  hideAlert($('certModalAlert'));
  openModal('certModal');
};

$('addCertBtn').addEventListener('click', () => {
  editingCertId = null;
  $('certModalTitle').textContent = '录入证书';
  ['f_certNo', 'f_studentName', 'f_courseName', 'f_issuedAt', 'f_validUntil', 'f_organization', 'f_email']
    .forEach((id) => { $(id).value = ''; });
  hideAlert($('certModalAlert'));
  openModal('certModal');
});

function readCertForm() {
  return {
    certNo: $('f_certNo').value.trim(),
    studentName: $('f_studentName').value.trim(),
    courseName: $('f_courseName').value.trim(),
    issuedAt: $('f_issuedAt').value,
    validUntil: $('f_validUntil').value,
    organization: $('f_organization').value.trim(),
    email: $('f_email').value.trim(),
  };
}

$('saveCertBtn').addEventListener('click', async () => {
  hideAlert($('certModalAlert'));
  const body = readCertForm();
  const btn = $('saveCertBtn');
  btn.disabled = true;
  try {
    const data = editingCertId
      ? await api('PUT', `/api/admin/certificates/${editingCertId}`, body)
      : await api('POST', '/api/admin/certificates', body);
    if (!data.ok) return showAlert($('certModalAlert'), 'error', data.error);
    closeModal('certModal');
    toast('success', editingCertId ? '证书已更新' : '证书已录入');
    loadCerts();
  } catch (err) {
    showAlert($('certModalAlert'), 'error', err.message);
  } finally {
    btn.disabled = false;
  }
});

window.openRevoke = function (id) {
  const c = certs.find((x) => x.id === id);
  if (!c) return;
  revokingCertId = id;
  $('revokeReason').value = '';
  $('revokeCertInfo').textContent = `${c.certNo} · ${c.studentName} · ${c.courseName}`;
  hideAlert($('revokeModalAlert'));
  openModal('revokeModal');
};

$('confirmRevokeBtn').addEventListener('click', async () => {
  const reason = $('revokeReason').value.trim();
  if (!reason) return showAlert($('revokeModalAlert'), 'error', '请填写吊销原因');
  const data = await api('POST', `/api/admin/certificates/${revokingCertId}/revoke`, { reason });
  if (!data.ok) return showAlert($('revokeModalAlert'), 'error', data.error);
  closeModal('revokeModal');
  toast('success', '证书已吊销');
  loadCerts();
});

window.restoreCert = async function (id) {
  if (!confirm('确定恢复该证书为有效状态吗？')) return;
  const data = await api('POST', `/api/admin/certificates/${id}/restore`, {});
  if (!data.ok) return toast('error', data.error);
  toast('success', '证书已恢复');
  loadCerts();
};

window.deleteCert = async function (id) {
  const c = certs.find((x) => x.id === id);
  if (!c) return;
  if (!confirm(`确定删除证书 ${c.certNo}（${c.studentName}）吗？删除后不可恢复。`)) return;
  const data = await api('DELETE', `/api/admin/certificates/${id}`);
  if (!data.ok) return toast('error', data.error);
  toast('success', '证书已删除');
  loadCerts();
};

$('searchBtn').addEventListener('click', loadCerts);
$('certSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadCerts(); });

// ---------- 管理员 ----------
async function loadAdmins() {
  const data = await api('GET', '/api/admin/admins');
  if (!data.ok) return;
  $('adminTbody').innerHTML = data.items.map((a) => `
    <tr>
      <td><strong>${esc(a.username)}</strong>${a.isSelf ? ' <span class="muted">（当前登录）</span>' : ''}</td>
      <td>${esc(a.displayName)}</td>
      <td>${a.active ? '<span class="tag tag-on">启用</span>' : '<span class="tag tag-off">已停用</span>'}</td>
      <td>${esc(a.createdBy || '—')}</td>
      <td>${new Date(a.createdAt).toLocaleString('zh-CN')}</td>
      <td class="actions-cell">
        <button class="btn btn-secondary btn-sm" onclick="resetPwd('${a.id}','${esc(a.username)}')">重置密码</button>
        ${a.isSelf
          ? '<button class="btn btn-secondary btn-sm" disabled>不能停用自己</button>'
          : `<button class="btn btn-outline-danger btn-sm" onclick="toggleAdmin('${a.id}',${!a.active})">${a.active ? '停用' : '启用'}</button>`}
      </td>
    </tr>
  `).join('');
}

$('addAdminBtn').addEventListener('click', () => {
  ['af_username', 'af_displayName', 'af_password'].forEach((id) => { $(id).value = ''; });
  hideAlert($('adminModalAlert'));
  openModal('adminModal');
});

$('saveAdminBtn').addEventListener('click', async () => {
  const body = {
    username: $('af_username').value.trim(),
    displayName: $('af_displayName').value.trim(),
    password: $('af_password').value,
  };
  const data = await api('POST', '/api/admin/admins', body);
  if (!data.ok) return showAlert($('adminModalAlert'), 'error', data.error);
  closeModal('adminModal');
  toast('success', `管理员 ${body.username} 已创建`);
  loadAdmins();
});

window.toggleAdmin = async function (id, active) {
  const data = await api('POST', `/api/admin/admins/${id}/set-active`, { active });
  if (!data.ok) return toast('error', data.error);
  toast('success', active ? '账号已启用' : '账号已停用');
  loadAdmins();
};

let resetTargetId = null;
window.resetPwd = function (id, username) {
  resetTargetId = id;
  $('rf_password').value = '';
  $('resetPwdInfo').textContent = `账号：${username}`;
  hideAlert($('resetPwdAlert'));
  openModal('resetPwdModal');
};
$('confirmResetPwdBtn').addEventListener('click', async () => {
  const data = await api('POST', `/api/admin/admins/${resetTargetId}/reset-password`, {
    password: $('rf_password').value,
  });
  if (!data.ok) return showAlert($('resetPwdAlert'), 'error', data.error);
  closeModal('resetPwdModal');
  toast('success', data.message || '密码已重置');
});

// 修改自己的密码
$('changePwdBtn').addEventListener('click', () => {
  $('cp_old').value = '';
  $('cp_new').value = '';
  hideAlert($('changePwdAlert'));
  openModal('changePwdModal');
});
$('confirmChangePwdBtn').addEventListener('click', async () => {
  const data = await api('POST', '/api/admin/change-password', {
    oldPassword: $('cp_old').value,
    newPassword: $('cp_new').value,
  });
  if (!data.ok) return showAlert($('changePwdAlert'), 'error', data.error);
  closeModal('changePwdModal');
  toast('success', '密码修改成功');
});

// ---------- 审计日志 ----------
const ACTION_LABELS = {
  'login.ok': '登录成功',
  'login.fail': '登录失败',
  'cert.verify': '公众核验',
  'cert.create': '录入证书',
  'cert.update': '编辑证书',
  'cert.revoke': '吊销证书',
  'cert.restore': '恢复证书',
  'cert.delete': '删除证书',
  'admin.create': '新增管理员',
  'admin.enable': '启用管理员',
  'admin.disable': '停用管理员',
  'admin.reset-password': '重置密码',
  'admin.change-password': '修改本人密码',
  'email.change.request': '发起邮箱更正',
  'email.change.ok': '邮箱更正成功',
  'email.change.fail': '邮箱更正失败',
};
async function loadLogs() {
  const data = await api('GET', '/api/admin/audit-logs?limit=300');
  if (!data.ok) return;
  $('logTbody').innerHTML = data.items.map((l) => `
    <tr>
      <td style="white-space:nowrap;">${new Date(l.at).toLocaleString('zh-CN')}</td>
      <td>${esc(l.actorName)} <span class="muted">(${esc(l.actor)})</span></td>
      <td>${esc(ACTION_LABELS[l.action] || l.action)}</td>
      <td class="log-detail">${esc(JSON.stringify(l.detail || {}))}</td>
    </tr>
  `).join('');
}
$('refreshLogsBtn').addEventListener('click', loadLogs);

// 启动
boot().catch((e) => showAlert($('loginAlert'), 'error', e.message));
