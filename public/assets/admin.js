'use strict';

const $ = (sel) => document.querySelector(sel);

const state = { page: 1, pages: 1, q: '', editingId: null, me: null };

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

let toastTimer = null;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2500);
}

function badgeHtml(status) {
  const cls = status === '有效' ? 'badge-ok' : status === '已过期' ? 'badge-warn' : 'badge-bad';
  return `<span class="badge ${cls}">${esc(status)}</span>`;
}

/* ---------- 登录 / 退出 ---------- */

async function boot() {
  const { json } = await api('/api/admin/me');
  if (json.ok) {
    state.me = json.admin;
    showDash();
  } else {
    $('#login-view').hidden = false;
    $('#dash-view').hidden = true;
  }
}

function showDash() {
  $('#login-view').hidden = true;
  $('#dash-view').hidden = false;
  $('#whoami').textContent = `当前管理员：${state.me.username}`;
  $('#whoami').hidden = false;
  $('#logout-btn').hidden = false;
  loadCerts();
  loadAdmins();
  loadAudit();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = $('#login-error');
  errEl.hidden = true;
  const fd = new FormData(e.target);
  const { json } = await api('/api/admin/login', {
    method: 'POST',
    body: { username: fd.get('username').trim(), password: fd.get('password') },
  });
  if (!json.ok) {
    errEl.textContent = json.error || '登录失败';
    errEl.hidden = false;
    return;
  }
  state.me = json.admin;
  e.target.reset();
  showDash();
});

$('#logout-btn').addEventListener('click', async () => {
  await api('/api/admin/logout', { method: 'POST' });
  location.reload();
});

/* ---------- 标签页 ---------- */

document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach((p) => (p.hidden = true));
    $('#tab-' + btn.dataset.tab).hidden = false;
    if (btn.dataset.tab === 'audit') loadAudit();
  });
});

/* ---------- 证书管理 ---------- */

async function loadCerts() {
  const { json } = await api(`/api/admin/certs?page=${state.page}&q=${encodeURIComponent(state.q)}`);
  if (!json.ok) return;
  state.page = json.page;
  state.pages = json.pages;
  const tbody = $('#cert-rows');
  if (!json.items.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted">暂无数据</td></tr>';
  } else {
    tbody.innerHTML = json.items.map((c) => `
      <tr>
        <td>${esc(c.cert_no)}</td>
        <td>${esc(c.name)}</td>
        <td>${esc(c.course_name)}</td>
        <td>${esc(c.org)}</td>
        <td>${esc(c.issue_date)}</td>
        <td>${esc(c.valid_until)}</td>
        <td>${badgeHtml(c.status)}</td>
        <td>${esc(c.contact_email || '—')}</td>
        <td>
          <button class="btn btn-small" data-act="edit" data-id="${esc(c.id)}">编辑</button>
          ${c.revoked
            ? `<button class="btn btn-small" data-act="restore" data-id="${esc(c.id)}">恢复</button>`
            : `<button class="btn btn-small btn-danger" data-act="revoke" data-id="${esc(c.id)}">吊销</button>`}
        </td>
      </tr>`).join('');
  }
  $('#page-info').textContent = `第 ${json.page} / ${json.pages} 页，共 ${json.total} 条`;
  $('#page-prev').disabled = json.page <= 1;
  $('#page-next').disabled = json.page >= json.pages;
  // 缓存当前页数据供编辑使用
  state.currentItems = json.items;
}

$('#cert-search').addEventListener('click', () => {
  state.q = $('#cert-q').value.trim();
  state.page = 1;
  loadCerts();
});
$('#cert-q').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    state.q = e.target.value.trim();
    state.page = 1;
    loadCerts();
  }
});
$('#page-prev').addEventListener('click', () => { if (state.page > 1) { state.page--; loadCerts(); } });
$('#page-next').addEventListener('click', () => { if (state.page < state.pages) { state.page++; loadCerts(); } });

function openCertModal(cert) {
  state.editingId = cert ? cert.id : null;
  $('#cert-modal-title').textContent = cert ? `编辑证书 ${cert.cert_no}` : '新增证书';
  const f = $('#cert-form');
  f.reset();
  f.elements.cert_no.readOnly = !!cert;
  if (cert) {
    f.elements.cert_no.value = cert.cert_no;
    f.elements.name.value = cert.name;
    f.elements.course_name.value = cert.course_name;
    f.elements.org.value = cert.org;
    f.elements.issue_date.value = cert.issue_date;
    f.elements.valid_until.value = cert.valid_until;
    f.elements.contact_email.value = cert.contact_email || '';
  }
  $('#cert-form-error').hidden = true;
  $('#cert-modal').hidden = false;
}

$('#cert-add').addEventListener('click', () => openCertModal(null));
$('#cert-cancel').addEventListener('click', () => ($('#cert-modal').hidden = true));

$('#cert-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = $('#cert-form-error');
  errEl.hidden = true;
  const f = e.target;
  const body = {
    cert_no: f.elements.cert_no.value.trim(),
    name: f.elements.name.value.trim(),
    course_name: f.elements.course_name.value.trim(),
    org: f.elements.org.value.trim(),
    issue_date: f.elements.issue_date.value,
    valid_until: f.elements.valid_until.value,
    contact_email: f.elements.contact_email.value.trim(),
  };
  const { json } = state.editingId
    ? await api(`/api/admin/certs/${state.editingId}`, { method: 'PUT', body })
    : await api('/api/admin/certs', { method: 'POST', body });
  if (!json.ok) {
    errEl.textContent = json.error || '保存失败';
    errEl.hidden = false;
    return;
  }
  $('#cert-modal').hidden = true;
  toast(state.editingId ? '证书已更新' : '证书已创建');
  loadCerts();
});

$('#cert-rows').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const id = btn.dataset.id;
  const cert = (state.currentItems || []).find((c) => c.id === id);
  if (btn.dataset.act === 'edit') {
    if (cert) openCertModal(cert);
  } else if (btn.dataset.act === 'revoke') {
    if (!cert) return;
    const reason = prompt(`确认吊销证书 ${cert.cert_no}（${cert.name}）？\n可填写吊销原因（选填）：`, '');
    if (reason === null) return;
    const { json } = await api(`/api/admin/certs/${id}/revoke`, { method: 'POST', body: { reason } });
    toast(json.ok ? '证书已吊销' : json.error || '操作失败');
    loadCerts();
  } else if (btn.dataset.act === 'restore') {
    if (!cert || !confirm(`确认恢复证书 ${cert.cert_no}（${cert.name}）？`)) return;
    const { json } = await api(`/api/admin/certs/${id}/restore`, { method: 'POST' });
    toast(json.ok ? '证书已恢复' : json.error || '操作失败');
    loadCerts();
  }
});

/* ---------- 管理员管理 ---------- */

async function loadAdmins() {
  const { json } = await api('/api/admin/admins');
  if (!json.ok) return;
  $('#admin-rows').innerHTML = json.items.map((a) => `
    <tr>
      <td>${esc(a.username)}${state.me && a.id === state.me.id ? '（我）' : ''}</td>
      <td>${a.active ? '<span class="badge badge-ok">启用</span>' : '<span class="badge badge-bad">禁用</span>'}</td>
      <td>${esc((a.created_at || '').slice(0, 10))}</td>
      <td><button class="btn btn-small" data-admin-toggle="${esc(a.id)}">${a.active ? '禁用' : '启用'}</button></td>
    </tr>`).join('');
}

$('#admin-add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msgEl = $('#admin-add-msg');
  msgEl.hidden = true;
  const fd = new FormData(e.target);
  const { json } = await api('/api/admin/admins', {
    method: 'POST',
    body: { username: fd.get('username').trim(), password: fd.get('password') },
  });
  msgEl.hidden = false;
  msgEl.className = 'alert ' + (json.ok ? 'alert-ok' : 'alert-error');
  msgEl.textContent = json.ok ? `管理员 ${json.admin.username} 已创建` : json.error || '创建失败';
  if (json.ok) {
    e.target.reset();
    loadAdmins();
  }
});

$('#admin-rows').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-admin-toggle]');
  if (!btn) return;
  const { json } = await api(`/api/admin/admins/${btn.dataset.adminToggle}/toggle`, { method: 'POST' });
  toast(json.ok ? '已更新' : json.error || '操作失败');
  loadAdmins();
});

/* ---------- 操作日志 ---------- */

const ACTION_LABELS = {
  admin_login: '登录',
  cert_create: '新增证书',
  cert_update: '更新证书',
  cert_revoke: '吊销证书',
  cert_restore: '恢复证书',
  email_change: '邮箱更正',
  admin_create: '新增管理员',
  admin_toggle: '启用/禁用管理员',
  password_change: '修改密码',
};

async function loadAudit() {
  const { json } = await api('/api/admin/audit');
  if (!json.ok) return;
  $('#audit-rows').innerHTML = json.items.length
    ? json.items.map((a) => `
      <tr>
        <td>${esc((a.at || '').replace('T', ' ').slice(0, 19))}</td>
        <td>${esc(ACTION_LABELS[a.action] || a.action)}</td>
        <td>${esc(a.actor)}</td>
        <td>${esc(a.detail)}</td>
      </tr>`).join('')
    : '<tr><td colspan="4" class="muted">暂无日志</td></tr>';
}

/* ---------- 修改密码 ---------- */

$('#pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msgEl = $('#pw-msg');
  msgEl.hidden = true;
  const fd = new FormData(e.target);
  const { json } = await api('/api/admin/password', {
    method: 'POST',
    body: { old_password: fd.get('old_password'), new_password: fd.get('new_password') },
  });
  msgEl.hidden = false;
  msgEl.className = 'alert ' + (json.ok ? 'alert-ok' : 'alert-error');
  msgEl.textContent = json.ok ? json.message || '密码已更新' : json.error || '修改失败';
  if (json.ok) e.target.reset();
});

boot();
