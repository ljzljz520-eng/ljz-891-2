// 管理后台 SPA：登录 / 证书 CRUD / 管理员管理 / 审计日志
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  const state = {
    admin: null,
    csrf: '',
    certs: { page: 1, pageSize: 10, total: 0, keyword: '', status: '' },
    admins: [],
    logs: { page: 1, pageSize: 10, total: 0, action: '' },
    editingCertId: null,
    editingAdminId: null,
    resettingAdminId: null,
  };

  // ---------- 基础 ----------
  let toastTimer = null;
  function toast(msg, type = '') {
    const t = $('toast');
    t.textContent = msg;
    t.className = 'toast show ' + type;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.className = 'toast ' + type), 2800);
  }

  function showAlert(id, msg) {
    const el = $(id);
    el.textContent = msg;
    el.hidden = false;
  }
  function hideAlert(id) {
    const el = $(id);
    el.hidden = true;
    el.textContent = '';
  }

  async function request(method, url, body) {
    const opt = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    };
    if (state.csrf) opt.headers['X-CSRF-Token'] = state.csrf;
    if (body !== undefined) opt.body = JSON.stringify(body);
    const res = await fetch(url, opt);
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error('服务器响应异常');
    }
    if (!res.ok || !data.ok) {
      const err = new Error(data?.error?.message || '请求失败');
      err.status = res.status;
      err.code = data?.error?.code;
      throw err;
    }
    if (data.csrf) state.csrf = data.csrf;
    return data;
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );
  }

  const STATUS_LABELS = { valid: '有效', expiring: '即将到期', expired: '已过期', revoked: '已吊销' };
  const STATUS_CLASS = { valid: 'valid', expiring: 'expiring', expired: 'expired', revoked: 'revoked' };
  const ACTION_LABELS = {
    'admin.login': '登录成功',
    'admin.login_failed': '登录失败',
    'admin.logout': '退出登录',
    'admin.password_self_changed': '修改自己的密码',
    'cert.created': '新增证书',
    'cert.updated': '编辑证书',
    'cert.revoked': '吊销证书',
    'cert.restored': '恢复证书',
    'cert.deleted': '删除证书',
    'email.corrected': '学员自助更正邮箱',
    'admin.created': '新增管理员',
    'admin.updated': '修改管理员',
    'admin.deleted': '删除管理员',
    'admin.password_reset': '重置管理员密码',
  };

  // ---------- 启动 ----------
  async function init() {
    bindStaticEvents();
    try {
      const data = await request('GET', '/api/admin/me');
      enterApp(data.admin, data.csrf);
    } catch {
      showLogin();
    }
  }

  function showLogin() {
    $('loginView').hidden = false;
    $('adminView').hidden = true;
    setTimeout(() => $('loginUsername').focus(), 50);
  }

  function enterApp(admin, csrf) {
    state.admin = admin;
    state.csrf = csrf;
    $('loginView').hidden = true;
    $('adminView').hidden = false;
    $('userName').textContent = admin.displayName;
    $('userAvatar').textContent = (admin.displayName || admin.username).slice(0, 1).toUpperCase();
    const roleEl = $('userRole');
    roleEl.textContent = admin.role === 'super' ? '超级管理员' : '编辑';
    $('mustChangeAlert').hidden = !admin.mustChangePassword;

    const isSuper = admin.role === 'super';
    $('tabAdmins').style.display = isSuper ? '' : 'none';
    $('tabLogs').style.display = isSuper ? '' : 'none';
    $('adminCreateBtn').style.display = isSuper ? '' : 'none';

    switchTab('certs');
    loadCertificates();
  }

  // ---------- 登录 ----------
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('loginAlert');
    const btn = $('loginBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> 登录中…';
    try {
      const data = await request('POST', '/api/admin/login', {
        username: $('loginUsername').value.trim(),
        password: $('loginPassword').value,
      });
      $('loginPassword').value = '';
      enterApp(data.admin, data.csrf);
    } catch (err) {
      showAlert('loginAlert', err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = '登录';
    }
  });

  $('logoutBtn').addEventListener('click', async () => {
    try {
      await request('POST', '/api/admin/logout');
    } catch {
      // 忽略
    }
    location.reload();
  });

  // ---------- Tab ----------
  function bindStaticEvents() {
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    $('certSearchBtn').addEventListener('click', () => {
      state.certs.keyword = $('certSearch').value.trim();
      state.certs.status = $('certStatusFilter').value;
      state.certs.page = 1;
      loadCertificates();
    });
    $('certSearch').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') $('certSearchBtn').click();
    });
    $('certResetBtn').addEventListener('click', () => {
      $('certSearch').value = '';
      $('certStatusFilter').value = '';
      state.certs.keyword = '';
      state.certs.status = '';
      state.certs.page = 1;
      loadCertificates();
    });
    $('certPrevBtn').addEventListener('click', () => changeCertPage(-1));
    $('certNextBtn').addEventListener('click', () => changeCertPage(1));
    $('certCreateBtn').addEventListener('click', () => openCertModal(null));

    $('adminCreateBtn').addEventListener('click', () => openAdminModal(null));
    $('adminForm').addEventListener('submit', submitAdminForm);

    $('logFilterBtn').addEventListener('click', () => {
      state.logs.action = $('logActionFilter').value;
      state.logs.page = 1;
      loadLogs();
    });
    $('logPrevBtn').addEventListener('click', () => changeLogPage(-1));
    $('logNextBtn').addEventListener('click', () => changeLogPage(1));

    $('certForm').addEventListener('submit', submitCertForm);
    $('cf_longTerm').addEventListener('change', toggleLongTerm);
    $('cf_revoked').addEventListener('change', toggleRevoked);

    $('changePwdBtn').addEventListener('click', () => {
      $('pf_old').value = '';
      $('pf_new').value = '';
      $('pf_new2').value = '';
      hideAlert('pwdAlert');
      $('pwdModal').hidden = false;
    });
    $('pwdForm').addEventListener('submit', submitOwnPassword);
    $('resetPwdForm').addEventListener('submit', submitResetPassword);

    document.querySelectorAll('[data-close]').forEach((btn) => {
      btn.addEventListener('click', () => ($(btn.dataset.close).hidden = true));
    });
    document.querySelectorAll('.modal-mask').forEach((mask) => {
      mask.addEventListener('click', (e) => {
        if (e.target === mask) mask.hidden = true;
      });
    });
  }

  function switchTab(name) {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $('tab-certs').hidden = name !== 'certs';
    $('tab-admins').hidden = name !== 'admins';
    $('tab-logs').hidden = name !== 'logs';
    if (name === 'admins' && state.admin?.role === 'super') loadAdmins();
    if (name === 'logs' && state.admin?.role === 'super') loadLogs();
  }

  // ---------- 证书 ----------
  async function loadCertificates() {
    const q = new URLSearchParams({
      page: state.certs.page,
      pageSize: state.certs.pageSize,
    });
    if (state.certs.keyword) q.set('keyword', state.certs.keyword);
    if (state.certs.status) q.set('status', state.certs.status);
    try {
      const data = await request('GET', '/api/admin/certificates?' + q.toString());
      state.certs.total = data.total;
      renderCertificates(data.items);
    } catch (err) {
      handleApiError(err);
    }
  }

  function renderCertificates(items) {
    const tbody = $('certTbody');
    if (!items.length) {
      tbody.innerHTML = '';
      $('certEmpty').hidden = false;
    } else {
      $('certEmpty').hidden = true;
      tbody.innerHTML = items
        .map((c) => {
          const st = c.status;
          return `<tr>
            <td class="wrap"><strong>${esc(c.certNo)}</strong></td>
            <td>${esc(c.studentName)}</td>
            <td class="wrap">${esc(c.courseName)}</td>
            <td>${esc(c.issueDate)}</td>
            <td>${c.longTerm ? '长期有效' : esc(c.validUntil || '—')}</td>
            <td class="wrap">${esc(c.institution)}</td>
            <td class="wrap">${esc(c.contactEmail || '—')}</td>
            <td><span class="badge badge-${STATUS_CLASS[st]}">${STATUS_LABELS[st] || st}</span></td>
            <td>
              <div class="actions">
                <button class="link-btn" data-edit-cert="${c.id}">编辑</button>
                ${
                  c.revoked
                    ? `<button class="link-btn" data-restore-cert="${c.id}">恢复</button>`
                    : `<button class="link-btn danger" data-revoke-cert="${c.id}">吊销</button>`
                }
                <button class="link-btn danger" data-del-cert="${c.id}">删除</button>
              </div>
            </td>
          </tr>`;
        })
        .join('');

      tbody.querySelectorAll('[data-edit-cert]').forEach((b) =>
        b.addEventListener('click', () => openCertModal(b.dataset.editCert))
      );
      tbody.querySelectorAll('[data-del-cert]').forEach((b) =>
        b.addEventListener('click', () => deleteCert(b.dataset.delCert))
      );
      tbody.querySelectorAll('[data-revoke-cert]').forEach((b) =>
        b.addEventListener('click', () => toggleRevoke(b.dataset.revokeCert, true))
      );
      tbody.querySelectorAll('[data-restore-cert]').forEach((b) =>
        b.addEventListener('click', () => toggleRevoke(b.dataset.restoreCert, false))
      );
    }
    const { page, pageSize, total } = state.certs;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    $('certPageInfo').textContent = `共 ${total} 条记录`;
    $('certPageNo').textContent = `${page} / ${pages}`;
    $('certPrevBtn').disabled = page <= 1;
    $('certNextBtn').disabled = page >= pages;
  }

  function changeCertPage(delta) {
    const pages = Math.max(1, Math.ceil(state.certs.total / state.certs.pageSize));
    const next = Math.min(Math.max(1, state.certs.page + delta), pages);
    if (next !== state.certs.page) {
      state.certs.page = next;
      loadCertificates();
    }
  }

  async function openCertModal(id) {
    hideAlert('certFormAlert');
    state.editingCertId = id;
    $('certModalTitle').textContent = id ? '编辑证书' : '新增证书';
    const f = {
      certNo: $('cf_certNo'),
      studentName: $('cf_studentName'),
      courseName: $('cf_courseName'),
      institution: $('cf_institution'),
      issueDate: $('cf_issueDate'),
      validUntil: $('cf_validUntil'),
      longTerm: $('cf_longTerm'),
      contactEmail: $('cf_contactEmail'),
      revoked: $('cf_revoked'),
      revokedReason: $('cf_revokedReason'),
    };
    Object.values(f).forEach((el) => (el.value = el.type === 'checkbox' ? false : ''));
    f.longTerm.checked = false;
    f.revoked.checked = false;
    $('cf_reasonWrap').hidden = true;
    toggleLongTerm();

    if (id) {
      try {
        const data = await request('GET', `/api/admin/certificates/${id}`);
        const c = data.certificate;
        f.certNo.value = c.certNo;
        f.studentName.value = c.studentName;
        f.courseName.value = c.courseName;
        f.institution.value = c.institution;
        f.issueDate.value = c.issueDate;
        f.validUntil.value = c.validUntil || '';
        f.longTerm.checked = !!c.longTerm;
        f.contactEmail.value = c.contactEmail || '';
        f.revoked.checked = !!c.revoked;
        f.revokedReason.value = c.revokedReason || '';
        $('cf_reasonWrap').hidden = !c.revoked;
        toggleLongTerm();
      } catch (err) {
        toast(err.message, 'error');
        return;
      }
    }
    $('certModal').hidden = false;
  }

  function toggleLongTerm() {
    const lt = $('cf_longTerm').checked;
    $('cf_validUntil').disabled = lt;
    $('longTermHint').textContent = lt ? '（长期有效，无需填写）' : '';
    if (lt) $('cf_validUntil').value = '';
  }
  function toggleRevoked() {
    $('cf_reasonWrap').hidden = !$('cf_revoked').checked;
  }

  async function submitCertForm(e) {
    e.preventDefault();
    hideAlert('certFormAlert');
    const payload = {
      certNo: $('cf_certNo').value.trim(),
      studentName: $('cf_studentName').value.trim(),
      courseName: $('cf_courseName').value.trim(),
      institution: $('cf_institution').value.trim(),
      issueDate: $('cf_issueDate').value,
      validUntil: $('cf_validUntil').value,
      longTerm: $('cf_longTerm').checked,
      contactEmail: $('cf_contactEmail').value.trim(),
      revoked: $('cf_revoked').checked,
      revokedReason: $('cf_revokedReason').value.trim(),
    };
    const btn = $('certSaveBtn');
    btn.disabled = true;
    btn.textContent = '保存中…';
    try {
      if (state.editingCertId) {
        await request('PUT', `/api/admin/certificates/${state.editingCertId}`, payload);
        toast('证书已更新', 'success');
      } else {
        await request('POST', '/api/admin/certificates', payload);
        toast('证书已创建', 'success');
      }
      $('certModal').hidden = true;
      loadCertificates();
    } catch (err) {
      showAlert('certFormAlert', err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = '保存';
    }
  }

  async function deleteCert(id) {
    if (!confirm('确定删除该证书吗？删除后学员将无法核验到此证书，此操作会记录日志。')) return;
    try {
      await request('DELETE', `/api/admin/certificates/${id}`);
      toast('证书已删除', 'success');
      loadCertificates();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function toggleRevoke(id, revoke) {
    let reason = '';
    if (revoke) {
      reason = prompt('请输入吊销原因（将对学员展示，可留空）：', '') ?? '';
      if (reason === null) return;
    }
    try {
      await request('POST', `/api/admin/certificates/${id}/revoke`, { revoked: revoke, reason: reason.trim() });
      toast(revoke ? '证书已吊销' : '证书已恢复', 'success');
      loadCertificates();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  // ---------- 管理员 ----------
  async function loadAdmins() {
    try {
      const data = await request('GET', '/api/admin/admins');
      state.admins = data.admins;
      renderAdmins();
    } catch (err) {
      handleApiError(err);
    }
  }

  function renderAdmins() {
    $('adminTbody').innerHTML = state.admins
      .map((a) => {
        return `<tr>
          <td><strong>${esc(a.username)}</strong>${a.mustChangePassword ? ' <span class="badge badge-expiring" style="font-size:11px">待改密</span>' : ''}</td>
          <td>${esc(a.displayName)}</td>
          <td><span class="role-tag role-${a.role}">${a.role === 'super' ? '超级管理员' : '编辑'}</span></td>
          <td><span class="status-dot ${a.active ? 'on' : 'off'}">${a.active ? '● 启用' : '○ 停用'}</span></td>
          <td>${esc((a.createdAt || '').replace('T', ' ').slice(0, 16))}</td>
          <td>
            <div class="actions">
              <button class="link-btn" data-edit-admin="${a.id}">编辑</button>
              <button class="link-btn" data-reset-admin="${a.id}">重置密码</button>
              <button class="link-btn danger" data-del-admin="${a.id}" ${a.id === state.admin.id ? 'disabled title="不能删除自己"' : ''}>删除</button>
            </div>
          </td>
        </tr>`;
      })
      .join('');

    document.querySelectorAll('[data-edit-admin]').forEach((b) =>
      b.addEventListener('click', () => editAdmin(b.dataset.editAdmin))
    );
    document.querySelectorAll('[data-reset-admin]').forEach((b) =>
      b.addEventListener('click', () => openResetPwd(b.dataset.resetAdmin))
    );
    document.querySelectorAll('[data-del-admin]').forEach((b) =>
      b.addEventListener('click', () => deleteAdmin(b.dataset.delAdmin))
    );
  }

  function openAdminModal() {
    hideAlert('adminFormAlert');
    state.editingAdminId = null;
    $('adminModalTitle').textContent = '新增管理员';
    $('af_username').value = '';
    $('af_username').disabled = false;
    $('af_displayName').value = '';
    $('af_role').value = 'editor';
    $('af_password').value = '';
    $('af_mustChange').checked = true;
    $('af_active').checked = true;
    $('adminModal').hidden = false;
  }

  async function editAdmin(id) {
    const a = state.admins.find((x) => x.id === id);
    if (!a) return;
    // 行内快捷调整角色/状态，同时提供完整编辑
    const choice = prompt(
      `编辑管理员「${a.username}」，请选择操作：\n  1 = 切换角色（当前：${a.role === 'super' ? '超级管理员' : '编辑'}）\n  2 = 切换启用/停用（当前：${a.active ? '启用' : '停用'}）\n  3 = 修改显示姓名\n\n直接关闭取消。`,
      '1'
    );
    if (choice === null) return;
    try {
      if (choice.trim() === '1') {
        await request('PATCH', `/api/admin/admins/${id}`, { role: a.role === 'super' ? 'editor' : 'super' });
        toast('角色已更新', 'success');
      } else if (choice.trim() === '2') {
        await request('PATCH', `/api/admin/admins/${id}`, { active: !a.active });
        toast('状态已更新', 'success');
      } else if (choice.trim() === '3') {
        const name = prompt('请输入新的显示姓名：', a.displayName);
        if (name === null) return;
        await request('PATCH', `/api/admin/admins/${id}`, { displayName: name.trim() });
        toast('显示姓名已更新', 'success');
      } else {
        return;
      }
      loadAdmins();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function submitAdminForm(e) {
    e.preventDefault();
    hideAlert('adminFormAlert');
    const payload = {
      username: $('af_username').value.trim(),
      displayName: $('af_displayName').value.trim(),
      role: $('af_role').value,
      password: $('af_password').value,
      mustChangePassword: $('af_mustChange').checked,
      active: $('af_active').checked,
    };
    try {
      await request('POST', '/api/admin/admins', payload);
      toast('管理员已创建', 'success');
      $('adminModal').hidden = true;
      loadAdmins();
    } catch (err) {
      showAlert('adminFormAlert', err.message);
    }
  }

  async function deleteAdmin(id) {
    const a = state.admins.find((x) => x.id === id);
    if (!a) return;
    if (!confirm(`确定删除管理员「${a.username}」吗？该账号将立即无法登录。`)) return;
    try {
      await request('DELETE', `/api/admin/admins/${id}`);
      toast('管理员已删除', 'success');
      loadAdmins();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function openResetPwd(id) {
    state.resettingAdminId = id;
    const a = state.admins.find((x) => x.id === id);
    $('resetPwdTitle').textContent = `重置密码 · ${a ? a.username : ''}`;
    $('rf_new').value = '';
    hideAlert('resetPwdAlert');
    $('resetPwdModal').hidden = false;
  }

  async function submitResetPassword(e) {
    e.preventDefault();
    try {
      await request('POST', `/api/admin/admins/${state.resettingAdminId}/reset-password`, {
        newPassword: $('rf_new').value,
      });
      toast('密码已重置，对方下次登录需修改', 'success');
      $('resetPwdModal').hidden = true;
    } catch (err) {
      showAlert('resetPwdAlert', err.message);
    }
  }

  async function submitOwnPassword(e) {
    e.preventDefault();
    hideAlert('pwdAlert');
    const p1 = $('pf_new').value;
    const p2 = $('pf_new2').value;
    if (p1 !== p2) {
      showAlert('pwdAlert', '两次输入的新密码不一致');
      return;
    }
    try {
      await request('POST', '/api/admin/me/password', {
        oldPassword: $('pf_old').value,
        newPassword: p1,
      });
      toast('密码修改成功', 'success');
      $('pwdModal').hidden = true;
      $('mustChangeAlert').hidden = true;
      state.admin.mustChangePassword = false;
    } catch (err) {
      showAlert('pwdAlert', err.message);
    }
  }

  // ---------- 日志 ----------
  async function loadLogs() {
    const q = new URLSearchParams({ page: state.logs.page, pageSize: state.logs.pageSize });
    if (state.logs.action) q.set('action', state.logs.action);
    try {
      const data = await request('GET', '/api/admin/audit-logs?' + q.toString());
      state.logs.total = data.total;
      renderLogs(data.items);
    } catch (err) {
      handleApiError(err);
    }
  }

  function renderLogs(items) {
    const tbody = $('logTbody');
    $('logEmpty').hidden = items.length !== 0;
    tbody.innerHTML = items
      .map((l) => {
        const detail = l.detail ? esc(JSON.stringify(l.detail)) : '';
        const target = l.targetType
          ? `${l.targetType === 'certificate' ? '证书' : '管理员'}:${esc(String(l.targetId).slice(-8))}`
          : '—';
        return `<tr>
          <td>${esc(l.at.replace('T', ' ').slice(0, 19))}</td>
          <td>${esc(l.adminName || '（匿名学员）')}</td>
          <td>${ACTION_LABELS[l.action] || esc(l.action)}</td>
          <td>${target}</td>
          <td>${esc(l.ip || '—')}</td>
          <td><span class="log-detail" title="${detail}">${detail}</span></td>
        </tr>`;
      })
      .join('');
    const { page, pageSize, total } = state.logs;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    $('logPageInfo').textContent = `共 ${total} 条记录`;
    $('logPageNo').textContent = `${page} / ${pages}`;
    $('logPrevBtn').disabled = page <= 1;
    $('logNextBtn').disabled = page >= pages;
  }

  function changeLogPage(delta) {
    const pages = Math.max(1, Math.ceil(state.logs.total / state.logs.pageSize));
    const next = Math.min(Math.max(1, state.logs.page + delta), pages);
    if (next !== state.logs.page) {
      state.logs.page = next;
      loadLogs();
    }
  }

  function handleApiError(err) {
    if (err.status === 401) {
      location.reload();
      return;
    }
    toast(err.message, 'error');
  }

  init();
})();
