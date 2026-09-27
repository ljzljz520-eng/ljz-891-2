'use strict';

const $ = (sel) => document.querySelector(sel);

const state = { cert: null };

async function api(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

function showError(msg) {
  const el = $('#verify-error');
  el.textContent = msg;
  el.hidden = !msg;
}

function showEcMsg(msg, isError) {
  const el = $('#ec-msg');
  el.textContent = msg;
  el.hidden = !msg;
  el.className = 'alert ' + (isError ? 'alert-error' : 'alert-ok');
}

function badgeClass(status) {
  if (status === '有效') return 'badge badge-ok';
  if (status === '已过期') return 'badge badge-warn';
  return 'badge badge-bad';
}

function renderCert(cert) {
  state.cert = cert;
  $('#result').hidden = false;
  const badge = $('#status-badge');
  badge.textContent = cert.status;
  badge.className = badgeClass(cert.status);
  $('#f-course').textContent = cert.course_name;
  $('#f-issue').textContent = cert.issue_date;
  $('#f-valid').textContent = cert.valid_until;
  $('#f-org').textContent = cert.org;
  $('#f-no').textContent = cert.cert_no;
  $('#f-name').textContent = cert.name;
  $('#f-email').textContent = cert.contact_email_masked || '（未登记）';
  $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('#verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  $('#result').hidden = true;
  state.cert = null;
  const fd = new FormData(e.target);
  const btn = $('#verify-btn');
  btn.disabled = true;
  try {
    const { status, json } = await api('/api/public/verify', {
      cert_no: fd.get('cert_no').trim(),
      name: fd.get('name').trim(),
    });
    if (!json.ok) {
      showError(json.error || `查询失败（${status}）`);
      return;
    }
    renderCert(json.cert);
  } catch {
    showError('网络异常，请稍后再试');
  } finally {
    btn.disabled = false;
  }
});

let countdownTimer = null;
function startCountdown(btn, seconds) {
  let left = seconds;
  btn.disabled = true;
  btn.textContent = `${left}s 后重发`;
  countdownTimer = setInterval(() => {
    left -= 1;
    if (left <= 0) {
      clearInterval(countdownTimer);
      btn.disabled = false;
      btn.textContent = '发送验证码';
    } else {
      btn.textContent = `${left}s 后重发`;
    }
  }, 1000);
}

$('#send-code').addEventListener('click', async (e) => {
  const btn = e.target;
  showEcMsg('');
  if (!state.cert) {
    showEcMsg('请先完成证书核验', true);
    return;
  }
  const newEmail = $('#ec-form').elements.new_email.value.trim();
  if (!newEmail) {
    showEcMsg('请先填写新邮箱', true);
    return;
  }
  btn.disabled = true;
  try {
    const { json } = await api('/api/public/email-change/request', {
      cert_no: state.cert.cert_no,
      name: state.cert.name,
      new_email: newEmail,
    });
    if (!json.ok) {
      showEcMsg(json.error || '发送失败', true);
      btn.disabled = false;
      return;
    }
    let msg = json.message || '验证码已发送';
    if (json.dev_code) msg += `（演示模式验证码：${json.dev_code}）`;
    showEcMsg(msg, false);
    startCountdown(btn, 60);
  } catch {
    showEcMsg('网络异常，请稍后再试', true);
    btn.disabled = false;
  }
});

$('#ec-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showEcMsg('');
  if (!state.cert) {
    showEcMsg('请先完成证书核验', true);
    return;
  }
  const fd = new FormData(e.target);
  try {
    const { json } = await api('/api/public/email-change/confirm', {
      cert_no: state.cert.cert_no,
      name: state.cert.name,
      new_email: fd.get('new_email').trim(),
      code: fd.get('code').trim(),
    });
    if (!json.ok) {
      showEcMsg(json.error || '更正失败', true);
      return;
    }
    showEcMsg(json.message || '联系邮箱已更正', false);
    e.target.reset();
    // 重新核验一次，刷新页面上的邮箱打码信息
    const { json: v } = await api('/api/public/verify', { cert_no: state.cert.cert_no, name: state.cert.name });
    if (v.ok) renderCert(v.cert);
  } catch {
    showEcMsg('网络异常，请稍后再试', true);
  }
});
