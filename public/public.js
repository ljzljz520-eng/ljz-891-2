'use strict';

const $ = (id) => document.getElementById(id);

function showAlert(el, type, msg) {
  el.className = `alert alert-${type} show`;
  el.textContent = msg;
}
function hideAlert(el) {
  el.className = 'alert';
  el.textContent = '';
}

async function api(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  let data;
  try {
    data = await resp.json();
  } catch (_) {
    throw new Error('服务器响应异常，请稍后重试');
  }
  if (!resp.ok && !data.error) throw new Error(`请求失败（${resp.status}）`);
  return data;
}

let lastCert = null;

// ---------- 核验 ----------
$('verifyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert($('verifyAlert'));
  $('resultCard').classList.add('hidden');
  const btn = $('verifyBtn');
  btn.disabled = true;
  btn.textContent = '核验中…';
  try {
    const data = await api('/api/verify', {
      certNo: $('certNo').value.trim(),
      studentName: $('studentName').value.trim(),
    });
    if (!data.ok) {
      showAlert($('verifyAlert'), 'error', data.error);
      return;
    }
    lastCert = data.cert;
    renderCert(data.cert);
  } catch (err) {
    showAlert($('verifyAlert'), 'error', err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '立即核验';
  }
});

function renderCert(c) {
  const set = (id, v) => { $(id).textContent = v || '—'; };
  set('rName', c.studentName);
  set('rNo', c.certNo);
  set('rCourse', c.courseName);
  set('rIssued', c.issuedAt);
  set('rValid', c.validUntil);
  set('rOrg', c.organization);

  const badge = $('statusBadge');
  badge.textContent = c.status.label;
  badge.className = `badge badge-${c.status.code}`;

  let note = '';
  if (c.status.code === 'revoked') {
    note = `该证书已被吊销。${c.status.reason ? '吊销原因：' + c.status.reason : ''}`;
  } else if (c.status.code === 'expired') {
    note = '该证书已超过有效期。';
  } else if (c.status.expireSoon) {
    note = `该证书有效，将于 ${c.status.daysLeft} 天后到期，请留意续期。`;
  } else {
    note = '该证书真实有效。';
  }
  $('statusNote').textContent = note;

  $('rEmail').textContent = c.maskedEmail ? c.maskedEmail : '（未登记）';
  $('openChangeBtn').disabled = c.status.code === 'revoked';
  $('resultCard').classList.remove('hidden');
}

// ---------- 邮箱更正 ----------
const modal = $('changeModal');
let cooldownTimer = null;

$('openChangeBtn').addEventListener('click', () => {
  if (!lastCert) return;
  $('newEmail').value = '';
  $('code').value = '';
  $('codeHint').textContent = '';
  hideAlert($('changeAlert'));
  resetSendBtn();
  modal.classList.add('show');
});
$('cancelChangeBtn').addEventListener('click', () => modal.classList.remove('show'));
modal.addEventListener('click', (e) => {
  if (e.target === modal) modal.classList.remove('show');
});

function resetSendBtn(remain) {
  const btn = $('sendCodeBtn');
  if (remain && remain > 0) {
    btn.disabled = true;
    btn.textContent = `${remain}s 后重发`;
  } else {
    btn.disabled = false;
    btn.textContent = '发送验证码';
  }
}

function startCooldown(seconds) {
  let remain = seconds;
  resetSendBtn(remain);
  clearInterval(cooldownTimer);
  cooldownTimer = setInterval(() => {
    remain -= 1;
    if (remain <= 0) {
      clearInterval(cooldownTimer);
      resetSendBtn();
    } else {
      resetSendBtn(remain);
    }
  }, 1000);
}

$('sendCodeBtn').addEventListener('click', async () => {
  hideAlert($('changeAlert'));
  const newEmail = $('newEmail').value.trim();
  if (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(newEmail)) {
    return showAlert($('changeAlert'), 'error', '请输入正确的新邮箱地址');
  }
  const btn = $('sendCodeBtn');
  btn.disabled = true;
  btn.textContent = '发送中…';
  try {
    const data = await api('/api/change-email/request-code', { newEmail });
    if (!data.ok) {
      showAlert($('changeAlert'), 'error', data.error);
      resetSendBtn();
      return;
    }
    showAlert(
      $('changeAlert'),
      'success',
      data.message + (data.devCode ? `（开发模式验证码：${data.devCode}）` : '')
    );
    $('codeHint').textContent =
      `验证码 ${data.ttlMinutes} 分钟内有效；如未收到，请在 ${data.resendAfterSeconds} 秒后重新发送。`;
    startCooldown(data.resendAfterSeconds);
  } catch (err) {
    showAlert($('changeAlert'), 'error', err.message);
    resetSendBtn();
  }
});

$('confirmChangeBtn').addEventListener('click', async () => {
  hideAlert($('changeAlert'));
  const newEmail = $('newEmail').value.trim();
  const code = $('code').value.trim();
  if (!newEmail) return showAlert($('changeAlert'), 'error', '请输入新邮箱');
  if (!/^\d{6}$/.test(code)) return showAlert($('changeAlert'), 'error', '请输入 6 位数字验证码');

  const btn = $('confirmChangeBtn');
  btn.disabled = true;
  btn.textContent = '提交中…';
  try {
    const data = await api('/api/change-email/confirm', { newEmail, code });
    if (!data.ok) {
      showAlert($('changeAlert'), 'error', data.error);
      return;
    }
    modal.classList.remove('show');
    if (lastCert) lastCert.maskedEmail = data.maskedEmail;
    $('rEmail').textContent = data.maskedEmail || '（未登记）';
    showAlert($('verifyAlert'), 'success', data.message);
    $('verifyAlert').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (err) {
    showAlert($('changeAlert'), 'error', err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '确认更正';
  }
});
