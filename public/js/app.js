// 学员端：证书核验 + 邮箱更正流程
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const els = {
    form: $('verifyForm'),
    certNo: $('certNo'),
    studentName: $('studentName'),
    verifyBtn: $('verifyBtn'),
    verifyBtnText: $('verifyBtnText'),
    verifyAlert: $('verifyAlert'),
    result: $('result'),
    notMatched: $('notMatched'),
    rCertNo: $('rCertNo'),
    rStatus: $('rStatus'),
    rName: $('rName'),
    rCourse: $('rCourse'),
    rIssue: $('rIssue'),
    rValid: $('rValid'),
    rInstitution: $('rInstitution'),
    rEmail: $('rEmail'),
    reasonRow: $('reasonRow'),
    rReason: $('rReason'),
    changeEmailBtn: $('changeEmailBtn'),
    modal: $('emailModal'),
    modalClose: $('emailModalClose'),
    emailAlert: $('emailAlert'),
    pane1: $('pane1'),
    pane2: $('pane2'),
    pane3: $('pane3'),
    step1: $('step1'),
    step2: $('step2'),
    step3: $('step3'),
    newEmail: $('newEmail'),
    sendCodeBtn: $('sendCodeBtn'),
    sendCodeBtnText: $('sendCodeBtnText'),
    sentEmailText: $('sentEmailText'),
    codeInput: $('codeInput'),
    confirmCodeBtn: $('confirmCodeBtn'),
    confirmCodeBtnText: $('confirmCodeBtnText'),
    resendCodeBtn: $('resendCodeBtn'),
    doneBtn: $('doneBtn'),
    toast: $('toast'),
  };

  const STATUS_TEXT = {
    valid: '证书有效',
    expiring: '即将到期',
    expired: '已过期',
    revoked: '已吊销',
  };

  let session = {
    token: '',
    email: '',
    emailMasked: '',
    cooldownUntil: 0,
    cooldownTimer: null,
  };

  // ---------- 工具 ----------
  function showAlert(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }
  function hideAlert(el) {
    el.hidden = true;
    el.textContent = '';
  }
  let toastTimer = null;
  function toast(msg, type = '') {
    els.toast.textContent = msg;
    els.toast.className = 'toast show ' + type;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      els.toast.className = 'toast ' + type;
    }, 3000);
  }

  async function api(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error('服务器响应异常，请稍后重试');
    }
    if (!res.ok || !data.ok) {
      const err = new Error(data?.error?.message || '请求失败，请稍后重试');
      err.status = res.status;
      err.code = data?.error?.code;
      err.data = data;
      throw err;
    }
    return data;
  }

  function setLoading(btn, textEl, loading, loadingText, normalText) {
    btn.disabled = loading;
    if (loading) {
      btn.innerHTML = '<span class="spinner"></span> ' + loadingText;
    } else {
      textEl ? (textEl.textContent = normalText) : (btn.textContent = normalText);
    }
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );
  }

  function formatDate(v) {
    if (!v) return '';
    return v;
  }

  // ---------- 核验 ----------
  els.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert(els.verifyAlert);
    els.result.hidden = true;
    els.notMatched.hidden = true;

    const certNo = els.certNo.value.trim();
    const studentName = els.studentName.value.trim();
    if (!certNo || !studentName) {
      showAlert(els.verifyAlert, '请输入证书编号和学员姓名');
      return;
    }

    setLoading(els.verifyBtn, null, true, '核验中…', '立即核验');
    try {
      const data = await api('/api/verify', { certNo, studentName });
      if (!data.matched) {
        els.notMatched.hidden = false;
        return;
      }
      renderResult(data);
    } catch (err) {
      showAlert(els.verifyAlert, err.message);
    } finally {
      els.verifyBtn.disabled = false;
      els.verifyBtn.innerHTML = '<span id="verifyBtnText">立即核验</span>';
    }
  });

  function renderResult(data) {
    const c = data.certificate;
    session.token = data.token;
    session.emailMasked = c.contactEmailMasked || '';

    els.rCertNo.textContent = c.certNo;
    els.rName.textContent = c.studentName;
    els.rCourse.textContent = c.courseName;
    els.rIssue.textContent = formatDate(c.issueDate) || '—';
    els.rValid.textContent = c.longTerm ? '长期有效' : formatDate(c.validUntil) || '—';
    els.rInstitution.textContent = c.institution;
    els.rEmail.textContent = c.contactEmailMasked || '暂未登记';

    els.rStatus.textContent = STATUS_TEXT[c.status] || c.status;
    els.rStatus.className = 'badge badge-' + c.status;

    if (c.status === 'revoked' && c.revokedReason) {
      els.reasonRow.hidden = false;
      els.rReason.textContent = '吊销原因：' + c.revokedReason;
    } else {
      els.reasonRow.hidden = true;
    }

    els.result.hidden = false;
  }

  // ---------- 邮箱更正弹窗 ----------
  function openModal() {
    if (!session.token) return;
    els.modal.hidden = false;
    showStep(1);
    hideAlert(els.emailAlert);
    els.newEmail.value = '';
    els.codeInput.value = '';
  }
  function closeModal() {
    els.modal.hidden = true;
    stopCooldown();
  }

  function showStep(n) {
    els.pane1.hidden = n !== 1;
    els.pane2.hidden = n !== 2;
    els.pane3.hidden = n !== 3;
    els.step1.classList.toggle('active', n >= 1);
    els.step2.classList.toggle('active', n >= 2);
    els.step3.classList.toggle('active', n >= 3);
    hideAlert(els.emailAlert);
  }

  els.changeEmailBtn.addEventListener('click', openModal);
  els.modalClose.addEventListener('click', closeModal);
  els.modal.addEventListener('click', (e) => {
    if (e.target === els.modal) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !els.modal.hidden) closeModal();
  });

  // 仅允许输入数字
  els.codeInput.addEventListener('input', () => {
    els.codeInput.value = els.codeInput.value.replace(/\D/g, '').slice(0, 6);
  });

  els.sendCodeBtn.addEventListener('click', sendCode);
  els.resendCodeBtn.addEventListener('click', sendCode);

  async function sendCode() {
    const newEmail = els.newEmail.value.trim();
    if (!newEmail) {
      showAlert(els.emailAlert, '请输入新联系邮箱');
      return;
    }
    hideAlert(els.emailAlert);
    setLoading(els.sendCodeBtn, els.sendCodeBtnText, true, '发送中…', '发送验证码');
    try {
      const data = await api('/api/email/request-code', { token: session.token, newEmail });
      session.email = newEmail;
      els.sentEmailText.textContent = newEmail;
      startCooldown(data.cooldown || 60);
      showStep(2);
      if (data.devCode) {
        toast('开发模式：验证码为 ' + data.devCode, 'success');
      } else {
        toast('验证码已发送，请查收邮件', 'success');
      }
      els.codeInput.focus();
    } catch (err) {
      if (err.code === 'COOLDOWN' && err.data?.retryAfter) {
        startCooldown(err.data.retryAfter);
        showAlert(els.emailAlert, err.message);
      } else {
        showAlert(els.emailAlert, err.message);
      }
    } finally {
      els.sendCodeBtn.disabled = false;
      els.sendCodeBtnText.textContent = '发送验证码';
    }
  }

  function startCooldown(seconds) {
    stopCooldown();
    session.cooldownUntil = Date.now() + seconds * 1000;
    const tick = () => {
      const left = Math.max(0, Math.ceil((session.cooldownUntil - Date.now()) / 1000));
      const label = left > 0 ? `重新发送（${left}s）` : '重新发送验证码';
      els.resendCodeBtn.textContent = label;
      els.resendCodeBtn.disabled = left > 0;
      if (left <= 0) stopCooldown();
    };
    tick();
    session.cooldownTimer = setInterval(tick, 1000);
  }
  function stopCooldown() {
    if (session.cooldownTimer) clearInterval(session.cooldownTimer);
    session.cooldownTimer = null;
    els.resendCodeBtn.textContent = '重新发送验证码';
    els.resendCodeBtn.disabled = false;
  }

  els.confirmCodeBtn.addEventListener('click', async () => {
    const code = els.codeInput.value.trim();
    if (!/^\d{6}$/.test(code)) {
      showAlert(els.emailAlert, '请输入收到的 6 位数字验证码');
      return;
    }
    hideAlert(els.emailAlert);
    setLoading(els.confirmCodeBtn, els.confirmCodeBtnText, true, '提交中…', '确认更正');
    try {
      const data = await api('/api/email/confirm', { token: session.token, code });
      session.emailMasked = data.contactEmailMasked;
      els.rEmail.textContent = data.contactEmailMasked || '暂未登记';
      showStep(3);
      stopCooldown();
    } catch (err) {
      showAlert(els.emailAlert, err.message);
      if (err.code === 'CODE_EXPIRED' || err.code === 'TOO_MANY_ATTEMPTS' || err.code === 'NO_CODE') {
        showStep(1);
      }
    } finally {
      els.confirmCodeBtn.disabled = false;
      els.confirmCodeBtnText.textContent = '确认更正';
    }
  });

  els.doneBtn.addEventListener('click', closeModal);
})();
