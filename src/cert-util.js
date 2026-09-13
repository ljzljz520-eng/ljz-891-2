'use strict';

// 证书状态：revoked 优先；其次按有效期日期（YYYY-MM-DD）判断
function certStatus(cert, now = new Date()) {
  if (cert.revoked) {
    return { code: 'revoked', label: '已吊销', reason: cert.revokeReason || '' };
  }
  if (cert.validUntil) {
    const end = new Date(`${cert.validUntil}T23:59:59+08:00`);
    if (!Number.isNaN(end.getTime())) {
      if (now.getTime() > end.getTime()) {
        return { code: 'expired', label: '已过期' };
      }
      // 90 天内到期给出提醒（不改变有效状态）
      const days = Math.ceil((end.getTime() - now.getTime()) / 86400000);
      if (days <= 90) return { code: 'valid', label: '有效', expireSoon: true, daysLeft: days };
    }
  }
  return { code: 'valid', label: '有效' };
}

// 对外展示的证书信息（不含内部 id 等）
function toPublicView(cert) {
  const status = certStatus(cert);
  return {
    certNo: cert.certNo,
    studentName: cert.studentName,
    courseName: cert.courseName,
    issuedAt: cert.issuedAt,
    validUntil: cert.validUntil,
    organization: cert.organization,
    status,
    hasEmail: Boolean(cert.email),
  };
}

// 后台列表用（含邮箱）
function toAdminView(cert) {
  return Object.assign({}, cert, { status: certStatus(cert) });
}

function maskEmail(email) {
  if (!email) return '';
  const [user, domain] = email.split('@');
  if (!domain) return email;
  if (user.length <= 1) return `${user}***@${domain}`;
  if (user.length === 2) return `${user[0]}***@${domain}`;
  return `${user.slice(0, 2)}${'*'.repeat(Math.min(4, user.length - 2))}@${domain}`;
}

module.exports = { certStatus, toPublicView, toAdminView, maskEmail };
