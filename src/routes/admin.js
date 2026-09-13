'use strict';

const express = require('express');
const db = require('../db');
const { hashPassword, verifyPassword } = require('../auth');
const { certStatus, toAdminView } = require('../cert-util');
const {
  rateLimit,
  requireLogin,
  str,
  isEmail,
  isDate,
  isUsername,
  isCertNo,
  badRequest,
} = require('../middleware');
const config = require('../config');

const router = express.Router();

function currentAdmin(req) {
  return db.getAdmin(req.session.admin.id);
}

function logAs(req, action, detail) {
  const a = currentAdmin(req);
  return db.addLog({
    actor: a ? a.username : req.session.admin.username,
    actorName: a ? a.displayName : req.session.admin.username,
    action,
    detail: detail || {},
  });
}

// ---------- 会话 ----------
router.post(
  '/login',
  rateLimit(config.RATE_LIMITS.loginPerIp),
  (req, res, next) => {
    try {
      const username = str(req.body.username);
      const password = str(req.body.password);
      if (!username || !password) throw badRequest('请输入账号和密码');

      const admin = db.findAdminByUsername(username);
      const ok = admin && admin.active && verifyPassword(password, admin.password);

      db.addLog({
        actor: username,
        actorName: admin ? admin.displayName : username,
        action: ok ? 'login.ok' : 'login.fail',
        detail: ok ? {} : { reason: admin ? (admin.active ? '密码错误' : '账号已停用') : '账号不存在' },
      }).catch(() => {});

      if (!ok) {
        return res.status(401).json({ ok: false, error: '账号或密码错误，或账号已停用' });
      }
      // 登录成功后重新生成会话，防止固定会话攻击
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.admin = { id: admin.id, username: admin.username };
        res.json({
          ok: true,
          admin: { username: admin.username, displayName: admin.displayName },
        });
      });
    } catch (e) {
      next(e);
    }
  }
);

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('sid').json({ ok: true }));
});

router.get('/me', (req, res) => {
  if (!req.session.admin) return res.json({ ok: false });
  const a = db.getAdmin(req.session.admin.id);
  if (!a || !a.active) {
    return req.session.destroy(() => res.json({ ok: false }));
  }
  res.json({ ok: true, admin: db.publicAdmin(a) });
});

router.post(
  '/change-password',
  requireLogin,
  (req, res, next) => {
    try {
      const a = currentAdmin(req);
      const oldPwd = str(req.body.oldPassword);
      const newPwd = str(req.body.newPassword);
      if (!verifyPassword(oldPwd, a.password)) throw badRequest('原密码不正确');
      if (newPwd.length < 8 || newPwd.length > 128) throw badRequest('新密码长度需为 8-128 位');
      if (!/[A-Za-z]/.test(newPwd) || !/\d/.test(newPwd)) {
        throw badRequest('新密码需同时包含字母和数字');
      }
      a.password = hashPassword(newPwd);
      db.updateAdmin(a.id, { password: a.password })
        .then(() => logAs(req, 'admin.change-password', { target: a.username }))
        .catch(() => {});
      res.json({ ok: true, message: '密码修改成功' });
    } catch (e) {
      next(e);
    }
  }
);

// ---------- 证书字段校验 ----------
function readCertBody(req) {
  const body = req.body || {};
  const cert = {
    certNo: str(body.certNo).toUpperCase(),
    studentName: str(body.studentName),
    courseName: str(body.courseName),
    issuedAt: str(body.issuedAt),
    validUntil: str(body.validUntil),
    organization: str(body.organization),
    email: str(body.email).toLowerCase(),
  };
  if (!isCertNo(cert.certNo)) throw badRequest('证书编号需为 3-40 位字母、数字或连字符');
  if (!cert.studentName || cert.studentName.length > 30) throw badRequest('请输入正确的学员姓名（不超过 30 字）');
  if (!cert.courseName || cert.courseName.length > 100) throw badRequest('请输入课程名称（不超过 100 字）');
  if (!isDate(cert.issuedAt)) throw badRequest('发证日期格式应为 YYYY-MM-DD');
  if (!isDate(cert.validUntil)) throw badRequest('有效期截止日期格式应为 YYYY-MM-DD');
  if (cert.validUntil < cert.issuedAt) throw badRequest('有效期截止日期不能早于发证日期');
  if (!cert.organization || cert.organization.length > 100) throw badRequest('请输入培训机构名称（不超过 100 字）');
  if (cert.email && !isEmail(cert.email)) throw badRequest('联系邮箱格式不正确');
  return cert;
}

// GET /api/admin/certificates?q=  列表/搜索
router.get('/certificates', requireLogin, (req, res) => {
  const q = str(req.query.q).toLowerCase();
  let list = db.listCertificates();
  if (q) {
    list = list.filter(
      (c) =>
        c.certNo.toLowerCase().includes(q) ||
        c.studentName.toLowerCase().includes(q) ||
        c.courseName.toLowerCase().includes(q) ||
        c.organization.toLowerCase().includes(q)
    );
  }
  list.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
  res.json({
    ok: true,
    items: list.map(toAdminView),
    total: list.length,
  });
});

// POST /api/admin/certificates  新建
router.post('/certificates', requireLogin, (req, res, next) => {
  try {
    const fields = readCertBody(req);
    if (db.findCertByNo(fields.certNo)) throw badRequest('证书编号已存在，请勿重复录入');
    const cert = Object.assign(
      {
        id: db.nextId('crt'),
        revoked: false,
        revokeReason: '',
        createdAt: db.nowIso(),
        updatedAt: db.nowIso(),
        createdBy: req.session.admin.username,
      },
      fields
    );
    db.insertCertificate(cert)
      .then(() => logAs(req, 'cert.create', { certNo: cert.certNo, studentName: cert.studentName }))
      .catch(() => {});
    res.status(201).json({ ok: true, cert: toAdminView(cert) });
  } catch (e) {
    next(e);
  }
});

// PUT /api/admin/certificates/:id  编辑
router.put('/certificates/:id', requireLogin, (req, res, next) => {
  try {
    const cert = db.getCertificate(req.params.id);
    if (!cert) return res.status(404).json({ ok: false, error: '证书不存在' });
    const fields = readCertBody(req);
    const dup = db.findCertByNo(fields.certNo);
    if (dup && dup.id !== cert.id) throw badRequest('证书编号与其他证书冲突');

    const before = {
      certNo: cert.certNo,
      studentName: cert.studentName,
      courseName: cert.courseName,
      issuedAt: cert.issuedAt,
      validUntil: cert.validUntil,
      organization: cert.organization,
      email: cert.email,
    };
    Object.assign(cert, fields, { updatedAt: db.nowIso() });
    db.saveCertificate(cert)
      .then(() => logAs(req, 'cert.update', { id: cert.id, before, after: fields }))
      .catch(() => {});
    res.json({ ok: true, cert: toAdminView(cert) });
  } catch (e) {
    next(e);
  }
});

// POST /api/admin/certificates/:id/revoke  吊销
router.post('/certificates/:id/revoke', requireLogin, (req, res, next) => {
  try {
    const cert = db.getCertificate(req.params.id);
    if (!cert) return res.status(404).json({ ok: false, error: '证书不存在' });
    const reason = str(req.body.reason);
    if (!reason) throw badRequest('请填写吊销原因');
    cert.revoked = true;
    cert.revokeReason = reason;
    cert.updatedAt = db.nowIso();
    db.saveCertificate(cert)
      .then(() => logAs(req, 'cert.revoke', { certNo: cert.certNo, reason }))
      .catch(() => {});
    res.json({ ok: true, cert: toAdminView(cert) });
  } catch (e) {
    next(e);
  }
});

// POST /api/admin/certificates/:id/restore  恢复
router.post('/certificates/:id/restore', requireLogin, (req, res, next) => {
  try {
    const cert = db.getCertificate(req.params.id);
    if (!cert) return res.status(404).json({ ok: false, error: '证书不存在' });
    const prevReason = cert.revokeReason;
    cert.revoked = false;
    cert.revokeReason = '';
    cert.updatedAt = db.nowIso();
    db.saveCertificate(cert)
      .then(() => logAs(req, 'cert.restore', { certNo: cert.certNo, prevReason }))
      .catch(() => {});
    res.json({ ok: true, cert: toAdminView(cert) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/admin/certificates/:id  误录删除
router.delete('/certificates/:id', requireLogin, (req, res, next) => {
  try {
    const cert = db.getCertificate(req.params.id);
    if (!cert) return res.status(404).json({ ok: false, error: '证书不存在' });
    const all = db.listCertificates();
    const idx = all.findIndex((c) => c.id === cert.id);
    all.splice(idx, 1);
    // 直接替换集合并落盘
    const dbObj = db.load();
    dbObj.certificates = all;
    db.persist()
      .then(() => logAs(req, 'cert.delete', { certNo: cert.certNo, studentName: cert.studentName }))
      .catch(() => {});
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// ---------- 多管理员 ----------
router.get('/admins', requireLogin, (req, res) => {
  const me = currentAdmin(req);
  res.json({
    ok: true,
    items: db.listAdmins().map((a) => Object.assign({}, a, { isSelf: me && a.id === me.id })),
  });
});

router.post('/admins', requireLogin, (req, res, next) => {
  try {
    const username = str(req.body.username);
    const displayName = str(req.body.displayName) || username;
    const password = str(req.body.password);
    if (!isUsername(username)) throw badRequest('账号需为 3-32 位字母、数字或下划线');
    if (displayName.length > 30) throw badRequest('显示名称不超过 30 字');
    if (password.length < 8 || password.length > 128) throw badRequest('初始密码长度需为 8-128 位');
    if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      throw badRequest('密码需同时包含字母和数字');
    }
    if (db.findAdminByUsername(username)) throw badRequest('账号已存在');

    const admin = {
      id: db.nextId('adm'),
      username,
      displayName,
      password: hashPassword(password),
      active: true,
      createdAt: db.nowIso(),
      createdBy: req.session.admin.username,
    };
    db.insertAdmin(admin)
      .then(() => logAs(req, 'admin.create', { target: username }))
      .catch(() => {});
    res.status(201).json({ ok: true, admin: db.publicAdmin(admin) });
  } catch (e) {
    next(e);
  }
});

router.post('/admins/:id/set-active', requireLogin, (req, res, next) => {
  try {
    const target = db.getAdmin(req.params.id);
    if (!target) return res.status(404).json({ ok: false, error: '管理员不存在' });
    const active = Boolean(req.body.active);
    const me = currentAdmin(req);
    if (target.id === me.id) throw badRequest('不能停用自己的账号');
    if (target.active === active) return res.json({ ok: true, admin: db.publicAdmin(target) });

    db.updateAdmin(target.id, { active })
      .then(() =>
        logAs(req, active ? 'admin.enable' : 'admin.disable', { target: target.username })
      )
      .catch(() => {});
    res.json({ ok: true, admin: db.publicAdmin(Object.assign(target, { active })) });
  } catch (e) {
    next(e);
  }
});

router.post('/admins/:id/reset-password', requireLogin, (req, res, next) => {
  try {
    const target = db.getAdmin(req.params.id);
    if (!target) return res.status(404).json({ ok: false, error: '管理员不存在' });
    const password = str(req.body.password);
    if (password.length < 8 || password.length > 128) throw badRequest('新密码长度需为 8-128 位');
    if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      throw badRequest('密码需同时包含字母和数字');
    }
    db.updateAdmin(target.id, { password: hashPassword(password) })
      .then(() => logAs(req, 'admin.reset-password', { target: target.username }))
      .catch(() => {});
    res.json({ ok: true, message: `已重置 ${target.username} 的密码` });
  } catch (e) {
    next(e);
  }
});

// ---------- 审计日志 ----------
router.get('/audit-logs', requireLogin, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  res.json({ ok: true, items: db.listLogs(limit) });
});

// 兼容引用（certStatus 可能用于统计）
router.get('/stats', requireLogin, (req, res) => {
  const certs = db.listCertificates();
  const stats = { total: certs.length, valid: 0, expired: 0, revoked: 0, expireSoon: 0 };
  for (const c of certs) {
    const s = certStatus(c);
    stats[s.code] = (stats[s.code] || 0) + 1;
    if (s.expireSoon) stats.expireSoon += 1;
  }
  stats.admins = db.listAdmins().filter((a) => a.active).length;
  res.json({ ok: true, stats });
});

module.exports = router;
