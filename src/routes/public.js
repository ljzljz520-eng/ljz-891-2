'use strict';

const express = require('express');
const db = require('../db');
const codes = require('../codes');
const { toPublicView, maskEmail } = require('../cert-util');
const {
  rateLimit,
  str,
  isEmail,
  isCertNo,
  badRequest,
} = require('../middleware');
const config = require('../config');

const router = express.Router();

// POST /api/verify  学员输入证书编号 + 姓名核验
router.post(
  '/verify',
  rateLimit(config.RATE_LIMITS.verifyPerIp),
  (req, res, next) => {
    try {
      const certNo = str(req.body.certNo);
      const studentName = str(req.body.studentName);
      if (!isCertNo(certNo)) throw badRequest('请输入正确的证书编号（3-40 位字母、数字或连字符）');
      if (!studentName || studentName.length > 30) throw badRequest('请输入正确的姓名');

      const cert = db.findCertificate(certNo, studentName);
      db.addLog({
        actor: 'public',
        actorName: '公众核验',
        action: 'cert.verify',
        detail: { certNo, studentName, hit: Boolean(cert) },
      }).catch(() => {});

      if (!cert) {
        // 不区分“编号不存在”和“姓名不匹配”，避免被枚举
        return res.json({ ok: false, error: '未查询到匹配的证书，请核对证书编号与姓名' });
      }

      const view = toPublicView(cert);
      // 仅返回脱敏邮箱，供页面判断“是否可发起更正”
      view.maskedEmail = maskEmail(cert.email);
      // 用于后续邮箱更正流程的临时凭证（会话内）
      req.session.pendingChange = {
        certId: cert.id,
        certNo: cert.certNo,
        studentName: cert.studentName,
      };
      res.json({ ok: true, cert: view });
    } catch (e) {
      next(e);
    }
  }
);

// 确保发起更正前已通过一次核验
function requireVerifiedSession(req) {
  const p = req.session && req.session.pendingChange;
  if (!p) {
    const err = new Error('请先完成证书核验，再申请更正邮箱');
    err.status = 403;
    throw err;
  }
  const cert = db.getCertificate(p.certId);
  if (!cert || cert.certNo !== p.certNo || cert.studentName !== p.studentName) {
    const err = new Error('核验信息已失效，请重新核验');
    err.status = 403;
    throw err;
  }
  return cert;
}

// POST /api/change-email/request-code  向新邮箱发送验证码
router.post(
  '/change-email/request-code',
  rateLimit(config.RATE_LIMITS.codeSendPerIp),
  async (req, res, next) => {
    try {
      const cert = requireVerifiedSession(req);
      if (cert.revoked) throw badRequest('该证书已被吊销，无法更正联系邮箱');

      const newEmail = str(req.body.newEmail).toLowerCase();
      if (!isEmail(newEmail)) throw badRequest('请输入正确的新邮箱地址');
      if (cert.email && newEmail === cert.email.toLowerCase()) {
        throw badRequest('新邮箱与当前登记邮箱一致，无需更正');
      }

      const result = await codes.sendChangeCode(cert, newEmail);

      db.addLog({
        actor: 'public',
        actorName: cert.studentName,
        action: 'email.change.request',
        detail: { certNo: cert.certNo, newEmail, delivered: result.delivered },
      }).catch(() => {});

      res.json({
        ok: true,
        message: result.delivered
          ? `验证码已发送至 ${newEmail}，请查收`
          : '验证码已生成（开发模式，未真正发送邮件）',
        ttlMinutes: Math.round(config.CODE_TTL_MS / 60000),
        resendAfterSeconds: Math.round(config.CODE_RESEND_MS / 1000),
        // 开发环境直接回显，方便无 SMTP 下联调；生产环境不返回
        devCode: !config.isProd ? result.devPayload && result.devPayload.code : undefined,
      });
    } catch (e) {
      next(e);
    }
  }
);

// POST /api/change-email/confirm  校验验证码并更新邮箱
router.post(
  '/change-email/confirm',
  rateLimit(config.RATE_LIMITS.verifyPerIp),
  (req, res, next) => {
    try {
      const cert = requireVerifiedSession(req);
      const newEmail = str(req.body.newEmail).toLowerCase();
      const code = str(req.body.code);
      if (!isEmail(newEmail)) throw badRequest('请输入正确的新邮箱地址');
      if (!/^\d{6}$/.test(code)) throw badRequest('请输入 6 位邮箱验证码');

      const v = codes.verifyChangeCode(cert.id, newEmail, code);
      if (!v.ok) {
        db.addLog({
          actor: 'public',
          actorName: cert.studentName,
          action: 'email.change.fail',
          detail: { certNo: cert.certNo, reason: v.reason },
        }).catch(() => {});
        return res.json({ ok: false, error: v.reason });
      }

      const oldEmail = cert.email || '';
      cert.email = newEmail;
      cert.updatedAt = db.nowIso();
      db.saveCertificate(cert)
        .then(() =>
          db.addLog({
            actor: 'public',
            actorName: cert.studentName,
            action: 'email.change.ok',
            detail: { certNo: cert.certNo, oldEmail, newEmail },
          })
        )
        .catch(() => {});

      // 更正完成，清理临时凭证
      delete req.session.pendingChange;
      req.session.save(() => {
        res.json({
          ok: true,
          message: '联系邮箱更正成功',
          maskedEmail: maskEmail(newEmail),
        });
      });
    } catch (e) {
      next(e);
    }
  }
);

module.exports = router;
