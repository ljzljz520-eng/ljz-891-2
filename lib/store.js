// JSON 文件持久化层：全量读取到内存，写入时原子替换文件
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { hashPassword } from './security.js';

let dataPath = '';
let db = null;
let saveChain = Promise.resolve();

const DEFAULT_SUPER_ADMIN_USERNAME = 'admin';
const DEFAULT_SUPER_ADMIN_PASSWORD = 'Admin@123456';

function emptyData() {
  return {
    meta: {
      tokenSecret: null, // 首次启动生成，用于签名核验令牌
    },
    admins: [],
    certificates: [],
    emailCodes: [], // 邮箱验证码记录（仅存哈希）
    auditLogs: [],
  };
}

/**
 * 初始化数据存储；首次启动写入默认超级管理员
 */
export async function initStore(filePath) {
  dataPath = filePath;
  await mkdir(path.dirname(filePath), { recursive: true });

  if (existsSync(filePath)) {
    const raw = await readFile(filePath, 'utf8');
    db = JSON.parse(raw);
    // 兼容性补全
    db.meta = db.meta || {};
    db.admins ||= [];
    db.certificates ||= [];
    db.emailCodes ||= [];
    db.auditLogs ||= [];
  } else {
    db = emptyData();
  }

  let firstRun = false;
  let superAdmin = null;
  if (!db.meta.tokenSecret) {
    db.meta.tokenSecret = randomBytes(32).toString('hex');
    firstRun = true;
  }
  if (db.admins.length === 0) {
    const passwordHash = await hashPassword(DEFAULT_SUPER_ADMIN_PASSWORD);
    superAdmin = {
      id: 'adm_' + randomBytes(12).toString('hex'),
      username: DEFAULT_SUPER_ADMIN_USERNAME,
      passwordHash,
      displayName: '超级管理员',
      role: 'super',
      mustChangePassword: true,
      active: true,
      createdAt: new Date().toISOString(),
      createdBy: null,
    };
    db.admins.push(superAdmin);
    firstRun = true;
  }

  // 全新部署时写入示例证书，便于直接体验学员核验页
  if (firstRun && db.certificates.length === 0) {
    const nowIso = new Date().toISOString();
    const fmt = (d) => d.toISOString().slice(0, 10);
    const addDays = (n) => {
      const d = new Date();
      d.setDate(d.getDate() + n);
      return fmt(d);
    };
    const seed = [
      { certNo: 'PX-2026-000127', studentName: '张伟', courseName: '安全生产管理人员培训', institution: '京华职业培训中心', issueDate: '2026-03-15', validUntil: '2027-03-14', contactEmail: 'zhangwei@example.com' },
      { certNo: 'PX-LT-2023-006', studentName: '李娜', courseName: '消防设施操作员（中级）', institution: '京华职业培训中心', issueDate: '2023-09-01', longTerm: true, contactEmail: '' },
      { certNo: 'PX-2025-0088', studentName: '刘洋', courseName: '特种设备安全管理（叉车）', institution: '华北应急安全培训学校', issueDate: addDays(-350), validUntil: addDays(15), contactEmail: '' },
      { certNo: 'PX-2024-0018', studentName: '王强', courseName: '低压电工作业培训', institution: '华北电力培训学校', issueDate: '2024-01-10', validUntil: '2025-01-09', contactEmail: '' },
      { certNo: 'PX-2025-0042', studentName: '陈静', courseName: '场（厂）内专用机动车辆作业', institution: '金蓝领技能培训基地', issueDate: '2025-04-20', validUntil: '2027-04-19', contactEmail: '', revoked: true, revokedReason: '持证人申请注销' },
    ];
    db.certificates = seed.map((s) => ({
      id: 'cer_seed_' + randomBytes(8).toString('hex'),
      longTerm: false,
      contactEmail: '',
      revoked: false,
      revokedReason: '',
      ...s,
      createdBy: superAdmin ? superAdmin.id : null,
      createdAt: nowIso,
      updatedAt: nowIso,
    }));
  }

  await persist();

  return {
    firstRun,
    defaultAdmin: {
      username: DEFAULT_SUPER_ADMIN_USERNAME,
      password: DEFAULT_SUPER_ADMIN_PASSWORD,
    },
  };
}

/** 原子写入：先写临时文件再 rename */
async function persist() {
  const task = async () => {
    const tmp = `${dataPath}.tmp-${process.pid}-${Date.now()}`;
    const content = JSON.stringify(db, null, 2);
    await writeFile(tmp, content, { encoding: 'utf8', mode: 0o600 });
    await rename(tmp, dataPath);
  };
  // 串行化写入，避免并发写覆盖
  saveChain = saveChain.then(task, task);
  return saveChain;
}

// ---------- 元信息 ----------
export function getTokenSecret() {
  return db.meta.tokenSecret;
}

// ---------- 管理员 ----------
export function listAdmins() {
  return db.admins;
}

export function findAdminByUsername(username) {
  const u = String(username || '').trim().toLowerCase();
  return db.admins.find((a) => a.username.toLowerCase() === u) || null;
}

export function findAdminById(id) {
  return db.admins.find((a) => a.id === id) || null;
}

export async function createAdmin(admin) {
  db.admins.push(admin);
  await persist();
  return admin;
}

export async function updateAdmin(id, patch) {
  const admin = findAdminById(id);
  if (!admin) return null;
  Object.assign(admin, patch);
  await persist();
  return admin;
}

export async function deleteAdmin(id) {
  const idx = db.admins.findIndex((a) => a.id === id);
  if (idx === -1) return false;
  db.admins.splice(idx, 1);
  await persist();
  return true;
}

export function countSuperAdmins() {
  return db.admins.filter((a) => a.role === 'super' && a.active).length;
}

// ---------- 证书 ----------
export function listCertificates({ keyword = '', status = '', page = 1, pageSize = 20 } = {}) {
  let items = db.certificates;
  if (keyword) {
    const kw = keyword.toLowerCase();
    items = items.filter(
      (c) =>
        c.certNo.toLowerCase().includes(kw) ||
        c.studentName.toLowerCase().includes(kw) ||
        (c.courseName || '').toLowerCase().includes(kw)
    );
  }
  if (status) {
    items = items.filter((c) => computeStatus(c) === status);
  }
  const total = items.length;
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total };
}

export function findCertificateById(id) {
  return db.certificates.find((c) => c.id === id) || null;
}

/** 按证书编号查找（编号不区分大小写、去空格） */
export function findCertificateByNo(certNo) {
  const no = String(certNo || '').trim().toLowerCase();
  return db.certificates.find((c) => c.certNo.toLowerCase() === no) || null;
}

export async function createCertificate(cert) {
  db.certificates.push(cert);
  await persist();
  return cert;
}

export async function updateCertificate(id, patch) {
  const cert = findCertificateById(id);
  if (!cert) return null;
  Object.assign(cert, patch, { updatedAt: new Date().toISOString() });
  await persist();
  return cert;
}

export async function deleteCertificate(id) {
  const idx = db.certificates.findIndex((c) => c.id === id);
  if (idx === -1) return false;
  db.certificates.splice(idx, 1);
  await persist();
  return true;
}

/**
 * 证书状态（依据吊销标记与有效期动态计算）：
 * revoked 已吊销 / valid 有效 / expiring 即将到期(30天内) / expired 已过期
 */
export function computeStatus(cert, now = Date.now()) {
  if (cert.revoked) return 'revoked';
  if (cert.validUntil) {
    const end = Date.parse(`${cert.validUntil}T23:59:59`);
    if (Number.isFinite(end)) {
      if (end < now) return 'expired';
      if (end - now <= 30 * 24 * 60 * 60 * 1000) return 'expiring';
    }
  }
  return 'valid';
}

// ---------- 邮箱验证码 ----------
export function listEmailCodes() {
  return db.emailCodes;
}

export function findEmailCodeById(id) {
  return db.emailCodes.find((c) => c.id === id) || null;
}

export async function createEmailCode(record) {
  db.emailCodes.push(record);
  await persist();
  return record;
}

export async function updateEmailCode(id, patch) {
  const rec = findEmailCodeById(id);
  if (!rec) return null;
  Object.assign(rec, patch);
  await persist();
  return rec;
}

/** 清理超过保留时长的验证码记录 */
export async function pruneEmailCodes(olderThanMs = 2 * 60 * 60 * 1000) {
  const cutoff = Date.now() - olderThanMs;
  const before = db.emailCodes.length;
  db.emailCodes = db.emailCodes.filter((c) => new Date(c.createdAt).getTime() > cutoff);
  if (db.emailCodes.length !== before) await persist();
}

// ---------- 审计日志 ----------
export async function addAuditLog(entry) {
  db.auditLogs.push(entry);
  // 仅保留最近 5000 条
  if (db.auditLogs.length > 5000) {
    db.auditLogs.splice(0, db.auditLogs.length - 5000);
  }
  await persist();
}

export function listAuditLogs({ page = 1, pageSize = 20, action = '', adminId = '' } = {}) {
  let items = db.auditLogs;
  if (action) items = items.filter((l) => l.action === action);
  if (adminId) items = items.filter((l) => l.adminId === adminId);
  items = [...items].reverse(); // 最新在前
  const total = items.length;
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total };
}
