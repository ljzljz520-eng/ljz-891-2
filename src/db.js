'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');

const EMPTY_DB = { seq: 0, admins: [], certificates: [], auditLogs: [] };

let data = null;
let writeChain = Promise.resolve();

function load() {
  if (data) return data;
  fs.mkdirSync(config.DATA_DIR, { recursive: true });
  if (fs.existsSync(config.DB_FILE)) {
    const raw = fs.readFileSync(config.DB_FILE, 'utf8');
    data = Object.assign({}, EMPTY_DB, JSON.parse(raw));
  } else {
    data = JSON.parse(JSON.stringify(EMPTY_DB));
  }
  return data;
}

function persist() {
  const snapshot = JSON.stringify(data, null, 2);
  const file = config.DB_FILE;
  // 串行化写入：先写临时文件再原子重命名，避免并发写坏数据
  writeChain = writeChain.then(
    () =>
      new Promise((resolve, reject) => {
        const tmp = path.join(
          config.DATA_DIR,
          `.db.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`
        );
        fs.writeFile(tmp, snapshot, (err) => {
          if (err) return reject(err);
          fs.rename(tmp, file, (err2) => {
            if (err2) fs.unlink(tmp, () => reject(err2));
            else resolve();
          });
        });
      })
  );
  return writeChain;
}

function nextId(prefix) {
  const db = load();
  db.seq += 1;
  return `${prefix}_${String(db.seq).padStart(8, '0')}`;
}

function nowIso() {
  return new Date().toISOString();
}

// ---------- 管理员 ----------
function findAdminByUsername(username) {
  return load().admins.find(
    (a) => a.username.toLowerCase() === String(username || '').trim().toLowerCase()
  );
}
function getAdmin(id) {
  return load().admins.find((a) => a.id === id) || null;
}
function listAdmins() {
  return load().admins.map(publicAdmin);
}
function publicAdmin(a) {
  return {
    id: a.id,
    username: a.username,
    displayName: a.displayName,
    active: a.active,
    createdAt: a.createdAt,
    createdBy: a.createdBy,
  };
}
function insertAdmin(admin) {
  load().admins.push(admin);
  return persist().then(() => admin);
}
function updateAdmin(id, patch) {
  const a = getAdmin(id);
  if (!a) return null;
  Object.assign(a, patch);
  return persist().then(() => a);
}

// ---------- 证书 ----------
function listCertificates() {
  return load().certificates.slice();
}
function getCertificate(id) {
  return load().certificates.find((c) => c.id === id) || null;
}
function findCertificate(certNo, studentName) {
  const no = String(certNo || '').trim().toLowerCase();
  const name = String(studentName || '').trim();
  return (
    load().certificates.find(
      (c) => c.certNo.toLowerCase() === no && c.studentName === name
    ) || null
  );
}
function findCertByNo(certNo) {
  const no = String(certNo || '').trim().toLowerCase();
  return load().certificates.find((c) => c.certNo.toLowerCase() === no) || null;
}
function insertCertificate(cert) {
  load().certificates.push(cert);
  return persist().then(() => cert);
}
function saveCertificate(cert) {
  return persist().then(() => cert);
}

// ---------- 审计日志 ----------
function addLog(entry) {
  const log = { id: nextId('log'), at: nowIso(), detail: {}, ...entry };
  load().auditLogs.push(log);
  // 日志只保留最近 5000 条
  const db = load();
  if (db.auditLogs.length > 5000) {
    db.auditLogs = db.auditLogs.slice(-5000);
  }
  return persist().then(() => log);
}
function listLogs(limit = 200) {
  return load().auditLogs.slice(-Number(limit)).reverse();
}

module.exports = {
  load,
  persist,
  nextId,
  nowIso,
  findAdminByUsername,
  getAdmin,
  listAdmins,
  publicAdmin,
  insertAdmin,
  updateAdmin,
  listCertificates,
  getCertificate,
  findCertificate,
  findCertByNo,
  insertCertificate,
  saveCertificate,
  addLog,
  listLogs,
};
