'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 数据目录可用 DATA_DIR 覆盖（测试时使用临时目录）
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const EMPTY = { admins: [], certs: [], email_codes: [], audit: [] };

function load() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return Object.assign({}, EMPTY, JSON.parse(raw));
  } catch {
    return Object.assign({}, EMPTY);
  }
}

const data = load();

/** 原子写盘：先写临时文件再 rename */
function save() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

/** 追加审计日志（新记录在前，最多保留 2000 条） */
function audit(action, actor, detail) {
  data.audit.unshift({
    id: crypto.randomBytes(8).toString('hex'),
    at: new Date().toISOString(),
    action,
    actor,
    detail: String(detail || '').slice(0, 500),
  });
  if (data.audit.length > 2000) data.audit.length = 2000;
}

module.exports = { data, save, audit, DB_FILE };
