'use strict';

// 用法：node src/cli/reset-password.js <账号> [新密码]
// 不提供新密码时随机生成 12 位密码。
const crypto = require('crypto');
const db = require('../db');
const { hashPassword } = require('../auth');

const username = process.argv[2];
let password = process.argv[3];
if (!username) {
  console.error('用法：npm run reset-password -- <账号> [新密码]');
  process.exit(1);
}
const admin = db.findAdminByUsername(username);
if (!admin) {
  console.error(`账号不存在：${username}`);
  process.exit(1);
}
if (!password) {
  password = 'Px' + crypto.randomBytes(7).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 10);
}
if (password.length < 8) {
  console.error('密码至少 8 位');
  process.exit(1);
}

db.updateAdmin(admin.id, { password: hashPassword(password) })
  .then(() =>
    db.addLog({
      actor: 'cli',
      actorName: '命令行工具',
      action: 'admin.reset-password',
      detail: { target: admin.username },
    })
  )
  .then(() => {
    console.log(`已重置账号 ${admin.username} 的密码：${password}`);
    process.exit(0);
  })
  .catch((e) => {
    console.error('重置失败：', e.message);
    process.exit(1);
  });
