'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const config = require('./config');
const db = require('./db');
const publicRoutes = require('./routes/public');
const adminRoutes = require('./routes/admin');

db.load();

const app = express();
app.set('trust proxy', 1);

app.use(express.json({ limit: '100kb' }));
app.use(
  session({
    name: 'sid',
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.isProd, // 生产环境走 HTTPS
      maxAge: 8 * 3600 * 1000, // 8 小时
    },
  })
);

// 静态前端
app.use(express.static(path.join(__dirname, '..', 'public')));

// API
app.use('/api', publicRoutes);
app.use('/api/admin', adminRoutes);

// 统一错误处理
app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) console.error('[error]', err);
  res.status(status).json({ ok: false, error: err.message || '服务器内部错误' });
});

// 前端页面路由回退（GET 非 API 路径交给静态页）
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'admin.html'));
});

app.listen(config.PORT, () => {
  console.log(`培训证书核验平台已启动：http://localhost:${config.PORT}`);
  console.log(`环境：${config.NODE_ENV}；SMTP：${config.smtp ? config.smtp.host : '未配置（开发模式，验证码写入 data/outbox.json）'}`);
});
