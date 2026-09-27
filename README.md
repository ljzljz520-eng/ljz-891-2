# 培训证书核验系统

学员证书核验页 + 多管理员后台 + 邮箱验证码更正流程。零外部依赖（Node.js ≥ 18 内置模块），开箱即用。

## 功能

**学员核验页（`/`，无需登录）**
- 输入证书编号 + 姓名，显示：课程名称、发证日期、有效期（至）、培训机构、证书状态（有效 / 已过期 / 已吊销）
- 联系邮箱更正：核验通过后，向新邮箱发送 6 位验证码（10 分钟有效、5 次尝试上限、一次性），验证通过即更新联系邮箱

**管理后台（`/admin`，多管理员）**
- 管理员登录 / 退出（HttpOnly + SameSite Cookie 会话，12 小时滑动过期）
- 证书维护：新增、编辑、吊销 / 恢复、关键字搜索、分页
- 管理员管理：在册管理员可新增管理员、启用 / 禁用（不能禁用自己，至少保留一个可用账号）
- 修改密码、操作日志（登录、证书变更、邮箱更正等全程留痕）

## 快速开始

```bash
npm start          # 默认监听 0.0.0.0:3000
# 打开 http://localhost:3000        学员核验页
# 打开 http://localhost:3000/admin  管理后台
```

首次启动自动写入种子数据：

- 默认管理员：`admin` / `Admin@123456`（可用环境变量 `ADMIN_PASSWORD` 覆盖，请尽快登录后修改）
- 演示证书（可用 `SEED_DEMO=0` 关闭）：

| 证书编号 | 姓名 | 状态 |
|---|---|---|
| `CERT-2025-0001` | 张三 | 有效 |
| `CERT-2024-0002` | 李四 | 已过期 |
| `CERT-XXXX-0003` | 王五 | 已吊销 |

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3000` / `0.0.0.0` | 监听地址 |
| `DATA_DIR` | `./data` | 数据目录（`db.json` 与 `outbox.log`） |
| `NODE_ENV` | development | `production` 时接口不再回传 `dev_code` |
| `ADMIN_PASSWORD` | `Admin@123456` | 首次初始化的管理员密码 |
| `SEED_DEMO` | `1` | 设为 `0` 不写入演示证书 |

## 邮件通道

默认实现（`server/mailer.js`）把邮件追加到 `data/outbox.log`，开发模式下接口同时返回 `dev_code` 便于联调。接入真实 SMTP / 邮件服务商时，只需替换 `sendMail` 实现，业务流程无需改动。

## API 一览

公开接口：
- `POST /api/public/verify` — 证书核验 `{cert_no, name}`
- `POST /api/public/email-change/request` — 发送邮箱更正验证码 `{cert_no, name, new_email}`
- `POST /api/public/email-change/confirm` — 确认更正 `{cert_no, name, new_email, code}`

管理接口（需登录，写操作需 `X-Requested-With: fetch` 头）：
- `POST /api/admin/login` / `POST /api/admin/logout` / `GET /api/admin/me`
- `GET /api/admin/certs?q=&page=` / `POST /api/admin/certs` / `PUT /api/admin/certs/:id`
- `POST /api/admin/certs/:id/revoke` / `POST /api/admin/certs/:id/restore`
- `GET /api/admin/admins` / `POST /api/admin/admins` / `POST /api/admin/admins/:id/toggle`
- `POST /api/admin/password` / `GET /api/admin/audit`

## 安全设计

- 密码 scrypt 加盐哈希，恒定时间比较；验证码仅存 SHA-256 哈希
- 会话 Cookie：HttpOnly + SameSite=Lax；写操作要求自定义头防 CSRF
- 核验、登录、发码接口均有限流；核验失败统一提示，不暴露编号是否存在
- 公开接口邮箱一律打码返回；关键操作写审计日志
- 安全响应头：CSP / X-Frame-Options / nosniff / Referrer-Policy

## 测试

```bash
npm test   # 33 项冒烟测试：核验、邮箱验证码全流程、证书维护、多管理员
```

## 目录结构

```
server/          后端（index.js 路由与 API、db.js JSON 存储、auth.js 会话、mailer.js 邮件、util.js）
public/          前端（verify.html 核验页、admin.html 后台、assets/）
test/smoke.js    冒烟测试
data/            运行时数据（git 忽略）
```
