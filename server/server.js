'use strict';
/* =====================================================================
 *  VPN 权限管控平台 —— 后端服务
 *
 *  安全设计
 *   ① 服务端强制鉴权：每个接口校验会话 + 模块级 r/rw 权限（前端判断只作展示）
 *   ② 口令：scrypt(N=16384) + 每用户随机盐 + 恒定时间比较 + 复杂度策略
 *   ③ 会话：服务端存储可吊销；HttpOnly + SameSite=Strict；绝对超时 + 空闲超时
 *   ④ 登录风控：同 IP+账号失败计数，达阈值锁定 15 分钟
 *   ⑤ SQL：全部参数化；输入统一类型/长度校验
 *   ⑥ 审计：所有写操作记录操作人、动作、对象、IP
 *   ⑦ CSRF：写请求必须带 X-Requested-With + SameSite=Strict
 * ===================================================================== */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const express = require('express');
const A = require('./auth.js');
const D = require('./dialects');          // 数据库方言（DB_DRIVER=mysql|sqlite）

const app = express();
const PORT = Number(process.env.PORT || 8787);
const ROOT = path.join(__dirname, '..');

/* ---------------- 数据库（方言层：mysql | sqlite） ----------------
 * 连接池/文件句柄、错误标记(dbDown)、SQL 方言差异全部封装在 dialects/ 下，
 * 业务代码只依赖 q / q1 / qv / D.run / D.sql.* ，不出现任何库专有语法。 */
const q  = (s, p) => D.all(s, p);                                  // 读取（SELECT）
const q1 = (s, p) => D.get(s, p);
const qv = (s, p) => D.scalar(s, p);
const db = { run: (s, p) => D.run(s, p), get: (s, p) => D.get(s, p), all: (s, p) => D.all(s, p) };

/* ---------------- 中间件 ---------------- */
app.disable('x-powered-by');
/* 头像上传以 base64 传入；前端已压缩到 256×256 JPEG（仅数十 KB），
   故将本路由 JSON 上限设为 2MB（远小于原 5MB），既留足余量又收紧限制。 */
app.use('/api/me/avatar', express.json({ limit: '2mb' }));
app.use(express.json({ limit: '128kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
  next();
});
app.use(express.static(ROOT, { index: 'index.html', maxAge: 0 }));
app.set('trust proxy', 1);

/* 头像上传目录（校验后才写入，仅允许 png/jpg/webp） */
const UPLOAD_DIR = path.join(__dirname, 'uploads', 'avatars');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads/avatars', express.static(UPLOAD_DIR, {
  maxAge: '7d',
  setHeaders: res => { res.setHeader('X-Content-Type-Options', 'nosniff'); },
}));
const ipOf = r => (r.headers['x-forwarded-for'] || '').split(',')[0].trim() || r.ip || '';

/* CSRF：写请求必须带自定义头（登录与网关推送除外） */
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) &&
      !/^\/api\/(auth\/login|ingest)/.test(req.path)) {
    if (req.headers['x-requested-with'] !== 'fetch')
      return res.status(400).json({ error: '缺少安全请求头' });
  }
  next();
});

/* ---------------- 权限模型 ---------------- */
const MODULES = ['account', 'dest', 'vpn', 'audit'];
const PERMS = ['none', 'r', 'rw'];
const permOf = u => ({ account: u.perm_account, dest: u.perm_dest, vpn: u.perm_vpn, audit: u.perm_audit });
const canView = (u, m) => !!u && (u.role === 'admin' || permOf(u)[m] !== 'none');
const canEdit = (u, m) => !!u && (u.role === 'admin' || permOf(u)[m] === 'rw');

function tokenOf(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)vpn_sid=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}
async function attach(req, _res, next) { req.user = await A.loadSession(D, tokenOf(req)); next(); }
function auth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '会话已失效，请重新登录' });
  next();
}
function need(mod, level) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: '会话已失效，请重新登录' });
    if (!(level === 'rw' ? canEdit(req.user, mod) : canView(req.user, mod))) {
      audit(req, '越权访问被拒绝', mod).catch(() => {});
      return res.status(403).json({ error: '权限不足' });
    }
    next();
  };
}
async function audit(req, act, target) {
  try {
    await q(`INSERT INTO audit_log (ts, actor, action, target, ip) VALUES (${D.sql.now3},?,?,?,?)`,
      [req.user ? req.user.name : 'anonymous', String(act).slice(0, 64),
       String(target == null ? '' : target).slice(0, 255), ipOf(req)]);
  } catch { /* 审计失败不阻断业务 */ }
}
const str = (v, n = 128) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
const bad = (res, m) => res.status(400).json({ error: m });
const normPerm = v => (PERMS.includes(v) ? v : 'none');

/* =====================================================================
 *  健康检查（前端据此切换真实模式 / 演示模式）
 * ===================================================================== */
app.get('/api/health', async (_req, res) => {
  try { await q('SELECT 1'); res.json({ ok: true, mode: 'server' }); }
  catch (e) { res.status(503).json({ ok: false, mode: 'server', error: String(e.message || e) }); }
});

/* Express 4 不会捕获 async 路由抛出的 rejection —— 请求会永久挂起（客户端只看到转圈）。
 * 所有不带 attach 的 async 路由都必须用它包一层。 */
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* =====================================================================
 *  认证
 * ===================================================================== */
/* 首次部署检测：admin 账号存在但口令未设置时，前端显示「设置初始口令」页。 */
app.get('/api/auth/setup-status', asyncHandler(async (_req, res) => {
  const row = await q1(`SELECT id FROM sys_account
    WHERE login='admin' AND (pwd_hash IS NULL OR pwd_hash='')`);
  res.json({ needSetup: !!row });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const login = str(req.body.login, 64);
  const pwd = typeof req.body.password === 'string' ? req.body.password : '';
  if (!login || !pwd) return bad(res, '请输入账号与密码');

  const ip = ipOf(req);
  const acct = await q1(`SELECT * FROM sys_account WHERE login=?`, [login]);
  // 管理员账号不参与失败锁定（避免被锁在门外）；失败仍会记录 login_fail 审计
  if (acct && acct.role !== 'admin' && acct.locked_until && new Date(acct.locked_until) > new Date())
    return res.status(423).json({ error: '账号已锁定，请稍后再试或联系管理员' });
  // 口令未设置（首次部署未配 ADMIN_INIT_PWD）时给出明确指引，而不是笼统的「密码错误」
  if (acct && !acct.pwd_hash)
    return res.status(409).json({ error: '初始口令尚未设置，请刷新页面完成设置' });

  if (!acct || acct.status !== 1 || !A.pwdVerify(pwd, acct.pwd_hash, acct.pwd_salt)) {
    if (acct) {
      const admin = acct.role === 'admin';        // 管理员账号不参与失败锁定
      if (!admin) {
        const n = (acct.failed_attempts || 0) + 1;
        await q(`UPDATE sys_account SET failed_attempts=? ${n >= 5 ? `, locked_until=${D.sql.plusMinutes('15')}` : ''} WHERE id=?`, [n, acct.id]);
        if (n >= 5) return res.status(429).json({ error: '失败次数过多，账号已锁定 15 分钟' });
      }
      await q(`INSERT INTO login_fail (ts, login, ip, reason) VALUES (${D.sql.now3},?,?,?)`, [login, ip, 'password']).catch(() => {});
    }
    return res.status(401).json({ error: '账号或密码错误' });
  }

  const token = await A.createSession(D, acct.id, ip, req.headers['user-agent']);
  await q(`UPDATE sys_account SET failed_attempts=0, locked_until=NULL,
           last_login_at=${D.sql.now3}, last_login_ip=? WHERE id=?`, [ip, acct.id]);
  await audit({ user: acct, headers: req.headers }, '登录系统', '-');
  res.setHeader('Set-Cookie', `vpn_sid=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${A.SESSION_HOURS * 3600}${process.env.COOKIE_SECURE === '1' ? '; Secure' : ''}`);
  res.json({ ok: true, mustChangePwd: !!acct.must_change_pwd });
}));

/* 首次设置 admin 口令。仅在口令尚未设置时有效；成功后直接建立会话，免去再登录一次。
 * 用条件 UPDATE（WHERE 口令为空）保证并发或重放时只有一个请求能生效。 */
app.post('/api/auth/setup', asyncHandler(async (req, res) => {
  const pwd = typeof req.body.password === 'string' ? req.body.password : '';
  const policyErr = A.pwdPolicy(pwd);
  if (policyErr) return bad(res, policyErr);

  const ip = ipOf(req);
  const { hash, salt } = A.pwdHash(pwd);
  const r = await D.run(`UPDATE sys_account SET pwd_hash=?, pwd_salt=?, must_change_pwd=0,
      failed_attempts=0, locked_until=NULL
    WHERE login='admin' AND (pwd_hash IS NULL OR pwd_hash='')`, [hash, salt]);
  if (!r.changes) return res.status(409).json({ error: '初始口令已设置，请直接登录' });

  const acct = await q1(`SELECT * FROM sys_account WHERE login='admin'`);
  await audit({ user: acct, headers: req.headers }, '设置初始管理员口令', 'admin');
  const token = await A.createSession(D, acct.id, ip, req.headers['user-agent']);
  await q(`UPDATE sys_account SET last_login_at=${D.sql.now3}, last_login_ip=? WHERE id=?`, [ip, acct.id]);
  res.setHeader('Set-Cookie', `vpn_sid=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${A.SESSION_HOURS * 3600}${process.env.COOKIE_SECURE === '1' ? '; Secure' : ''}`);
  res.json({ ok: true });
}));

app.post('/api/auth/logout', attach, async (req, res) => {
  await A.destroySession(D, tokenOf(req));
  await audit(req, '退出系统', '-').catch(() => {});
  res.setHeader('Set-Cookie', 'vpn_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/auth/me', attach, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: '未登录' });
  res.json({ id: req.user.id, name: req.user.name, login: req.user.login, role: req.user.role,
    perm: permOf(req.user), mustChangePwd: !!req.user.must_change_pwd });
});

app.post('/api/auth/password', attach, auth, async (req, res) => {
  const a = await q1(`SELECT * FROM sys_account WHERE id=?`, [req.user.id]);
  if (!A.pwdVerify(String(req.body.old || ''), a.pwd_hash, a.pwd_salt)) return bad(res, '原密码不正确');
  const m = A.pwdPolicy(String(req.body.next || ''));
  if (m) return bad(res, m);
  const { hash, salt } = A.pwdHash(String(req.body.next));
  await q(`UPDATE sys_account SET pwd_hash=?, pwd_salt=?, must_change_pwd=0 WHERE id=?`, [hash, salt, a.id]);
  await audit(req, '修改本人密码', '-');
  res.json({ ok: true });
});

/* 头像上传：校验 MIME / 体积 / 文件头魔数后才落盘 */
app.post('/api/me/avatar', attach, auth, async (req, res) => {
  const m = String(req.body.data || '').match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/);
  if (!m) return bad(res, '仅支持 PNG / JPEG / WebP 图片');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 2 * 1024 * 1024) return bad(res, '图片不能超过 2MB');
  const okSig =
    (m[1] === 'png'  && buf.slice(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))) ||
    (m[1] === 'jpeg' && buf[0] === 0xff && buf[1] === 0xd8 && buf[buf.length-2] === 0xff && buf[buf.length-1] === 0xd9) ||
    (m[1] === 'webp' && buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP');
  if (!okSig) return bad(res, '文件内容与声明类型不符');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const name = crypto.randomBytes(12).toString('hex') + '.' + ext;
  fs.writeFileSync(path.join(UPLOAD_DIR, name), buf, { mode: 0o644 });
  await q(`UPDATE sys_account SET avatar=? WHERE id=?`, [name, req.user.id]);
  await audit(req, '更换头像', '-');
  res.json({ ok: true, avatar: `/uploads/avatars/${name}` });
});

/* =====================================================================
 *  聚合状态
 * ===================================================================== */
app.get('/api/state', attach, auth, async (req, res) => {
  const out = { me: { id: req.user.id, name: req.user.name, login: req.user.login, role: req.user.role,
    avatar: req.user.avatar ? `/uploads/avatars/${req.user.avatar}` : null,
    perm: permOf(req.user), mustChangePwd: !!req.user.must_change_pwd } };
  if (canView(req.user, 'account'))
    out.accounts = await q(`SELECT id, login, name, role, perm_account, perm_dest, perm_vpn, perm_audit,
      status, last_login_at, last_login_ip, created_at FROM sys_account ORDER BY id`);
  if (canView(req.user, 'dest')) {
    out.pools = await q(`SELECT id, name, ip, port, proto, descr FROM dest_pool ORDER BY id`);
    const ks = await q(`SELECT id, name, descr FROM dest_package ORDER BY id`);
    for (const k of ks)
      k.poolIds = (await q(`SELECT pool_id FROM dest_package_item WHERE package_id=?`, [k.id])).map(r => r.pool_id);
    out.packages = ks;
  }
  if (canView(req.user, 'vpn')) {
    const vs = await q(`SELECT id, name, vpn_ip, note, status, mode, created_at FROM vpn_account ORDER BY id`);
    for (const v of vs)
      v.grants = (await q(`SELECT kind, ref_id FROM vpn_grant WHERE vpn_id=?`, [v.id])).map(g => ({ t: g.kind, id: g.ref_id }));
    out.vpn = vs;
  }
  res.json(out);
});

/* =====================================================================
 *  账号管理
 * ===================================================================== */
app.post('/api/accounts', attach, need('account', 'rw'), async (req, res) => {
  const login = str(req.body.login, 64), name = str(req.body.name, 64), role = str(req.body.role, 16);
  if (!login || !name) return bad(res, '登录账号与姓名必填');
  if (!['sec', 'op', 'custom'].includes(role)) return bad(res, '角色非法');
  const m = A.pwdPolicy(String(req.body.password || ''));
  if (m) return bad(res, m);
  if (await q1(`SELECT id FROM sys_account WHERE login=?`, [login])) return bad(res, '登录账号已存在');
  const { hash, salt } = A.pwdHash(String(req.body.password));
  const r = await D.run(`INSERT INTO sys_account (login, name, pwd_hash, pwd_salt, role,
      perm_account, perm_dest, perm_vpn, perm_audit, status, must_change_pwd)
    VALUES (?,?,?,?,?,?,?,?,?,?,1)`,
    [login, name, hash, salt, role, normPerm(req.body.perm_account), normPerm(req.body.perm_dest),
     normPerm(req.body.perm_vpn), normPerm(req.body.perm_audit), req.body.status === 0 ? 0 : 1]);
  await audit(req, '新增管理员账号', `${name}(${login})`);
  res.json({ ok: true, id: r.id });
});

app.put('/api/accounts/:id', attach, need('account', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  const t = await q1(`SELECT * FROM sys_account WHERE id=?`, [id]);
  if (!t) return res.status(404).json({ error: '账号不存在' });
  if (t.role === 'admin' && t.id !== req.user.id) return bad(res, '不能修改其他超级管理员');
  await q(`UPDATE sys_account SET name=?, login=?, role=?, perm_account=?, perm_dest=?, perm_vpn=?, perm_audit=?, status=? WHERE id=?`,
    [str(req.body.name, 64) || t.name, str(req.body.login, 64) || t.login, str(req.body.role, 16) || t.role,
     normPerm(req.body.perm_account), normPerm(req.body.perm_dest), normPerm(req.body.perm_vpn),
     normPerm(req.body.perm_audit), req.body.status === 0 ? 0 : 1, id]);
  await audit(req, '修改账号权限', `${t.name}(${t.login})`);
  res.json({ ok: true });
});

app.delete('/api/accounts/:id', attach, need('account', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return bad(res, '不能删除自己');
  const t = await q1(`SELECT * FROM sys_account WHERE id=?`, [id]);
  if (!t) return res.status(404).json({ error: '账号不存在' });
  if (t.role === 'admin') return bad(res, '超级管理员不可删除');
  await q(`DELETE FROM sys_account WHERE id=?`, [id]);
  await audit(req, '删除管理员账号', `${t.name}(${t.login})`);
  res.json({ ok: true });
});

app.post('/api/accounts/:id/password', attach, need('account', 'rw'), async (req, res) => {
  const m = A.pwdPolicy(String(req.body.password || ''));
  if (m) return bad(res, m);
  const { hash, salt } = A.pwdHash(String(req.body.password));
  const id = Number(req.params.id);
  await q(`UPDATE sys_account SET pwd_hash=?, pwd_salt=?, must_change_pwd=1,
           failed_attempts=0, locked_until=NULL WHERE id=?`, [hash, salt, id]);
  const t = await q1(`SELECT name FROM sys_account WHERE id=?`, [id]);
  await audit(req, '重置账号密码', t ? t.name : id);
  res.json({ ok: true });
});

/* =====================================================================
 *  目的地池 / 目的地包
 * ===================================================================== */
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/* 端口规格解析（存 VARCHAR）：支持中英文逗号分隔、单端口与区间，可混用。
   例：'' -> ''（全部端口）；'80' -> '80'；'100-200' -> '100-200'；
       '9，100-200' / '9,100-200' -> '9,100-200'。
   返回 { spec, error }；spec='' 表示「全部端口」。 */
function parsePorts(raw) {
  const s = String(raw == null ? '' : raw).replace(/[，、]/g, ',').trim();
  if (!s) return { spec: '' };                                   // 留空 = 全部端口
  const parts = s.split(',').map(x => x.trim()).filter(Boolean);
  if (!parts.length) return { spec: '' };
  if (parts.length > 64) return { error: '端口条目过多（最多 64 段）' };
  const out = [];
  for (const p of parts) {
    const single = p.match(/^(\d{1,5})$/);
    const range  = p.match(/^(\d{1,5})\s*-\s*(\d{1,5})$/);
    if (single) {
      const a = Number(single[1]);
      if (a < 1 || a > 65535) return { error: `端口需在 1-65535 之间：${p}` };
      out.push(String(a));
    } else if (range) {
      const a = Number(range[1]), b = Number(range[2]);
      if (a < 1 || a > 65535 || b < 1 || b > 65535) return { error: `端口需在 1-65535 之间：${p}` };
      if (a > b) return { error: `端口区间起止颠倒：${p}（应写成 小-大，如 100-200）` };
      out.push(`${a}-${b}`);
    } else {
      return { error: `端口格式不正确：${p}（应为 80、100-200，或它们的逗号组合）` };
    }
  }
  return { spec: [...new Set(out)].join(',') };                   // 去重并保持顺序
}

app.post('/api/pools', attach, need('dest', 'rw'), async (req, res) => {
  const name = str(req.body.name, 64), ip = str(req.body.ip, 45);
  const proto = req.body.proto === 'UDP' ? 'UDP' : 'TCP';
  const pr = parsePorts(req.body.port);
  if (pr.error) return bad(res, pr.error);
  if (!name || !ip) return bad(res, '名称与 IP 必填');
  if (!IP_RE.test(ip)) return bad(res, 'IP 格式不正确');
  try {
    const r = await D.run(`INSERT INTO dest_pool (name, ip, port, proto, descr) VALUES (?,?,?,?,?)`,
      [name, ip, pr.spec, proto, str(req.body.descr, 128) || null]);
    await audit(req, '新增 IP-端口', `${name} ${ip}:${pr.spec || '全部端口'}`);
    res.json({ ok: true, id: r.id });
  } catch (e) {
    if (D.isDup(e)) return bad(res, '该 IP:端口:协议 组合已存在');
    throw e;
  }
});
app.put('/api/pools/:id', attach, need('dest', 'rw'), async (req, res) => {
  const name = str(req.body.name, 64), ip = str(req.body.ip, 45);
  const pr = parsePorts(req.body.port);
  if (pr.error) return bad(res, pr.error);
  if (!name || !ip) return bad(res, '名称与 IP 必填');
  if (!IP_RE.test(ip)) return bad(res, 'IP 格式不正确');
  try {
    await q(`UPDATE dest_pool SET name=?, ip=?, port=?, proto=?, descr=? WHERE id=?`,
      [name, ip, pr.spec, req.body.proto === 'UDP' ? 'UDP' : 'TCP',
       str(req.body.descr, 128) || null, Number(req.params.id)]);
  } catch (e) {
    if (D.isDup(e)) return bad(res, '该 IP:端口:协议 组合已存在');
    throw e;
  }
  await audit(req, '修改 IP-端口', `${name} ${ip}:${pr.spec || '全部端口'}`);
  res.json({ ok: true });
});
app.delete('/api/pools/:id', attach, need('dest', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  const t = await q1(`SELECT name FROM dest_pool WHERE id=?`, [id]);
  await q(`DELETE FROM dest_pool WHERE id=?`, [id]);   // 外键级联清理包内条目与授权
  await audit(req, '删除 IP-端口', t ? t.name : id);
  res.json({ ok: true });
});

async function setItems(pkgId, ids) {
  await q(`DELETE FROM dest_package_item WHERE package_id=?`, [pkgId]);
  for (const raw of (Array.isArray(ids) ? ids : [])) {
    const pid = Number(raw);
    if (!Number.isInteger(pid)) continue;
    if (await q1(`SELECT id FROM dest_pool WHERE id=?`, [pid]))
      await q(`${D.insertIgnore} INTO dest_package_item (package_id, pool_id) VALUES (?,?)`, [pkgId, pid]);
  }
}
app.post('/api/packages', attach, need('dest', 'rw'), async (req, res) => {
  const name = str(req.body.name, 64);
  if (!name) return bad(res, '包名称必填');
  const r = await D.run(`INSERT INTO dest_package (name, descr) VALUES (?,?)`, [name, str(req.body.descr, 128) || null]);
  await setItems(r.id, req.body.poolIds);
  await audit(req, '新增目的地包', name);
  res.json({ ok: true, id: r.id });
});
app.put('/api/packages/:id', attach, need('dest', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  await q(`UPDATE dest_package SET name=?, descr=? WHERE id=?`,
    [str(req.body.name, 64), str(req.body.descr, 128) || null, id]);
  await setItems(id, req.body.poolIds);
  await audit(req, '修改目的地包', str(req.body.name, 64));
  res.json({ ok: true });
});
app.delete('/api/packages/:id', attach, need('dest', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  await q(`DELETE FROM vpn_grant WHERE kind='pkg' AND ref_id=?`, [id]);
  const t = await q1(`SELECT name FROM dest_package WHERE id=?`, [id]);
  await q(`DELETE FROM dest_package WHERE id=?`, [id]);
  await audit(req, '删除目的地包', t ? t.name : id);
  res.json({ ok: true });
});

/* =====================================================================
 *  WireGuard 密钥与 peer 管理
 *  - 密钥由平台生成（标准 X25519，与 wg genkey 等价），私钥 AES-256-GCM 加密落库
 *  - 两种落地模式（WG_MODE）：
 *      agent（默认）：网关上 vpn-sync 拉 /api/gateway/peers 自行落地，Web 无需特权
 *      local        ：平台就在网关本机，直接写 wg0.conf 并 wg syncconf（需 root）
 * ===================================================================== */
const WG_MARK_BEG = '# >>> vpn-ctrl managed';
const WG_MARK_END = '# <<< vpn-ctrl managed';
const KEYFILE = path.join(__dirname, '.wgkey');

/** 主密钥：优先环境变量；否则用 .wgkey（首次生成，600 权限）派生 */
function masterKey() {
  if (process.env.WG_KEY_SECRET)
    return crypto.scryptSync(process.env.WG_KEY_SECRET, 'vpn-wg-key-v1', 32);
  if (!fs.existsSync(KEYFILE))
    fs.writeFileSync(KEYFILE, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
  return crypto.scryptSync(fs.readFileSync(KEYFILE, 'utf8').trim(), 'vpn-wg-key-v1', 32);
}
function encKey(s) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ct = Buffer.concat([c.update(String(s), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decKey(s) {
  try {
    const b = Buffer.from(String(s), 'base64'), k = masterKey();
    const d = crypto.createDecipheriv('aes-256-gcm', k, b.slice(0, 12));
    d.setAuthTag(b.slice(12, 28));
    return Buffer.concat([d.update(b.slice(28)), d.final()]).toString('utf8');
  } catch { return null; }
}
/** 生成 WireGuard 密钥对（Curve25519，32 字节原始密钥 base64） */
function wgKeygen() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'der' }).slice(-32).toString('base64'),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32).toString('base64'),
  };
}
const isLocal = () => String(process.env.WG_MODE || 'agent').toLowerCase() === 'local';
const wgConfPath = () => process.env.WG_CONF || '/etc/wireguard/wg0.conf';
const wgIface = () => process.env.WG_IFACE || 'wg0';

async function peerRows() {
  return q(`SELECT name, vpn_ip, pubkey FROM vpn_account
    WHERE status=1 AND pubkey IS NOT NULL AND pubkey<>'' ORDER BY id`);
}
const renderPeers = vs => vs.map(v =>
  `# ${v.name} ${v.vpn_ip}\n[Peer]\nPublicKey = ${v.pubkey}\nAllowedIPs = ${v.vpn_ip}/32`).join('\n\n');

/** 同机模式：把托管块写回 wg0.conf 并热加载（数组传参，不经 shell，防注入） */
async function applyLocal() {
  const conf = wgConfPath(), iface = wgIface();
  const vs = await peerRows();
  const block = `${WG_MARK_BEG}\n${renderPeers(vs)}\n${WG_MARK_END}`;
  let cur = fs.existsSync(conf) ? fs.readFileSync(conf, 'utf8') : '';
  const re = new RegExp(`${WG_MARK_BEG}[\\s\\S]*?${WG_MARK_END}`);
  cur = re.test(cur) ? cur.replace(re, block) : (cur.replace(/\s+$/, '') + '\n\n' + block + '\n');
  fs.writeFileSync(conf, cur, { mode: 0o600 });
  const stripped = execFileSync('wg-quick', ['strip', iface], { encoding: 'utf8' });
  execFileSync('wg', ['syncconf', iface, '/dev/stdin'], { input: stripped });
  return vs.length;
}
/** 变更后按需落地；失败不阻断业务，仅记录 */
async function syncPeers(req) {
  if (!isLocal()) return;
  try { const n = await applyLocal(); await audit(req, '同步 WireGuard peer', `${n} 个`); }
  catch (e) { console.error('[WG] local apply failed:', e.message); }
}
function serverPub() {
  if (process.env.WG_SERVER_PUB) return process.env.WG_SERVER_PUB.trim();
  const p = path.join(path.dirname(wgConfPath()), 'server.pub');
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim();
  return '';
}

/* =====================================================================
 *  VPN 账号与授权
 * ===================================================================== */
app.post('/api/vpn', attach, need('vpn', 'rw'), async (req, res) => {
  const name = str(req.body.name, 64);
  if (!name) return bad(res, '真实姓名必填');
  let ip = str(req.body.vpn_ip, 45);
  if (ip && !IP_RE.test(ip)) return bad(res, 'IP 格式不正确');
  if (!ip) {
    const used = (await q(`SELECT vpn_ip FROM vpn_account`)).map(r => Number(String(r.vpn_ip).split('.')[3]) || 0);
    ip = '10.100.0.' + ((used.length ? Math.max(...used) : 10) + 1);
  }
  const { priv, pub } = wgKeygen();
  try {
    const r = await D.run(`INSERT INTO vpn_account (name, vpn_ip, note, pubkey, privkey) VALUES (?,?,?,?,?)`,
      [name, ip, str(req.body.note, 128) || null, pub, encKey(priv)]);
    await audit(req, '新增 VPN 用户', `${name} ${ip}（默认空权限，已生成密钥）`);
    await syncPeers(req);
    res.json({ ok: true, id: r.id, vpn_ip: ip, pubkey: pub });
  } catch (e) {
    if (D.isDup(e)) return bad(res, '该姓名或 IP 已存在');
    throw e;
  }
});
app.put('/api/vpn/:id', attach, need('vpn', 'rw'), async (req, res) => {
  await q(`UPDATE vpn_account SET name=?, note=?, status=? WHERE id=?`,
    [str(req.body.name, 64), str(req.body.note, 128) || null, req.body.status === 0 ? 0 : 1, Number(req.params.id)]);
  await audit(req, '修改 VPN 用户', str(req.body.name, 64));
  res.json({ ok: true });
});
app.delete('/api/vpn/:id', attach, need('vpn', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  const t = await q1(`SELECT name FROM vpn_account WHERE id=?`, [id]);
  await q(`DELETE FROM vpn_account WHERE id=?`, [id]);
  await audit(req, '删除 VPN 用户', t ? t.name : id);
  await syncPeers(req);
  res.json({ ok: true });
});
app.get('/api/gateway/peers', asyncHandler(async (req, res) => {
  if (process.env.INGEST_TOKEN && req.headers['x-ingest-token'] !== process.env.INGEST_TOKEN)
    return res.status(401).json({ error: 'invalid token' });
  res.json({ peers: await peerRows() });
}));
/* 汇总某用户被授权的目标 IP（/32），用于客户端 AllowedIPs 自动路由。
   复用与 /api/gateway/grants 相同的 pool/pkg 展开逻辑。 */
async function grantedDestIps(vpnId) {
  const gs = await q(`SELECT kind, ref_id FROM vpn_grant WHERE vpn_id=?`, [vpnId]);
  const ips = new Set();
  for (const g of gs) {
    if (g.kind === 'pool') {
      const p = await q1(`SELECT ip FROM dest_pool WHERE id=?`, [g.ref_id]);
      if (p && p.ip) ips.add(p.ip);
    } else {
      const items = await q(`SELECT pool_id FROM dest_package_item WHERE package_id=?`, [g.ref_id]);
      for (const it of items) {
        const p = await q1(`SELECT ip FROM dest_pool WHERE id=?`, [it.pool_id]);
        if (p && p.ip) ips.add(p.ip);
      }
    }
  }
  return [...ips];
}

app.get('/api/vpn/:id/conf', attach, need('vpn', 'r'), async (req, res) => {
  const v = await q1(`SELECT name, vpn_ip, privkey, mode FROM vpn_account WHERE id=?`, [Number(req.params.id)]);
  if (!v) return res.status(404).json({ error: '用户不存在' });
  const priv = v.privkey ? decKey(v.privkey) : null;
  const pub = serverPub();
  const ep = process.env.WG_ENDPOINT || '';
  if (!priv || !pub || !ep)
    return res.status(400).json({ error: '缺少配置要素：请设置 WG_ENDPOINT 与网关公钥（WG_SERVER_PUB 或 server.pub），且该用户已有密钥' });
  const mode = v.mode === 'deny' ? 'deny' : 'allow';
  const allowParts = [];
  for (const p of String(process.env.WG_CLIENT_ALLOWED || '10.100.0.0/24, 10.0.0.0/8').split(',')) {
    const t = p.trim(); if (t) allowParts.push(t);
  }
  if (mode === 'deny') {
    // 黑名单模式：默认放行全部网段（全量走隧道），仅网关侧 deny 列表被禁止。
    allowParts.push('0.0.0.0/0');
  } else {
    // AllowedIPs = env 基础路由 + 该用户被授权的目标 IP(/32)。
    // 这样在网页授权某内网目标后，客户端会自动把该目标路由进隧道，
    // 不再需要手动在 WG_CLIENT_ALLOWED 里列出所有内网段（否则跨子网目标连不通）。
    for (const ip of await grantedDestIps(Number(req.params.id))) allowParts.push(ip + '/32');
  }
  const _seen = new Set(); const allowIps = [];
  for (const x of allowParts) { if (!_seen.has(x)) { _seen.add(x); allowIps.push(x); } }

  const conf = `[Interface]
PrivateKey = ${priv}
Address = ${v.vpn_ip}/24
MTU = ${process.env.WG_CLIENT_MTU || 1280}
${process.env.WG_CLIENT_DNS ? `DNS = ${process.env.WG_CLIENT_DNS}\n` : ''}
[Peer]
PublicKey = ${pub}
Endpoint = ${ep}
AllowedIPs = ${allowIps.join(', ')}
PersistentKeepalive = 25
`;
  res.json({ name: v.name, vpn_ip: v.vpn_ip, conf });
});
app.put('/api/vpn/:id/grants', attach, need('vpn', 'rw'), async (req, res) => {
  const id = Number(req.params.id);
  if (!(await q1(`SELECT id FROM vpn_account WHERE id=?`, [id])))
    return res.status(404).json({ error: '用户不存在' });
  // 模式：allow（白名单，默认）/ deny（黑名单）。前端勾选的目的地在 deny 模式下即为「禁止访问」例外。
  const mode = req.body.mode === 'deny' ? 'deny' : 'allow';
  await q(`UPDATE vpn_account SET mode=? WHERE id=?`, [mode, id]);
  await q(`DELETE FROM vpn_grant WHERE vpn_id=?`, [id]);
  for (const g of (Array.isArray(req.body.grants) ? req.body.grants : [])) {
    if (g.t !== 'pool' && g.t !== 'pkg') continue;
    const refId = Number(g.id);
    if (!Number.isInteger(refId)) continue;
    const exists = g.t === 'pool'
      ? await q1(`SELECT id FROM dest_pool WHERE id=?`, [refId])
      : await q1(`SELECT id FROM dest_package WHERE id=?`, [refId]);
    if (exists) await q(`${D.insertIgnore} INTO vpn_grant (vpn_id, kind, ref_id) VALUES (?,?,?)`, [id, g.t, refId]);
  }
  const t = await q1(`SELECT name FROM vpn_account WHERE id=?`, [id]);
  await audit(req, mode === 'deny' ? '启用黑名单模式' : '授权目的地',
    `${t ? t.name : id} → 模式=${mode}，${(req.body.grants || []).length} 项目的地`);
  res.json({ ok: true });
});

/* =====================================================================
 *  访问日志 / 审计 / 统计
 * ===================================================================== */
app.get('/api/logs', attach, need('audit', 'r'), async (req, res) => {
  const w = [], p = [];
  const { name, dst, port, act, days } = req.query;
  if (name) { w.push('user_name LIKE ?'); p.push('%' + str(name, 64) + '%'); }
  if (dst)  { w.push('dst_ip LIKE ?');    p.push('%' + str(dst, 45) + '%'); }
  if (port) { w.push('dst_port = ?');     p.push(Number(port)); }
  if (act === 'ALLOW' || act === 'DENY') { w.push('action = ?'); p.push(act); }
  if (days) { w.push(`ts >= ${D.sql.daysAgo('?')}`); p.push(Number(days) || 1); }
  res.json({ rows: await q(`SELECT ts, user_name, src_ip, dst_ip, dst_port, proto, action
    FROM access_log ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY ts DESC LIMIT 500`, p) });
});

app.get('/api/logs/export', attach, need('audit', 'r'), async (_req, res) => {
  const rows = await q(`SELECT ts, user_name, src_ip, dst_ip, dst_port, proto, action
    FROM access_log ORDER BY ts DESC LIMIT 20000`);
  const csv = ['时间,姓名,来源IP,目标IP,端口,协议,结果'].concat(rows.map(r =>
    [r.ts, r.user_name, r.src_ip, r.dst_ip, r.dst_port, r.proto, r.action].join(','))).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="vpn-access.csv"');
  res.send('\ufeff' + csv);
});

app.get('/api/audit', attach, need('audit', 'r'), async (_req, res) => {
  res.json({ rows: await q(`SELECT ts, actor, action, target, ip FROM audit_log ORDER BY ts DESC LIMIT 500`) });
});

app.get('/api/stats', attach, need('audit', 'r'), async (_req, res) => {
  res.json({
    today:  await qv(`SELECT COUNT(*) FROM access_log WHERE ts >= ${D.sql.todayStart}`),
    week:   await qv(`SELECT COUNT(*) FROM access_log WHERE ts >= ${D.sql.daysAgo('7')}`),
    denied: await qv(`SELECT COUNT(*) FROM access_log WHERE action='DENY'`),
    active: await qv(`SELECT COUNT(DISTINCT user_name) FROM access_log WHERE ts >= ${D.sql.daysAgo('7')}`),
  });
});

/* 网关同步：拉取"有效授权清单"（生产用独立 token，与 ingest 同一套凭据）
   返回每个 VPN 用户的固定内网 IP 与其被允许的目的地，供网关侧 agent 渲染 nftables 规则 */
app.get('/api/gateway/grants', asyncHandler(async (req, res) => {
  if (process.env.INGEST_TOKEN && req.headers['x-ingest-token'] !== process.env.INGEST_TOKEN)
    return res.status(401).json({ error: 'invalid token' });
  const vs = await q(`SELECT id, name, vpn_ip, mode FROM vpn_account WHERE status=1 ORDER BY id`);
  const out = [];
  for (const v of vs) {
    const mode = v.mode === 'deny' ? 'deny' : 'allow';
    const gs = await q(`SELECT kind, ref_id FROM vpn_grant WHERE vpn_id=?`, [v.id]);
    const allow = [], deny = [], seen = new Set();
    const push = (arr, p) => {
      if (!p) return;
      const ports = p.port == null ? '' : String(p.port);   // '' = 全部端口；否则形如 '9,100-200'
      const k = `${p.ip}:${ports}:${p.proto}`;
      if (seen.has(k)) return;
      seen.add(k);
      arr.push({ ip: p.ip, ports, proto: p.proto });
    };
    for (const g of gs) {
      // deny 模式下：勾选的目的地进入 deny（禁止）清单；allow 模式下进入 allow（放行）清单
      const arr = mode === 'deny' ? deny : allow;
      if (g.kind === 'pool') {
        push(arr, await q1(`SELECT ip, port, proto FROM dest_pool WHERE id=?`, [g.ref_id]));
      } else {
        const items = await q(`SELECT pool_id FROM dest_package_item WHERE package_id=?`, [g.ref_id]);
        for (const it of items)
          push(arr, await q1(`SELECT ip, port, proto FROM dest_pool WHERE id=?`, [it.pool_id]));
      }
    }
    out.push({ vpn_ip: v.vpn_ip, name: v.name, mode, allow, deny });
  }
  res.json({ users: out });
}));

/* 网关采集器推送日志（生产用独立 token） */
app.post('/api/ingest', asyncHandler(async (req, res) => {
  if (process.env.INGEST_TOKEN && req.headers['x-ingest-token'] !== process.env.INGEST_TOKEN)
    return res.status(401).json({ error: 'invalid token' });
  const rows = Array.isArray(req.body) ? req.body : [req.body];
  for (const r of rows) {
    const v = r.user_name ? await q1(`SELECT id FROM vpn_account WHERE name=?`, [str(r.user_name, 64)]) : null;
    await q(`INSERT INTO access_log (ts, vpn_id, user_name, src_ip, dst_ip, dst_port, proto, action)
      VALUES (?,?,?,?,?,?,?,?)`,
      [r.ts || new Date().toISOString().slice(0, 19).replace('T', ' '), v ? v.id : null,
       str(r.user_name, 64) || null, str(r.src_ip, 45), str(r.dst_ip, 45),
       Number(r.dst_port) || 0, str(r.proto, 8) || 'TCP', r.action === 'DENY' ? 'DENY' : 'ALLOW']);
  }
  res.json({ ok: true, n: rows.length });
}));

/* =====================================================================
 *  错误处理
 * ===================================================================== */
app.use((err, _req, res, _next) => {
  console.error('[ERR]', err && err.message ? err.message : err);
  if (err && err.dbDown) return res.status(503).json({ error: '数据库暂时不可用' });
  res.status(500).json({ error: '服务器内部错误' });   // 不回显细节
});

/* 最后一道网：即使有未捕获的异步异常，也只记日志、不退出进程。
 * 管控平台的可用性与"网关规则是否被正确下发"直接相关，不能被单个请求打挂。 */
process.on('unhandledRejection', e => {
  console.error('[FATAL-GUARD] unhandledRejection:', e && e.message ? e.message : e);
});
process.on('uncaughtException', e => {
  console.error('[FATAL-GUARD] uncaughtException:', e && e.message ? e.message : e);
});

/* =====================================================================
 *  初始化
 * ===================================================================== */
async function initDb() {
  await D.initSchema();                     // 方言各自建表：schema.sql / schema.sqlite.sql
  console.log(`[init] 表结构已就绪（${D.name}）`);
  try {
    const cols = await D.columns('vpn_account');
    if (!cols.includes('pubkey'))  await D.run(`ALTER TABLE vpn_account ADD COLUMN pubkey  VARCHAR(64)  NULL`);
    if (!cols.includes('privkey')) await D.run(`ALTER TABLE vpn_account ADD COLUMN privkey VARCHAR(255) NULL`);
    if (!cols.includes('mode'))    await D.run(`ALTER TABLE vpn_account ADD COLUMN mode VARCHAR(8) NOT NULL DEFAULT 'allow'`);
  } catch (e) { console.error('[WARN] 字段迁移失败：', e.message); }
  /* 不设任何固定默认口令。未配置 ADMIN_INIT_PWD 时，admin 以「口令未设置」状态创建
     （pwd_hash 存空串），首次打开平台会引导在网页上设置口令。
     这样既避免"源码公开 ⇒ 后台口令公开"，也避免初始口令出现在日志/终端历史里。 */
  const PWD = process.env.ADMIN_INIT_PWD || '';
  const mk = async (login, name, role, pa, pd, pv, pu) => {
    if (await q1(`SELECT id FROM sys_account WHERE login=?`, [login])) return;
    const { hash, salt } = PWD ? A.pwdHash(PWD) : { hash: '', salt: '' };
    await q(`INSERT INTO sys_account (login, name, pwd_hash, pwd_salt, role,
      perm_account, perm_dest, perm_vpn, perm_audit, must_change_pwd)
      VALUES (?,?,?,?,?,?,?,?,?,?)`, [login, name, hash, salt, role, pa, pd, pv, pu, PWD ? 0 : 1]);
  };
  await mk('admin', '系统管理员', 'admin', 'rw', 'rw', 'rw', 'rw');
  console.log(PWD
    ? '[init] 管理员账号已就绪（口令取自 .env 的 ADMIN_INIT_PWD）'
    : '[init] admin 口令未设置 —— 请打开平台首页完成初始口令设置（仅首次）');
  /* 演示账号只在 SEED_DEMO=1 时创建：默认多出 3 个账号（其中 1 个是管理员角色）
     在真实环境里是无意义的额外入口，不该随初始化产生。 */
  if (process.env.SEED_DEMO === '1') {
    await mk('zhangwei', '张伟', 'admin', 'rw', 'rw', 'rw', 'rw');
    await mk('lijing', '李静', 'sec', 'r', 'r', 'r', 'r');
    await mk('wangqiang', '王强', 'op', 'none', 'r', 'rw', 'r');
    console.log('[init] 演示账号已创建（SEED_DEMO=1）：zhangwei / lijing / wangqiang');
  }

  if (process.env.SEED_DEMO !== '1') return;
  if ((await qv(`SELECT COUNT(*) FROM dest_pool`)) > 0) { console.log('[init] 演示数据已存在，跳过'); return; }

  const pools = [['业务-Web-01','10.0.10.5',443,'TCP','业务系统前端'],['业务-Web-02','10.0.10.6',443,'TCP','前端备'],
    ['业务-后台','10.0.10.7',8080,'TCP','运营管理后台'],['数据库-MySQL','10.0.20.5',3306,'TCP','主库'],
    ['数据库-Redis','10.0.20.6',6379,'TCP','缓存'],['运维-RDP-01','10.0.10.20',3389,'TCP','Windows 跳板'],
    ['运维-RDP-02','10.0.10.21',3389,'TCP','应用服务器'],['堡垒机','10.0.30.10',443,'TCP','JumpServer'],
    ['SSH-跳板','10.0.30.11',22,'TCP','Linux 跳板机'],['内网DNS','10.0.0.2',53,'UDP','域名解析']];
  const ids = {};
  for (const [name, ip, port, proto, d] of pools) {
    const r = await D.run(`INSERT INTO dest_pool (name, ip, port, proto, descr) VALUES (?,?,?,?,?)`, [name, ip, String(port), proto, d]);
    ids[name] = r.id;
  }
  const pkgMap = { '研发常用': ['业务-Web-01','业务-Web-02','业务-后台','数据库-MySQL'],
    '运维必备': ['运维-RDP-01','运维-RDP-02','SSH-跳板','堡垒机'], '只读审计': ['堡垒机'] };
  const pkgIds = {};
  for (const [n, list] of Object.entries(pkgMap)) {
    const r = await D.run(`INSERT INTO dest_package (name, descr) VALUES (?,?)`, [n, '演示数据']);
    pkgIds[n] = r.id;
    await setItems(r.id, list.map(x => ids[x]));
  }
  const users = [['陈晓明','10.100.0.11','研发部',[['pkg','研发常用'],['pool','内网DNS']]],
    ['刘芳','10.100.0.12','运维部',[['pkg','运维必备'],['pkg','只读审计']]],
    ['赵磊','10.100.0.13','研发部',[['pool','SSH-跳板']]],['孙丽','10.100.0.14','市场部',[]],
    ['周鹏','10.100.0.15','运维部',[['pkg','运维必备']]],['吴敏','10.100.0.16','财务部',[]]];
  for (const [name, ip, note, grants] of users) {
    const r = await D.run(`INSERT INTO vpn_account (name, vpn_ip, note) VALUES (?,?,?)`, [name, ip, note]);
    for (const [t, key] of grants) {
      const refId = t === 'pkg' ? pkgIds[key] : ids[key];
      if (refId) await q(`INSERT INTO vpn_grant (vpn_id, kind, ref_id) VALUES (?,?,?)`, [r.id, t, refId]);
    }
  }
  /* 注意：演示模式只写入「配置类」数据（目的地池 / 包 / 账号 / 授权），
     不写入 access_log 审计行。审计表必须只反映真实网关回传的流日志，
     伪造审计记录会直接破坏「可溯源」这一核心承诺。若需在真机验证流级审计，
     请改用仓库 verify/ 目录下的端到端方案，而不是用假数据填充审计表。 */
}

(async () => {
  if (process.argv.includes('--init')) { await initDb(); process.exit(0); }
  try { await q('SELECT 1'); }
  catch (e) {
    console.error(`[WARN] 数据库（${D.name}）不可用：`, e.message,
      '\n       前端会提示「无法连接后端服务」；解决后执行 npm run init 并重启');
  }
  setInterval(() => A.sweepSessions(D).catch(() => {}), 3600_000).unref();
  app.listen(PORT, () => {
    console.log(`[ok] 后端已启动  http://127.0.0.1:${PORT}   （DB: ${D.name}${D.file ? ' · ' + D.file : ''}）`);
    console.log(`[ok] 会话策略：绝对 ${A.SESSION_HOURS}h / 空闲 ${A.IDLE_MINUTES}min`);
  });
})();
