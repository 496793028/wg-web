'use strict';
/* =====================================================================
 * db.js —— 数据库连接、口令哈希、会话管理
 *
 * 安全要点：
 *  · 全部使用预编译参数化查询（mysql2 execute），杜绝 SQL 注入
 *  · 口令用 scrypt（内存硬、抗 GPU），每用户独立随机盐，恒定时间比较
 *  · 会话为服务端存储（DB），可即时吊销；cookie 存 token，DB 只存 sha256
 * ===================================================================== */
const mysql = require('mysql2/promise');
const crypto = require('crypto');

/* ---------------- 连接池 ---------------- */
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'vpn_ctrl',
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_POOL || 10),
  queueLimit: 0,
  charset: 'utf8mb4',
  supportBigNumbers: true,
  dateStrings: ['DATE', 'DATETIME'],   // 直接返回字符串，避免时区漂移
});

/** 参数化查询，返回结果数组 */
async function q(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}
/** 取单行 */
async function q1(sql, params = []) {
  const rows = await q(sql, params);
  return rows[0] || null;
}
/** 取单个标量 */
async function qv(sql, params = []) {
  const r = await q1(sql, params);
  return r ? Object.values(r)[0] : null;
}

/* ---------------- 口令 ---------------- */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function pwdHash(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, SCRYPT.keylen, SCRYPT);
  return { hash: dk.toString('hex'), salt: salt.toString('hex') };
}

function pwdVerify(pw, hashHex, saltHex) {
  try {
    const dk = crypto.scryptSync(String(pw), Buffer.from(saltHex, 'hex'), SCRYPT.keylen, SCRYPT);
    const h = Buffer.from(hashHex, 'hex');
    if (h.length !== dk.length) return false;
    return crypto.timingSafeEqual(h, dk);        // 恒定时间比较，防时序侧信道
  } catch { return false; }
}

/** 企业口令策略：长度 ≥10，且同时包含字母与数字（可按需提高） */
function pwdPolicy(p) {
  if (typeof p !== 'string' || p.length < 10) return '密码长度至少 10 位';
  if (!/[A-Za-z]/.test(p)) return '密码需包含字母';
  if (!/\d/.test(p)) return '密码需包含数字';
  return null;
}

/* ---------------- 会话 ---------------- */
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');

const SESSION_HOURS = Number(process.env.SESSION_HOURS || 8);   // 绝对超时
const IDLE_MINUTES = Number(process.env.IDLE_MINUTES || 60);    // 空闲超时

async function createSession(accountId, ip, ua) {
  const token = newToken();
  await q(
    `INSERT INTO sys_session (id, account_id, created_at, last_seen, expires_at, ip, user_agent)
     VALUES (?, ?, NOW(3), NOW(3), DATE_ADD(NOW(3), INTERVAL ? HOUR), ?, ?)`,
    [sha256(token), accountId, SESSION_HOURS, ip || null, String(ua || '').slice(0, 255)]
  );
  return token;
}

async function loadSession(token) {
  if (!token) return null;
  const id = sha256(token);
  const s = await q1(
    `SELECT * FROM sys_session WHERE id=? AND revoked=0 AND expires_at > NOW(3)`, [id]);
  if (!s) return null;

  if (Date.now() - new Date(s.last_seen).getTime() > IDLE_MINUTES * 60000) {
    await q(`UPDATE sys_session SET revoked=1 WHERE id=?`, [id]);   // 空闲超时即吊销
    return null;
  }
  await q(`UPDATE sys_session SET last_seen=NOW(3) WHERE id=?`, [id]);

  return await q1(
    `SELECT id, login, name, role, perm_account, perm_dest, perm_vpn, perm_audit,
            status, must_change_pwd
     FROM sys_account WHERE id=? AND status=1`, [s.account_id]);
}

async function destroySession(token) {
  if (!token) return;
  await q(`UPDATE sys_session SET revoked=1 WHERE id=?`, [sha256(token)]);
}

/** 清理过期会话（建议配 cron 每小时跑一次） */
async function sweepSessions() {
  await q(`DELETE FROM sys_session WHERE revoked=1 OR expires_at < DATE_SUB(NOW(3), INTERVAL 1 DAY)`);
}

module.exports = {
  pool, q, q1, qv,
  pwdHash, pwdVerify, pwdPolicy,
  sha256, newToken,
  createSession, loadSession, destroySession, sweepSessions,
  SESSION_HOURS, IDLE_MINUTES,
};
