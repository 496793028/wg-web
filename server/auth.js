'use strict';
/* =====================================================================
 *  安全基线配置
 *  - 口令：scrypt（内存硬、抗 GPU），每用户独立盐，恒定时间比较
 *  - 会话：服务端存储，可即时吊销；cookie 仅存随机 token
 *  - 全部 SQL 使用预编译参数化查询，杜绝注入
 * ===================================================================== */
const crypto = require('crypto');

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 8);
const IDLE_MINUTES = Number(process.env.IDLE_MINUTES || 60);

/* ---------------- 口令 ---------------- */
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
    return crypto.timingSafeEqual(h, dk);
  } catch { return false; }
}
/** 口令策略：≥6 位，含大小写字母与数字 */
function pwdPolicy(p) {
  if (typeof p !== 'string' || p.length < 6) return '密码长度至少 6 位';
  if (!/[a-z]/.test(p) || !/[A-Z]/.test(p)) return '密码需同时包含大小写字母';
  if (!/\d/.test(p)) return '密码需包含数字';
  return null;
}

const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');

module.exports = {
  SCRYPT, SESSION_HOURS, IDLE_MINUTES,
  pwdHash, pwdVerify, pwdPolicy,
  sha256, newToken,

  /* ---------------- 会话（由数据库方言注入查询能力）---------------- */
  async createSession(D, accountId, ip, ua) {
    const token = newToken();
    await D.run(
      `INSERT INTO sys_session (id, account_id, created_at, last_seen, expires_at, ip, user_agent)
       VALUES (?,?,${D.sql.now3},${D.sql.now3},${D.sql.plusHours('?')},?,?)`,
      [sha256(token), accountId, SESSION_HOURS, ip || null, String(ua || '').slice(0, 255)]);
    return token;
  },

  async loadSession(D, token) {
    if (!token) return null;
    const id = sha256(token);
    const s = await D.get(
      `SELECT * FROM sys_session WHERE id=? AND revoked=0 AND expires_at > ${D.sql.now3}`, [id]);
    if (!s) return null;
    if (Date.now() - new Date(String(s.last_seen).replace(' ', 'T')).getTime() > IDLE_MINUTES * 60000) {
      await D.run(`UPDATE sys_session SET revoked=1 WHERE id=?`, [id]);
      return null;
    }
    await D.run(`UPDATE sys_session SET last_seen=${D.sql.now3} WHERE id=?`, [id]);
    return await D.get(
      `SELECT id, login, name, role, avatar, perm_account, perm_dest, perm_vpn, perm_audit,
              status, must_change_pwd
       FROM sys_account WHERE id=? AND status=1`, [s.account_id]);
  },

  async destroySession(D, token) {
    if (token) await D.run(`UPDATE sys_session SET revoked=1 WHERE id=?`, [sha256(token)]);
  },

  /** 清理过期会话，建议每小时执行一次 */
  async sweepSessions(D) {
    await D.run(`DELETE FROM sys_session
      WHERE revoked=1 OR expires_at < ${D.sql.daysAgo('1')}`);
  },
};
