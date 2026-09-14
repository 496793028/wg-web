'use strict';
/* =====================================================================
 *  方言层 · MySQL（默认）
 *  统一接口：all / get / scalar / run / exec / tx / close
 *           + SQL 片段 sql.now3 / plusHours / plusMinutes / daysAgo / todayStart
 *           + insertIgnore / isDup / columns / initSchema
 *  server.js 与 auth.js 只依赖这层接口，不再出现 MySQL 专有语法。
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

/* 连接级错误：标记 dbDown，便于上层回 503 而不是 500 */
const DOWN = new Set(['ECONNREFUSED', 'PROTOCOL_CONNECTION_LOST', 'ER_ACCESS_DENIED_ERROR',
  'ER_BAD_DB_ERROR', 'ETIMEDOUT', 'ENOTFOUND', 'EHOSTUNREACH']);

function create() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'vpn_ctrl',
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_POOL || 10),
    charset: 'utf8mb4',
    dateStrings: true,          // 日期直接返回字符串，避免时区漂移
    supportBigNumbers: true,
  });
  const mark = e => { if (e && DOWN.has(e.code)) e.dbDown = true; return e; };
  const P = p => (Array.isArray(p) ? p : (p === undefined ? [] : [p]));

  async function all(sql, p) {
    try { return (await pool.execute(sql, P(p)))[0]; } catch (e) { throw mark(e); }
  }
  async function get(sql, p) {
    const r = await all(sql, p);
    return (Array.isArray(r) ? r[0] : null) || null;      // INSERT/UPDATE 时第 0 项是 ResultSetHeader
  }
  async function scalar(sql, p) { const r = await get(sql, p); return r ? Object.values(r)[0] : null; }
  async function run(sql, p) {
    try {
      const [r] = await pool.execute(sql, P(p));
      return { id: r.insertId, changes: r.affectedRows };
    } catch (e) { throw mark(e); }
  }
  async function exec(sql) { return pool.query(sql); }

  /** 事务：fn 拿到绑定该连接的 { run, get, all } */
  async function tx(fn) {
    const conn = await pool.getConnection();
    const cq = async (sql, p) => (await conn.execute(sql, P(p)))[0];
    try {
      await conn.beginTransaction();
      const r = await fn({
        run: async (sql, p) => { const [x] = await conn.execute(sql, P(p)); return { id: x.insertId, changes: x.affectedRows }; },
        get: async (sql, p) => { const r2 = await cq(sql, p); return (Array.isArray(r2) ? r2[0] : null) || null; },
        all: cq,
      });
      await conn.commit();
      return r;
    } catch (e) { try { await conn.rollback(); } catch { /* ignore */ } throw e; }
    finally { conn.release(); }
  }

  async function columns(table) {
    const rows = await all(
      `SELECT COLUMN_NAME AS c FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?`, [table]);
    return rows.map(r => r.c);
  }

  /** 建表：schema.sql 按 ';' 拆分逐条执行（与原实现一致，忽略兼容性差异） */
  async function initSchema() {
    const sql = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
    for (const stmt of sql.split(';')) {
      const s = stmt.replace(/--[^\n]*/g, '').trim();
      if (s) { try { await all(s); } catch { /* 忽略分区等兼容性差异 */ } }
    }
  }

  return {
    name: 'mysql',
    sql: {
      now3: 'NOW(3)',
      plusHours: e => `DATE_ADD(NOW(3), INTERVAL ${e} HOUR)`,
      plusMinutes: e => `DATE_ADD(NOW(3), INTERVAL ${e} MINUTE)`,
      daysAgo: e => `DATE_SUB(NOW(3), INTERVAL ${e} DAY)`,
      todayStart: 'CURDATE()',
    },
    insertIgnore: 'INSERT IGNORE',
    isDup: e => !!e && e.code === 'ER_DUP_ENTRY',
    all, get, scalar, run, exec, tx, columns, initSchema,
    async close() { await pool.end(); },
  };
}

module.exports = { create };
