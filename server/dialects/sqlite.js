'use strict';
/* =====================================================================
 *  方言层 · SQLite（单机 / 轻量部署）
 *  驱动：Node 内置 node:sqlite（Node ≥ 22.5，无需任何 npm 依赖）
 *   · WAL：多读 + 单写并行，读不被写阻塞
 *   · foreign_keys=ON：级联删除生效
 *   · 时间统一存 'YYYY-MM-DD HH:MM:SS.mmm' 文本，与 MySQL 版字符串格式一致
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const NOW3 = "strftime('%Y-%m-%d %H:%M:%f','now','localtime')";

function create() {
  const file = process.env.DB_FILE || path.join(__dirname, '..', 'data', 'vpn_ctrl.sqlite');
  fs.mkdirSync(path.dirname(file), { recursive: true });

  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode=WAL');
  db.exec('PRAGMA busy_timeout=5000');
  db.exec('PRAGMA foreign_keys=ON');
  db.exec('PRAGMA synchronous=NORMAL');

  /* 参数规整：node:sqlite 不接受 undefined / boolean。
     注意：node:sqlite 会把 JS 数字一律绑成 REAL（typeof(443)='real'）。
     写 INTEGER 列无妨（INTEGER 亲和性会无损转回 443）；
     但写 TEXT 列会被转成 '443.0' —— 往文本列插数字时请显式 String()。 */
  const norm = p => {
    const arr = Array.isArray(p) ? p : (p === undefined ? [] : [p]);
    return arr.map(v => {
      if (v === undefined || v === null) return null;
      if (typeof v === 'boolean') return v ? 1 : 0;
      if (typeof v === 'bigint') return Number(v);
      if (typeof v === 'number' || typeof v === 'string') return v;
      if (v instanceof Date) return v.toISOString().slice(0, 23).replace('T', ' ');
      return String(v);
    });
  };
  const mark = e => {
    if (e && /SQLITE_(CANTOPEN|READONLY|NOTADB|IOERR|CORRUPT|FULL)/.test(String(e.code || ''))) e.dbDown = true;
    return e;
  };

  /* 全部 async：与 mysql 方言保持同一契约（调用点存在 .catch 链，同步实现会炸） */
  async function all(sql, p) {
    try { return db.prepare(sql).all(...norm(p)); } catch (e) { throw mark(e); }
  }
  async function get(sql, p) {
    try { return db.prepare(sql).get(...norm(p)) || null; } catch (e) { throw mark(e); }
  }
  async function scalar(sql, p) { const r = await get(sql, p); return r ? Object.values(r)[0] : null; }
  async function run(sql, p) {
    try {
      const r = db.prepare(sql).run(...norm(p));
      return { id: r.lastInsertRowid === undefined ? undefined : Number(r.lastInsertRowid), changes: r.changes };
    } catch (e) { throw mark(e); }
  }
  async function exec(sql) { return db.exec(sql); }

  async function tx(fn) {
    db.exec('BEGIN');
    try {
      const r = await fn({ run, get, all });
      db.exec('COMMIT');
      return r;
    } catch (e) { try { db.exec('ROLLBACK'); } catch { /* ignore */ } throw e; }
  }

  async function columns(table) {
    return all(`PRAGMA table_info(${String(table).replace(/[^\w]/g, '')})`).then(r => r.map(x => x.name));
  }

  /** 建表：整份脚本交给 exec（它能正确处理触发器内部的分号） */
  async function initSchema() {
    db.exec(fs.readFileSync(path.join(__dirname, '..', 'schema.sqlite.sql'), 'utf8'));
  }

  return {
    name: 'sqlite',
    file,
    sql: {
      now3: NOW3,
      plusHours: e => `strftime('%Y-%m-%d %H:%M:%f','now','localtime','+' || ${e} || ' hours')`,
      plusMinutes: e => `strftime('%Y-%m-%d %H:%M:%f','now','localtime','+' || ${e} || ' minutes')`,
      daysAgo: e => `strftime('%Y-%m-%d %H:%M:%f','now','localtime','-' || ${e} || ' days')`,
      todayStart: `date('now','localtime')`,
    },
    insertIgnore: 'INSERT OR IGNORE',
    isDup: e => !!e && (/UNIQUE constraint failed/i.test(e.message || '') ||
                        String(e.code || '').startsWith('SQLITE_CONSTRAINT')),
    all, get, scalar, run, exec, tx, columns, initSchema,
    async close() { db.close(); },
  };
}

module.exports = { create };
