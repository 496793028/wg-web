'use strict';
/* =====================================================================
 *  数据库方言选择器
 *    DB_DRIVER=mysql   （默认）远程/独立 MySQL
 *    DB_DRIVER=sqlite  单机、零依赖（Node 内置 node:sqlite）
 * ===================================================================== */
const DRIVER = String(process.env.DB_DRIVER || 'mysql').trim().toLowerCase();

let mod;
if (DRIVER === 'sqlite' || DRIVER === 'sqlite3') mod = require('./sqlite.js');
else if (DRIVER === 'mysql' || DRIVER === 'mariadb') mod = require('./mysql.js');
else {
  console.error(`[DB] 不支持的 DB_DRIVER="${DRIVER}"（可选：mysql | sqlite）`);
  process.exit(1);
}

const dialect = mod.create();
dialect.driver = DRIVER;
module.exports = dialect;
