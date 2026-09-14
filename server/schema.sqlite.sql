-- =============================================================
--  VPN 权限管控平台 —— SQLite 表结构（与 schema.sql 等价）
--  由 dialects/sqlite.js 整份 exec() 执行；连接层已设 WAL / foreign_keys=ON
--  时间统一存 'YYYY-MM-DD HH:MM:SS.mmm' 文本，与 MySQL 版字符串格式一致
--  说明：ENUM -> TEXT + CHECK；AUTO_INCREMENT -> INTEGER PRIMARY KEY AUTOINCREMENT；
--        建表内的 KEY 索引拆成独立 CREATE INDEX；ON UPDATE 用触发器模拟
-- =============================================================

-- ---------- 1. 管理员账号 ----------
CREATE TABLE IF NOT EXISTS sys_account (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  login           TEXT    NOT NULL,
  name            TEXT    NOT NULL,
  pwd_hash        TEXT    NOT NULL,
  pwd_salt        TEXT    NOT NULL,
  role            TEXT    NOT NULL DEFAULT 'custom' CHECK (role IN ('admin','sec','op','custom')),
  perm_account    TEXT    NOT NULL DEFAULT 'none' CHECK (perm_account IN ('none','r','rw')),
  perm_dest       TEXT    NOT NULL DEFAULT 'none' CHECK (perm_dest IN ('none','r','rw')),
  perm_vpn        TEXT    NOT NULL DEFAULT 'none' CHECK (perm_vpn IN ('none','r','rw')),
  perm_audit      TEXT    NOT NULL DEFAULT 'none' CHECK (perm_audit IN ('none','r','rw')),
  status          INTEGER NOT NULL DEFAULT 1,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    TEXT    NULL,
  must_change_pwd INTEGER NOT NULL DEFAULT 0,
  avatar          TEXT    NULL,
  last_login_at   TEXT    NULL,
  last_login_ip   TEXT    NULL,
  created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime')),
  updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_login   ON sys_account(login);
CREATE INDEX        IF NOT EXISTS idx_status ON sys_account(status);

-- 等价于 MySQL 的 ON UPDATE CURRENT_TIMESTAMP(3)（WHEN 守卫避免触发器递归）
CREATE TRIGGER IF NOT EXISTS trg_sys_account_updated
AFTER UPDATE ON sys_account
FOR EACH ROW WHEN NEW.updated_at = OLD.updated_at
BEGIN
  UPDATE sys_account SET updated_at = strftime('%Y-%m-%d %H:%M:%f','now','localtime') WHERE id = NEW.id;
END;

-- ---------- 2. 会话（服务端可吊销）----------
CREATE TABLE IF NOT EXISTS sys_session (
  id          TEXT PRIMARY KEY,
  account_id  INTEGER NOT NULL,
  created_at  TEXT    NOT NULL,
  last_seen   TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  ip          TEXT    NULL,
  user_agent  TEXT    NULL,
  revoked     INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (account_id) REFERENCES sys_account(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sess_account ON sys_session(account_id);
CREATE INDEX IF NOT EXISTS idx_sess_expires ON sys_session(expires_at);

-- ---------- 3. 目的地 IP-端口池 ----------
CREATE TABLE IF NOT EXISTS dest_pool (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL,
  ip         TEXT    NOT NULL,
  port       TEXT    NOT NULL DEFAULT '',
  proto      TEXT    NOT NULL DEFAULT 'TCP' CHECK (proto IN ('TCP','UDP')),
  descr      TEXT    NULL,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_endpoint ON dest_pool(ip, port, proto);

-- ---------- 4. 目的地包 ----------
CREATE TABLE IF NOT EXISTS dest_package (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL,
  descr      TEXT    NULL,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_pkg_name ON dest_package(name);

CREATE TABLE IF NOT EXISTS dest_package_item (
  package_id INTEGER NOT NULL,
  pool_id    INTEGER NOT NULL,
  PRIMARY KEY (package_id, pool_id),
  FOREIGN KEY (package_id) REFERENCES dest_package(id) ON DELETE CASCADE,
  FOREIGN KEY (pool_id)    REFERENCES dest_pool(id)    ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_item_pool ON dest_package_item(pool_id);

-- ---------- 5. VPN 账号（按真实姓名）----------
CREATE TABLE IF NOT EXISTS vpn_account (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL,
  vpn_ip     TEXT    NOT NULL,
  note       TEXT    NULL,
  pubkey     TEXT    NULL,
  privkey    TEXT    NULL,
  status     INTEGER NOT NULL DEFAULT 1,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_vpn_name ON vpn_account(name);
CREATE UNIQUE INDEX IF NOT EXISTS uk_vpn_ip   ON vpn_account(vpn_ip);

CREATE TABLE IF NOT EXISTS vpn_grant (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  vpn_id     INTEGER NOT NULL,
  kind       TEXT    NOT NULL CHECK (kind IN ('pool','pkg')),
  ref_id     INTEGER NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime')),
  FOREIGN KEY (vpn_id) REFERENCES vpn_account(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_grant      ON vpn_grant(vpn_id, kind, ref_id);
CREATE INDEX        IF NOT EXISTS idx_grant_vpn ON vpn_grant(vpn_id);

-- ---------- 6. 访问日志 ----------
CREATE TABLE IF NOT EXISTS access_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT    NOT NULL,
  vpn_id    INTEGER NULL,
  user_name TEXT    NULL,
  src_ip    TEXT    NOT NULL,
  dst_ip    TEXT    NOT NULL,
  dst_port  INTEGER NOT NULL,
  proto     TEXT    NOT NULL,
  action    TEXT    NOT NULL CHECK (action IN ('ALLOW','DENY'))
);
CREATE INDEX IF NOT EXISTS idx_ts   ON access_log(ts);
CREATE INDEX IF NOT EXISTS idx_user ON access_log(user_name);
CREATE INDEX IF NOT EXISTS idx_dst  ON access_log(dst_ip, dst_port);

-- ---------- 7. 管理员操作审计 ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime')),
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NULL,
  ip     TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

-- ---------- 8. 登录失败记录 ----------
CREATE TABLE IF NOT EXISTS login_fail (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now','localtime')),
  login  TEXT NULL,
  ip     TEXT NULL,
  reason TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_lf_ts ON login_fail(ts);
CREATE INDEX IF NOT EXISTS idx_lf_ip ON login_fail(ip);

-- =============================================================
--  运维建议
--   1) 定期备份：直接复制 .sqlite 文件（WAL 模式下用 `sqlite3 db ".backup out"` 更稳）
--   2) 日志归档：access_log 按月清理/归档，保持单库体积可控
--   3) 不要把库文件放在网络盘（NFS/SMB）——SQLite 的锁在网络盘上不可靠
-- =============================================================
