-- =============================================================
--  VPN 权限管控平台 —— MySQL 表结构
--  导入： mysql -u root -p < schema.sql
--  字符集 utf8mb4；时间统一 DATETIME(3) 保证毫秒级可审计
-- =============================================================

CREATE DATABASE IF NOT EXISTS vpn_ctrl
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vpn_ctrl;

-- ---------- 1. 管理员账号 ----------
CREATE TABLE IF NOT EXISTS sys_account (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  login           VARCHAR(64)  NOT NULL,
  name            VARCHAR(64)  NOT NULL,
  pwd_hash        CHAR(128)    NOT NULL COMMENT 'scrypt(N=16384) 派生密钥 hex',
  pwd_salt        CHAR(32)     NOT NULL COMMENT '16 字节随机盐 hex',
  role            ENUM('admin','sec','op','custom') NOT NULL DEFAULT 'custom',
  perm_account    ENUM('none','r','rw') NOT NULL DEFAULT 'none',
  perm_dest       ENUM('none','r','rw') NOT NULL DEFAULT 'none',
  perm_vpn        ENUM('none','r','rw') NOT NULL DEFAULT 'none',
  perm_audit      ENUM('none','r','rw') NOT NULL DEFAULT 'none',
  status          TINYINT      NOT NULL DEFAULT 1 COMMENT '1启用 0停用',
  failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until    DATETIME(3)  NULL COMMENT '锁定截止',
  must_change_pwd TINYINT      NOT NULL DEFAULT 0 COMMENT '强制改密',
  avatar          VARCHAR(255) NULL COMMENT '头像文件名（存于 uploads/avatars）',
  last_login_at   DATETIME(3)  NULL,
  last_login_ip   VARCHAR(45)  NULL,
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_login (login),
  KEY idx_status (status)
) ENGINE=InnoDB COMMENT='平台管理员账号';

-- ---------- 2. 会话（服务端可吊销）----------
CREATE TABLE IF NOT EXISTS sys_session (
  id          CHAR(64) PRIMARY KEY COMMENT 'sha256(token)',
  account_id  BIGINT UNSIGNED NOT NULL,
  created_at  DATETIME(3) NOT NULL,
  last_seen   DATETIME(3) NOT NULL COMMENT '空闲超时依据',
  expires_at  DATETIME(3) NOT NULL COMMENT '绝对超时',
  ip          VARCHAR(45)  NULL,
  user_agent  VARCHAR(255) NULL,
  revoked     TINYINT NOT NULL DEFAULT 0,
  KEY idx_account (account_id),
  KEY idx_expires (expires_at),
  CONSTRAINT fk_sess_acct FOREIGN KEY (account_id) REFERENCES sys_account(id) ON DELETE CASCADE
) ENGINE=InnoDB COMMENT='登录会话';

-- ---------- 3. 目的地 IP-端口池 ----------
CREATE TABLE IF NOT EXISTS dest_pool (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(64)  NOT NULL,
  ip         VARCHAR(45)  NOT NULL,
  port       VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '端口规格：空=全部端口；支持单端口/区间/逗号分隔，如 9,100-200',
  proto      VARCHAR(16) NOT NULL DEFAULT 'TCP',
  descr      VARCHAR(128) NULL,
  created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_endpoint (ip, port, proto)
) ENGINE=InnoDB COMMENT='目的地 IP-端口池';

-- ---------- 4. 目的地包 ----------
CREATE TABLE IF NOT EXISTS dest_package (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(64)  NOT NULL,
  descr      VARCHAR(128) NULL,
  created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_name (name)
) ENGINE=InnoDB COMMENT='目的地包（IP-端口的组合）';

CREATE TABLE IF NOT EXISTS dest_package_item (
  package_id BIGINT UNSIGNED NOT NULL,
  pool_id    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (package_id, pool_id),
  KEY idx_pool (pool_id),
  CONSTRAINT fk_item_pkg  FOREIGN KEY (package_id) REFERENCES dest_package(id) ON DELETE CASCADE,
  CONSTRAINT fk_item_pool FOREIGN KEY (pool_id)    REFERENCES dest_pool(id)    ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- 5. VPN 账号（按真实姓名）----------
CREATE TABLE IF NOT EXISTS vpn_account (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(64) NOT NULL COMMENT '真实姓名',
  vpn_ip     VARCHAR(45) NOT NULL COMMENT '固定内网 IP，审计关联主键',
  note       VARCHAR(128) NULL COMMENT '部门/备注',
  pubkey     VARCHAR(64)  NULL COMMENT 'WireGuard peer 公钥（base64，平台生成）',
  privkey    VARCHAR(255) NULL COMMENT 'WireGuard 私钥：AES-256-GCM 加密存储，明文仅下发配置时解密',
  mode       ENUM('allow','deny') NOT NULL DEFAULT 'allow' COMMENT '授权模式：allow=白名单(默认)，deny=黑名单',
  full_proxy TINYINT NOT NULL DEFAULT 0 COMMENT '全代理模式：1=开启后该用户全部流量经网关转发（外网走 NAT，内网仍按授权控制）',
  status     TINYINT     NOT NULL DEFAULT 1,
  login_enabled TINYINT  NOT NULL DEFAULT 0 COMMENT '客户端登录启用：1=启用（可用姓名+口令登录），0=未启用（口令可为空）',
  pwd_enc    VARCHAR(255) NULL COMMENT '客户端登录口令：AES-256-GCM 加密存储。需可回显（管理员查看 / 随配置一并交付本人），故不使用单向散列',
  last_login_at DATETIME(3) NULL COMMENT '客户端最近登录时间',
  last_login_ip VARCHAR(45) NULL COMMENT '客户端最近登录来源 IP',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_name (name),
  UNIQUE KEY uk_ip   (vpn_ip)
) ENGINE=InnoDB COMMENT='VPN 账号（同时承载 WireGuard peer 配置与客户端登录凭据，二者一一绑定）';

CREATE TABLE IF NOT EXISTS vpn_grant (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  vpn_id     BIGINT UNSIGNED NOT NULL,
  kind       ENUM('pool','pkg') NOT NULL,
  ref_id     BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_grant (vpn_id, kind, ref_id),
  KEY idx_vpn (vpn_id),
  CONSTRAINT fk_grant_vpn FOREIGN KEY (vpn_id) REFERENCES vpn_account(id) ON DELETE CASCADE
) ENGINE=InnoDB COMMENT='用户被授权的目的地';

-- ---------- 6. 访问日志 ----------
CREATE TABLE IF NOT EXISTS access_log (
  id        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts        DATETIME(3)   NOT NULL,
  vpn_id    BIGINT UNSIGNED NULL,
  user_name VARCHAR(64)   NULL,
  src_ip    VARCHAR(45)   NOT NULL,
  dst_ip    VARCHAR(45)   NOT NULL,
  dst_port  INT UNSIGNED  NOT NULL,
  proto     VARCHAR(8)    NOT NULL,
  action    ENUM('ALLOW','DENY') NOT NULL,
  KEY idx_ts   (ts),
  KEY idx_user (user_name),
  KEY idx_dst  (dst_ip, dst_port)
) ENGINE=InnoDB COMMENT='网关 nftables 流日志落库';

-- ---------- 7. 管理员操作审计 ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id     BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  actor  VARCHAR(64)  NOT NULL,
  action VARCHAR(64)  NOT NULL,
  target VARCHAR(255) NULL,
  ip     VARCHAR(45)  NULL,
  KEY idx_ts (ts),
  KEY idx_actor (actor)
) ENGINE=InnoDB COMMENT='平台操作审计（建议设为只追加）';

-- ---------- 8. 登录失败记录 ----------
CREATE TABLE IF NOT EXISTS login_fail (
  id     BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  login  VARCHAR(64) NULL,
  ip     VARCHAR(45) NULL,
  reason VARCHAR(64) NULL,
  KEY idx_ts (ts),
  KEY idx_ip (ip)
) ENGINE=InnoDB;

-- =============================================================
--  生产环境加固建议
-- =============================================================
-- 1) 专用应用账号（禁止用 root），并对审计表只授予 INSERT：
--    CREATE USER 'vpnapp'@'localhost' IDENTIFIED BY '<强随机密码>';
--    GRANT SELECT,INSERT,UPDATE,DELETE ON vpn_ctrl.* TO 'vpnapp'@'localhost';
--    REVOKE UPDATE,DELETE ON vpn_ctrl.audit_log  FROM 'vpnapp'@'localhost';
--    REVOKE UPDATE,DELETE ON vpn_ctrl.access_log FROM 'vpnapp'@'localhost';
--    FLUSH PRIVILEGES;
--
-- 2) 审计表防篡改触发器：
--    DELIMITER //
--    CREATE TRIGGER trg_audit_no_upd BEFORE UPDATE ON audit_log
--      FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='审计记录不可修改';
--    CREATE TRIGGER trg_audit_no_del BEFORE DELETE ON audit_log
--      FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='审计记录不可删除';
--    //
--    DELIMITER ;
--
-- 3) access_log 按月分区并定期归档，留存不少于 6 个月（等保要求）。
--
-- 4) MySQL 启用 TLS：require_secure_transport=ON。
-- =============================================================
