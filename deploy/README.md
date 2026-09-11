# 部署说明（Web 平台 + 网关执行面）

本目录文件均为**模板**，部署时复制到系统对应位置。整体分两端：

```
[ 平台侧 ]  Node 服务 + MySQL            —— 管理面：账号 / 目的地 / 授权 / 审计查询
[ 网关侧 ]  vpn-sync + vpn-logship       —— 执行面：拉取授权落地规则 + 回传流日志
```

平台通过两个只读接口把"意图"交给网关（用 `INGEST_TOKEN` 鉴权）：
- `GET /api/gateway/peers` → WireGuard peer 列表
- `GET /api/gateway/grants` → 每用户被允许的目的地

网关执行面把它们翻译成 `wg` peer + `nftables` 默认拒绝/按授权放行。

---

## 一、平台侧（Web）

```bash
# 1. 数据库
mysql -u root -p < server/schema.sql          # 建库建表（含生产加固建议注释）

# 2. 依赖与配置
cd server && npm install --omit=dev
cp .env.example .env && vi .env               # 必填：DB_* / INGEST_TOKEN / WG_* / COOKIE_SECURE=1

# 3. 托管
sudo install -m 0644 ../deploy/vpn-web.service /etc/systemd/system/vpn-web.service
sudo systemctl daemon-reload && sudo systemctl enable --now vpn-web

# 4. HTTPS 反代
sudo cp ../deploy/nginx-vpn.conf /etc/nginx/conf.d/vpn-web.conf   # 改域名/证书路径
sudo nginx -t && sudo systemctl reload nginx
```

平台自身的安全基线（仓库已实现）：scrypt 口令 + 服务端可吊销会话、失败锁定、
参数化查询、RBAC（account/dest/vpn/audit × r/rw）、CSRF 自定义头、`trust proxy`。

**生产必做**：MySQL 用专用最小权限账号（见 `schema.sql` 末尾），审计表加防篡改触发器，
`access_log` 按月分区并留存 ≥6 个月，`COOKIE_SECURE=1`，证书启用。

---

## 二、网关侧（执行面）

```bash
# 1. 落脚本
sudo install -m 0755 gateway/vpn-sync.py    /usr/local/bin/vpn-sync.py
sudo install -m 0755 gateway/vpn-logship.py /usr/local/bin/vpn-logship.py

# 2. 配置（token / base 与平台一致）
sudo install -m 0644 gateway/vpn-sync.env.example /etc/vpn-sync.env && sudo chmod 600 /etc/vpn-sync.env
sudo vi /etc/vpn-sync.env

# 3. WireGuard 服务端接口（真实网关机需内核支持 WireGuard 或 wireguard-go）
#    平台在 local 模式下会写托管块；agent 模式下由 vpn-sync 写 /etc/wireguard/wg0.conf 的托管块
sudo install -m 0600 /dev/null /etc/wireguard/wg0.conf   # 先放一个含 [Interface] 的最小配置

# 4. 服务
sudo install -m 0644 gateway/vpn-sync.service    /etc/systemd/system/vpn-sync.service
sudo install -m 0644 gateway/vpn-logship.service /etc/systemd/system/vpn-logship.service
sudo install -m 0644 gateway/vpn-logship.logrotate /etc/logrotate.d/vpn-flow
sudo install -m 0644 deploy/rsyslog-vpn-flow.conf  /etc/rsyslog.d/40-vpn-flow.conf
sudo systemctl daemon-reload
sudo systemctl restart rsyslog
sudo systemctl enable --now vpn-sync vpn-logship
```

### 工作流

1. `vpn-sync` 每 30s 拉一次 `peers`/`grants`：
   - peers → 渲染 `wg0.conf` 托管块（`# >>> vpn-ctrl managed`）→ `wg syncconf` 热加载；
   - grants → 生成 `inet vpnflow` 表（默认拒绝 + 按 `源VPN IP→目的IP:端口/协议` 放行，记账 `vpn-flow ALLOW/DENY`）。
2. nftables 记账日志经 rsyslog 落到 `/var/log/vpn-flow.log`；
3. `vpn-logship` 跟随该文件，解析后 `POST /api/ingest` 入库（离线存 SQLite 不丢，恢复后补传）。

### 安全边界

- forward 链**只约束 `iifname "wg0"` 的新建连接**，主机其它转发/服务零影响；
- 已建立连接交给 conntrack，不误伤回程；
- nft 下发为**单事务原子重载**，规则始终一致。

---

## 三、验证

```bash
# 网关执行面端到端（netns 隔离、自清理、不残留）；需 root
sudo bash verify/run-on-3.39-enforce.sh

# shipper 冒烟（任意 Python3 环境，无需 MySQL）
python3 verify/smoke-logship.py
```

详见 `verify/管控面验证记录.md`（已验证项）与 `verify/真机验证-需用户环境.md`（待用户环境项）。
