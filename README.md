# VPN 权限管控平台

> 基于 **WireGuard** 的企业内网 VPN 权限管控系统 —— **nftables 逐用户精细放行 + Web 管理界面 + 操作与访问审计**

![License](https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey.svg)
![Node](https://img.shields.io/badge/Node-%3E%3D18-339933.svg)
![MySQL](https://img.shields.io/badge/MySQL-5.7%20%7C%208.0-4479A1.svg)

> ⚠️ **本项目采用 source-available（源码可见）许可，不是开源软件** —— 详见 [许可协议](#许可协议)。
>
> **WireGuard®** 是 Jason A. Donenfeld 的注册商标。本项目是**独立的第三方项目**，与 WireGuard 项目、
> Jason A. Donenfeld、zx2c4 及 Edge Security LLC **无任何隶属、赞助或背书关系**，名称仅用于说明技术兼容性。

---

> 📌 **验证状态（2026-09-11）**
>
> - **管控执行面**：网关 agent `gateway/vpn-sync.py` 依据平台下发的授权，生成 nftables 规则（`iifname "wg0"` **默认拒绝** + 按 `源VPN IP → 目的IP:端口/协议` 放行）并 `wg syncconf` 热加载 peer。已在真实网关 **192.168.3.39（CentOS 7.9 / kernel 3.10 / nftables v0.8）** 用 netns 隔离验证：**授权目的地可达、未授权目的地被拦截**（真流量穿过 forward 链）。
> - **流级审计数据面**：nftables 记账日志（前缀 `vpn-flow ALLOW` / `vpn-flow DENY`）→ rsyslog 落盘 → `vpn-logship` 解析 → `POST /api/ingest`。已用真实内核日志行闭合验证到接口契约（含 token 鉴权）。
> - **平台 + 数据库**：真实 `server.js` 已直连真实 MySQL（8.0）跑通登录 / RBAC / CRUD / `POST /api/ingest` 落库 / `/api/logs` 查询与导出 / 审计查询。
> - **真实 WireGuard 隧道**：3.39 无内核模块，改用 **wireguard-go（用户态）** 在 netns 内验证 —— **真实握手成功**、隧道内已授权目的可达、未授权被 nftables 拦、主机服务零影响。
> - **仍未验证**：内核态 WireGuard 与真实网卡性能（本轮 111 MB/s 是 veth 上界）、HTTPS/TLS、多用户规模、shipper 在网关长跑。
>
> 验证记录见 `verify/管控面验证记录.md`；待办与所需环境见 `verify/真机验证-需用户环境.md`。

## 目录

- [它解决什么问题](#它解决什么问题)
- [核心特性](#核心特性)
- [架构](#架构)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [目录结构](#目录结构)
- [网关对接接口](#网关对接接口)
- [⚠️ 部署前必读](#️-部署前必读)
- [文档索引](#文档索引)
- [商标声明](#商标声明)
- [许可协议](#许可协议)

---

## 它解决什么问题

VPN 开通之后，「**谁能连、能连到哪台机器的哪个端口**」往往散落在各网关配置里、靠口口相传，没有统一记录。一旦发生越权访问或泄漏，**难以溯源**。

本平台把这件事收敛到**一个带留痕、可审计的管理界面**里：

- **账号 / 角色 / 模块权限矩阵** —— 谁能进平台、能管哪类资源
- **目的地池（IP-端口）+ 目的地包（组合）** —— 把零散内网地址组织成可授权单元；端口支持 **留空=全部端口**、单端口、区间（`100-200`）与多段混用（`9,100-200`，中英文逗号均可）
- **按真实姓名分配 VPN 账号 + 可视化授权** —— 谁可访问哪些目的地，一目了然
- **访问记录 + 管理员操作审计** —— 每一次新建连接、每一次后台改动都有留痕

## 核心特性

| 能力 | 说明 |
| --- | --- |
| **逐用户精细放行** | 每个用户绑定固定虚拟 IP（`/32`），网关按源 IP 精确放行到「某台机器的某个端口 / 端口区间 / 全部端口」，默认拒绝 |
| **WireGuard 密钥托管** | 后端生成 X25519 密钥对，**私钥经 AES-256-GCM 加密落库**；客户端配置一键生成（复制 / 下载 `.conf`） |
| **双模式 peer 落地** | `agent`（网关拉取，Web 无需 root）/ `local`（平台直写 `wg syncconf`，需 root） |
| **授权双向对账** | 平台删除用户 → 网关侧 peer 自动移除，**不留僵尸 peer** |
| **全链路审计** | 管理员所有写操作落库（操作人 / 动作 / 对象 / 来源 IP）；用户访问记录可按人、目标、端口、结果、时间筛选（流日志需网关 `vpn-logship` 回传，参考最小实现见 `verify/vpn-logship-min.py`，不随正式发布分发） |
| **企业级安全基线** | scrypt 口令哈希、服务端可吊销会话、登录失败锁定、全程参数化 SQL、CSRF 防护、HTTPS 就绪 |
| **零构建前端** | 纯静态 `index.html` + `app.js` + `styles.css`，双主题（深色 / 浅色），无打包步骤 |

## 架构

```
   控制面（本平台）                        数据面（网关）
┌──────────────────────┐          ┌──────────────────────┐
│  浏览器 UI           │          │  WireGuard (wg0)     │
│  Express 后端  8787  │  ① 授权  │  nftables per-user   │
│  MySQL  授权数据     │ ───────► │  规则（按源 IP 放行）│
│                      │ ◄─────── │  流日志 vpn-flow     │
└──────────────────────┘  ② 日志  └──────────────────────┘
```

- **① 授权下发**：网关上 `vpn-sync` 定时拉 `GET /api/gateway/grants`，把「谁能访问哪些 IP:端口」渲染成 nftables 规则并重载。
- **② 日志回传**：网关上需自行部署 `vpn-logship`（读 `/var/log/vpn-flow.log`，解析后 `POST /api/ingest` 推回平台；本仓库不随附该脚本与 systemd 单元）。

**信任锚**：WireGuard 在 hub 侧强制「用某 peer 公钥解密的包，源地址必须匹配该 peer 的 `AllowedIPs`」。因此网关上看到 `SRC=10.100.0.11` 就**确定是那个人** —— per-user 权限与审计由此成立。

## 技术栈

| 层 | 选型 |
| --- | --- |
| 前端 | 原生 HTML / CSS / JS（无框架、无构建） |
| 后端 | Node.js ≥ 18 + Express 4 |
| 数据库 | MySQL 5.7 / 8.0（`mysql2` 连接池） |
| 网关 | WireGuard + nftables + systemd |

## 快速开始

### 1. 配置环境变量

```bash
cp .env.example .env
```

**至少修改这几项**（详见 [部署前必读](#️-部署前必读)）：

```ini
DB_HOST=127.0.0.1
DB_USER=vpnapp
DB_PASS=<改成强口令>
ADMIN_INIT_PWD=<改成强口令>
INGEST_TOKEN=<改成随机长串>
WG_KEY_SECRET=<改成随机长串>
```

### 2. 初始化数据库

```bash
cd server
npm install
npm run init        # 建表 + 创建初始管理员
```

### 3. 启动

```bash
npm start           # → http://127.0.0.1:8787
```

或回到项目根目录，在已放置 `.env` 的前提下直接运行：

```bash
node server/server.js      # 与 npm start 等价，自动读取项目根目录 .env
```

### 4. 自检（可选）

```bash
cd server && npm run selftest
```

覆盖口令哈希、口令策略、会话令牌、SQL 参数化扫描、安全中间件等静态与单元检查，应输出 `26 通过 / 0 失败`。

> **生产部署请勿使用上述临时启动方式**，请改用 systemd 单元托管进程，并做好 MySQL 加固与 Nginx 反向代理（相关配置不在本仓库范围内）。

## 目录结构

```
.
├── index.html                      # 前端入口
├── app.js                          # 前端逻辑（视图 + 交互）
├── styles.css                      # 样式（双主题）
├── .env.example                    # 环境变量模板（复制为 .env）
├── LICENSE                         # PolyForm Noncommercial 1.0.0
└── server/
    ├── server.js                   # 后端主程序（全部 REST API）
    ├── auth.js                     # 口令哈希 / 会话 / 令牌
    ├── db.js                       # 数据库连接
    ├── schema.sql                  # 表结构
    ├── selftest.js                 # 安全逻辑自检
    └── .env.example                # 另一份环境变量模板
```

## 网关对接接口

两个**免登录、由 `x-ingest-token` 保护**的接口，供网关侧 agent 调用：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/gateway/grants` | 拉取「IP → 允许目标」授权清单（`vpn-sync` 用） |
| `GET` | `/api/gateway/peers` | 拉取 WireGuard peer 清单（`vpn-sync` 对账用） |
| `POST` | `/api/ingest` | 回传访问日志（`vpn-logship` 用） |

其余接口均需登录会话，并按模块（`account` / `dest` / `vpn` / `audit`）校验 `r` / `rw` 权限。

## ⚠️ 部署前必读

**1. 初始管理员口令：默认在网页上设置，源码中没有任何固定默认口令**

`.env` 的 `ADMIN_INIT_PWD` **默认为空**。留空时，`npm run init` 会以「口令未设置」状态创建 `admin` 账号，
**首次打开平台会自动进入初始化页**，由你在网页上设定口令。

若你选择在 `.env` 中预设（适合自动化部署），请务必换成自己的强口令：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_INIT_PWD` | 空 → 走网页初始化 | 若填写，需 ≥6 位且含大小写字母与数字 |
| `DB_PASS` | 空 | 数据库口令，**务必设置** |
| `INGEST_TOKEN` | 空 | 网关推送鉴权，**生产必须设置** |
| `WG_KEY_SECRET` | 空 | 私钥加密主密钥 |

> ⚠️ **完成初始化之前，不要把平台暴露到公网。**
> 在口令设定完成前，任何能访问到该服务的人都可以抢先调用初始化接口设定口令。
> 建议初始化后刷新页面确认已回到正常登录页。

**2. 备份 `server/.wgkey`**

若未在 `.env` 中设置 `WG_KEY_SECRET`，平台首次运行会自动生成 `server/.wgkey`。
**丢失它 = 所有历史私钥无法解密**，只能给全部用户重新签发密钥与配置。

**3. `ADMIN_INIT_PWD` 仅在 `npm run init` 首次建号时生效**，之后修改 `.env` 不会影响已有账号，
需在「账号管理 → 重置密码」中修改。

**4. 本项目是控制面，不是数据面**

平台负责密钥 / 授权 / 审计，**不含流量转发代码**。真正生效的访问控制需要网关侧 `vpn-sync` / `vpn-logship` 配合（相关脚本与 systemd 单元需自行准备，本仓库不随附完整部署手册）。

**5. HTTPS 部署注意**

经 Nginx 终止 TLS 时，必须设置 `COOKIE_SECURE=1` 并传递 `X-Forwarded-For`，否则会出现「登录后一刷新就掉线」或「审计来源 IP 全部失真」。

## 文档索引

本仓库仅包含平台源码、本文件与 `LICENSE`。详细的部署 / 管理员 / 发布手册**不随仓库分发**；
部署相关的关键步骤与注意事项已浓缩在上方「快速开始」与「⚠️ 部署前必读」两节中。

## 商标声明

- **WireGuard®** 是 **Jason A. Donenfeld** 的注册商标。
- 本项目是**独立的第三方项目**，与 WireGuard 项目、Jason A. Donenfeld、zx2c4 以及
  Edge Security LLC **不存在任何隶属、赞助、背书或关联关系**；本项目**并非** WireGuard 官方产品，
  亦非官方认可的衍生项目。
- 本项目中出现的 "WireGuard" 字样**仅用于指示所对接的技术与协议**（指示性合理使用 /
  nominative fair use），不构成对商标的任何主张或使用许可。
- 本项目**不包含、也不分发** WireGuard 的源代码或二进制文件。平台通过调用部署环境中已安装的
  `wg` / `wg-quick` 等命令行工具与其交互（独立进程调用），不构成 WireGuard 的衍生作品。
- **部署者需自行安装 WireGuard，并自行遵守其各自的许可条款**：内核模块为 GPLv2，
  用户态工具（`wg`、`wg-quick`）与各平台客户端为 MIT / ISC。
- 商标使用政策：<https://www.wireguard.com/trademark-policy/>

---

## 许可协议

本项目采用 **PolyForm Noncommercial License 1.0.0**（PolyForm 非商业性使用许可 1.0.0）。

| | 条款 | 说明 |
| --- | --- | --- |
| ✅ | **使用 Use** | 任何**非商业**目的均可使用。包括个人学习 / 研究 / 实验 / 测试，以及慈善机构、教育机构、公共研究机构、公共安全或卫生机构、环境保护组织、政府机构的使用（不论其资金来源） |
| ✅ | **分发 Distribution** | 可分发自本软件的副本，**包括经修改的版本** |
| ✅ | **修改 Changes and New Works** | 可修改本软件，并可基于本软件创作新作品 |
| 📌 | **署名 Notices** | 必须确保每一位接收者同时获得本许可条款（或其链接），以及所有以 `Required Notice:` 开头的明文行 |
| ❌ | **商业性使用 Noncommercial** | 不得将本软件用于商业目的 |

**附加保障条款**

- **专利许可 Patent License** —— 许可人授予使用本软件所需的专利许可
- **防御性终止 Patent Defense** —— 若你书面主张本软件侵犯专利，你所获的专利许可立即终止
- **免责 No Liability** —— 本软件按「现状」提供，不附带任何担保

- 协议全文：[`LICENSE`](LICENSE)
- 官方文本：<https://polyformproject.org/licenses/noncommercial/1.0.0>
- Copyright (c) 2026 sjy

> ⚠️ **这是 source-available（源码可见）许可，不是开源许可。**
> 按 OSI（Open Source Initiative）的定义，开源许可不得限制商业使用，而本许可明确限制。
> **引用或转述本项目时，请勿称其为「开源软件」。**

### 免责声明

本项目按「现状」提供，不附带任何明示或暗示的担保。使用者需自行评估其在自身网络环境中的适用性与安全性，并自行承担部署与使用风险。
