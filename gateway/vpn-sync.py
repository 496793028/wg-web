#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpn-sync —— 自研网关执行面 agent（不依赖 Defguard）

把管控平台的「意图」落地为网关上的真实网络策略：
  peers  -> wg0.conf 托管块 + `wg syncconf` 热加载（增/删 peer，不中断已有连接）
  grants -> nftables 执行规则集：
              allow 模式（默认）：**默认拒绝** + 仅放行 allow 清单内的 (目的IP:端口/协议)
              deny  模式（黑名单）：先 drop deny 清单目的地，再兜底 accept 该用户全部新连接
  另外写 ip2name.json，供日志采集器把源 IP 还原成用户名

安全边界（重要）：
  - forward 链只约束 `iifname "wg0"` 的**新建连接**；主机其它转发/服务零影响
  - 已建立连接交给 conntrack（规则只匹配 ct state new），不会误伤回程
  - nft 下发走单次事务 `add table -> delete table -> 重新定义`，原子且幂等
    （这是 nft 老版本也支持的原子重载写法；`add+flush` 在旧版会因"表不存在"整体回滚）
  - 所有外部命令数组传参，不经 shell，防注入

兼容性：
  - 已在 nftables v0.8（CentOS 7.9）验证：需用**数字**优先级 `priority 0`
    （命名优先级 `priority filter` 不被识别），且不支持 `nft -f -`，故写临时文件再 `-f`

用法：
  vpn-sync.py --once                     跑一轮后退出（systemd timer / 测试）
  vpn-sync.py --interval 30              常驻，每 30s 同步一次
  vpn-sync.py --once --dry-run           只拉取+渲染+打印，不下发
  vpn-sync.py --once --skip-wg           只下发 nft（内核无 WG 模块时用）
  vpn-sync.py --once --skip-nft          只同步 wg peer
"""
from __future__ import print_function

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

WG_MARK_BEG = '# >>> vpn-ctrl managed'
WG_MARK_END = '# <<< vpn-ctrl managed'


def _internal_nets():
    """界定「内网」的网段集合（逗号分隔 CIDR），用于全代理模式区分内/外网。

    外网（不在此集合内的目的 IP）在全代理模式下被放行并经网关 NAT 出口；
    内网目的 IP 依旧受下方 allow/deny 授权约束。可用环境变量 VPN_INTERNAL_NETS
    覆盖（如 '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10'）。
    默认覆盖 RFC1918，适配绝大多数内网部署；若平台纳管的目的地含非 RFC1918 的内网
    段，请显式设置该变量，否则该段会被误判为「外网」而绕过权限控制。"""
    raw = (os.environ.get('VPN_INTERNAL_NETS') or '').strip()
    nets = [x.strip() for x in raw.split(',') if x.strip()] if raw else \
        ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    return ', '.join(nets)


INTERNAL_NETS = _internal_nets()


def log(msg):
    sys.stderr.write('[vpn-sync] %s\n' % msg)
    sys.stderr.flush()


def run_cmd(argv, input_bytes=None, check=True):
    """数组传参执行外部命令，可选喂 stdin。不经过 shell。"""
    p = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = p.communicate(input_bytes)
    out_s = out.decode('utf-8', 'replace') if out else ''
    err_s = err.decode('utf-8', 'replace') if err else ''
    if check and p.returncode != 0:
        raise RuntimeError('命令失败(%d): %s\n%s' % (p.returncode, ' '.join(argv), err_s))
    return p.returncode, out_s, err_s


def http_get(base, path, token):
    req = urllib.request.Request(
        base.rstrip('/') + path,
        headers={'x-ingest-token': token} if token else {},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode('utf-8'))


def load_json_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def fetch_peers(args):
    d = load_json_file(args.peers_file) if args.peers_file else http_get(args.base, '/api/gateway/peers', args.token)
    return d.get('peers', []) if isinstance(d, dict) else d


def fetch_grants(args):
    d = load_json_file(args.grants_file) if args.grants_file else http_get(args.base, '/api/gateway/grants', args.token)
    return d.get('users', []) if isinstance(d, dict) else d


def render_wg_block(peers):
    parts = []
    for v in peers:
        parts.append('# %s %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32'
                     % (v.get('name', ''), v.get('vpn_ip', ''),
                        v.get('pubkey', ''), v.get('vpn_ip', '')))
    body = '\n\n'.join(parts) if parts else '# (no active peer)'
    return '%s\n%s\n%s' % (WG_MARK_BEG, body, WG_MARK_END)


PORT_SPEC_RE = re.compile(r'^[0-9,\-]+$')


def _protos(raw):
    """协议可多选：'TCP' / 'UDP' / 'TCP,UDP' -> ['tcp'] / ['udp'] / ['tcp','udp']（非法值丢弃，兜底 tcp）"""
    ps = [p.strip().lower() for p in str(raw or 'TCP').split(',') if p.strip()]
    ps = [p for p in ps if p in ('tcp', 'udp')]
    return ps or ['tcp']


def _port_match(spec):
    """把端口规格转成 nft 匹配片段（返回前缀，含前导空格）。

    '' 或 None  -> ' dport { 1-65535 }'  表示全部端口（显式全端口；避免光秃秃的 `tcp` 紧挨 `ct` 被旧版 nft 报 syntax error）
    '9,100-200' -> ' dport { 9, 100-200 }'
    非法字符     -> None          调用方跳过该条
    """
    spec = ('' if spec is None else str(spec)).strip()
    if not spec:
        return ' dport { 1-65535 }'
    if not PORT_SPEC_RE.match(spec):
        return None
    segs = [s.strip() for s in spec.split(',') if s.strip()]
    if not segs:
        return ''
    return ' dport { %s }' % ', '.join(segs)


def _daddr(a):
    """目的地 -> nft「ip daddr」匹配值。

    优先用服务端展开好的 cidrs（单机 / 末位0整段 / 掩码 / 区间 / 逗号组合 → CIDR 列表），
    多目标时生成 nft 集合 { a, b, c }；无 cidrs 时退回旧字段 ip（单值），兼容旧版 grants。
    返回 None 表示该条目无有效地址，调用方应跳过。
    """
    cs = a.get('cidrs')
    if not cs:
        cs = [a.get('ip')] if a.get('ip') else []
    cs = [str(c).strip() for c in cs if str(c or '').strip()]
    if not cs:
        return None
    return cs[0] if len(cs) == 1 else '{ %s }' % ', '.join(cs)


def render_nft(iface, users, log_limit=None):
    """生成完整 nftables 执行规则集（单事务原子重载）。返回 (文本, 放行规则数)。

    两种模式（来自 grants 的 mode 字段）：
      allow（白名单，默认）：仅放行 allow 清单内的 (目的IP:端口/协议)；其余默认拒绝。
      deny （黑名单）      ：先 drop deny 清单内的目的地，再对该用户来源 IP 兜底 accept 全部，
                             即「默认放行全部网段，仅禁止清单内目的地」。

    注释一律 ASCII：避免网关 locale 非 UTF-8 时 nft 解析异常。
    """
    lim = (' limit rate %s' % log_limit) if log_limit else ''
    L = []
    L.append('add table inet vpnflow')
    L.append('delete table inet vpnflow')
    L.append('table inet vpnflow {')
    L.append('    chain forward {')
    L.append('        type filter hook forward priority 0; policy accept;')
    L.append('')
    L.append('        # non-wg0 traffic: pass through untouched (host unaffected)')
    L.append('        iifname != "%s" return' % iface)
    L.append('')
    L.append('        # ==== generated by vpn-sync from /api/gateway/grants ====')
    n = 0
    for u in users:
        ip = u.get('vpn_ip')
        if not ip:
            continue
        mode = u.get('mode', 'allow')
        if mode == 'deny':
            # 黑名单：先显式禁止 deny 清单目的地，再兜底放行该用户全部新连接
            deny = u.get('deny') or []
            L.append('        # %s (%s) BLACKLIST: deny %d dest, then accept all'
                     % (u.get('name', ''), ip, len(deny)))
            for a in deny:
                pm = _port_match(a.get('ports', a.get('port', '')))
                if pm is None:
                    log('skip bad port spec: %r' % (a.get('ports', a.get('port', '')),))
                    continue
                da = _daddr(a)
                if da is None:
                    log('skip empty dest: %r' % (a,))
                    continue
                for proto in _protos(a.get('proto')):
                    L.append('        iifname "%s" ip saddr %s ip daddr %s %s%s '
                             'ct state new log prefix "vpn-flow DENY "%s drop'
                             % (iface, ip, da, proto, pm, lim))
                    n += 1
            L.append('        iifname "%s" ip saddr %s ct state new log prefix "vpn-flow ALLOW "%s accept'
                     % (iface, ip, lim))
            n += 1
        else:
            allow = u.get('allow') or []
            # 无授权且非全代理 -> 该用户整体上无任何放行，交由文末默认拒绝处理
            if not allow and not u.get('full_proxy'):
                continue
            L.append('        # %s (%s) allow %d%s'
                     % (u.get('name', ''), ip, len(allow),
                        ' + FULL-PROXY' if u.get('full_proxy') else ''))
            for a in allow:
                pm = _port_match(a.get('ports', a.get('port', '')))
                if pm is None:
                    log('skip bad port spec: %r' % (a.get('ports', a.get('port', '')),))
                    continue
                da = _daddr(a)
                if da is None:
                    log('skip empty dest: %r' % (a,))
                    continue
                for proto in _protos(a.get('proto')):
                    L.append('        iifname "%s" ip saddr %s ip daddr %s %s%s '
                             'ct state new log prefix "vpn-flow ALLOW "%s accept'
                             % (iface, ip, da, proto, pm, lim))
                    n += 1
            if u.get('full_proxy'):
                # 全代理：内网目的地（INTERNAL_NETS 之内）仍受上方 allow 清单约束；
                # 其余（外网）一律放行，并由网关既有 wg0->WAN masquerade 做 NAT 出口。
                L.append('        # %s (%s) FULL-PROXY: external (non-internal) accepted+NAT'
                         % (u.get('name', ''), ip))
                L.append('        iifname "%s" ip saddr %s ip daddr != { %s } ct state new '
                         'log prefix "vpn-flow ALLOW "%s accept'
                         % (iface, ip, INTERNAL_NETS, lim))
                n += 1
    L.append('')
    L.append('        # ==== default deny: unauthorized new conn, log + drop ====')
    L.append('        iifname "%s" ct state new log prefix "vpn-flow DENY "%s drop' % (iface, lim))
    L.append('    }')
    L.append('}')
    return '\n'.join(L) + '\n', n


def replace_managed_block(cur, block):
    rex = re.compile(re.escape(WG_MARK_BEG) + r'[\s\S]*?' + re.escape(WG_MARK_END))
    if rex.search(cur):
        return rex.sub(lambda m: block, cur)
    return cur.rstrip('\n') + ('\n\n' if cur.strip() else '') + block + '\n'


def apply_wg(args, block):
    conf = args.wg_conf
    cur = ''
    if os.path.exists(conf):
        with open(conf, 'r', encoding='utf-8') as f:
            cur = f.read()
    new = replace_managed_block(cur, block)
    if new == cur:
        log('wg 配置无变化，跳过热加载')
        return
    tmp = conf + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(new)
    os.chmod(tmp, 0o600)
    os.replace(tmp, conf)
    _, stripped, _ = run_cmd(['wg-quick', 'strip', args.iface])
    run_cmd(['wg', 'syncconf', args.iface, '/dev/stdin'], input_bytes=stripped.encode())
    log('已热加载 %d 个 peer 到 %s' % (block.count('[Peer]'), args.iface))


def apply_nft(text):
    """老版 nft 不支持 `nft -f -`，写临时文件再 -f。"""
    fd, path = tempfile.mkstemp(prefix='vpnflow-', suffix='.nft')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        run_cmd(['nft', '-f', path])
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def write_ip2name(args, users):
    m = {}
    for u in users:
        if u.get('vpn_ip') and u.get('name'):
            m[u['vpn_ip']] = u['name']
    try:
        if not os.path.isdir(args.state_dir):
            os.makedirs(args.state_dir)
    except Exception:
        pass
    path = os.path.join(args.state_dir, 'ip2name.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(m, f, ensure_ascii=False, indent=2)


def sync_once(args):
    peers = fetch_peers(args)
    users = fetch_grants(args)
    log('拉取到 peers=%d users=%d' % (len(peers), len(users)))
    block = None if args.skip_wg else render_wg_block(peers)
    nft_text, rule_n = render_nft(args.iface, users, args.log_limit)

    if args.emit_wg and block is not None:
        with open(args.emit_wg, 'w', encoding='utf-8') as f:
            f.write(block + '\n')
    if args.emit_nft:
        with open(args.emit_nft, 'w', encoding='utf-8') as f:
            f.write(nft_text)

    if args.dry_run:
        log('dry-run：不下发（将生成 %d 条放行规则 + 1 条默认拒绝）' % rule_n)
        sys.stdout.write(nft_text)
        if block is not None:
            sys.stdout.write('\n' + block + '\n')
        return

    if block is not None:
        apply_wg(args, block)
    if not args.skip_nft:
        apply_nft(nft_text)
        log('已下发 nftables 执行面（%d 条放行 + 1 条默认拒绝）' % rule_n)
    try:
        write_ip2name(args, users)
    except Exception as e:
        log('写 ip2name.json 失败：%s' % e)


def main():
    ap = argparse.ArgumentParser(description='vpn-sync 网关执行面 agent')
    ap.add_argument('--base', default=os.environ.get('VPN_BASE', 'http://127.0.0.1:8787'))
    ap.add_argument('--token', default=os.environ.get('INGEST_TOKEN', ''))
    ap.add_argument('--iface', default=os.environ.get('WG_IFACE', 'wg0'))
    ap.add_argument('--wg-conf', dest='wg_conf', default=os.environ.get('WG_CONF', '/etc/wireguard/wg0.conf'))
    ap.add_argument('--state-dir', dest='state_dir', default=os.environ.get('VPN_SYNC_STATE', '/var/lib/vpn-sync'))
    ap.add_argument('--interval', type=int, default=int(os.environ.get('VPN_SYNC_INTERVAL', '30')))
    ap.add_argument('--once', action='store_true', help='跑一轮后退出')
    ap.add_argument('--dry-run', dest='dry_run', action='store_true')
    ap.add_argument('--skip-wg', dest='skip_wg', action='store_true', help='不下发 wg（内核无 WG 模块时）')
    ap.add_argument('--skip-nft', dest='skip_nft', action='store_true')
    ap.add_argument('--peers-file', dest='peers_file', default=None, help='离线夹具：peers JSON')
    ap.add_argument('--grants-file', dest='grants_file', default=None, help='离线夹具：grants JSON')
    ap.add_argument('--emit-wg', dest='emit_wg', default=None, help='把渲染的 wg 托管块写到该文件（审查用）')
    ap.add_argument('--emit-nft', dest='emit_nft', default=None, help='把生成的 nft 规则集写到该文件（审查用）')
    ap.add_argument('--log-limit', dest='log_limit', default=os.environ.get('VPN_LOG_LIMIT', ''),
                    help='log 限速，如 "50/second"；留空不限速')
    args = ap.parse_args()

    if args.once:
        sync_once(args)
        return
    while True:
        try:
            sync_once(args)
        except Exception as e:
            log('同步失败：%s' % e)
        time.sleep(max(5, args.interval))


if __name__ == '__main__':
    main()
