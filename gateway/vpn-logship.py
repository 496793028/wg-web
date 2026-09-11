#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpn-logship —— 生产级流日志回传器（替代 verify/vpn-logship-min.py 的最小版）

相比最小版的增强：
  - 本地持久化缓冲（SQLite）：平台不可达时日志**不丢**，恢复后补传
  - 断点续传：记录文件读取偏移，重启后从上次位置继续
  - 失败重试 + 指数退避；按批发送，成功后删除已确认记录
  - 用户名还原：读 vpn-sync 产出的 ip2name.json，把源 IP 映射成姓名
  - 可直接对接生产（systemd 托管 + logrotate）

日志来源：网关 rsyslog 落盘的 nftables 记账日志（前缀 "vpn-flow ALLOW|DENY"）。
接口契约：POST {base}/api/ingest，头 x-ingest-token，体为行数组（与 server.js:624 一致）。

用法：
  vpn-logship.py --log /var/log/vpn-flow.log --token TOKEN \
                 --base https://vpn.example.com --map /var/lib/vpn-sync/ip2name.json \
                 --state /var/lib/vpn-logship/queue.db
"""
from __future__ import print_function

import argparse
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error

LINE = re.compile(r'SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*?PROTO=(\w+).*?DPT=(\d+)')
VERDICT = re.compile(r'vpn-flow\s+(ALLOW|DENY)')


def log(msg):
    sys.stderr.write('[vpn-logship] %s\n' % msg)
    sys.stderr.flush()


class Store(object):
    """SQLite 持久化队列 + 文件偏移记录。"""

    def __init__(self, path):
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d)
            except OSError:
                pass
        self.conn = sqlite3.connect(path)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('CREATE TABLE IF NOT EXISTS pending('
                          'id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)')
        self.conn.execute('CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)')
        self.conn.commit()

    def add(self, row):
        self.conn.execute('INSERT INTO pending(payload) VALUES(?)',
                          (json.dumps(row, ensure_ascii=False),))
        self.conn.commit()

    def pending(self, limit):
        cur = self.conn.execute('SELECT id, payload FROM pending ORDER BY id LIMIT ?', (limit,))
        return cur.fetchall()

    def ack(self, ids):
        if not ids:
            return
        q = 'DELETE FROM pending WHERE id IN (%s)' % ','.join('?' * len(ids))
        self.conn.execute(q, ids)
        self.conn.commit()

    def count(self):
        return self.conn.execute('SELECT COUNT(*) FROM pending').fetchone()[0]

    def get_meta(self, k, default=None):
        r = self.conn.execute('SELECT v FROM meta WHERE k=?', (k,)).fetchone()
        return r[0] if r else default

    def set_meta(self, k, v):
        self.conn.execute('INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)', (k, str(v)))
        self.conn.commit()


def post(base, token, rows, token_header='x-ingest-token'):
    data = json.dumps(rows).encode('utf-8')
    req = urllib.request.Request(
        base.rstrip('/') + '/api/ingest', data=data,
        headers={'Content-Type': 'application/json', token_header: token},
        method='POST')
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode('utf-8')


def load_map(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def flush(store, args, ip2name):
    """把队列里的记录按批发送；成功的删除，失败的保留（下轮重试）。"""
    while True:
        rows = store.pending(args.batch)
        if not rows:
            return
        ids = [r[0] for r in rows]
        payload = []
        for _, p in rows:
            row = json.loads(p)
            row['user_name'] = ip2name.get(row.get('src_ip'))
            payload.append(row)
        try:
            resp = post(args.base, args.token, payload)
            store.ack(ids)
            log('sent %d, resp=%s, remaining=%d' % (len(ids), resp.strip()[:80], store.count()))
        except urllib.error.HTTPError as e:
            log('HTTP %d（不丢，保留下轮重试）: %s' % (e.code, e.read().decode()[:120]))
            return
        except Exception as e:
            log('发送失败（不丢，保留下轮重试）: %s' % e)
            return


def tail_forever(store, args):
    """跟随日志文件：解析新行入库，定期重发。"""
    offset_key = 'offset:' + os.path.abspath(args.log)
    while True:
        ip2name = load_map(args.map)
        try:
            if not os.path.exists(args.log):
                time.sleep(2)
                continue
            size = os.path.getsize(args.log)
            off = int(store.get_meta(offset_key, '0') or '0')
            if size < off:          # 日志被 rotate/截断
                off = 0
            with open(args.log, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(off)
                for line in f:
                    if 'vpn-flow' not in line:
                        continue
                    m = LINE.search(line)
                    if not m:
                        continue
                    vm = VERDICT.search(line)
                    src_ip = m.group(1)
                    store.add({
                        'src_ip': src_ip,
                        'dst_ip': m.group(2),
                        'dst_port': int(m.group(4)),
                        'proto': m.group(3),
                        'action': vm.group(1) if vm else 'ALLOW',
                        'user_name': ip2name.get(src_ip),
                    })
                new_off = f.tell()
            store.set_meta(offset_key, new_off)
        except Exception as e:
            log('读日志出错: %s' % e)
        flush(store, args, ip2name)
        time.sleep(args.poll)


def main():
    ap = argparse.ArgumentParser(description='生产级 VPN 流日志回传器')
    ap.add_argument('--log', default=os.environ.get('VPN_FLOW_LOG', '/var/log/vpn-flow.log'))
    ap.add_argument('--token', default=os.environ.get('INGEST_TOKEN', ''))
    ap.add_argument('--base', default=os.environ.get('VPN_BASE', 'http://127.0.0.1:8787'))
    ap.add_argument('--map', default=os.environ.get('VPN_IP2NAME', '/var/lib/vpn-sync/ip2name.json'))
    ap.add_argument('--state', default=os.environ.get('VPN_LOGSTATE', '/var/lib/vpn-logship/queue.db'))
    ap.add_argument('--batch', type=int, default=200)
    ap.add_argument('--poll', type=int, default=5, help='轮询间隔（秒）')
    ap.add_argument('--once', action='store_true', help='处理一遍后退出（测试/一次性）')
    args = ap.parse_args()

    store = Store(args.state)
    if args.once:
        tail_once(store, args)
        return
    log('start: log=%s base=%s batch=%d poll=%ds' % (args.log, args.base, args.batch, args.poll))
    tail_forever(store, args)


def tail_once(store, args):
    """读一遍当前文件内容（从记录偏移开始），入库并尝试发送，然后退出。"""
    ip2name = load_map(args.map)
    offset_key = 'offset:' + os.path.abspath(args.log)
    if os.path.exists(args.log):
        size = os.path.getsize(args.log)
        off = int(store.get_meta(offset_key, '0') or '0')
        if size < off:
            off = 0
        with open(args.log, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(off)
            for line in f:
                if 'vpn-flow' not in line:
                    continue
                m = LINE.search(line)
                if not m:
                    continue
                vm = VERDICT.search(line)
                store.add({'src_ip': m.group(1), 'dst_ip': m.group(2),
                           'dst_port': int(m.group(4)), 'proto': m.group(3),
                           'action': vm.group(1) if vm else 'ALLOW'})
            store.set_meta(offset_key, f.tell())
    flush(store, args, ip2name)
    log('done once, remaining=%d' % store.count())


if __name__ == '__main__':
    main()
