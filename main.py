# -*- coding: UTF-8 -*-
"""
2026 最终优化版 - 重点修复 hy2 跳跃端口 28000-29000 + 最大化保留原有节点
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logging.warning("GeoLite2-City.mmdb 未找到")

def get_location(ip):
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city.replace(' ', '')}" if city else c
    except:
        return "UNK"

def make_fingerprint(p):
    # 加入 ports 信息，避免跳跃端口节点被误判重复
    key = f"{p.get('server')}|{p.get('port')}|{p.get('ports')}|{p.get('type')}|{p.get('uuid') or p.get('password') or p.get('auth_str')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def normalize_proxy(raw: dict) -> dict:
    p = dict(raw)

    # === sing-box vnext 处理（修复前两个节点 server:null）===
    if isinstance(p.get('settings'), dict) and isinstance(p['settings'].get('vnext'), list):
        vnext = p['settings']['vnext'][0]
        p['server'] = vnext.get('address') or vnext.get('server')
        p['port'] = vnext.get('port')
        if isinstance(vnext.get('users'), list) and vnext['users']:
            user = vnext['users'][0]
            p['uuid'] = user.get('id')
            p['flow'] = user.get('flow')

    if isinstance(p.get('streamSettings'), dict):
        stream = p['streamSettings']
        p['network'] = stream.get('network')
        if stream.get('security') == 'reality' and isinstance(stream.get('realitySettings'), dict):
            r = stream['realitySettings']
            p['tls'] = True
            p['servername'] = r.get('serverName')
            p['client-fingerprint'] = r.get('fingerprint', 'chrome')
            p['reality-opts'] = {
                'public-key': r.get('publicKey'),
                'short-id': r.get('shortId', '')
            }
            p.setdefault('flow', 'xtls-rprx-vision')

    # === 通用字段映射 ===
    p.setdefault('server', p.get('address') or p.get('server') or p.get('server_addr'))
    p.setdefault('port', p.get('port') or p.get('server_port') or 443)
    p.setdefault('uuid', p.get('uuid') or p.get('id'))
    p.setdefault('password', p.get('password') or p.get('auth') or p.get('auth_str'))
    p.setdefault('auth_str', p.get('auth_str') or p.get('auth') or p.get('password'))
    p.setdefault('servername', p.get('servername') or p.get('sni') or p.get('peer') or p.get('server_name'))
    p.setdefault('skip-cert-verify', p.get('skip-cert-verify') or p.get('insecure', True))
    p.setdefault('udp', True)

    typ = (p.get('type') or p.get('protocol') or '').lower().strip()
    if typ:
        p['type'] = typ

    # === 重点修复：跳跃端口处理（hy2 28000-29000）===
    ports_str = None
    if isinstance(p.get('server'), str) and (',' in p['server'] or '-' in p['server']):
        server_part, port_part, ports_str = parse_server_port(p['server'])
        p['server'] = server_part
        if port_part:
            p['port'] = port_part
    if not ports_str:
        ports_str = p.get('ports') or p.get('portRange') or p.get('port_range')

    if ports_str:
        p['ports'] = str(ports_str).strip()
        p.pop('portRange', None)
        p.pop('port_range', None)

    # === Hysteria / Hysteria2 标准化 ===
    if typ == 'hysteria':
        p['auth_str'] = p.get('auth_str') or p.get('password', '')
        up_val = p.get('up_mbps') or p.get('up') or 100
        down_val = p.get('down_mbps') or p.get('down') or 100
        p['up'] = f"{up_val} Mbps".replace(' Mbps Mbps', ' Mbps')
        p['down'] = f"{down_val} Mbps".replace(' Mbps Mbps', ' Mbps')
        p.setdefault('alpn', ['h3'])
    elif typ == 'hysteria2':
        p['password'] = p.get('password') or p.get('auth_str', '')
        up_val = p.get('up_mbps') or p.get('up') or 55
        down_val = p.get('down_mbps') or p.get('down') or 55
        p['up'] = f"{up_val} Mbps".replace(' Mbps Mbps', ' Mbps')
        p['down'] = f"{down_val} Mbps".replace(' Mbps Mbps', ' Mbps')
        p.setdefault('alpn', ['h3'])

    # === 清理无效字段 ===
    for k in ['tag', 'settings', 'streamSettings', 'mux', 'up_mbps', 'down_mbps']:
        p.pop(k, None)
    for k in list(p.keys()):
        if p[k] is None or p[k] == '':
            p.pop(k, None)

    # === 2026 最新规则补全 ===
    if typ in ('vless', 'vmess'):
        p.setdefault('client-fingerprint', 'chrome')
    if typ == 'tuic':
        p.setdefault('udp-relay-mode', 'native')
        p.setdefault('congestion-controller', 'bbr')
    if p.get('reality-opts') or p.get('tls') is True:
        p.setdefault('client-fingerprint', 'chrome')

    if typ == 'vless' and p.get('reality-opts'):
        p.setdefault('smux', {'enabled': True, 'protocol': 'h2mux', 'max-connections': 1, 'min-streams': 4, 'padding': True})
        p.setdefault('brutal-opts', {'enabled': True, 'up': 50, 'down': 100})

    if isinstance(p.get('alpn'), str):
        p['alpn'] = [p['alpn']]
    elif not p.get('alpn'):
        p['alpn'] = ['h3']

    return p


def parse_server_port(srv):   # 专门用于跳跃端口解析
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv or '-' in srv:
        parts = [p.strip() for p in re.split(r'[,]', srv)]
        main = parts[0]
        if len(parts) > 1 and re.search(r'\d+-\d+', parts[-1]):
            ports_range = parts[-1]
        srv = main
    # IPv6
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range


# ==================== 下面三个函数基本不变 ====================
def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                if url.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)
                logging.info(f"✓ {prefix}系列 处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 {file_path} 失败: {e}")

def process_clash(data, prefix):
    content = yaml.safe_load(data)
    proxies = content.get('proxies', []) or content.get('proxy', [])
    for i, raw in enumerate(proxies):
        if not isinstance(raw, dict):
            continue
        p = normalize_proxy(raw)
        if not p.get('server'):
            continue
        fp = make_fingerprint(p)
        if fp in servers_list:
            continue
        p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','UNK').upper()}-{i+1}"
        extracted_proxies.append(p)
        servers_list.append(fp)

def process_json(data, prefix):
    content = json.loads(data)
    items = content.get('outbounds', []) or content.get('proxies', []) or [content]
    for i, raw in enumerate(items):
        if not isinstance(raw, dict):
            continue
        p = normalize_proxy(raw)
        if not p.get('server'):
            continue
        fp = make_fingerprint(p)
        if fp in servers_list:
            continue
        p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','UNK').upper()}-{i+1}"
        extracted_proxies.append(p)
        servers_list.append(fp)

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logging.info("=== 2026 最终优化版（重点修复跳跃端口）开始提取 ===")
    
    process_file("urls/sources.txt", "Y-")
    process_file("urls/sources-j.txt", "Z-")

    logging.info(f"✅ 总共提取到 {len(extracted_proxies)} 个有效节点（已恢复 hy2 跳跃端口节点）")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    logging.info("🎉 输出完成：outputs/clash_meta.yaml")
