# -*- coding: UTF-8 -*-
"""
Final Fixed Version - 2026-03-24
强制更新 clash_meta.yaml + base64.txt + vless_subscription.txt
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import base64
import hashlib
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logging.warning("GeoLite2-City.mmdb not found")

def get_location(ip):
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

def make_fingerprint(p):
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def normalize_name(p, idx, sub_idx):
    return f"{get_location(p.get('server'))}-{p.get('type','unk').upper()}-{idx+1}-{sub_idx+1}"

def parse_server_port(srv):
    srv = str(srv).strip()
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2))
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    return srv, 443

def process_urls(file_path, processor, name):
    before = len(extracted_proxies)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for i, url in enumerate(urls):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as r:
                    data = r.read().decode('utf-8', errors='ignore')
                processor(data, i)
            except Exception as e:
                logging.error(f"✗ {name} 失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 {name} 文件失败: {e}")
    logging.info(f"{name} 本次新增节点: {len(extracted_proxies) - before}")

# ==================== 处理器 ====================

def process_clash_meta(data, index):
    try:
        c = yaml.safe_load(data)
        proxies = c.get('proxies', []) or c.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            p['name'] = normalize_name(p, index, i)
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash Meta 处理异常 {index}: {e}")

def process_hysteria(data, index):
    try:
        c = json.loads(data)
        servers = c.get('server') or c.get('servers', [])
        if isinstance(servers, str): servers = [servers]
        for i, s in enumerate(servers):
            if not s: continue
            server, port = parse_server_port(s)
            p = {
                "name": normalize_name({"server": server, "type": "hysteria"}, index, i),
                "type": "hysteria", "server": server, "port": port,
                "auth-str": c.get('auth_str') or c.get('auth', ''), 
                "up": 80, "down": 100, "sni": c.get('sni', ''), 
                "skip-cert-verify": True
            }
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria 处理异常 {index}: {e}")

def process_hysteria2(data, index):
    try:
        c = json.loads(data)
        s = c.get('server', '')
        if not s: return
        server, port = parse_server_port(s)
        p = {
            "name": normalize_name({"server": server, "type": "hysteria2"}, index, 0),
            "type": "hysteria2", "server": server, "port": port,
            "password": c.get('auth') or c.get('password', ''),
            "sni": (c.get('tls') or {}).get('sni', ''),
            "skip-cert-verify": True
        }
        fp = make_fingerprint(p)
        if fp not in servers_list:
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria2 处理异常 {index}: {e}")

def process_xray_singbox(data, index):
    try:
        c = json.loads(data)
        outs = c.get('outbounds', []) or c.get('proxies', [])
        for i, ob in enumerate(outs):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'shadowsocks'): continue
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            p = {"server": server, "port": port, "type": proto}
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
            elif proto == 'ss':
                p['password'] = settings.get('password')
                p['cipher'] = settings.get('method', 'aes-256-gcm')
            p['name'] = normalize_name(p, index, i)
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Xray/Sing-box 处理异常 {index}: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    logging.info("=== 开始提取节点 ===")

    process_urls("urls/clash_meta_urls.txt", process_clash_meta, "Clash Meta")
    process_urls("urls/hysteria_urls.txt", process_hysteria, "Hysteria")
    process_urls("urls/hysteria2_urls.txt", process_hysteria2, "Hysteria2")
    process_urls("urls/xray_urls.txt", process_xray_singbox, "Xray")
    process_urls("urls/singbox_urls.txt", process_xray_singbox, "Sing-box")
    process_urls("urls/ss_urls.txt", process_xray_singbox, "SS")

    total = len(extracted_proxies)
    logging.info(f"总共提取到 {total} 个有效节点")

    # ==================== 强制更新全部 3 个文件 ====================

    # 1. clash_meta.yaml
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logging.info("✅ clash_meta.yaml 已更新")

    # 2. base64.txt
    all_links = []
    for p in extracted_proxies:
        typ = p.get('type', '').lower()
        name = p.get('name', 'node')
        if typ == 'vless':
            link = (f"vless://{p.get('uuid')}@{p['server']}:{p['port']}?"
                    f"type={p.get('network','tcp')}&security={'tls' if p.get('tls') else 'none'}"
                    f"&sni={p.get('servername','')}&fp=chrome&alpn=h3,http/1.1&allowInsecure=1"
                    f"#{name}")
            all_links.append(link)
        elif typ == 'hysteria2':
            link = f"hysteria2://{p.get('password')}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
            all_links.append(link)
        elif typ == 'hysteria':
            link = f"hy://{p.get('auth-str', p.get('password', ''))}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
            all_links.append(link)
        elif typ == 'ss':
            userinfo = f"{p.get('cipher', 'aes-256-gcm')}:{p.get('password')}"
            link = f"ss://{base64.b64encode(userinfo.encode()).decode()}@{p['server']}:{p['port']}#{name}"
            all_links.append(link)

    with open("outputs/base64.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))
    logging.info(f"✅ base64.txt 已更新 ({len(all_links)} 条链接)")

    # 3. vless_subscription.txt（单个 base64 订阅）
    vless_links = [ln for ln in all_links if ln.startswith("vless://")]
    with open("outputs/vless_subscription.txt", "w", encoding="utf-8") as f:
        if vless_links:
            encoded = base64.b64encode("\n".join(vless_links).encode()).decode()
            f.write(encoded)
            logging.info(f"✅ vless_subscription.txt 已更新 ({len(vless_links)} 条 VLESS)")
        else:
            f.write("")
            logging.info("ℹ️ vless_subscription.txt 为空（无 VLESS 节点）")

    logging.info("=== 全部 3 个输出文件已强制更新完成 ===")
