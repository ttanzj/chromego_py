# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v2.9 - 防死循环最终稳定版
Y系列完全不动
Z系列（sources-j.txt）全部处理 + 防卡死 + 可用性测试
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re
import base64
import socket
import time
from urllib.parse import urlparse, parse_qs

# ==================== 全局防卡死设置 ====================
socket.setdefaulttimeout(15)                    # 全局 socket 超时 15 秒
urllib.request.socket.setdefaulttimeout(15)     # urllib 超时

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
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}|{p.get('network','')}|{p.get('sni','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def test_node_availability(proxy, timeout=8):
    server = proxy.get('server')
    port = int(proxy.get('port', 443))
    if not server:
        return False, 9999
    try:
        start = time.time()
        with socket.create_connection((server, port), timeout=timeout):
            delay = int((time.time() - start) * 1000)
        return True, delay
    except:
        return False, 9999

def preprocess_subscription(data: str):
    content = data.strip()
    if not content:
        return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            return decoded
    except:
        pass
    if any(line.strip().startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')) for line in content.splitlines()[:10]):
        return content
    return content

def parse_general_node(line: str, prefix: str, index: int):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    try:
        if line.startswith('vmess://'):
            b64 = line[8:]
            padding = '=' * (-len(b64) % 4)
            cfg = json.loads(base64.b64decode(b64 + padding).decode('utf-8'))
            p = {
                "name": f"{prefix}GEN-VMESS-{index}",
                "type": "vmess",
                "server": cfg.get("add") or cfg.get("address"),
                "port": int(cfg.get("port", 443)),
                "uuid": cfg.get("id") or cfg.get("uuid"),
                "alterId": cfg.get("aid", 0),
                "cipher": cfg.get("scy", "auto"),
                "tls": cfg.get("tls") in ("tls", "1", True),
                "skip-cert-verify": True,
                "network": cfg.get("net", "tcp"),
                "ws-opts": {"path": cfg.get("path", "/"), "headers": {"Host": cfg.get("host", cfg.get("sni", ""))}} if cfg.get("net") == "ws" else None,
                "sni": cfg.get("sni") or cfg.get("host")
            }
            return p if p.get("server") and p.get("uuid") else None

        elif line.startswith('vless://'):
            url = urlparse(line)
            uuid = url.username or url.path.strip('/')
            q = parse_qs(url.query)
            p = {
                "name": f"{prefix}GEN-VLESS-{index}",
                "type": "vless",
                "server": url.hostname,
                "port": int(url.port or 443),
                "uuid": uuid,
                "tls": q.get("security", [""])[0] in ("tls", "reality"),
                "skip-cert-verify": True,
                "network": q.get("type", ["tcp"])[0],
                "sni": q.get("sni", [""])[0] or q.get("host", [""])[0],
            }
            if p.get("network") == "ws":
                p["ws-opts"] = {"path": q.get("path", ["/"])[0], "headers": {"Host": p["sni"]}}
            return p if p.get("server") and p.get("uuid") else None

        elif line.startswith(('hysteria2://', 'hy2://')):
            url = urlparse(line)
            q = parse_qs(url.query)
            p = {
                "name": f"{prefix}GEN-HY2-{index}",
                "type": "hysteria2",
                "server": url.hostname,
                "port": int(url.port or 443),
                "password": url.username or url.path.strip('/'),
                "sni": q.get("sni", [""])[0],
                "skip-cert-verify": q.get("insecure", ["0"])[0] in ("1", "true")
            }
            return p if p.get("server") and p.get("password") else None

        elif line.startswith('trojan://'):
            url = urlparse(line)
            q = parse_qs(url.query)
            p = {
                "name": f"{prefix}GEN-TROJAN-{index}",
                "type": "trojan",
                "server": url.hostname,
                "port": int(url.port or 443),
                "password": url.username or url.path.strip('/'),
                "sni": q.get("sni", [""])[0],
                "skip-cert-verify": True
            }
            return p if p.get("server") and p.get("password") else None
    except:
        pass
    return None

# ====================== Z系列单链接处理（带重试 + 防卡死） ======================
def process_z_url(url, prefix="Z-"):
    for attempt in range(3):  # 最多重试 3 次
        try:
            logging.info(f"[{attempt+1}/3] 正在处理 Z系列: {url}")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_data = resp.read().decode('utf-8', errors='ignore')

            processed_data = preprocess_subscription(raw_data)
            added = 0

            # 增强解析（vmess/vless/hy2/trojan）
            lines = [line.strip() for line in processed_data.splitlines() if line.strip()]
            for i, line in enumerate(lines):
                node = parse_general_node(line, prefix, i + 1)
                if node and node.get('server'):
                    fp = make_fingerprint(node)
                    if fp in servers_list:
                        continue
                    is_alive, delay = test_node_availability(node, timeout=6)
                    if is_alive and delay <= 1000:
                        node['name'] = f"{node['name']}-{delay}ms"
                        extracted_proxies.append(node)
                        servers_list.append(fp)
                        added += 1

            # 原始逻辑补充
            if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                process_clash(processed_data, prefix)
            else:
                process_json(processed_data, prefix)

            logging.info(f"✓ Z系列处理完成: {url} → 新增可用节点 {added} 个")
            return  # 成功则退出重试

        except Exception as e:
            logging.warning(f"[{attempt+1}/3] 处理失败 {url}: {type(e).__name__} - {e}")
            if attempt < 2:
                time.sleep(3)  # 失败后等待 3 秒再重试
            else:
                logging.error(f"✗ Z系列最终失败 {url}")

# ====================== 原有函数（完全保留） ======================
def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')

                processed_data = preprocess_subscription(raw_data)

                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                    process_clash(processed_data, prefix)
                else:
                    process_json(processed_data, prefix)

                logging.info(f"✓ {prefix}系列 ChromeGo 原逻辑处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ {prefix}系列 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logging.error(f"读取 {file_path} 失败: {e}")

def process_clash(data, prefix):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','unk').upper()}-{i+1}"
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash 处理异常: {e}")

def process_json(data, prefix):
    try:
        content = json.loads(data)
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
            
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                
                if ports_range:
                    final_port = main_port
                    final_ports = ports_range
                    name_suffix = f" ({ports_range})"
                else:
                    final_port = main_port
                    final_ports = None
                    name_suffix = ""

                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                    "type": typ,
                    "server": server,
                    "port": final_port,
                    "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                    "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                    "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                    "skip-cert-verify": content.get('insecure', True),
                    "alpn": content.get('alpn', 'h3')
                }
                
                if final_ports:
                    p['ports'] = final_ports
                
                if typ == "hysteria":
                    p["up"] = content.get('upmbps') or content.get('up') or 100
                    p["down"] = content.get('downmbps') or content.get('down') or 100
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria', 'hysteria2'): continue
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            p = {"server": server, "port": port, "type": proto}
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
            p['name'] = f"{prefix}{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}"
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"JSON 处理异常: {e}")

def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = [p.strip() for p in srv.split(',')]
        main_part = parts[0]
        if len(parts) > 1 and '-' in parts[-1]:
            ports_range = parts[-1]
        srv = main_part

    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logging.info("=== ChromeGo Enhanced v2.9 防死循环版启动 ===")

    # Y系列（完全不动）
    process_file("urls/sources.txt", "Y-")

    # Z系列（全部走防卡死处理）
    try:
        with open("urls/sources-j.txt", 'r', encoding='utf-8') as f:
            z_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        logging.info(f"共发现 {len(z_urls)} 个 Z系列订阅源，开始逐个处理...")
        
        for idx, url in enumerate(z_urls, 1):
            logging.info(f"--- 处理第 {idx}/{len(z_urls)} 个 Z系列源 ---")
            process_z_url(url, "Z-")
            
    except Exception as e:
        logging.error(f"读取 sources-j.txt 失败: {e}")

    logging.info(f"最终共保留 {len(extracted_proxies)} 个节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logging.info("✅ clash_meta.yaml 已生成完成！")
