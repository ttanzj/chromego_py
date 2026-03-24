# -*- coding: UTF-8 -*-
"""
最后一版微调 - 按要求处理跳跃端口
有跳跃端口的节点：
  - port  = 跳跃端口范围（如 28000-29000）
  - ports = 主端口（如 27921）
  - 名称最后加上跳跃端口信息
无跳跃端口的节点：正常写入 port
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
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def parse_server_port(srv):
    """返回 (server, main_port, ports_range)"""
    srv = str(srv).strip()
    main_port = 443
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
    return srv, main_port, ports_range

def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')

                if url.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)

                logging.info(f"✓ {prefix}系列 处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ {prefix}系列 处理失败 {url}: {e}")
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
            typ = "hysteria2" if "hysteria2" in str(content).lower() else "hysteria"
            
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                
                # ==================== 按你的要求处理跳跃端口 ====================
                if ports_range:
                    # 有跳跃端口：port = 跳跃范围，ports = 主端口
                    final_port = ports_range
                    final_ports = str(main_port)
                    name_suffix = f" ({ports_range})"
                else:
                    # 无跳跃端口：正常写入 port
                    final_port = main_port
                    final_ports = None
                    name_suffix = ""

                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                    "type": typ,
                    "server": server,
                    "port": final_port,           # 按要求：有跳跃端口时写入跳跃范围
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

        # outbounds 处理（保留基本支持）
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

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    logging.info("=== 开始提取节点 ===")
    process_file("urls/sources.txt", "Y-")
    process_file("urls/sources-j.txt", "Z-")

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logging.info("✅ clash_meta.yaml 已成功生成！")
