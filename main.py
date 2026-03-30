#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5 - 纯 Y 系列版（vless 提取加强版）
- 增强去重逻辑（支持 sni）
- 去除 "Y-" 前缀
- 修复 hy1 alpn 丢失问题
- 加强 vless 节点提取（支持 sing-box JSON + 纯 vless:// 链接）
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

# ==================== 全局设置 ====================
socket.setdefaulttimeout(15)
urllib.request.socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []          # 全局去重指纹
extracted_proxies: list[dict] = []    # 最终节点列表

geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到，位置信息将显示 UNK")

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

def make_fingerprint(p: dict) -> str:
    """增强版指纹去重"""
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('servername','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def preprocess_subscription(data: str) -> str:
    """预处理订阅内容"""
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
    return content

# ====================== 解析单条 vless:// 链接 ======================
def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith('vless://'):
            return None
        url = urlparse(link)
        uuid = url.username
        server = url.hostname
        port = int(url.port) if url.port else 443
        
        params = parse_qs(url.query)
        
        p = {
            "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', ['none'])[0] in ('tls', 'reality'),
            "sni": params.get('sni', [''])[0] or params.get('serverName', [''])[0],
            "flow": params.get('flow', [''])[0],
            "client-fingerprint": params.get('fp', ['chrome'])[0],
        }
        
        if params.get('security', [''])[0] == 'reality':
            p['reality-opts'] = {
                "public-key": params.get('pbk', [''])[0],
                "short-id": params.get('sid', [''])[0]
            }
        
        # 清理空值
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except:
        return None

# ====================== 处理函数 ======================
def process_file(file_path: str):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
       
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')
                
                processed = preprocess_subscription(raw_data)
                lines = [line.strip() for line in processed.splitlines() if line.strip()]
                
                added = False
                # 优先处理纯 vless:// 链接
                for line in lines:
                    if line.startswith('vless://'):
                        proxy = parse_vless_link(line)
                        if proxy:
                            fp = make_fingerprint(proxy)
                            if fp not in servers_list:
                                extracted_proxies.append(proxy)
                                servers_list.append(fp)
                                added = True
                
                if added:
                    logger.info(f"✓ 从 vless:// 链接提取节点: {url}")
                    continue
                
                # 原有 Clash / JSON 处理逻辑
                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed or 'proxy:' in processed:
                    process_clash(processed)
                else:
                    process_json(processed)
                
                logger.info(f"✓ 订阅源处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
           
            original_name = p.get('name', '')
            if original_name.startswith('Y-'):
                new_name = original_name[2:]
            else:
                loc = get_location(p.get('server'))
                node_type = p.get('type', 'unk').upper()
                new_name = f"{loc}-{node_type}-{i+1}"
           
            p['name'] = new_name
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str):
    try:
        content = json.loads(data)
        
        # Hysteria 系列处理
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str):
                servers = [servers]
           
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
           
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                name_suffix = f" ({ports_range})" if ports_range else ""
                
                if typ == "hysteria":
                    alpn = content.get('alpn')
                    if isinstance(alpn, str):
                        alpn = [alpn]
                    elif not alpn:
                        alpn = ["h3"]
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": content.get('insecure', True),
                        "alpn": alpn,
                        "up": content.get('upmbps') or content.get('up') or 100,
                        "down": content.get('downmbps') or content.get('down') or 100,
                    }
                else:
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": content.get('insecure', True),
                        "alpn": content.get('alpn', ["h3"]),
                    }
                
                if ports_range:
                    p['ports'] = ports_range
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # vless / vmess / trojan 处理
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): 
                continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria', 'hysteria2'): 
                continue
                
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: 
                continue
                
            port = int(settings.get('port', 443))
            
            p = {
                "name": f"{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}",
                "type": proto,
                "server": server,
                "port": port,
            }
            
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
                p['flow'] = settings.get('flow', '')
                p['network'] = settings.get('network', 'tcp')
                security = settings.get('security', '')
                p['tls'] = security in ('tls', 'reality')
                p['sni'] = settings.get('serverName') or settings.get('sni') or ''
                p['client-fingerprint'] = settings.get('fingerprint', 'chrome')
                if security == 'reality':
                    p['reality-opts'] = {
                        "public-key": settings.get('publicKey', ''),
                        "short-id": settings.get('shortId', '')
                    }
            
            elif proto == 'vmess':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
                p['alterId'] = settings.get('alterId', 0)
                p['network'] = settings.get('network', 'tcp')
                p['tls'] = settings.get('security') == 'tls'
                p['sni'] = settings.get('serverName') or settings.get('sni') or ''
            
            elif proto == 'trojan':
                p['password'] = settings.get('password')
                p['sni'] = settings.get('serverName') or settings.get('sni') or ''
                p['tls'] = True
            
            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
            
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
                
    except Exception:
        pass   # 非标准JSON时跳过（已由链接解析处理）

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
    logger.info("=== ChromeGo Enhanced v3.5 vless加强版启动 ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成！输出文件 → outputs/clash_meta.yaml")
