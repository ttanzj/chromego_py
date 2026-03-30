#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5 - 纯 Y 系列版（最终平衡优化版）
- 完整支持 Clash YAML（Alvin9999 来源）
- 完整支持 Xray/V2Ray JSON（vless reality + xtls）
- 支持纯 vless:// 直链
- 保留 hy1/hy2 完整处理
- 增强 sni 去重 + 去除 Y- 前缀
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

servers_list: list[str] = []
extracted_proxies: list[dict] = []

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
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('servername','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content:
        return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        return decoded
    except:
        return content

# ====================== vless:// 直链解析 ======================
def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith('vless://'): return None
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
            p['reality-opts'] = {"public-key": params.get('pbk', [''])[0], "short-id": params.get('sid', [''])[0]}
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except:
        return None

# ====================== Xray/V2Ray JSON 处理（vless Reality） ======================
def process_json(data: str):
    try:
        content = json.loads(data)
        count = 0
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or '').lower()
            if proto != 'vless': continue

            settings = ob.get('settings', {})
            vnext = settings.get('vnext', [{}])[0]
            server = vnext.get('address')
            port = int(vnext.get('port', 443))
            if not server: continue

            user = vnext.get('users', [{}])[0]
            stream = ob.get('streamSettings', {})
            reality = stream.get('realitySettings', {}) or stream.get('xtlsSettings', {})

            p = {
                "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": user.get('id'),
                "flow": user.get('flow', ''),
                "network": stream.get('network', 'tcp'),
                "tls": stream.get('security') in ('tls', 'reality', 'xtls'),
                "sni": reality.get('serverName') or stream.get('serverName') or '',
                "client-fingerprint": reality.get('fingerprint', 'chrome'),
            }

            if stream.get('security') == 'reality':
                p['reality-opts'] = {
                    "public-key": reality.get('publicKey', ''),
                    "short-id": reality.get('shortId', '')
                }

            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
                count += 1
        if count > 0:
            logger.info(f"从 Xray JSON 提取 {count} 个 vless 节点")
    except:
        pass

# ====================== Hysteria 处理 ======================
def process_hysteria(content: dict):
    # 此处保留你原来的 hysteria 处理逻辑，简化版
    servers = content.get('server') or content.get('servers', [])
    if isinstance(servers, str): servers = [servers]
    typ = "hysteria2" if "hysteria2" in str(content).lower() else "hysteria"
    for i, s in enumerate(servers):
        if not s: continue
        server, port, ports_range = parse_server_port(s)
        name_suffix = f" ({ports_range})" if ports_range else ""
        p = {
            "name": f"{get_location(server)}-{typ.upper()}-{len(extracted_proxies)+1}{name_suffix}",
            "type": typ,
            "server": server,
            "port": port,
            "password": content.get('auth') or content.get('password', ''),
            "sni": content.get('sni') or content.get('server_name', ''),
            "skip-cert-verify": content.get('insecure', True),
            "alpn": content.get('alpn', ["h3"]) if isinstance(content.get('alpn'), list) else ["h3"],
        }
        if typ == "hysteria":
            p["up"] = content.get('upmbps') or 100
            p["down"] = content.get('downmbps') or 100
        if ports_range:
            p['ports'] = ports_range

        fp = make_fingerprint(p)
        if fp not in servers_list:
            extracted_proxies.append(p)
            servers_list.append(fp)

# ====================== Clash 处理（完整保留字段） ======================
def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        count = 0
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue

            original_name = p.get('name', '')
            if original_name.startswith('Y-'):
                p['name'] = original_name[2:]
            else:
                loc = get_location(p.get('server'))
                node_type = p.get('type', 'unk').upper()
                p['name'] = f"{loc}-{node_type}-{i+1}"

            extracted_proxies.append(p)
            servers_list.append(fp)
            count += 1
        logger.info(f"从 Clash 提取 {count} 个节点")
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

# ====================== 辅助函数 ======================
def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = [p.strip() for p in srv.split(',')]
        main_part = parts[0]
        if len(parts) > 1 and '-' in parts[-1]:
            ports_range = parts[-1]
        srv = main_part
    if ':' in srv and srv.rsplit(':', 1)[1].isdigit():
        host, port = srv.rsplit(':', 1)
        return host.strip('[]'), int(port), ports_range
    return srv, 443, ports_range

# ====================== 主流程 ======================
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

                # vless 直链
                added = any(parse_vless_link(line) and (extracted_proxies.append(parse_vless_link(line)) or True) 
                          for line in lines if line.startswith('vless://'))

                if added:
                    logger.info(f"✓ vless:// 直链提取成功: {url}")
                    continue

                # 主处理
                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed:
                    process_clash(processed)
                else:
                    try:
                        content = json.loads(processed)
                        if 'outbounds' in content:
                            process_json(processed)
                        else:
                            process_hysteria(content)
                    except:
                        pass

                logger.info(f"✓ 处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取文件失败: {e}")

# ====================== 启动 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.5 最终平衡版启动 ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成 → outputs/clash_meta.yaml")
