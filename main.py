#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5 - 纯 Y 系列版（vless Reality + Xray 完整适配版）
- 完整支持 Alvin9999 来源的 Clash YAML
- 完整支持 Xray/V2Ray JSON 配置（vnext + streamSettings）
- 支持纯 vless:// 直链
- 增强 sni 去重 + 去除 Y- 前缀 + hy1 alpn 修复
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

# ====================== 解析 vless:// 直链 ======================
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
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except:
        return None

# ====================== 加强版 Xray/V2Ray JSON 处理（关键修复） ======================
def process_json(data: str):
    try:
        content = json.loads(data)
        count = 0
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict):
                continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto != 'vless':
                continue

            # 处理 vnext 结构（你提供的配置就是这种）
            vnext = ob.get('settings', {}).get('vnext', [{}])[0]
            server = vnext.get('address')
            port = int(vnext.get('port', 443))
            if not server:
                continue

            user = vnext.get('users', [{}])[0]

            stream = ob.get('streamSettings', {})
            reality = stream.get('realitySettings', {})

            p = {
                "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": user.get('id'),
                "flow": user.get('flow', ''),
                "network": stream.get('network', 'tcp'),
                "tls": stream.get('security') in ('tls', 'reality'),
                "sni": reality.get('serverName') or stream.get('serverName') or '',
                "client-fingerprint": reality.get('fingerprint', 'chrome'),
            }

            if stream.get('security') == 'reality':
                p['reality-opts'] = {
                    "public-key": reality.get('publicKey', ''),
                    "short-id": reality.get('shortId', '')
                }

            # 清理空值
            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}

            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
                count += 1

        if count > 0:
            logger.info(f"从 Xray JSON 提取 {count} 个 vless 节点")
    except Exception as e:
        pass  # 非 JSON 或解析失败时静默跳过

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
                new_name = original_name[2:]
            else:
                loc = get_location(p.get('server'))
                node_type = p.get('type', 'unk').upper()
                new_name = f"{loc}-{node_type}-{i+1}"
            
            p['name'] = new_name
            extracted_proxies.append(p)
            servers_list.append(fp)
            count += 1
        if count > 0:
            logger.info(f"从 Clash 配置提取 {count} 个节点")
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

# ====================== 主处理流程 ======================
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
                    logger.info(f"✓ 从 vless:// 直链提取到节点: {url}")
                    continue

                # Clash 或 JSON
                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed or 'proxy:' in processed:
                    process_clash(processed)
                else:
                    process_json(processed)
                
                logger.info(f"✓ 处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.5 vless Reality + Xray 完整适配版启动 ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成！ → outputs/clash_meta.yaml")
