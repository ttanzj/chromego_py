#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.1 - Z系列强力解析版（已修复 f-string 语法错误）
Y系列：完全保留原始提取和输出逻辑
Z系列：订阅源地址提取方式不变，预处理 + 解析全面强化
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
from pathlib import Path

# ==================== 全局防卡死设置 ====================
socket.setdefaulttimeout(15)
urllib.request.socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []
extracted_y: list[dict] = []
extracted_z: list[dict] = []
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
    key = "|".join(str(p.get(k, '')).lower().strip() for k in [
        'server', 'port', 'type', 'uuid', 'password', 'auth-str', 'network', 'sni'
    ])
    return hashlib.md5(key.encode()).hexdigest()

def test_node_availability(proxy: dict, timeout: int = 8) -> tuple[bool, int]:
    server = proxy.get('server')
    port = int(proxy.get('port', 443))
    if not server:
        return False, 9999
    try:
        start = time.time()
        with socket.create_connection((server, port), timeout=timeout):
            delay = int((time.time() - start) * 1000)
        return True, delay
    except Exception:
        return False, 9999

# ====================== 强化预处理（已修复 f-string） ======================
def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content:
        return content

    attempts = 0
    max_attempts = 5
    logger.info(f"原始内容长度: {len(content)} 字符")

    while attempts < max_attempts:
        attempts += 1
        if "\n" not in content and len(content) > 100 and "://" not in content[:150]:
            try:
                padding = '=' * (-len(content) % 4)
                decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
                if len(decoded) > len(content) * 0.7 and any(p in decoded[:400] for p in 
                    ['vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'proxies:', 'outbounds:']):
                    content = decoded.strip()
                    logger.info(f"✅ Base64 解码成功（第 {attempts} 层）")
                    continue
            except Exception:
                break
        else:
            break

    # 强制拆行
    if "\n" not in content and any(p in content for p in ['://', 'proxies:', '{']):
        content = content.replace('vmess://', '\nvmess://') \
                         .replace('vless://', '\nvless://') \
                         .replace('trojan://', '\ntrojan://') \
                         .replace('hysteria2://', '\nhysteria2://') \
                         .replace('hy2://', '\nhy2://')
        logger.info("✅ 已强制拆分成多行")

    # 修复后的预览输出（避免 f-string 中出现反斜杠）
    preview = content[:300].replace('\n', '\\n')
    logger.info(f"预处理完成 → 最终 {len(content)} 字符，前300字符预览: {preview}")
    return content

def parse_general_node(line: str, prefix: str, index: int) -> dict | None:
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
            uuid = url.username
            if not uuid and url.path:
                uuid = url.path.lstrip('/')
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
    except Exception:
        pass
    return None

def process_z_url(url: str, prefix: str = "Z-"):
    for attempt in range(3):
        try:
            logger.info(f"[{attempt+1}/3] 开始处理 Z系列源: {url}")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})

            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_data = resp.read().decode('utf-8', errors='ignore')

            processed_data = preprocess_subscription(raw_data)
            added = 0

            lines = [line.strip() for line in processed_data.splitlines() if line.strip() and not line.startswith('#')]
            logger.info(f"该源解析出 {len(lines)} 行有效内容，开始逐行处理...")

            for i, line in enumerate(lines):
                node = parse_general_node(line, prefix, i + 1)
                if node and node.get('server'):
                    fp = make_fingerprint(node)
                    if fp in servers_list:
                        continue

                    is_alive, delay = test_node_availability(node, timeout=8)
                    if is_alive and delay <= 1500:
                        node['name'] = f"{node['name']}-{delay}ms"
                        extracted_z.append(node)
                        servers_list.append(fp)
                        added += 1
                        if added <= 8:
                            logger.info(f"  ✓ 添加节点 #{added}: {node['name']} | {node.get('type')} | {node.get('server')}")
                elif i < 15 or '://' in line:
                    logger.debug(f"  未解析行 {i+1}: {line[:150]}...")

            if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                process_clash(processed_data, prefix, extracted_z)
            else:
                process_json(processed_data, prefix, extracted_z)

            logger.info(f"✓ Z系列处理完成: {url} → 新增可用节点 {added} 个")
            return

        except Exception as e:
            logger.warning(f"[{attempt+1}/3] Z系列失败 {url}: {type(e).__name__} - {e}")
            if attempt < 2:
                time.sleep(3)
            else:
                logger.error(f"✗ Z系列最终放弃（强制跳过）: {url}")

def process_file(file_path: str, prefix: str, target_list: list):
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
                    process_clash(processed_data, prefix, target_list)
                else:
                    process_json(processed_data, prefix, target_list)

                logger.info(f"✓ Y系列处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ Y系列处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

def process_clash(data: str, prefix: str, target_list: list):
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
            target_list.append(p)
            servers_list.append(fp)
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str, prefix: str, target_list: list):
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
                name_suffix = f" ({ports_range})" if ports_range else ""
                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                    "type": typ,
                    "server": server,
                    "port": main_port,
                    "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                    "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                    "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                    "skip-cert-verify": content.get('insecure', True),
                    "alpn": content.get('alpn', 'h3')
                }
                if ports_range: p['ports'] = ports_range
                if typ == "hysteria":
                    p["up"] = content.get('upmbps') or content.get('up') or 100
                    p["down"] = content.get('downmbps') or content.get('down') or 100

                fp = make_fingerprint(p)
                if fp not in servers_list:
                    target_list.append(p)
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
            p['name'] = f"{prefix}{get_location(server)}-{proto.upper()}-{len(target_list)+1}"
            fp = make_fingerprint(p)
            if fp not in servers_list:
                target_list.append(p)
                servers_list.append(fp)
    except Exception as e:
        logger.error(f"JSON 处理异常: {e}")

def parse_server_port(srv: str):
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
        if m: return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.1 Z系列强力解析版启动 ===")

    logger.info("开始处理 Y系列（sources.txt）...")
    process_file("urls/sources.txt", "Y-", extracted_y)

    try:
        z_path = "urls/sources-j.txt"
        if os.path.exists(z_path):
            with open(z_path, 'r', encoding='utf-8') as f:
                z_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"共发现 {len(z_urls)} 个 Z系列订阅源，开始逐个强力处理...")
            for idx, url in enumerate(z_urls, 1):
                logger.info(f"--- 处理第 {idx}/{len(z_urls)} 个 Z系列源 ---")
                process_z_url(url, "Z-")
        else:
            logger.warning(f"{z_path} 文件不存在，跳过 Z系列")
    except Exception as e:
        logger.error(f"读取 sources-j.txt 失败: {e}")

    combined = extracted_y + extracted_z
    logger.info(f"最终节点统计 → 总计: {len(combined)} | Y: {len(extracted_y)} | Z: {len(extracted_z)}")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": combined}, f, allow_unicode=True, sort_keys=False)

    with open("outputs/y_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_y}, f, allow_unicode=True, sort_keys=False)

    with open("outputs/z_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_z}, f, allow_unicode=True, sort_keys=False)

    logger.info("✅ 输出完成！")
    logger.info("   • outputs/clash_meta.yaml  ← Y+Z 合并（推荐使用）")
    logger.info("   • outputs/y_clash.yaml      ← 仅Y系列")
    logger.info("   • outputs/z_clash.yaml      ← 仅Z系列")
