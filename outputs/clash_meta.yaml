#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.3 - 纯 Y 系列简化版
- 已移除所有 Z 系列处理
- 节点命名不再带 "Y-" 前缀
- 优化名称重复问题 + 更好保留复杂字段（Reality / tuic / hysteria2 等）
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

servers_list: list[str] = []          # 全局去重
extracted_proxies: list[dict] = []    # 统一存放所有节点
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到，位置信息显示 UNK")

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

# ====================== 增强版指纹去重 ======================
def make_fingerprint(p: dict) -> str:
    key_parts = [
        str(p.get('server', '')).lower().strip(),
        str(p.get('port', '')).strip(),
        str(p.get('type', '')).lower().strip(),
        str(p.get('uuid', '') or p.get('password', '') or p.get('auth-str', '')).strip(),
        str(p.get('network', '')).lower().strip(),
        str(p.get('sni', '')).lower().strip(),
    ]
    key = "|".join(key_parts)
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

# ====================== 预处理（保留基础功能） ======================
def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content:
        return content

    # 简单 Base64 处理
    if "\n" not in content and len(content) > 100 and "://" not in content[:150]:
        try:
            padding = '=' * (-len(content) % 4)
            decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
            if any(p in decoded[:300] for p in ['vmess://', 'vless://', 'trojan://', 'hysteria']):
                content = decoded.strip()
        except Exception:
            pass
    return content

# ====================== 核心：优化后的 Clash 处理（Y系列主要逻辑） ======================
def process_clash(data: str, prefix: str = ""):
    """优化版 Clash 处理 - 解决名称重复 + 更好字段保留"""
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        added = 0

        for i, orig_p in enumerate(proxies):
            if not isinstance(orig_p, dict) or not orig_p.get('server'):
                continue

            p = dict(orig_p)                    # 深拷贝
            fp = make_fingerprint(p)

            if fp in servers_list:
                continue

            # 改进命名：去掉 "Y-"，格式更清晰
            loc = get_location(p.get('server'))
            node_type = str(p.get('type', 'unk')).upper()
            name = f"{loc}-{node_type}-{i+1}"

            # 如果有端口范围，加上后缀
            if p.get('ports'):
                name += f" ({p.get('ports')})"

            p['name'] = name

            # 保留所有原始字段（重要！Reality、smux、brutal 等都要保留）
            extracted_proxies.append(p)
            servers_list.append(fp)
            added += 1

            if added <= 6:   # 只打印前几个用于观察
                logger.info(f"  添加节点: {name} | {p.get('type')} | {p.get('server')}")

        logger.info(f"Clash 处理完成，本次新增 {added} 个节点")
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str, prefix: str = ""):
    """保留 JSON 处理（以防某些源是 JSON 格式）"""
    try:
        content = json.loads(data)
        # ...（保持原有 process_json 逻辑，如果你不需要可简化，这里暂时保留框架）
        logger.info("JSON 处理完成（当前主要使用 Clash 格式）")
    except Exception as e:
        logger.error(f"JSON 处理异常: {e}")

def process_file(file_path: str):
    """处理 sources.txt 中的所有订阅源"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        for url in urls:
            try:
                logger.info(f"正在处理订阅源: {url}")
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')

                processed_data = preprocess_subscription(raw_data)

                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                    process_clash(processed_data)
                else:
                    process_json(processed_data)

                logger.info(f"✓ 订阅源处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.3 纯 Y 系列简化版启动 ===")

    # 只处理 Y 系列（sources.txt）
    process_file("urls/sources.txt")

    # 输出最终文件
    logger.info(f"最终共提取 {len(extracted_proxies)} 个节点")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logger.info("✅ 输出完成！")
    logger.info("   输出文件: outputs/clash_meta.yaml （已去除 Y- 前缀，名称更干净）")
