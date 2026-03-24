# -*- coding: UTF-8 -*-
"""
Modified for ttanzj/chromego_py
Added: VLESS Base64 subscription output, fixed Xray VLESS parsing, better logging
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logging.warning("GeoLite2-City.mmdb not found, location will be 'UNK'")

def get_physical_location(ip):
    if not geo_reader:
        return "UNK"
    try:
        response = geo_reader.city(ip)
        country = response.country.iso_code or "UNK"
        city = response.city.name or ""
        return f"{country}-{city}" if city else country
    except:
        return "UNK"

def process_urls(urls_file, method):
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        for idx, url in enumerate(urls):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = response.read().decode('utf-8')
                method(data, idx)
                logging.info(f"✓ 处理成功: {url}")
            except Exception as e:
                logging.error(f"✗ 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取文件 {urls_file} 失败: {e}")

def process_clash_meta(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', [])
        for i, proxy in enumerate(proxies):
            if not isinstance(proxy, dict) or 'server' not in proxy:
                continue
            key = f"{proxy['server']}:{proxy.get('port', '')}-{proxy.get('type', '')}"
            if key in servers_list:
                continue
            location = get_physical_location(proxy['server'])
            proxy['name'] = f"{location}-{proxy.get('type', 'unk')} | {index+1}-{i+1}"
            extracted_proxies.append(proxy)
            servers_list.append(key)
    except Exception as e:
        logging.error(f"Clash Meta 处理失败 {index}: {e}")

def process_hysteria(data, index):
    # ... (保持原逻辑，略微优化)
    try:
        content = json.loads(data)
        # 原 hysteria 处理代码（保持不变）
        auth = content.get('auth_str', '')
        server = content['server'].split(":")[0]
        port = int(content['server'].split(":")[1].split(',')[0])
        location = get_physical_location(server)
        name = f"{location}-Hysteria | {index+1}"
        proxy = {
            "name": name, "type": "hysteria", "server": server, "port": port,
            "auth-str": auth, "up": 80, "down": 100, "fast-open": True,
            "protocol": content.get('protocol', 'udp'), "sni": content.get('server_name', ''),
            "skip-cert-verify": content.get('insecure', True)
        }
        key = f"{server}:{port}-hysteria"
        if key not in servers_list:
            extracted_proxies.append(proxy)
            servers_list.append(key)
    except Exception as e:
        logging.error(f"Hysteria 处理失败 {index}: {e}")

def process_hysteria2(data, index):
    try:
        content = json.loads(data)
        auth = content.get('auth', content.get('password', ''))
        server = content['server'].split(":")[0]
        port = int(content['server'].split(":")[1].split(',')[0])
        location = get_physical_location(server)
        name = f"{location}-Hysteria2 | {index+1}"
        proxy = {
            "name": name, "type": "hysteria2", "server": server, "port": port,
            "password": auth, "sni": content.get('tls', {}).get('sni', ''),
            "skip-cert-verify": content.get('tls', {}).get('insecure', True)
        }
        key = f"{server}:{port}-hysteria2"
        if key not in servers_list:
            extracted_proxies.append(proxy)
            servers_list.append(key)
    except Exception as e:
        logging.error(f"Hysteria2 处理失败 {index}: {e}")

def process_xray(data, index):
    try:
        content = json.loads(data)
        outbounds = content.get('outbounds', [])
        for ob in outbounds:
            if ob.get('protocol') == "vless":
                settings = ob.get('settings', {}).get('vnext', [{}])[0]
                stream = ob.get('streamSettings', {})
                server = settings.get('address')
                port = settings.get('port')
                uuid = settings.get('users', [{}])[0].get('id')
                if not all([server, port, uuid]):
                    continue
                flow = settings.get('users', [{}])[0].get('flow', '')
                security = stream.get('security', 'none')
                sni = stream.get('tlsSettings', {}).get('serverName', '') or stream.get('realitySettings', {}).get('serverName', '')
                network = stream.get('network', 'tcp')

                proxy = {
                    "name": f"{get_physical_location(server)}-VLESS | {index+1}",
                    "type": "vless",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "network": network,
                    "tls": security != "none",
                    "servername": sni,
                    "skip-cert-verify": True,
                    "flow": flow
                }
                if network == "ws":
                    proxy["ws-opts"] = {"path": stream.get('wsSettings', {}).get('path', '/')}
                key = f"{server}:{port}-vless"
                if key not in servers_list:
                    extracted_proxies.append(proxy)
                    servers_list.append(key)
    except Exception as e:
        logging.error(f"Xray VLESS 处理失败 {index}: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    # 处理所有类型
    process_urls("urls/clash_meta_urls.txt", process_clash_meta)
    process_urls("urls/hysteria_urls.txt", process_hysteria)
    process_urls("urls/hysteria2_urls.txt", process_hysteria2)
    process_urls("urls/xray_urls.txt", process_xray)
    # singbox / ss / naiverproxy 可按需添加类似 process_ 函数

    logging.info(f"共提取到 {len(extracted_proxies)} 个节点")

    # 输出 Clash Meta
    template = {"proxies": extracted_proxies}
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump(template, f, allow_unicode=True, sort_keys=False)

    # 新增：输出纯 VLESS Base64 订阅（解决“只能导入 VLESS”问题）
    vless_links = []
    for p in extracted_proxies:
        if p.get("type") == "vless":
            link = f"vless://{p['uuid']}@{p['server']}:{p['port']}?type={p.get('network','tcp')}&security={ 'tls' if p.get('tls') else 'none' }&sni={p.get('servername','')}&flow={p.get('flow','')}&fp=chrome# {p['name']}"
            vless_links.append(link)

    with open("outputs/vless_base64.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(vless_links))
    with open("outputs/vless_subscription.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(vless_links).encode()).decode())

    logging.info("输出完成！请查看 outputs/ 目录")
    logging.info("新增 vless_subscription.txt 可直接导入 v2rayN / Nekobox 等客户端")
