import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """从 .bat 文件中提取订阅地址（yaml / json / yml）"""
    urls = []
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    
    # 单个 bat 文件内去重，保持顺序
    seen = set()
    unique_urls = [url for url in urls if not (url in seen or seen.add(url))]
    return unique_urls


def process_folder(top_folder: str, root_dir: Path) -> dict:
    """处理单个客户端文件夹，返回 {分组名: [url列表]}"""
    groups = defaultdict(list)
    top_path = root_dir / top_folder
    
    if not top_path.exists() or not top_path.is_dir():
        print(f"⚠️  文件夹不存在，跳过: {top_folder}/")
        return {}
    
    print(f"\n开始处理 → {top_folder}")
    
    found_any = False
    for ip_update_dir in top_path.rglob("ip_Update"):
        if not ip_update_dir.is_dir():
            continue
            
        group_name = ip_update_dir.parent.name
        bat_files = list(ip_update_dir.glob("*.bat"))
        
        if not bat_files:
            continue
            
        found_any = True
        print(f"  → 找到 {len(bat_files)} 个 .bat 文件  ({top_folder}/{group_name}/ip_Update)")
        
        for bat_file in bat_files:
            try:
                content = bat_file.read_text(encoding="utf-8", errors="ignore")
                urls = extract_subscription_urls(content)
                if urls:
                    groups[group_name].extend(urls)
            except Exception as e:
                print(f"    读取失败 {bat_file.name}: {e}")
    
    if not found_any:
        print(f"  ⚠️  {top_folder} 中未找到任何 ip_Update 文件夹")
    
    # 每个分组内部去重
    final_groups = {}
    for group_name, url_list in groups.items():
        seen = set()
        unique_urls = [url for url in url_list if not (url in seen or seen.add(url))]
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    return final_groups


def write_sources_file(groups: dict, filepath: Path):
    """写入 sources 文件（支持空内容）"""
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        if not groups:
            f.write("# 无有效订阅地址\n")
            return
        
        first_group = True
        for group_name in sorted(groups.keys()):
            if not first_group:
                f.write("\n")
            f.write(f"# {group_name}\n")
            for url in groups[group_name]:
                f.write(url + "\n")
            first_group = False


def main():
    root_dir = Path.cwd()
    output_dir = root_dir / "urls"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    clients = ["EdgeGo", "ChromeGo", "FirefoxFQ"]
    all_groups = defaultdict(list)   # 用于最终合并
    
    print("=== 开始提取订阅地址 ===\n")
    
    for client in clients:
        groups = process_folder(client, root_dir)
        
        # 无论是否有数据，都生成对应的 _sources.txt 文件
        client_file = output_dir / f"{client}_sources.txt"
        write_sources_file(groups, client_file)
        
        if groups:
            print(f"✅ 已生成 {client_file.name}  ({len(groups)} 个分组, {sum(len(u) for u in groups.values())} 条地址)")
        else:
            print(f"✅ 已生成 {client_file.name}  (无数据)")
        
        # 收集用于合并
        for group_name, urls in groups.items():
            all_groups[group_name].extend(urls)
    
    # ===================== 生成最终 sources.txt =====================
    final_groups = {}
    for group_name, url_list in all_groups.items():
        seen = set()
        unique_urls = [url for url in url_list if not (url in seen or seen.add(url))]
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    final_file = output_dir / "sources.txt"
    write_sources_file(final_groups, final_file)
    
    print("\n" + "=" * 75)
    print("🎉 任务完成！已在 urls/ 目录下生成以下 4 个文件：")
    print(f"   • EdgeGo_sources.txt")
    print(f"   • ChromeGo_sources.txt")
    print(f"   • FirefoxFQ_sources.txt")
    print(f"   • sources.txt   ← 最终合并文件（三个客户端合并后分组内去重）")
    print("=" * 75)
    
    total_groups = len(final_groups)
    total_urls = sum(len(urls) for urls in final_groups.values())
    print(f"最终 sources.txt 统计：{total_groups} 个分组，共 {total_urls} 条订阅地址")


if __name__ == "__main__":
    main()
