import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """
    从 .bat 文件内容中提取所有订阅地址（.yaml / .json / .yml）
    """
    urls = []
    # 匹配 https://... 的 yaml/json/yml 文件
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    
    # 在单个 bat 文件内去重，保持出现顺序
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls


def main():
    root_dir = Path.cwd()  # 项目根目录
    
    top_folders = ["EdgeGo", "ChromeGo", "FirefoxFQ"]
    
    # key: 节点类型文件夹名（如 "Clash Meta", "Hysteria2" 等）
    # value: 该分组下的所有订阅地址（仅在本分组内去重）
    groups = defaultdict(list)
    
    print("正在扫描三个客户端文件夹...\n")
    
    for top_folder in top_folders:
        top_path = root_dir / top_folder
        if not top_path.exists() or not top_path.is_dir():
            print(f"⚠️  文件夹不存在: {top_folder}/")
            continue
        
        # 查找所有 ip_Update 目录
        for ip_update_dir in top_path.rglob("ip_Update"):
            if not ip_update_dir.is_dir():
                continue
            
            # 分组名称 = ip_Update 的上一级文件夹（节点类型）
            group_name = ip_update_dir.parent.name
            
            bat_files = list(ip_update_dir.glob("*.bat"))
            if not bat_files:
                continue
                
            print(f"  处理 → {top_folder}/{group_name}/ip_Update/  ({len(bat_files)} 个 .bat 文件)")
            
            for bat_file in bat_files:
                try:
                    content = bat_file.read_text(encoding="utf-8", errors="ignore")
                    urls = extract_subscription_urls(content)
                    if urls:
                        groups[group_name].extend(urls)
                except Exception as e:
                    print(f"    读取失败 {bat_file.name}: {e}")
    
    # 仅在每个分组内部去重，保持首次出现顺序
    final_groups = {}
    for group_name, url_list in groups.items():
        seen = set()
        unique_urls = []
        for url in url_list:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    # 写入文件
    output_dir = root_dir / "urls"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "sources.txt"
    
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        first_group = True
        for group_name in sorted(final_groups.keys()):   # 按分组名排序，可去掉 sorted 改成原来出现顺序
            if not first_group:
                f.write("\n")   # 分组之间空一行
            f.write(f"# {group_name}\n")
            for url in final_groups[group_name]:
                f.write(url + "\n")
            first_group = False
    
    # 输出统计
    total_groups = len(final_groups)
    total_urls = sum(len(urls) for urls in final_groups.values())
    
    print("\n" + "=" * 60)
    print("✅ 处理完成！")
    print(f"   输出文件 → {output_file}")
    print(f"   总分组数 → {total_groups}")
    print(f"   总地址数 → {total_urls}（分组内已去重）")
    print("=" * 60)
    
    for group_name, urls in final_groups.items():
        print(f"   # {group_name:<15} → {len(urls):>3} 条")


if __name__ == "__main__":
    main()
