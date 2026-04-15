import urllib.request
import os
from urllib.error import URLError, HTTPError


def fetch_url(url: str) -> str:
    """读取订阅地址内容"""
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.getcode() == 200:
                return response.read().decode('utf-8', errors='replace')
            else:
                return f"# 【错误】HTTP {response.getcode()} - {url}\n"
    except (URLError, HTTPError) as e:
        return f"# 【错误】无法访问 {url}：{str(e)}\n"
    except Exception as e:
        return f"# 【错误】未知异常 {url}：{str(e)}\n"


def sanitize_filename(name: str) -> str:
    """清理文件名非法字符"""
    invalid = '<>:"/\\|?*'
    for char in invalid:
        name = name.replace(char, '_')
    # 去除首尾空格和多余下划线
    name = name.strip().strip('_')
    return name[:100]  # 限制长度


def main():
    input_file = "urls/sources.txt"
    output_dir = "outputs"

    if not os.path.exists(input_file):
        print(f"❌ 未找到 {input_file} 文件！")
        return

    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 输出文件夹：{output_dir}/\n")

    # 解析分组
    groups = []
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_group = None
    current_urls = []

    for line in lines:
        stripped = line.strip()
        if stripped == "":
            if current_group and current_urls:
                groups.append((current_group, current_urls[:]))
                current_urls = []
            current_group = None
            continue

        if current_group is None:
            current_group = line.rstrip()   # 保留原始标题
            current_urls = []
        else:
            if stripped:
                current_urls.append(stripped)

    if current_group and current_urls:
        groups.append((current_group, current_urls[:]))

    print(f"✅ 共解析到 {len(groups)} 个分组，开始下载...\n")

    total = 0
    for group_id, urls in groups:
        # 生成文件名（使用格式标识）
        filename = sanitize_filename(group_id.replace("#", "").strip())
        if not filename:
            filename = f"group_{len(groups)}"
        
        output_file = os.path.join(output_dir, f"{filename}.txt")

        print(f"📂 处理分组：{group_id} → {output_file} ({len(urls)} 个地址)")

        with open(output_file, "w", encoding="utf-8") as out:
            out.write(f"# =======================\n")
            out.write(f"# {group_id}\n")
            out.write(f"# 由 merge_sources.py 自动生成\n")
            out.write(f"# =======================\n\n")

            for url in urls:
                print(f"   ⬇️ 下载 → {url}")
                content = fetch_url(url)
                total += 1
                out.write(content)
                out.write("\n\n")

    print(f"\n🎉 全部完成！共处理 {total} 个订阅")
    print(f"📁 所有文件已保存至：{output_dir}/")


if __name__ == "__main__":
    main()
