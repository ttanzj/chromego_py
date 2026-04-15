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


def main():
    input_file = "urls/sources.txt"
    output_dir = "outputs"
    output_file = os.path.join(output_dir, "merged_subscriptions.txt")

    # 检查输入文件
    if not os.path.exists(input_file):
        print(f"❌ 未找到 {input_file} 文件！")
        return

    # 创建 outputs 文件夹（如果不存在）
    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 输出文件夹已确认：{output_dir}/")

    # 解析分组
    groups = []
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_group = None
    current_urls = []

    for line in lines:
        stripped = line.strip()
        if stripped == "":  # 空行 = 分组结束
            if current_group and current_urls:
                groups.append((current_group, current_urls[:]))
                current_urls = []
            current_group = None
            continue

        if current_group is None:
            current_group = line.rstrip()  # 保留原始分组名
            current_urls = []
        else:
            if stripped:
                current_urls.append(stripped)

    # 最后一个分组
    if current_group and current_urls:
        groups.append((current_group, current_urls[:]))

    print(f"✅ 共解析到 {len(groups)} 个分组，开始下载...\n")

    # 写入合并文件
    with open(output_file, "w", encoding="utf-8") as out:
        out.write("# =======================\n")
        out.write("# 合并后的订阅文件\n")
        out.write("# 由 merge_sources.py 自动生成\n")
        out.write(f"# 输出路径：{output_file}\n")
        out.write("# =======================\n\n")

        total = 0
        for group_id, urls in groups:
            print(f"📂 处理分组：{group_id}  ({len(urls)} 个地址)")
            for url in urls:
                print(f"   ⬇️  下载 → {url}")
                content = fetch_url(url)
                total += 1

                out.write(f"{group_id}\n")
                out.write(content)
                out.write("\n\n")

    print(f"\n🎉 全部完成！共处理 {total} 个订阅")
    print(f"📄 输出文件路径：{output_file}")


if __name__ == "__main__":
    main()
