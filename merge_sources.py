name: 自动合并订阅文件

on:
  schedule:
    - cron: '0 0 * * *'      # 北京时间每天早上 8 点
  workflow_dispatch:

jobs:
  merge:
    runs-on: ubuntu-latest
    
    steps:
      - name: 检出代码
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: 设置 Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: 创建输出目录
        run: mkdir -p outputs

      - name: 执行合并脚本
        run: python merge_sources.py

      - name: 配置 Git 并提交更新
        run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"
          
          # 关键修复：先拉取最新代码
          git pull --rebase origin main
          
          if git diff --quiet outputs/merged_subscriptions.txt; then
            echo "📭 本次订阅内容无变化，跳过提交"
          else
            echo "📤 检测到更新，正在提交..."
            git add outputs/merged_subscriptions.txt
            git commit -m "🔄 自动更新合并订阅文件 $(date '+%Y-%m-%d %H:%M:%S')"
            git push
          fi
