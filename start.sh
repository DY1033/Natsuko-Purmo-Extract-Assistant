#!/usr/bin/env bash
# 解压码提取站一键启动（Linux / macOS）
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] 没有找到 python3，请先安装 Python 3.8+ 再运行。"
    exit 1
fi

if [ ! -d venv ]; then
    echo "[*] 第一次运行，正在创建运行环境..."
    python3 -m venv venv
    ./venv/bin/pip install -q --upgrade pip
    ./venv/bin/pip install -q -r requirements.txt
fi

echo ""
echo "  =========================================="
echo "   启动后浏览器访问 http://127.0.0.1:5000/"
echo "   第一次使用会进入安装向导"
echo "  =========================================="
echo ""

HOST="${HOST:-0.0.0.0}" PORT="${PORT:-5000}" exec ./venv/bin/python app.py
