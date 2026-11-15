@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 解压码提取站

where python >nul 2>nul
if errorlevel 1 (
    echo [!] 没有找到 Python。
    echo     请先到 https://www.python.org/downloads/ 安装 Python 3.8 以上版本，
    echo     安装时记得勾选 “Add Python to PATH”，然后重新运行本文件。
    pause
    exit /b 1
)

if not exist venv (
    echo [*] 第一次运行，正在创建运行环境（约 1-2 分钟）...
    python -m venv venv
    call venv\Scripts\activate.bat
    python -m pip install --upgrade pip -q
    pip install -r requirements.txt -q
    if errorlevel 1 (
        echo [!] 依赖安装失败，请检查网络后重试。
        pause
        exit /b 1
    )
) else (
    call venv\Scripts\activate.bat
)

echo.
echo   ==========================================
echo    服务启动后浏览器会自动打开
echo    第一次使用会进入安装向导
echo   ==========================================
echo.

start "" http://127.0.0.1:5000/
python app.py
pause
