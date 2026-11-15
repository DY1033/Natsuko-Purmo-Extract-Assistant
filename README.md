# 解压码提取站（NATSUKO PROGRAM）

> 完整的使用、部署与故障排查说明见 **[使用说明.md](使用说明.md)**。本文档只保留最少必要信息。

一个轻量的「解压码分发」工具：你在后台创建解压码，系统生成一串公钥；把公钥（或一张说明页 HTML）发给对方，对方在你网站输入公钥就能拿到解压码。解压码本身不出现在文件里，也不用怕截图泄露——公钥可以随时停用、换新或限次。

## 功能一览

- **前台提取**：输入公钥即显示解压码，支持一键复制、带参数链接自动填充（`/?k=公钥`）
- **后台管理**：创建 / 编辑 / 停用 / 删除、重置次数、更换公钥、CSV 导出、提取日志（含 IP）
- **限次与有效期**：每条解压码可设置最大提取次数和过期时间
- **分享说明页**：一键下载离线 HTML 说明页放进压缩包，对方双击打开就能看到提取方法
- **每条独立风格**：说明页有 4 种风格（简洁白 / 极简 / 米色纸张 / 深色），可以按条分配
- **版权署名**：首页底部 Natsuko Program 固定保留、不可关闭，署名文字链接到 [natsuko.online](https://natsuko.online)

## 环境要求

- Python 3.8 及以上（Windows / Linux / macOS 均可）
- 无需数据库服务，数据存在本地 SQLite

## 安装步骤

### 方式一：一键启动（推荐）

**Windows**：双击 `start.bat`
首次运行会自动创建虚拟环境并安装依赖，然后打开浏览器进入安装向导。

**Linux / macOS**：

```bash
chmod +x start.sh
./start.sh
```

### 方式二：手动安装

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt      # Windows: venv\Scripts\pip install -r requirements.txt
./venv/bin/python app.py                        # Windows: venv\Scripts\python app.py
```

### 方式三：Docker

```bash
docker build -t extract-site .
docker run -d -p 5000:5000 -v ./data:/app/data extract-site
```

## 安装向导

服务启动后，浏览器打开 `http://127.0.0.1:5000/` 会自动进入安装向导，需要填：

| 项目 | 说明 |
|---|---|
| 网站名称 | 显示在页面顶部和浏览器标题 |
| 首页说明 / 页脚 | 前台展示的两句话 |
| 后台密码 | 至少 6 位，装完自动登录 |
| 分享说明页文案 | 放进压缩包的 HTML 说明页用的 |
| NATSUKO PROGRAM 署名 | 首页底部版权标识，发行版固定保留、不可取消，链接到 natsuko.online |

装完之后这些内容随时可以在后台右上角「设置」里改。

## 部署到服务器（正式使用）

生产环境建议 gunicorn + Nginx：

```bash
./venv/bin/pip install gunicorn
DATA_DIR=./data ./venv/bin/gunicorn -w 2 -b 127.0.0.1:5010 app:app
```

Nginx 反向代理示例：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5010;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 禁止访问敏感文件
    location ~* /(\.git|venv|data)/ { return 404; }
    location ~* \.(db|py|log|sql)$  { return 404; }
}
```

HTTPS 证书可以用 certbot 一条命令搞定（DNS 验证或 HTTP 验证均可）。

## 目录结构

```
├── app.py            # 全部后端逻辑（单文件）
├── requirements.txt  # 依赖：flask、gunicorn
├── start.bat         # Windows 一键启动
├── start.sh          # Linux / macOS 一键启动
├── templates/        # 页面模板
├── static/           # 样式
└── data/             # 运行后自动生成：codes.db（数据）、config.json（密码）、secret.key
```

## 常用运维

| 操作 | 命令 |
|---|---|
| 备份数据 | 直接复制 `data/codes.db` |
| 修改监听端口 | `PORT=8000 python app.py` |
| 用环境变量设置密码 | `ADMIN_PASSWORD=xxx python app.py`（优先级高于后台密码） |
| 重置后台密码 | 删除 `data/config.json` 后重启，恢复默认密码 `admin123` |

## 安全说明

- 解压码存储在服务端，说明页 HTML 里**只含公钥**，不包含解压码
- 后台登录有防暴力破解（同 IP 连续失败会被暂时锁定）
- 提取接口有频率限制，防止穷举公钥
- 公钥空间约 59 bit，且去掉了易混淆字符（0/O/1/I/L）

## 版权

本项目由 **NATSUKO PROGRAM** 开发（[natsuko.online](https://natsuko.online)）。首页底部的署名在发行版中固定保留、不可通过后台关闭；如需二次开发，请保留代码中的版权声明与署名链接。
