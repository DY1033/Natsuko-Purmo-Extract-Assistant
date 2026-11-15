#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解压码提取站 —— 单文件 Flask 后端
后台：创建解压码，系统生成唯一公钥（提取密钥）
前台：输入公钥 -> 提取对应的解压码
"""
from __future__ import annotations

import os
import re
import io
import csv
import json
import time
import hmac
import sqlite3
import secrets
import hashlib
import threading
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import quote

from flask import (
    Flask, request, jsonify, session, render_template, g,
    redirect, url_for, Response, abort
)
from werkzeug.middleware.proxy_fix import ProxyFix

# ----------------------------------------------------------------------------
# 基础配置
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "codes.db")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
SECRET_PATH = os.path.join(DATA_DIR, "secret.key")

DEFAULT_ADMIN_PASSWORD = "admin123"
SESSION_HOURS = 12

APP_VERSION = "1.1.1"
INSTALL_FLAG = os.path.join(DATA_DIR, "installed.json")

# 版权署名：发行版固定保留，后台与安装向导都无法关闭
AUTHOR_NAME = "Natsuko Program"
AUTHOR_URL = "https://natsuko.online"
WATERMARK_LOCKED = True

# 去掉容易混淆的 0/O/1/I/L，共 31 个字符
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
KEY_LEN = 12          # 12 位 → 约 59 bit 随机空间
GROUP_SIZE = 4        # XXXX-XXXX-XXXX

app = Flask(__name__)


# ----------------------------------------------------------------------------
# 密钥 / 配置
# ----------------------------------------------------------------------------
def _load_or_create_secret() -> bytes:
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "rb") as f:
            data = f.read().strip()
            if data:
                return data
    data = secrets.token_bytes(32)
    with open(SECRET_PATH, "wb") as f:
        f.write(data)
    try:
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    return data


def _hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000
    ).hex()
    return f"pbkdf2_sha256$120000${salt}${digest}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iters)
        ).hex()
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False


def _load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    cfg = {"password_hash": _hash_password(DEFAULT_ADMIN_PASSWORD)}
    _save_config(cfg)
    return cfg


def _save_config(cfg: dict) -> None:
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


app.json.ensure_ascii = False  # 返回中文而非 \uXXXX
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
    JSON_AS_ASCII=False,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
app.config["DB_PATH"] = DB_PATH

# 授权服务（仅服务端部署包含 license_server.py；开源版缺失时自动降级）
try:
    from license_server import lic as license_bp, init_license_tables
    app.register_blueprint(license_bp)
    LICENSE_SERVER_MODE = True
except Exception:  # pragma: no cover - 客户端版本走这里
    init_license_tables = None
    LICENSE_SERVER_MODE = False

# 授权客户端（安装版：激活 / 每日校验 / 停用逻辑）
LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER") or "https://extract.natsuko.online"
try:
    from license_client import LicenseClient
    license_client = LicenseClient(LICENSE_SERVER_URL, DATA_DIR)
except Exception:  # pragma: no cover
    license_client = None
CLIENT_LICENSE_MODE = bool(license_client) and not LICENSE_SERVER_MODE


@app.before_request
def _redirect_to_install():
    """还没走安装向导时，把访问者带到安装页。"""
    if is_installed():
        return None
    path = request.path
    if path.startswith("/static/") or path in ("/install", "/api/install", "/healthz", "/favicon.ico"):
        return None
    return redirect("/install")


@app.before_request
def _enforce_license():
    """安装版：授权未通过 / 被封禁 / 长期离线时，整站停用只留授权页。"""
    if not CLIENT_LICENSE_MODE or not is_installed():
        return None
    path = request.path
    if (path.startswith(("/static/", "/api/license/", "/license"))
            or path in ("/healthz", "/favicon.ico")):
        return None
    license_client.maybe_check()
    if license_client.is_valid():
        return None
    return redirect("/license")


def admin_password_env() -> str | None:
    """环境变量 ADMIN_PASSWORD 优先级最高，方便容器化部署。"""
    v = os.environ.get("ADMIN_PASSWORD")
    return v if v else None


# ----------------------------------------------------------------------------
# 数据库
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS codes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key   TEXT    NOT NULL UNIQUE,
    title        TEXT    NOT NULL DEFAULT '',
    secret       TEXT    NOT NULL,
    note         TEXT    NOT NULL DEFAULT '',
    share_theme  TEXT    NOT NULL DEFAULT '',
    max_uses     INTEGER,
    used_count   INTEGER NOT NULL DEFAULT 0,
    expires_at   TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT    NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code_id    INTEGER,
    public_key TEXT NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    ok         INTEGER NOT NULL,
    reason     TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 领取凭据：同一 IP 对同一公钥，24 小时内重复提取只算一次
CREATE TABLE IF NOT EXISTS grants (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code_id    INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    last_at    TEXT    NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_codes_key ON codes(public_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_code_ip ON grants(code_id, ip);
CREATE INDEX IF NOT EXISTS idx_grants_expires ON grants(expires_at);
"""

# 一次提取后，同一 IP 在多少小时内重复提取不再计数
GRANT_HOURS = 24


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """老版本数据库补字段，保证升级后不丢数据。

    gunicorn 多 worker 会同时执行这里，所以用写锁串行化，
    并对 duplicate column / database is locked 做容错，避免启动时进程直接崩掉。
    """
    for attempt in range(3):
        try:
            conn.execute("BEGIN IMMEDIATE")
            cols = {row[1] for row in conn.execute("PRAGMA table_info(codes)")}
            if "share_theme" not in cols:
                conn.execute("ALTER TABLE codes ADD COLUMN share_theme TEXT NOT NULL DEFAULT ''")
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            conn.rollback()
            msg = str(exc).lower()
            if "duplicate column" in msg:
                return
            if "locked" in msg and attempt < 2:
                time.sleep(0.5)
                continue
            raise


def init_db() -> None:
    # gunicorn 多 worker 会同时建表，遇到写锁重试几次
    for attempt in range(4):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=20)
            try:
                conn.executescript(SCHEMA)
                _migrate(conn)
                conn.commit()
            finally:
                conn.close()
            break
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() and attempt < 3:
                time.sleep(0.6)
                continue
            raise
    if init_license_tables:
        try:
            init_license_tables(DB_PATH)
        except Exception:
            pass


def is_installed() -> bool:
    """安装过（向导完成）或者已有旧版配置，都算已安装，避免升级后又被拦去装一遍。"""
    return os.path.exists(INSTALL_FLAG) or os.path.exists(CONFIG_PATH)


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def gen_public_key() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(KEY_LEN))
    return "-".join(
        raw[i:i + GROUP_SIZE] for i in range(0, KEY_LEN, GROUP_SIZE)
    )


def normalize_key(text: str) -> str:
    """去掉空格/连字符等，仅保留字母数字，统一大写。"""
    return re.sub(r"[^A-Z0-9]", "", (text or "").upper())


def format_key(raw: str) -> str:
    return "-".join(
        raw[i:i + GROUP_SIZE] for i in range(0, len(raw), GROUP_SIZE)
    )


def is_valid_key(raw: str) -> bool:
    return len(raw) == KEY_LEN and all(c in ALPHABET for c in raw)


def parse_expires(value):
    """接收前端传来的 ISO 字符串（带时区），统一转 UTC ISO；非法返回 None。"""
    if not value:
        return None
    try:
        v = str(value).strip()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None


def is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def client_ip() -> str:
    """取客户端真实 IP。

    ProxyFix 已按 x_for=1 把反代传来的最后一段还原到 remote_addr，
    优先用它，避免客户端伪造 X-Forwarded-For 绕过提取次数统计。
    """
    ip = (request.remote_addr or "").strip()
    if ip and not ip.startswith("127.") and ip != "::1":
        return ip[:64]
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        # 取最后一段（最靠近本站的真实来源），不信任最左端
        return fwd.split(",")[-1].strip()[:64]
    return ip[:64]


# ----------------------------------------------------------------------------
# 简易内存限流（单进程；多进程部署可换 Redis）
# ----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def _prune(self, key: str, now: float):
        arr = [t for t in self.hits.get(key, []) if now - t < self.window]
        if arr:
            self.hits[key] = arr
        else:
            self.hits.pop(key, None)
        return arr

    def check(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            return len(self._prune(key, now)) < self.limit

    def hit(self, key: str):
        now = time.time()
        with self.lock:
            arr = self._prune(key, now)
            arr.append(now)
            self.hits[key] = arr

    def retry_after(self, key: str) -> int:
        now = time.time()
        with self.lock:
            arr = self._prune(key, now)
            if not arr:
                return 0
            return max(1, int(self.window - (now - min(arr))) + 1)


extract_limiter = RateLimiter(limit=20, window=300)   # 5 分钟 20 次
login_limiter = RateLimiter(limit=8, window=600)      # 10 分钟 8 次


# ----------------------------------------------------------------------------
# 鉴权
# ----------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="未登录或登录已过期", code="UNAUTHORIZED"), 401
            # 保持用户当前入口，/manage 进来就回 /manage/login，避免地址跳来跳去
            target = "admin_login_m" if request.path.startswith("/manage") else "admin_login"
            return redirect(url_for(target))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def touch_session():
    if session.get("admin"):
        session.permanent = True


# ----------------------------------------------------------------------------
# 页面路由
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    # 服务端部署（授权中心）首页是官网，不再暴露解压码提取表单
    if LICENSE_SERVER_MODE:
        return render_template(
            "landing.html",
            dev_logged_in=bool(session.get("dev_uid")),
            version=APP_VERSION,
            year=time.strftime("%Y"),
        )
    return render_template("index.html")


@app.route("/license")
def license_page():
    if not CLIENT_LICENSE_MODE:
        return redirect("/")
    return render_template("license.html", info=license_client.info())


@app.route("/api/license/refresh", methods=["POST"])
def api_license_refresh():
    """授权页与后台共用的手动校验入口。"""
    if not CLIENT_LICENSE_MODE:
        return jsonify(ok=False, error="此版本无需授权"), 400
    valid, msg = license_client.refresh()
    return jsonify(ok=True, valid=valid, msg=msg, info=license_client.info())


@app.route("/api/license/status")
def api_license_status():
    if not CLIENT_LICENSE_MODE:
        return jsonify(ok=False, error="此版本无需授权"), 400
    return jsonify(ok=True, valid=license_client.is_valid(), info=license_client.info())


@app.route("/admin")
@login_required
def admin_page():
    return render_template("admin.html")


@app.route("/manage")
@login_required
def admin_page_m():
    return render_template("admin.html")


@app.route("/admin/login")
def admin_login():
    if session.get("admin"):
        return redirect("/admin")
    return render_template("login.html")


@app.route("/manage/login")
def admin_login_m():
    if session.get("admin"):
        return redirect("/manage")
    return render_template("login.html")


@app.route("/healthz")
def healthz():
    return jsonify(ok=True, ts=now_iso())


# ----------------------------------------------------------------------------
# 前台接口：提取解压码
# ----------------------------------------------------------------------------
@app.route("/api/extract", methods=["POST"])
def api_extract():
    ip = client_ip()
    is_limited = not extract_limiter.check(ip)

    if is_limited:
        retry = extract_limiter.retry_after(ip)
        return jsonify(
            ok=False, code="RATE_LIMITED",
            error=f"尝试过于频繁，请 {retry} 秒后再试"
        ), 429

    payload = request.get_json(silent=True) or {}
    raw = normalize_key(payload.get("key", ""))
    extract_limiter.hit(ip)

    if not raw:
        return jsonify(ok=False, code="EMPTY", error="请输入公钥"), 400
    if not is_valid_key(raw):
        _write_log(None, format_key(raw) or raw, False, "KEY_INVALID")
        return jsonify(ok=False, code="KEY_INVALID",
                       error="公钥格式不正确，应为 12 位字符（如 AB3D-9F2K-7Q1M）"), 400

    key = format_key(raw)
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE public_key = ?", (key,)).fetchone()

    if row is None:
        _write_log(None, key, False, "NOT_FOUND")
        return jsonify(ok=False, code="NOT_FOUND",
                       error="没有找到该公钥，请核对后重试"), 404

    if not row["enabled"]:
        _write_log(row["id"], key, False, "DISABLED")
        return jsonify(ok=False, code="DISABLED",
                       error="该解压码已被停用，请联系分享者"), 403

    if is_expired(row["expires_at"]):
        _write_log(row["id"], key, False, "EXPIRED")
        return jsonify(ok=False, code="EXPIRED",
                       error="该解压码已过期，请联系分享者获取新的公钥"), 410

    # 同一 IP 对同一公钥：24 小时内重复提取视为同一次，不消耗次数
    now = now_iso()
    grant_until = (
        datetime.now(timezone.utc) + timedelta(hours=GRANT_HOURS)
    ).isoformat(timespec="seconds")

    # 一条语句同时处理「新领取」和「过期后重新领取」；
    # 已有未过期凭据时 WHERE 不成立，changes() 为 0，即判定为重复提取。
    cur = db.execute(
        "INSERT INTO grants (code_id, ip, created_at, expires_at, last_at, uses)"
        " VALUES (?,?,?,?,?,1)"
        " ON CONFLICT(code_id, ip) DO UPDATE SET"
        "   created_at = excluded.created_at,"
        "   expires_at = excluded.expires_at,"
        "   last_at   = excluded.last_at,"
        "   uses      = grants.uses + 1"
        " WHERE grants.expires_at <= ?",
        (row["id"], ip, now, grant_until, now, now),
    )
    reused = cur.rowcount == 0

    if reused:
        g = db.execute(
            "SELECT expires_at, uses FROM grants WHERE code_id = ? AND ip = ?",
            (row["id"], ip),
        ).fetchone()
        db.execute(
            "UPDATE grants SET uses = uses + 1, last_at = ? WHERE code_id = ? AND ip = ?",
            (now, row["id"], ip),
        )
        db.commit()
        _write_log(row["id"], key, True, "REUSE")
        return jsonify(
            ok=True,
            secret=row["secret"],
            title=row["title"],
            note=row["note"],
            used_count=row["used_count"],
            max_uses=row["max_uses"],
            expires_at=row["expires_at"],
            reused=True,
            grant_expires_at=g["expires_at"] if g else grant_until,
        )

    # 新的一次提取：原子累加，避免并发下越过上限
    upd = db.execute(
        "UPDATE codes SET used_count = used_count + 1, last_used_at = ?"
        " WHERE id = ? AND (max_uses IS NULL OR used_count < max_uses)",
        (now, row["id"]),
    )
    if upd.rowcount == 0:
        # 次数刚好用尽，撤销刚才写入的凭据
        db.rollback()
        _write_log(row["id"], key, False, "EXHAUSTED")
        return jsonify(ok=False, code="EXHAUSTED",
                       error="该公钥的提取次数已用完，请联系分享者"), 429

    db.commit()
    _purge_grants(db)
    _write_log(row["id"], key, True, "OK")

    return jsonify(
        ok=True,
        secret=row["secret"],
        title=row["title"],
        note=row["note"],
        used_count=row["used_count"] + 1,
        max_uses=row["max_uses"],
        expires_at=row["expires_at"],
        reused=False,
        grant_expires_at=grant_until,
    )


_last_purge = 0.0


def _purge_grants(db, force: bool = False) -> None:
    """清掉过期的领取凭据。进程内节流，最多半小时执行一次。"""
    global _last_purge
    now_ts = time.time()
    if not force and now_ts - _last_purge < 1800:
        return
    _last_purge = now_ts
    try:
        db.execute("DELETE FROM grants WHERE expires_at <= ?", (now_iso(),))
        db.commit()
    except sqlite3.Error:
        pass


def _write_log(code_id, public_key, ok, reason):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO logs (code_id, public_key, ip, user_agent, ok, reason, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (code_id, public_key, client_ip(),
             (request.headers.get("User-Agent") or "")[:255],
             1 if ok else 0, reason, now_iso()),
        )
        db.commit()
    except Exception:
        pass


# ----------------------------------------------------------------------------
# 后台接口：登录 / 登出 / 改密码
# ----------------------------------------------------------------------------
@app.route("/api/admin/login", methods=["POST"])
def api_login():
    ip = client_ip()
    if not login_limiter.check(ip):
        retry = login_limiter.retry_after(ip)
        return jsonify(ok=False, error=f"尝试次数过多，请 {retry} 秒后再试"), 429

    payload = request.get_json(silent=True) or {}
    pwd = str(payload.get("password", ""))
    login_limiter.hit(ip)

    env_pwd = admin_password_env()
    if env_pwd is not None:
        good = hmac.compare_digest(pwd, env_pwd)
    else:
        good = _verify_password(pwd, _load_config().get("password_hash", ""))

    if not good:
        return jsonify(ok=False, error="密码错误"), 401

    session.permanent = True
    session["admin"] = True
    session["login_at"] = now_iso()
    return jsonify(ok=True, using_env_password=env_pwd is not None)


@app.route("/api/admin/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify(ok=True)


@app.route("/api/admin/password", methods=["POST"])
@login_required
def api_change_password():
    if admin_password_env() is not None:
        return jsonify(ok=False, error="当前密码由环境变量 ADMIN_PASSWORD 指定，请在部署配置中修改"), 400

    payload = request.get_json(silent=True) or {}
    old = str(payload.get("old_password", ""))
    new = str(payload.get("new_password", ""))

    cfg = _load_config()
    if not _verify_password(old, cfg.get("password_hash", "")):
        return jsonify(ok=False, error="原密码不正确"), 400
    if len(new) < 6:
        return jsonify(ok=False, error="新密码至少 6 位"), 400

    cfg["password_hash"] = _hash_password(new)
    _save_config(cfg)
    session.clear()
    return jsonify(ok=True, message="密码已更新，请重新登录")


# ----------------------------------------------------------------------------
# 后台接口：解压码管理
# ----------------------------------------------------------------------------
def _serialize(row) -> dict:
    return {
        "id": row["id"],
        "public_key": row["public_key"],
        "title": row["title"],
        "secret": row["secret"],
        "note": row["note"],
        "share_theme": row["share_theme"] or "",
        "max_uses": row["max_uses"],
        "used_count": row["used_count"],
        "expires_at": row["expires_at"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "expired": is_expired(row["expires_at"]),
        "exhausted": row["max_uses"] is not None and row["used_count"] >= row["max_uses"],
    }


@app.route("/api/admin/codes", methods=["GET"])
@login_required
def api_list_codes():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    sql = "SELECT * FROM codes"
    params: list = []
    if q:
        sql += " WHERE public_key LIKE ? OR title LIKE ? OR note LIKE ?"
        like = f"%{q}%"
        params = [like, like, like]
    sql += " ORDER BY id DESC"
    rows = db.execute(sql, params).fetchall()

    all_rows = db.execute("SELECT enabled, expires_at, used_count, max_uses FROM codes").fetchall()
    today = datetime.now(timezone.utc).date().isoformat()
    stats = {
        "total": len(all_rows),
        "active": sum(
            1 for r in all_rows
            if r["enabled"] and not is_expired(r["expires_at"])
            and not (r["max_uses"] is not None and r["used_count"] >= r["max_uses"])
        ),
        "total_uses": sum(r["used_count"] for r in all_rows),
        "today_uses": db.execute(
            "SELECT COUNT(*) c FROM logs WHERE ok = 1 AND created_at LIKE ?",
            (today + "%",),
        ).fetchone()["c"],
    }
    return jsonify(ok=True, codes=[_serialize(r) for r in rows], stats=stats)


@app.route("/api/admin/codes", methods=["POST"])
@login_required
def api_create_code():
    payload = request.get_json(silent=True) or {}

    secret = str(payload.get("secret", "")).strip()
    if not secret:
        return jsonify(ok=False, error="解压码不能为空"), 400
    if len(secret) > 200:
        return jsonify(ok=False, error="解压码过长（最多 200 字符）"), 400

    title = str(payload.get("title", "")).strip()[:100] or "未命名解压码"
    note = str(payload.get("note", "")).strip()[:500]

    share_theme = str(payload.get("share_theme", "") or "").strip()
    if share_theme and share_theme not in SHARE_THEMES:
        return jsonify(ok=False, error="不支持的说明页风格"), 400

    max_uses = payload.get("max_uses")
    if max_uses in ("", None):
        max_uses = None
    else:
        try:
            max_uses = int(max_uses)
            if max_uses < 1:
                raise ValueError
            if max_uses > 1_000_000:
                max_uses = 1_000_000
        except (TypeError, ValueError):
            return jsonify(ok=False, error="最大提取次数应为正整数，留空表示不限"), 400

    expires_at = parse_expires(payload.get("expires_at"))
    if payload.get("expires_at") and expires_at is None:
        return jsonify(ok=False, error="有效期格式不正确"), 400
    if expires_at and is_expired(expires_at):
        return jsonify(ok=False, error="有效期必须晚于当前时间"), 400

    db = get_db()
    key = gen_public_key()
    for _ in range(8):
        exists = db.execute("SELECT 1 FROM codes WHERE public_key = ?", (key,)).fetchone()
        if not exists:
            break
        key = gen_public_key()
    else:
        return jsonify(ok=False, error="公钥生成失败，请重试"), 500

    cur = db.execute(
        "INSERT INTO codes (public_key, title, secret, note, share_theme, max_uses, expires_at,"
        " enabled, used_count, created_at) VALUES (?,?,?,?,?,?,?,1,0,?)",
        (key, title, secret, note, share_theme, max_uses, expires_at, now_iso()),
    )
    db.commit()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(ok=True, code=_serialize(row))


@app.route("/api/admin/codes/<int:code_id>", methods=["PATCH"])
@login_required
def api_update_code(code_id: int):
    payload = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    if row is None:
        return jsonify(ok=False, error="记录不存在"), 404

    fields, params = [], []

    if "title" in payload:
        title = str(payload["title"]).strip()[:100] or "未命名解压码"
        fields.append("title = ?"); params.append(title)
    if "secret" in payload:
        secret = str(payload["secret"]).strip()
        if not secret:
            return jsonify(ok=False, error="解压码不能为空"), 400
        fields.append("secret = ?"); params.append(secret[:200])
    if "note" in payload:
        fields.append("note = ?"); params.append(str(payload["note"]).strip()[:500])
    if "share_theme" in payload:
        th = str(payload["share_theme"] or "").strip()
        if th and th not in SHARE_THEMES:
            return jsonify(ok=False, error="不支持的说明页风格"), 400
        fields.append("share_theme = ?"); params.append(th)
    if "enabled" in payload:
        fields.append("enabled = ?"); params.append(1 if payload["enabled"] else 0)
    if "max_uses" in payload:
        mu = payload["max_uses"]
        if mu in ("", None):
            fields.append("max_uses = ?"); params.append(None)
        else:
            try:
                mu = int(mu)
                if mu < 1:
                    raise ValueError
            except (TypeError, ValueError):
                return jsonify(ok=False, error="最大提取次数应为正整数"), 400
            fields.append("max_uses = ?"); params.append(mu)
    if "expires_at" in payload:
        if not payload["expires_at"]:
            fields.append("expires_at = ?"); params.append(None)
        else:
            exp = parse_expires(payload["expires_at"])
            if exp is None:
                return jsonify(ok=False, error="有效期格式不正确"), 400
            fields.append("expires_at = ?"); params.append(exp)

    if not fields:
        return jsonify(ok=False, error="没有需要更新的内容"), 400

    params.append(code_id)
    db.execute(f"UPDATE codes SET {', '.join(fields)} WHERE id = ?", params)
    db.commit()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    return jsonify(ok=True, code=_serialize(row))


@app.route("/api/admin/codes/<int:code_id>", methods=["DELETE"])
@login_required
def api_delete_code(code_id: int):
    db = get_db()
    db.execute("DELETE FROM grants WHERE code_id = ?", (code_id,))
    db.execute("DELETE FROM codes WHERE id = ?", (code_id,))
    db.commit()
    return jsonify(ok=True)


@app.route("/api/admin/codes/<int:code_id>/reset", methods=["POST"])
@login_required
def api_reset_usage(code_id: int):
    db = get_db()
    db.execute("UPDATE codes SET used_count = 0, last_used_at = NULL WHERE id = ?", (code_id,))
    # 清零后重新开始计时，否则同一 IP 仍会命中 24 小时内的旧凭据
    db.execute("DELETE FROM grants WHERE code_id = ?", (code_id,))
    db.commit()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    if row is None:
        return jsonify(ok=False, error="记录不存在"), 404
    return jsonify(ok=True, code=_serialize(row))


@app.route("/api/admin/codes/<int:code_id>/regenerate", methods=["POST"])
@login_required
def api_regenerate_key(code_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    if row is None:
        return jsonify(ok=False, error="记录不存在"), 404

    key = gen_public_key()
    for _ in range(8):
        if not db.execute("SELECT 1 FROM codes WHERE public_key = ?", (key,)).fetchone():
            break
        key = gen_public_key()

    db.execute("UPDATE codes SET public_key = ? WHERE id = ?", (key, code_id))
    db.commit()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    return jsonify(ok=True, code=_serialize(row))


@app.route("/api/admin/logs", methods=["GET"])
@login_required
def api_logs():
    db = get_db()
    limit = min(int(request.args.get("limit", 100) or 100), 500)
    rows = db.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify(ok=True, logs=[dict(r) for r in rows])


@app.route("/api/admin/export.csv")
@login_required
def api_export():
    db = get_db()
    rows = db.execute("SELECT * FROM codes ORDER BY id DESC").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "公钥", "名称", "解压码", "提取说明", "已提取", "最大次数",
                     "有效期至", "状态", "创建时间", "最后提取"])
    for r in rows:
        writer.writerow([
            r["id"], r["public_key"], r["title"], r["secret"], r["note"],
            r["used_count"], r["max_uses"] or "不限", r["expires_at"] or "永久",
            "启用" if r["enabled"] else "停用", r["created_at"], r["last_used_at"] or "",
        ])
    data = "\ufeff" + buf.getvalue()
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=extract-codes.csv"},
    )


# ----------------------------------------------------------------------------
# 站点设置
# ----------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "site_name": "解压码提取",
    "site_intro": "公钥由分享者提供，输入后可以看到对应的解压码。",
    "site_footer": "解压码由分享者设置。如果公钥失效，请联系分享者重新生成。",
    "share_theme": "plain",
    "share_title": "解压说明",
    "share_intro": "这个压缩包有密码。解压码不在包里面，按下面三步取一下。",
    "share_footer": "公钥失效或打不开，可以联系发你文件的人重新要一个。",
    "show_watermark": "1",
    "contact_name": "",
    "contact_url": "",
    "smtp_host": "",
    "smtp_port": "465",
    "smtp_user": "",
    "smtp_pass": "",
    "smtp_from": "",
    "smtp_ssl": "1",
}

SHARE_THEMES = ("plain", "dark", "paper", "minimal")


def get_settings() -> dict:
    if "settings" in g:
        return g.settings
    data = dict(DEFAULT_SETTINGS)
    try:
        for row in get_db().execute("SELECT key, value FROM settings"):
            if row["key"] in data:
                data[row["key"]] = row["value"]
    except sqlite3.Error:
        pass
    g.settings = data
    return data


@app.context_processor
def inject_site():
    try:
        s = get_settings()
    except Exception:
        s = dict(DEFAULT_SETTINGS)
    if CLIENT_LICENSE_MODE:
        # 安装版：页脚署名由授权服务器按站点下发，本地不可改
        watermark = license_client.watermark()
    else:
        watermark = True if WATERMARK_LOCKED else s.get("show_watermark", "1") != "0"
    return {
        "client_mode": CLIENT_LICENSE_MODE,
        "license_mode": bool(globals().get("LICENSE_SERVER_MODE")),
        "site": {
            "name": s["site_name"],
            "intro": s["site_intro"],
            "footer": s["site_footer"],
            "watermark": watermark,
            "watermark_locked": WATERMARK_LOCKED,
            "author_name": AUTHOR_NAME,
            "author_url": AUTHOR_URL,
            "contact_name": s.get("contact_name", ""),
            "contact_url": s.get("contact_url", ""),
            "year": time.strftime("%Y"),
        }
    }


@app.route("/api/admin/settings", methods=["GET"])
@login_required
def api_get_settings():
    return jsonify(ok=True, settings=get_settings(), themes=list(SHARE_THEMES))


@app.route("/api/admin/settings", methods=["POST"])
@login_required
def api_save_settings():
    payload = request.get_json(silent=True) or {}
    limits = {
        "site_name": 40,
        "site_intro": 200,
        "site_footer": 200,
        "share_title": 30,
        "share_intro": 200,
        "share_footer": 200,
        "contact_name": 30,
        "contact_url": 200,
        "smtp_host": 120,
        "smtp_port": 6,
        "smtp_user": 120,
        "smtp_pass": 200,
        "smtp_from": 120,
    }
    updates = {}
    for key, limit in limits.items():
        if key not in payload:
            continue
        value = str(payload[key]).strip()
        if not value and key in ("site_name", "share_title"):
            return jsonify(ok=False, error="名称不能为空"), 400
        updates[key] = value[:limit]

    if "share_theme" in payload:
        theme = str(payload["share_theme"])
        if theme not in SHARE_THEMES:
            return jsonify(ok=False, error="不支持的风格"), 400
        updates["share_theme"] = theme

    if "show_watermark" in payload:
        if WATERMARK_LOCKED:
            # 发行版：署名固定保留，忽略关闭请求
            updates["show_watermark"] = "1"
        else:
            updates["show_watermark"] = "1" if payload["show_watermark"] in (True, 1, "1", "true") else "0"

    if "smtp_ssl" in payload:
        updates["smtp_ssl"] = "1" if payload["smtp_ssl"] in (True, 1, "1", "true") else "0"

    # 邮件密码留空表示不修改，避免后台回显明文
    if not updates.get("smtp_pass"):
        updates.pop("smtp_pass", None)

    if not updates:
        return jsonify(ok=False, error="没有需要保存的内容"), 400

    db = get_db()
    for key, value in updates.items():
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    db.commit()
    g.pop("settings", None)
    return jsonify(ok=True, settings=get_settings())


# ----------------------------------------------------------------------------
# 安装向导
# ----------------------------------------------------------------------------
@app.route("/install")
def install_page():
    if is_installed():
        return redirect("/admin")
    return render_template("install.html", themes=list(SHARE_THEMES), defaults=DEFAULT_SETTINGS)


@app.route("/api/install", methods=["POST"])
def api_install():
    if is_installed():
        return jsonify(ok=False, error="站点已经初始化过了"), 400

    payload = request.get_json(silent=True) or {}

    site_name = str(payload.get("site_name", "")).strip()[:40]
    site_intro = str(payload.get("site_intro", "")).strip()[:200]
    site_footer = str(payload.get("site_footer", "")).strip()[:200]
    share_title = str(payload.get("share_title", "")).strip()[:30]
    share_intro = str(payload.get("share_intro", "")).strip()[:200]
    share_footer = str(payload.get("share_footer", "")).strip()[:200]
    password = str(payload.get("password", ""))
    confirm = str(payload.get("password_confirm", ""))
    watermark = "1" if (WATERMARK_LOCKED or payload.get("show_watermark") in (True, 1, "1", "true")) else "0"

    if not site_name:
        return jsonify(ok=False, error="请填写网站名称"), 400
    if len(password) < 6:
        return jsonify(ok=False, error="后台密码至少 6 位"), 400
    if password != confirm:
        return jsonify(ok=False, error="两次输入的密码不一致"), 400

    if CLIENT_LICENSE_MODE:
        # 安装版必须先激活授权：授权码 + 部署域名
        lic_ok, lic_msg = license_client.activate(
            str(payload.get("license_key", "")),
            str(payload.get("license_domain", "")),
            secrets.token_hex(8),
        )
        if not lic_ok:
            return jsonify(ok=False, error=lic_msg or "授权校验未通过"), 403

    values = {
        "site_name": site_name,
        "site_intro": site_intro or DEFAULT_SETTINGS["site_intro"],
        "site_footer": site_footer or DEFAULT_SETTINGS["site_footer"],
        "share_title": share_title or DEFAULT_SETTINGS["share_title"],
        "share_intro": share_intro or DEFAULT_SETTINGS["share_intro"],
        "share_footer": share_footer or DEFAULT_SETTINGS["share_footer"],
        "share_theme": "plain",
        "show_watermark": watermark,
    }

    db = get_db()
    for key, value in values.items():
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    db.commit()
    g.pop("settings", None)

    cfg = _load_config()
    cfg["password_hash"] = _hash_password(password)
    cfg["installed_at"] = now_iso()
    cfg["version"] = APP_VERSION
    _save_config(cfg)

    with open(INSTALL_FLAG, "w", encoding="utf-8") as f:
        json.dump(
            {"installed_at": now_iso(), "version": APP_VERSION},
            f, ensure_ascii=False, indent=2,
        )

    session.permanent = True
    session["admin"] = True
    session["login_at"] = now_iso()
    return jsonify(ok=True, redirect="/admin")


# ----------------------------------------------------------------------------
# 导出「解压说明」单页 HTML（放进压缩包用）
# ----------------------------------------------------------------------------
EXTRACT_PAGE_TPL = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}} - {{PKG}}</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 16px 48px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    font-size: 15px; line-height: 1.65;
    background: var(--page-bg); color: var(--ink);
  }
  body.theme-plain {
    --page-bg: #f4f5f7; --card-bg: #fff; --card-border: #e4e6e9;
    --ink: #1c1e21; --muted: #7b8494; --line: #eef0f2;
    --accent: #2563eb; --accent-ink: #fff;
    --key-bg: #f7f8fa; --key-border: #e4e6e9; --key-ink: #1c1e21;
    --note-bg: #fffdf5; --note-border: #f0e6c8; --note-ink: #6b5a2a;
  }
  body.theme-dark {
    --page-bg: #15171a; --card-bg: #1c1f23; --card-border: #2b2f35;
    --ink: #e9ebee; --muted: #99a1ab; --line: #2a2e34;
    --accent: #7aa2ff; --accent-ink: #101318;
    --key-bg: #21252a; --key-border: #343a41; --key-ink: #d7e4ff;
    --note-bg: #24211a; --note-border: #3d3728; --note-ink: #d8caa0;
  }
  body.theme-paper {
    --page-bg: #f5f2ec; --card-bg: #fffdf8; --card-border: #e5dece;
    --ink: #2b2620; --muted: #7d7364; --line: #eae3d5;
    --accent: #a05a2c; --accent-ink: #fff;
    --key-bg: #faf5e9; --key-border: #e3d8c2; --key-ink: #6b4a22;
    --note-bg: #fdf8ed; --note-border: #e7dcc4; --note-ink: #6d5a33;
  }
  body.theme-minimal {
    --page-bg: #fff; --card-bg: #fff; --card-border: transparent;
    --ink: #17181a; --muted: #8a9099; --line: #e9eaec;
    --accent: #17181a; --accent-ink: #fff;
    --key-bg: #fff; --key-border: #dcdee2; --key-ink: #17181a;
    --note-bg: #fafafa; --note-border: #e6e7e9; --note-ink: #4a4f57;
  }
  .page {
    max-width: 520px; margin: 0 auto; background: var(--card-bg);
    border: 1px solid var(--card-border); border-radius: 8px; padding: 30px 28px 24px;
    box-shadow: 0 1px 2px rgba(16,24,40,.04);
  }
  body.theme-minimal .page { border: 0; box-shadow: none; padding: 8px 0 0; max-width: 480px; }
  .label { font-size: 12px; color: var(--muted); letter-spacing: .04em; }
  h1 { font-size: 21px; margin: 6px 0 10px; word-break: break-word; }
  .lead { color: var(--muted); font-size: 14px; margin: 0 0 22px; }
  .steps { border-top: 1px solid var(--line); }
  .step { display: flex; gap: 12px; padding: 14px 0; border-bottom: 1px solid var(--line); }
  .step .n {
    flex: none; width: 22px; height: 22px; border-radius: 50%;
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent); font-size: 12px; line-height: 22px; text-align: center;
  }
  .step .t { font-weight: 600; font-size: 14px; }
  .step .d { color: var(--muted); font-size: 13px; word-break: break-all; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .keybox {
    margin: 22px 0 6px; padding: 16px; background: var(--key-bg);
    border: 1px solid var(--key-border); border-radius: 6px;
  }
  .kval {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 22px; letter-spacing: .06em; font-weight: 600;
    margin: 6px 0 12px; word-break: break-all; user-select: all; color: var(--key-ink);
  }
  .kbtns { display: flex; gap: 8px; flex-wrap: wrap; }
  .kbtns button, .kbtns a {
    display: inline-block; height: 32px; line-height: 30px; padding: 0 12px;
    border: 1px solid var(--key-border); border-radius: 4px; background: transparent;
    color: var(--ink); font-size: 13px; cursor: pointer; text-decoration: none;
  }
  .kbtns button:hover { opacity: .75; }
  .kbtns a { border-color: var(--accent); background: var(--accent); color: var(--accent-ink); }
  .kbtns a:hover { opacity: .9; text-decoration: none; }
  .note {
    margin-top: 16px; padding: 10px 12px; background: var(--note-bg);
    border: 1px solid var(--note-border); border-radius: 4px; font-size: 13px; color: var(--note-ink);
    white-space: pre-wrap; word-break: break-word;
  }
  .foot { margin-top: 24px; padding-top: 14px; border-top: 1px solid var(--line); font-size: 12px; color: var(--muted); }
  .foot code { font-family: ui-monospace, Menlo, Consolas, monospace; }
  @media (max-width: 480px) {
    .page { padding: 22px 18px 18px; }
    .kval { font-size: 19px; }
    body.theme-minimal .page { padding: 4px 0 0; }
  }
  @media print {
    body { background: #fff; padding: 0; }
    .page { border: 0; box-shadow: none; max-width: none; padding: 0; }
    .kbtns { display: none; }
  }
</style>
</head>
<body class="theme-{{THEME}}">
<div class="page">
  <div class="label">{{TITLE}}</div>
  <h1>{{PKG}}</h1>
  <p class="lead">{{INTRO}}</p>

  <div class="steps">
    <div class="step">
      <span class="n">1</span>
      <div>
        <div class="t">打开提取页</div>
        <div class="d"><a href="{{URL}}" target="_blank" rel="noopener">{{URL}}</a></div>
      </div>
    </div>
    <div class="step">
      <span class="n">2</span>
      <div>
        <div class="t">输入下面的公钥</div>
        <div class="d">直接复制粘贴，大小写和横线都不影响</div>
      </div>
    </div>
    <div class="step">
      <span class="n">3</span>
      <div>
        <div class="t">页面上会显示解压码</div>
        <div class="d">拿到后回到压缩包输入就行</div>
      </div>
    </div>
  </div>

  <div class="keybox">
    <div class="label">公钥</div>
    <div class="kval" id="kval">{{KEY}}</div>
    <div class="kbtns">
      <button type="button" onclick="copyKey()">复制公钥</button>
      <a href="{{URL_KEY}}" target="_blank" rel="noopener">打开提取页</a>
    </div>
  </div>
{{NOTE_BLOCK}}
  <div class="foot">
    提取页：<code>{{HOST}}</code><br>
    {{FOOT}}
  </div>
</div>

<script>
function copyKey() {
  var el = document.getElementById('kval');
  var text = el.textContent.trim();
  function fallback() {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    flash('已复制');
  }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(function () { flash('已复制'); }, fallback);
  } else {
    fallback();
  }
}
function flash(msg) {
  var b = document.querySelector('.kbtns button');
  if (!b) return;
  var old = b.textContent;
  b.textContent = msg;
  setTimeout(function () { b.textContent = old; }, 1500);
}
</script>
</body>
</html>
"""


def html_escape(s) -> str:
    return (str(s or "")
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def build_extract_page(row, base_url: str) -> str:
    """生成可离线打开的单页 HTML。row 可以是 sqlite3.Row 或 dict。"""
    cfg = get_settings()
    url = base_url.rstrip("/") + "/"
    url_key = url + "?k=" + row["public_key"]

    note_block = ""
    if row["note"]:
        note_block = '  <div class="note">%s</div>' % html_escape(row["note"])

    try:
        row_theme = (row["share_theme"] or "")
    except (KeyError, IndexError, TypeError):
        row_theme = ""
    theme = row_theme or cfg.get("share_theme", "plain")
    if theme not in SHARE_THEMES:
        theme = "plain"

    return (
        EXTRACT_PAGE_TPL
        .replace("{{THEME}}", theme)
        .replace("{{TITLE}}", html_escape(cfg["share_title"]))
        .replace("{{PKG}}", html_escape(row["title"] or "未命名"))
        .replace("{{INTRO}}", html_escape(cfg["share_intro"]))
        .replace("{{FOOT}}", html_escape(cfg["share_footer"]))
        .replace("{{KEY}}", html_escape(row["public_key"]))
        .replace("{{URL_KEY}}", html_escape(url_key))
        .replace("{{HOST}}", html_escape(url.rstrip("/")))
        .replace("{{NOTE_BLOCK}}", note_block)
        .replace("{{URL}}", html_escape(url))
    )


@app.route("/api/admin/codes/<int:code_id>/html", methods=["GET"])
@login_required
def api_export_html(code_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE id = ?", (code_id,)).fetchone()
    if row is None:
        return jsonify(ok=False, error="记录不存在"), 404

    page = build_extract_page(row, request.url_root)

    name = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", row["title"] or "解压说明").strip(" .")[:60]
    filename = f"解压说明-{name or '未命名'}.html"
    quoted = quote(filename, safe="")
    return Response(
        page,
        mimetype="text/html",
        headers={
            "Content-Disposition": f"attachment; filename=\"extract-note.html\"; filename*=UTF-8''{quoted}",
            "Cache-Control": "no-store",
        },
    )


@app.route("/api/admin/share-preview", methods=["GET"])
@login_required
def api_share_preview():
    theme = (request.args.get("theme") or "").strip()
    sample = {
        "title": "示例素材包",
        "public_key": "AB3D-9F2K-7Q1M",
        "note": "这里显示你在创建解压码时填的说明，例如：解压有问题找我。",
        "share_theme": theme if theme in SHARE_THEMES else "",
    }
    return Response(build_extract_page(sample, request.url_root), mimetype="text/html")


# ----------------------------------------------------------------------------
# 错误处理
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error="接口不存在"), 404
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify(ok=False, error="请求体过大"), 413


init_db()  # 兼容 gunicorn 等 WSGI 部署方式


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    print(f"  ➜  解压码提取站 v{APP_VERSION}")
    print(f"  ➜  前台: http://127.0.0.1:{port}/")
    print(f"  ➜  后台: http://127.0.0.1:{port}/admin")
    app.run(host=host, port=port, debug=debug, threaded=True)
