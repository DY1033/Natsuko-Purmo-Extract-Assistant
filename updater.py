#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在线更新客户端：拉取服务端签发的包体 → SHA-256 + Ed25519 双重校验
→ 备份现有程序文件 → 原子替换（保留 data/、venv/ 等用户数据）→ 通知主进程重载。

私钥只存在于授权服务端；这里只内置公钥，任何人无法伪造通过验签的包体。
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import shutil
import signal
import threading
import time
import zipfile
from datetime import datetime, timezone
from urllib import request as urlreq

# 服务端 Ed25519 公钥（Raw 32 字节，Base64）。与私钥配对，公开无安全风险。
PUBLIC_KEY_B64 = "pU7BZyQhjzdGl9cp/Vdbzg2SsSypLe4+h+rN9ze1bsw="
MAX_SIZE = 32 * 1024 * 1024
SKIP_PREFIXES = ("data/", "venv/", ".git/", "__pycache__/", ".venv/")
SKIP_NAMES = {"license_server.py"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _post(url: str, payload: dict, timeout: int = 10) -> dict:
    req = urlreq.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "PurmoUpdater/1.2"},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"ok": False, "network_error": str(exc)[:160]}


def check(server: str, current_version: str, license_state: dict) -> dict:
    """向授权服务器查询最新版。需要有效授权码。"""
    key = (license_state.get("key") or "").strip()
    if not key:
        return {"ok": False, "error": "站点尚未激活授权，无法检查更新"}
    data = _post((server or "").rstrip("/") + "/api/update/check", {
        "key": key,
        "domain": license_state.get("domain", ""),
        "current_version": current_version,
    })
    if data.get("network_error"):
        data["error"] = "连不上更新服务器：" + data["network_error"]
    return data


def download(url: str, timeout: int = 90) -> bytes:
    req = urlreq.Request(url, headers={"User-Agent": "PurmoUpdater/1.2"})
    with urlreq.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(MAX_SIZE + 1)
    if len(raw) > MAX_SIZE:
        raise ValueError("更新包超过 32 MB 限制")
    return raw


def verify(raw: bytes, sha256_hex: str, signature_hex: str) -> None:
    """摘要 + 签名双重校验；任一不符直接抛异常，绝不落盘安装。"""
    if not sha256_hex or not signature_hex:
        raise ValueError("更新信息缺少校验值")
    digest = hashlib.sha256(raw).digest()
    if not hmac.compare_digest(digest.hex(), sha256_hex.lower()):
        raise ValueError("SHA-256 校验失败：包体不完整或已被篡改")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))
        pub.verify(bytes.fromhex(signature_hex), digest)
    except (ImportError, ValueError, InvalidSignature) as exc:
        raise ValueError("Ed25519 验签失败：包体不是官方签发：" + str(exc)[:80])


def _members(zf: zipfile.ZipFile):
    """只取安全的程序文件；用户数据目录、虚拟环境等一律跳过。"""
    out = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        low = name.lower()
        if not name or name.endswith("/"):
            continue
        if name.startswith("/") or ".." in name.split("/") or ":" in name:
            raise ValueError("更新包包含非法路径：" + name[:60])
        if any(low.startswith(p) for p in SKIP_PREFIXES):
            continue
        if low.split("/")[-1] in SKIP_NAMES or low.endswith(".pyc"):
            continue
        out.append((info, name))
    if not any(n == "app.py" for _, n in out):
        raise ValueError("更新包缺少 app.py，拒绝安装")
    return out


def _backup(base_dir: str, data_dir: str, old_version: str) -> str:
    backup_dir = os.path.join(data_dir, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    safe = "".join(c for c in old_version if c.isalnum() or c in ".-")
    path = os.path.join(backup_dir, "before-v" + safe + "-" + time.strftime("%Y%m%d-%H%M%S") + ".zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(base_dir):
            rel = os.path.relpath(root, base_dir)
            dirs[:] = [d for d in dirs if d not in ("data", "venv", ".venv", "__pycache__", ".git", "backups")]
            if rel == ".":
                rel = ""
            for fn in files:
                if fn.endswith((".pyc", ".zip", ".db", ".log", ".key")):
                    continue
                src = os.path.join(root, fn)
                try:
                    zf.write(src, os.path.join(rel, fn))
                except OSError:
                    pass
    return path


def install(raw: bytes, info: dict, base_dir: str, data_dir: str,
            current_version: str) -> dict:
    """验签通过后替换程序文件。返回 {version, backup, files}。"""
    version = str(info.get("version") or "").strip()
    if not version or any(c not in "0123456789abcdeF." for c in version):
        raise ValueError("更新包版本号非法")

    verify(raw, info.get("sha256", ""), info.get("signature", ""))

    staging_root = os.path.join(data_dir, "updates")
    os.makedirs(staging_root, exist_ok=True)
    stage = os.path.join(staging_root, "stage-" + version + "-" + secrets_token())
    saved = os.path.join(staging_root, "package-" + version + ".zip")
    os.makedirs(stage, exist_ok=True)

    try:
        with open(saved, "wb") as f:
            f.write(raw)
        with zipfile.ZipFile(__import__("io").BytesIO(raw)) as zf:
            members = _members(zf)
            # 先全部落到暂存目录，成功后再逐个替换，避免半包状态
            for member, name in members:
                target = os.path.join(stage, name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

        backup = _backup(base_dir, data_dir, current_version)
        written = 0
        for _, name in members:
            src = os.path.join(stage, name)
            dst = os.path.join(base_dir, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            written += 1
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    history_path = os.path.join(data_dir, "update_history.json")
    try:
        history = json.load(open(history_path, encoding="utf-8"))
    except Exception:
        history = []
    history.insert(0, {
        "from": current_version, "to": version, "at": now_iso(),
        "sha256": info.get("sha256", ""), "files": written,
        "backup": os.path.basename(backup),
    })
    with open(history_path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(history[:20], f, ensure_ascii=False, indent=2)
    os.replace(history_path + ".tmp", history_path)

    return {"version": version, "backup": os.path.basename(backup), "files": written}


def secrets_token() -> str:
    import secrets
    return secrets.token_hex(4)


def result_path(data_dir: str) -> str:
    return os.path.join(data_dir, "updates", "last_result.json")


def set_result(data_dir: str, payload: dict) -> None:
    os.makedirs(os.path.join(data_dir, "updates"), exist_ok=True)
    path = result_path(data_dir)
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(path + ".tmp", path)


def get_result(data_dir: str) -> dict:
    try:
        with open(result_path(data_dir), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def history(data_dir: str) -> list:
    try:
        with open(os.path.join(data_dir, "update_history.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def is_gunicorn() -> bool:
    """判断当前 worker 是否运行在 gunicorn 下（父进程即 master）。"""
    try:
        with open("/proc/" + str(os.getppid()) + "/cmdline", "rb") as f:
            return b"gunicorn" in f.read().lower()
    except Exception:
        return False


def reload_master() -> bool:
    """给 gunicorn master 发 HUP：优雅重启所有 worker，加载新代码。"""
    if not is_gunicorn():
        return False
    try:
        os.kill(os.getppid(), signal.SIGHUP)
        return True
    except OSError:
        return False


def start_worker(fn, *args) -> None:
    t = threading.Thread(target=fn, args=args, daemon=True)
    t.start()