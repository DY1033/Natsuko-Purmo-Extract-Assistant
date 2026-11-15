#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
授权客户端（开源安装版专用）

- 安装时用授权码 + 站点域名向授权服务器激活
- 每天自动校验一次授权状态，后台可手动刷新
- 授权被驳回 / 封禁 / 域名不匹配 → 站点停用，只显示授权页
- 网络抖动沿用最近一次已知的有效状态；超过 7 天没能和授权服务器
  通讯成功才会判定失效，避免别人机房抖一下就全站挂掉
- 页脚署名显隐由授权服务器按站点单独下发，本地不可改
"""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
REASON_TEXT = {
    "pending": "授权还在审核中",
    "rejected": "授权申请未通过",
    "banned": "授权已被封禁",
    "invalid_key": "授权码不存在",
    "domain_mismatch": "域名与授权码不匹配",
}


def norm_domain(raw: str) -> str:
    s = (raw or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("?")[0]
    s = s.split("@")[-1].split(":")[0]
    return s.strip(".")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _age_days(iso: str) -> float:
    try:
        d = datetime.fromisoformat(iso)
        return (datetime.now(timezone.utc) - d).total_seconds() / 86400
    except Exception:
        return 999.0


class LicenseClient:
    def __init__(self, server: str, data_dir: str):
        self.server = (server or "").rstrip("/")
        self.path = os.path.join(data_dir, "license.json")
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 存储
    def _read(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _write(self, state: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------ 网络
    def _post(self, endpoint: str, payload: dict, timeout: int = 8) -> dict:
        req = urllib.request.Request(
            self.server + endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "User-Agent": "PurmoExtract/1.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as exc:
            return {"ok": False, "network_error": str(exc)[:120]}

    # ------------------------------------------------------------------ 操作
    def activate(self, key: str, domain: str, instance: str) -> tuple[bool, str]:
        key = (key or "").strip().upper()
        domain = norm_domain(domain)
        if not re.fullmatch(r"NP-[A-Z0-9]{4}(-[A-Z0-9]{4}){4}", key):
            return False, "授权码格式不正确，应为 NP-XXXX-XXXX-XXXX-XXXX"
        if not DOMAIN_RE.match(domain):
            return False, "域名格式不正确"

        data = self._post("/api/license/activate",
                          {"key": key, "domain": domain, "instance": instance})
        if data.get("network_error"):
            return False, "连不上授权服务器，请检查网络后重试"

        if not data.get("ok") or not data.get("valid"):
            return False, data.get("error") or REASON_TEXT.get(
                data.get("reason", ""), "授权校验未通过")

        self._write({
            "key": key, "domain": domain, "instance": instance,
            "status": "approved", "valid": True,
            "watermark": bool(data.get("watermark", True)),
            "app_name": data.get("app_name", ""),
            "activated_at": now_iso(),
            "last_ok_at": now_iso(),
        })
        return True, ""

    def refresh(self) -> tuple[bool, str]:
        """手动 / 定时校验。返回 (是否有效, 展示信息)。"""
        st = self._read()
        key = st.get("key")
        domain = st.get("domain")
        if not key:
            return False, "尚未激活授权"

        data = self._post("/api/license/check",
                          {"key": key, "domain": domain,
                           "instance": st.get("instance", "")})

        if data.get("network_error"):
            # 网络不通：沿用缓存，但累计太久就停用
            if st.get("last_ok_at") and _age_days(st["last_ok_at"]) > 7:
                return False, "连续 7 天无法联系授权服务器，站点已暂停"
            return bool(st.get("valid")), "暂时联系不上授权服务器，沿用上次校验结果"

        if not data.get("ok"):
            return bool(st.get("valid")), "授权服务器返回异常，沿用上次校验结果"

        st["last_ok_at"] = now_iso()
        st["status"] = data.get("status", "")
        st["valid"] = bool(data.get("valid"))
        st["watermark"] = bool(data.get("watermark", True))
        st["checked_at"] = now_iso()
        self._write(st)

        if not st["valid"]:
            return False, REASON_TEXT.get(data.get("reason", ""), "授权未生效")
        return True, "授权正常"

    def maybe_check(self) -> None:
        """每日一次的后台校验，阻塞时间极短（8s 超时 + 每天一次）。"""
        with self._lock:
            st = self._read()
            last = st.get("checked_at") or ""
            if last and _age_days(last) < 1:
                return
            try:
                self.refresh()
            except Exception:
                pass

    # ------------------------------------------------------------------ 状态
    def is_valid(self) -> bool:
        st = self._read()
        if not st.get("key") or not st.get("valid"):
            return False
        # 超过 7 天没能与授权服务器通讯成功 → 停用
        if st.get("last_ok_at") and _age_days(st["last_ok_at"]) > 7:
            return False
        return True

    def watermark(self) -> bool:
        """未授权时强制显示署名；有效时由授权服务器下发。"""
        st = self._read()
        if not self.is_valid():
            return True
        return bool(st.get("watermark", True))

    def info(self) -> dict:
        st = self._read()
        return {
            "key": st.get("key", ""),
            "domain": st.get("domain", ""),
            "status": st.get("status", ""),
            "valid": bool(st.get("valid")),
            "watermark": bool(st.get("watermark", True)),
            "app_name": st.get("app_name", ""),
            "activated_at": st.get("activated_at", ""),
            "last_ok_at": (st.get("last_ok_at") or "").replace("T", " ")[:16],
            "checked_at": (st.get("checked_at") or "").replace("T", " ")[:16],
            "server": self.server,
        }
