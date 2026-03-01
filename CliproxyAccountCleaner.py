#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced UI:
- 直接读取管理端 auth-files 列表
- 支持 401 检测、额度检测、联合检测（与 clean_codex_accounts.py 逻辑对齐）
- 支持关闭/开启账号（PATCH /auth-files/status）与永久删除（DELETE）
"""

import os
import sys
import json
import asyncio
import threading
import urllib.parse
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import aiohttp

HERE = os.path.abspath(os.path.dirname(__file__))


def pick_existing_in(base_dir, *names):
    for n in names:
        p = os.path.join(base_dir, n)
        if os.path.exists(p):
            return p
    return os.path.join(base_dir, names[0])


def resolve_config_path():
    if getattr(sys, "frozen", False):
        exe_dir = os.path.abspath(os.path.dirname(sys.executable))
        return pick_existing_in(exe_dir, "config.json", "config.json.txt")
    return pick_existing_in(HERE, "config.json", "config.json.txt")


CONFIG_PATH = resolve_config_path()

DEFAULT_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
DEFAULT_TIMEOUT = 12
DEFAULT_WORKERS = 120
DEFAULT_QUOTA_WORKERS = 100
DEFAULT_CLOSE_WORKERS = 20
DEFAULT_ENABLE_WORKERS = 20
DEFAULT_DELETE_WORKERS = 20
DEFAULT_RETRIES = 1
DEFAULT_TARGET_TYPE = "codex"
DEFAULT_QUOTA_THRESHOLD = 95
DEFAULT_OUTPUT = "invalid_codex_accounts.json"
DEFAULT_QUOTA_OUTPUT = "invalid_quota_accounts.json"


def load_config(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError("config.json 顶层必须是对象")
    return data


def mgmt_headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}


def safe_json_text(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def as_json_obj(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return safe_json_text(value)
    return {}


def get_item_type(item):
    return item.get("type") or item.get("typo")


def extract_chatgpt_account_id(item):
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return val
    return None


def fetch_auth_files(base_url, token, timeout):
    r = requests.get(
        f"{base_url}/v0/management/auth-files",
        headers=mgmt_headers(token),
        timeout=timeout,
    )
    r.raise_for_status()
    return safe_json(r).get("files") or []


def refresh_quota_source(base_url, token, timeout):
    """
    与管理页“刷新认证文件&额度”保持一致：
    先请求 config.yaml，再请求 auth-files，最后执行 quota api-call。
    """
    requests.get(
        f"{base_url}/v0/management/config.yaml",
        headers=mgmt_headers(token),
        timeout=timeout,
    ).raise_for_status()

    r = requests.get(
        f"{base_url}/v0/management/auth-files",
        headers=mgmt_headers(token),
        timeout=timeout,
    )
    r.raise_for_status()
    return safe_json(r).get("files") or []


def build_probe_payload(auth_index, user_agent, chatgpt_account_id=None):
    call_header = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    if chatgpt_account_id:
        call_header["Chatgpt-Account-Id"] = chatgpt_account_id

    return {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_header,
    }


def build_quota_payload(auth_index, user_agent, chatgpt_account_id=None):
    call_header = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    if chatgpt_account_id:
        call_header["Chatgpt-Account-Id"] = chatgpt_account_id

    return {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_header,
    }


async def probe_accounts(
    base_url,
    token,
    candidates,
    user_agent,
    fallback_account_id,
    workers,
    timeout,
    retries,
):
    async def probe_one(session, sem, item):
        auth_index = item.get("auth_index")
        name = item.get("name") or item.get("id")
        account = item.get("account") or item.get("email") or ""

        result = {
            "name": name,
            "account": account,
            "auth_index": auth_index,
            "provider": item.get("provider"),
            "type": get_item_type(item),
            "status_code": None,
            "invalid_401": False,
            "error": None,
        }

        if not auth_index:
            result["error"] = "missing auth_index"
            return result

        chatgpt_account_id = extract_chatgpt_account_id(item) or fallback_account_id
        payload = build_probe_payload(auth_index, user_agent, chatgpt_account_id)

        for attempt in range(retries + 1):
            try:
                async with sem:
                    async with session.post(
                        f"{base_url}/v0/management/api-call",
                        headers={**mgmt_headers(token), "Content-Type": "application/json"},
                        json=payload,
                        timeout=timeout,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            raise RuntimeError(f"management api-call http {resp.status}: {text[:200]}")

                        data = safe_json_text(text)
                        sc = data.get("status_code")
                        result["status_code"] = sc
                        result["invalid_401"] = (sc == 401)
                        if sc is None:
                            result["error"] = "missing status_code in api-call response"
                        else:
                            result["error"] = None
                        return result
            except Exception as e:
                result["error"] = str(e)
                if attempt >= retries:
                    return result

        return result

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, workers))

    out = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [asyncio.create_task(probe_one(session, sem, item)) for item in candidates]
        for t in asyncio.as_completed(tasks):
            out.append(await t)
    return out


async def check_quota_accounts(
    base_url,
    token,
    candidates,
    user_agent,
    fallback_account_id,
    workers,
    timeout,
    retries,
    weekly_quota_threshold,
    primary_quota_threshold,
):
    # 对齐管理页刷新顺序：config.yaml -> auth-files -> api-call
    refreshed_files = refresh_quota_source(base_url, token, timeout)

    # 使用刷新后的 auth-files 重建候选，避免用到旧快照
    refreshed_by_auth_index = {}
    for f in refreshed_files:
        ai = f.get("auth_index")
        if ai:
            refreshed_by_auth_index[ai] = f

    refreshed_candidates = []
    for item in candidates:
        ai = item.get("auth_index")
        refreshed_candidates.append(refreshed_by_auth_index.get(ai) or item)

    async def quota_one(session, sem, item):
        auth_index = item.get("auth_index")
        name = item.get("name") or item.get("id")
        account = item.get("account") or item.get("email") or ""

        result = {
            "name": name,
            "account": account,
            "auth_index": auth_index,
            "provider": item.get("provider"),
            "type": get_item_type(item),
            "status_code": None,
            "used_percent": None,
            "reset_at": None,
            # New fields for 5-hour and weekly quotas
            "primary_used_percent": None,
            "primary_reset_at": None,
            "individual_used_percent": None,
            "individual_reset_at": None,
            "invalid_quota": False,
            "quota_source": None,
            "invalid_401": False,
            "error": None,
        }

        # 先读取 auth-files 中已有的状态信息（例如 usage_limit_reached）作为兜底
        # 仅当本次 wham/usage 没有返回可判定的额度字段时才使用，避免旧状态覆盖实时额度判断
        quota_marked_by_status = False
        status_message = item.get("status_message")
        sm_data = as_json_obj(status_message)
        sm_error = sm_data.get("error") if isinstance(sm_data, dict) else {}
        if isinstance(sm_error, dict):
            sm_type = sm_error.get("type")
            if sm_type in ("usage_limit_reached", "insufficient_quota", "quota_exceeded"):
                quota_marked_by_status = True
                if sm_error.get("resets_at") is not None:
                    result["reset_at"] = sm_error.get("resets_at")

        if not auth_index:
            result["error"] = "missing auth_index"
            return result

        chatgpt_account_id = extract_chatgpt_account_id(item) or fallback_account_id
        payload = build_quota_payload(auth_index, user_agent, chatgpt_account_id)

        for attempt in range(retries + 1):
            try:
                async with sem:
                    async with session.post(
                        f"{base_url}/v0/management/api-call",
                        headers={**mgmt_headers(token), "Content-Type": "application/json"},
                        json=payload,
                        timeout=timeout,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            raise RuntimeError(f"management api-call http {resp.status}: {text[:200]}")

                        data = safe_json_text(text)
                        sc = data.get("status_code")
                        result["status_code"] = sc

                        if sc == 200:
                            body = data.get("body", "")
                            usage_data = as_json_obj(body)

                            # Debug: capture raw response
                            result["raw_response"] = body

                            rate_limit = usage_data.get("rate_limit") or usage_data.get("rateLimit") or {}

                            def pick_first_val(d, *keys):
                                if not isinstance(d, dict):
                                    return None
                                for k in keys:
                                    if d.get(k) is not None:
                                        return d.get(k)
                                return None

                            def parse_percent(v):
                                if v is None:
                                    return None
                                if isinstance(v, (int, float)):
                                    return float(v)
                                try:
                                    s = str(v).strip().rstrip("%")
                                    if s == "":
                                        return None
                                    return float(s)
                                except Exception:
                                    return None

                            def parse_window(name, win):
                                if not isinstance(win, dict):
                                    return None
                                return {
                                    "name": name,
                                    "used_percent": parse_percent(
                                        pick_first_val(win, "used_percent", "usedPercent", "used_percentage")
                                    ),
                                    "reset_at": pick_first_val(win, "reset_at", "resetAt"),
                                    "limit_window_seconds": pick_first_val(
                                        win,
                                        "limit_window_seconds",
                                        "limitWindowSeconds",
                                        "window_seconds",
                                        "windowSeconds",
                                    ),
                                    "remaining": pick_first_val(win, "remaining"),
                                    "limit_reached": pick_first_val(win, "limit_reached", "limitReached"),
                                }

                            windows = []
                            for key in (
                                "primary_window",
                                "secondary_window",
                                "individual_window",
                                "primaryWindow",
                                "secondaryWindow",
                                "individualWindow",
                            ):
                                parsed = parse_window(key, rate_limit.get(key))
                                if parsed is not None:
                                    windows.append(parsed)

                            weekly_window = None
                            short_window = None

                            for w in windows:
                                lname = str(w.get("name") or "").lower()
                                if weekly_window is None and "individual" in lname:
                                    weekly_window = w
                                if short_window is None and "secondary" in lname:
                                    short_window = w

                            with_seconds = [
                                w for w in windows if isinstance(w.get("limit_window_seconds"), (int, float))
                            ]
                            if weekly_window is None and with_seconds:
                                weekly_window = max(with_seconds, key=lambda x: x["limit_window_seconds"])

                            if short_window is None and with_seconds:
                                sorted_ws = sorted(with_seconds, key=lambda x: x["limit_window_seconds"])
                                if weekly_window is None:
                                    short_window = sorted_ws[0]
                                else:
                                    for w in sorted_ws:
                                        if w.get("name") != weekly_window.get("name"):
                                            short_window = w
                                            break

                            if weekly_window is None and windows:
                                weekly_window = windows[0]

                            if short_window is None and len(windows) > 1:
                                for w in windows:
                                    if weekly_window is None or w.get("name") != weekly_window.get("name"):
                                        short_window = w
                                        break

                            # 单窗口场景：若窗口很短，按5小时窗口处理；否则按周窗口处理
                            if (
                                short_window is None
                                and weekly_window is not None
                                and isinstance(weekly_window.get("limit_window_seconds"), (int, float))
                                and weekly_window.get("limit_window_seconds") <= 6 * 3600
                            ):
                                short_window = weekly_window
                                weekly_window = None

                            weekly_used_percent = weekly_window.get("used_percent") if weekly_window else None
                            weekly_reset_at = weekly_window.get("reset_at") if weekly_window else None
                            short_used_percent = short_window.get("used_percent") if short_window else None
                            short_reset_at = short_window.get("reset_at") if short_window else None

                            # 兼容原字段语义：individual=周，primary=5小时
                            result["individual_used_percent"] = weekly_used_percent
                            result["individual_reset_at"] = weekly_reset_at
                            result["primary_used_percent"] = short_used_percent
                            result["primary_reset_at"] = short_reset_at

                            used_percent = None
                            if weekly_used_percent is not None:
                                used_percent = weekly_used_percent
                                result["quota_source"] = "weekly"
                            elif short_used_percent is not None:
                                used_percent = short_used_percent
                                result["quota_source"] = "5hour"

                            if used_percent is not None:
                                result["used_percent"] = used_percent
                                if result["quota_source"] == "weekly":
                                    result["invalid_quota"] = used_percent >= weekly_quota_threshold
                                elif result["quota_source"] == "5hour":
                                    result["invalid_quota"] = used_percent >= primary_quota_threshold

                            # 无 used_percent 时，使用 remaining/limit_reached/allowed 兜底识别无额度
                            if result.get("used_percent") is None:
                                remaining_zero = any(w.get("remaining") == 0 for w in windows)
                                weekly_limit_reached = bool(weekly_window and weekly_window.get("limit_reached") is True)
                                short_limit_reached = bool(short_window and short_window.get("limit_reached") is True)
                                rate_limit_reached = pick_first_val(rate_limit, "limit_reached", "limitReached") is True
                                rate_allowed = pick_first_val(rate_limit, "allowed")

                                if weekly_limit_reached:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True
                                    result["quota_source"] = "weekly_limit"
                                elif short_limit_reached:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True
                                    result["quota_source"] = "5hour_limit"
                                elif remaining_zero:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True
                                    result["quota_source"] = "remaining"
                                elif rate_limit_reached or rate_allowed is False:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True
                                    result["quota_source"] = "rate_limit_flag"
                                elif quota_marked_by_status:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True
                                    result["quota_source"] = "status_message"

                            # Set overall reset time (prefer weekly, fallback 5-hour)
                            result["reset_at"] = weekly_reset_at or short_reset_at or result.get("reset_at")
                        elif sc == 401:
                            result["invalid_401"] = True

                        if sc is None:
                            result["error"] = "missing status_code in api-call response"
                        else:
                            result["error"] = None
                        return result
            except Exception as e:
                result["error"] = str(e)
                if attempt >= retries:
                    return result

        return result

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, workers))

    out = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [asyncio.create_task(quota_one(session, sem, item)) for item in refreshed_candidates]
        for t in asyncio.as_completed(tasks):
            out.append(await t)
    return out


async def set_disabled_names(base_url, token, names, disabled, workers, timeout):
    """Toggle account disabled status via management endpoint.
    disabled=True  => close account
    disabled=False => enable account
    """

    async def set_one(session, sem, name):
        url = f"{base_url}/v0/management/auth-files/status"
        payload = {"name": name, "disabled": bool(disabled)}
        try:
            async with sem:
                async with session.patch(
                    url,
                    headers={**mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    data = safe_json_text(text)
                    ok = resp.status == 200 and data.get("status") == "ok"
                    return {
                        "name": name,
                        "updated": ok,
                        "disabled": bool(disabled),
                        "status": resp.status,
                        "error": None if ok else text[:200],
                    }
        except Exception as e:
            return {
                "name": name,
                "updated": False,
                "disabled": bool(disabled),
                "status": None,
                "error": str(e),
            }

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, workers))

    out = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [asyncio.create_task(set_one(session, sem, n)) for n in names]
        for t in asyncio.as_completed(tasks):
            out.append(await t)
    return out


async def close_names(base_url, token, names, close_workers, timeout):
    return await set_disabled_names(base_url, token, names, True, close_workers, timeout)


async def enable_names(base_url, token, names, enable_workers, timeout):
    return await set_disabled_names(base_url, token, names, False, enable_workers, timeout)


async def delete_names(base_url, token, names, delete_workers, timeout):
    async def delete_one(session, sem, name):
        encoded = urllib.parse.quote(name, safe="")
        url = f"{base_url}/v0/management/auth-files?name={encoded}"
        try:
            async with sem:
                async with session.delete(url, headers=mgmt_headers(token), timeout=timeout) as resp:
                    text = await resp.text()
                    data = safe_json_text(text)
                    ok = resp.status == 200 and data.get("status") == "ok"
                    return {"name": name, "deleted": ok, "status": resp.status, "error": None if ok else text[:200]}
        except Exception as e:
            return {"name": name, "deleted": False, "status": None, "error": str(e)}

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, delete_workers))

    out = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [asyncio.create_task(delete_one(session, sem, n)) for n in names]
        for t in asyncio.as_completed(tasks):
            out.append(await t)
    return out


class EnhancedUI(tk.Tk):
    def __init__(self, conf, config_path):
        super().__init__()
        self.title("账号管理（增强版）")
        self.geometry("1220x760")
        self.minsize(1080, 640)

        self.conf = conf
        self.config_path = config_path
        self.all_accounts = []
        self.filtered_accounts = []
        self._compact_usage_mode = False
        self._layout_update_job = None

        self._init_config_vars()
        self._setup_styles()
        self._build()
        self._load_accounts()

    def _init_config_vars(self):
        self.base_url_var = tk.StringVar(value=str(self.conf.get("base_url") or ""))
        self.token_var = tk.StringVar(value=str(self.conf.get("token") or self.conf.get("cpa_password") or ""))
        self.workers_var = tk.StringVar(value=str(self.conf.get("workers") or DEFAULT_WORKERS))
        self.quota_workers_var = tk.StringVar(value=str(self.conf.get("quota_workers") or DEFAULT_QUOTA_WORKERS))
        self.delete_workers_var = tk.StringVar(value=str(self.conf.get("delete_workers") or DEFAULT_DELETE_WORKERS))
        # Separate thresholds for weekly and 5-hour quotas
        self.weekly_quota_threshold_var = tk.StringVar(value=str(self.conf.get("weekly_quota_threshold") or DEFAULT_QUOTA_THRESHOLD))
        self.primary_quota_threshold_var = tk.StringVar(value=str(self.conf.get("primary_quota_threshold") or DEFAULT_QUOTA_THRESHOLD))

        auto_interval = int(self.conf.get("auto_interval_minutes") or 30)
        self.auto_enabled_var = tk.BooleanVar(value=bool(self.conf.get("auto_enabled", False)))
        self.auto_interval_var = tk.StringVar(value=str(max(1, auto_interval)))

        auto_401_action = str(self.conf.get("auto_action_401") or "删除")
        if auto_401_action not in ("删除", "仅标记"):
            auto_401_action = "删除"
        self.auto_401_action_var = tk.StringVar(value=auto_401_action)

        auto_quota_action = str(self.conf.get("auto_action_quota") or "关闭")
        if auto_quota_action not in ("关闭", "删除", "仅标记"):
            auto_quota_action = "关闭"
        self.auto_quota_action_var = tk.StringVar(value=auto_quota_action)

        self._auto_job = None
        self._auto_running = False

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        bg = "#eef6ff"
        panel_bg = "#ffffff"
        self.configure(bg=bg)

        style.configure("TFrame", background=bg, relief="flat", borderwidth=0)
        style.configure("TLabelframe", background=bg, relief="flat", borderwidth=0)
        style.configure("TLabelframe.Label", background=bg, foreground="#0f172a")
        style.configure("TLabel", background=bg, foreground="#0f172a")
        style.configure("TEntry", fieldbackground="#ffffff", borderwidth=0)
        style.configure("TCombobox", fieldbackground="#f4f8fc", borderwidth=0, relief="flat", foreground="#1f2937", arrowsize=14)
        style.map("TCombobox", fieldbackground=[("readonly", "#f4f8fc")], selectbackground=[("readonly", "#dbe7f3")], selectforeground=[("readonly", "#1f2937")])

        style.configure("TCheckbutton", background=bg, foreground="#334155")
        style.map("TCheckbutton", background=[("active", bg)], foreground=[("active", "#1e293b")])
        style.configure("Treeview", rowheight=24, fieldbackground=panel_bg, background=panel_bg, borderwidth=0)
        style.configure("Treeview.Heading", padding=(8, 6), background="#dbeafe", foreground="#0f172a", borderwidth=0)

        style.configure("Unified.TButton", padding=(12, 6), background="#8fa7bf", foreground="#f8fafc", borderwidth=0, relief="flat")
        style.map("Unified.TButton", background=[("active", "#839db6"), ("pressed", "#778fa8")], relief=[("pressed", "flat"), ("active", "flat")])

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        self.status = tk.StringVar(value="正在加载账号列表...")
        ttk.Label(top, textvariable=self.status).pack(side="left")

        ttk.Button(top, text="刷新", command=self._load_accounts, style="Unified.TButton").pack(side="right")
        ttk.Button(top, text="退出", command=self.destroy, style="Unified.TButton").pack(side="right", padx=8)

        cfg = ttk.LabelFrame(self, text="基础参数", padding=(10, 8))
        cfg.pack(fill="x", padx=10, pady=(0, 6))

        row1 = ttk.Frame(cfg)
        row1.pack(fill="x", pady=(0, 4))
        ttk.Label(row1, text="服务地址(base_url)").pack(side="left")
        ttk.Entry(row1, textvariable=self.base_url_var, width=40).pack(side="left", padx=(6, 12))
        ttk.Label(row1, text="令牌(token/cpa_password)").pack(side="left")
        ttk.Entry(row1, textvariable=self.token_var, width=30, show="*").pack(side="left", padx=(6, 0))

        row2 = ttk.Frame(cfg)
        row2.pack(fill="x")
        ttk.Label(row2, text="并发(workers)").pack(side="left")
        ttk.Entry(row2, textvariable=self.workers_var, width=8).pack(side="left", padx=(6, 12))
        ttk.Label(row2, text="额度并发(quota_workers)").pack(side="left")
        ttk.Entry(row2, textvariable=self.quota_workers_var, width=8).pack(side="left", padx=(6, 12))
        ttk.Label(row2, text="删除并发(delete_workers)").pack(side="left")
        ttk.Entry(row2, textvariable=self.delete_workers_var, width=8).pack(side="left", padx=(6, 12))

        row3 = ttk.Frame(cfg)
        row3.pack(fill="x", pady=(8, 0))
        ttk.Label(row3, text="周额度阈值:").pack(side="left")
        ttk.Entry(row3, textvariable=self.weekly_quota_threshold_var, width=8).pack(side="left", padx=(6, 12))
        ttk.Label(row3, text="5小时额度阈值:").pack(side="left")
        ttk.Entry(row3, textvariable=self.primary_quota_threshold_var, width=8).pack(side="left", padx=(6, 0))

        auto = ttk.LabelFrame(self, text="定时检测", padding=(10, 8))
        auto.pack(fill="x", padx=10, pady=(0, 6))

        auto_row = ttk.Frame(auto)
        auto_row.pack(fill="x")
        ttk.Checkbutton(auto_row, text="启用定时任务", variable=self.auto_enabled_var).pack(side="left")
        ttk.Label(auto_row, text="间隔(分钟)").pack(side="left", padx=(10, 4))
        ttk.Entry(auto_row, textvariable=self.auto_interval_var, width=6).pack(side="left", padx=(0, 10))

        ttk.Label(auto_row, text="401账号操作").pack(side="left", padx=(0, 4))
        ttk.Combobox(
            auto_row,
            textvariable=self.auto_401_action_var,
            values=["删除", "仅标记"],
            state="readonly",
            width=8,
        ).pack(side="left", padx=(0, 10))

        ttk.Label(auto_row, text="无额度账号操作").pack(side="left", padx=(0, 4))
        ttk.Combobox(
            auto_row,
            textvariable=self.auto_quota_action_var,
            values=["关闭", "删除", "仅标记"],
            state="readonly",
            width=8,
        ).pack(side="left", padx=(0, 10))

        ttk.Button(auto_row, text="启动定时任务", command=self.start_auto_check, style="Unified.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(auto_row, text="停止定时任务", command=self.stop_auto_check, style="Unified.TButton").pack(side="left")

        self.auto_status_var = tk.StringVar(value="定时任务：未启动")
        ttk.Label(auto, textvariable=self.auto_status_var).pack(side="left", pady=(6, 0))

        self.auto_interval_var.trace_add("write", lambda *_: self._save_config())
        self.auto_401_action_var.trace_add("write", lambda *_: self._save_config())
        self.auto_quota_action_var.trace_add("write", lambda *_: self._save_config())
        self.auto_enabled_var.trace_add("write", lambda *_: self._save_config())

        # 运行参数改动后也持久化到 config.json
        self.base_url_var.trace_add("write", lambda *_: self._save_config())
        self.token_var.trace_add("write", lambda *_: self._save_config())
        self.workers_var.trace_add("write", lambda *_: self._save_config())
        self.quota_workers_var.trace_add("write", lambda *_: self._save_config())
        self.delete_workers_var.trace_add("write", lambda *_: self._save_config())
        self.weekly_quota_threshold_var.trace_add("write", lambda *_: self._save_config())
        self.primary_quota_threshold_var.trace_add("write", lambda *_: self._save_config())

        filter_frame = ttk.Frame(self, padding=(10, 0, 10, 5))
        filter_frame.pack(fill="x")

        ttk.Label(filter_frame, text="过滤:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self._apply_filter)
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=30).pack(side="left", padx=5)

        self.filter_status = ttk.Combobox(
            filter_frame,
            values=["全部", "错误", "活跃", "未知", "已关闭", "401失效", "无额度"],
            state="readonly",
            width=10,
        )
        self.filter_status.set("全部")
        self.filter_status.bind("<<ComboboxSelected>>", self._apply_filter)
        self.filter_status.pack(side="left", padx=5)

        status_frame = ttk.Frame(self, relief="flat", padding=(4, 1))
        status_frame.pack(side="bottom", fill="x")
        status_frame.columnconfigure(0, weight=1)

        self.status_bar = tk.StringVar(value="就绪")
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_bar,
            anchor="w",
            justify="left",
            bg="#e0f2fe",
            fg="#0f172a",
        )
        self.status_label.grid(row=0, column=0, sticky="ew")

        self.brand_label = tk.Label(
            status_frame,
            text="海十Mirage的AI工具ai.hsnb.fun",
            anchor="e",
            justify="right",
            bg="#e0f2fe",
            fg="#1e3a8a",
        )
        self.brand_label.grid(row=0, column=1, sticky="e", padx=(8, 0))
        status_frame.bind("<Configure>", self._update_status_wrap)

        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(fill="both", expand=True)

        bar = ttk.Frame(mid)
        bar.pack(fill="x", pady=(0, 6))

        ttk.Button(bar, text="全选", command=self.select_all, style="Unified.TButton").pack(side="left")
        ttk.Button(bar, text="全不选", command=self.select_none, style="Unified.TButton").pack(side="left", padx=6)

        ttk.Button(bar, text="检查401", command=self.check_401, style="Unified.TButton").pack(side="left", padx=6)
        ttk.Button(bar, text="检查额度", command=self.check_quota, style="Unified.TButton").pack(side="left", padx=6)
        ttk.Button(bar, text="检查401+额度", command=self.check_both, style="Unified.TButton").pack(side="left", padx=6)

        ttk.Button(bar, text="关闭选中", command=self.close_selected, style="Unified.TButton").pack(side="left", padx=12)
        ttk.Button(bar, text="恢复已关闭", command=self.recover_closed_accounts, style="Unified.TButton").pack(side="left", padx=6)
        ttk.Button(bar, text="永久删除", command=self.delete_selected, style="Unified.TButton").pack(side="left", padx=6)

        self.action_progress = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.action_progress).pack(side="right")

        columns = ("name", "account", "status", "error_info", "usage_limit")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", height=24)

        self.tree.heading("name", text="文件名")
        self.tree.heading("account", text="账号/邮箱")
        self.tree.heading("status", text="状态")
        self.tree.heading("error_info", text="错误信息")
        self.tree.heading("usage_limit", text="额度信息")

        self.tree.column("name", width=280, minwidth=160, anchor="w")
        self.tree.column("account", width=220, minwidth=140, anchor="w")
        self.tree.column("status", width=90, minwidth=80, anchor="center")
        self.tree.column("error_info", width=320, minwidth=150, anchor="w")
        self.tree.column("usage_limit", width=320, minwidth=220, anchor="w")

        yscroll = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.toggle_item)
        self.tree.bind("<Configure>", self._on_tree_resize)
        self.after(80, self._update_tree_columns)

    def _update_status_wrap(self, event):
        total_width = int(getattr(event, "width", 0) or 0)
        brand_width = 0
        try:
            brand_width = int(self.brand_label.winfo_reqwidth())
        except Exception:
            brand_width = 0

        # 窗口较窄时让品牌文字换到下一行，避免遮挡状态提示
        if total_width < 960:
            self.brand_label.grid_configure(row=1, column=0, columnspan=2, sticky="e", padx=(0, 0))
        else:
            self.brand_label.grid_configure(row=0, column=1, columnspan=1, sticky="e", padx=(8, 0))

        if total_width < 960:
            width = max(120, total_width - 20)
        else:
            width = max(120, total_width - brand_width - 30)
        try:
            self.status_label.configure(wraplength=width)
        except Exception:
            pass

    def _on_tree_resize(self, _event=None):
        if self._layout_update_job:
            try:
                self.after_cancel(self._layout_update_job)
            except Exception:
                pass
        self._layout_update_job = self.after(60, self._update_tree_columns)

    def _update_tree_columns(self):
        self._layout_update_job = None
        try:
            total_width = int(self.tree.winfo_width())
        except Exception:
            total_width = 0
        if total_width <= 0:
            return

        # 固定列使用较小宽度，剩余空间优先给“错误信息”和“额度信息”
        name_w = max(160, int(total_width * 0.22))
        account_w = max(140, int(total_width * 0.18))
        status_w = max(80, int(total_width * 0.08))

        remain = total_width - name_w - account_w - status_w
        error_w = max(150, int(remain * 0.40))
        usage_w = max(220, remain - error_w)

        # 窄屏时切换为紧凑额度文案，避免关键字段被截断
        compact_mode = total_width < 1120
        if compact_mode != self._compact_usage_mode:
            self._compact_usage_mode = compact_mode
            self._apply_filter()

        try:
            self.tree.column("name", width=name_w)
            self.tree.column("account", width=account_w)
            self.tree.column("status", width=status_w)
            self.tree.column("error_info", width=error_w)
            self.tree.column("usage_limit", width=usage_w)
        except Exception:
            pass

    def _normalize_base_url(self, raw):
        s = str(raw or "").strip()
        s = (
            s.replace("：", ":")
            .replace("／", "/")
            .replace("。", ".")
            .replace("，", ",")
            .replace("；", ";")
            .replace("　", " ")
        )
        s = s.strip().strip("。；，,")
        if s.endswith("/"):
            s = s[:-1]
        return s

    def _save_config(self):
        try:
            # 基础运行参数
            self.conf["base_url"] = self._normalize_base_url(self.base_url_var.get())
            token = self._normalize_token(self.token_var.get())
            self.conf["token"] = token
            self.conf["cpa_password"] = token

            workers_text = str(self.workers_var.get() or "").strip()
            quota_workers_text = str(self.quota_workers_var.get() or "").strip()
            delete_workers_text = str(self.delete_workers_var.get() or "").strip()

            try:
                workers = int(workers_text)
                if workers > 0:
                    self.conf["workers"] = workers
            except Exception:
                pass

            try:
                quota_workers = int(quota_workers_text)
                if quota_workers > 0:
                    self.conf["quota_workers"] = quota_workers
            except Exception:
                pass

            try:
                delete_workers = int(delete_workers_text)
                if delete_workers > 0:
                    self.conf["delete_workers"] = delete_workers
            except Exception:
                pass

            # Save weekly quota threshold
            weekly_quota_threshold_text = str(self.weekly_quota_threshold_var.get() or "").strip()
            try:
                weekly_quota_threshold = int(weekly_quota_threshold_text)
                if 0 <= weekly_quota_threshold <= 100:
                    self.conf["weekly_quota_threshold"] = weekly_quota_threshold
            except Exception:
                pass

            # Save 5-hour quota threshold
            primary_quota_threshold_text = str(self.primary_quota_threshold_var.get() or "").strip()
            try:
                primary_quota_threshold = int(primary_quota_threshold_text)
                if 0 <= primary_quota_threshold <= 100:
                    self.conf["primary_quota_threshold"] = primary_quota_threshold
            except Exception:
                pass

            # 定时配置
            self.conf["auto_enabled"] = bool(self.auto_enabled_var.get())

            interval_text = str(self.auto_interval_var.get() or "").strip()
            try:
                interval_minutes = int(interval_text)
                if interval_minutes > 0:
                    self.conf["auto_interval_minutes"] = interval_minutes
            except Exception:
                pass

            self.conf["auto_action_401"] = self.auto_401_action_var.get()
            self.conf["auto_action_quota"] = self.auto_quota_action_var.get()

            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.conf, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showwarning("保存配置失败", f"配置未写入 config.json:\n{e}")

    def _normalize_token(self, raw):
        s = str(raw or "").strip()
        s = s.replace("　", " ").strip().strip("。；，,")
        return s

    def _ensure_accounts_loaded(self, action_name):
        if self.all_accounts:
            return True
        messagebox.showinfo(action_name, "当前账号列表为空，请先点击“刷新”并确保加载成功。")
        return False

    def _runtime(self):
        base_url = self._normalize_base_url(self.base_url_var.get())
        token = self._normalize_token(self.token_var.get())

        if not base_url:
            raise RuntimeError("请在界面中填写服务地址(base_url)")
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            raise RuntimeError("服务地址格式错误：必须以 http:// 或 https:// 开头")
        if not token:
            raise RuntimeError("请在界面中填写令牌(token/cpa_password)")
        if any(ord(ch) > 255 for ch in token):
            raise RuntimeError("令牌中包含非英文字符，请检查是否混入中文标点（如 。）")

        return {
            "base_url": base_url,
            "token": token,
            "timeout": int(self.conf.get("timeout") or DEFAULT_TIMEOUT),
            "workers": int(self.workers_var.get() or DEFAULT_WORKERS),
            "quota_workers": int(self.quota_workers_var.get() or DEFAULT_QUOTA_WORKERS),
            "close_workers": int(self.conf.get("close_workers") or DEFAULT_CLOSE_WORKERS),
            "enable_workers": int(self.conf.get("enable_workers") or DEFAULT_ENABLE_WORKERS),
            "delete_workers": int(self.delete_workers_var.get() or DEFAULT_DELETE_WORKERS),
            "retries": int(self.conf.get("retries") or DEFAULT_RETRIES),
            "user_agent": self.conf.get("user_agent") or DEFAULT_UA,
            "chatgpt_account_id": self.conf.get("chatgpt_account_id") or None,
            "target_type": (self.conf.get("target_type") or DEFAULT_TARGET_TYPE).lower(),
            "provider": (self.conf.get("provider") or "").lower(),
            "weekly_quota_threshold": int(self.weekly_quota_threshold_var.get() or DEFAULT_QUOTA_THRESHOLD),
            "primary_quota_threshold": int(self.primary_quota_threshold_var.get() or DEFAULT_QUOTA_THRESHOLD),
            "output": self.conf.get("output") or DEFAULT_OUTPUT,
            "quota_output": self.conf.get("quota_output") or DEFAULT_QUOTA_OUTPUT,
        }

    def _load_accounts(self):
        self.status.set("正在从API加载账号列表...")
        self.action_progress.set("")

        def worker():
            try:
                rt = self._runtime()
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])

                accounts = []
                for f in files:
                    status_msg = f.get("status_message", "")
                    error_info = ""
                    usage_limit = ""

                    if f.get("status") == "error" and status_msg:
                        parsed = safe_json_text(status_msg)
                        err = parsed.get("error") or {}
                        error_info = err.get("message") or status_msg[:150]
                        if err.get("type") == "usage_limit_reached" and err.get("resets_at"):
                            try:
                                usage_limit = f"重置时间: {datetime.fromtimestamp(err['resets_at']).strftime('%Y-%m-%d %H:%M')}"
                            except Exception:
                                pass

                    accounts.append(
                        {
                            "name": f.get("name") or "",
                            "account": f.get("account") or f.get("email") or "",
                            "status": f.get("status") or "unknown",
                            "error_info": error_info,
                            "usage_limit": usage_limit,
                            "auth_index": f.get("auth_index"),
                            "provider": f.get("provider"),
                            "type": get_item_type(f),
                            "disabled": bool(f.get("disabled", False)),
                            "invalid_401": False,
                            "invalid_quota": False,
                            "used_percent": None,
                            "reset_at": None,
                            "check_error": None,
                            "_selected": True,
                            "raw": f,
                        }
                    )

                self.after(0, self._show_accounts, accounts)
            except Exception as e:
                self.after(0, messagebox.showerror, "加载失败", str(e))
                self.after(0, self.status.set, "加载失败")

        threading.Thread(target=worker, daemon=True).start()

    def _show_accounts(self, accounts):
        self.all_accounts = accounts
        self._apply_filter()

        total = len(accounts)
        error_count = len([a for a in accounts if a["status"] == "error"])
        active_count = len([a for a in accounts if a["status"] == "active"])

        self.status.set(f"加载完成: 总共={total} 错误={error_count} 活跃={active_count}")
        self.status_bar.set(
            "双击行可切换勾选；可执行检查401/额度，关闭选中或恢复已关闭（PATCH /auth-files/status），删除选中（DELETE）。"
        )

    def _display_status(self, account):
        if account.get("invalid_401"):
            return "401失效"
        if account.get("invalid_quota"):
            return "无额度"
        if account.get("disabled"):
            return "已关闭"
        s = account.get("status") or "unknown"
        if s == "active":
            return "活跃"
        if s == "error":
            return "错误"
        if s in ("", "unknown"):
            return "未知"
        return str(s)

    def _display_usage(self, account):
        used_percent = account.get("used_percent")
        quota_source = account.get("quota_source")

        if used_percent is not None:
            source_name = ""
            if quota_source == "weekly":
                source_name = "周"
            elif quota_source == "5hour":
                source_name = "5小时"
            elif quota_source == "remaining":
                source_name = "剩余"
            elif quota_source == "status_message":
                source_name = "状态"

            weekly_percent = account.get("individual_used_percent")
            short_percent = account.get("primary_used_percent")
            reset_time = ""
            if account.get("reset_at"):
                try:
                    reset_time = datetime.fromtimestamp(account["reset_at"]).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    reset_time = ""

            if self._compact_usage_mode:
                compact_parts = [f"使用{used_percent}%"]
                if weekly_percent is not None:
                    compact_parts.append(f"周{weekly_percent}%")
                if short_percent is not None:
                    compact_parts.append(f"5h{short_percent}%")
                if reset_time:
                    compact_parts.append(f"重置{reset_time[5:]}")
                if source_name:
                    compact_parts.append(source_name)
                return " | ".join(compact_parts)

            parts = [f"使用率: {used_percent}%"]
            if weekly_percent is not None:
                parts.append(f"周: {weekly_percent}%")
            if short_percent is not None:
                parts.append(f"5小时: {short_percent}%")
            if reset_time:
                parts.append(f"重置: {reset_time}")
            if source_name:
                parts.append(f"来源: {source_name}")
            return " | ".join(parts)

        usage_limit = account.get("usage_limit") or ""
        if self._compact_usage_mode and len(usage_limit) > 64:
            return usage_limit[:61] + "..."
        return usage_limit

    def _apply_filter(self, *_):
        for i in self.tree.get_children():
            self.tree.delete(i)

        text_filter = (self.filter_var.get() or "").lower()
        status_filter = self.filter_status.get()

        filtered = []
        for account in self.all_accounts:
            if status_filter == "错误" and account.get("status") != "error":
                continue
            if status_filter == "活跃" and account.get("status") != "active":
                continue
            if status_filter == "未知" and account.get("status") not in ["unknown", ""]:
                continue
            if status_filter == "已关闭" and not account.get("disabled"):
                continue
            if status_filter == "401失效" and not account.get("invalid_401"):
                continue
            if status_filter == "无额度" and not account.get("invalid_quota"):
                continue

            if text_filter:
                search_text = " ".join(
                    [
                        account.get("name") or "",
                        account.get("account") or "",
                        account.get("error_info") or "",
                        account.get("provider") or "",
                        str(account.get("type") or ""),
                    ]
                ).lower()
                if text_filter not in search_text:
                    continue

            filtered.append(account)

        self.filtered_accounts = filtered

        for idx, account in enumerate(filtered):
            prefix = "[X]" if account.get("_selected") else "[ ]"
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    f"{prefix} {account.get('name', '')}",
                    account.get("account", ""),
                    self._display_status(account),
                    (account.get("check_error") or account.get("error_info") or "")[:120],
                    self._display_usage(account),
                ),
            )

        self.status_bar.set(f"显示 {len(filtered)} / {len(self.all_accounts)} 个账号")

    def toggle_item(self, _event=None):
        item_id = self.tree.focus()
        if not item_id:
            return
        idx = int(item_id)
        account = self.filtered_accounts[idx]
        account["_selected"] = not account.get("_selected", False)

        prefix = "[X]" if account["_selected"] else "[ ]"
        self.tree.item(
            item_id,
            values=(
                f"{prefix} {account.get('name', '')}",
                account.get("account", ""),
                self._display_status(account),
                (account.get("check_error") or account.get("error_info") or "")[:120],
                self._display_usage(account),
            ),
        )

    def select_all(self):
        for idx, account in enumerate(self.filtered_accounts):
            account["_selected"] = True
            self.tree.item(
                str(idx),
                values=(
                    f"[X] {account.get('name', '')}",
                    account.get("account", ""),
                    self._display_status(account),
                    (account.get("check_error") or account.get("error_info") or "")[:120],
                    self._display_usage(account),
                ),
            )

    def select_none(self):
        for idx, account in enumerate(self.filtered_accounts):
            account["_selected"] = False
            self.tree.item(
                str(idx),
                values=(
                    f"[ ] {account.get('name', '')}",
                    account.get("account", ""),
                    self._display_status(account),
                    (account.get("check_error") or account.get("error_info") or "")[:120],
                    self._display_usage(account),
                ),
            )

    def _selected_names(self):
        return [a.get("name") for a in self.filtered_accounts if a.get("_selected") and a.get("name")]

    def _candidate_raw_items(self, rt):
        target_type = rt["target_type"]
        provider = rt["provider"]

        candidates = []
        for account in self.all_accounts:
            raw = account.get("raw") or {}
            item_type = str(get_item_type(raw) or "").lower()
            item_provider = str(raw.get("provider") or "").lower()

            if target_type and item_type != target_type:
                continue
            if provider and item_provider != provider:
                continue
            if not raw.get("auth_index"):
                continue
            candidates.append(raw)

        return candidates

    def _quota_candidate_raw_items(self, rt):
        """额度检测仅检查活跃与未知账号，不检查错误/已关闭账号。"""
        target_type = rt["target_type"]
        provider = rt["provider"]

        candidates = []
        for account in self.all_accounts:
            if account.get("disabled"):
                continue

            status = (account.get("status") or "unknown").lower()
            if status not in ("active", "unknown", ""):
                continue

            raw = account.get("raw") or {}
            item_type = str(get_item_type(raw) or "").lower()
            item_provider = str(raw.get("provider") or "").lower()

            if target_type and item_type != target_type:
                continue
            if provider and item_provider != provider:
                continue
            if not raw.get("auth_index"):
                continue
            candidates.append(raw)

        return candidates

    def _collect_invalid_names(self, probe_results, quota_results):
        invalid_401_names = []
        for r in probe_results:
            if r.get("invalid_401") and r.get("name"):
                invalid_401_names.append(r.get("name"))

        invalid_quota_names = []
        limit_only_quota_names = []
        for r in quota_results:
            if r.get("invalid_quota") and r.get("name"):
                invalid_quota_names.append(r.get("name"))
                if r.get("quota_source") == "status_message":
                    # 仅由 limit/状态消息判定的账号：只标记，不参与自动删除
                    limit_only_quota_names.append(r.get("name"))

        return (
            sorted(set(invalid_401_names)),
            sorted(set(invalid_quota_names)),
            sorted(set(limit_only_quota_names)),
        )

    def _auto_apply_actions(self, rt, invalid_401_names, invalid_quota_names, limit_only_quota_names):
        action_401 = self.auto_401_action_var.get()
        action_quota = self.auto_quota_action_var.get()

        deleted_names = []
        closed_names = []
        delete_errors = []
        close_errors = []

        to_delete = set()
        to_close = set()
        limit_only_set = set(limit_only_quota_names or [])

        if action_401 == "删除":
            to_delete.update(invalid_401_names)

        if action_quota == "删除":
            # limit/status_message 仅作为标记，不参与删除
            to_delete.update([n for n in invalid_quota_names if n not in limit_only_set])
        elif action_quota == "关闭":
            to_close.update(invalid_quota_names)

        to_close -= to_delete

        if to_close:
            close_results = asyncio.run(
                close_names(rt["base_url"], rt["token"], sorted(to_close), rt["close_workers"], rt["timeout"])
            )
            for r in close_results:
                if r.get("updated"):
                    closed_names.append(r.get("name"))
                else:
                    close_errors.append(f"{r.get('name')}: {r.get('error')}")

        if to_delete:
            delete_results = asyncio.run(
                delete_names(rt["base_url"], rt["token"], sorted(to_delete), rt["delete_workers"], rt["timeout"])
            )
            for r in delete_results:
                if r.get("deleted"):
                    deleted_names.append(r.get("name"))
                else:
                    delete_errors.append(f"{r.get('name')}: {r.get('error')}")

        return {
            "deleted": sorted([n for n in deleted_names if n]),
            "closed": sorted([n for n in closed_names if n]),
            "delete_errors": delete_errors,
            "close_errors": close_errors,
        }

    def _run_scheduled_check_once(self):
        if self._auto_running:
            return
        if not self.auto_enabled_var.get():
            return

        self._auto_running = True
        self.action_progress.set("定时任务执行中：正在检测401和额度...")

        def worker():
            summary = None
            try:
                rt = self._runtime()
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                candidates = []
                for f in files:
                    item_type = str(get_item_type(f) or "").lower()
                    item_provider = str(f.get("provider") or "").lower()
                    if rt["target_type"] and item_type != rt["target_type"]:
                        continue
                    if rt["provider"] and item_provider != rt["provider"]:
                        continue
                    if not f.get("auth_index"):
                        continue
                    candidates.append(f)

                if not candidates:
                    summary = {
                        "candidates": 0,
                        "invalid_401": 0,
                        "invalid_quota": 0,
                        "deleted": [],
                        "closed": [],
                        "delete_errors": [],
                        "close_errors": [],
                        "error": None,
                    }
                else:
                    probe_results = asyncio.run(
                        probe_accounts(
                            rt["base_url"],
                            rt["token"],
                            candidates,
                            rt["user_agent"],
                            rt["chatgpt_account_id"],
                            rt["workers"],
                            rt["timeout"],
                            rt["retries"],
                        )
                    )
                    quota_results = asyncio.run(
                        check_quota_accounts(
                            rt["base_url"],
                            rt["token"],
                            candidates,
                            rt["user_agent"],
                            rt["chatgpt_account_id"],
                            rt["quota_workers"],
                            rt["timeout"],
                            rt["retries"],
                            rt["weekly_quota_threshold"],
                            rt["primary_quota_threshold"],
                        )
                    )

                    invalid_401_names, invalid_quota_names, limit_only_quota_names = self._collect_invalid_names(
                        probe_results, quota_results
                    )
                    action_result = self._auto_apply_actions(
                        rt,
                        invalid_401_names,
                        invalid_quota_names,
                        limit_only_quota_names,
                    )

                    summary = {
                        "candidates": len(candidates),
                        "invalid_401": len(invalid_401_names),
                        "invalid_quota": len(invalid_quota_names),
                        "deleted": action_result["deleted"],
                        "closed": action_result["closed"],
                        "delete_errors": action_result["delete_errors"],
                        "close_errors": action_result["close_errors"],
                        "error": None,
                    }
            except Exception as e:
                summary = {
                    "candidates": 0,
                    "invalid_401": 0,
                    "invalid_quota": 0,
                    "deleted": [],
                    "closed": [],
                    "delete_errors": [],
                    "close_errors": [],
                    "error": str(e),
                }

            self.after(0, self._scheduled_check_done, summary)

        threading.Thread(target=worker, daemon=True).start()

    def _scheduled_check_done(self, summary):
        self._auto_running = False

        if summary.get("error"):
            self.auto_status_var.set(f"定时任务失败：{summary.get('error')}")
            self.action_progress.set("定时任务失败")
        else:
            self.auto_status_var.set(
                "定时任务已执行："
                f"候选={summary.get('candidates')} 401={summary.get('invalid_401')} "
                f"无额度={summary.get('invalid_quota')} 删除={len(summary.get('deleted', []))} "
                f"关闭={len(summary.get('closed', []))}"
            )
            self.action_progress.set("定时任务执行完成")

            error_lines = []
            if summary.get("delete_errors"):
                error_lines.append("删除失败:\n" + "\n".join(summary.get("delete_errors")[:10]))
            if summary.get("close_errors"):
                error_lines.append("关闭失败:\n" + "\n".join(summary.get("close_errors")[:10]))
            if error_lines:
                messagebox.showwarning("定时任务部分失败", "\n\n".join(error_lines))

        self._load_accounts()
        self._schedule_next_auto_check()

    def _schedule_next_auto_check(self):
        if self._auto_job is not None:
            self.after_cancel(self._auto_job)
            self._auto_job = None

        if not self.auto_enabled_var.get():
            return

        try:
            interval_minutes = int(self.auto_interval_var.get() or 0)
        except Exception:
            self.auto_status_var.set("定时任务参数错误：间隔分钟必须为整数")
            return

        if interval_minutes <= 0:
            self.auto_status_var.set("定时任务参数错误：间隔分钟必须大于0")
            return

        self._auto_job = self.after(interval_minutes * 60 * 1000, self._run_scheduled_check_once)

    def start_auto_check(self):
        self.auto_enabled_var.set(True)
        self._save_config()
        self._schedule_next_auto_check()
        self.auto_status_var.set(
            f"定时任务已启动：每 {self.auto_interval_var.get()} 分钟执行一次，"
            f"401->{self.auto_401_action_var.get()}，无额度->{self.auto_quota_action_var.get()}"
        )
        self._run_scheduled_check_once()

    def stop_auto_check(self):
        self.auto_enabled_var.set(False)
        if self._auto_job is not None:
            self.after_cancel(self._auto_job)
            self._auto_job = None
        self._save_config()
        self.auto_status_var.set("定时任务：已停止")

    def check_401(self):
        if not self._ensure_accounts_loaded("检查401"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        candidates = self._candidate_raw_items(rt)
        if not candidates:
            messagebox.showinfo("检查401", "没有符合 target_type/provider 且带 auth_index 的账号可检测。")
            return

        self.action_progress.set(f"正在检查401... 候选={len(candidates)}")

        def worker():
            try:
                results = asyncio.run(
                    probe_accounts(
                        rt["base_url"],
                        rt["token"],
                        candidates,
                        rt["user_agent"],
                        rt["chatgpt_account_id"],
                        rt["workers"],
                        rt["timeout"],
                        rt["retries"],
                    )
                )
                invalid_401 = [r for r in results if r.get("invalid_401")]
                with open(rt["output"], "w", encoding="utf-8") as f:
                    json.dump(invalid_401, f, ensure_ascii=False, indent=2)
                self.after(0, self._check_401_done, results, rt["output"])
            except Exception as e:
                self.after(0, messagebox.showerror, "401检测失败", str(e))
                self.after(0, self.action_progress.set, "401检测失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_401_done(self, results, output_path):
        by_name = {r.get("name"): r for r in results if r.get("name")}

        invalid_count = 0
        error_count = 0
        for account in self.all_accounts:
            r = by_name.get(account.get("name"))
            if not r:
                continue
            account["invalid_401"] = bool(r.get("invalid_401"))
            account["check_error"] = r.get("error")
            if account["invalid_401"]:
                invalid_count += 1
            if r.get("error"):
                error_count += 1

        self._apply_filter()
        self.action_progress.set(f"401检测完成：失效={invalid_count} 异常={error_count}")
        messagebox.showinfo("401检测完成", f"401失效: {invalid_count}\n检测异常: {error_count}\n导出文件: {output_path}")

    def check_quota(self):
        if not self._ensure_accounts_loaded("额度检测"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        candidates = self._quota_candidate_raw_items(rt)
        if not candidates:
            messagebox.showinfo("额度检测", "没有符合条件（活跃/未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            return

        self.action_progress.set(f"正在检查额度... 候选={len(candidates)}")

        def worker():
            try:
                results = asyncio.run(
                    check_quota_accounts(
                        rt["base_url"],
                        rt["token"],
                        candidates,
                        rt["user_agent"],
                        rt["chatgpt_account_id"],
                        rt["quota_workers"],
                        rt["timeout"],
                        rt["retries"],
                        rt["weekly_quota_threshold"],
                        rt["primary_quota_threshold"],
                    )
                )
                invalid_quota = [r for r in results if r.get("invalid_quota")]
                with open(rt["quota_output"], "w", encoding="utf-8") as f:
                    json.dump(invalid_quota, f, ensure_ascii=False, indent=2)
                self.after(0, self._check_quota_done, results, rt["quota_output"])
            except Exception as e:
                self.after(0, messagebox.showerror, "额度检测失败", str(e))
                self.after(0, self.action_progress.set, "额度检测失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_quota_done(self, results, output_path):
        by_name = {r.get("name"): r for r in results if r.get("name")}

        quota_count = 0
        error_count = 0
        for account in self.all_accounts:
            r = by_name.get(account.get("name"))
            if not r:
                continue
            account["invalid_quota"] = bool(r.get("invalid_quota"))
            account["used_percent"] = r.get("used_percent")
            account["primary_used_percent"] = r.get("primary_used_percent")
            account["primary_reset_at"] = r.get("primary_reset_at")
            account["individual_used_percent"] = r.get("individual_used_percent")
            account["individual_reset_at"] = r.get("individual_reset_at")
            account["quota_source"] = r.get("quota_source")
            account["reset_at"] = r.get("reset_at")
            account["check_error"] = r.get("error")
            if account["invalid_quota"]:
                quota_count += 1
            if r.get("error"):
                error_count += 1

        self._apply_filter()
        self.action_progress.set(f"额度检测完成：无额度={quota_count} 异常={error_count}")
        messagebox.showinfo("额度检测完成", f"无额度: {quota_count}\n检测异常: {error_count}\n导出文件: {output_path}")

    def check_both(self):
        if not self._ensure_accounts_loaded("联合检测"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        candidates = self._candidate_raw_items(rt)
        if not candidates:
            messagebox.showinfo("联合检测", "没有符合 target_type/provider 且带 auth_index 的账号可检测。")
            return

        self.action_progress.set(f"正在联合检测... 候选={len(candidates)}")

        def worker():
            try:
                probe_results = asyncio.run(
                    probe_accounts(
                        rt["base_url"],
                        rt["token"],
                        candidates,
                        rt["user_agent"],
                        rt["chatgpt_account_id"],
                        rt["workers"],
                        rt["timeout"],
                        rt["retries"],
                    )
                )
                quota_results = asyncio.run(
                    check_quota_accounts(
                        rt["base_url"],
                        rt["token"],
                        candidates,
                        rt["user_agent"],
                        rt["chatgpt_account_id"],
                        rt["quota_workers"],
                        rt["timeout"],
                        rt["retries"],
                        rt["weekly_quota_threshold"],
                        rt["primary_quota_threshold"],
                    )
                )

                invalid_401 = [r for r in probe_results if r.get("invalid_401")]
                invalid_quota = [r for r in quota_results if r.get("invalid_quota")]

                with open(rt["output"], "w", encoding="utf-8") as f:
                    json.dump(invalid_401, f, ensure_ascii=False, indent=2)
                with open(rt["quota_output"], "w", encoding="utf-8") as f:
                    json.dump(invalid_quota, f, ensure_ascii=False, indent=2)

                self.after(0, self._check_both_done, probe_results, quota_results, rt["output"], rt["quota_output"])
            except Exception as e:
                self.after(0, messagebox.showerror, "联合检测失败", str(e))
                self.after(0, self.action_progress.set, "联合检测失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_both_done(self, probe_results, quota_results, output_path, quota_output_path):
        probe_by_name = {r.get("name"): r for r in probe_results if r.get("name")}
        quota_by_name = {r.get("name"): r for r in quota_results if r.get("name")}

        count_401 = 0
        count_quota = 0
        count_err = 0

        for account in self.all_accounts:
            name = account.get("name")
            p = probe_by_name.get(name)
            q = quota_by_name.get(name)

            if p:
                account["invalid_401"] = bool(p.get("invalid_401"))
                if account["invalid_401"]:
                    count_401 += 1
                if p.get("error"):
                    count_err += 1

            if q:
                account["invalid_quota"] = bool(q.get("invalid_quota"))
                account["used_percent"] = q.get("used_percent")
                account["primary_used_percent"] = q.get("primary_used_percent")
                account["primary_reset_at"] = q.get("primary_reset_at")
                account["individual_used_percent"] = q.get("individual_used_percent")
                account["individual_reset_at"] = q.get("individual_reset_at")
                account["quota_source"] = q.get("quota_source")
                account["reset_at"] = q.get("reset_at")
                if account["invalid_quota"]:
                    count_quota += 1
                if q.get("error"):
                    count_err += 1

            account["check_error"] = (q.get("error") if q else None) or (p.get("error") if p else None)

        self._apply_filter()
        self.action_progress.set(f"联合检测完成：401={count_401} 无额度={count_quota}")
        messagebox.showinfo(
            "联合检测完成",
            f"401失效: {count_401}\n无额度: {count_quota}\n检测异常: {count_err}\n401导出: {output_path}\n额度导出: {quota_output_path}",
        )

    def close_selected(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("关闭账号", "你没有选择任何账号。")
            return

        if messagebox.askyesno(
            "确认关闭",
            f"确定要关闭选中的 {len(names)} 个账号吗？\n\n将调用 PATCH /v0/management/auth-files/status。",
        ):
            self._start_close(names)

    def _start_close(self, names):
        self.action_progress.set(f"正在关闭 {len(names)} 个账号...")

        def worker():
            try:
                rt = self._runtime()
                result = asyncio.run(
                    close_names(rt["base_url"], rt["token"], names, rt["close_workers"], rt["timeout"])
                )
                self.after(0, self._close_done, result)
            except Exception as e:
                self.after(0, messagebox.showerror, "关闭失败", str(e))
                self.after(0, self.action_progress.set, "关闭失败")

        threading.Thread(target=worker, daemon=True).start()

    def _close_done(self, results):
        ok = [r for r in results if r.get("updated")]
        bad = [r for r in results if not r.get("updated")]

        self.action_progress.set(f"关闭完成：成功={len(ok)} 失败={len(bad)}")

        if bad:
            msg = "部分关闭失败：\n" + "\n".join([f"- {r.get('name')}: {r.get('error')}" for r in bad[:15]])
            if len(bad) > 15:
                msg += f"\n... 还有 {len(bad)-15} 条"
            messagebox.showwarning("关闭结果", msg)
        else:
            messagebox.showinfo("关闭结果", f"关闭成功：{len(ok)} 个")

        self._load_accounts()

    def recover_closed_accounts(self):
        if not self._ensure_accounts_loaded("恢复已关闭"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        candidates = []
        for account in self.all_accounts:
            if not account.get("disabled"):
                continue
            raw = account.get("raw") or {}
            item_type = str(get_item_type(raw) or "").lower()
            item_provider = str(raw.get("provider") or "").lower()

            if rt["target_type"] and item_type != rt["target_type"]:
                continue
            if rt["provider"] and item_provider != rt["provider"]:
                continue
            if not raw.get("auth_index"):
                continue
            candidates.append(raw)

        if not candidates:
            messagebox.showinfo("恢复已关闭", "没有符合条件的已关闭账号可检测。")
            return

        if not messagebox.askyesno(
            "确认恢复",
            (
                f"将检测 {len(candidates)} 个已关闭账号的额度。\n"
                "仅当不满足“无额度”条件时，才会自动开启这些账号。\n\n"
                "继续吗？"
            ),
        ):
            return

        self.action_progress.set(f"正在检测已关闭账号额度... 候选={len(candidates)}")

        def worker():
            try:
                quota_results = asyncio.run(
                    check_quota_accounts(
                        rt["base_url"],
                        rt["token"],
                        candidates,
                        rt["user_agent"],
                        rt["chatgpt_account_id"],
                        rt["quota_workers"],
                        rt["timeout"],
                        rt["retries"],
                        rt["weekly_quota_threshold"],
                        rt["primary_quota_threshold"],
                    )
                )

                recoverable = [
                    r
                    for r in quota_results
                    if r.get("status_code") == 200
                    and not r.get("invalid_quota")
                ]
                names_to_enable = [r.get("name") for r in recoverable if r.get("name")]

                enable_results = []
                if names_to_enable:
                    enable_results = asyncio.run(
                        enable_names(
                            rt["base_url"],
                            rt["token"],
                            names_to_enable,
                            rt["enable_workers"],
                            rt["timeout"],
                        )
                    )

                self.after(0, self._recover_closed_done, quota_results, enable_results)
            except Exception as e:
                self.after(0, messagebox.showerror, "恢复失败", str(e))
                self.after(0, self.action_progress.set, "恢复失败")

        threading.Thread(target=worker, daemon=True).start()

    def _recover_closed_done(self, quota_results, enable_results):
        quota_by_name = {r.get("name"): r for r in quota_results if r.get("name")}
        enable_by_name = {r.get("name"): r for r in enable_results if r.get("name")}

        checked = len(quota_results)
        recoverable = 0
        enabled_ok = 0
        enabled_fail = 0
        quota_errors = 0

        for account in self.all_accounts:
            name = account.get("name")
            q = quota_by_name.get(name)
            if q:
                account["invalid_quota"] = bool(q.get("invalid_quota"))
                account["used_percent"] = q.get("used_percent")
                account["primary_used_percent"] = q.get("primary_used_percent")
                account["primary_reset_at"] = q.get("primary_reset_at")
                account["individual_used_percent"] = q.get("individual_used_percent")
                account["individual_reset_at"] = q.get("individual_reset_at")
                account["quota_source"] = q.get("quota_source")
                account["reset_at"] = q.get("reset_at")
                account["check_error"] = q.get("error")
                if q.get("error"):
                    quota_errors += 1
                if q.get("status_code") == 200 and not q.get("invalid_quota"):
                    recoverable += 1

            e = enable_by_name.get(name)
            if e:
                if e.get("updated"):
                    account["disabled"] = False
                    if account.get("raw"):
                        account["raw"]["disabled"] = False
                    enabled_ok += 1
                else:
                    enabled_fail += 1
                    account["check_error"] = e.get("error") or account.get("check_error")

        self._apply_filter()
        self.action_progress.set(f"恢复流程完成：开启成功={enabled_ok} 失败={enabled_fail}")

        messagebox.showinfo(
            "恢复已关闭结果",
            (
                f"已关闭检测: {checked}\n"
                f"额度恢复(可开启): {recoverable}\n"
                f"开启成功: {enabled_ok}\n"
                f"开启失败: {enabled_fail}\n"
                f"检测异常: {quota_errors}"
            ),
        )

        self._load_accounts()

    def delete_selected(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("删除账号", "你没有选择任何账号。")
            return

        if messagebox.askyesno("确认删除", f"确定要永久删除选中的 {len(names)} 个账号吗？\n\n此操作不可恢复。"):
            self._start_delete(names)

    def _start_delete(self, names):
        self.action_progress.set(f"正在删除 {len(names)} 个账号...")

        def worker():
            try:
                rt = self._runtime()
                result = asyncio.run(
                    delete_names(rt["base_url"], rt["token"], names, rt["delete_workers"], rt["timeout"])
                )
                self.after(0, self._delete_done, result)
            except Exception as e:
                self.after(0, messagebox.showerror, "删除失败", str(e))
                self.after(0, self.action_progress.set, "删除失败")

        threading.Thread(target=worker, daemon=True).start()

    def _delete_done(self, results):
        ok = [r for r in results if r.get("deleted")]
        bad = [r for r in results if not r.get("deleted")]

        self.action_progress.set(f"删除完成：成功={len(ok)} 失败={len(bad)}")

        if bad:
            msg = "部分删除失败：\n" + "\n".join([f"- {r.get('name')}: {r.get('error')}" for r in bad[:15]])
            if len(bad) > 15:
                msg += f"\n... 还有 {len(bad)-15} 条"
            messagebox.showwarning("删除结果", msg)
        else:
            messagebox.showinfo("删除结果", f"删除成功：{len(ok)} 个")

        self._load_accounts()


def main():
    conf = load_config(CONFIG_PATH)
    app = EnhancedUI(conf, CONFIG_PATH)
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[启动失败] {e}", file=sys.stderr)
        input("按回车退出...")
        raise
