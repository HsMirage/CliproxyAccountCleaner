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
import argparse
import json
import asyncio
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception:
    tk = None
    ttk = None
    messagebox = None
import requests
import aiohttp

HERE = os.path.abspath(os.path.dirname(__file__))
_TK_BASE = tk.Tk if tk is not None else object


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
DEFAULT_ACTIVE_QUOTA_OUTPUT = "active_quota_history.jsonl"
DEFAULT_STANDBY_OUTPUT = "standby_accounts.json"
STREAM_ERROR_ACTIVE_MESSAGE = "stream error: stream disconnected before completion: stream closed before response.completed"
LIMIT_KEYWORDS = (
    "usage_limit_reached",
    "insufficient_quota",
    "quota_exceeded",
    "limit_reached",
    "rate limit",
)


def _contains_limit_error(value):
    """判断文本/结构化对象中是否包含额度耗尽信号。"""

    def _walk_texts(obj):
        texts = []
        if isinstance(obj, dict):
            for v in obj.values():
                texts.extend(_walk_texts(v))
        elif isinstance(obj, list):
            for v in obj:
                texts.extend(_walk_texts(v))
        elif obj is not None:
            texts.append(str(obj))
        return texts

    texts = []
    if isinstance(value, str):
        texts.append(value)
        parsed = safe_json_text(value)
        if isinstance(parsed, dict):
            texts.extend(_walk_texts(parsed))
    else:
        texts.extend(_walk_texts(value))

    merged = " ".join(t.lower() for t in texts if t)
    return any(k in merged for k in LIMIT_KEYWORDS)


def load_config(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"config.json 格式错误: {e}")
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


def management_action_succeeded(status_code, payload, allow_no_content=False):
    """Treat management mutations as successful only for explicit success responses."""
    if allow_no_content and status_code == 204:
        return True
    if status_code != 200:
        return False
    return as_json_obj(payload).get("status") == "ok"


def write_json_file(path, data):
    p = Path(str(path))
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_item_type(item):
    return item.get("type") or item.get("typo")


def extract_chatgpt_account_id(item):
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return val
    return None


def _is_stream_error_active(raw_status, status_message):
    if str(raw_status or "").strip().lower() != "error":
        return False

    parsed = safe_json_text(status_message or "")
    err = parsed.get("error") if isinstance(parsed, dict) else {}
    message = ""
    if isinstance(err, dict):
        message = str(err.get("message") or "")
    if not message:
        message = str(status_message or "")

    return STREAM_ERROR_ACTIVE_MESSAGE in message.lower()


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


def build_usage_payload(auth_index, user_agent, chatgpt_account_id=None):
    """统一构造 usage 探测请求，避免 401/额度检测各自维护一份相同协议。"""

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


def build_probe_payload(auth_index, user_agent, chatgpt_account_id=None):
    return build_usage_payload(auth_index, user_agent, chatgpt_account_id)


def build_quota_payload(auth_index, user_agent, chatgpt_account_id=None):
    return build_usage_payload(auth_index, user_agent, chatgpt_account_id)


async def _run_bounded(items, limit, make_coro):
    """Run async jobs with bounded in-flight tasks.
    Avoid creating one task per item when item count is huge.
    """
    limit = max(1, int(limit or 1))
    it = iter(items or [])
    running = set()
    out = []

    for _ in range(limit):
        try:
            item = next(it)
        except StopIteration:
            break
        running.add(asyncio.create_task(make_coro(item)))

    while running:
        done, running = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            out.append(await task)
            try:
                item = next(it)
            except StopIteration:
                continue
            running.add(asyncio.create_task(make_coro(item)))

    return out


async def probe_accounts(
    base_url,
    token,
    candidates,
    user_agent,
    fallback_account_id,
    workers,
    timeout,
    retries,
    refresh_candidates=True,
    refreshed_by_auth_index=None,
):
    # 对齐额度检测：先尽量刷新 auth-files，避免使用旧快照导致误判
    if refreshed_by_auth_index is None:
        refreshed_by_auth_index = {}

    if refresh_candidates:
        try:
            refreshed_files = refresh_quota_source(base_url, token, timeout)
            refreshed_by_auth_index = {}
            for f in refreshed_files:
                ai = f.get("auth_index")
                if ai:
                    refreshed_by_auth_index[ai] = f
        except Exception:
            # 刷新失败时回退到原候选，避免整次检测中断
            refreshed_by_auth_index = {}

    refreshed_candidates = []
    for item in candidates:
        ai = item.get("auth_index")
        refreshed_candidates.append(refreshed_by_auth_index.get(ai) or item)

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

                        # 401 需要二次确认：若允许重试，先重试一次再判失效，避免瞬时误判
                        if sc == 401 and attempt < retries:
                            continue

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

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        out = await _run_bounded(
            refreshed_candidates,
            max(1, workers),
            lambda item: probe_one(session, sem, item),
        )
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
    refresh_candidates=True,
    refreshed_by_auth_index=None,
):
    # 对齐管理页刷新顺序：config.yaml -> auth-files -> api-call
    if refreshed_by_auth_index is None:
        refreshed_by_auth_index = {}

    if refresh_candidates:
        try:
            refreshed_files = refresh_quota_source(base_url, token, timeout)

            # 使用刷新后的 auth-files 重建候选，避免用到旧快照
            refreshed_by_auth_index = {}
            for f in refreshed_files:
                ai = f.get("auth_index")
                if ai:
                    refreshed_by_auth_index[ai] = f
        except Exception:
            # 刷新失败时回退到原候选，避免整次检测中断
            if not isinstance(refreshed_by_auth_index, dict):
                refreshed_by_auth_index = {}

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
        status_text = str(status_message or "").lower()

        limit_keywords = LIMIT_KEYWORDS

        sm_error = sm_data.get("error") if isinstance(sm_data, dict) else None
        if isinstance(sm_error, dict):
            sm_type = str(sm_error.get("type") or "").lower()
            sm_code = str(sm_error.get("code") or "").lower()
            sm_msg = str(sm_error.get("message") or "").lower()
            if any(k in sm_type or k in sm_code or k in sm_msg for k in limit_keywords):
                quota_marked_by_status = True
            if sm_error.get("resets_at") is not None:
                result["reset_at"] = sm_error.get("resets_at")
        elif isinstance(sm_error, str):
            sm_error_text = sm_error.lower()
            if any(k in sm_error_text for k in limit_keywords):
                quota_marked_by_status = True

        if not quota_marked_by_status and isinstance(sm_data, dict):
            top_type = str(sm_data.get("type") or "").lower()
            top_code = str(sm_data.get("code") or "").lower()
            top_msg = str(sm_data.get("message") or "").lower()
            if any(k in top_type or k in top_code or k in top_msg for k in limit_keywords):
                quota_marked_by_status = True

        if not quota_marked_by_status and any(k in status_text for k in limit_keywords):
            quota_marked_by_status = True

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

                            def select_quota_windows(windows):
                                weekly_window = None
                                short_window = None

                                def is_seconds(value):
                                    return isinstance(value, (int, float))

                                for window in windows:
                                    lower_name = str(window.get("name") or "").lower()
                                    seconds = window.get("limit_window_seconds")

                                    if short_window is None:
                                        if "primary" in lower_name or "short" in lower_name:
                                            short_window = window
                                        elif is_seconds(seconds) and seconds <= 6 * 3600:
                                            short_window = window

                                    if weekly_window is None:
                                        if "individual" in lower_name or "weekly" in lower_name:
                                            weekly_window = window
                                        elif "secondary" in lower_name and (not is_seconds(seconds) or seconds > 6 * 3600):
                                            weekly_window = window

                                with_seconds = [
                                    w for w in windows if is_seconds(w.get("limit_window_seconds"))
                                ]

                                if short_window is None and with_seconds:
                                    short_window = min(with_seconds, key=lambda x: x["limit_window_seconds"])

                                if weekly_window is None and with_seconds:
                                    sorted_ws = sorted(with_seconds, key=lambda x: x["limit_window_seconds"], reverse=True)
                                    for w in sorted_ws:
                                        if short_window is None or w.get("name") != short_window.get("name"):
                                            weekly_window = w
                                            break

                                if weekly_window is None and windows:
                                    for w in windows:
                                        if short_window is None or w.get("name") != short_window.get("name"):
                                            weekly_window = w
                                            break

                                if short_window is None and windows:
                                    for w in windows:
                                        if weekly_window is None or w.get("name") != weekly_window.get("name"):
                                            short_window = w
                                            break

                                if (
                                    short_window is None
                                    and weekly_window is not None
                                    and is_seconds(weekly_window.get("limit_window_seconds"))
                                    and weekly_window.get("limit_window_seconds") <= 6 * 3600
                                ):
                                    short_window = weekly_window
                                    weekly_window = None

                                return weekly_window, short_window

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

                            weekly_window, short_window = select_quota_windows(windows)

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

                            # 无 used_percent 时，使用 remaining/limit_reached/allowed 兜底识别额度耗尽
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
                        else:
                            # 接口非200但状态消息或返回内容明确提示额度耗尽时，仍按无额度处理
                            if quota_marked_by_status or _contains_limit_error(data) or _contains_limit_error(text):
                                result["used_percent"] = 100
                                result["invalid_quota"] = True
                                result["quota_source"] = "status_message"

                        if sc is None:
                            if _contains_limit_error(data) or _contains_limit_error(text):
                                result["used_percent"] = 100
                                result["invalid_quota"] = True
                                result["quota_source"] = "status_message"
                                result["error"] = None
                            else:
                                result["error"] = "missing status_code in api-call response"
                        else:
                            result["error"] = None
                        return result
            except Exception as e:
                if _contains_limit_error(str(e)):
                    result["used_percent"] = 100
                    result["invalid_quota"] = True
                    result["quota_source"] = "status_message"
                    result["error"] = None
                else:
                    result["error"] = str(e)
                if attempt >= retries:
                    return result

        return result

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, workers))

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        out = await _run_bounded(
            refreshed_candidates,
            max(1, workers),
            lambda item: quota_one(session, sem, item),
        )
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
                    ok = management_action_succeeded(resp.status, data)
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

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        out = await _run_bounded(
            names,
            max(1, workers),
            lambda n: set_one(session, sem, n),
        )
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
                    ok = management_action_succeeded(resp.status, data, allow_no_content=True)
                    return {"name": name, "deleted": ok, "status": resp.status, "error": None if ok else text[:200]}
        except Exception as e:
            return {"name": name, "deleted": False, "status": None, "error": str(e)}

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    sem = asyncio.Semaphore(max(1, delete_workers))

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        out = await _run_bounded(
            names,
            max(1, delete_workers),
            lambda n: delete_one(session, sem, n),
        )
    return out


class EnhancedUI(_TK_BASE):
    def __init__(self, conf, config_path):
        if tk is None:
            raise RuntimeError("当前环境缺少 tkinter，无法启动桌面模式。")
        super().__init__()
        self.title("CliproxyAccountCleaner v1.4.0")
        self.geometry("1220x760")
        self.minsize(1080, 640)

        self.conf = conf
        self.config_path = config_path
        self.all_accounts = []
        self.filtered_accounts = []
        self._compact_usage_mode = False
        self._layout_update_job = None
        self._on_help_page = False
        self._config_save_job = None

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
        self.auto_enabled_var = tk.BooleanVar(value=False)
        self.auto_interval_var = tk.StringVar(value=str(max(1, auto_interval)))

        auto_401_action = str(self.conf.get("auto_action_401") or "删除")
        if auto_401_action not in ("删除", "仅标记"):
            auto_401_action = "删除"
        self.auto_401_action_var = tk.StringVar(value=auto_401_action)

        auto_quota_action = str(self.conf.get("auto_action_quota") or "关闭")
        if auto_quota_action not in ("关闭", "删除", "仅标记"):
            auto_quota_action = "关闭"
        self.auto_quota_action_var = tk.StringVar(value=auto_quota_action)

        keep_active_count = int(self.conf.get("auto_keep_active_count") or 0)
        self.auto_keep_active_var = tk.StringVar(value=str(max(0, keep_active_count)))
        self.auto_allow_closed_scan_var = tk.BooleanVar(value=bool(self.conf.get("auto_allow_scan_closed", False)))

        self.standby_names = self._load_standby_names_from_file()

        self._auto_job = None
        self._auto_running = False

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        bg = "#f3f6fb"
        card_bg = "#ffffff"
        text_main = "#0f172a"
        text_sub = "#475569"

        self.configure(bg=bg)

        style.configure("TFrame", background=bg, relief="flat", borderwidth=0)
        style.configure("Card.TFrame", background=card_bg, relief="flat", borderwidth=0)
        style.configure("CardInner.TFrame", background=card_bg, relief="flat", borderwidth=0)

        style.configure("TLabelframe", background=bg, relief="flat", borderwidth=0)
        style.configure("TLabelframe.Label", background=bg, foreground=text_main)
        style.configure("Card.TLabelframe", background=bg, relief="flat", borderwidth=0)
        style.configure("Card.TLabelframe.Label", background=bg, foreground=text_main)

        style.configure("TLabel", background=bg, foreground=text_main)
        style.configure("Header.TLabel", background=card_bg, foreground=text_main, font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Subtle.TLabel", background=card_bg, foreground=text_sub)

        style.configure("TEntry", fieldbackground="#ffffff", borderwidth=1)
        style.configure(
            "TCombobox",
            fieldbackground="#ffffff",
            borderwidth=1,
            relief="flat",
            foreground="#1f2937",
            arrowsize=14,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", "#ffffff")],
            selectbackground=[("readonly", "#dbeafe")],
            selectforeground=[("readonly", "#1f2937")],
        )

        style.configure("TCheckbutton", background=card_bg, foreground="#334155")
        style.map("TCheckbutton", background=[("active", card_bg)], foreground=[("active", "#1e293b")])

        style.configure("Treeview", rowheight=26, fieldbackground=card_bg, background=card_bg, borderwidth=0)
        style.configure("Treeview.Heading", padding=(8, 7), background="#e2e8f0", foreground=text_main, borderwidth=0)

        button_bg = "#90aecd"
        button_bg_active = "#7f9fbe"
        button_bg_pressed = "#6f90b0"
        button_fg = "#f4f8fc"

        for btn_style in ("Primary.TButton", "Neutral.TButton", "Warn.TButton", "Danger.TButton"):
            style.configure(btn_style, padding=(12, 7), background=button_bg, foreground=button_fg, borderwidth=0, relief="flat")
            style.map(
                btn_style,
                background=[("active", button_bg_active), ("pressed", button_bg_pressed)],
                relief=[("pressed", "flat"), ("active", "flat")],
            )

    def _build(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0, minsize=28)
        self.grid_columnconfigure(0, weight=1)

        main = ttk.Frame(self, padding=(6, 4, 6, 4))
        main.grid(row=0, column=0, sticky="nsew")

        header = ttk.Frame(main, style="Card.TFrame", padding=(6, 2))
        header.pack(fill="x", pady=(0, 1))
        header.columnconfigure(0, weight=1)

        self.status = tk.StringVar(value="正在加载账号列表...")
        ttk.Label(header, textvariable=self.status, style="Subtle.TLabel").grid(row=0, column=0, sticky="w")

        top_actions = ttk.Frame(header, style="Card.TFrame")
        top_actions.grid(row=0, column=1, sticky="e")
        ttk.Button(top_actions, text="刷新账号列表", command=self._load_accounts, style="Primary.TButton").pack(side="left")
        self.help_btn = ttk.Button(top_actions, text="使用说明", command=self._toggle_help_page, style="Neutral.TButton")
        self.help_btn.pack(side="left", padx=(8, 0))
        ttk.Button(top_actions, text="关闭窗口", command=self.destroy, style="Neutral.TButton").pack(side="left", padx=(8, 0))

        self.main_content = ttk.Frame(main)
        self.main_content.pack(fill="both", expand=True)

        config_wrap = ttk.Frame(self.main_content)
        config_wrap.pack(fill="x", pady=(0, 2))

        cfg = ttk.LabelFrame(config_wrap, text="连接与检测参数", style="Card.TLabelframe", padding=(8, 5))
        cfg.pack(fill="x", pady=(0, 6))
        cfg_top_row = ttk.Frame(cfg)
        cfg_top_row.pack(fill="x", pady=(0, 3))
        cfg_top_row.columnconfigure(1, weight=1)
        cfg_top_row.columnconfigure(3, weight=1)

        ttk.Label(cfg_top_row, text="管理端地址 (base_url)").grid(row=0, column=0, sticky="w")
        ttk.Entry(cfg_top_row, textvariable=self.base_url_var).grid(row=0, column=1, sticky="ew", padx=(8, 18))

        ttk.Label(cfg_top_row, text="访问令牌 (token / cpa_password)").grid(row=0, column=2, sticky="w")
        ttk.Entry(cfg_top_row, textvariable=self.token_var).grid(row=0, column=3, sticky="ew", padx=(8, 0))

        params_row = ttk.Frame(cfg)
        params_row.pack(fill="x")
        ttk.Label(params_row, text="401 检测并发").pack(side="left")
        ttk.Entry(params_row, textvariable=self.workers_var, width=8).pack(side="left", padx=(6, 14))
        ttk.Label(params_row, text="额度检测并发").pack(side="left")
        ttk.Entry(params_row, textvariable=self.quota_workers_var, width=8).pack(side="left", padx=(6, 14))
        ttk.Label(params_row, text="删除并发").pack(side="left")
        ttk.Entry(params_row, textvariable=self.delete_workers_var, width=8).pack(side="left", padx=(6, 22))

        ttk.Label(params_row, text="周额度阈值 (%)").pack(side="left")
        ttk.Entry(params_row, textvariable=self.weekly_quota_threshold_var, width=8).pack(side="left", padx=(6, 14))
        ttk.Label(params_row, text="5 小时额度阈值 (%)").pack(side="left")
        ttk.Entry(params_row, textvariable=self.primary_quota_threshold_var, width=8).pack(side="left", padx=(6, 14))
        ttk.Label(params_row, text="活跃账号目标数").pack(side="left")
        ttk.Entry(params_row, textvariable=self.auto_keep_active_var, width=7).pack(side="left", padx=(6, 0))

        auto = ttk.LabelFrame(config_wrap, text="自动巡检设置", style="Card.TLabelframe", padding=(8, 5))
        auto.pack(fill="x", pady=(0, 2))

        auto_row1 = ttk.Frame(auto)
        auto_row1.pack(fill="x", pady=(0, 3))
        ttk.Label(auto_row1, text="巡检间隔 (分钟)").pack(side="left")
        ttk.Entry(auto_row1, textvariable=self.auto_interval_var, width=7).pack(side="left", padx=(6, 14))
        ttk.Label(auto_row1, text="401 账号处理").pack(side="left")
        ttk.Combobox(
            auto_row1,
            textvariable=self.auto_401_action_var,
            values=["删除", "仅标记"],
            state="readonly",
            width=9,
        ).pack(side="left", padx=(6, 14))

        ttk.Label(auto_row1, text="额度耗尽账号处理").pack(side="left")
        ttk.Combobox(
            auto_row1,
            textvariable=self.auto_quota_action_var,
            values=["关闭", "删除", "仅标记"],
            state="readonly",
            width=9,
        ).pack(side="left", padx=(6, 14))

        ttk.Checkbutton(
            auto_row1,
            text="不足时允许从已关闭账号补齐",
            variable=self.auto_allow_closed_scan_var,
        ).pack(side="left", padx=(0, 14))

        self.auto_toggle_btn = ttk.Button(
            auto_row1,
            text="停止自动巡检" if self.auto_enabled_var.get() else "启动自动巡检",
            command=self.toggle_auto_check,
            style="Primary.TButton",
        )
        self.auto_toggle_btn.pack(side="left", padx=(0, 6))

        self.auto_status_var = tk.StringVar(value="自动巡检状态：未启动")
        ttk.Label(auto, textvariable=self.auto_status_var, style="Subtle.TLabel").pack(side="left", pady=(7, 0))

        self.auto_interval_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.auto_401_action_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.auto_quota_action_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.auto_enabled_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.auto_keep_active_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.auto_allow_closed_scan_var.trace_add("write", lambda *_: self._schedule_save_config())

        # 运行参数改动后也持久化到 config.json
        self.base_url_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.token_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.workers_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.quota_workers_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.delete_workers_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.weekly_quota_threshold_var.trace_add("write", lambda *_: self._schedule_save_config())
        self.primary_quota_threshold_var.trace_add("write", lambda *_: self._schedule_save_config())

        filter_frame = ttk.LabelFrame(self.main_content, text="筛选与搜索", style="Card.TLabelframe", padding=(8, 5))
        filter_frame.pack(fill="x", pady=(0, 2))

        ttk.Label(filter_frame, text="关键词").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self._apply_filter)
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=34).pack(side="left", padx=(6, 16))

        ttk.Label(filter_frame, text="状态筛选").pack(side="left")
        self.filter_status = ttk.Combobox(
            filter_frame,
            values=["全部", "活跃", "未知", "已关闭", "备用", "401无效", "额度耗尽"],
            state="readonly",
            width=10,
        )
        self.filter_status.set("全部")
        self.filter_status.bind("<<ComboboxSelected>>", self._apply_filter)
        self.filter_status.pack(side="left", padx=(6, 12))
        ttk.Label(filter_frame, text="提示：双击表格行可切换勾选状态", style="Subtle.TLabel").pack(side="left")

        ops = ttk.LabelFrame(self.main_content, text="批量操作", style="Card.TLabelframe", padding=(8, 5))
        ops.pack(fill="x", pady=(0, 2))

        ops_row = ttk.Frame(ops)
        ops_row.pack(fill="x")
        ttk.Button(ops_row, text="全选", command=self.select_all, style="Neutral.TButton").pack(side="left")
        ttk.Button(ops_row, text="取消全选", command=self.select_none, style="Neutral.TButton").pack(side="left", padx=(6, 10))
        ttk.Button(ops_row, text="检测401无效", command=self.check_401, style="Primary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(ops_row, text="检测额度", command=self.check_quota, style="Primary.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="检测(401+额度)", command=self.check_both, style="Primary.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="关闭选中账号", command=self.close_selected, style="Warn.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="恢复已关闭", command=self.recover_closed_accounts, style="Neutral.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="加入备用池", command=self.add_selected_to_standby, style="Neutral.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="备用转活跃", command=self.remove_selected_from_standby, style="Neutral.TButton").pack(side="left", padx=6)
        ttk.Button(ops_row, text="永久删除", command=self.delete_selected, style="Danger.TButton").pack(side="left", padx=(6, 0))

        self.action_progress = tk.StringVar(value="")
        ttk.Label(ops, textvariable=self.action_progress, style="Subtle.TLabel").pack(fill="x", pady=(6, 0))

        table_panel = ttk.Frame(self.main_content)
        table_panel.pack(fill="both", expand=True)

        columns = ("account", "status", "usage_limit", "error_info")
        self.tree = ttk.Treeview(table_panel, columns=columns, show="headings", height=24)

        self.tree.heading("account", text="账号 / 邮箱")
        self.tree.heading("status", text="状态")
        self.tree.heading("usage_limit", text="额度详情")
        self.tree.heading("error_info", text="错误信息")

        self.tree.column("account", width=300, minwidth=180, anchor="w")
        self.tree.column("status", width=90, minwidth=80, anchor="center")
        self.tree.column("usage_limit", width=420, minwidth=260, anchor="w")
        self.tree.column("error_info", width=320, minwidth=180, anchor="w")

        yscroll = ttk.Scrollbar(table_panel, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.help_page = ttk.Frame(main, style="Card.TFrame", padding=(14, 12))
        self.help_page.columnconfigure(0, weight=1)
        self.help_page.rowconfigure(0, weight=1)

        self.help_canvas = tk.Canvas(self.help_page, highlightthickness=0, bg="#f3f6fb")
        self.help_canvas.grid(row=0, column=0, sticky="nsew")

        help_scroll = ttk.Scrollbar(self.help_page, orient="vertical", command=self.help_canvas.yview)
        help_scroll.grid(row=0, column=1, sticky="ns")
        self.help_canvas.configure(yscrollcommand=help_scroll.set)

        self.help_inner = ttk.Frame(self.help_canvas, style="Card.TFrame")
        self._help_window = self.help_canvas.create_window((0, 0), window=self.help_inner, anchor="nw")
        self.help_inner.bind("<Configure>", self._on_help_inner_configure)
        self.help_canvas.bind("<Configure>", self._on_help_canvas_configure)

        help_card = ttk.LabelFrame(self.help_inner, text="使用说明", style="Card.TLabelframe", padding=(14, 12))
        help_card.pack(fill="both", expand=True)

        ttk.Label(help_card, text="一、快速上手", style="Header.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(help_card, text="1) 填写“管理端地址(base_url)”和“访问令牌(token/cpa_password)”。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="2) 点击“刷新账号列表”，确认账号已加载。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="3) 活跃账号目标数（全局参数）：在自动巡检、检测、移出备用、恢复已关闭等涉及开启账号的流程中都会生效；系统会把活跃账号控制在目标数以内。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="4) 不足时允许从已关闭账号补齐（全局参数）：开启后，备用池不够时会继续扫描已关闭账号。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="5) 先执行“检测401无效 / 检测额度 / 联合检测”，再进行关闭、恢复、删除。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="6) 401无效账号推荐删除 / 无额度账号推荐关闭 / 其他普通报错账号默认按活跃展示", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="7) 可用关键词+状态筛选；双击表格行可勾选/取消勾选。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x", pady=(0, 8))
        ttk.Label(help_card, text="8) 当前默认只操作codex账号，其他类型账号会扫描但不会操作，可以手动操作。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x", pady=(0, 8))

        ttk.Separator(help_card, orient="horizontal").pack(fill="x", pady=(2, 8))

        ttk.Label(help_card, text="二、状态与筛选说明", style="Header.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(help_card, text="- 状态判定采用统一优先级（从高到低）：401无效 > 备用 > 已关闭 > 额度耗尽 > 活跃 > 未知。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 活跃：包含检测通过账号，以及非401/非额度耗尽的普通报错账号。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 未知：新导入的账号，尚未完成有效检测（建议优先检测）。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 已关闭：手动关闭的账号，可通过点击“恢复已关闭”按钮检测后恢复使用。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 备用：账号在备用池中，默认不参与主流程。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 401无效：认证无效账号，可直接删除，无限保留。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 额度耗尽：命中额度阈值或限额信号，且不属于401。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 若账号同时命中多个状态（如既在备用池又401失效），界面会优先显示“401无效”。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Separator(help_card, orient="horizontal").pack(fill="x", pady=(2, 8))

        ttk.Label(help_card, text="三、备用池说明", style="Header.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(help_card, text="- 加入备用池：将选中账号加入备用列表，并立即关闭账号。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 备用转活跃：会先做 401+额度检测，仅“状态正常且非额度耗尽”的账号会开启并移入活跃账号池，并且移出备用池。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 自动补齐活跃账号时，系统会优先从备用池挑选可恢复账号。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x", pady=(0, 8))

        ttk.Separator(help_card, orient="horizontal").pack(fill="x", pady=(2, 8))

        ttk.Label(help_card, text="四、自动巡检说明（重点）", style="Header.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(help_card, text="- 巡检间隔：按分钟周期执行。启动后会先立即执行一次。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 401处理：删除/仅标记；额度处理：关闭/删除/仅标记（按你的下拉选项执行）。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x", pady=(0, 8))

        ttk.Separator(help_card, orient="horizontal").pack(fill="x", pady=(2, 8))

        ttk.Label(help_card, text="五、复杂操作与风险提示", style="Header.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(help_card, text="- 推荐流程：联合检测（401+额度） → 核对状态 → 批量关闭/恢复/删除。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- “并发值”：并发值越高检测速度越快，性能消耗越大（消耗的是cliproxy api所在机器的能），推荐自动巡检时设置小并发数。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- “永久删除”：不可恢复，请先确认筛选条件和勾选结果。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x")
        ttk.Label(help_card, text="- 如检测结果异常，先检查 base_url、token 和网络连通性，再重试。", style="Subtle.TLabel", justify="left", wraplength=1060).pack(anchor="w", fill="x", pady=(0, 10))

        ttk.Button(help_card, text="返回主界面", command=self._toggle_help_page, style="Primary.TButton").pack(anchor="w")

        self.bind_all("<MouseWheel>", self._on_help_mousewheel, add="+")
        self.bind_all("<Button-4>", self._on_help_mousewheel, add="+")
        self.bind_all("<Button-5>", self._on_help_mousewheel, add="+")

        status_frame = ttk.Frame(self, relief="flat", padding=(6, 1), height=26)
        status_frame.grid(row=1, column=0, sticky="ew")
        status_frame.grid_propagate(False)
        status_frame.columnconfigure(0, weight=1)
        status_frame.columnconfigure(1, weight=0)

        self.status_bar = tk.StringVar(value="准备就绪")
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_bar,
            anchor="w",
            justify="left",
            bg="#e2e8f0",
            fg="#0f172a",
        )
        self.status_label.grid(row=0, column=0, sticky="ew")
        self.footer_brand_label = tk.Label(
            status_frame,
            text="HsMirageAI小站:ai.hsnb.fun",
            anchor="e",
            justify="right",
            bg="#e2e8f0",
            fg="#475569",
        )
        self.footer_brand_label.grid(row=0, column=1, sticky="e", padx=(8, 0))
        status_frame.bind("<Configure>", self._update_status_wrap)

        self.tree.bind("<Double-1>", self.toggle_item)
        self.tree.bind("<Configure>", self._on_tree_resize)
        self.after(80, self._update_tree_columns)

    def _on_help_inner_configure(self, _event=None):
        try:
            self.help_canvas.configure(scrollregion=self.help_canvas.bbox("all"))
        except Exception:
            pass

    def _on_help_canvas_configure(self, event):
        try:
            self.help_canvas.itemconfigure(self._help_window, width=event.width)
        except Exception:
            pass

    def _on_help_mousewheel(self, event):
        if not self._on_help_page:
            return
        delta = getattr(event, "delta", 0)
        if delta:
            step = -1 if delta > 0 else 1
            self.help_canvas.yview_scroll(step, "units")
            return

        num = getattr(event, "num", None)
        if num == 4:
            self.help_canvas.yview_scroll(-1, "units")
        elif num == 5:
            self.help_canvas.yview_scroll(1, "units")

    def _toggle_help_page(self):
        if self._on_help_page:
            self.help_page.pack_forget()
            self.main_content.pack(fill="both", expand=True)
            self.help_btn.configure(text="使用说明")
            self._on_help_page = False
            self.status_bar.set("已返回主界面")
        else:
            self.main_content.pack_forget()
            self.help_page.pack(fill="both", expand=True)
            self.help_btn.configure(text="返回主界面")
            self._on_help_page = True
            self.status_bar.set("当前为使用说明页面")

    def _update_status_wrap(self, event):
        total_width = int(getattr(event, "width", 0) or 0)
        width = max(120, total_width - 20)
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

        # 优先给“额度信息”和“错误信息”更多空间
        status_w = max(80, int(total_width * 0.09))
        account_w = max(180, int(total_width * 0.26))
        remain = total_width - status_w - account_w
        usage_w = max(260, int(remain * 0.58))
        error_w = max(180, remain - usage_w)

        # 窄屏时切换为紧凑额度文案，避免关键字段被截断
        compact_mode = total_width < 1120
        if compact_mode != self._compact_usage_mode:
            self._compact_usage_mode = compact_mode
            self._apply_filter()

        try:
            self.tree.column("account", width=account_w)
            self.tree.column("status", width=status_w)
            self.tree.column("usage_limit", width=usage_w)
            self.tree.column("error_info", width=error_w)
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

    def _schedule_save_config(self):
        """输入过程中做防抖保存，避免每按一个键就写盘。"""

        if self._config_save_job is not None:
            try:
                self.after_cancel(self._config_save_job)
            except Exception:
                pass
        self._config_save_job = self.after(400, self._save_config)

    def _save_config(self):
        self._config_save_job = None
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

            keep_active_text = str(self.auto_keep_active_var.get() or "").strip()
            try:
                keep_active = int(keep_active_text)
                if keep_active >= 0:
                    self.conf["auto_keep_active_count"] = keep_active
            except Exception:
                pass

            self.conf["auto_allow_scan_closed"] = bool(self.auto_allow_closed_scan_var.get())
            self.conf["standby_output"] = self.conf.get("standby_output") or DEFAULT_STANDBY_OUTPUT
            self.conf.pop("standby_accounts", None)

            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.conf, f, ensure_ascii=False, indent=2)
        except Exception as e:
            # 配置自动保存失败时仅写状态栏，避免用户输入过程中被反复弹窗打断。
            self.status_bar.set(f"配置自动保存失败：{e}")

    def _normalize_token(self, raw):
        s = str(raw or "").strip()
        s = s.replace("　", " ").strip().strip("。；，,")
        return s

    def _ensure_accounts_loaded(self, action_name):
        if self.all_accounts:
            return True
        messagebox.showinfo(action_name, "当前账号列表为空，请先点击“刷新”并确保加载成功。")
        return False

    def _parse_int_input(self, label, raw_value, default_value=None, min_value=None, max_value=None):
        """统一做数值输入校验，避免运行时直接抛 ValueError。"""

        text = str(raw_value or "").strip()
        if text == "":
            if default_value is not None:
                value = int(default_value)
            else:
                raise RuntimeError(f"{label} 不能为空")
        else:
            try:
                value = int(text)
            except Exception:
                raise RuntimeError(f"{label} 必须是整数")

        if min_value is not None and value < min_value:
            raise RuntimeError(f"{label} 不能小于 {min_value}")
        if max_value is not None and value > max_value:
            raise RuntimeError(f"{label} 不能大于 {max_value}")
        return value

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

        workers = self._parse_int_input("401 检测并发", self.workers_var.get(), DEFAULT_WORKERS, min_value=1)
        quota_workers = self._parse_int_input("额度检测并发", self.quota_workers_var.get(), DEFAULT_QUOTA_WORKERS, min_value=1)
        delete_workers = self._parse_int_input("删除并发", self.delete_workers_var.get(), DEFAULT_DELETE_WORKERS, min_value=1)
        weekly_quota_threshold = self._parse_int_input(
            "周额度阈值 (%)", self.weekly_quota_threshold_var.get(), DEFAULT_QUOTA_THRESHOLD, min_value=0, max_value=100
        )
        primary_quota_threshold = self._parse_int_input(
            "5 小时额度阈值 (%)", self.primary_quota_threshold_var.get(), DEFAULT_QUOTA_THRESHOLD, min_value=0, max_value=100
        )
        auto_keep_active_count = self._parse_int_input(
            "活跃账号目标数", self.auto_keep_active_var.get(), 0, min_value=0
        )

        return {
            "base_url": base_url,
            "token": token,
            "timeout": int(self.conf.get("timeout") or DEFAULT_TIMEOUT),
            "workers": workers,
            "quota_workers": quota_workers,
            "close_workers": int(self.conf.get("close_workers") or DEFAULT_CLOSE_WORKERS),
            "enable_workers": int(self.conf.get("enable_workers") or DEFAULT_ENABLE_WORKERS),
            "delete_workers": delete_workers,
            "retries": int(self.conf.get("retries") or DEFAULT_RETRIES),
            "user_agent": self.conf.get("user_agent") or DEFAULT_UA,
            "chatgpt_account_id": self.conf.get("chatgpt_account_id") or None,
            "target_type": (self.conf.get("target_type") or DEFAULT_TARGET_TYPE).lower(),
            "provider": (self.conf.get("provider") or "").lower(),
            "weekly_quota_threshold": weekly_quota_threshold,
            "primary_quota_threshold": primary_quota_threshold,
            "output": self.conf.get("output") or DEFAULT_OUTPUT,
            "quota_output": self.conf.get("quota_output") or DEFAULT_QUOTA_OUTPUT,
            "active_quota_output": self.conf.get("active_quota_output") or DEFAULT_ACTIVE_QUOTA_OUTPUT,
            "auto_keep_active_count": auto_keep_active_count,
            "auto_allow_scan_closed": bool(self.auto_allow_closed_scan_var.get()),
            "auto_action_401": self.auto_401_action_var.get(),
            "auto_action_quota": self.auto_quota_action_var.get(),
        }

    def _active_target_count(self):
        try:
            return max(0, int(self.auto_keep_active_var.get() or 0))
        except Exception:
            return max(0, int(self.conf.get("auto_keep_active_count") or 0))

    def _current_active_count(self):
        count = 0
        for account in (self.all_accounts or []):
            if self._status_bucket(account) == "活跃":
                count += 1
        return count

    def _build_active_target_meta(self):
        target_active = self._active_target_count()
        current_active = self._current_active_count()
        unlimited = target_active <= 0
        available_slots = max(0, target_active - current_active)
        return {
            "target_active": target_active,
            "current_active": current_active,
            "available_slots": available_slots,
            "unlimited": unlimited,
        }

    def _rescan_active_and_refresh_gap(self, rt, target_active, current_active_before):
        summary = {
            "rescanned": False,
            "scanned": 0,
            "active_before": int(current_active_before),
            "active_after": int(current_active_before),
            "available_slots_after": max(0, int(target_active) - int(current_active_before)),
            "invalid_401": 0,
            "invalid_quota": 0,
            "errors": [],
        }

        try:
            target = int(target_active)
        except Exception:
            target = 0
        try:
            current = int(current_active_before)
        except Exception:
            current = 0

        if target <= 0 or current < target:
            return summary

        try:
            files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
            self._refresh_standby_names_for_files(files)
            active_candidates = self._collect_primary_auto_candidates_from_files(files, rt)
            scan_summary = self._scan_for_recovery(rt, active_candidates, need_count=None)
            probe_by_identity = scan_summary.get("probe_by_name") or {}
            quota_by_identity = scan_summary.get("quota_by_name") or {}
            scanned_keys = set(probe_by_identity.keys()) | set(quota_by_identity.keys())
            if scanned_keys:
                self._apply_scan_maps_to_accounts(scanned_keys, probe_by_identity, quota_by_identity)

            invalid_401 = len(scan_summary.get("invalid_401") or [])
            invalid_quota = len(scan_summary.get("invalid_quota") or [])
            active_after = self._current_active_count()

            summary["rescanned"] = True
            summary["scanned"] = int(scan_summary.get("scanned") or 0)
            summary["active_after"] = int(active_after)
            summary["available_slots_after"] = max(0, target - int(active_after))
            summary["invalid_401"] = invalid_401
            summary["invalid_quota"] = invalid_quota
            summary["errors"] = list(scan_summary.get("errors") or [])
            return summary
        except Exception as e:
            summary["rescanned"] = True
            summary["errors"] = [str(e)]
            return summary

    def _pick_names_with_active_target_limit(self, names):
        ordered = []
        seen = set()
        for name in (names or []):
            n = str(name or "").strip()
            if not n or n in seen:
                continue
            seen.add(n)
            ordered.append(n)

        target_active = self._active_target_count()
        current_active = self._current_active_count()

        # 目标数<=0 视为不限制
        if target_active <= 0:
            return {
                "selected": ordered,
                "skipped": [],
                "target_active": target_active,
                "current_active": current_active,
                "available_slots": len(ordered),
                "unlimited": True,
            }

        available_slots = max(0, target_active - current_active)
        selected = ordered[:available_slots]
        skipped = ordered[available_slots:]

        return {
            "selected": selected,
            "skipped": skipped,
            "target_active": target_active,
            "current_active": current_active,
            "available_slots": available_slots,
            "unlimited": False,
        }

    def _pick_keys_with_active_target_limit(self, raws):
        ordered_raws = []
        seen_keys = set()
        for raw in (raws or []):
            key = self._result_identity_key(raw)
            if not key or key in seen_keys:
                continue
            seen_keys.add(key)
            ordered_raws.append(raw)

        target_active = self._active_target_count()
        current_active = self._current_active_count()

        if target_active <= 0:
            selected_raws = ordered_raws
            skipped_raws = []
            unlimited = True
            available_slots = len(ordered_raws)
        else:
            available_slots = max(0, target_active - current_active)
            selected_raws = ordered_raws[:available_slots]
            skipped_raws = ordered_raws[available_slots:]
            unlimited = False

        selected_names = []
        for raw in selected_raws:
            name = str((raw or {}).get("name") or "").strip()
            if name:
                selected_names.append(name)

        skipped_names = []
        for raw in skipped_raws:
            name = str((raw or {}).get("name") or "").strip()
            if name:
                skipped_names.append(name)

        return {
            "selected": selected_names,
            "skipped": skipped_names,
            "selected_keys": {self._result_identity_key(raw) for raw in selected_raws if self._result_identity_key(raw)},
            "skipped_keys": {self._result_identity_key(raw) for raw in skipped_raws if self._result_identity_key(raw)},
            "target_active": target_active,
            "current_active": current_active,
            "available_slots": available_slots,
            "unlimited": unlimited,
        }

    def _rebalance_active_target_by_runtime(self, rt):
        summary = {
            "target_active": max(0, int(rt.get("auto_keep_active_count") or 0)),
            "active_before": 0,
            "active_after": 0,
            "moved_to_standby_count": 0,
            "enabled_count": 0,
            "enforce_applied": False,
            "enforce_skipped": False,
            "error_count": 0,
            "error": None,
        }

        try:
            target_active = summary["target_active"]
            if target_active <= 0:
                summary["enforce_skipped"] = True
                return summary

            summary["active_before"] = self._current_active_count()
            rebalance_errors = []

            if summary["active_before"] >= target_active:
                gap_rescan = self._rescan_active_and_refresh_gap(rt, target_active, summary["active_before"])
                summary["active_before"] = int(gap_rescan.get("active_after") or summary["active_before"])
                rebalance_errors.extend(gap_rescan.get("errors") or [])

            overflow_result = {"overflow_total": 0, "moved_to_standby": [], "move_errors": []}
            if self._current_active_count() > target_active:
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                self._refresh_standby_names_for_files(files)
                primary_candidates = self._collect_primary_auto_candidates_from_files(files, rt)
                overflow_result = self._move_active_overflow_to_standby(rt, primary_candidates, target_active)
            summary["moved_to_standby_count"] = len(overflow_result.get("moved_to_standby") or [])
            rebalance_errors.extend(overflow_result.get("move_errors") or [])

            files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
            self._refresh_standby_names_for_files(files)
            need_count = max(0, target_active - self._current_active_count())

            picked_names = []
            standby_scan_errors = []
            closed_scan_errors = []
            standby_file_dirty = False

            if need_count > 0:
                standby_candidates = self._collect_standby_candidates_from_files(files, rt)
                standby_scan = self._scan_for_recovery(rt, standby_candidates, need_count)
                picked_names.extend(standby_scan.get("recoverable") or [])
                standby_scan_errors.extend(standby_scan.get("errors") or [])

                standby_probe_by_name = standby_scan.get("probe_by_name") or {}
                standby_quota_by_name = standby_scan.get("quota_by_name") or {}
                standby_scanned_names = set(standby_probe_by_name.keys()) | set(standby_quota_by_name.keys())
                if standby_scanned_names:
                    self._apply_scan_maps_to_accounts(standby_scanned_names, standby_probe_by_name, standby_quota_by_name)

                standby_invalid_401 = {n for n in (standby_scan.get("invalid_401") or []) if n}
                standby_invalid_quota = {n for n in (standby_scan.get("invalid_quota") or []) if n}
                standby_to_remove = standby_invalid_401 | standby_invalid_quota
                if standby_to_remove:
                    for name in standby_to_remove:
                        if name in self.standby_names:
                            self.standby_names.remove(name)
                            standby_file_dirty = True

                    for account in (self.all_accounts or []):
                        name = str(account.get("name") or "").strip()
                        if not name or name not in standby_to_remove:
                            continue
                        account["standby"] = False
                        if name in standby_invalid_quota:
                            account["disabled"] = True
                            if account.get("raw"):
                                account["raw"]["disabled"] = True
                        elif name in standby_invalid_401:
                            account["disabled"] = False
                            if account.get("raw"):
                                account["raw"]["disabled"] = False

                remaining_need = max(0, need_count - len(picked_names))
                if remaining_need > 0 and rt.get("auto_allow_scan_closed"):
                    closed_candidates = self._collect_closed_candidates_from_files(files, rt, exclude_names=picked_names)
                    closed_scan = self._scan_for_recovery(rt, closed_candidates, remaining_need)
                    picked_names.extend(closed_scan.get("recoverable") or [])
                    closed_scan_errors.extend(closed_scan.get("errors") or [])

                    closed_probe_by_name = closed_scan.get("probe_by_name") or {}
                    closed_quota_by_name = closed_scan.get("quota_by_name") or {}
                    closed_scanned_names = set(closed_probe_by_name.keys()) | set(closed_quota_by_name.keys())
                    if closed_scanned_names:
                        self._apply_scan_maps_to_accounts(closed_scanned_names, closed_probe_by_name, closed_quota_by_name)

            enabled_count = 0
            enable_errors = []
            if picked_names:
                account_by_name = {}
                for account in (self.all_accounts or []):
                    name = str(account.get("name") or "").strip()
                    if name:
                        account_by_name[name] = account

                enable_results = asyncio.run(
                    enable_names(
                        rt["base_url"],
                        rt["token"],
                        picked_names,
                        rt["enable_workers"],
                        rt["timeout"],
                    )
                )
                for r in enable_results:
                    name = r.get("name")
                    if r.get("updated") and name:
                        enabled_count += 1
                        account = account_by_name.get(name)
                        if account:
                            account["standby"] = False
                            account["disabled"] = False
                            if account.get("raw"):
                                account["raw"]["disabled"] = False
                            account["check_error"] = None
                        if name in self.standby_names:
                            self.standby_names.remove(name)
                            standby_file_dirty = True
                    else:
                        enable_errors.append(f"{name}: {r.get('error')}")

            if standby_file_dirty:
                try:
                    self._save_standby_names_to_file()
                except Exception as e:
                    enable_errors.append(f"备用池保存失败: {e}")

            rebalance_errors.extend(standby_scan_errors)
            rebalance_errors.extend(closed_scan_errors)
            rebalance_errors.extend(enable_errors)

            summary["enabled_count"] = enabled_count
            summary["active_after"] = self._current_active_count()
            summary["enforce_applied"] = True
            summary["error_count"] = len(rebalance_errors)
            return summary
        except Exception as e:
            summary["error"] = str(e)
            return summary

    def _resolve_output_path(self, path_text):
        p = Path(str(path_text or "").strip() or DEFAULT_ACTIVE_QUOTA_OUTPUT)
        # 相对路径统一按 config.json 所在目录解析，避免 frozen/不同启动目录导致读写不一致
        base_dir = Path(self.config_path).resolve().parent if self.config_path else Path(HERE)
        if not p.is_absolute():
            p = base_dir / p
        return p

    def _standby_output_path(self):
        return self._resolve_output_path(self.conf.get("standby_output") or DEFAULT_STANDBY_OUTPUT)

    def _load_standby_names_from_file(self):
        names = set()
        for item in self._load_standby_entries_from_file():
            name = self._standby_entry_name(item)
            if name:
                names.add(name)
        return names

    def _load_standby_entries_from_file(self):
        path = self._standby_output_path()
        if not path.exists():
            legacy = self.conf.get("standby_accounts") or []
            if isinstance(legacy, list):
                return list(legacy)
            return []
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return []
            return data
        except Exception:
            return []

    def _standby_entry_name(self, item):
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                return name
            raw = item.get("raw")
            if isinstance(raw, dict):
                raw_name = str(raw.get("name") or "").strip()
                if raw_name:
                    return raw_name
            return ""
        return str(item or "").strip()

    def _standby_entry_keys(self, item):
        values = []
        if isinstance(item, dict):
            for key in ("name", "account", "email", "auth_index", "authIndex"):
                values.append(item.get(key))
            raw = item.get("raw")
            if isinstance(raw, dict):
                for key in ("name", "account", "email", "auth_index", "authIndex"):
                    values.append(raw.get(key))
        else:
            values.append(item)
        return {str(value).strip() for value in values if str(value or "").strip()}

    def _resolve_standby_names_for_files(self, files):
        standby_entries = self._load_standby_entries_from_file()
        if not standby_entries:
            return set()

        standby_lookup = set()
        for item in standby_entries:
            standby_lookup.update(self._standby_entry_keys(item))
        if not standby_lookup:
            return set()

        resolved = set()
        for item in (files or []):
            name = str((item or {}).get("name") or "").strip()
            if not name:
                continue
            if self._standby_entry_keys(item) & standby_lookup:
                resolved.add(name)
        return resolved

    def _refresh_standby_names_for_files(self, files):
        self.standby_names = self._resolve_standby_names_for_files(files)
        return self.standby_names

    def _save_standby_names_to_file(self):
        path = self._standby_output_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        cleaned = {str(name).strip() for name in (self.standby_names or set()) if str(name or "").strip()}
        self.standby_names = cleaned
        with path.open("w", encoding="utf-8") as f:
            json.dump(sorted(cleaned), f, ensure_ascii=False, indent=2)

    def _record_active_quota_snapshot(self, scan_type):
        out_path = self._resolve_output_path(self.conf.get("active_quota_output") or DEFAULT_ACTIVE_QUOTA_OUTPUT)

        records = []
        now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for account in self.all_accounts:
            # 与界面状态桶保持一致：仅记录“活跃”账号（含普通报错）
            if self._status_bucket(account) != "活跃":
                continue

            used_percent = account.get("used_percent")
            weekly_percent = account.get("individual_used_percent")
            short_percent = account.get("primary_used_percent")

            records.append(
                {
                    "captured_at": now_text,
                    "scan_type": scan_type,
                    "account": account.get("account") or "",
                    "name": account.get("name") or "",
                    "used_percent": used_percent,
                    "weekly_used_percent": weekly_percent,
                    "primary_used_percent": short_percent,
                    "quota_source": account.get("quota_source"),
                    "reset_at": account.get("reset_at"),
                    "weekly_reset_at": account.get("individual_reset_at"),
                    "primary_reset_at": account.get("primary_reset_at"),
                }
            )

        if not records:
            return {"count": 0, "path": str(out_path), "error": None}

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("a", encoding="utf-8") as f:
                for row in records:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            return {"count": len(records), "path": str(out_path), "error": None}
        except Exception as e:
            return {"count": 0, "path": str(out_path), "error": str(e)}

    def _load_accounts(self):
        self.status.set("正在从API加载账号列表...")
        self.action_progress.set("")

        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            self.status.set("加载失败")
            return

        previous_state_by_id = {}
        for a in (self.all_accounts or []):
            key = a.get("_identity") or a.get("name") or a.get("auth_index")
            if key:
                previous_state_by_id[key] = a

        previous_ids = set(previous_state_by_id.keys())
        is_incremental_refresh = bool(previous_ids)

        def worker():
            try:
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                self._refresh_standby_names_for_files(files)

                accounts = []
                for f in files:
                    status_msg = f.get("status_message", "")
                    status_msg_obj = as_json_obj(status_msg)
                    status_msg_text = str(status_msg or "")
                    error_info = ""
                    usage_limit = ""
                    limit_marked_by_status = False
                    limit_reset_at = None
                    identity = f.get("name") or f.get("auth_index") or ""

                    raw_status = f.get("status")
                    normalized_status = raw_status or "unknown"
                    stream_error_active = _is_stream_error_active(raw_status, status_msg)

                    prev = previous_state_by_id.get(identity) or {}
                    pending_scan = bool(prev.get("_pending_scan", False))

                    if is_incremental_refresh and identity and identity not in previous_ids:
                        # 新增账号默认标记为未知，且在完成扫描前保持未知
                        normalized_status = "unknown"
                        pending_scan = True

                    err = status_msg_obj.get("error") if isinstance(status_msg_obj, dict) else {}
                    if normalized_status == "error" and status_msg_text:
                        if isinstance(err, dict):
                            error_info = err.get("message") or status_msg_text[:150]
                        else:
                            error_info = status_msg_text[:150]

                    if isinstance(err, dict) and err.get("resets_at") is not None:
                        limit_reset_at = err.get("resets_at")

                    if _contains_limit_error(raw_status) or _contains_limit_error(status_msg_obj) or _contains_limit_error(status_msg_text):
                        limit_marked_by_status = True
                        if not usage_limit and limit_reset_at:
                            try:
                                usage_limit = f"重置时间: {datetime.fromtimestamp(limit_reset_at).strftime('%Y-%m-%d %H:%M')}"
                            except Exception:
                                pass

                    # 新增账号在未扫描前保持未知，避免仅刷新就被接口状态覆盖
                    if pending_scan:
                        account_status = "unknown"
                    else:
                        # 保留上一轮扫描得到的状态（active/error），仅当账号从未被扫描时才使用 normalized_status
                        account_status = prev.get("status") if prev.get("status") in ("active", "error") else normalized_status

                    name = f.get("name") or ""
                    prev_invalid_quota = bool(prev.get("invalid_quota", False))
                    prev_used_percent = prev.get("used_percent")
                    prev_quota_source = prev.get("quota_source")
                    prev_reset_at = prev.get("reset_at")

                    invalid_quota = prev_invalid_quota or limit_marked_by_status
                    used_percent = prev_used_percent
                    quota_source = prev_quota_source
                    reset_at = prev_reset_at

                    if limit_marked_by_status:
                        used_percent = 100
                        quota_source = "status_message"
                        if limit_reset_at is not None:
                            reset_at = limit_reset_at

                    accounts.append(
                        {
                            "name": name,
                            "account": f.get("account") or f.get("email") or "",
                            "status": account_status,
                            "stream_error_active": stream_error_active,
                            "error_info": error_info,
                            "usage_limit": usage_limit,
                            "auth_index": f.get("auth_index"),
                            "provider": f.get("provider"),
                            "type": get_item_type(f),
                            "disabled": bool(f.get("disabled", False)),
                            "standby": bool(name and name in self.standby_names),
                            # 保留上一轮检测结果，避免删除401后额度耗尽标记丢失
                            "invalid_401": bool(prev.get("invalid_401", False)),
                            "invalid_quota": invalid_quota,
                            "used_percent": used_percent,
                            "primary_used_percent": prev.get("primary_used_percent"),
                            "primary_reset_at": prev.get("primary_reset_at"),
                            "individual_used_percent": prev.get("individual_used_percent"),
                            "individual_reset_at": prev.get("individual_reset_at"),
                            "quota_source": quota_source,
                            "reset_at": reset_at,
                            "check_error": prev.get("check_error"),
                            "_pending_scan": pending_scan,
                            "_selected": True,
                            "_identity": identity,
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
        active_count = len([a for a in accounts if self._status_bucket(a) == "活跃"])
        unknown_count = len([a for a in accounts if self._status_bucket(a) == "未知"])
        closed_count = len([a for a in accounts if self._status_bucket(a) == "已关闭"])
        standby_count = len([a for a in accounts if self._status_bucket(a) == "备用"])
        target_active = self._active_target_count()

        if target_active <= 0:
            target_text = "不限"
            gap_text = "-"
        else:
            target_text = str(target_active)
            gap_text = str(target_active - active_count)

        self.status.set(
            f"加载完成: 总共={total} 活跃={active_count} 未知={unknown_count} 已关闭={closed_count} 备用={standby_count} | 目标活跃={target_text} 差值={gap_text}"
        )

    def _apply_scan_status(self, account, status_code):
        if status_code is None:
            # 已参与扫描但响应缺少状态码：记为错误，避免继续停留在未知列表
            account["status"] = "error"
            account["stream_error_active"] = False
            account["_pending_scan"] = False
            return
        if status_code == 200:
            account["status"] = "active"
        else:
            account["status"] = "error"
        account["stream_error_active"] = False
        account["_pending_scan"] = False

    def _status_bucket(self, account):
        """统一状态桶判定，确保显示/筛选/统计使用同一规则。"""
        if account.get("invalid_401"):
            return "401无效"
        if account.get("standby"):
            return "备用"
        if account.get("disabled"):
            return "已关闭"
        if account.get("invalid_quota"):
            return "额度耗尽"

        s = (account.get("status") or "unknown").lower()
        if s in ("active", "error") or bool(account.get("stream_error_active")):
            return "活跃"
        if s in ("", "unknown"):
            return "未知"
        return str(account.get("status") or s)

    def _display_status(self, account):
        return self._status_bucket(account)


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

    def _display_error_info(self, account):
        if self._status_bucket(account) == "已关闭":
            return ""
        return (account.get("check_error") or account.get("error_info") or "")[:160]

    def _apply_filter(self, *_):
        for i in self.tree.get_children():
            self.tree.delete(i)

        text_filter = (self.filter_var.get() or "").lower()
        status_filter = self.filter_status.get()

        filtered = []
        for account in self.all_accounts:
            bucket = self._status_bucket(account)
            if status_filter != "全部" and bucket != status_filter:
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
                    f"{prefix} {account.get('account', '')}",
                    self._display_status(account),
                    self._display_usage(account),
                    self._display_error_info(account),
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
                f"{prefix} {account.get('account', '')}",
                self._display_status(account),
                self._display_usage(account),
                self._display_error_info(account),
            ),
        )

    def select_all(self):
        for idx, account in enumerate(self.filtered_accounts):
            account["_selected"] = True
            self.tree.item(
                str(idx),
                values=(
                    f"[X] {account.get('account', '')}",
                    self._display_status(account),
                    self._display_usage(account),
                    self._display_error_info(account),
                ),
            )

    def select_none(self):
        for idx, account in enumerate(self.filtered_accounts):
            account["_selected"] = False
            self.tree.item(
                str(idx),
                values=(
                    f"[ ] {account.get('account', '')}",
                    self._display_status(account),
                    self._display_usage(account),
                    self._display_error_info(account),
                ),
            )

    def _selected_names(self):
        return [a.get("name") for a in self.filtered_accounts if a.get("_selected") and a.get("name")]

    def add_selected_to_standby(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("加入备用", "你没有选择任何账号。")
            return

        if not messagebox.askyesno(
            "确认加入备用",
            (
                f"确定将选中的 {len(names)} 个账号加入备用列表吗？\n\n"
                "加入备用后会自动关闭账号，并在定时补齐时优先从备用中恢复。"
            ),
        ):
            return

        self.action_progress.set(f"正在加入备用并关闭账号... 数量={len(names)}")

        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            self.action_progress.set("加入备用失败")
            return

        def worker():
            try:
                close_results = asyncio.run(
                    close_names(rt["base_url"], rt["token"], names, rt["close_workers"], rt["timeout"])
                )
                self.after(0, self._add_standby_done, close_results)
            except Exception as e:
                self.after(0, messagebox.showerror, "加入备用失败", str(e))
                self.after(0, self.action_progress.set, "加入备用失败")

        threading.Thread(target=worker, daemon=True).start()

    def _add_standby_done(self, close_results):
        ok = [r.get("name") for r in close_results if r.get("updated") and r.get("name")]
        bad = [r for r in close_results if not r.get("updated")]

        for name in ok:
            self.standby_names.add(name)

        try:
            self._save_standby_names_to_file()
        except Exception as e:
            messagebox.showwarning("加入备用结果", f"备用文件写入失败:\n{e}")
        self._save_config()
        self.action_progress.set(f"加入备用完成：成功={len(ok)} 失败={len(bad)}")

        if bad:
            msg = "以下账号加入备用失败：\n" + "\n".join([f"- {r.get('name')}: {r.get('error')}" for r in bad[:15]])
            if len(bad) > 15:
                msg += f"\n... 还有 {len(bad)-15} 条"
            messagebox.showwarning("加入备用结果", msg)
        else:
            messagebox.showinfo("加入备用结果", f"已加入备用并关闭：{len(ok)} 个")

        self._load_accounts()

    def remove_selected_from_standby(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("移出备用", "你没有选择任何账号。")
            return

        standby_selected = [name for name in names if name in self.standby_names]
        if not standby_selected:
            messagebox.showinfo("移出备用", "选中账号中没有备用账号。")
            return

        if not messagebox.askyesno(
            "确认移出备用",
            (
                f"将对选中的 {len(standby_selected)} 个备用账号执行 401 + 额度扫描。\n"
                "仅状态正常且非额度耗尽账号会被开启并移出备用。\n\n"
                "继续吗？"
            ),
        ):
            return

        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        candidates = []
        for account in self.all_accounts:
            if account.get("name") not in standby_selected:
                continue
            raw = account.get("raw") or {}
            if not raw.get("auth_index"):
                continue
            candidates.append(raw)

        if not candidates:
            messagebox.showinfo("移出备用", "选中的备用账号缺少 auth_index，无法检测。")
            return

        active_target_meta = self._build_active_target_meta()
        target_active = int(active_target_meta.get("target_active") or 0)
        current_active_before = int(active_target_meta.get("current_active") or 0)
        available_slots_before = int(active_target_meta.get("available_slots") or 0)
        available_slots_text = "不限" if active_target_meta.get("unlimited") else str(available_slots_before)
        gap_rescan_summary = None
        if (not active_target_meta.get("unlimited")) and available_slots_before <= 0:
            self.action_progress.set("当前差值=0，先复扫活跃账号以校准缺口...")
            gap_rescan_summary = self._rescan_active_and_refresh_gap(rt, target_active, current_active_before)
            current_active_before = int(gap_rescan_summary.get("active_after") or current_active_before)
            available_slots_before = int(gap_rescan_summary.get("available_slots_after") or 0)
            available_slots_text = str(available_slots_before)
            if available_slots_before <= 0:
                extra_lines = [
                    f"活跃复扫：扫描={int(gap_rescan_summary.get('scanned') or 0)}",
                    f"发现401={int(gap_rescan_summary.get('invalid_401') or 0)}",
                    f"发现额度耗尽={int(gap_rescan_summary.get('invalid_quota') or 0)}",
                ]
                if gap_rescan_summary.get("errors"):
                    extra_lines.append("复扫异常: " + " | ".join((gap_rescan_summary.get("errors") or [])[:3]))
                self.action_progress.set("移出备用已跳过：复扫后可开启名额仍为0")
                messagebox.showinfo(
                    "移出备用",
                    (
                        f"复扫后仍无可开启名额（目标={target_active}，当前活跃={current_active_before}）。\n"
                        "本次不会从备用池补齐。\n\n"
                        + "\n".join(extra_lines)
                    ),
                )
                return

        scan_need_count = None if active_target_meta.get("unlimited") else max(0, available_slots_before)
        scan_need_text = "全量扫描" if scan_need_count is None else f"按缺口扫描，最多补齐 {scan_need_count} 个"

        self.action_progress.set(
            f"正在检测备用账号并尝试移出... 候选={len(candidates)} | 目标={target_active} 当前活跃={current_active_before} 可开启名额={available_slots_text} | {scan_need_text}"
        )

        def worker():
            try:
                scan_summary = self._scan_for_recovery(rt, candidates, need_count=scan_need_count)
                probe_by_identity = scan_summary.get("probe_by_name") or {}
                quota_by_identity = scan_summary.get("quota_by_name") or {}
                probe_results = list(probe_by_identity.values())
                quota_results = list(quota_by_identity.values())

                recoverable_names = list(scan_summary.get("recoverable") or [])
                limit_meta = self._pick_names_with_active_target_limit(recoverable_names)
                if isinstance(limit_meta, dict):
                    limit_meta = dict(limit_meta)
                    limit_meta["scanned"] = int(scan_summary.get("scanned") or 0)
                    limit_meta["recoverable_detected"] = len(recoverable_names)
                    limit_meta["scan_need_count"] = scan_need_count
                    limit_meta["scan_errors"] = list(scan_summary.get("errors") or [])
                    limit_meta["gap_rescan_summary"] = gap_rescan_summary or {}

                names_to_enable = list(limit_meta.get("selected") or [])

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

                self.after(
                    0,
                    self._remove_standby_scan_done,
                    standby_selected,
                    candidates,
                    probe_results,
                    quota_results,
                    enable_results,
                    limit_meta,
                )
            except Exception as e:
                self.after(0, messagebox.showerror, "移出备用失败", str(e))
                self.after(0, self.action_progress.set, "移出备用失败")

        threading.Thread(target=worker, daemon=True).start()

    def _remove_standby_scan_done(self, standby_selected, candidate_raws, probe_results, quota_results, enable_results, limit_meta=None):
        probe_by_identity, _probe_conflicts = self._index_results_by_identity(probe_results)
        quota_by_identity, _quota_conflicts = self._index_results_by_identity(quota_results)
        enable_by_name = {r.get("name"): r for r in enable_results if r.get("name")}

        limit_data = limit_meta if isinstance(limit_meta, dict) else self._build_active_target_meta()
        target_active = int(limit_data.get("target_active") or 0)
        current_active_before = int(limit_data.get("current_active") or 0)
        available_slots_before = int(limit_data.get("available_slots") or 0)
        available_slots_text = "不限" if limit_data.get("unlimited") else str(available_slots_before)
        scanned_count = int(limit_data.get("scanned") or 0) if isinstance(limit_data, dict) else 0
        scan_need_count = limit_data.get("scan_need_count") if isinstance(limit_data, dict) else None
        scan_errors_extra = list(limit_data.get("scan_errors") or []) if isinstance(limit_data, dict) else []
        gap_rescan_summary = (limit_data.get("gap_rescan_summary") or {}) if isinstance(limit_data, dict) else {}

        selected_for_enable_names = []
        skipped_by_target_names = []
        if isinstance(limit_meta, dict):
            selected_for_enable_names = [n for n in (limit_meta.get("selected") or []) if n]
            skipped_by_target_names = [n for n in (limit_meta.get("skipped") or []) if n]

        selected_for_enable_set = set(selected_for_enable_names)
        skipped_by_target_set = set(skipped_by_target_names)
        selected_for_enable_keys = self._pick_identity_keys_for_names(candidate_raws, selected_for_enable_names)
        skipped_by_target_keys = self._pick_identity_keys_for_names(candidate_raws, skipped_by_target_names)

        enabled_names = [r.get("name") for r in enable_results if r.get("updated") and r.get("name")]
        failed_enable_names = [r.get("name") for r in enable_results if (not r.get("updated")) and r.get("name")]
        enable_success_keys = self._pick_identity_keys_for_names(candidate_raws, enabled_names)
        enable_failed_keys = self._pick_identity_keys_for_names(candidate_raws, failed_enable_names)

        selected_identity_keys = self._pick_identity_keys_for_names(candidate_raws, standby_selected)

        recoverable = 0
        active_count = 0
        moved_401_count = 0
        moved_closed_count = 0
        enable_fail = 0
        detect_errors = 0

        for account in self.all_accounts:
            account_key = self._account_identity_key(account)
            name = str(account.get("name") or "").strip()
            if selected_identity_keys:
                if account_key not in selected_identity_keys:
                    continue
            else:
                if name not in standby_selected:
                    continue
            p = self._result_for_account(probe_by_identity, account)
            q = self._result_for_account(quota_by_identity, account)
            if self._is_recoverable_by_scan(p, q):
                recoverable += 1

        for account in self.all_accounts:
            account_key = self._account_identity_key(account)
            name = str(account.get("name") or "").strip()
            if selected_identity_keys:
                if account_key not in selected_identity_keys:
                    continue
            else:
                if name not in standby_selected:
                    continue

            p = self._result_for_account(probe_by_identity, account)
            q = self._result_for_account(quota_by_identity, account)

            invalid_401 = bool(p and p.get("invalid_401"))
            invalid_quota = bool(q and q.get("invalid_quota"))

            if p:
                account["invalid_401"] = invalid_401
                self._apply_scan_status(account, p.get("status_code"))
                if p.get("error"):
                    detect_errors += 1

            if q:
                account["invalid_quota"] = invalid_quota
                if not p:
                    self._apply_scan_status(account, q.get("status_code"))
                account["used_percent"] = q.get("used_percent")
                account["primary_used_percent"] = q.get("primary_used_percent")
                account["primary_reset_at"] = q.get("primary_reset_at")
                account["individual_used_percent"] = q.get("individual_used_percent")
                account["individual_reset_at"] = q.get("individual_reset_at")
                account["quota_source"] = q.get("quota_source")
                account["reset_at"] = q.get("reset_at")
                if q.get("error"):
                    detect_errors += 1

            # 默认保留在备用池；仅在实际迁移到其他列表时才移出备用池
            account["standby"] = True
            if name:
                self.standby_names.add(name)

            if invalid_401:
                moved_401_count += 1
                account["standby"] = False
                self.standby_names.discard(name)
                account["disabled"] = False
                if account.get("raw"):
                    account["raw"]["disabled"] = False
                account["check_error"] = (p.get("error") if p else None) or (q.get("error") if q else None)
                continue

            if invalid_quota:
                moved_closed_count += 1
                account["standby"] = False
                self.standby_names.discard(name)
                account["disabled"] = True
                if account.get("raw"):
                    account["raw"]["disabled"] = True
                account["check_error"] = (q.get("error") if q else None) or (p.get("error") if p else None)
                continue

            e = enable_by_name.get(name)
            enabled_ok = (account_key in enable_success_keys) if enable_success_keys else bool(e and e.get("updated"))
            selected_for_enable = (
                (account_key in selected_for_enable_keys) if selected_for_enable_keys else (name in selected_for_enable_set)
            )
            skipped_by_target = (
                (account_key in skipped_by_target_keys) if skipped_by_target_keys else (name in skipped_by_target_set)
            )
            marked_failed = (account_key in enable_failed_keys) if enable_failed_keys else bool(e and not e.get("updated"))

            if enabled_ok:
                active_count += 1
                account["standby"] = False
                self.standby_names.discard(name)
                account["disabled"] = False
                if account.get("raw"):
                    account["raw"]["disabled"] = False
                account["check_error"] = None
            else:
                # 未成功开启（含因活跃目标数跳过）保持备用状态，不误转为已关闭
                account["disabled"] = True
                if account.get("raw"):
                    account["raw"]["disabled"] = True

                if selected_for_enable and not skipped_by_target and marked_failed:
                    enable_fail += 1
                    if e:
                        account["check_error"] = e.get("error")
                    else:
                        account["check_error"] = (q.get("error") if q else None) or (p.get("error") if p else None)
                elif skipped_by_target:
                    account["check_error"] = None
                else:
                    account["check_error"] = None

        try:
            self._save_standby_names_to_file()
        except Exception as e:
            messagebox.showwarning("移出备用", f"备用文件写入失败:\n{e}")

        self._save_config()
        self._apply_filter()
        skipped_by_target = len(skipped_by_target_keys) if skipped_by_target_keys else len(skipped_by_target_set)
        recoverable_count = recoverable
        enabled_count = active_count

        self.action_progress.set(f"移出备用完成：活跃={active_count} 401={moved_401_count} 已关闭={moved_closed_count}")

        msg_lines = [
            f"活跃目标门控：目标={target_active}，当前活跃={current_active_before}，可开启名额={available_slots_text}",
            f"本次选中备用账号：{len(standby_selected)}",
            (
                f"本轮实际扫描：{scanned_count}"
                if scanned_count > 0
                else f"本轮实际扫描：{len(candidate_raws)}"
            ),
            f"符合开启条件：{recoverable_count}",
            f"开启成功：{enabled_count}",
            f"转入401列表：{moved_401_count}",
            f"转入已关闭列表：{moved_closed_count}",
        ]
        if scan_need_count is not None:
            msg_lines.insert(2, f"本轮扫描目标补齐数：{int(scan_need_count)}")
        if gap_rescan_summary.get("rescanned"):
            msg_lines.insert(
                1,
                (
                    f"缺口校准复扫：扫描={int(gap_rescan_summary.get('scanned') or 0)} "
                    f"401={int(gap_rescan_summary.get('invalid_401') or 0)} "
                    f"额度={int(gap_rescan_summary.get('invalid_quota') or 0)}"
                ),
            )
            detect_errors += len(gap_rescan_summary.get("errors") or [])
        if scan_errors_extra:
            detect_errors += len(scan_errors_extra)
        if enable_fail > 0:
            msg_lines.append(f"开启失败：{enable_fail}")
        if detect_errors > 0:
            msg_lines.append(f"检测异常：{detect_errors}")
        if skipped_by_target > 0:
            msg_lines.append(f"受全局活跃目标数限制未开启：{skipped_by_target}")

        messagebox.showinfo("移出备用结果", "\n".join(msg_lines))

        self._load_accounts()

    def _unknown_filter_selected(self):
        return str(self.filter_status.get() or "").strip() == "未知"

    def _candidate_raw_items(self, rt, only_unknown=False):
        """返回可检测账号：默认活跃（含普通报错）/未知；only_unknown=True 时仅未知。"""
        target_type = rt["target_type"]
        provider = rt["provider"]

        candidates = []
        for account in self.all_accounts:
            if account.get("disabled"):
                continue
            if account.get("standby"):
                continue

            status = (account.get("status") or "unknown").lower()
            if only_unknown:
                if status not in ("unknown", ""):
                    continue
            else:
                if status not in ("active", "unknown", "error", ""):
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

    def _quota_candidate_raw_items(self, rt, only_unknown=False):
        """额度检测默认检查活跃（含普通报错）/未知；unknown筛选时仅检查未知。"""
        return self._candidate_raw_items(rt, only_unknown=only_unknown)

    def _raw_matches_target(self, raw, rt):
        item_type = str(get_item_type(raw) or "").lower()
        item_provider = str(raw.get("provider") or "").lower()

        if rt["target_type"] and item_type != rt["target_type"]:
            return False
        if rt["provider"] and item_provider != rt["provider"]:
            return False
        if not raw.get("auth_index"):
            return False
        return True

    def _collect_primary_auto_candidates_from_files(self, files, rt):
        candidates = []
        for f in files:
            name = str(f.get("name") or "").strip()
            if bool(f.get("disabled")):
                continue
            if name and name in self.standby_names:
                continue

            status = str(f.get("status") or "unknown").lower()
            status_msg = f.get("status_message") or ""
            # 普通 error 账号与 active 同池处理；401/额度会在后续检测中单独归类
            if status not in ("active", "error") and not _is_stream_error_active(status, status_msg):
                continue
            if not self._raw_matches_target(f, rt):
                continue
            candidates.append(f)
        return candidates

    def _collect_unknown_candidates_from_files(self, files, rt):
        candidates = []
        for f in files:
            name = str(f.get("name") or "").strip()
            if bool(f.get("disabled")):
                continue
            if name and name in self.standby_names:
                continue

            status = str(f.get("status") or "unknown").lower()
            if status not in ("unknown", ""):
                continue
            if not self._raw_matches_target(f, rt):
                continue
            candidates.append(f)
        return candidates

    def _collect_standby_candidates_from_files(self, files, rt, exclude_names=None):
        exclude_set = set(exclude_names or [])
        candidates = []
        for f in files:
            name = str(f.get("name") or "").strip()
            if not name or name not in self.standby_names:
                continue
            if name in exclude_set:
                continue
            if not self._raw_matches_target(f, rt):
                continue
            candidates.append(f)
        return candidates

    def _collect_closed_candidates_from_files(self, files, rt, exclude_names=None):
        exclude_set = set(exclude_names or [])
        candidates = []
        for f in files:
            name = str(f.get("name") or "").strip()
            if not bool(f.get("disabled")):
                continue
            if name in self.standby_names:
                continue
            if name and name in exclude_set:
                continue
            if not self._raw_matches_target(f, rt):
                continue
            candidates.append(f)
        return candidates

    def _result_identity_key(self, item):
        ai = str((item or {}).get("auth_index") or "").strip()
        if ai:
            return f"ai:{ai}"
        name = str((item or {}).get("name") or "").strip()
        if name:
            return f"name:{name}"
        return ""

    def _account_identity_key(self, account):
        raw = (account or {}).get("raw") or {}
        ai = str((raw.get("auth_index") if isinstance(raw, dict) else "") or account.get("auth_index") or "").strip()
        if ai:
            return f"ai:{ai}"
        name = str((account or {}).get("name") or "").strip()
        if name:
            return f"name:{name}"
        return ""

    def _pick_identity_keys_for_names(self, raw_items, names):
        name_quota = {}
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            name_quota[name] = int(name_quota.get(name) or 0) + 1

        if not name_quota:
            return set()

        picked_keys = set()
        picked_count_by_name = {}
        for raw in (raw_items or []):
            name = str((raw or {}).get("name") or "").strip()
            need = int(name_quota.get(name) or 0)
            if need <= 0:
                continue

            picked = int(picked_count_by_name.get(name) or 0)
            if picked >= need:
                continue

            key = self._result_identity_key(raw)
            if not key:
                continue

            picked_keys.add(key)
            picked_count_by_name[name] = picked + 1

            done = True
            for quota_name, quota_count in name_quota.items():
                if int(picked_count_by_name.get(quota_name) or 0) < int(quota_count):
                    done = False
                    break
            if done:
                break

        return picked_keys

    def _index_results_by_identity(self, results):
        indexed = {}
        conflict_count = 0
        for r in (results or []):
            key = self._result_identity_key(r)
            if not key:
                continue
            if key in indexed:
                conflict_count += 1
            indexed[key] = r
        return indexed, conflict_count

    def _result_for_account(self, indexed_results, account):
        key = self._account_identity_key(account)
        if not key:
            return None
        return (indexed_results or {}).get(key)

    def _is_recoverable_by_scan(self, probe_result, quota_result):
        if not probe_result or not quota_result:
            return False
        if probe_result.get("status_code") != 200:
            return False
        if probe_result.get("invalid_401"):
            return False
        if probe_result.get("error"):
            return False

        if quota_result.get("status_code") != 200:
            return False
        if quota_result.get("invalid_quota"):
            return False
        if quota_result.get("error"):
            return False
        return True

    def _apply_scan_maps_to_accounts(self, names, probe_by_name, quota_by_name):
        names_set = {str(n or "").strip() for n in (names or []) if str(n or "").strip()}
        if not names_set:
            return

        for account in (self.all_accounts or []):
            account_key = self._account_identity_key(account)
            account_name = str(account.get("name") or "").strip()
            if account_key not in names_set and (not account_name or account_name not in names_set):
                continue

            p = self._result_for_account(probe_by_name or {}, account)
            q = self._result_for_account(quota_by_name or {}, account)

            if p:
                account["invalid_401"] = bool(p.get("invalid_401"))
                self._apply_scan_status(account, p.get("status_code"))

            if q:
                account["invalid_quota"] = bool(q.get("invalid_quota"))
                if not p:
                    self._apply_scan_status(account, q.get("status_code"))
                account["used_percent"] = q.get("used_percent")
                account["primary_used_percent"] = q.get("primary_used_percent")
                account["primary_reset_at"] = q.get("primary_reset_at")
                account["individual_used_percent"] = q.get("individual_used_percent")
                account["individual_reset_at"] = q.get("individual_reset_at")
                account["quota_source"] = q.get("quota_source")
                account["reset_at"] = q.get("reset_at")

            if p or q:
                account["check_error"] = (q.get("error") if q else None) or (p.get("error") if p else None)

    def _target_scan_batch_size(self, rt):
        try:
            workers = max(1, int(rt.get("workers") or DEFAULT_WORKERS))
        except Exception:
            workers = max(1, int(DEFAULT_WORKERS))

        # 活跃目标模式下严格按“并发”作为每批扫描量
        return workers

    def _scan_for_recovery(self, rt, candidates, need_count=None):
        if not candidates:
            return {
                "scanned": 0,
                "recoverable": [],
                "invalid_401": [],
                "invalid_quota": [],
                "limit_only_quota": [],
                "errors": [],
                "probe_by_name": {},
                "quota_by_name": {},
                "merge_conflict_count": 0,
            }

        target_count = None
        if need_count is not None:
            try:
                target_count = max(0, int(need_count))
            except Exception:
                target_count = 0
            if target_count <= 0:
                return {
                    "scanned": 0,
                    "recoverable": [],
                    "invalid_401": [],
                    "invalid_quota": [],
                    "limit_only_quota": [],
                    "errors": [],
                    "probe_by_name": {},
                    "quota_by_name": {},
                    "merge_conflict_count": 0,
                }

        recoverable_names = []
        recoverable_set = set()
        invalid_401_set = set()
        invalid_quota_set = set()
        limit_only_quota_set = set()
        scan_errors = []
        scanned_count = 0
        merge_conflict_count = 0
        probe_result_by_name = {}
        quota_result_by_name = {}

        refreshed_by_auth_index = {}
        try:
            refreshed_files = refresh_quota_source(rt["base_url"], rt["token"], rt["timeout"])
            for f in refreshed_files:
                ai = f.get("auth_index")
                if ai:
                    refreshed_by_auth_index[ai] = f
        except Exception:
            refreshed_by_auth_index = {}

        if target_count is None:
            chunk_size = max(1, min(len(candidates), max(1, rt.get("workers", 1))))
        else:
            batch_size = self._target_scan_batch_size(rt)
            chunk_size = max(1, min(len(candidates), batch_size))

        for i in range(0, len(candidates), chunk_size):
            if target_count is not None and len(recoverable_names) >= target_count:
                break

            chunk = candidates[i : i + chunk_size]
            if not chunk:
                continue

            probe_results = asyncio.run(
                probe_accounts(
                    rt["base_url"],
                    rt["token"],
                    chunk,
                    rt["user_agent"],
                    rt["chatgpt_account_id"],
                    rt["workers"],
                    rt["timeout"],
                    rt["retries"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed_by_auth_index,
                )
            )
            quota_results = asyncio.run(
                check_quota_accounts(
                    rt["base_url"],
                    rt["token"],
                    chunk,
                    rt["user_agent"],
                    rt["chatgpt_account_id"],
                    rt["quota_workers"],
                    rt["timeout"],
                    rt["retries"],
                    rt["weekly_quota_threshold"],
                    rt["primary_quota_threshold"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed_by_auth_index,
                )
            )

            scanned_count += len(chunk)

            probe_by_identity, probe_conflicts = self._index_results_by_identity(probe_results)
            quota_by_identity, quota_conflicts = self._index_results_by_identity(quota_results)
            merge_conflict_count += (probe_conflicts + quota_conflicts)
            probe_result_by_name.update(probe_by_identity)
            quota_result_by_name.update(quota_by_identity)

            for r in probe_results:
                if r.get("invalid_401") and r.get("name"):
                    invalid_401_set.add(r.get("name"))
                if r.get("error"):
                    scan_errors.append(f"{r.get('name')}: {r.get('error')}")
            for r in quota_results:
                if r.get("invalid_quota") and r.get("name"):
                    invalid_quota_set.add(r.get("name"))
                    if r.get("quota_source") == "status_message":
                        limit_only_quota_set.add(r.get("name"))
                if r.get("error"):
                    scan_errors.append(f"{r.get('name')}: {r.get('error')}")

            for item in chunk:
                name = item.get("name")
                if not name or name in recoverable_set:
                    continue
                item_key = self._result_identity_key(item)
                p = (probe_by_identity.get(item_key) if item_key else None) or probe_by_identity.get(f"name:{name}")
                q = (quota_by_identity.get(item_key) if item_key else None) or quota_by_identity.get(f"name:{name}")
                if self._is_recoverable_by_scan(p, q):
                    recoverable_set.add(name)
                    recoverable_names.append(name)
                    if target_count is not None and len(recoverable_names) >= target_count:
                        break

        if target_count is None:
            recoverable_out = recoverable_names
        else:
            recoverable_out = recoverable_names[:target_count]

        return {
            "scanned": scanned_count,
            "recoverable": recoverable_out,
            "invalid_401": sorted(invalid_401_set),
            "invalid_quota": sorted(invalid_quota_set),
            "limit_only_quota": sorted(limit_only_quota_set),
            "errors": scan_errors,
            "probe_by_name": probe_result_by_name,
            "quota_by_name": quota_result_by_name,
            "merge_conflict_count": merge_conflict_count,
        }

    def _close_names_to_standby(self, rt, names):
        ordered_names = []
        seen = set()
        for name in (names or []):
            n = str(name or "").strip()
            if not n or n in seen:
                continue
            seen.add(n)
            ordered_names.append(n)

        if not ordered_names:
            return {"overflow_total": 0, "moved_to_standby": [], "move_errors": []}

        moved_names = []
        move_errors = []
        close_results = asyncio.run(
            close_names(rt["base_url"], rt["token"], ordered_names, rt["close_workers"], rt["timeout"])
        )
        moved_set = set()
        for r in close_results:
            name = str(r.get("name") or "").strip()
            if r.get("updated") and name:
                moved_names.append(name)
                moved_set.add(name)
                self.standby_names.add(name)
            else:
                move_errors.append(f"{name}: {r.get('error')}")

        if moved_set:
            for account in (self.all_accounts or []):
                name = str(account.get("name") or "").strip()
                if name not in moved_set:
                    continue
                account["standby"] = True
                account["disabled"] = True
                if account.get("raw"):
                    account["raw"]["disabled"] = True
                account["check_error"] = None

            try:
                self._save_standby_names_to_file()
            except Exception as e:
                move_errors.append(f"备用池保存失败: {e}")

        return {
            "overflow_total": len(ordered_names),
            "moved_to_standby": sorted({n for n in moved_names if n}),
            "move_errors": move_errors,
        }

    def _move_active_overflow_to_standby(self, rt, primary_candidates, target_active):
        keep_candidates = list(primary_candidates or [])
        overflow_candidates = []
        if target_active > 0 and len(keep_candidates) > target_active:
            overflow_candidates = keep_candidates[target_active:]
            keep_candidates = keep_candidates[:target_active]

        overflow_names = []
        for item in overflow_candidates:
            name = str((item or {}).get("name") or "").strip()
            if name:
                overflow_names.append(name)

        move_result = self._close_names_to_standby(rt, overflow_names)

        return {
            "keep_candidates": keep_candidates,
            "overflow_total": int(move_result.get("overflow_total") or 0),
            "moved_to_standby": list(move_result.get("moved_to_standby") or []),
            "move_errors": list(move_result.get("move_errors") or []),
        }

    def _scan_active_candidates_and_apply(self, rt, active_candidates, need_count=None):
        if not active_candidates:
            return {
                "scanned": 0,
                "active_ok": [],
                "invalid_401": [],
                "invalid_quota": [],
                "actions": {"deleted": [], "closed": [], "delete_errors": [], "close_errors": []},
                "scan_errors": [],
                "merge_conflict_count": 0,
            }

        target_count = None
        if need_count is not None:
            try:
                target_count = max(0, int(need_count))
            except Exception:
                target_count = 0
            if target_count <= 0:
                return {
                    "scanned": 0,
                    "active_ok": [],
                    "invalid_401": [],
                    "invalid_quota": [],
                    "actions": {"deleted": [], "closed": [], "delete_errors": [], "close_errors": []},
                    "scan_errors": [],
                    "merge_conflict_count": 0,
                }

        active_ok_names = []
        active_ok_set = set()
        invalid_401_set = set()
        invalid_quota_set = set()
        limit_only_quota_set = set()
        scan_errors = []
        scanned_count = 0
        merge_conflict_count = 0

        if target_count is None:
            chunk_size = max(1, min(len(active_candidates), max(1, rt.get("workers", 1))))
        else:
            batch_size = self._target_scan_batch_size(rt)
            chunk_size = max(1, min(len(active_candidates), batch_size))

        for i in range(0, len(active_candidates), chunk_size):
            if target_count is not None and len(active_ok_names) >= target_count:
                break

            chunk = active_candidates[i : i + chunk_size]
            if not chunk:
                continue

            probe_results = asyncio.run(
                probe_accounts(
                    rt["base_url"],
                    rt["token"],
                    chunk,
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
                    chunk,
                    rt["user_agent"],
                    rt["chatgpt_account_id"],
                    rt["quota_workers"],
                    rt["timeout"],
                    rt["retries"],
                    rt["weekly_quota_threshold"],
                    rt["primary_quota_threshold"],
                )
            )

            scanned_count += len(chunk)

            probe_by_identity, probe_conflicts = self._index_results_by_identity(probe_results)
            quota_by_identity, quota_conflicts = self._index_results_by_identity(quota_results)
            merge_conflict_count += (probe_conflicts + quota_conflicts)

            for r in probe_results:
                if r.get("invalid_401") and r.get("name"):
                    invalid_401_set.add(r.get("name"))
                if r.get("error"):
                    scan_errors.append(f"{r.get('name')}: {r.get('error')}")

            for r in quota_results:
                if r.get("invalid_quota") and r.get("name"):
                    name = r.get("name")
                    invalid_quota_set.add(name)
                    if r.get("quota_source") == "status_message":
                        limit_only_quota_set.add(name)
                if r.get("error"):
                    scan_errors.append(f"{r.get('name')}: {r.get('error')}")

            for item in chunk:
                name = item.get("name")
                if not name or name in active_ok_set:
                    continue
                item_key = self._result_identity_key(item)
                p = (probe_by_identity.get(item_key) if item_key else None) or probe_by_identity.get(f"name:{name}")
                q = (quota_by_identity.get(item_key) if item_key else None) or quota_by_identity.get(f"name:{name}")
                if self._is_recoverable_by_scan(p, q):
                    active_ok_set.add(name)
                    active_ok_names.append(name)
                    if target_count is not None and len(active_ok_names) >= target_count:
                        break

        action_result = self._auto_apply_actions(
            rt,
            sorted(invalid_401_set),
            sorted(invalid_quota_set),
            sorted(limit_only_quota_set),
        )

        if target_count is None:
            active_ok_out = active_ok_names
        else:
            active_ok_out = active_ok_names[:target_count]

        return {
            "scanned": scanned_count,
            "active_ok": active_ok_out,
            "invalid_401": sorted(invalid_401_set),
            "invalid_quota": sorted(invalid_quota_set),
            "actions": action_result,
            "scan_errors": scan_errors,
            "merge_conflict_count": merge_conflict_count,
        }

    def _apply_auto_401_action_only(self, rt, invalid_401_names):
        names = sorted({n for n in (invalid_401_names or []) if n})
        if not names:
            return {"deleted": [], "errors": []}
        action_401 = str(rt.get("auto_action_401") or self.conf.get("auto_action_401") or "删除")
        if action_401 != "删除":
            return {"deleted": [], "errors": []}

        deleted_names = []
        delete_errors = []
        delete_results = asyncio.run(
            delete_names(rt["base_url"], rt["token"], names, rt["delete_workers"], rt["timeout"])
        )
        for r in delete_results:
            if r.get("deleted"):
                deleted_names.append(r.get("name"))
            else:
                delete_errors.append(f"{r.get('name')}: {r.get('error')}")
        return {"deleted": sorted([n for n in deleted_names if n]), "errors": delete_errors}

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
        action_401 = str(rt.get("auto_action_401") or self.conf.get("auto_action_401") or "删除")
        action_quota = str(rt.get("auto_action_quota") or self.conf.get("auto_action_quota") or "关闭")

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

    def _observe_active_convergence(self, rt, target_active, max_reads=3, interval_seconds=0.6):
        try:
            reads = max(1, int(self.conf.get("auto_convergence_reads") or max_reads))
        except Exception:
            reads = max_reads
        try:
            interval = float(self.conf.get("auto_convergence_interval_seconds") or interval_seconds)
            interval = max(0.0, interval)
        except Exception:
            interval = interval_seconds

        samples = []
        read_error = None
        for idx in range(reads):
            try:
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                self._refresh_standby_names_for_files(files)
                active_candidates = self._collect_primary_auto_candidates_from_files(files, rt)
                active_scan = self._scan_for_recovery(rt, active_candidates, need_count=None)
                active_count = len(active_scan.get("recoverable") or [])
                samples.append(active_count)
            except Exception as e:
                read_error = str(e)
                break

            if active_count == target_active:
                break
            if idx < (reads - 1) and interval > 0:
                time.sleep(interval)

        active_observed = samples[-1] if samples else 0
        unlimited_target = int(target_active) <= 0
        stable_reading = len(samples) >= 2 and samples[-1] == samples[-2]

        if unlimited_target:
            target_met = read_error is None
            gap_to_target = 0
            consistency_state = "met" if target_met else "pending_convergence"
        else:
            target_met = bool(samples) and active_observed == target_active
            gap_to_target = int(target_active) - int(active_observed)
            if target_met:
                consistency_state = "met"
            elif stable_reading or read_error:
                consistency_state = "not_met"
            else:
                consistency_state = "pending_convergence"

        return {
            "active_observed": active_observed,
            "samples": samples,
            "target_met": target_met,
            "gap_to_target": gap_to_target,
            "consistency_state": consistency_state,
            "read_error": read_error,
        }

    def _run_scheduled_check_once(self):
        if self._auto_running:
            return
        if not self.auto_enabled_var.get():
            return

        try:
            rt = self._runtime()
        except Exception as e:
            self.auto_status_var.set(f"自动巡检参数错误：{e}")
            self.action_progress.set("自动巡检参数错误")
            return

        self._auto_running = True
        self.action_progress.set("自动巡检执行中：正在按活跃目标补齐...")

        def worker():
            summary = None
            try:
                files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                self._refresh_standby_names_for_files(files)

                primary_candidates = self._collect_primary_auto_candidates_from_files(files, rt)
                initial_active = len(primary_candidates)
                target_active = int(rt.get("auto_keep_active_count") or 0)

                # 主账号池始终全量扫描，确保活跃目标按“可用活跃账号数”而不是“开启总数”计算
                active_scan = self._scan_active_candidates_and_apply(rt, primary_candidates, need_count=None)
                active_ok_names = list(active_scan.get("active_ok") or [])
                active_ok_all_names = list(active_ok_names)

                overflow_result = {
                    "overflow_total": 0,
                    "moved_to_standby": [],
                    "move_errors": [],
                }
                if target_active > 0 and len(active_ok_names) > target_active:
                    overflow_names = active_ok_names[target_active:]
                    overflow_result = self._close_names_to_standby(rt, overflow_names)
                    active_ok_names = active_ok_names[:target_active]

                unknown_candidates = self._collect_unknown_candidates_from_files(files, rt)
                unknown_scan = self._scan_for_recovery(rt, unknown_candidates, need_count=None)

                unknown_invalid_401 = sorted(set(unknown_scan.get("invalid_401") or []))
                unknown_invalid_quota = sorted(set(unknown_scan.get("invalid_quota") or []))
                unknown_limit_only_quota = sorted(set(unknown_scan.get("limit_only_quota") or []))

                unknown_action_result = self._auto_apply_actions(
                    rt,
                    unknown_invalid_401,
                    unknown_invalid_quota,
                    unknown_limit_only_quota,
                )

                deleted_unknown_set = set(unknown_action_result.get("deleted") or [])
                closed_unknown_set = set(unknown_action_result.get("closed") or [])
                unknown_recoverable_names = [
                    n
                    for n in (unknown_scan.get("recoverable") or [])
                    if n and n not in deleted_unknown_set and n not in closed_unknown_set
                ]
                to_standby_names = sorted(set(unknown_recoverable_names))

                unknown_standby_result = self._close_names_to_standby(rt, to_standby_names)
                unknown_standby_moved = list(unknown_standby_result.get("moved_to_standby") or [])
                unknown_standby_errors = list(unknown_standby_result.get("move_errors") or [])

                replenish_files = fetch_auth_files(rt["base_url"], rt["token"], rt["timeout"])
                self._refresh_standby_names_for_files(replenish_files)
                active_after_scan = len(active_ok_names)

                standby_candidates = self._collect_standby_candidates_from_files(replenish_files, rt)
                need_count = max(0, target_active - active_after_scan)

                standby_scan = self._scan_for_recovery(rt, standby_candidates, need_count)
                picked_names = list(standby_scan.get("recoverable") or [])

                closed_scan = {
                    "scanned": 0,
                    "recoverable": [],
                    "invalid_401": [],
                    "invalid_quota": [],
                    "limit_only_quota": [],
                    "errors": [],
                    "probe_by_name": {},
                    "quota_by_name": {},
                    "merge_conflict_count": 0,
                }
                closed_overflow_to_standby = []
                closed_recoverable_detected = 0
                remaining_need = max(0, need_count - len(picked_names))
                if remaining_need > 0 and rt.get("auto_allow_scan_closed"):
                    closed_candidates = self._collect_closed_candidates_from_files(
                        replenish_files, rt, exclude_names=picked_names
                    )
                    closed_scan = self._scan_for_recovery(rt, closed_candidates, need_count=remaining_need)
                    picked_names.extend(closed_scan.get("recoverable") or [])

                    # 已关闭池中本轮已扫描且“可恢复”的账号，若因目标已补齐未被开启，转入备用池
                    closed_probe_by_identity = closed_scan.get("probe_by_name") or {}
                    closed_quota_by_identity = closed_scan.get("quota_by_name") or {}
                    closed_recoverable_all_set = set()
                    for key in (set(closed_probe_by_identity.keys()) | set(closed_quota_by_identity.keys())):
                        p = closed_probe_by_identity.get(key)
                        q = closed_quota_by_identity.get(key)
                        if not self._is_recoverable_by_scan(p, q):
                            continue
                        name = str((p or q or {}).get("name") or "").strip()
                        if name:
                            closed_recoverable_all_set.add(name)

                    closed_recoverable_detected = len(closed_recoverable_all_set)
                    picked_from_closed_set = {
                        str(n).strip()
                        for n in (closed_scan.get("recoverable") or [])
                        if str(n or "").strip()
                    }
                    overflow_set = closed_recoverable_all_set - picked_from_closed_set
                    if overflow_set:
                        for name in overflow_set:
                            self.standby_names.add(name)
                        closed_overflow_to_standby = sorted(overflow_set)

                enabled_names = []
                enable_errors = []
                standby_recoverable_set = set(standby_scan.get("recoverable") or [])
                standby_removed_by_enable = []
                if picked_names:
                    enable_results = asyncio.run(
                        enable_names(
                            rt["base_url"],
                            rt["token"],
                            picked_names,
                            rt["enable_workers"],
                            rt["timeout"],
                        )
                    )
                    for r in enable_results:
                        name = r.get("name")
                        if r.get("updated"):
                            if name:
                                enabled_names.append(name)
                            if name and name in standby_recoverable_set and name in self.standby_names:
                                self.standby_names.remove(name)
                                standby_removed_by_enable.append(name)
                        else:
                            enable_errors.append(f"{name}: {r.get('error')}")

                invalid_401_all = sorted(
                    {
                        n
                        for n in (
                            (active_scan.get("invalid_401") or [])
                            + (unknown_scan.get("invalid_401") or [])
                            + (standby_scan.get("invalid_401") or [])
                            + (closed_scan.get("invalid_401") or [])
                        )
                        if n
                    }
                )

                invalid_quota_all = sorted(
                    {
                        n
                        for n in (
                            (active_scan.get("invalid_quota") or [])
                            + (unknown_scan.get("invalid_quota") or [])
                            + (standby_scan.get("invalid_quota") or [])
                            + (closed_scan.get("invalid_quota") or [])
                        )
                        if n
                    }
                )

                processed_401 = set(active_scan.get("invalid_401") or []) | set(unknown_scan.get("invalid_401") or [])
                extra_invalid_401 = sorted({n for n in invalid_401_all if n not in processed_401})
                extra_401_action_result = self._apply_auto_401_action_only(rt, extra_invalid_401)

                processed_quota = set(active_scan.get("invalid_quota") or []) | set(unknown_scan.get("invalid_quota") or [])
                extra_invalid_quota = sorted({n for n in invalid_quota_all if n not in processed_quota})
                extra_limit_only_quota = sorted(
                    {
                        n
                        for n in (
                            (standby_scan.get("limit_only_quota") or [])
                            + (closed_scan.get("limit_only_quota") or [])
                        )
                        if n
                    }
                )
                extra_quota_action_result = self._auto_apply_actions(
                    rt,
                    [],
                    extra_invalid_quota,
                    extra_limit_only_quota,
                )

                deleted_all = sorted(
                    {
                        n
                        for n in (
                            (active_scan.get("actions", {}).get("deleted") or [])
                            + (unknown_action_result.get("deleted") or [])
                            + (extra_401_action_result.get("deleted") or [])
                            + (extra_quota_action_result.get("deleted") or [])
                        )
                        if n
                    }
                )

                close_errors_all = list(active_scan.get("actions", {}).get("close_errors") or []) + list(
                    unknown_action_result.get("close_errors") or []
                ) + list(extra_quota_action_result.get("close_errors") or []) + list(unknown_standby_errors)
                delete_errors_all = list(active_scan.get("actions", {}).get("delete_errors") or []) + list(
                    unknown_action_result.get("delete_errors") or []
                ) + list(extra_401_action_result.get("errors") or []) + list(
                    extra_quota_action_result.get("delete_errors") or []
                )

                closed_quota_all = sorted(
                    {
                        n
                        for n in (
                            (active_scan.get("actions", {}).get("closed") or [])
                            + (unknown_action_result.get("closed") or [])
                            + (extra_quota_action_result.get("closed") or [])
                        )
                        if n
                    }
                )

                moved_to_standby_all = sorted(
                    {
                        n
                        for n in (
                            (overflow_result.get("moved_to_standby") or [])
                            + unknown_standby_moved
                            + closed_overflow_to_standby
                        )
                        if n
                    }
                )
                move_errors_all = list(overflow_result.get("move_errors") or [])

                convergence = self._observe_active_convergence(rt, target_active)
                active_after_scan = int(convergence.get("active_observed") or 0)
                target_met = bool(convergence.get("target_met"))
                gap_to_target = int(convergence.get("gap_to_target") or 0)
                consistency_state = str(convergence.get("consistency_state") or "pending_convergence")

                standby_file_dirty = (
                    bool(unknown_standby_moved)
                    or bool(standby_removed_by_enable)
                    or bool(closed_overflow_to_standby)
                )
                deleted_set = set(deleted_all)
                if deleted_set:
                    removed_deleted = [name for name in list(self.standby_names) if name in deleted_set]
                    if removed_deleted:
                        for name in removed_deleted:
                            self.standby_names.discard(name)
                        standby_file_dirty = True

                closed_set = set(closed_quota_all)
                if closed_set:
                    removed_closed = [name for name in list(self.standby_names) if name in closed_set]
                    if removed_closed:
                        for name in removed_closed:
                            self.standby_names.discard(name)
                        standby_file_dirty = True

                if standby_file_dirty:
                    try:
                        self._save_standby_names_to_file()
                    except Exception as e:
                        move_errors_all.append(f"备用池保存失败: {e}")

                merge_conflict_count = (
                    int(active_scan.get("merge_conflict_count") or 0)
                    + int(unknown_scan.get("merge_conflict_count") or 0)
                    + int(standby_scan.get("merge_conflict_count") or 0)
                    + int(closed_scan.get("merge_conflict_count") or 0)
                )

                summary = {
                    "target_active": target_active,
                    "initial_active": initial_active,
                    "active_scanned": active_scan.get("scanned", 0),
                    "active_after_scan": active_after_scan,
                    "active_observed": active_after_scan,
                    "target_met": target_met,
                    "gap_to_target": gap_to_target,
                    "consistency_state": consistency_state,
                    "need_count": max(0, target_active - active_after_scan),
                    "standby_candidates": len(standby_candidates),
                    "standby_scanned": standby_scan.get("scanned", 0),
                    "closed_scanned": closed_scan.get("scanned", 0),
                    "picked_count": len(picked_names),
                    "enabled": sorted([n for n in enabled_names if n]),
                    "enable_errors": enable_errors,
                    "invalid_401": len(invalid_401_all),
                    "deleted_401": deleted_all,
                    "closed_quota": closed_quota_all,
                    "delete_errors": delete_errors_all,
                    "close_errors": close_errors_all,
                    "overflow_total": int(overflow_result.get("overflow_total") or 0),
                    "moved_to_standby": moved_to_standby_all,
                    "move_errors": move_errors_all,
                    "unknown_candidates": len(unknown_candidates),
                    "unknown_scanned": unknown_scan.get("scanned", 0),
                    "unknown_recoverable": len(unknown_recoverable_names),
                    "unknown_standby_moved": len(unknown_standby_moved),
                    "closed_recoverable_detected": closed_recoverable_detected,
                    "closed_overflow_to_standby": len(closed_overflow_to_standby),
                    "merge_conflict_count": merge_conflict_count,
                    "convergence_samples": list(convergence.get("samples") or []),
                    "convergence_read_error": convergence.get("read_error"),
                    "scan_errors": (
                        list(active_scan.get("scan_errors") or [])
                        + list(unknown_scan.get("errors") or [])
                        + list(standby_scan.get("errors") or [])
                        + list(closed_scan.get("errors") or [])
                    ),
                    "active_valid_names": sorted({n for n in (active_ok_all_names + enabled_names) if n}),
                    "invalid_401_names": list(invalid_401_all),
                    "invalid_quota_names": list(invalid_quota_all),
                    "error": None,
                }

            except Exception as e:
                summary = {
                    "target_active": 0,
                    "initial_active": 0,
                    "active_scanned": 0,
                    "active_after_scan": 0,
                    "need_count": 0,
                    "standby_candidates": 0,
                    "standby_scanned": 0,
                    "closed_scanned": 0,
                    "picked_count": 0,
                    "enabled": [],
                    "enable_errors": [],
                    "invalid_401": 0,
                    "deleted_401": [],
                    "closed_quota": [],
                    "delete_errors": [],
                    "close_errors": [],
                    "overflow_total": 0,
                    "moved_to_standby": [],
                    "move_errors": [],
                    "unknown_candidates": 0,
                    "unknown_scanned": 0,
                    "unknown_recoverable": 0,
                    "unknown_standby_moved": 0,
                    "closed_recoverable_detected": 0,
                    "closed_overflow_to_standby": 0,
                    "scan_errors": [],
                    "error": str(e),
                }

            self.after(0, self._scheduled_check_done, summary)

        threading.Thread(target=worker, daemon=True).start()

    def _scheduled_check_done(self, summary):
        self._auto_running = False

        if summary.get("error"):
            self.auto_status_var.set(f"自动巡检失败：{summary.get('error')}")
            self.action_progress.set("自动巡检失败")
        else:
            consistency_state = str(summary.get("consistency_state") or "pending_convergence")
            state_label = {
                "met": "已达标",
                "not_met": "未达标",
                "pending_convergence": "待收敛",
            }.get(consistency_state, consistency_state)

            target_active = int(summary.get("target_active") or 0)
            active_observed = int(summary.get("active_observed") or summary.get("active_after_scan") or 0)
            gap_to_target = int(summary.get("gap_to_target") or 0)
            merge_conflict_count = int(summary.get("merge_conflict_count") or 0)

            self.auto_status_var.set(
                "自动巡检已开启："
                f"一致性={state_label} "
                f"目标={target_active} "
                f"后台回读活跃={active_observed} "
                f"差值={gap_to_target} "
                f"活跃初始={summary.get('initial_active')} "
                f"活跃扫描={summary.get('active_scanned')} "
                f"补齐={len(summary.get('enabled', []))} "
                f"转备用={len(summary.get('moved_to_standby', []))} "
                f"未知扫描={summary.get('unknown_scanned')}/{summary.get('unknown_candidates')} "
                f"未知入备用={summary.get('unknown_standby_moved')} "
                f"已关转备用={summary.get('closed_overflow_to_standby', 0)} "
                f"本轮401={summary.get('invalid_401')} "
                f"合并冲突={merge_conflict_count}"
            )

            if consistency_state == "met":
                self.action_progress.set("自动巡检完成：目标已达成")
            elif consistency_state == "not_met":
                self.action_progress.set("自动巡检完成：目标未达成")
            else:
                self.action_progress.set("自动巡检完成：状态待收敛")

            error_lines = []
            if summary.get("enable_errors"):
                error_lines.append("开启失败:\n" + "\n".join(summary.get("enable_errors")[:10]))
            if summary.get("delete_errors"):
                error_lines.append("删除401失败:\n" + "\n".join(summary.get("delete_errors")[:10]))
            if summary.get("close_errors"):
                error_lines.append("关闭失败:\n" + "\n".join(summary.get("close_errors")[:10]))
            if summary.get("move_errors"):
                error_lines.append("转入备用失败:\n" + "\n".join(summary.get("move_errors")[:10]))
            if summary.get("scan_errors"):
                error_lines.append("扫描异常:\n" + "\n".join(summary.get("scan_errors")[:10]))
            if error_lines:
                messagebox.showwarning("自动巡检部分失败", "\n\n".join(error_lines))

        # 回写本轮扫描状态，避免刷新后沿用旧的 invalid 标记造成 UI 差值
        try:
            active_valid_set = {str(n).strip() for n in (summary.get("active_valid_names") or []) if str(n).strip()}
            invalid_401_set = {str(n).strip() for n in (summary.get("invalid_401_names") or []) if str(n).strip()}
            invalid_quota_set = {str(n).strip() for n in (summary.get("invalid_quota_names") or []) if str(n).strip()}
            tracked_names = active_valid_set | invalid_401_set | invalid_quota_set
            if tracked_names:
                for account in (self.all_accounts or []):
                    name = str(account.get("name") or "").strip()
                    if not name or name not in tracked_names:
                        continue
                    account["invalid_401"] = (name in invalid_401_set)
                    account["invalid_quota"] = (name in invalid_quota_set)
                    if name in active_valid_set:
                        account["status"] = "active"
                        account["_pending_scan"] = False
                        account["check_error"] = None
        except Exception:
            pass

        self._load_accounts()
        self._schedule_next_auto_check()
        self._refresh_auto_toggle_button()

    def _refresh_auto_toggle_button(self):
        try:
            self.auto_toggle_btn.configure(
                text="停止自动巡检" if self.auto_enabled_var.get() else "启动自动巡检"
            )
        except Exception:
            pass

    def toggle_auto_check(self):
        if self.auto_enabled_var.get():
            self.stop_auto_check()
        else:
            self.start_auto_check()

    def _schedule_next_auto_check(self):
        if self._auto_job is not None:
            self.after_cancel(self._auto_job)
            self._auto_job = None

        if not self.auto_enabled_var.get():
            return

        try:
            interval_minutes = int(self.auto_interval_var.get() or 0)
        except Exception:
            self.auto_status_var.set("自动巡检参数错误：间隔分钟必须为整数")
            return

        if interval_minutes <= 0:
            self.auto_status_var.set("自动巡检参数错误：间隔分钟必须大于0")
            return

        self._auto_job = self.after(interval_minutes * 60 * 1000, self._run_scheduled_check_once)

    def start_auto_check(self):
        self.auto_enabled_var.set(True)
        self._save_config()
        self._schedule_next_auto_check()
        self._refresh_auto_toggle_button()
        self.auto_status_var.set(
            f"自动巡检已开启：每 {self.auto_interval_var.get()} 分钟执行一次，"
            f"允许扫描已关闭={'是' if self.auto_allow_closed_scan_var.get() else '否'}，"
            f"401处理={self.auto_401_action_var.get()}"
        )
        self._run_scheduled_check_once()

    def stop_auto_check(self):
        self.auto_enabled_var.set(False)
        if self._auto_job is not None:
            self.after_cancel(self._auto_job)
            self._auto_job = None
        self._save_config()
        self._refresh_auto_toggle_button()
        self.auto_status_var.set("自动巡检：已停止")

    def check_401(self):
        if not self._ensure_accounts_loaded("检测 401 失效"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        only_unknown = self._unknown_filter_selected()
        candidates = self._candidate_raw_items(rt, only_unknown=only_unknown)
        if not candidates:
            if only_unknown:
                messagebox.showinfo("检测 401 失效", "当前筛选为“未知”，没有符合条件（未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            else:
                messagebox.showinfo("检测 401 失效", "没有符合条件（活跃（含普通报错）/未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            return

        active_target_meta = self._build_active_target_meta()
        target_active = int(active_target_meta.get("target_active") or 0)
        current_active_before = int(active_target_meta.get("current_active") or 0)
        available_slots_before = int(active_target_meta.get("available_slots") or 0)
        available_slots_text = "不限" if active_target_meta.get("unlimited") else str(available_slots_before)

        self.action_progress.set(
            f"正在检测 401 失效... 候选={len(candidates)} | 目标={target_active} 当前活跃={current_active_before} 可开启名额={available_slots_text}"
        )

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
                write_json_file(rt["output"], invalid_401)
                self.after(0, self._check_401_done, results, rt["output"], active_target_meta)
            except Exception as e:
                self.after(0, messagebox.showerror, "401 检测失败", str(e))
                self.after(0, self.action_progress.set, "401 检测失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_401_done(self, results, output_path, active_target_meta=None):
        probe_by_identity, _probe_conflicts = self._index_results_by_identity(results)

        limit_meta = active_target_meta if isinstance(active_target_meta, dict) else self._build_active_target_meta()
        target_active = int(limit_meta.get("target_active") or 0)
        current_active_before = int(limit_meta.get("current_active") or 0)
        available_slots_before = int(limit_meta.get("available_slots") or 0)
        available_slots_text = "不限" if limit_meta.get("unlimited") else str(available_slots_before)

        invalid_count = 0
        error_count = 0
        for account in self.all_accounts:
            r = self._result_for_account(probe_by_identity, account)
            if not r:
                continue
            account["invalid_401"] = bool(r.get("invalid_401"))
            self._apply_scan_status(account, r.get("status_code"))
            account["check_error"] = r.get("error")
            if account["invalid_401"]:
                invalid_count += 1
            if r.get("error"):
                error_count += 1

        snapshot = self._record_active_quota_snapshot("401")

        rebalance_summary = None
        try:
            rt = self._runtime()
            rebalance_summary = self._rebalance_active_target_by_runtime(rt)
        except Exception as e:
            rebalance_summary = {"error": str(e)}

        self._load_accounts()
        self._apply_filter()
        self.action_progress.set(f"401 检测完成：无效={invalid_count} 异常={error_count}")
        msg_lines = [
            f"活跃目标门控：目标={target_active}，当前活跃={current_active_before}，可开启名额={available_slots_text}",
            f"401无效：{invalid_count}",
            f"检测异常：{error_count}",
        ]
        if snapshot.get("error"):
            msg_lines.append(f"记录失败：{snapshot.get('error')}")
        if rebalance_summary:
            if rebalance_summary.get("error"):
                msg_lines.append(f"活跃目标调整失败：{rebalance_summary.get('error')}")
            elif rebalance_summary.get("enforce_applied"):
                msg_lines.append(
                    f"活跃目标调整：转备用 {rebalance_summary.get('moved_to_standby_count')} 个，"
                    f"补齐 {rebalance_summary.get('enabled_count')} 个，"
                    f"调整后活跃 {rebalance_summary.get('active_after')} 个"
                )
            elif rebalance_summary.get("enforce_skipped"):
                msg_lines.append("活跃目标调整：已跳过（活跃账号目标数<=0 视为不限制）")
        messagebox.showinfo("401 检测完成", "\n".join(msg_lines))

    def check_quota(self):
        if not self._ensure_accounts_loaded("额度检测"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        only_unknown = self._unknown_filter_selected()
        candidates = self._quota_candidate_raw_items(rt, only_unknown=only_unknown)
        if not candidates:
            if only_unknown:
                messagebox.showinfo("额度检测", "当前筛选为“未知”，没有符合条件（未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            else:
                messagebox.showinfo("额度检测", "没有符合条件（活跃（含普通报错）/未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            return

        self.action_progress.set(f"正在检测额度状态... 候选={len(candidates)}")

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
                write_json_file(rt["quota_output"], invalid_quota)
                self.after(0, self._check_quota_done, results, rt["quota_output"])
            except Exception as e:
                self.after(0, messagebox.showerror, "额度检测失败", str(e))
                self.after(0, self.action_progress.set, "额度检测失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_quota_done(self, results, output_path):
        quota_by_identity, _quota_conflicts = self._index_results_by_identity(results)

        quota_count = 0
        error_count = 0
        for account in self.all_accounts:
            r = self._result_for_account(quota_by_identity, account)
            if not r:
                continue
            account["invalid_quota"] = bool(r.get("invalid_quota"))
            self._apply_scan_status(account, r.get("status_code"))
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

        snapshot = self._record_active_quota_snapshot("quota")

        rebalance_summary = None
        try:
            rt = self._runtime()
            rebalance_summary = self._rebalance_active_target_by_runtime(rt)
        except Exception as e:
            rebalance_summary = {"error": str(e)}

        self._load_accounts()
        self._apply_filter()
        self.action_progress.set(f"额度检测完成：额度耗尽={quota_count} 异常={error_count}")
        msg = f"额度耗尽: {quota_count}\n检测异常: {error_count}\n导出文件: {output_path}\n活跃额度记录: {snapshot.get('count', 0)} 条\n记录文件: {snapshot.get('path')}"
        if snapshot.get("error"):
            msg += f"\n记录失败: {snapshot.get('error')}"
        if rebalance_summary:
            if rebalance_summary.get("error"):
                msg += f"\n全局活跃目标平衡失败: {rebalance_summary.get('error')}"
            elif rebalance_summary.get("enforce_applied"):
                msg += (
                    f"\n活跃目标平衡: 目标={rebalance_summary.get('target_active')}"
                    f"，扫描后活跃={rebalance_summary.get('active_before')}"
                    f"，转备用={rebalance_summary.get('moved_to_standby_count')}"
                    f"，从池补齐={rebalance_summary.get('enabled_count')}"
                    f"，平衡后活跃={rebalance_summary.get('active_after')}"
                )
            elif rebalance_summary.get("enforce_skipped"):
                msg += "\n活跃目标平衡: 已跳过（活跃账号目标数<=0 视为不限制）"
        messagebox.showinfo("额度检测完成", msg)

    def check_both(self):
        if not self._ensure_accounts_loaded("联合检测（401+额度）"):
            return
        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return

        only_unknown = self._unknown_filter_selected()
        candidates = self._candidate_raw_items(rt, only_unknown=only_unknown)
        if not candidates:
            if only_unknown:
                messagebox.showinfo("联合检测（401+额度）", "当前筛选为“未知”，没有符合条件（未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            else:
                messagebox.showinfo("联合检测（401+额度）", "没有符合条件（活跃（含普通报错）/未知、未关闭、匹配 target_type/provider 且带 auth_index）的账号可检测。")
            return

        active_target_meta = self._build_active_target_meta()
        target_active = int(active_target_meta.get("target_active") or 0)
        current_active_before = int(active_target_meta.get("current_active") or 0)
        available_slots_before = int(active_target_meta.get("available_slots") or 0)
        available_slots_text = "不限" if active_target_meta.get("unlimited") else str(available_slots_before)

        self.action_progress.set(
            f"正在联合检测（401+额度）... 候选={len(candidates)} | 目标={target_active} 当前活跃={current_active_before} 可开启名额={available_slots_text}"
        )

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

                write_json_file(rt["output"], invalid_401)
                write_json_file(rt["quota_output"], invalid_quota)

                self.after(
                    0,
                    self._check_both_done,
                    probe_results,
                    quota_results,
                    rt["output"],
                    rt["quota_output"],
                    active_target_meta,
                )
            except Exception as e:
                self.after(0, messagebox.showerror, "联合检测（401+额度）失败", str(e))
                self.after(0, self.action_progress.set, "联合检测（401+额度）失败")

        threading.Thread(target=worker, daemon=True).start()

    def _check_both_done(self, probe_results, quota_results, output_path, quota_output_path, active_target_meta=None):
        probe_by_identity, _probe_conflicts = self._index_results_by_identity(probe_results)
        quota_by_identity, _quota_conflicts = self._index_results_by_identity(quota_results)

        limit_meta = active_target_meta if isinstance(active_target_meta, dict) else self._build_active_target_meta()
        target_active = int(limit_meta.get("target_active") or 0)
        current_active_before = int(limit_meta.get("current_active") or 0)
        available_slots_before = int(limit_meta.get("available_slots") or 0)
        available_slots_text = "不限" if limit_meta.get("unlimited") else str(available_slots_before)

        count_401 = 0
        count_quota = 0
        count_err = 0

        for account in self.all_accounts:
            p = self._result_for_account(probe_by_identity, account)
            q = self._result_for_account(quota_by_identity, account)

            if p:
                account["invalid_401"] = bool(p.get("invalid_401"))
                self._apply_scan_status(account, p.get("status_code"))
                if account["invalid_401"]:
                    count_401 += 1
                if p.get("error"):
                    count_err += 1

            if q:
                account["invalid_quota"] = bool(q.get("invalid_quota"))
                if not p:
                    self._apply_scan_status(account, q.get("status_code"))
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

        snapshot = self._record_active_quota_snapshot("both")

        rebalance_summary = None
        try:
            rt = self._runtime()
            rebalance_summary = self._rebalance_active_target_by_runtime(rt)
        except Exception as e:
            rebalance_summary = {"error": str(e)}

        self._load_accounts()
        self._apply_filter()
        self.action_progress.set(f"联合检测（401+额度）完成：401={count_401} 额度耗尽={count_quota}")
        msg_lines = [
            f"活跃目标门控：目标={target_active}，当前活跃={current_active_before}，可开启名额={available_slots_text}",
            f"401无效：{count_401}",
            f"额度耗尽：{count_quota}",
            f"检测异常：{count_err}",
        ]
        if snapshot.get("error"):
            msg_lines.append(f"记录失败：{snapshot.get('error')}")
        if rebalance_summary:
            if rebalance_summary.get("error"):
                msg_lines.append(f"活跃目标调整失败：{rebalance_summary.get('error')}")
            elif rebalance_summary.get("enforce_applied"):
                msg_lines.append(
                    f"活跃目标调整：转备用 {rebalance_summary.get('moved_to_standby_count')} 个，"
                    f"补齐 {rebalance_summary.get('enabled_count')} 个，"
                    f"调整后活跃 {rebalance_summary.get('active_after')} 个"
                )
            elif rebalance_summary.get("enforce_skipped"):
                msg_lines.append("活跃目标调整：已跳过（活跃账号目标数<=0 视为不限制）")
        messagebox.showinfo("联合检测（401+额度）完成", "\n".join(msg_lines))

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

        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            self.action_progress.set("关闭失败")
            return

        def worker():
            try:
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
            # 备用池账号由“备用转活跃”流程单独处理，这里只恢复普通已关闭账号
            if account.get("standby"):
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
                f"将检测 {len(candidates)} 个已关闭账号的额度与状态（含401/其他错误）。\n"
                "仅当状态正常且不满足“额度耗尽”条件时，才会自动开启这些账号。\n\n"
                "继续吗？"
            ),
        ):
            return

        active_target_meta = self._build_active_target_meta()
        target_active = int(active_target_meta.get("target_active") or 0)
        current_active_before = int(active_target_meta.get("current_active") or 0)
        available_slots_before = int(active_target_meta.get("available_slots") or 0)
        available_slots_text = "不限" if active_target_meta.get("unlimited") else str(available_slots_before)
        gap_rescan_summary = None
        if (not active_target_meta.get("unlimited")) and available_slots_before <= 0:
            self.action_progress.set("当前差值=0，先复扫活跃账号以校准缺口...")
            gap_rescan_summary = self._rescan_active_and_refresh_gap(rt, target_active, current_active_before)
            current_active_before = int(gap_rescan_summary.get("active_after") or current_active_before)
            available_slots_before = int(gap_rescan_summary.get("available_slots_after") or 0)
            available_slots_text = str(available_slots_before)
            if available_slots_before <= 0:
                extra_lines = [
                    f"活跃复扫：扫描={int(gap_rescan_summary.get('scanned') or 0)}",
                    f"发现401={int(gap_rescan_summary.get('invalid_401') or 0)}",
                    f"发现额度耗尽={int(gap_rescan_summary.get('invalid_quota') or 0)}",
                ]
                if gap_rescan_summary.get("errors"):
                    extra_lines.append("复扫异常: " + " | ".join((gap_rescan_summary.get("errors") or [])[:3]))
                self.action_progress.set("恢复已关闭已跳过：复扫后可开启名额仍为0")
                messagebox.showinfo(
                    "恢复已关闭",
                    (
                        f"复扫后仍无可开启名额（目标={target_active}，当前活跃={current_active_before}）。\n"
                        "本次不会从已关闭账号补齐。\n\n"
                        + "\n".join(extra_lines)
                    ),
                )
                return

        scan_need_count = None if active_target_meta.get("unlimited") else max(0, available_slots_before)
        scan_need_text = "全量扫描" if scan_need_count is None else f"按缺口扫描，最多补齐 {scan_need_count} 个"

        self.action_progress.set(
            f"正在检测已关闭账号额度与状态... 候选={len(candidates)} | 目标={target_active} 当前活跃={current_active_before} 可开启名额={available_slots_text} | {scan_need_text}"
        )

        def worker():
            try:
                scan_summary = self._scan_for_recovery(rt, candidates, need_count=scan_need_count)
                probe_by_identity = scan_summary.get("probe_by_name") or {}
                quota_by_identity = scan_summary.get("quota_by_name") or {}
                probe_results = list(probe_by_identity.values())
                quota_results = list(quota_by_identity.values())

                recoverable_names = list(scan_summary.get("recoverable") or [])
                limit_meta = self._pick_names_with_active_target_limit(recoverable_names)
                if isinstance(limit_meta, dict):
                    limit_meta = dict(limit_meta)
                    limit_meta["scanned"] = int(scan_summary.get("scanned") or 0)
                    limit_meta["recoverable_detected"] = len(recoverable_names)
                    limit_meta["scan_need_count"] = scan_need_count
                    limit_meta["scan_errors"] = list(scan_summary.get("errors") or [])
                    limit_meta["gap_rescan_summary"] = gap_rescan_summary or {}
                names_to_enable = list(limit_meta.get("selected") or [])

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

                self.after(0, self._recover_closed_done, candidates, probe_results, quota_results, enable_results, limit_meta)
            except Exception as e:
                self.after(0, messagebox.showerror, "恢复失败", str(e))
                self.after(0, self.action_progress.set, "恢复失败")

        threading.Thread(target=worker, daemon=True).start()

    def _recover_closed_done(self, candidate_raws, probe_results, quota_results, enable_results, limit_meta=None):
        probe_by_identity, _probe_conflicts = self._index_results_by_identity(probe_results)
        quota_by_identity, _quota_conflicts = self._index_results_by_identity(quota_results)

        selected_for_enable_names = []
        if isinstance(limit_meta, dict):
            selected_for_enable_names = [n for n in (limit_meta.get("selected") or []) if n]

        selected_for_enable_set = set(selected_for_enable_names)
        selected_for_enable_keys = self._pick_identity_keys_for_names(candidate_raws, selected_for_enable_names)
        enabled_names = [r.get("name") for r in enable_results if r.get("updated") and r.get("name")]
        failed_enable_names = [r.get("name") for r in enable_results if (not r.get("updated")) and r.get("name")]
        enable_success_keys = self._pick_identity_keys_for_names(candidate_raws, enabled_names)
        enable_failed_keys = self._pick_identity_keys_for_names(candidate_raws, failed_enable_names)
        enable_by_name = {r.get("name"): r for r in enable_results if r.get("name")}

        limit_data = limit_meta if isinstance(limit_meta, dict) else self._build_active_target_meta()
        target_active = int(limit_data.get("target_active") or 0)
        current_active_before = int(limit_data.get("current_active") or 0)
        available_slots_before = int(limit_data.get("available_slots") or 0)
        available_slots_text = "不限" if limit_data.get("unlimited") else str(available_slots_before)
        scanned_count = int(limit_data.get("scanned") or 0) if isinstance(limit_data, dict) else 0
        scan_need_count = limit_data.get("scan_need_count") if isinstance(limit_data, dict) else None
        scan_errors_extra = list(limit_data.get("scan_errors") or []) if isinstance(limit_data, dict) else []
        gap_rescan_summary = (limit_data.get("gap_rescan_summary") or {}) if isinstance(limit_data, dict) else {}

        checked = scanned_count if scanned_count > 0 else max(len(probe_results), len(quota_results))
        recoverable = 0
        enabled_ok = 0
        enabled_fail = 0
        detect_errors = 0
        invalid_401_count = 0
        other_status_count = 0
        overflow_to_standby_names = set()
        standby_save_error = None

        for account in self.all_accounts:
            account_key = self._account_identity_key(account)
            name = str(account.get("name") or "").strip()
            p = self._result_for_account(probe_by_identity, account)
            q = self._result_for_account(quota_by_identity, account)
            recoverable_by_scan = False

            if p:
                account["invalid_401"] = bool(p.get("invalid_401"))
                p_status = p.get("status_code")
                if account["invalid_401"]:
                    invalid_401_count += 1
                elif p_status is not None and p_status != 200:
                    other_status_count += 1
                if p.get("error"):
                    detect_errors += 1

            if q:
                account["invalid_quota"] = bool(q.get("invalid_quota"))
                account["used_percent"] = q.get("used_percent")
                account["primary_used_percent"] = q.get("primary_used_percent")
                account["primary_reset_at"] = q.get("primary_reset_at")
                account["individual_used_percent"] = q.get("individual_used_percent")
                account["individual_reset_at"] = q.get("individual_reset_at")
                account["quota_source"] = q.get("quota_source")
                account["reset_at"] = q.get("reset_at")
                if q.get("error"):
                    detect_errors += 1

                p_ok = bool(
                    p
                    and p.get("status_code") == 200
                    and not p.get("invalid_401")
                    and not p.get("error")
                )
                if p_ok and q.get("status_code") == 200 and not q.get("invalid_quota") and not q.get("error"):
                    recoverable_by_scan = True
                    recoverable += 1

            if q and q.get("error"):
                account["check_error"] = q.get("error")
            elif p and p.get("error"):
                account["check_error"] = p.get("error")
            elif p and p.get("status_code") not in (None, 200):
                account["check_error"] = f"api status_code={p.get('status_code')}"
            elif q and q.get("status_code") not in (None, 200):
                account["check_error"] = f"quota status_code={q.get('status_code')}"
            elif p or q:
                account["check_error"] = None

            e = enable_by_name.get(name)
            selected_for_enable = (
                (account_key in selected_for_enable_keys) if selected_for_enable_keys else (name in selected_for_enable_set)
            )
            enabled_ok_for_account = (
                (account_key in enable_success_keys) if enable_success_keys else bool(e and e.get("updated"))
            )
            marked_failed = (
                (account_key in enable_failed_keys) if enable_failed_keys else bool(e and not e.get("updated"))
            )

            if enabled_ok_for_account:
                account["standby"] = False
                account["disabled"] = False
                if account.get("raw"):
                    account["raw"]["disabled"] = False
                enabled_ok += 1
            elif selected_for_enable and marked_failed:
                account["standby"] = False
                enabled_fail += 1
                if e:
                    account["check_error"] = e.get("error") or account.get("check_error")
            elif recoverable_by_scan and (not selected_for_enable):
                # 本轮已扫出可用，但因活跃目标数限制未开启：转入备用池，避免浪费扫描结果
                if name:
                    overflow_to_standby_names.add(name)
                    self.standby_names.add(name)
                account["standby"] = True
                account["disabled"] = True
                if account.get("raw"):
                    account["raw"]["disabled"] = True
                account["check_error"] = None
            elif p or q:
                account["standby"] = False

        if overflow_to_standby_names:
            try:
                self._save_standby_names_to_file()
            except Exception as e:
                standby_save_error = str(e)

        self._apply_filter()
        self.action_progress.set(
            f"恢复流程完成：开启成功={enabled_ok} 失败={enabled_fail} 转备用={len(overflow_to_standby_names)}"
        )

        skipped_by_target = 0
        if isinstance(limit_meta, dict):
            skipped_keys = limit_meta.get("skipped_keys") or set()
            if skipped_keys:
                skipped_by_target = len(skipped_keys)
            else:
                skipped_by_target = len(limit_meta.get("skipped") or [])
        skipped_by_target = max(skipped_by_target, len(overflow_to_standby_names))

        recoverable_count = recoverable
        enabled_count = enabled_ok

        msg_lines = [
            f"活跃目标门控：目标={target_active}，当前活跃={current_active_before}，可开启名额={available_slots_text}",
            f"已关闭账号检测数：{checked}",
            f"符合开启条件：{recoverable_count}",
            f"开启成功：{enabled_count}",
            f"401无效：{invalid_401_count}",
            f"其他状态异常：{other_status_count}",
        ]
        if gap_rescan_summary.get("rescanned"):
            msg_lines.insert(
                1,
                (
                    f"缺口校准复扫：扫描={int(gap_rescan_summary.get('scanned') or 0)} "
                    f"401={int(gap_rescan_summary.get('invalid_401') or 0)} "
                    f"额度={int(gap_rescan_summary.get('invalid_quota') or 0)}"
                ),
            )
            detect_errors += len(gap_rescan_summary.get("errors") or [])
        if scan_need_count is not None:
            msg_lines.insert(1, f"本轮扫描目标补齐数：{int(scan_need_count)}")
        if scanned_count > 0:
            msg_lines.insert(2, f"本轮实际扫描：{scanned_count}")
        if scan_errors_extra:
            detect_errors += len(scan_errors_extra)
        if enabled_fail > 0:
            msg_lines.append(f"开启失败：{enabled_fail}")
        if detect_errors > 0:
            msg_lines.append(f"检测异常：{detect_errors}")
        if skipped_by_target > 0:
            msg_lines.append(f"受全局活跃目标数限制未开启：{skipped_by_target}")
        if overflow_to_standby_names:
            msg_lines.append(f"本轮可用但超出目标的账号已转入备用池：{len(overflow_to_standby_names)}")
        if standby_save_error:
            msg_lines.append(f"备用池保存失败：{standby_save_error}")

        messagebox.showinfo("恢复已关闭结果", "\n".join(msg_lines))

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

        try:
            rt = self._runtime()
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            self.action_progress.set("删除失败")
            return

        def worker():
            try:
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
    parser = argparse.ArgumentParser(description="CliproxyAccountCleaner")
    parser.add_argument("--desktop", action="store_true", help="使用桌面模式(Tkinter)")
    parser.add_argument("--host", default="127.0.0.1", help="网页模式监听地址")
    parser.add_argument("--port", type=int, default=8765, help="网页模式端口")
    parser.add_argument("--no-browser", action="store_true", help="网页模式启动时不自动打开浏览器")
    args = parser.parse_args()

    if args.desktop:
        if tk is None:
            raise RuntimeError("当前环境缺少 tkinter，无法启动桌面模式。请改用网页模式或安装 Tk 运行时。")
        conf = load_config(CONFIG_PATH)
        app = EnhancedUI(conf, CONFIG_PATH)
        app.mainloop()
        return

    from cliproxy_web_mode import run_web_mode
    run_web_mode(host=args.host, port=args.port, no_browser=args.no_browser, ns=globals())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[启动失败] {e}", file=sys.stderr)
        raise
