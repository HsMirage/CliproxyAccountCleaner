#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI版本账号清理工具 - 适用于无桌面环境的服务器
支持批量管理数千个账号
"""

import os
import sys
import json
import asyncio
import time
import threading
import urllib.parse
import aiohttp

try:
    import msvcrt
except Exception:
    msvcrt = None

HERE = os.path.abspath(os.path.dirname(__file__))

# 默认配置
DEFAULT_CONFIG = {
    "base_url": "http://127.0.0.1:8317",
    "cpa_password": "",
    "target_type": "codex",
    "workers": 100,
    "quota_workers": 100,
    "delete_workers": 20,
    "timeout": 10,
    "retries": 1,
    "quota_threshold": 99,
    "weekly_quota_threshold": 99,
    "primary_quota_threshold": 99,
    "auto_enabled": False,
    "auto_interval_minutes": 30,
    "auto_action_401": "删除",
    "auto_action_quota": "关闭",
    "auto_keep_active_count": 0,
    "auto_allow_scan_closed": False,
    "standby_output": "standby_accounts.json",
}

LIMIT_KEYWORDS = (
    "usage_limit_reached",
    "insufficient_quota",
    "quota_exceeded",
    "limit_reached",
    "rate limit",
)

LAST_PROGRESS_LINE_LENGTH = 0


import re

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def format_ts(ts):
    if not ts:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return "-"


def spinner_char():
    """返回一个随时间变化的字符，用于提示界面仍在持续刷新。"""
    frames = "│╱─╲"
    return frames[int(time.time() * 5) % len(frames)]



def colorize_status(text, color_code="96"):
    """为关键状态文本添加 ANSI 颜色，提升 CLI 中的可见性。"""
    return f"\033[{color_code}m{text}\033[0m"



def colorize_auto_flag(flag):
    """为自动巡检相关布尔状态着色。"""
    return colorize_status("是", "96") if flag else colorize_status("否", "93")



def colorize_auto_state_text(message):
    """为自动巡检状态文案着色。"""
    text = str(message or "")
    if any(keyword in text for keyword in ("运行中", "正在执行", "已启动", "已启用")):
        return colorize_status(text, "96")
    if any(keyword in text for keyword in ("失败", "错误", "已停止")):
        return colorize_status(text, "91")
    if any(keyword in text for keyword in ("未启动", "未启用", "等待", "无需")):
        return colorize_status(text, "93")
    return text


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")



def visible_text_length(text):
    """计算去掉 ANSI 转义码后的可见长度，避免进度行清理残留。"""
    return len(ANSI_ESCAPE_RE.sub("", str(text or "")))



def colorize_progress_stat(key, value):
    """仅为进度行中的状态型字段着色，避免整行过度花哨。"""
    key_text = str(key)
    value_text = str(value)

    if key_text in ("成功",):
        return colorize_status(key_text, "92"), colorize_status(value_text, "92")
    if key_text in ("失败", "异常"):
        color_code = "91" if str(value_text) != "0" else "92"
        return colorize_status(key_text, color_code), colorize_status(value_text, color_code)
    if key_text in ("401无效", "额度耗尽"):
        color_code = "91" if str(value_text) != "0" else "92"
        return colorize_status(key_text, color_code), colorize_status(value_text, color_code)
    return key_text, value_text


def create_auto_state():
    return {
        "enabled": False,
        "running": False,
        "last_run_at": None,
        "last_error": None,
        "last_summary": {},
        "interval_minutes": DEFAULT_CONFIG["auto_interval_minutes"],
        "next_run_at": None,
        "loop_started_at": None,
        "cycle_count": 0,
        "message": "未启动",
    }


def snapshot_auto_state(auto_state, auto_lock):
    with auto_lock:
        return dict(auto_state)


def set_auto_state(auto_state, auto_lock, **kwargs):
    with auto_lock:
        auto_state.update(kwargs)



def is_auto_patrol_enabled(auto_state, auto_lock):
    """是否仍将自动巡检视为已启用。"""
    return bool(snapshot_auto_state(auto_state, auto_lock).get("enabled"))



def is_auto_patrol_thread_alive(auto_runtime):
    """后台巡检线程是否仍在存活，用于处理停止中的过渡态。"""
    thread = auto_runtime.get("thread")
    return bool(thread and thread.is_alive())


def build_auto_status_lines(auto_state):
    enabled = bool(auto_state.get("enabled"))
    running = bool(auto_state.get("running"))
    next_run_at = auto_state.get("next_run_at")
    countdown = "-"
    heartbeat = spinner_char()
    interval_minutes = auto_state.get("interval_minutes") or DEFAULT_CONFIG["auto_interval_minutes"]
    if enabled and next_run_at:
        countdown = str(max(0, int(next_run_at - time.time()))) + " 秒"

    summary = auto_state.get("last_summary") or {}
    message = auto_state.get("message") or "-"
    if message != "-":
        message = f"{message} {heartbeat}"
    message = colorize_auto_state_text(message)

    return [
        "🤖 自动巡检状态",
        f"  - 已启用: {colorize_auto_flag(enabled)}",
        f"  - 巡检间隔: {interval_minutes} 分钟",
        f"  - 上次巡检: {format_ts(auto_state.get('last_run_at'))}",
        f"  - 上次结果: 401={summary.get('invalid_401_count', 0)} 额度={summary.get('invalid_quota_count', 0)} 删除={summary.get('deleted_count', 0)} 关闭={summary.get('closed_count', 0)} 失败={colorize_status(str(summary.get('error_count', 0)), '91') if summary.get('error_count', 0) else colorize_status('0', '92')}",
        f"  - 活跃目标: 目标={summary.get('target_active', 0)} 巡检前={summary.get('active_before', 0)} 巡检后={summary.get('active_after', 0)}",
        f"  - 补位动作: 转备用={summary.get('moved_to_standby_count', 0)} 备用补齐={summary.get('enabled_from_standby_count', 0)} 已关闭补齐={summary.get('enabled_from_closed_count', 0)}",
        f"  - 下次巡检: {format_ts(next_run_at)}",
        f"  - 倒计时: {countdown}",
        f"  - 正在执行: {colorize_auto_flag(running)}",
        f"    {message}",
    ]


async def show_loading(message):
    """显示loading动画"""
    chars = "│╱─╲"
    idx = 0
    try:
        while True:
            sys.stdout.write(f"\r{message} {chars[idx % len(chars)]}")
            sys.stdout.flush()
            idx += 1
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        sys.stdout.write(f"\r{' ' * (len(message) + 2)}\r")
        sys.stdout.flush()


def render_progress_line(label, total, completed, **stats):
    """输出单行进度，便于手动操作时观察当前阶段与完成数。"""
    global LAST_PROGRESS_LINE_LENGTH
    parts = [f"{label}: 候选={total} 已完成={completed}/{total}"]
    for key, value in stats.items():
        colored_key, colored_value = colorize_progress_stat(key, value)
        parts.append(f"{colored_key}={colored_value}")
    line = " | ".join(parts)
    # 进度行可能包含 ANSI 颜色码，这里按可见长度补空格，避免旧字符残留。
    visible_len = visible_text_length(line)
    padding = max(0, LAST_PROGRESS_LINE_LENGTH - visible_len)
    sys.stdout.write("\r" + line + (" " * padding))
    sys.stdout.flush()
    LAST_PROGRESS_LINE_LENGTH = visible_len


def clear_progress_line():
    """清除上一条单行进度，避免残留字符污染后续输出。"""
    global LAST_PROGRESS_LINE_LENGTH
    if LAST_PROGRESS_LINE_LENGTH > 0:
        sys.stdout.write("\r" + (" " * LAST_PROGRESS_LINE_LENGTH) + "\r")
        sys.stdout.flush()
        LAST_PROGRESS_LINE_LENGTH = 0


class UserCancelledError(Exception):
    """用户主动取消当前长流程，并退回上一级菜单。"""



def manual_cancel_requested(cancel_key="q"):
    """轮询键盘输入，允许在长流程执行中即时取消。"""
    if msvcrt is None:
        return False

    while msvcrt.kbhit():
        key = msvcrt.getwch()
        if key and key.lower() == cancel_key:
            return True
    return False


async def cancel_pending_tasks(pending):
    """取消并回收尚未完成的任务，避免后台残留协程继续输出。"""
    if not pending:
        return
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)


async def process_tasks_with_progress(tasks, on_result, cancel_message=None):
    """按批消费异步任务，支持进度回调和用户手动取消。"""
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
        if cancel_message and manual_cancel_requested():
            await cancel_pending_tasks(pending | done)
            raise UserCancelledError(cancel_message)
        if not done:
            continue
        for task in done:
            on_result(await task)


def load_config():
    """加载配置文件"""
    config_path = os.path.join(HERE, "config.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG


def standby_output_path(config):
    path = str(config.get("standby_output") or DEFAULT_CONFIG["standby_output"] or "").strip()
    if not path:
        path = DEFAULT_CONFIG["standby_output"]
    if os.path.isabs(path):
        return path
    return os.path.join(HERE, path)


def load_standby_entries(config):
    path = standby_output_path(config)
    if not os.path.exists(path):
        legacy = config.get("standby_accounts") or []
        if isinstance(legacy, list):
            return list(legacy)
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def standby_entry_name(item):
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


def standby_entry_keys(item):
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


def resolve_standby_names_for_files(config, auth_files):
    standby_entries = load_standby_entries(config)
    if not standby_entries:
        return set()

    standby_lookup = set()
    for item in standby_entries:
        standby_lookup.update(standby_entry_keys(item))
    if not standby_lookup:
        return set()

    resolved = set()
    for item in (auth_files or []):
        name = str((item or {}).get("name") or "").strip()
        if not name:
            continue
        if standby_entry_keys(item) & standby_lookup:
            resolved.add(name)
    return resolved


def load_standby_names(config):
    names = set()
    for item in load_standby_entries(config):
        name = standby_entry_name(item)
        if name:
            names.add(name)
    return names


def save_standby_names(config, standby_names):
    path = standby_output_path(config)
    os.makedirs(os.path.dirname(path) or HERE, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sorted({str(item).strip() for item in (standby_names or set()) if str(item).strip()}), f, ensure_ascii=False, indent=2)


def mgmt_headers(token):
    """管理端请求头"""
    return {"Authorization": f"Bearer {token}"}


def safe_json_text(text):
    """安全解析JSON"""
    try:
        return json.loads(text)
    except:
        return None


def extract_chatgpt_account_id(item):
    """兼容多种账号ID字段，和 GUI 版保持一致。"""
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return val

    id_token = item.get("id_token") or {}
    if isinstance(id_token, dict):
        for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
            val = id_token.get(key)
            if val:
                return val
    return None


def build_usage_payload(auth_index, chatgpt_account_id=None):
    """统一 usage 探测 payload，避免 401/额度检测协议漂移。"""
    payload = {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": {
            "Authorization": "Bearer $TOKEN$",
            "Content-Type": "application/json",
            "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
        },
    }
    if chatgpt_account_id:
        payload["header"]["Chatgpt-Account-Id"] = chatgpt_account_id
    return payload


def is_detection_candidate(item, target_type, allow_disabled=False):
    """对齐 GUI 版：检测未关闭的目标类型账号，而不是只看 active。"""
    if item.get("type") != target_type:
        return False
    if (not allow_disabled) and item.get("disabled"):
        return False
    return bool(item.get("auth_index"))


def parse_percent(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip().rstrip("%")
        if text == "":
            return None
        return float(text)
    except Exception:
        return None


def pick_first_val(d, *keys):
    if not isinstance(d, dict):
        return None
    for key in keys:
        if d.get(key) is not None:
            return d.get(key)
    return None


def parse_window(name, window):
    if not isinstance(window, dict):
        return None
    return {
        "name": name,
        "used_percent": parse_percent(pick_first_val(window, "used_percent", "usedPercent", "used_percentage")),
        "limit_window_seconds": pick_first_val(
            window,
            "limit_window_seconds",
            "limitWindowSeconds",
            "window_seconds",
            "windowSeconds",
        ),
        "remaining": pick_first_val(window, "remaining"),
        "limit_reached": pick_first_val(window, "limit_reached", "limitReached"),
    }


def select_quota_windows(windows):
    """Pick weekly and short windows from wham/usage payloads.

    Current observed Codex payloads use:
    - primary_window: short window (about 5h)
    - secondary_window: long window (about weekly)
    - individual_window: sometimes also represents the long window
    """
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

    with_seconds = [w for w in windows if is_seconds(w.get("limit_window_seconds"))]

    if short_window is None and with_seconds:
        short_window = min(with_seconds, key=lambda x: x["limit_window_seconds"])

    if weekly_window is None and with_seconds:
        sorted_windows = sorted(with_seconds, key=lambda x: x["limit_window_seconds"], reverse=True)
        for window in sorted_windows:
            if short_window is None or window.get("name") != short_window.get("name"):
                weekly_window = window
                break

    if weekly_window is None and windows:
        for window in windows:
            if short_window is None or window.get("name") != short_window.get("name"):
                weekly_window = window
                break

    if short_window is None and windows:
        for window in windows:
            if weekly_window is None or window.get("name") != weekly_window.get("name"):
                short_window = window
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


def _contains_limit_error(value):
    """判断是否包含额度耗尽信号"""
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


async def fetch_auth_files(base_url, token, timeout):
    """获取所有认证文件列表"""
    url = f"{base_url}/v0/management/auth-files"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=mgmt_headers(token), timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("files", [])
    except Exception as e:
        print(f"获取账号列表失败: {e}")
    return []


async def check_401_batch(base_url, token, items, workers, timeout, target_type, allow_disabled=False, progress_label=None):
    """批量检测401错误"""
    results = []

    async def check_one(session, sem, item):
        async with sem:
            name = item.get("name", "")
            auth_index = item.get("auth_index", "")
            result = {"name": name, "invalid_401": False, "status_code": None, "error": None}

            if not auth_index:
                result["error"] = "missing auth_index"
                return result

            # 对齐 GUI 版的账号ID提取与 payload 构造逻辑，避免部分账号误判。
            chatgpt_account_id = extract_chatgpt_account_id(item)
            payload = build_usage_payload(auth_index, chatgpt_account_id)

            try:
                async with session.post(
                    f"{base_url}/v0/management/api-call",
                    headers={**mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        result["error"] = f"api-call http {resp.status}"
                        return result

                    data = safe_json_text(text)
                    if data:
                        status_code = data.get("status_code")
                        result["status_code"] = status_code
                        result["invalid_401"] = status_code == 401
                    else:
                        result["error"] = "invalid response"

            except Exception as e:
                result["error"] = str(e)

            return result

    filtered = [item for item in items if is_detection_candidate(item, target_type, allow_disabled=allow_disabled)]
    total = len(filtered)
    progress_title = progress_label if (not progress_label or msvcrt is None) else f"{progress_label}(按Q取消)"
    if progress_title and total > 0:
        render_progress_line(progress_title, total, 0, **{"401无效": 0, "异常": 0})

    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(workers)
        tasks = [asyncio.create_task(check_one(session, sem, item)) for item in filtered]
        completed = 0
        invalid_count = 0
        error_count = 0

        def handle_result(result):
            nonlocal completed, invalid_count, error_count
            results.append(result)
            completed += 1
            if result.get("invalid_401"):
                invalid_count += 1
            if result.get("error"):
                error_count += 1
            if progress_title:
                render_progress_line(progress_title, total, completed, **{"401无效": invalid_count, "异常": error_count})

        try:
            await process_tasks_with_progress(tasks, handle_result, cancel_message="已取消401检测，返回主菜单")
        finally:
            if progress_title and total > 0:
                clear_progress_line()
                sys.stdout.write("\n")
                sys.stdout.flush()

    return results


async def check_quota_batch(base_url, token, items, workers, timeout, target_type, weekly_quota_threshold, primary_quota_threshold, allow_disabled=False, progress_label=None):
    """批量检测额度"""
    results = []

    async def check_one(session, sem, item):
        async with sem:
            name = item.get("name", "")
            auth_index = item.get("auth_index", "")
            result = {"name": name, "invalid_quota": False, "status_code": None, "used_percent": None, "error": None}

            if not auth_index:
                result["error"] = "missing auth_index"
                return result

            # 对齐 GUI 版的账号ID提取与 payload 构造逻辑，避免部分账号误判。
            chatgpt_account_id = extract_chatgpt_account_id(item)
            payload = build_usage_payload(auth_index, chatgpt_account_id)

            try:
                async with session.post(
                    f"{base_url}/v0/management/api-call",
                    headers={**mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        result["error"] = f"api-call http {resp.status}"
                        return result

                    data = safe_json_text(text)
                    if not data:
                        result["error"] = "invalid response"
                        return result

                    status_code = data.get("status_code")
                    result["status_code"] = status_code
                    if status_code == 200:
                        body = data.get("body", "")
                        usage_data = safe_json_text(body) if isinstance(body, str) else body

                        if isinstance(usage_data, dict):
                            rate_limit = usage_data.get("rate_limit") or usage_data.get("rateLimit") or {}

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
                            short_used_percent = short_window.get("used_percent") if short_window else None

                            if weekly_used_percent is not None:
                                result["used_percent"] = weekly_used_percent
                                result["invalid_quota"] = weekly_used_percent >= weekly_quota_threshold
                            elif short_used_percent is not None:
                                result["used_percent"] = short_used_percent
                                result["invalid_quota"] = short_used_percent >= primary_quota_threshold

                            if not result["invalid_quota"]:
                                remaining_zero = any(window.get("remaining") == 0 for window in windows)
                                weekly_limit_reached = bool(weekly_window and weekly_window.get("limit_reached") is True)
                                short_limit_reached = bool(short_window and short_window.get("limit_reached") is True)
                                rate_limit_reached = pick_first_val(rate_limit, "limit_reached", "limitReached") is True

                                if weekly_limit_reached or short_limit_reached or remaining_zero or rate_limit_reached:
                                    result["used_percent"] = 100
                                    result["invalid_quota"] = True

                    elif _contains_limit_error(data) or _contains_limit_error(text):
                        result["used_percent"] = 100
                        result["invalid_quota"] = True

            except Exception as e:
                if _contains_limit_error(str(e)):
                    result["used_percent"] = 100
                    result["invalid_quota"] = True
                else:
                    result["error"] = str(e)

            return result

    filtered = [item for item in items if is_detection_candidate(item, target_type, allow_disabled=allow_disabled)]
    total = len(filtered)
    progress_title = progress_label if (not progress_label or msvcrt is None) else f"{progress_label}(按Q取消)"
    if progress_title and total > 0:
        render_progress_line(progress_title, total, 0, **{"额度耗尽": 0, "异常": 0})

    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(workers)
        tasks = [asyncio.create_task(check_one(session, sem, item)) for item in filtered]
        completed = 0
        invalid_count = 0
        error_count = 0

        def handle_result(result):
            nonlocal completed, invalid_count, error_count
            results.append(result)
            completed += 1
            if result.get("invalid_quota"):
                invalid_count += 1
            if result.get("error"):
                error_count += 1
            if progress_title:
                render_progress_line(progress_title, total, completed, **{"额度耗尽": invalid_count, "异常": error_count})

        try:
            await process_tasks_with_progress(tasks, handle_result, cancel_message="已取消额度检测，返回主菜单")
        finally:
            if progress_title and total > 0:
                clear_progress_line()
                sys.stdout.write("\n")
                sys.stdout.flush()

    return results


async def delete_accounts(base_url, token, names, workers, timeout, progress_label=None):
    """批量删除账号"""
    results = []

    async def delete_one(session, sem, name):
        async with sem:
            try:
                encoded_name = urllib.parse.quote(str(name), safe="")
                url = f"{base_url}/v0/management/auth-files?name={encoded_name}"
                async with session.delete(url, headers=mgmt_headers(token), timeout=timeout) as resp:
                    text = await resp.text()
                    data = safe_json_text(text) or {}
                    success = resp.status == 200 and data.get("status") == "ok"
                    return {"name": name, "success": success, "status": resp.status}
            except Exception as e:
                return {"name": name, "success": False, "error": str(e)}

    total = len(names)
    progress_title = progress_label if (not progress_label or msvcrt is None) else f"{progress_label}(按Q取消)"
    if progress_title and total > 0:
        render_progress_line(progress_title, total, 0, **{"成功": 0, "失败": 0})

    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(workers)
        tasks = [asyncio.create_task(delete_one(session, sem, name)) for name in names]
        completed = 0
        success_count = 0
        failed_count = 0

        def handle_result(result):
            nonlocal completed, success_count, failed_count
            results.append(result)
            completed += 1
            if result.get("success"):
                success_count += 1
            else:
                failed_count += 1
            if progress_title:
                render_progress_line(progress_title, total, completed, **{"成功": success_count, "失败": failed_count})

        try:
            await process_tasks_with_progress(tasks, handle_result, cancel_message="已取消删除操作，返回主菜单")
        finally:
            if progress_title and total > 0:
                clear_progress_line()
                sys.stdout.write("\n")
                sys.stdout.flush()

    return results


async def close_accounts(base_url, token, names, workers, timeout, progress_label=None):
    """批量关闭账号"""
    results = []

    async def close_one(session, sem, name):
        async with sem:
            try:
                url = f"{base_url}/v0/management/auth-files/status"
                # 对齐 GUI 版接口：通过 disabled=true 关闭单个账号。
                payload = {"name": name, "disabled": True}
                async with session.patch(url, headers=mgmt_headers(token), json=payload, timeout=timeout) as resp:
                    text = await resp.text()
                    data = safe_json_text(text) or {}
                    success = resp.status == 200 and data.get("status") == "ok"
                    return {"name": name, "success": success, "status": resp.status}
            except Exception as e:
                return {"name": name, "success": False, "error": str(e)}

    total = len(names)
    progress_title = progress_label if (not progress_label or msvcrt is None) else f"{progress_label}(按Q取消)"
    if progress_title and total > 0:
        render_progress_line(progress_title, total, 0, **{"成功": 0, "失败": 0})

    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(workers)
        tasks = [asyncio.create_task(close_one(session, sem, name)) for name in names]
        completed = 0
        success_count = 0
        failed_count = 0

        def handle_result(result):
            nonlocal completed, success_count, failed_count
            results.append(result)
            completed += 1
            if result.get("success"):
                success_count += 1
            else:
                failed_count += 1
            if progress_title:
                render_progress_line(progress_title, total, completed, **{"成功": success_count, "失败": failed_count})

        try:
            await process_tasks_with_progress(tasks, handle_result, cancel_message="已取消关闭操作，返回主菜单")
        finally:
            if progress_title and total > 0:
                clear_progress_line()
                sys.stdout.write("\n")
                sys.stdout.flush()

    return results


async def enable_accounts(base_url, token, names, workers, timeout):
    """批量启用账号，对齐 GUI 版接口：disabled=false。"""
    results = []

    async def enable_one(session, sem, name):
        async with sem:
            try:
                url = f"{base_url}/v0/management/auth-files/status"
                payload = {"name": name, "disabled": False}
                async with session.patch(url, headers=mgmt_headers(token), json=payload, timeout=timeout) as resp:
                    text = await resp.text()
                    data = safe_json_text(text) or {}
                    success = resp.status == 200 and data.get("status") == "ok"
                    return {"name": name, "success": success, "status": resp.status}
            except Exception as e:
                return {"name": name, "success": False, "error": str(e)}

    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(workers)
        tasks = [enable_one(session, sem, name) for name in names]
        results = await asyncio.gather(*tasks)

    return results


async def scan_recoverable_names(config, items, need_count=None):
    """扫描一批候选账号，找出可恢复为活跃的账号。"""
    if not items:
        return [], [], []

    probe_results = await check_401_batch(
        config["base_url"],
        config.get("cpa_password") or config.get("token", ""),
        items,
        config["workers"],
        config["timeout"],
        config["target_type"],
        allow_disabled=True,
    )
    quota_results = await check_quota_batch(
        config["base_url"],
        config.get("cpa_password") or config.get("token", ""),
        items,
        config["quota_workers"],
        config["timeout"],
        config["target_type"],
        config["weekly_quota_threshold"],
        config["primary_quota_threshold"],
        allow_disabled=True,
    )

    probe_by_name = {item.get("name"): item for item in probe_results if item.get("name")}
    quota_by_name = {item.get("name"): item for item in quota_results if item.get("name")}
    recoverable = []
    for raw in items:
        name = raw.get("name")
        if not name:
            continue
        probe = probe_by_name.get(name) or {}
        quota = quota_by_name.get(name) or {}
        if probe.get("status_code") != 200 or probe.get("invalid_401") or probe.get("error"):
            continue
        if quota.get("status_code") != 200 or quota.get("invalid_quota") or quota.get("error"):
            continue
        recoverable.append(name)
        if need_count is not None and len(recoverable) >= need_count:
            break

    return recoverable, probe_results, quota_results


async def rebalance_active_accounts(config, standby_names, auth_files, invalid_401_names, invalid_quota_names):
    """在自动巡检中按活跃目标数进行回收与补位。"""
    target_active = max(0, int(config.get("auto_keep_active_count") or 0))
    if target_active <= 0:
        return {
            "target_active": target_active,
            "active_before": 0,
            "active_after": 0,
            "moved_to_standby": [],
            "enabled_from_standby": [],
            "enabled_from_closed": [],
        }

    invalid_set = set(invalid_401_names or []) | set(invalid_quota_names or [])
    active_candidates = [
        item for item in auth_files
        if item.get("type") == config["target_type"]
        and not item.get("disabled")
        and item.get("name")
        and item.get("name") not in standby_names
        and item.get("name") not in invalid_set
    ]
    active_names = [item.get("name") for item in active_candidates if item.get("name")]
    moved_to_standby = []

    if len(active_names) > target_active:
        overflow_names = active_names[target_active:]
        close_results = await close_accounts(
            config["base_url"],
            config.get("cpa_password") or config.get("token", ""),
            overflow_names,
            config["delete_workers"],
            config["timeout"],
        )
        moved_to_standby = [item.get("name") for item in close_results if item.get("success") and item.get("name")]
        for name in moved_to_standby:
            standby_names.add(name)
        active_names = active_names[:target_active]

    enabled_from_standby = []
    enabled_from_closed = []
    need_count = max(0, target_active - len(active_names))

    if need_count > 0:
        standby_candidates = [
            item for item in auth_files
            if item.get("type") == config["target_type"]
            and item.get("disabled")
            and item.get("name") in standby_names
            and item.get("auth_index")
        ]
        recoverable, _probe, _quota = await scan_recoverable_names(config, standby_candidates, need_count=need_count)
        if recoverable:
            enable_results = await enable_accounts(
                config["base_url"],
                config.get("cpa_password") or config.get("token", ""),
                recoverable,
                config["delete_workers"],
                config["timeout"],
            )
            enabled_from_standby = [item.get("name") for item in enable_results if item.get("success") and item.get("name")]
            for name in enabled_from_standby:
                standby_names.discard(name)
            need_count = max(0, need_count - len(enabled_from_standby))

    if need_count > 0 and config.get("auto_allow_scan_closed"):
        closed_candidates = [
            item for item in auth_files
            if item.get("type") == config["target_type"]
            and item.get("disabled")
            and item.get("name") not in standby_names
            and item.get("auth_index")
        ]
        recoverable, _probe, _quota = await scan_recoverable_names(config, closed_candidates, need_count=need_count)
        if recoverable:
            enable_results = await enable_accounts(
                config["base_url"],
                config.get("cpa_password") or config.get("token", ""),
                recoverable,
                config["delete_workers"],
                config["timeout"],
            )
            enabled_from_closed = [item.get("name") for item in enable_results if item.get("success") and item.get("name")]

    active_after = len(active_names) + len(enabled_from_standby) + len(enabled_from_closed)
    return {
        "target_active": target_active,
        "active_before": len(active_candidates),
        "active_after": active_after,
        "moved_to_standby": moved_to_standby,
        "enabled_from_standby": enabled_from_standby,
        "enabled_from_closed": enabled_from_closed,
    }


async def run_auto_check_once(config):
    """执行一次自动巡检，聚焦 CLI 最常用能力：401/额度检测 + 自动动作。"""
    base_url = config["base_url"]
    token = config.get("cpa_password") or config.get("token", "")
    target_type = config["target_type"]
    workers = config["workers"]
    quota_workers = config["quota_workers"]
    delete_workers = config["delete_workers"]
    timeout = config["timeout"]
    weekly_quota_threshold = config["weekly_quota_threshold"]
    primary_quota_threshold = config["primary_quota_threshold"]
    auto_action_401 = config.get("auto_action_401") or "删除"
    auto_action_quota = config.get("auto_action_quota") or "关闭"
    auth_files = await fetch_auth_files(base_url, token, timeout)
    if not auth_files:
        raise RuntimeError("自动巡检未获取到账号列表")
    standby_names = resolve_standby_names_for_files(config, auth_files)

    invalid_401 = await check_401_batch(base_url, token, auth_files, workers, timeout, target_type)
    invalid_quota = await check_quota_batch(
        base_url,
        token,
        auth_files,
        quota_workers,
        timeout,
        target_type,
        weekly_quota_threshold,
        primary_quota_threshold,
    )

    invalid_401_names = sorted({r["name"] for r in invalid_401 if r.get("invalid_401") and r.get("name")})
    invalid_quota_names = sorted({r["name"] for r in invalid_quota if r.get("invalid_quota") and r.get("name")})
    failed_401 = [r for r in invalid_401 if r.get("error")]
    failed_quota = [r for r in invalid_quota if r.get("error")]

    deleted_count = 0
    closed_count = 0

    if auto_action_401 == "删除" and invalid_401_names:
        delete_results = await delete_accounts(base_url, token, invalid_401_names, delete_workers, timeout)
        deleted_count += sum(1 for item in delete_results if item.get("success"))

    if auto_action_quota == "删除" and invalid_quota_names:
        delete_results = await delete_accounts(base_url, token, invalid_quota_names, delete_workers, timeout)
        deleted_count += sum(1 for item in delete_results if item.get("success"))
    elif auto_action_quota == "关闭" and invalid_quota_names:
        close_results = await close_accounts(base_url, token, invalid_quota_names, delete_workers, timeout)
        closed_count += sum(1 for item in close_results if item.get("success"))

    auth_files_after = await fetch_auth_files(base_url, token, timeout)
    standby_names = resolve_standby_names_for_files(config, auth_files_after)
    rebalance_summary = await rebalance_active_accounts(
        config,
        standby_names,
        auth_files_after,
        invalid_401_names,
        invalid_quota_names,
    )
    save_standby_names(config, standby_names)

    return {
        "interval_minutes": int(config.get("auto_interval_minutes") or 30),
        "invalid_401_count": len(invalid_401_names),
        "invalid_quota_count": len(invalid_quota_names),
        "deleted_count": deleted_count,
        "closed_count": closed_count,
        "error_count": len(failed_401) + len(failed_quota),
        "scanned_count": len(auth_files),
        "target_active": rebalance_summary.get("target_active", 0),
        "active_before": rebalance_summary.get("active_before", 0),
        "active_after": rebalance_summary.get("active_after", 0),
        "moved_to_standby_count": len(rebalance_summary.get("moved_to_standby") or []),
        "enabled_from_standby_count": len(rebalance_summary.get("enabled_from_standby") or []),
        "enabled_from_closed_count": len(rebalance_summary.get("enabled_from_closed") or []),
    }


def auto_patrol_worker(config, auto_state, auto_lock, stop_event, trigger_event):
    interval_minutes = max(1, int(config.get("auto_interval_minutes") or 30))
    interval_seconds = interval_minutes * 60
    set_auto_state(
        auto_state,
        auto_lock,
        enabled=True,
        interval_minutes=interval_minutes,
        loop_started_at=time.time(),
        next_run_at=time.time(),
        message="自动巡检已启动，等待首次执行",
    )

    while not stop_event.is_set():
        now = time.time()
        next_run_at = snapshot_auto_state(auto_state, auto_lock).get("next_run_at") or now
        wait_seconds = max(0.0, next_run_at - now)

        if trigger_event.wait(wait_seconds):
            trigger_event.clear()
            if stop_event.is_set():
                break

        if stop_event.is_set():
            break

        set_auto_state(auto_state, auto_lock, running=True, message="正在执行巡检...")
        try:
            summary = asyncio.run(run_auto_check_once(config))
            cycle_count = int(snapshot_auto_state(auto_state, auto_lock).get("cycle_count") or 0) + 1
            set_auto_state(
                auto_state,
                auto_lock,
                running=False,
                last_run_at=time.time(),
                last_error=None,
                last_summary=summary,
                cycle_count=cycle_count,
                next_run_at=time.time() + interval_seconds,
                message=f"第 {cycle_count} 次巡检完成",
            )
        except Exception as exc:
            set_auto_state(
                auto_state,
                auto_lock,
                running=False,
                last_run_at=time.time(),
                last_error=str(exc),
                next_run_at=time.time() + interval_seconds,
                message=f"巡检失败：{exc}",
            )

    set_auto_state(auto_state, auto_lock, enabled=False, running=False, next_run_at=None, message="自动巡检已停止")


def stop_auto_patrol(auto_state, auto_lock, auto_runtime):
    if not auto_runtime.get("thread"):
        set_auto_state(auto_state, auto_lock, enabled=False, running=False, next_run_at=None, message="自动巡检未启动")
        return

    auto_runtime["stop_event"].set()
    auto_runtime["trigger_event"].set()
    # 不在前台阻塞等待后台线程完整退出，避免用户按 S 后需要卡几秒。
    # 后台线程会在当前轮次结束或下一次检查 stop_event 时自行退出。
    thread = auto_runtime.get("thread")
    if thread and (not thread.is_alive()):
        auto_runtime["thread"] = None
    set_auto_state(
        auto_state,
        auto_lock,
        enabled=False,
        next_run_at=None,
        message="正在停止自动巡检，后台任务会尽快退出",
    )


def start_auto_patrol(config, auto_state, auto_lock, auto_runtime):
    if auto_runtime.get("thread") and auto_runtime["thread"].is_alive():
        return False

    stop_event = threading.Event()
    trigger_event = threading.Event()
    thread = threading.Thread(
        target=auto_patrol_worker,
        args=(dict(config), auto_state, auto_lock, stop_event, trigger_event),
        daemon=True,
    )
    auto_runtime["stop_event"] = stop_event
    auto_runtime["trigger_event"] = trigger_event
    auto_runtime["thread"] = thread
    thread.start()
    return True


def trigger_auto_patrol_once(auto_runtime):
    if auto_runtime.get("trigger_event"):
        auto_runtime["trigger_event"].set()


def auto_patrol_status_screen(auto_state, auto_lock, auto_runtime):
    if msvcrt is None:
        print("\n⚠️ 当前平台不支持实时按键监听，将返回主菜单。")
        return

    while True:
        current = snapshot_auto_state(auto_state, auto_lock)
        clear_screen()
        print_separator()
        print("🤖 自动巡检状态界面")
        print_separator()
        for line in build_auto_status_lines(current):
            print(line)
        if current.get("last_error"):
            print(f"  - 上次错误: {current.get('last_error')}")
        print()
        print("快捷键: [R] 立即执行一次  [S] 停止自动巡检  [M] 返回主菜单")

        end_time = time.time() + 1.0
        while time.time() < end_time:
            if msvcrt.kbhit():
                key = msvcrt.getwch().lower()
                if key == "r":
                    trigger_auto_patrol_once(auto_runtime)
                elif key == "s":
                    stop_auto_patrol(auto_state, auto_lock, auto_runtime)
                    return
                elif key == "m":
                    return
            time.sleep(0.05)


def print_separator():
    """打印分隔线"""
    print("=" * 80)


def print_statistics(auth_files, invalid_401, invalid_quota, target_type, has_checked_401, has_checked_quota):
    """打印统计信息"""
    print_separator()
    print(f"📊 账号统计信息 (目标类型: {target_type})")
    print_separator()

    total = len(auth_files)
    target_accounts = [a for a in auth_files if a.get("type") == target_type]
    active_accounts = [a for a in target_accounts if a.get("status") == "active"]
    closed_accounts = [a for a in target_accounts if a.get("disabled")]

    print(f"总账号数: {total}")
    print(f"目标类型账号数: {len(target_accounts)}")
    print(f"  - 活跃: {len(active_accounts)}")
    print(f"  - 已关闭: {len(closed_accounts)}")
    print()

    if has_checked_401:
        invalid_401_names = {r["name"] for r in invalid_401 if r.get("invalid_401")}
        print(f"❌ 401错误账号: {len(invalid_401_names)}")
    else:
        print(f"❌ 401错误账号: 未检测")

    if has_checked_quota:
        invalid_quota_names = {r["name"] for r in invalid_quota if r.get("invalid_quota")}
        print(f"📉 额度耗尽账号: {len(invalid_quota_names)}")
    else:
        print(f"📉 额度耗尽账号: 未检测")

    if has_checked_401 and has_checked_quota:
        invalid_401_names = {r["name"] for r in invalid_401 if r.get("invalid_401")}
        invalid_quota_names = {r["name"] for r in invalid_quota if r.get("invalid_quota")}
        print(f"⚠️  问题账号总数: {len(invalid_401_names | invalid_quota_names)}")

    print_separator()


def reset_detection_results():
    """刷新账号列表或执行批量操作后清空旧检测结果，避免后续误用过期状态。"""
    return [], [], False, False


def show_menu(auto_patrol_running=False):
    """显示操作菜单"""
    print("\n📋 操作菜单:")
    print("  1. 检测401错误")
    print("  2. 检测额度")
    print("  3. 完整检测 (401 + 额度)")
    print("  4. 查看401错误账号列表 (前50个)")
    print("  5. 查看额度耗尽账号列表 (前50个)")
    print("  6. 批量删除所有401错误账号")
    print("  7. 批量删除所有额度耗尽账号")
    print("  8. 批量删除所有问题账号 (401 + 额度耗尽)")
    print("  9. 批量关闭所有额度耗尽账号")
    print("  10. 重新获取账号列表")
    if auto_patrol_running:
        print(f"  11. {colorize_auto_state_text('自动巡检运行中，查看巡检状态')}")
        print(f"  12. {colorize_auto_state_text('停止自动巡检')}")
    else:
        print("  11. 进入自动巡检状态")
        print("  12. 当前无需停止自动巡检")
    print("  0. 退出")
    print()


def show_account_list(accounts, title, limit=50):
    """显示账号列表"""
    print_separator()
    print(f"📝 {title}")
    print_separator()
    
    if not accounts:
        print("(无)")
        return
    
    for i, name in enumerate(accounts[:limit], 1):
        print(f"  {i}. {name}")
    
    if len(accounts) > limit:
        print(f"\n  ... 还有 {len(accounts) - limit} 个账号未显示")
    
    print(f"\n总计: {len(accounts)} 个账号")


def preview_targets(names, title, limit=10):
    """危险操作前先预览部分目标账号，降低误操作概率。"""
    print_separator()
    print(f"⚠️  {title}")
    print_separator()
    for index, name in enumerate((names or [])[:limit], 1):
        print(f"  {index}. {name}")
    total = len(names or [])
    if total > limit:
        print(f"\n  ... 还有 {total - limit} 个账号未显示")
    print(f"\n总计: {total} 个账号")


def print_failed_samples(results, title, limit=10):
    """打印批处理失败样本，方便快速定位失败原因。"""
    failed = [item for item in (results or []) if not item.get("success")]
    if not failed:
        return

    print_separator()
    print(f"⚠️  {title}")
    print_separator()
    for index, item in enumerate(failed[:limit], 1):
        name = item.get("name") or "<unknown>"
        error = item.get("error") or f"http_status={item.get('status')}"
        print(f"  {index}. {name} -> {error}")
    if len(failed) > limit:
        print(f"\n  ... 还有 {len(failed) - limit} 条失败未显示")



def print_detection_report(title, problem_label, invalid_results, failure_title, limit=10):
    """检测结束后直接输出报告与失败样本，避免失败列表单独占菜单位置。"""
    invalid_names = [item.get("name") for item in (invalid_results or []) if item.get(problem_label) and item.get("name")]
    failed_items = [item for item in (invalid_results or []) if item.get("error") and item.get("name")]
    total_count = len(invalid_results or [])
    invalid_count = len(invalid_names)
    failed_count = len(failed_items)

    invalid_count_text = colorize_status(str(invalid_count), "91") if invalid_count else colorize_status("0", "92")
    failed_count_text = colorize_status(str(failed_count), "91") if failed_count else colorize_status("0", "92")

    print_separator()
    print(f"📋 {title}")
    print_separator()
    print(f"  总检测账号  : {total_count}")
    print(f"  命中问题账号: {invalid_count_text}")
    print(f"  检测失败账号: {failed_count_text}")

    if failed_items:
        print()
        print(f"  失败样本    : {colorize_status(failure_title, '91')} (前{limit}个)")
        for index, item in enumerate(failed_items[:limit], 1):
            name = item.get("name") or "<unknown>"
            error = item.get("error") or "unknown error"
            print(f"    {index}. {name} -> {colorize_status(error, '91')}")
        if failed_count > limit:
            print(f"\n    ... 还有 {failed_count - limit} 个失败账号未显示")
    else:
        print(f"  失败样本    : {colorize_status('无', '92')}")


async def main():
    """主函数"""
    print_separator()
    print("🚀 CLI账号清理工具")
    print_separator()

    config = load_config()
    base_url = config["base_url"]
    token = config.get("cpa_password") or config.get("token", "")
    target_type = config["target_type"]
    workers = config["workers"]
    quota_workers = config["quota_workers"]
    delete_workers = config["delete_workers"]
    timeout = config["timeout"]
    weekly_quota_threshold = config["weekly_quota_threshold"]
    primary_quota_threshold = config["primary_quota_threshold"]

    if not token:
        print("❌ 错误: 配置文件中未设置 cpa_password 或 token")
        return

    print(f"📡 连接到: {base_url}")
    print(f"🎯 目标类型: {target_type}")
    print(f"⚙️  并发数: 401检测={workers}, 额度检测={quota_workers}, 删除={delete_workers}")
    print(f"📏 阈值: 周额度={weekly_quota_threshold}%, 5小时额度={primary_quota_threshold}%")
    print()

    auto_state = create_auto_state()
    auto_lock = threading.Lock()
    auto_runtime = {"thread": None, "stop_event": None, "trigger_event": None}

    print("🔍 正在获取账号列表...")
    auth_files = await fetch_auth_files(base_url, token, timeout)
    if not auth_files:
        print("❌ 未获取到任何账号")
        return

    print(f"✅ 获取到 {len(auth_files)} 个账号")
    print("💡 提示: 启动时跳过检测以加快速度，请在菜单中选择检测选项")

    invalid_401 = []
    invalid_quota = []
    has_checked_401 = False
    has_checked_quota = False

    while True:
        invalid_401_names = [r["name"] for r in invalid_401 if r.get("invalid_401")]
        invalid_quota_names = [r["name"] for r in invalid_quota if r.get("invalid_quota")]
        all_invalid_names = list(set(invalid_401_names + invalid_quota_names))
        auto_patrol_running = is_auto_patrol_enabled(auto_state, auto_lock)
        auto_patrol_thread_alive = is_auto_patrol_thread_alive(auto_runtime)

        print_statistics(auth_files, invalid_401, invalid_quota, target_type, has_checked_401, has_checked_quota)
        auto_patrol_status_text = colorize_auto_state_text("运行中，可查看巡检状态") if auto_patrol_running else colorize_auto_state_text("当前未启动")
        print(f"🤖 自动巡检: {auto_patrol_status_text}")
        show_menu(auto_patrol_running=auto_patrol_running)

        try:
            choice = input("请选择操作 [0-12]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n👋 再见!")
            break

        if choice == "0":
            stop_auto_patrol(auto_state, auto_lock, auto_runtime)
            print("\n👋 再见!")
            break

        try:
            if choice == "1":
                invalid_401 = await check_401_batch(
                    base_url,
                    token,
                    auth_files,
                    workers,
                    timeout,
                    target_type,
                    progress_label="401检测进度",
                )
                has_checked_401 = True
                print_detection_report("401检测报告", "invalid_401", invalid_401, "401检测失败账号")

            elif choice == "2":
                invalid_quota = await check_quota_batch(
                    base_url,
                    token,
                    auth_files,
                    quota_workers,
                    timeout,
                    target_type,
                    weekly_quota_threshold,
                    primary_quota_threshold,
                    progress_label="额度检测进度",
                )
                has_checked_quota = True
                print_detection_report("额度检测报告", "invalid_quota", invalid_quota, "额度检测失败账号")

            elif choice == "3":
                print_separator()
                print("📦 完整检测报告")
                print_separator()
                print("阶段 1/2: 401检测")
                invalid_401 = await check_401_batch(
                    base_url,
                    token,
                    auth_files,
                    workers,
                    timeout,
                    target_type,
                    progress_label="完整检测-401阶段",
                )
                has_checked_401 = True
                print_detection_report("401检测报告", "invalid_401", invalid_401, "401检测失败账号")

                print()
                print("阶段 2/2: 额度检测")
                invalid_quota = await check_quota_batch(
                    base_url,
                    token,
                    auth_files,
                    quota_workers,
                    timeout,
                    target_type,
                    weekly_quota_threshold,
                    primary_quota_threshold,
                    progress_label="完整检测-额度阶段",
                )
                has_checked_quota = True
                print_detection_report("额度检测报告", "invalid_quota", invalid_quota, "额度检测失败账号")

            elif choice == "4":
                show_account_list(invalid_401_names, "401错误账号列表")

            elif choice == "5":
                show_account_list(invalid_quota_names, "额度耗尽账号列表")

            elif choice == "6":
                if not invalid_401_names:
                    print("\n✅ 没有401错误账号需要删除")
                    continue

                preview_targets(invalid_401_names, "即将删除的401错误账号")
                confirm = input("确认删除? [y/N]: ").strip().lower()
                if confirm == "y":
                    print(f"\n🗑️  正在删除 {len(invalid_401_names)} 个账号...")
                    results = await delete_accounts(
                        base_url,
                        token,
                        invalid_401_names,
                        delete_workers,
                        timeout,
                        progress_label="删除401账号进度",
                    )
                    success_count = sum(1 for r in results if r.get("success"))
                    print(f"✅ 成功删除 {success_count}/{len(invalid_401_names)} 个账号")
                    print_failed_samples(results, "删除401账号失败样本")
                    print("\n🔄 重新获取账号列表...")
                    auth_files = await fetch_auth_files(base_url, token, timeout)
                    invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()

            elif choice == "7":
                if not invalid_quota_names:
                    print("\n✅ 没有额度耗尽账号需要删除")
                    continue

                preview_targets(invalid_quota_names, "即将删除的额度耗尽账号")
                confirm = input("确认删除? [y/N]: ").strip().lower()
                if confirm == "y":
                    print(f"\n🗑️  正在删除 {len(invalid_quota_names)} 个账号...")
                    results = await delete_accounts(
                        base_url,
                        token,
                        invalid_quota_names,
                        delete_workers,
                        timeout,
                        progress_label="删除额度账号进度",
                    )
                    success_count = sum(1 for r in results if r.get("success"))
                    print(f"✅ 成功删除 {success_count}/{len(invalid_quota_names)} 个账号")
                    print_failed_samples(results, "删除额度账号失败样本")
                    print("\n🔄 重新获取账号列表...")
                    auth_files = await fetch_auth_files(base_url, token, timeout)
                    invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()

            elif choice == "8":
                if not all_invalid_names:
                    print("\n✅ 没有问题账号需要删除")
                    continue

                preview_targets(all_invalid_names, "即将删除的问题账号 (401 + 额度耗尽)")
                print(f"\n   - 401错误: {len(invalid_401_names)}")
                print(f"   - 额度耗尽: {len(invalid_quota_names)}")
                confirm = input("确认删除? [y/N]: ").strip().lower()
                if confirm == "y":
                    print(f"\n🗑️  正在删除 {len(all_invalid_names)} 个账号...")
                    results = await delete_accounts(
                        base_url,
                        token,
                        all_invalid_names,
                        delete_workers,
                        timeout,
                        progress_label="删除问题账号进度",
                    )
                    success_count = sum(1 for r in results if r.get("success"))
                    print(f"✅ 成功删除 {success_count}/{len(all_invalid_names)} 个账号")
                    print_failed_samples(results, "删除问题账号失败样本")
                    print("\n🔄 重新获取账号列表...")
                    auth_files = await fetch_auth_files(base_url, token, timeout)
                    invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()

            elif choice == "9":
                if not invalid_quota_names:
                    print("\n✅ 没有额度耗尽账号需要关闭")
                    continue

                preview_targets(invalid_quota_names, "即将关闭的额度耗尽账号")
                confirm = input("确认关闭? [y/N]: ").strip().lower()
                if confirm == "y":
                    print(f"\n🔒 正在关闭 {len(invalid_quota_names)} 个账号...")
                    results = await close_accounts(
                        base_url,
                        token,
                        invalid_quota_names,
                        delete_workers,
                        timeout,
                        progress_label="关闭额度账号进度",
                    )
                    success_count = sum(1 for r in results if r.get("success"))
                    print(f"✅ 成功关闭 {success_count}/{len(invalid_quota_names)} 个账号")
                    print_failed_samples(results, "关闭额度账号失败样本")
                    print("\n🔄 重新获取账号列表...")
                    auth_files = await fetch_auth_files(base_url, token, timeout)
                    invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()

            elif choice == "10":
                print("\n🔄 重新获取账号列表...")
                auth_files = await fetch_auth_files(base_url, token, timeout)
                print(f"✅ 获取到 {len(auth_files)} 个账号")
                invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()
                print("💡 已清空旧检测结果，请按需重新检测")

            elif choice == "11":
                config["auto_enabled"] = True
                if start_auto_patrol(config, auto_state, auto_lock, auto_runtime):
                    print("\n✅ 自动巡检已启动")
                else:
                    if auto_patrol_running:
                        print("\nℹ️ 自动巡检已在运行，直接进入状态界面")
                    elif auto_patrol_thread_alive:
                        print("\nℹ️ 自动巡检正在停止收尾，暂不重复启动，可查看当前状态")
                    else:
                        print("\nℹ️ 自动巡检当前不可启动，请稍后再试")
                auto_patrol_status_screen(auto_state, auto_lock, auto_runtime)

            elif choice == "12":
                if auto_patrol_running:
                    stop_auto_patrol(auto_state, auto_lock, auto_runtime)
                    print("\n✅ 自动巡检已停止")
                else:
                    print("\nℹ️ 自动巡检当前未启动")

            else:
                print("\n❌ 无效的选择，请重新输入")

        except UserCancelledError as exc:
            # 手动中断后立即回到主菜单，同时刷新账号列表，避免继续使用部分完成后的旧状态。
            print(f"\n⚠️ {exc}")
            print("🔄 正在刷新账号列表并清空旧检测结果...")
            auth_files = await fetch_auth_files(base_url, token, timeout)
            print(f"✅ 获取到 {len(auth_files)} 个账号")
            invalid_401, invalid_quota, has_checked_401, has_checked_quota = reset_detection_results()
            continue


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 程序已中断")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        



