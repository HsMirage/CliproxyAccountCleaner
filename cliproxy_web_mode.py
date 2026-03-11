#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import hmac
import json
import os
import secrets
import threading
import time
import webbrowser
from datetime import datetime


def _b(v):
    return v if isinstance(v, bool) else str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _i(v, d, lo=None, hi=None):
    try:
        o = int(v)
    except Exception:
        o = int(d)
    if lo is not None:
        o = max(lo, o)
    if hi is not None:
        o = min(hi, o)
    return o


def _names(v):
    if v is None:
        return []
    if isinstance(v, list):
        src = [str(x or "").strip() for x in v]
    else:
        src = [x.strip() for x in str(v or "").replace(",", "\n").splitlines()]
    out, seen = [], set()
    for n in src:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _rst(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
    except Exception:
        return ""


class WebState:
    def __init__(self, ns, conf, config_path):
        self.ns = ns
        self.conf = dict(conf or {})
        self.config_path = config_path
        self.lock = threading.RLock()
        self.rows = []
        self.standby = set()
        self.auto_running = False
        self.auto_stop = threading.Event()
        self.auto_status = "未启动"
        self.auto_last = {}
        self.action_progress = {
            "op": "",
            "running": False,
            "total": 0,
            "done": 0,
            "success": 0,
            "failed": 0,
            "last_name": "",
            "last_error": "",
            "message": "",
            "started_at": 0.0,
            "updated_at": 0.0,
            "ended_at": 0.0,
        }
        self._load_standby()

    def _log(self, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[cliproxy-web {ts}] {message}", flush=True)

    def _names_preview(self, names, limit=10):
        arr = [str(x or "").strip() for x in (names or []) if str(x or "").strip()]
        if len(arr) <= limit:
            return ",".join(arr)
        return ",".join(arr[:limit]) + f"...(+{len(arr) - limit})"

    def _status_summary_text(self):
        with self.lock:
            total = len(self.rows)
            active = len([x for x in self.rows if self._bucket(x) == "active"])
            closed = len([x for x in self.rows if self._bucket(x) == "closed"])
            standby = len([x for x in self.rows if self._bucket(x) == "standby"])
            invalid_401 = len([x for x in self.rows if self._bucket(x) == "invalid_401"])
            invalid_quota = len([x for x in self.rows if self._bucket(x) == "invalid_quota"])
        return f"total={total} active={active} closed={closed} standby={standby} invalid401={invalid_401} invalid_quota={invalid_quota}"

    def _progress_start(self, op, total):
        now = time.time()
        with self.lock:
            self.action_progress = {
                "op": str(op or ""),
                "running": True,
                "total": int(total or 0),
                "done": 0,
                "success": 0,
                "failed": 0,
                "last_name": "",
                "last_error": "",
                "message": "",
                "started_at": now,
                "updated_at": now,
                "ended_at": 0.0,
            }

    def _progress_tick(self, name, ok, err=""):
        with self.lock:
            p = self.action_progress
            if not p.get("running"):
                return
            p["done"] = int(p.get("done") or 0) + 1
            if ok:
                p["success"] = int(p.get("success") or 0) + 1
            else:
                p["failed"] = int(p.get("failed") or 0) + 1
            p["last_name"] = str(name or "")
            p["last_error"] = str(err or "")
            p["updated_at"] = time.time()

    def _progress_finish(self, message=""):
        now = time.time()
        with self.lock:
            p = self.action_progress
            p["running"] = False
            p["message"] = str(message or "")
            p["updated_at"] = now
            p["ended_at"] = now

    def progress_snapshot(self):
        with self.lock:
            return dict(self.action_progress)

    async def _set_disabled_with_progress(self, base_url, token, names, disabled, workers, timeout, track=False):
        aiohttp = self.ns["aiohttp"]
        mgmt_headers = self.ns["mgmt_headers"]
        management_action_succeeded = self.ns["management_action_succeeded"]
        safe_json_text = self.ns["safe_json_text"]

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
                        return {"name": name, "updated": ok, "disabled": bool(disabled), "status": resp.status, "error": None if ok else text[:200]}
            except Exception as e:
                return {"name": name, "updated": False, "disabled": bool(disabled), "status": None, "error": str(e)}

        connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
        client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
        sem = asyncio.Semaphore(max(1, workers))

        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
            limit = max(1, int(workers or 1))
            it = iter(names or [])
            running = set()
            out = []

            for _ in range(limit):
                try:
                    name = next(it)
                except StopIteration:
                    break
                running.add(asyncio.create_task(set_one(session, sem, name)))

            while running:
                done, running = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    r = await task
                    out.append(r)
                    if track:
                        self._progress_tick(r.get("name"), bool(r.get("updated")), r.get("error") or "")
                    try:
                        name = next(it)
                    except StopIteration:
                        continue
                    running.add(asyncio.create_task(set_one(session, sem, name)))
        return out

    def _runtime(self, need=False):
        c = dict(self.conf)
        base = str(c.get("base_url") or "").strip().rstrip("/")
        token = str(c.get("token") or c.get("cpa_password") or "").strip()
        auto_interval = c.get("auto_interval_minutes")
        if auto_interval is None:
            auto_interval = c.get("auto_check_interval_minutes")
        auto_401_raw = str(c.get("auto_action_401") or c.get("auto_401_action") or "").strip().lower()
        auto_quota_raw = str(c.get("auto_action_quota") or c.get("auto_quota_action") or "").strip().lower()
        auto_fill = c.get("auto_allow_scan_closed")
        if auto_fill is None:
            auto_fill = c.get("auto_allow_closed_scan", False)
        if need:
            if not base.lower().startswith(("http://", "https://")):
                raise RuntimeError("base_url 必须是 http:// 或 https://")
            if not token:
                raise RuntimeError("token / cpa_password 不能为空")
        return {
            "base": base,
            "token": token,
            "target_type": str(c.get("target_type") or self.ns["DEFAULT_TARGET_TYPE"]).strip().lower(),
            "provider": str(c.get("provider") or "").strip().lower(),
            "ua": str(c.get("user_agent") or self.ns["DEFAULT_UA"]),
            "chat_id": str(c.get("chatgpt_account_id") or "").strip(),
            "timeout": _i(c.get("timeout"), self.ns["DEFAULT_TIMEOUT"], 3, 120),
            "workers": _i(c.get("workers"), self.ns["DEFAULT_WORKERS"], 1, 600),
            "quota_workers": _i(c.get("quota_workers"), self.ns["DEFAULT_QUOTA_WORKERS"], 1, 600),
            "close_workers": _i(c.get("close_workers"), self.ns["DEFAULT_CLOSE_WORKERS"], 1, 300),
            "enable_workers": _i(c.get("enable_workers"), self.ns["DEFAULT_ENABLE_WORKERS"], 1, 300),
            "delete_workers": _i(c.get("delete_workers"), self.ns["DEFAULT_DELETE_WORKERS"], 1, 300),
            "retries": _i(c.get("retries"), self.ns["DEFAULT_RETRIES"], 0, 5),
            "weekly": _i(c.get("weekly_quota_threshold"), self.ns["DEFAULT_QUOTA_THRESHOLD"], 0, 100),
            "primary": _i(c.get("primary_quota_threshold"), self.ns["DEFAULT_QUOTA_THRESHOLD"], 0, 100),
            "auto_intv": _i(auto_interval, 30, 1, 1440),
            "auto_401": "mark" if auto_401_raw in ("mark", "only_mark", "仅标记") else "delete",
            "auto_quota": "delete" if auto_quota_raw in ("delete", "del", "remove", "删除") else ("mark" if auto_quota_raw in ("mark", "only_mark", "仅标记") else "close"),
            "auto_fill": _b(auto_fill),
            "auto_target": _i(c.get("auto_keep_active_count"), 0, 0, 99999),
        }

    def _save(self):
        self.ns["write_json_file"](self.config_path, self.conf)

    def _out_path(self, value):
        p = str(value or "").strip()
        if not p:
            p = "output.json"
        path = self.ns["Path"](p)
        if path.is_absolute():
            return path
        base_dir = self.ns["Path"](self.config_path).resolve().parent if self.config_path else self.ns["Path"](self.ns["HERE"])
        return base_dir / p

    def update_conf(self, data):
        if not isinstance(data, dict):
            return
        with self.lock:
            self.conf.update(data)
            self.conf["token"] = str(self.conf.get("token") or self.conf.get("cpa_password") or "").strip()
            self.conf["cpa_password"] = self.conf["token"]
            self.conf["target_type"] = str(self.conf.get("target_type") or self.ns["DEFAULT_TARGET_TYPE"]).strip().lower()
            self.conf["provider"] = str(self.conf.get("provider") or "").strip().lower()
            if "auto_check_interval_minutes" in self.conf:
                self.conf["auto_interval_minutes"] = _i(self.conf.get("auto_check_interval_minutes"), 30, 1, 1440)
            if "auto_401_action" in self.conf:
                auto_401 = str(self.conf.get("auto_401_action") or "").strip().lower()
                self.conf["auto_action_401"] = "仅标记" if auto_401 in ("mark", "only_mark", "仅标记") else "删除"
            if "auto_quota_action" in self.conf:
                auto_quota = str(self.conf.get("auto_quota_action") or "").strip().lower()
                if auto_quota in ("delete", "del", "remove", "删除"):
                    self.conf["auto_action_quota"] = "删除"
                elif auto_quota in ("mark", "only_mark", "仅标记"):
                    self.conf["auto_action_quota"] = "仅标记"
                else:
                    self.conf["auto_action_quota"] = "关闭"
            if "auto_allow_closed_scan" in self.conf:
                self.conf["auto_allow_scan_closed"] = bool(self.conf.get("auto_allow_closed_scan"))
            self.conf.pop("auto_check_interval_minutes", None)
            self.conf.pop("auto_401_action", None)
            self.conf.pop("auto_quota_action", None)
            self.conf.pop("auto_allow_closed_scan", None)
        self._save()

    def _standby_path(self):
        return self._out_path(self.conf.get("standby_output") or self.ns["DEFAULT_STANDBY_OUTPUT"])

    def _load_standby(self):
        with self.lock:
            self._set_standby_locked(self._load_standby_names())

    def _save_standby(self):
        with self.lock:
            cleaned = self._set_standby_locked(self.standby)
        self.ns["write_json_file"](self._standby_path(), sorted(cleaned))

    def _load_standby_names(self):
        names = set()
        for item in self._load_standby_entries():
            name = self._standby_entry_name(item)
            if name:
                names.add(name)
        return names

    def _load_standby_entries(self):
        p = self._standby_path()
        if not p.exists():
            legacy = self.conf.get("standby_accounts") or []
            if isinstance(legacy, list):
                return list(legacy)
            return []
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
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
        standby_entries = self._load_standby_entries()
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

    def _set_standby_locked(self, names):
        cleaned = {str(name).strip() for name in (names or set()) if str(name or "").strip()}
        self.standby = cleaned
        for row in self.rows:
            row["standby"] = str(row.get("name") or "").strip() in cleaned
        return cleaned

    def _refresh_standby_for_files_locked(self, files):
        return self._set_standby_locked(self._resolve_standby_names_for_files(files))

    def _refresh_standby_from_rows_locked(self):
        files = []
        for row in self.rows:
            raw = row.get("raw")
            if isinstance(raw, dict):
                files.append(raw)
        if files:
            return self._refresh_standby_for_files_locked(files)
        return self._set_standby_locked(self._load_standby_names())

    def _bucket(self, a):
        if a.get("invalid_401"):
            return "invalid_401"
        if a.get("standby"):
            return "standby"
        if a.get("disabled"):
            return "closed"
        if a.get("invalid_quota"):
            return "invalid_quota"
        s = str(a.get("status") or "unknown").lower()
        return "active" if s in ("active", "error") or a.get("stream_error_active") else "unknown"

    def _bucket_text(self, k):
        return {"invalid_401": "401无效", "standby": "备用", "closed": "已关闭", "invalid_quota": "额度耗尽", "active": "活跃", "unknown": "未知"}.get(k, k)

    def _usage(self, a):
        if a.get("used_percent") is None:
            return ""
        src = {"weekly": "周", "5hour": "5小时", "remaining": "剩余", "status_message": "状态", "weekly_limit": "周限额", "5hour_limit": "5小时限额", "rate_limit_flag": "限流"}.get(str(a.get("quota_source") or ""), "-")
        parts = [f"使用率: {a.get('used_percent')}%"]
        if a.get("individual_used_percent") is not None:
            parts.append(f"周: {a.get('individual_used_percent')}%")
        if a.get("primary_used_percent") is not None:
            parts.append(f"5小时: {a.get('primary_used_percent')}%")
        rt = _rst(a.get("reset_at"))
        if rt:
            parts.append(f"重置: {rt}")
        parts.append(f"来源: {src}")
        return " | ".join(parts)

    def snapshot(self):
        with self.lock:
            rows = []
            sm = {"total": len(self.rows), "active": 0, "unknown": 0, "closed": 0, "standby": 0, "invalid_401": 0, "invalid_quota": 0}
            for a in self.rows:
                k = self._bucket(a)
                if k in sm:
                    sm[k] += 1
                rows.append({"name": a.get("name") or "", "account": a.get("account") or "", "status_key": k, "status": self._bucket_text(k), "usage": self._usage(a), "error": (a.get("check_error") or "")[:240], "disabled": bool(a.get("disabled")), "standby": bool(a.get("standby"))})
            cfg = self._runtime(False)
            pub = {"base_url": cfg["base"], "token": cfg["token"], "target_type": cfg["target_type"], "provider": cfg["provider"], "workers": cfg["workers"], "quota_workers": cfg["quota_workers"], "delete_workers": cfg["delete_workers"], "close_workers": cfg["close_workers"], "enable_workers": cfg["enable_workers"], "timeout": cfg["timeout"], "retries": cfg["retries"], "weekly_quota_threshold": cfg["weekly"], "primary_quota_threshold": cfg["primary"], "chatgpt_account_id": cfg["chat_id"], "auto_check_interval_minutes": cfg["auto_intv"], "auto_401_action": cfg["auto_401"], "auto_quota_action": cfg["auto_quota"], "auto_allow_closed_scan": cfg["auto_fill"], "auto_keep_active_count": cfg["auto_target"]}
            return {"rows": rows, "summary": sm, "auto": {"running": self.auto_running, "status": self.auto_status, "last_summary": dict(self.auto_last or {})}, "config": pub}

    def _active_count(self):
        with self.lock:
            return len([x for x in self.rows if self._bucket(x) == "active"])

    def refresh(self):
        rt = self._runtime(True)
        files = self.ns["fetch_auth_files"](rt["base"], rt["token"], rt["timeout"])
        with self.lock:
            old = {x.get("name"): x for x in self.rows if x.get("name")}
            self._refresh_standby_for_files_locked(files)
            out = []
            for raw in files:
                n = str(raw.get("name") or "").strip()
                if not n:
                    continue
                o = old.get(n) or {}
                st = str(raw.get("status") or o.get("status") or "unknown")
                out.append({"name": n, "account": raw.get("account") or raw.get("email") or "", "auth_index": raw.get("auth_index"), "provider": raw.get("provider") or "", "type": str(self.ns["get_item_type"](raw) or ""), "status": st, "disabled": bool(raw.get("disabled")), "stream_error_active": self.ns["_is_stream_error_active"](st, raw.get("status_message") or ""), "standby": n in self.standby, "invalid_401": bool(o.get("invalid_401")), "invalid_quota": bool(o.get("invalid_quota")), "used_percent": o.get("used_percent"), "primary_used_percent": o.get("primary_used_percent"), "individual_used_percent": o.get("individual_used_percent"), "reset_at": o.get("reset_at"), "quota_source": o.get("quota_source"), "check_error": o.get("check_error") or "", "raw": raw})
            self.rows = sorted(out, key=lambda x: (x.get("name") or "").lower())
        return {"loaded": len(files)}

    def _cands(self, names=None, include_closed=False):
        wanted = set(_names(names))
        rt = self._runtime(False)
        out = []
        with self.lock:
            self._refresh_standby_from_rows_locked()
            for a in self.rows:
                if wanted and a.get("name") not in wanted:
                    continue
                if not include_closed and a.get("disabled"):
                    continue
                if a.get("standby"):
                    continue
                if rt["target_type"] and str(a.get("type") or "").lower() != rt["target_type"]:
                    continue
                if rt["provider"] and str(a.get("provider") or "").lower() != rt["provider"]:
                    continue
                r = a.get("raw") or {}
                if r.get("auth_index"):
                    out.append(r)
        return out

    def _raw_matches_target(self, raw, rt):
        item_type = str(self.ns["get_item_type"](raw) or "").lower()
        item_provider = str(raw.get("provider") or "").lower()
        if rt["target_type"] and item_type != rt["target_type"]:
            return False
        if rt["provider"] and item_provider != rt["provider"]:
            return False
        if not raw.get("auth_index"):
            return False
        return True

    def _collect_standby_candidates(self, files, rt, exclude_names=None):
        ex = set(exclude_names or [])
        out = []
        for raw in (files or []):
            name = str(raw.get("name") or "").strip()
            if not name or name not in self.standby:
                continue
            if name in ex:
                continue
            if not self._raw_matches_target(raw, rt):
                continue
            out.append(raw)
        return out

    def _collect_closed_candidates(self, files, rt, exclude_names=None):
        ex = set(exclude_names or [])
        out = []
        for raw in (files or []):
            name = str(raw.get("name") or "").strip()
            if not bool(raw.get("disabled")):
                continue
            if name in self.standby:
                continue
            if name and name in ex:
                continue
            if not self._raw_matches_target(raw, rt):
                continue
            out.append(raw)
        return out

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

    def _scan_for_recovery(self, rt, candidates, need_count=None):
        if not candidates:
            return {"scanned": 0, "recoverable": [], "recoverable_all": [], "invalid_401": [], "invalid_quota": [], "errors": []}

        target = None
        if need_count is not None:
            try:
                target = max(0, int(need_count))
            except Exception:
                target = 0
            if target <= 0:
                return {"scanned": 0, "recoverable": [], "recoverable_all": [], "invalid_401": [], "invalid_quota": [], "errors": []}

        refreshed = {}
        try:
            files = self.ns["refresh_quota_source"](rt["base"], rt["token"], rt["timeout"])
            for f in files:
                ai = f.get("auth_index")
                if ai:
                    refreshed[ai] = f
        except Exception:
            refreshed = {}

        recoverable = []
        recoverable_set = set()
        recoverable_all = []
        invalid_401 = set()
        invalid_quota = set()
        errors = []
        scanned = 0

        chunk_size = max(1, min(len(candidates), max(1, rt["workers"])))
        for i in range(0, len(candidates), chunk_size):
            if target is not None and len(recoverable) >= target:
                break
            chunk = candidates[i : i + chunk_size]
            if not chunk:
                continue

            probe = asyncio.run(
                self.ns["probe_accounts"](
                    rt["base"],
                    rt["token"],
                    chunk,
                    rt["ua"],
                    rt["chat_id"],
                    rt["workers"],
                    rt["timeout"],
                    rt["retries"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed,
                )
            )
            quota = asyncio.run(
                self.ns["check_quota_accounts"](
                    rt["base"],
                    rt["token"],
                    chunk,
                    rt["ua"],
                    rt["chat_id"],
                    rt["quota_workers"],
                    rt["timeout"],
                    rt["retries"],
                    rt["weekly"],
                    rt["primary"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed,
                )
            )
            scanned += len(chunk)

            # 回写本地行状态
            self._apply_probe(probe)
            self._apply_quota(quota)

            p_by_key = {}
            q_by_key = {}
            for r in probe:
                key = str(r.get("auth_index") or "")
                name = str(r.get("name") or "")
                if key:
                    p_by_key[f"ai:{key}"] = r
                if name:
                    p_by_key[f"name:{name}"] = r
                if r.get("invalid_401") and name:
                    invalid_401.add(name)
                if r.get("error"):
                    errors.append(f"{name}: {r.get('error')}")
            for r in quota:
                key = str(r.get("auth_index") or "")
                name = str(r.get("name") or "")
                if key:
                    q_by_key[f"ai:{key}"] = r
                if name:
                    q_by_key[f"name:{name}"] = r
                if r.get("invalid_quota") and name:
                    invalid_quota.add(name)
                if r.get("error"):
                    errors.append(f"{name}: {r.get('error')}")

            for item in chunk:
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                ai = str(item.get("auth_index") or "").strip()
                key = f"ai:{ai}" if ai else f"name:{name}"
                p = p_by_key.get(key) or p_by_key.get(f"name:{name}")
                q = q_by_key.get(key) or q_by_key.get(f"name:{name}")
                if self._is_recoverable_by_scan(p, q):
                    if name not in recoverable_set:
                        recoverable_set.add(name)
                        recoverable_all.append(name)
                        if target is None or len(recoverable) < target:
                            recoverable.append(name)
                        if target is not None and len(recoverable) >= target:
                            break

        return {
            "scanned": scanned,
            "recoverable": recoverable,
            "recoverable_all": recoverable_all,
            "invalid_401": sorted(invalid_401),
            "invalid_quota": sorted(invalid_quota),
            "errors": errors,
        }

    def _apply_probe(self, results):
        with self.lock:
            by_ai = {x.get("auth_index"): x for x in self.rows if x.get("auth_index")}
            by_n = {x.get("name"): x for x in self.rows if x.get("name")}
            for r in results:
                a = by_ai.get(r.get("auth_index")) or by_n.get(r.get("name"))
                if not a:
                    continue
                sc = r.get("status_code")
                a["invalid_401"] = bool(r.get("invalid_401"))
                a["check_error"] = r.get("error") or ""
                if sc == 200:
                    a["status"] = "active"
                elif sc in (401, 429, 403, 500):
                    a["status"] = "error"

    def _apply_quota(self, results):
        with self.lock:
            by_ai = {x.get("auth_index"): x for x in self.rows if x.get("auth_index")}
            by_n = {x.get("name"): x for x in self.rows if x.get("name")}
            for r in results:
                a = by_ai.get(r.get("auth_index")) or by_n.get(r.get("name"))
                if not a:
                    continue
                a["invalid_quota"] = bool(r.get("invalid_quota"))
                a["used_percent"] = r.get("used_percent")
                a["primary_used_percent"] = r.get("primary_used_percent")
                a["individual_used_percent"] = r.get("individual_used_percent")
                a["reset_at"] = r.get("reset_at")
                a["quota_source"] = r.get("quota_source")
                if r.get("error"):
                    a["check_error"] = r.get("error")

    def check401(self, names=None):
        if not self.rows:
            self.refresh()
        rt = self._runtime(True)
        c = self._cands(names, include_closed=False)
        if not c:
            return {"checked": 0, "invalid_401": 0}
        ret = asyncio.run(self.ns["probe_accounts"](rt["base"], rt["token"], c, rt["ua"], rt["chat_id"], rt["workers"], rt["timeout"], rt["retries"]))
        self._apply_probe(ret)
        bad = [x for x in ret if x.get("invalid_401")]
        self.ns["write_json_file"](self._out_path(self.conf.get("output") or self.ns["DEFAULT_OUTPUT"]), bad)
        return {"checked": len(ret), "invalid_401": len(bad)}

    def check_quota(self, names=None):
        if not self.rows:
            self.refresh()
        rt = self._runtime(True)
        c = self._cands(names, include_closed=False)
        if not c:
            return {"checked": 0, "invalid_quota": 0}
        ret = asyncio.run(self.ns["check_quota_accounts"](rt["base"], rt["token"], c, rt["ua"], rt["chat_id"], rt["quota_workers"], rt["timeout"], rt["retries"], rt["weekly"], rt["primary"]))
        self._apply_quota(ret)
        bad = [x for x in ret if x.get("invalid_quota")]
        self.ns["write_json_file"](self._out_path(self.conf.get("quota_output") or self.ns["DEFAULT_QUOTA_OUTPUT"]), bad)
        return {"checked": len(ret), "invalid_quota": len(bad)}

    def check_all(self, names=None):
        if not self.rows:
            self.refresh()
        rt = self._runtime(True)
        # 自动巡检主联合检测只扫描非关闭账号，避免在账号量大时一次性拉起海量任务。
        # 已关闭账号的补位检测在 _auto_once 的“缺口补位”流程里按需执行。
        c = self._cands(names, include_closed=False)
        if not c:
            return {"checked": 0, "invalid_401": 0, "invalid_quota": 0}
        refreshed = {}
        try:
            for it in self.ns["refresh_quota_source"](rt["base"], rt["token"], rt["timeout"]):
                if it.get("auth_index"):
                    refreshed[it.get("auth_index")] = it
        except Exception:
            refreshed = {}

        # 分块处理，避免 candidates 很大时一次性创建过多协程任务导致 CPU/内存冲高
        chunk_size = max(1, min(len(c), max(1, max(rt["workers"], rt["quota_workers"]))))
        all_probe = []
        all_quota = []
        for i in range(0, len(c), chunk_size):
            chunk = c[i : i + chunk_size]
            p = asyncio.run(
                self.ns["probe_accounts"](
                    rt["base"],
                    rt["token"],
                    chunk,
                    rt["ua"],
                    rt["chat_id"],
                    rt["workers"],
                    rt["timeout"],
                    rt["retries"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed,
                )
            )
            q = asyncio.run(
                self.ns["check_quota_accounts"](
                    rt["base"],
                    rt["token"],
                    chunk,
                    rt["ua"],
                    rt["chat_id"],
                    rt["quota_workers"],
                    rt["timeout"],
                    rt["retries"],
                    rt["weekly"],
                    rt["primary"],
                    refresh_candidates=False,
                    refreshed_by_auth_index=refreshed,
                )
            )
            all_probe.extend(p)
            all_quota.extend(q)
            self._apply_probe(p)
            self._apply_quota(q)

        bad401 = [x for x in all_probe if x.get("invalid_401")]
        badq = [x for x in all_quota if x.get("invalid_quota")]
        self.ns["write_json_file"](self._out_path(self.conf.get("output") or self.ns["DEFAULT_OUTPUT"]), bad401)
        self.ns["write_json_file"](self._out_path(self.conf.get("quota_output") or self.ns["DEFAULT_QUOTA_OUTPUT"]), badq)
        return {"checked": len(c), "invalid_401": len(bad401), "invalid_quota": len(badq)}

    def close(self, names, track_progress=False):
        n = _names(names)
        if not n:
            return {"selected": 0, "success": 0, "failed": 0, "ok_names": []}
        rt = self._runtime(True)
        if track_progress:
            self._progress_start("close", len(n))
        try:
            ret = asyncio.run(
                self._set_disabled_with_progress(
                    rt["base"],
                    rt["token"],
                    n,
                    True,
                    rt["close_workers"],
                    rt["timeout"],
                    track=bool(track_progress),
                )
            )
        except Exception as e:
            if track_progress:
                self._progress_finish(f"关闭失败: {e}")
            raise
        ok = {x.get("name") for x in ret if x.get("updated")}
        with self.lock:
            for a in self.rows:
                if a.get("name") in ok:
                    a["disabled"] = True
        ok_names = sorted([x for x in ok if x])
        if track_progress:
            self._progress_finish(f"关闭完成: 成功={len(ok)} 失败={len(n) - len(ok)}")
        self._log(f"关闭账号: selected={len(n)} success={len(ok)} failed={len(n) - len(ok)} names={self._names_preview(ok_names)}")
        return {"selected": len(n), "success": len(ok), "failed": len(n) - len(ok), "ok_names": ok_names}

    def recover(self, names, drop_standby=False):
        n = _names(names)
        if not n:
            return {"selected": 0, "success": 0, "failed": 0, "ok_names": []}
        rt = self._runtime(True)
        ret = asyncio.run(self.ns["enable_names"](rt["base"], rt["token"], n, rt["enable_workers"], rt["timeout"]))
        ok = {x.get("name") for x in ret if x.get("updated")}
        with self.lock:
            if drop_standby:
                self._refresh_standby_from_rows_locked()
            for a in self.rows:
                if a.get("name") in ok:
                    a["disabled"] = False
            if drop_standby and ok:
                for name in ok:
                    if name in self.standby:
                        self.standby.remove(name)
                for a in self.rows:
                    if a.get("name") in ok:
                        a["standby"] = False
        if drop_standby and ok:
            self._save_standby()
        ok_names = sorted([x for x in ok if x])
        self._log(f"开启账号: selected={len(n)} success={len(ok)} failed={len(n) - len(ok)} names={self._names_preview(ok_names)}")
        return {"selected": len(n), "success": len(ok), "failed": len(n) - len(ok), "ok_names": ok_names}

    def add_standby(self, names):
        n = _names(names)
        add = 0
        with self.lock:
            self._refresh_standby_from_rows_locked()
            for x in n:
                if x not in self.standby:
                    self.standby.add(x)
                    add += 1
            for a in self.rows:
                a["standby"] = a.get("name") in self.standby
        self._save_standby()
        self._log(f"加入备用池: selected={len(n)} added={add} names={self._names_preview(n)}")
        return {"selected": len(n), "added": add}

    def rm_standby(self, names):
        n = _names(names)
        rm = 0
        with self.lock:
            self._refresh_standby_from_rows_locked()
            for x in n:
                if x in self.standby:
                    self.standby.remove(x)
                    rm += 1
            for a in self.rows:
                a["standby"] = a.get("name") in self.standby
        self._save_standby()
        return {"selected": len(n), "removed": rm}

    def promote_standby(self, names):
        selected = _names(names)
        if not selected:
            return {"selected": 0, "scanned": 0, "recoverable": 0, "enabled": 0, "moved_401": 0, "moved_closed": 0, "skipped_by_target": 0}

        rt = self._runtime(True)
        files = self.ns["fetch_auth_files"](rt["base"], rt["token"], rt["timeout"])
        with self.lock:
            self._refresh_standby_for_files_locked(files)
        candidates = self._collect_standby_candidates(files, rt)
        selected_set = set(selected)
        candidates = [x for x in candidates if str(x.get("name") or "").strip() in selected_set]
        if not candidates:
            return {"selected": len(selected), "scanned": 0, "recoverable": 0, "enabled": 0, "moved_401": 0, "moved_closed": 0, "skipped_by_target": 0}

        target = int(rt.get("auto_target") or 0)
        current_active = self._active_count()
        need_count = None if target <= 0 else max(0, target - current_active)
        scan = self._scan_for_recovery(rt, candidates, need_count=need_count)

        recoverable_names = list(scan.get("recoverable") or [])
        enabled_set = set()
        if recoverable_names:
            enabled = self.recover(recoverable_names, drop_standby=True)
            enabled_set = set(enabled.get("ok_names") or [])

        invalid_401 = set(scan.get("invalid_401") or [])
        invalid_quota = set(scan.get("invalid_quota") or [])

        moved_401 = 0
        moved_closed = 0
        with self.lock:
            for row in self.rows:
                name = str(row.get("name") or "").strip()
                if not name or name not in selected_set:
                    continue
                # 默认保留备用；在迁移场景再改状态
                row["standby"] = True
                self.standby.add(name)
                if name in invalid_401:
                    moved_401 += 1
                    row["standby"] = False
                    self.standby.discard(name)
                    row["disabled"] = False
                    row["invalid_401"] = True
                    continue
                if name in invalid_quota:
                    moved_closed += 1
                    row["standby"] = False
                    self.standby.discard(name)
                    row["disabled"] = True
                    row["invalid_quota"] = True
                    continue
                if name in enabled_set:
                    row["standby"] = False
                    self.standby.discard(name)
                    row["disabled"] = False
                else:
                    row["disabled"] = True
        self._save_standby()
        skipped = max(0, len(scan.get("recoverable_all") or []) - len(recoverable_names))
        return {
            "selected": len(selected),
            "scanned": int(scan.get("scanned") or 0),
            "recoverable": len(scan.get("recoverable_all") or []),
            "enabled": len(enabled_set),
            "moved_401": moved_401,
            "moved_closed": moved_closed,
            "skipped_by_target": skipped,
            "error_count": len(scan.get("errors") or []),
        }

    def recover_closed_accounts(self, names=None):
        rt = self._runtime(True)
        selected = set(_names(names))
        files = self.ns["fetch_auth_files"](rt["base"], rt["token"], rt["timeout"])
        with self.lock:
            self._refresh_standby_for_files_locked(files)
        closed = self._collect_closed_candidates(files, rt)
        if selected:
            closed = [x for x in closed if str(x.get("name") or "").strip() in selected]
        if not closed:
            return {"candidates": 0, "scanned": 0, "recoverable": 0, "enabled": 0, "to_standby": 0, "skipped_by_target": 0}

        target = int(rt.get("auto_target") or 0)
        current_active = self._active_count()
        need_count = None if target <= 0 else max(0, target - current_active)
        if target > 0 and need_count <= 0:
            return {"candidates": len(closed), "scanned": 0, "recoverable": 0, "enabled": 0, "to_standby": 0, "skipped_by_target": 0}

        scan = self._scan_for_recovery(rt, closed, need_count=need_count)
        names_to_enable = list(scan.get("recoverable") or [])
        enabled_set = set()
        if names_to_enable:
            enabled = self.recover(names_to_enable, drop_standby=True)
            enabled_set = set(enabled.get("ok_names") or [])

        # 本轮已扫可用但受目标限制未开启 -> 转备用池并关闭
        recoverable_all = set(scan.get("recoverable_all") or [])
        to_standby = sorted(recoverable_all - set(names_to_enable))
        standby_moved = 0
        if to_standby:
            close_ret = self.close(to_standby)
            closed_ok = set(close_ret.get("ok_names") or [])
            if closed_ok:
                self.add_standby(sorted(closed_ok))
                standby_moved = len(closed_ok)

        return {
            "candidates": len(closed),
            "scanned": int(scan.get("scanned") or 0),
            "recoverable": len(recoverable_all),
            "enabled": len(enabled_set),
            "to_standby": standby_moved,
            "skipped_by_target": max(0, len(recoverable_all) - len(names_to_enable)),
            "error_count": len(scan.get("errors") or []),
        }

    def delete(self, names):
        n = _names(names)
        if not n:
            return {"selected": 0, "success": 0, "failed": 0}
        rt = self._runtime(True)
        ret = asyncio.run(self.ns["delete_names"](rt["base"], rt["token"], n, rt["delete_workers"], rt["timeout"]))
        ok = {x.get("name") for x in ret if x.get("deleted")}
        with self.lock:
            self._refresh_standby_from_rows_locked()
            self.rows = [x for x in self.rows if x.get("name") not in ok]
            self.standby = {x for x in self.standby if x not in ok}
        self._save_standby()
        self._log(f"删除账号: selected={len(n)} success={len(ok)} failed={len(n) - len(ok)} names={self._names_preview(sorted([x for x in ok if x]))}")
        return {"selected": len(n), "success": len(ok), "failed": len(n) - len(ok)}

    def _auto_once(self):
        rt = self._runtime(True)
        s = self.check_all(None)
        with self.lock:
            bad401 = [x.get("name") for x in self.rows if x.get("invalid_401")]
            badq = [x.get("name") for x in self.rows if x.get("invalid_quota")]
        h401 = 0
        hq = 0
        if rt["auto_401"] == "delete" and bad401:
            h401 = self.delete(bad401).get("success", 0)
        if rt["auto_quota"] == "close" and badq:
            hq = self.close(badq).get("success", 0)
        elif rt["auto_quota"] == "delete" and badq:
            hq = self.delete(badq).get("success", 0)

        # 对齐桌面版：活跃账号目标数是“上限”
        overflow_total = 0
        overflow_closed = 0
        target = int(rt.get("auto_target") or 0)
        if target > 0:
            with self.lock:
                active_names = [x.get("name") for x in self.rows if self._bucket(x) == "active" and x.get("name")]
            if len(active_names) > target:
                overflow_names = active_names[target:]
                overflow_total = len(overflow_names)
                if overflow_names:
                    close_ret = self.close(overflow_names)
                    closed_names = close_ret.get("ok_names") or []
                    overflow_closed = len(closed_names)
                    if closed_names:
                        self.add_standby(closed_names)

        # 对齐桌面版：目标不足时，先从备用池补；可选从已关闭池补
        refill_need = 0
        standby_scanned = 0
        standby_recoverable = 0
        standby_enabled = 0
        closed_scanned = 0
        closed_recoverable = 0
        closed_enabled = 0
        closed_overflow_to_standby = 0
        refill_errors = []
        if target > 0:
            with self.lock:
                active_after_overflow = len([x for x in self.rows if self._bucket(x) == "active"])
            refill_need = max(0, target - active_after_overflow)
            if refill_need > 0:
                files = self.ns["fetch_auth_files"](rt["base"], rt["token"], rt["timeout"])
                with self.lock:
                    self._refresh_standby_for_files_locked(files)

                standby_candidates = self._collect_standby_candidates(files, rt)
                standby_scan = self._scan_for_recovery(rt, standby_candidates, need_count=refill_need)
                standby_scanned = int(standby_scan.get("scanned") or 0)
                standby_recoverable = len(standby_scan.get("recoverable") or [])
                refill_errors.extend(standby_scan.get("errors") or [])
                picked = list(standby_scan.get("recoverable") or [])

                remaining = max(0, refill_need - len(picked))
                if remaining > 0 and rt.get("auto_fill"):
                    closed_candidates = self._collect_closed_candidates(files, rt, exclude_names=picked)
                    closed_scan = self._scan_for_recovery(rt, closed_candidates, need_count=remaining)
                    closed_scanned = int(closed_scan.get("scanned") or 0)
                    closed_recoverable = len(closed_scan.get("recoverable") or [])
                    refill_errors.extend(closed_scan.get("errors") or [])
                    picked.extend(closed_scan.get("recoverable") or [])

                    recoverable_all = set(closed_scan.get("recoverable_all") or [])
                    picked_from_closed = set(closed_scan.get("recoverable") or [])
                    overflow_set = recoverable_all - picked_from_closed
                    if overflow_set:
                        self.add_standby(sorted(overflow_set))
                        closed_overflow_to_standby = len(overflow_set)

                if picked:
                    enable_ret = self.recover(picked, drop_standby=True)
                    enabled_names = set(enable_ret.get("ok_names") or [])
                    standby_enabled = len([x for x in enabled_names if x in set(standby_scan.get("recoverable") or [])])
                    closed_enabled = len(enabled_names) - standby_enabled

        result = {
            "scan": s,
            "handled_401": h401,
            "handled_quota": hq,
            "target_active": target,
            "overflow_total": overflow_total,
            "overflow_closed": overflow_closed,
            "refill_need": refill_need,
            "standby_scanned": standby_scanned,
            "standby_recoverable": standby_recoverable,
            "standby_enabled": standby_enabled,
            "closed_scanned": closed_scanned,
            "closed_recoverable": closed_recoverable,
            "closed_enabled": closed_enabled,
            "closed_overflow_to_standby": closed_overflow_to_standby,
            "refill_error_count": len(refill_errors),
        }
        self._log(
            "自动巡检完成: "
            f"checked={s.get('checked', 0)} "
            f"bad401={s.get('invalid_401', 0)} bad_quota={s.get('invalid_quota', 0)} "
            f"handled401={h401} handled_quota={hq} "
            f"refill_need={refill_need} standby_enabled={standby_enabled} closed_enabled={closed_enabled} | "
            + self._status_summary_text()
        )
        return result

    def auto_start(self):
        with self.lock:
            if self.auto_running:
                return {"started": False}
            self.auto_running = True
            self.auto_status = "运行中"
            self.auto_last = {}
            self.auto_stop.clear()
        self._log("自动巡检已启动")
        def w():
            while not self.auto_stop.is_set():
                try:
                    d = self._auto_once()
                    with self.lock:
                        self.auto_last = d
                        self.auto_status = "运行中"
                except Exception as e:
                    with self.lock:
                        self.auto_status = f"异常: {e}"
                    self._log(f"自动巡检异常: {e}")

                wait_total = max(1, self._runtime(False)["auto_intv"] * 60)
                waited = 0
                while waited < wait_total and not self.auto_stop.is_set():
                    left = wait_total - waited
                    self._log(f"自动巡检状态心跳: {self._status_summary_text()} next_scan_in={left}s")
                    step = min(10, left)
                    if self.auto_stop.wait(step):
                        break
                    waited += step
            with self.lock:
                self.auto_running = False
                if self.auto_status == "运行中":
                    self.auto_status = "已停止"
            self._log("自动巡检线程已停止")
        threading.Thread(target=w, daemon=True).start()
        return {"started": True}

    def auto_stop_now(self):
        with self.lock:
            self.auto_running = False
            self.auto_status = "已停止"
        self.auto_stop.set()
        self._log("收到停止自动巡检请求")
        return {"stopped": True}


class AuthManager:
    def __init__(self, conf, config_path, save_cb):
        self.cookie_name = "cliproxy_session"
        self.session_ttl = 24 * 60 * 60
        self._save_cb = save_cb
        self.config_path = str(config_path or "")
        self.lock = threading.RLock()
        self.sessions = {}
        self.enabled = False
        self.username = ""
        self.password = ""
        self.config_error = ""
        self.refresh(conf, config_exists=os.path.exists(self.config_path))
        self.ensure_config_keys(conf)

    def ensure_config_keys(self, conf):
        changed = False
        if "web_login_username" not in conf:
            conf["web_login_username"] = ""
            changed = True
        if "web_login_password" not in conf:
            conf["web_login_password"] = ""
            changed = True
        if changed:
            try:
                self._save_cb()
            except Exception as e:
                self.config_error = f"config.json 无法写入登录字段: {e}"

    def refresh(self, conf, config_exists=True):
        with self.lock:
            self._cleanup_sessions()
            self.config_error = ""
            user = conf.get("web_login_username")
            pwd = conf.get("web_login_password")
            if user is None and pwd is None:
                self.enabled = False
                self.username = ""
                self.password = ""
                if not config_exists:
                    self.config_error = "config.json 不存在，当前按免登录模式运行。"
                return
            if not isinstance(user, str) or not isinstance(pwd, str):
                self.enabled = False
                self.username = ""
                self.password = ""
                self.config_error = "登录配置字段类型错误，已降级为免登录。"
                return
            user = user.strip()
            pwd = pwd.strip()
            if not user and not pwd:
                self.enabled = False
                self.username = ""
                self.password = ""
                return
            if not user or not pwd:
                self.enabled = False
                self.username = ""
                self.password = ""
                self.config_error = "登录配置不完整（需同时填写账号和密码），已降级为免登录。"
                return
            if len(user) > 128 or len(pwd) > 256:
                self.enabled = False
                self.username = ""
                self.password = ""
                self.config_error = "登录配置长度不合法，已降级为免登录。"
                return
            self.enabled = True
            self.username = user
            self.password = pwd

    def _cleanup_sessions(self):
        now = int(time.time())
        expired = [k for k, v in self.sessions.items() if int(v or 0) <= now]
        for k in expired:
            self.sessions.pop(k, None)

    def _extract_cookie_token(self, headers):
        cookie = str(headers.get("Cookie") or "")
        if not cookie:
            return ""
        for part in cookie.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) != 2:
                continue
            if kv[0].strip() == self.cookie_name:
                return kv[1].strip()
        return ""

    def _is_authenticated_locked(self, headers):
        if not self.enabled:
            return True
        self._cleanup_sessions()
        token = self._extract_cookie_token(headers)
        return bool(token and token in self.sessions)

    def is_authenticated(self, headers):
        with self.lock:
            return self._is_authenticated_locked(headers)

    def login(self, username, password):
        u = str(username or "").strip()
        p = str(password or "").strip()
        if len(u) < 1 or len(p) < 1 or len(u) > 128 or len(p) > 256:
            return {"ok": False, "error": "账号或密码错误。"}
        if any(ord(ch) < 32 for ch in (u + p)):
            return {"ok": False, "error": "输入格式不合法。"}
        with self.lock:
            if not self.enabled:
                return {"ok": True, "token": ""}
            if not (hmac.compare_digest(u, self.username) and hmac.compare_digest(p, self.password)):
                return {"ok": False, "error": "账号或密码错误。"}
            token = secrets.token_urlsafe(32)
            self.sessions[token] = int(time.time()) + self.session_ttl
            return {"ok": True, "token": token}

    def logout(self, headers):
        with self.lock:
            token = self._extract_cookie_token(headers)
            if token:
                self.sessions.pop(token, None)
            return {"ok": True}

    def auth_state(self, headers):
        with self.lock:
            return {
                "ok": True,
                "enabled": self.enabled,
                "authenticated": self._is_authenticated_locked(headers),
                "config_error": self.config_error,
            }

    def cookie_header(self, token):
        if not token:
            return f"{self.cookie_name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        return f"{self.cookie_name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={self.session_ttl}"



WEB_PAGE = r"""<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CliproxyAccountCleaner v1.4.0</title>
<style>
:root{--bg:#fff4f9;--panel:#fffafc;--line:#efbfd3;--line2:#f6d7e5;--btn:#ff78ac;--btn2:#ff5a98;--text:#5a3146;--thead:#ffe7f2}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:radial-gradient(circle at 10% -10%,#ffe8f2 0,#fff4f9 40%,#ffeef6 100%);color:var(--text);font-family:"Microsoft YaHei","Segoe UI",Tahoma,sans-serif;font-size:14px}
.window{margin:10px;border:1px solid var(--line);background:var(--panel);min-height:calc(100% - 20px);display:flex;flex-direction:column;border-radius:16px;overflow:hidden;box-shadow:0 10px 26px rgba(214,95,144,.16)}
.topline{padding:10px 12px;border-bottom:1px solid var(--line2);background:linear-gradient(90deg,#fff8fc,#fff1f8);display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
.toolbar{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid #f2a4c4;background:var(--btn);color:#fff;padding:6px 14px;cursor:pointer;border-radius:10px;min-height:34px;transition:all .18s}.btn:hover{background:var(--btn2)}.btn:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(255,127,176,.22)}.btn:active{transform:translateY(1px)}.btn:disabled{opacity:.55;cursor:not-allowed}.btn.danger{background:#ff5f80;border-color:#f39cb4}
.section{padding:8px 10px 0}.title{font-size:16px;color:#2b3b50;margin:2px 0 8px}
.row{display:grid;grid-template-columns:repeat(12,minmax(80px,1fr));gap:8px 10px;margin-bottom:8px}.field{display:flex;align-items:center;gap:6px;min-width:0}.field label{white-space:nowrap}.field input,.field select{height:34px;border:1px solid var(--line);background:#fff;padding:3px 8px;width:100%;border-radius:10px;outline:none}.field input:focus,.field select:focus{border-color:#ff92bf;box-shadow:0 0 0 4px rgba(255,142,190,.16)}
.s2{grid-column:span 2}.s3{grid-column:span 3}.s4{grid-column:span 4}.s5{grid-column:span 5}.s6{grid-column:span 6}.note{border:1px solid var(--line2);background:#fff4fa;padding:7px 9px;margin-bottom:8px;color:#8a5d73;border-radius:10px}
.ops{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}.ops .btn{min-width:102px;padding:6px 10px}
.table-wrap{margin:0 10px 10px;border:1px solid var(--line);background:#fff;display:flex;flex-direction:column;min-height:300px;max-height:52vh;border-radius:12px;overflow:hidden}.scroll{overflow:auto;flex:1}table{width:100%;border-collapse:collapse;table-layout:fixed}
thead th{position:sticky;top:0;background:var(--thead);border-bottom:1px solid var(--line);padding:8px 6px;text-align:left}
tbody td{border-bottom:1px solid #f8ddeb;padding:7px 6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:#fff}tbody tr:hover td{background:#fff4fa}tbody tr.sel td{background:#ffe8f3}
.statusbar{border-top:1px solid var(--line2);padding:8px 10px;background:#fff4fa;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
.modal-mask{position:fixed;inset:0;background:rgba(78,21,45,.28);display:none;align-items:center;justify-content:center;padding:20px}.modal{width:min(760px,100%);background:#fffafc;border:1px solid var(--line);box-shadow:0 8px 22px rgba(94,36,66,.22);padding:14px;border-radius:14px}.modal pre{white-space:pre-wrap;max-height:58vh;overflow:auto;background:#fff6fb;border:1px solid var(--line2);padding:10px;border-radius:10px}
.login-mask{position:fixed;inset:0;background:rgba(252,236,245,.88);backdrop-filter:blur(2px);display:none;align-items:center;justify-content:center;padding:16px;z-index:9999}
.login-card{width:min(420px,100%);background:#fff;border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 28px rgba(214,95,144,.25);padding:18px}
.login-card h2{margin:0 0 6px;color:#c24f83}.login-card p{margin:0 0 12px;color:#8a5d73}
.login-card .err{min-height:20px;color:#d73662;font-size:13px}
@media (max-width:980px){.row{grid-template-columns:repeat(6,minmax(80px,1fr))}.s6,.s5,.s4,.s3,.s2{grid-column:span 6}.table-wrap{max-height:45vh}}
</style></head><body>
<div class="login-mask" id="loginMask">
<div class="login-card">
<h2>登录系统</h2>
<p>请输入账号和密码后继续</p>
<div class="field" style="margin-bottom:10px"><label style="min-width:60px">账号</label><input id="loginUser" maxlength="128" autocomplete="username"></div>
<div class="field" style="margin-bottom:10px"><label style="min-width:60px">密码</label><input id="loginPass" type="password" maxlength="256" autocomplete="current-password"></div>
<div class="err" id="loginErr"></div>
<div style="display:flex;gap:8px"><button class="btn" id="btnDoLogin">登录</button><button class="btn" id="btnLoginClear" type="button">清空</button></div>
<div class="note" id="loginHint" style="margin-top:10px;display:none"></div>
</div></div>
<div class="window">
<div class="topline"><div id="summaryLine">加载中...</div><div class="toolbar"><button class="btn" id="btnRefreshTop">刷新账号列表</button><button class="btn" id="btnHelp">使用说明</button><button class="btn danger" id="btnLogout">退出登录</button></div></div>
<div class="section"><div class="title">连接与检测参数</div><div class="row">
<div class="field s6"><label>管理端地址 (base_url)</label><input id="base_url" placeholder="https://your-cliproxy-host"></div>
<div class="field s6"><label>访问令牌 (token / cpa_password)</label><input id="token" type="password"></div>
<div class="field s2"><label>401 检测并发</label><input id="workers" type="number"></div>
<div class="field s2"><label>额度检测并发</label><input id="quota_workers" type="number"></div>
<div class="field s2"><label>删除并发</label><input id="delete_workers" type="number"></div>
<div class="field s2"><label>关闭并发</label><input id="close_workers" type="number"></div>
<div class="field s2"><label>恢复并发</label><input id="enable_workers" type="number"></div>
<div class="field s2"><label>重试次数</label><input id="retries" type="number"></div>
<div class="field s2"><label>超时秒</label><input id="timeout" type="number"></div>
<div class="field s2"><label>周额度阈值 (%)</label><input id="weekly_quota_threshold" type="number"></div>
<div class="field s2"><label>5 小时额度阈值 (%)</label><input id="primary_quota_threshold" type="number"></div>
<div class="field s2"><label>活跃账号目标数</label><input id="auto_keep_active_count" type="number"></div>
<div class="field s3"><label>账号类型筛选</label><input id="target_type"></div>
<div class="field s3"><label>Provider 筛选</label><input id="provider"></div>
<div class="field s6"><label>ChatGPT Account ID (可选)</label><input id="chatgpt_account_id"></div>
</div></div>
<div class="section"><div class="title">自动巡检设置</div><div class="row">
<div class="field s2"><label>巡检间隔 (分钟)</label><input id="auto_check_interval_minutes" type="number"></div>
<div class="field s2"><label>401 账号处理</label><select id="auto_401_action"><option value="delete">删除</option><option value="mark">仅标记</option></select></div>
<div class="field s2"><label>额度耗尽账号处理</label><select id="auto_quota_action"><option value="close">关闭</option><option value="delete">删除</option><option value="mark">仅标记</option></select></div>
<div class="field s4"><label><input id="auto_allow_closed_scan" type="checkbox" style="width:auto;height:auto">不足时允许从已关闭账号补齐</label></div>
<div class="s2" style="display:flex;gap:8px"><button class="btn" id="btnAutoStart">启动自动巡检</button><button class="btn" id="btnAutoStop">停止</button></div>
</div><div class="note" id="autoLine">自动巡检状态: 未启动</div></div>
<div class="section"><div class="title">筛选与搜索</div><div class="row">
<div class="field s4"><label>关键词</label><input id="keyword" placeholder="账号/邮箱/错误信息"></div>
<div class="field s2"><label>状态筛选</label><select id="statusFilter"><option value="all">全部</option><option value="standby">备用</option><option value="active">活跃</option><option value="unknown">未知</option><option value="closed">已关闭</option><option value="invalid_401">401无效</option><option value="invalid_quota">额度耗尽</option></select></div>
<div class="s6 note">提示: 双击表格行可切换勾选状态，检测类按钮未勾选时默认作用于当前筛选结果。</div></div></div>
<div class="section"><div class="title">批量操作</div>
<div class="ops"><button class="btn" id="btnSelectAll">全选</button><button class="btn" id="btnSelectNone">取消全选</button><button class="btn" id="btnCheck401">检测401无效</button><button class="btn" id="btnCheckQuota">检测额度</button><button class="btn" id="btnCheckAll">检测（401+额度）</button><button class="btn" id="btnClose">关闭选中账号</button><button class="btn" id="btnRecover">恢复已关闭</button><button class="btn" id="btnAddStandby">加入备用池</button><button class="btn" id="btnRemoveStandby">备用转活跃</button><button class="btn danger" id="btnDelete">永久删除</button></div>
<div class="note" id="actionLine">就绪</div></div>
<div class="table-wrap"><div class="scroll"><table><thead><tr><th style="width:42px">#</th><th style="width:310px">账号 / 邮箱</th><th style="width:120px">状态</th><th>额度详情</th><th style="width:290px">错误信息</th></tr></thead><tbody id="rowsBody"></tbody></table></div></div>
<div class="statusbar"><div id="footLeft">显示 0 / 0 个账号</div><div>HsMirageAI小站:ai.hsnb.fun</div></div></div>
<div class="modal-mask" id="helpMask"><div class="modal"><h3>使用说明</h3><pre>1. 填写 base_url 和 token，然后点击“刷新账号列表”。
2. 双击表格行可勾选/取消；也可以用全选按钮。
3. 检测类按钮支持 401、额度、联合检测。
4. 账号动作支持关闭、恢复、加入/移出备用、永久删除。
5. 自动巡检会按间隔循环执行联合检测，并按设置处理异常账号。
6. 恢复已关闭：默认检查全部非备用的已关闭账号；可按筛选缩小范围。
7. 备用转活跃：仅对勾选的备用账号做401+额度检测后再开启。</pre><div style="text-align:right"><button class="btn" id="btnHelpClose">关闭</button></div></div></div>
<script>
const IDS=["base_url","token","target_type","provider","workers","quota_workers","delete_workers","close_workers","enable_workers","timeout","retries","weekly_quota_threshold","primary_quota_threshold","chatgpt_account_id","auto_check_interval_minutes","auto_401_action","auto_quota_action","auto_keep_active_count"];
const NUM=new Set(["workers","quota_workers","delete_workers","close_workers","enable_workers","timeout","retries","weekly_quota_threshold","primary_quota_threshold","auto_check_interval_minutes","auto_keep_active_count"]);
const SEL=new Set();let ROWS=[];let SUM={total:0,active:0,unknown:0,closed:0,standby:0,invalid_401:0,invalid_quota:0};
const AUTH={enabled:false,authenticated:false};
const esc=t=>String(t??"").replace(/[&<>\"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
function showLogin(msg=""){const m=document.getElementById("loginMask");if(m)m.style.display="flex";document.getElementById("loginErr").textContent=msg||""}
function hideLogin(){const m=document.getElementById("loginMask");if(m)m.style.display="none";document.getElementById("loginErr").textContent=""}
function setLoginHint(text){const n=document.getElementById("loginHint");if(!n)return;if(text){n.style.display="block";n.textContent=text}else{n.style.display="none";n.textContent=""}}
async function loadAuthState(){const d=await j("/api/auth/state");AUTH.enabled=!!d.enabled;AUTH.authenticated=!!d.authenticated;setLoginHint(d.config_error||"");if(AUTH.enabled&&!AUTH.authenticated)showLogin();else hideLogin();return d}
function rcfg(){const c={};for(const id of IDS){const e=document.getElementById(id);if(!e)continue;c[id]=NUM.has(id)?Number(e.value||0):e.value;}c.auto_allow_closed_scan=!!document.getElementById("auto_allow_closed_scan").checked;return c}
function wcfg(c){if(!c)return;for(const id of IDS){if(!(id in c))continue;const e=document.getElementById(id);if(e)e.value=c[id]??""}document.getElementById("auto_allow_closed_scan").checked=!!c.auto_allow_closed_scan}
function frows(){const kw=(document.getElementById("keyword").value||"").trim().toLowerCase();const st=document.getElementById("statusFilter").value||"all";return ROWS.filter(r=>{if(st!=="all"&&r.status_key!==st)return false;if(!kw)return true;return [r.name,r.account,r.status,r.usage,r.error].join(" ").toLowerCase().includes(kw)})}
function draw(){const rows=frows();const tb=document.getElementById("rowsBody");if(!rows.length){tb.innerHTML='<tr><td colspan="5">无数据</td></tr>'}else{tb.innerHTML=rows.map(r=>`<tr class="${SEL.has(r.name)?"sel":""}" data-name="${esc(r.name)}"><td><input type="checkbox" data-name="${esc(r.name)}" ${SEL.has(r.name)?"checked":""}></td><td title="${esc(r.name)}">${esc(r.name||r.account||"-")}</td><td>${esc(r.status||"")}</td><td title="${esc(r.usage||"")}">${esc(r.usage||"")}</td><td title="${esc(r.error||"")}">${esc(r.error||"")}</td></tr>`).join("")}document.getElementById("footLeft").textContent=`显示 ${rows.length} / ${SUM.total||0} 个账号`}
function head(auto){document.getElementById("summaryLine").textContent=`加载完成: 总共=${SUM.total||0} 错误401=${SUM.invalid_401||0} 活跃=${SUM.active||0} 未知=${SUM.unknown||0} 已关闭=${SUM.closed||0} 备用=${SUM.standby||0}`;document.getElementById("autoLine").textContent=`自动巡检状态: ${(auto&&auto.status)||"未启动"} (${auto&&auto.running?"运行中":"停止"})`}
function sync(s){if(!s)return;wcfg(s.config||{});ROWS=Array.isArray(s.rows)?s.rows:[];SUM=s.summary||SUM;head(s.auto||{});const ns=new Set(ROWS.map(x=>x.name));for(const n of Array.from(SEL)){if(!ns.has(n))SEL.delete(n)}draw()}
async function j(url,opt){const r=await fetch(url,opt);let d={};try{d=await r.json()}catch(_){d={}}if(r.status===401){const e=new Error("未登录或会话已过期，请重新登录。");e.code=401;throw e}if(!r.ok||d&&d.ok===false)throw new Error((d&&d.error)||`HTTP ${r.status}`);return d}
function detectNames(){const s=Array.from(SEL);return s.length?s:frows().map(x=>x.name)}
let CLOSE_PROGRESS_TIMER=null;
function stopCloseProgressPoll(){if(CLOSE_PROGRESS_TIMER){clearInterval(CLOSE_PROGRESS_TIMER);CLOSE_PROGRESS_TIMER=null}}
async function pollCloseProgressOnce(){const d=await j("/api/progress");const p=d.progress||{};if((p.op||"")!=="close"){return}const total=Number(p.total||0);const done=Number(p.done||0);const success=Number(p.success||0);const failed=Number(p.failed||0);const pct=total>0?Math.floor((done*100)/total):0;document.getElementById("actionLine").textContent=`关闭进度: ${done}/${total} (${pct}%) 成功=${success} 失败=${failed}`;if(!p.running){stopCloseProgressPoll()}}
async function startCloseProgressPoll(){stopCloseProgressPoll();await pollCloseProgressOnce();CLOSE_PROGRESS_TIMER=setInterval(async()=>{try{await pollCloseProgressOnce()}catch(e){if(e.code===401){showLogin(e.message)}stopCloseProgressPoll()}},700)}
const ACTION_LABELS={"refresh":"正在刷新账号列表","check_401":"正在执行 401 无效检测","check_quota":"正在执行额度检测","check_all":"正在执行联合检测（401 + 额度）","close":"正在关闭选中账号","recover_closed":"正在恢复已关闭账号","add_standby":"正在将选中账号加入备用池","remove_standby":"正在将备用账号转为活跃","delete":"正在永久删除选中账号","auto_start":"正在启动自动巡检","auto_stop":"正在停止自动巡检"};
async function run(a,needSel=false,ask=""){const hint=ACTION_LABELS[a]||"执行中";try{let names=[];if(["check_401","check_quota","check_all"].includes(a)){names=detectNames()}else if(needSel){names=Array.from(SEL);if(!names.length){alert("请先勾选账号");return}}if(ask&&!window.confirm(ask))return;const cnt=names.length?` (${names.length} 个账号)`:"";
document.getElementById("actionLine").textContent=hint+cnt+"，请稍候...";if(a==="close"){await startCloseProgressPoll()}const d=await j("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:a,config:rcfg(),selected_names:names})});if(d.state)sync(d.state);stopCloseProgressPoll();document.getElementById("actionLine").textContent=d.message||(hint.replace("正在","")+" 完成")}catch(e){stopCloseProgressPoll();if(e.code===401){showLogin(e.message);return}document.getElementById("actionLine").textContent=hint.replace("正在","")+" 失败: "+e.message}}
document.getElementById("keyword").addEventListener("input",draw);document.getElementById("statusFilter").addEventListener("change",draw);
document.getElementById("rowsBody").addEventListener("change",e=>{const n=e.target&&e.target.dataset&&e.target.dataset.name;if(!n)return;e.target.checked?SEL.add(n):SEL.delete(n);draw()});
document.getElementById("rowsBody").addEventListener("dblclick",e=>{const tr=e.target.closest("tr[data-name]");if(!tr)return;const n=tr.dataset.name;SEL.has(n)?SEL.delete(n):SEL.add(n);draw()});
document.getElementById("btnSelectAll").onclick=()=>{for(const r of frows())SEL.add(r.name);draw()};document.getElementById("btnSelectNone").onclick=()=>{SEL.clear();draw()};
document.getElementById("btnRefreshTop").onclick=()=>run("refresh");document.getElementById("btnCheck401").onclick=()=>run("check_401");document.getElementById("btnCheckQuota").onclick=()=>run("check_quota");document.getElementById("btnCheckAll").onclick=()=>run("check_all");
document.getElementById("btnClose").onclick=()=>run("close",true);document.getElementById("btnRecover").onclick=()=>run("recover_closed",false);document.getElementById("btnAddStandby").onclick=()=>run("add_standby",true);document.getElementById("btnRemoveStandby").onclick=()=>run("remove_standby",true);document.getElementById("btnDelete").onclick=()=>run("delete",true,"确认永久删除选中账号？此操作不可恢复。");
document.getElementById("btnAutoStart").onclick=()=>run("auto_start");document.getElementById("btnAutoStop").onclick=()=>run("auto_stop");
document.getElementById("btnHelp").onclick=()=>document.getElementById("helpMask").style.display="flex";document.getElementById("btnHelpClose").onclick=()=>document.getElementById("helpMask").style.display="none";document.getElementById("helpMask").onclick=e=>{if(e.target.id==="helpMask")e.target.style.display="none"};
document.getElementById("btnLoginClear").onclick=()=>{document.getElementById("loginUser").value="";document.getElementById("loginPass").value="";document.getElementById("loginErr").textContent=""};
document.getElementById("btnDoLogin").onclick=async()=>{try{const username=(document.getElementById("loginUser").value||"").trim();const password=document.getElementById("loginPass").value||"";if(!username||!password){document.getElementById("loginErr").textContent="请输入账号和密码";return}await j("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});document.getElementById("loginPass").value="";await loadAuthState();const d=await j("/api/state");sync(d.state||d)}catch(e){document.getElementById("loginErr").textContent=e.message||"登录失败"}};
document.getElementById("btnLogout").onclick=async()=>{try{await j("/api/auth/logout",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})}catch(_){}showLogin("已退出登录")};
(async()=>{try{await loadAuthState();if(AUTH.enabled&&!AUTH.authenticated){document.getElementById("actionLine").textContent="请先登录";return}const d=await j("/api/state");sync(d.state||d)}catch(e){document.getElementById("actionLine").textContent=`初始化失败: ${e.message}`}})();
</script></body></html>"""


def run_web_mode(host, port, no_browser, ns):
    state = WebState(ns, ns["load_config"](ns["CONFIG_PATH"]), ns["CONFIG_PATH"])
    auth = AuthManager(state.conf, ns["CONFIG_PATH"], state._save)
    BaseHTTPRequestHandler = ns["BaseHTTPRequestHandler"]
    ThreadingHTTPServer = ns["ThreadingHTTPServer"]

    def sync_auth_runtime():
        auth.refresh(state.conf, config_exists=os.path.exists(str(ns["CONFIG_PATH"])))

    def action(payload):
        payload = payload or {}
        state.update_conf(payload.get("config") or {})
        sync_auth_runtime()
        a = str(payload.get("action") or "state").strip().lower()
        names = payload.get("selected_names")
        if a == "state":
            return {"ok": True, "message": "ok", "state": state.snapshot()}
        if a == "refresh":
            d = state.refresh()
            return {"ok": True, "message": f"[刷新账号列表] 完成，共加载 {d.get('loaded', 0)} 个账号", "state": state.snapshot(), "data": d}
        if a == "check_401":
            d = state.check401(names)
            return {"ok": True, "message": f"[401 无效检测] 完成，共检测 {d.get('checked', 0)} 个账号，发现 {d.get('invalid_401', 0)} 个已失效（401）", "state": state.snapshot(), "data": d}
        if a == "check_quota":
            d = state.check_quota(names)
            return {"ok": True, "message": f"[额度检测] 完成，共检测 {d.get('checked', 0)} 个账号，发现 {d.get('invalid_quota', 0)} 个额度耗尽", "state": state.snapshot(), "data": d}
        if a == "check_all":
            d = state.check_all(names)
            return {"ok": True, "message": f"[联合检测（401 + 额度）] 完成，共检测 {d.get('checked', 0)} 个账号，发现 {d.get('invalid_401', 0)} 个已失效（401）、{d.get('invalid_quota', 0)} 个额度耗尽", "state": state.snapshot(), "data": d}
        if a == "close":
            d = state.close(names, track_progress=True); return {"ok": True, "message": f"[关闭账号] 完成，共选中 {d.get('selected', len(names or []))} 个，成功关闭 {d.get('success', 0)} 个，失败 {d.get('failed', 0)} 个", "state": state.snapshot(), "data": d}
        if a == "recover_closed":
            d = state.recover_closed_accounts(names); return {"ok": True, "message": f"[恢复已关闭账号] 完成，成功开启 {d.get('enabled', 0)} 个，转入备用池 {d.get('to_standby', 0)} 个", "state": state.snapshot(), "data": d}
        if a == "add_standby":
            d = state.add_standby(names); return {"ok": True, "message": f"[加入备用池] 完成，共选中 {d.get('selected', len(names or []))} 个，成功加入 {d.get('added', 0)} 个", "state": state.snapshot(), "data": d}
        if a == "remove_standby":
            d = state.promote_standby(names); return {"ok": True, "message": f"[备用转活跃] 完成，成功开启 {d.get('enabled', 0)} 个，其中 {d.get('moved_401', 0)} 个检测为401已失效、{d.get('moved_closed', 0)} 个额度耗尽已关闭", "state": state.snapshot(), "data": d}
        if a == "delete":
            d = state.delete(names); return {"ok": True, "message": f"[永久删除账号] 完成，共选中 {d.get('selected', len(names or []))} 个，成功删除 {d.get('success', 0)} 个，失败 {d.get('failed', 0)} 个", "state": state.snapshot(), "data": d}
        if a == "auto_start":
            d = state.auto_start(); return {"ok": True, "message": "自动巡检已启动" if d.get("started") else "自动巡检已在运行", "state": state.snapshot(), "data": d}
        if a == "auto_stop":
            d = state.auto_stop_now(); return {"ok": True, "message": "自动巡检已停止", "state": state.snapshot(), "data": d}
        if a == "auto_status":
            return {"ok": True, "message": "ok", "state": state.snapshot()}
        raise RuntimeError(f"unsupported action: {a}")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, payload, ct="application/json; charset=utf-8", extra_headers=None):
            if isinstance(payload, (dict, list)):
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            elif isinstance(payload, str):
                data = payload.encode("utf-8")
            else:
                data = b""
            self.send_response(code)
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(data)))
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(str(k), str(v))
            self.end_headers()
            if data:
                self.wfile.write(data)

        def _read_json(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except Exception:
                n = 0
            if n <= 0:
                return {}
            raw = self.rfile.read(n)
            try:
                return json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                return {}

        def _need_auth(self):
            return not auth.is_authenticated(self.headers)

        def do_GET(self):
            if self.path == "/":
                self._send(200, WEB_PAGE, ct="text/html; charset=utf-8")
                return
            if self.path.startswith("/api/auth/state"):
                sync_auth_runtime()
                self._send(200, auth.auth_state(self.headers))
                return
            if self.path.startswith("/api/progress"):
                if self._need_auth():
                    self._send(401, {"ok": False, "error": "unauthorized"})
                    return
                self._send(200, {"ok": True, "progress": state.progress_snapshot()})
                return
            if self.path.startswith("/api/state"):
                if self._need_auth():
                    self._send(401, {"ok": False, "error": "unauthorized"})
                    return
                self._send(200, {"ok": True, "state": state.snapshot()})
                return
            self._send(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if self.path == "/api/auth/login":
                sync_auth_runtime()
                body = self._read_json()
                ret = auth.login(body.get("username"), body.get("password"))
                if not ret.get("ok"):
                    self._send(401, {"ok": False, "error": ret.get("error") or "登录失败", **auth.auth_state(self.headers)})
                    return
                token = str(ret.get("token") or "")
                self._send(200, {"ok": True, "message": "登录成功", **auth.auth_state(self.headers)}, extra_headers=[("Set-Cookie", auth.cookie_header(token))] if token else None)
                return
            if self.path == "/api/auth/logout":
                auth.logout(self.headers)
                self._send(200, {"ok": True, "message": "已退出"}, extra_headers=[("Set-Cookie", auth.cookie_header(""))])
                return
            if self.path != "/api/run":
                self._send(404, {"ok": False, "error": "not found"})
                return
            if self._need_auth():
                self._send(401, {"ok": False, "error": "unauthorized"})
                return
            try:
                self._send(200, action(self._read_json()))
            except Exception as e:
                self._send(500, {"ok": False, "error": str(e)})

        def log_message(self, *args):
            return

    httpd = ThreadingHTTPServer((host, int(port)), Handler)
    url = f"http://{host}:{int(port)}"
    print(f"[web] started: {url}")
    if not no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            state.auto_stop_now()
        except Exception:
            pass
        httpd.server_close()
