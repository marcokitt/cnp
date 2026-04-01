#!/usr/bin/env python3
"""
Cyber Lab Orchestrator v3.1

What this version adds compared to v3:
- Optional SSH access to the Caldera host to enumerate adversaries live at startup.
- Dedicated monitor windows for:
  1) Caldera adversaries / operation progress
  2) Wazuh live events in pseudo-tabular format with alternating rows
- Sequential execution of multiple Caldera adversaries with the atomic planner.
- Progress bar that keeps the script alive until all operations complete.
- Export of:
  - HTML report
  - CSV summary of ATT&CK techniques observed
  - JSON bundle for D3FEND-oriented post-processing
  - ATT&CK Navigator layer JSON (useful as an interchange artifact)

Notes:
- Caldera API schemas vary across versions. This script uses best-effort support for both
  legacy /api/rest and newer /api/v2 endpoints, with graceful fallbacks.
- The script is intended for authorized lab validation only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import os
import platform
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

try:
    import yaml
except Exception:
    print("PyYAML is required: python -m pip install pyyaml", file=sys.stderr)
    raise

try:
    import paramiko
except Exception:
    print("paramiko is required: python -m pip install paramiko", file=sys.stderr)
    raise


ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_BLUE = "\033[94m"
ANSI_RESET = "\033[0m"
ANSI_DIM = "\033[2m"
ANSI_BOLD = "\033[1m"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class SSHConfig:
    host: str
    port: int = 22
    username: str = ""
    password: Optional[str] = None
    key_path: Optional[str] = None


@dataclass
class LabConfig:
    caldera_url: str
    caldera_api_key: str
    caldera_username: str
    caldera_password: str
    caldera_target_agent_paw: Optional[str]
    caldera_operation_name_prefix: str
    caldera_adversary_ids: List[str]
    caldera_use_legacy_api: bool
    caldera_group: str
    caldera_source: str
    caldera_atomic_planner: str
    caldera_ssh: Optional[SSHConfig]

    wazuh_ssh: SSHConfig
    wazuh_log_path: str

    target_ip: Optional[str]
    known_lab_ips: List[str]
    preferred_source_ips: List[str]

    output_dir: str
    monitor_seconds_after_last_operation: int
    launch_monitor_window: bool
    d3fend_mappings_url: str
    attack_lookup_base: str
    debug_caldera: bool
    debug_wazuh: bool

    @staticmethod
    def from_file(path: str) -> "LabConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        caldera_host = data["caldera"]["url"].replace("http://", "").replace("https://", "").split(":")[0]
        target_ip = data.get("lab", {}).get("target_ip") or data.get("target", {}).get("ip")

        known_lab_ips = list(dict.fromkeys([
            ip for ip in [
                target_ip,
                caldera_host,
                data["wazuh"].get("host"),
                *(data.get("runtime", {}).get("known_lab_ips", []) or []),
            ] if ip
        ]))

        caldera_ssh_block = data.get("caldera", {}).get("ssh") or {}
        caldera_ssh = None
        if caldera_ssh_block.get("host"):
            caldera_ssh = SSHConfig(
                host=caldera_ssh_block["host"],
                port=int(caldera_ssh_block.get("port", 22)),
                username=caldera_ssh_block.get("username", ""),
                password=caldera_ssh_block.get("password"),
                key_path=caldera_ssh_block.get("key_path"),
            )

        return LabConfig(
            caldera_url=data["caldera"]["url"].rstrip("/"),
            caldera_api_key=data["caldera"]["api_key"],
            caldera_username=data["caldera"].get("username", ""),
            caldera_password=data["caldera"].get("password", ""),
            caldera_target_agent_paw=data["caldera"].get("target_agent_paw"),
            caldera_operation_name_prefix=data["caldera"].get("operation_name_prefix", "auto-op"),
            caldera_adversary_ids=data["caldera"].get("adversary_ids", []) or [],
            caldera_use_legacy_api=bool(data["caldera"].get("use_legacy_api", True)),
            caldera_group=data["caldera"].get("group", "red"),
            caldera_source=data["caldera"].get("source", "basic"),
            caldera_atomic_planner=data["caldera"].get("atomic_planner", "atomic"),
            caldera_ssh=caldera_ssh,
            wazuh_ssh=SSHConfig(
                host=data["wazuh"]["host"],
                port=int(data["wazuh"].get("port", 22)),
                username=data["wazuh"]["username"],
                password=data["wazuh"].get("password"),
                key_path=data["wazuh"].get("key_path"),
            ),
            wazuh_log_path=data["wazuh"].get("log_path", "/var/ossec/logs/alerts/alerts.json"),
            target_ip=target_ip,
            known_lab_ips=known_lab_ips,
            preferred_source_ips=data.get("runtime", {}).get("preferred_source_ips", []) or [],
            output_dir=data.get("runtime", {}).get("output_dir", "output"),
            monitor_seconds_after_last_operation=int(data.get("runtime", {}).get("monitor_seconds_after_last_operation", 120)),
            launch_monitor_window=bool(data.get("runtime", {}).get("launch_monitor_window", True)),
            d3fend_mappings_url=data.get("mitre", {}).get(
                "d3fend_mappings_url",
                "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json",
            ),
            attack_lookup_base=data.get("mitre", {}).get(
                "attack_lookup_base", "https://attack.mitre.org/techniques/"
            ),
            debug_caldera=bool(data.get("runtime", {}).get("debug_caldera", True)),
            debug_wazuh=bool(data.get("runtime", {}).get("debug_wazuh", False)),
        )


class SSHRunner:
    def __init__(self, cfg: SSHConfig):
        self.cfg = cfg
        self.client: Optional[paramiko.SSHClient] = None

    def __enter__(self) -> "SSHRunner":
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: Dict[str, Any] = {
            "hostname": self.cfg.host,
            "port": self.cfg.port,
            "username": self.cfg.username,
            "timeout": 20,
            "banner_timeout": 20,
            "auth_timeout": 20,
        }
        if self.cfg.key_path:
            kwargs["key_filename"] = self.cfg.key_path
        else:
            kwargs["password"] = self.cfg.password
        self.client.connect(**kwargs)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.client:
            self.client.close()

    def exec(self, command: str, get_pty: bool = False) -> Tuple[str, str, int]:
        assert self.client is not None
        stdin, stdout, stderr = self.client.exec_command(command, get_pty=get_pty)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return out, err, code

    def open_tail(self, command: str):
        assert self.client is not None
        transport = self.client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport unavailable")
        channel = transport.open_session()
        channel.get_pty()
        channel.exec_command(command)
        return channel


class CalderaClient:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg
        self.base = cfg.caldera_url
        self.session = requests.Session()
        self.session.headers.update({
            "KEY": cfg.caldera_api_key,
            "Content-Type": "application/json",
        })

    @staticmethod
    def _coerce_mapping(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
                if isinstance(parsed, list):
                    return {"items": parsed, "raw": value}
            except Exception:
                pass
            return {"raw": value, "id": value, "operation_id": value}
        if isinstance(value, list):
            if not value:
                return {}
            first = value[0]
            if isinstance(first, dict):
                return first
            return {"items": value, "raw": value}
        if value is None:
            return {}
        return {"raw": value}

    @staticmethod
    def _coerce_list_of_dicts(value: Any) -> List[Dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            for key in ("items", "objects", "adversaries", "operations", "data"):
                v = value.get(key)
                if isinstance(v, list):
                    return [item for item in v if isinstance(item, dict)]
        return []

    def _debug(self, label: str, payload: Any) -> None:
        if not getattr(self.cfg, "debug_caldera", False):
            return
        try:
            rendered = json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception:
            rendered = repr(payload)
        print(f"{ANSI_DIM}[caldera-debug] {label}: {rendered}{ANSI_RESET}")

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base}{path}"
        resp = self.session.request(method, url, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp

    def list_adversaries_legacy(self) -> List[Dict[str, Any]]:
        resp = self._request("POST", "/api/rest", data=json.dumps({"index": "adversaries"}))
        data = resp.json()
        self._debug("list_operations_legacy.response", data)
        return data if isinstance(data, list) else data.get("objects", [])

    def list_adversaries_v2(self) -> List[Dict[str, Any]]:
        resp = self._request("GET", "/api/v2/adversaries")
        data = resp.json()
        self._debug("list_operations_v2.response", data)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("adversaries", "objects", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        return []

    def list_adversaries(self) -> List[Dict[str, Any]]:
        if self.cfg.caldera_use_legacy_api:
            try:
                return self.list_adversaries_legacy()
            except Exception:
                return self.list_adversaries_v2()
        try:
            return self.list_adversaries_v2()
        except Exception:
            return self.list_adversaries_legacy()

    def normalize_adversary(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "adversary_id": obj.get("adversary_id") or obj.get("id") or obj.get("name") or "unknown",
            "name": obj.get("name") or obj.get("display_name") or obj.get("adversary_id") or obj.get("id") or "unknown",
            "description": obj.get("description") or "",
            "atomic_order": self.cfg.caldera_atomic_planner,
        }

    def create_operation_legacy(self, name: str, adversary_id: str) -> Dict[str, Any]:
        payload = {
            "index": "operations",
            "name": name,
            "group": self.cfg.caldera_group,
            "adversary_id": adversary_id,
            "planner": self.cfg.caldera_atomic_planner,
            "source": self.cfg.caldera_source,
            "jitter": "2/8",
            "obfuscator": "plain-text",
        }
        if self.cfg.caldera_target_agent_paw:
            payload["auto_close"] = False
        resp = self._request("PUT", "/api/rest", data=json.dumps(payload))
        raw = resp.json() if resp.text.strip() else {"status": "submitted"}
        self._debug("create_operation_legacy.response", raw)
        return self._coerce_mapping(raw)

    def create_operation_v2(self, name: str, adversary_id: str) -> Dict[str, Any]:
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "planner": {"planner_id": self.cfg.caldera_atomic_planner},
            "source": {"id": self.cfg.caldera_source},
            "group": self.cfg.caldera_group,
            "jitter": "2/8",
            "obfuscator": "plain-text",
        }
        resp = self._request("POST", "/api/v2/operations", data=json.dumps(payload))
        raw = resp.json() if resp.text.strip() else {"status": "submitted"}
        self._debug("create_operation_v2.response", raw)
        return self._coerce_mapping(raw)

    def create_operation(self, name: str, adversary_id: str) -> Dict[str, Any]:
        if self.cfg.caldera_use_legacy_api:
            try:
                return self.create_operation_legacy(name, adversary_id)
            except Exception:
                return self.create_operation_v2(name, adversary_id)
        try:
            return self.create_operation_v2(name, adversary_id)
        except Exception:
            return self.create_operation_legacy(name, adversary_id)

    def list_operations_legacy(self) -> List[Dict[str, Any]]:
        resp = self._request("POST", "/api/rest", data=json.dumps({"index": "operations"}))
        data = resp.json()
        return data if isinstance(data, list) else data.get("objects", [])

    def list_operations_v2(self) -> List[Dict[str, Any]]:
        resp = self._request("GET", "/api/v2/operations")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("operations", "objects", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        return []

    def list_operations(self) -> List[Dict[str, Any]]:
        if self.cfg.caldera_use_legacy_api:
            try:
                return self.list_operations_legacy()
            except Exception:
                return self.list_operations_v2()
        try:
            return self.list_operations_v2()
        except Exception:
            return self.list_operations_legacy()

    def get_operation(self, operation_id: str) -> Optional[Dict[str, Any]]:
        operations = self.list_operations()
        for op in operations:
            if str(op.get("id")) == str(operation_id) or str(op.get("op_id")) == str(operation_id):
                return op
        return None

    def find_operation_id_by_name(self, operation_name: str) -> Optional[str]:
        operations = self.list_operations()
        for op in operations:
            if str(op.get("name") or "") == str(operation_name):
                op_id = self.extract_operation_id(op)
                if op_id:
                    return op_id
        return None

    @staticmethod
    def extract_operation_id(operation_info: Any) -> Optional[str]:
        info = CalderaClient._coerce_mapping(operation_info)
        for key in ("id", "op_id", "operation_id", "paw"):
            value = info.get(key)
            if value:
                return str(value)
        for key in ("data", "operation", "result"):
            nested = info.get(key)
            if isinstance(nested, dict):
                for subkey in ("id", "op_id", "operation_id", "paw"):
                    value = nested.get(subkey)
                    if value:
                        return str(value)
        items = CalderaClient._coerce_list_of_dicts(info)
        for item in items:
            for key in ("id", "op_id", "operation_id", "paw"):
                value = item.get(key)
                if value:
                    return str(value)
        raw = info.get("raw")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return None

    @staticmethod
    def operation_state(operation: Optional[Dict[str, Any]]) -> str:
        info = CalderaClient._coerce_mapping(operation)
        if not info:
            return "unknown"
        for key in ("state", "status", "phase"):
            value = info.get(key)
            if value:
                return str(value).lower()
        if isinstance(info.get("data"), dict):
            for key in ("state", "status", "phase"):
                value = info["data"].get(key)
                if value:
                    return str(value).lower()
        if info.get("finished") is True:
            return "finished"
        if info.get("close") is True:
            return "closed"
        return "running"

    @staticmethod
    def operation_progress(operation: Optional[Dict[str, Any]]) -> Tuple[int, int]:
        if not operation:
            return 0, 0
        chain = operation.get("chain") or operation.get("link_chain") or []
        total = len(chain) if isinstance(chain, list) else 0
        completed = 0
        if isinstance(chain, list):
            for item in chain:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("status") or item.get("state") or "").lower()
                if status in {"success", "completed", "skipped", "finished", "executed"}:
                    completed += 1
        if total == 0 and operation.get("finished") is True:
            return 1, 1
        return completed, total

    def ssh_list_adversaries(self) -> List[Dict[str, Any]]:
        if not self.cfg.caldera_ssh:
            return []
        with SSHRunner(self.cfg.caldera_ssh) as ssh:
            curl_cmd = (
                f"curl -sk -H 'KEY: {self.cfg.caldera_api_key}' "
                f"-H 'Content-Type: application/json' "
                f"-X POST {shlex.quote(self.cfg.caldera_url + '/api/rest')} "
                f"-d '{json.dumps({'index': 'adversaries'})}'"
            )
            out, err, code = ssh.exec(curl_cmd)
            if code == 0 and out.strip():
                try:
                    data = json.loads(out)
                    if isinstance(data, list):
                        return data
                except Exception:
                    pass

            curl_cmd_v2 = (
                f"curl -sk -H 'KEY: {self.cfg.caldera_api_key}' "
                f"{shlex.quote(self.cfg.caldera_url + '/api/v2/adversaries')}"
            )
            out, err, code = ssh.exec(curl_cmd_v2)
            if code == 0 and out.strip():
                try:
                    data = json.loads(out)
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict):
                        for key in ("adversaries", "objects", "items"):
                            if isinstance(data.get(key), list):
                                return data[key]
                except Exception:
                    pass
        return []


class D3fendMapper:
    def __init__(self, mappings_url: str) -> None:
        self.mappings_url = mappings_url
        self.loaded = False
        self.attack_to_d3fend: Dict[str, Set[str]] = {}

    def load(self) -> None:
        if self.loaded:
            return
        resp = requests.get(self.mappings_url, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                text = json.dumps(obj, ensure_ascii=False)
                attack_ids = {m.upper() for m in ATTACK_ID_RE.findall(text)}
                d3f_ids = set(re.findall(r"d3f:[A-Za-z0-9_]+", text))
                for aid in attack_ids:
                    self.attack_to_d3fend.setdefault(aid, set()).update(d3f_ids)
                for value in obj.values():
                    walk(value)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)
        self.loaded = True

    def map_attack_ids(self, attack_ids: Set[str]) -> Dict[str, List[str]]:
        self.load()
        result: Dict[str, List[str]] = {}
        for aid in sorted(attack_ids):
            result[aid] = sorted(self.attack_to_d3fend.get(aid, set()))
        return result


def now_utc() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sanitize_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())[:120] or "unknown"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def html_escape_json(obj: Any) -> str:
    return html.escape(json.dumps(obj, ensure_ascii=False, indent=2))


def iter_values(obj: Any):
    if isinstance(obj, dict):
        for _, v in obj.items():
            yield from iter_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_values(item)
    else:
        yield obj


def valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def find_ipv4s_in_obj(obj: Any) -> List[str]:
    found: List[str] = []
    for value in iter_values(obj):
        if isinstance(value, str):
            for ip in IPV4_RE.findall(value):
                if valid_ipv4(ip):
                    found.append(ip)
    return found


def deep_get(obj: Dict[str, Any], path: List[str]) -> Any:
    cur: Any = obj
    for item in path:
        if not isinstance(cur, dict) or item not in cur:
            return None
        cur = cur[item]
    return cur


def extract_attack_ids(alert: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()
    text = json.dumps(alert, ensure_ascii=False)
    found.update({m.upper() for m in ATTACK_ID_RE.findall(text)})
    mitre_block = alert.get("rule", {}).get("mitre", {})
    if isinstance(mitre_block, dict):
        attack_ids = mitre_block.get("id", [])
        if isinstance(attack_ids, list):
            found.update({str(x).upper() for x in attack_ids})
        elif isinstance(attack_ids, str):
            found.add(attack_ids.upper())
    return found


def severity_of(alert: Dict[str, Any]) -> int:
    try:
        return int(alert.get("rule", {}).get("level", 0))
    except Exception:
        return 0


def extract_timestamp(alert: Dict[str, Any]) -> str:
    return str(alert.get("timestamp") or alert.get("@timestamp") or now_utc())


def infer_source_ip(alert: Dict[str, Any], cfg: LabConfig) -> str:
    preferred_paths = [
        ["data", "srcip"],
        ["srcip"],
        ["win", "eventdata", "sourceIp"],
        ["win", "eventdata", "SourceIp"],
        ["sysmon", "event_data", "SourceIp"],
        ["network", "srcip"],
    ]

    candidates: List[str] = []
    for path in preferred_paths:
        value = deep_get(alert, path)
        if isinstance(value, str):
            for ip in IPV4_RE.findall(value):
                if valid_ipv4(ip):
                    candidates.append(ip)

    candidates.extend(find_ipv4s_in_obj(alert))

    preferred = [ip for ip in candidates if ip in set(cfg.preferred_source_ips)]
    if preferred:
        return preferred[0]

    excluded = set(filter(None, cfg.known_lab_ips))
    if cfg.target_ip:
        excluded.add(cfg.target_ip)
    filtered = [ip for ip in candidates if ip not in excluded]
    if filtered:
        return filtered[0]
    if candidates:
        return candidates[0]
    return "unknown"


class WazuhTailMonitor(threading.Thread):
    def __init__(self, cfg: LabConfig, line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]", stop_event: threading.Event):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.line_queue = line_queue
        self.stop_event = stop_event
        self.command = f"sudo tail -n 0 -F {self.cfg.wazuh_log_path}"

    def run(self) -> None:
        try:
            with SSHRunner(self.cfg.wazuh_ssh) as ssh:
                channel = ssh.open_tail(self.command)
                buffer = ""
                while not self.stop_event.is_set():
                    if channel.recv_ready():
                        chunk = channel.recv(65535).decode("utf-8", errors="replace")
                        buffer += chunk
                        while "\n" in buffer:
                            raw_line, buffer = buffer.split("\n", 1)
                            line = raw_line.strip()
                            if not line:
                                continue
                            try:
                                parsed = json.loads(line)
                            except Exception:
                                parsed = {"raw": line}
                            self.line_queue.put((line, parsed))
                    else:
                        time.sleep(0.2)
        except Exception as exc:
            self.line_queue.put((f"__MONITOR_ERROR__ {exc}", {"monitor_error": str(exc)}))


class OperationProgressMonitor(threading.Thread):
    def __init__(self, caldera: CalderaClient, operation_id: str, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.caldera = caldera
        self.operation_id = operation_id
        self.stop_event = stop_event
        self.snapshots: List[Dict[str, Any]] = []
        self.last_state: str = "unknown"
        self.last_completed: int = 0
        self.last_total: int = 0

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                op = self.caldera.get_operation(self.operation_id)
                if op:
                    self.snapshots.append(op)
                    self.last_state = self.caldera.operation_state(op)
                    self.last_completed, self.last_total = self.caldera.operation_progress(op)
                    if self.last_state in {"finished", "complete", "completed", "cleanup", "closed"}:
                        break
                time.sleep(3)
            except Exception:
                time.sleep(3)


class SharedState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.current_operation_name: str = "idle"
        self.current_adversary_id: str = ""
        self.current_operation_id: str = ""
        self.current_state: str = "idle"
        self.completed_steps: int = 0
        self.total_steps: int = 0
        self.overall_index: int = 0
        self.overall_total: int = 0
        self.finished: bool = False

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "current_operation_name": self.current_operation_name,
                "current_adversary_id": self.current_adversary_id,
                "current_operation_id": self.current_operation_id,
                "current_state": self.current_state,
                "completed_steps": self.completed_steps,
                "total_steps": self.total_steps,
                "overall_index": self.overall_index,
                "overall_total": self.overall_total,
                "finished": self.finished,
            }

    def update(self, **kwargs: Any) -> None:
        with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, v)


def progress_bar(done: int, total: int, width: int = 32) -> str:
    if total <= 0:
        return "[" + ("#" * 1).ljust(width, ".") + "]"
    ratio = max(0.0, min(1.0, done / total))
    fill = int(ratio * width)
    return "[" + ("#" * fill).ljust(width, ".") + "]"


def launch_monitor_window(title: str, args: List[str]) -> bool:
    if platform.system().lower() != "windows":
        return False
    subprocess.Popen(["cmd", "/c", "start", title] + args, shell=False)
    return True


def print_wazuh_table_row(index: int, ts: str, level: int, src_ip: str, agent: str, description: str) -> None:
    zebra = ANSI_DIM if index % 2 else ""
    sev = ANSI_GREEN
    if level >= 10:
        sev = ANSI_RED
    elif level >= 5:
        sev = ANSI_YELLOW
    description = (description or "").replace("\r", " ").replace("\n", " ").strip()
    if len(description) > 96:
        description = description[:93] + "..."
    row = f"{ts:<21} | {str(level):<5} | {src_ip:<15} | {agent[:18]:<18} | {description:<96}"
    print(f"{zebra}{sev}{row}{ANSI_RESET}")


def live_wazuh_ui(config_path: str) -> int:
    cfg = LabConfig.from_file(config_path)
    q: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop = threading.Event()
    mon = WazuhTailMonitor(cfg, q, stop)
    mon.start()

    print(f"{ANSI_BOLD}Timestamp              | Lvl   | Source IP       | Agent              | Description{ANSI_RESET}")
    print("=" * 170)
    idx = 0
    try:
        while True:
            try:
                _, parsed = q.get(timeout=1)
            except queue.Empty:
                continue
            if parsed.get("monitor_error"):
                print(f"Wazuh monitor error: {parsed['monitor_error']}")
                continue
            src = infer_source_ip(parsed, cfg)
            level = severity_of(parsed)
            agent = str(parsed.get("agent", {}).get("name", "unknown"))
            desc = str(parsed.get("rule", {}).get("description", parsed.get("decoder", {}).get("name", "event")))
            ts = extract_timestamp(parsed)
            print_wazuh_table_row(idx, ts, level, src, agent, desc)
            idx += 1
    except KeyboardInterrupt:
        stop.set()
        mon.join(timeout=2)
        return 0


def live_caldera_ui(config_path: str, state_path: str, adversaries_path: str) -> int:
    state_file = Path(state_path)
    adv_file = Path(adversaries_path)
    last_render = ""
    try:
        while True:
            data: Dict[str, Any] = {}
            advs: List[Dict[str, Any]] = []
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
            if adv_file.exists():
                try:
                    advs = json.loads(adv_file.read_text(encoding="utf-8"))
                except Exception:
                    advs = []

            done = int(data.get("completed_steps", 0) or 0)
            total = int(data.get("total_steps", 0) or 0)
            bar = progress_bar(done, total)
            overall_idx = int(data.get("overall_index", 0) or 0)
            overall_total = int(data.get("overall_total", 0) or 0)
            finished = bool(data.get("finished", False))

            lines = [
                f"{ANSI_BOLD}CALDERA LIVE MONITOR{ANSI_RESET}",
                f"Operation : {data.get('current_operation_name', 'idle')}",
                f"Adversary : {data.get('current_adversary_id', '')}",
                f"Op ID     : {data.get('current_operation_id', '')}",
                f"State     : {data.get('current_state', 'idle')}",
                f"Progress  : {bar} {done}/{total}",
                f"Queue     : {overall_idx}/{overall_total}",
                "",
                f"{ANSI_BOLD}Adversaries loaded at startup{ANSI_RESET}",
            ]
            for i, adv in enumerate(advs[:50], start=1):
                zebra = ANSI_DIM if i % 2 else ""
                lines.append(f"{zebra}{i:>2}. {adv.get('adversary_id','?'):<24} {adv.get('name','')}{ANSI_RESET}")
            if len(advs) > 50:
                lines.append(f"... and {len(advs)-50} more")
            if finished:
                lines.append("")
                lines.append(f"{ANSI_GREEN}All queued operations completed.{ANSI_RESET}")
            rendered = "\n".join(lines)
            if rendered != last_render:
                os.system("cls" if platform.system().lower() == "windows" else "clear")
                print(rendered)
                last_render = rendered
            if finished:
                break
            time.sleep(1)
        return 0
    except KeyboardInterrupt:
        return 0


def generate_attack_csv(path: Path, attack_ids: Set[str], d3f_map: Dict[str, List[str]], attack_lookup_base: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["attack_id", "attack_url", "d3fend_ids"])
        for aid in sorted(attack_ids):
            writer.writerow([
                aid,
                f"{attack_lookup_base}{aid.replace('.', '/')}/",
                "; ".join(d3f_map.get(aid, [])),
            ])


def generate_d3fend_json(path: Path, session_id: str, attack_ids: Set[str], d3f_map: Dict[str, List[str]], alerts: List[Dict[str, Any]]) -> None:
    bundle = {
        "session_id": session_id,
        "generated_at": now_utc(),
        "attack_ids": sorted(attack_ids),
        "attack_to_d3fend": d3f_map,
        "events": [
            {
                "timestamp": extract_timestamp(a),
                "source_ip": a.get("_inferred_source_ip", "unknown"),
                "agent": a.get("agent", {}).get("name"),
                "rule_description": a.get("rule", {}).get("description"),
                "rule_level": a.get("rule", {}).get("level"),
                "attack_ids": sorted(extract_attack_ids(a)),
            }
            for a in alerts
        ],
    }
    write_json(path, bundle)


def generate_attack_navigator_layer(path: Path, attack_ids: Set[str]) -> None:
    techniques = [{"techniqueID": aid, "score": 1, "comment": "Observed via Wazuh during Caldera emulation"} for aid in sorted(attack_ids)]
    layer = {
        "name": "Observed Techniques",
        "versions": {"navigator": "4.9.1", "layer": "4.5", "attack": "18"},
        "domain": "enterprise-attack",
        "description": "Observed ATT&CK techniques from Caldera/Wazuh session",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#66b1ff", "#003f8a"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Observed", "color": "#003f8a"}],
    }
    write_json(path, layer)


def generate_report(
    output_path: Path,
    title: str,
    config: LabConfig,
    session_id: str,
    operation_runs: List[Dict[str, Any]],
    observed_alerts: List[Dict[str, Any]],
    attack_ids: Set[str],
    d3f_map: Dict[str, List[str]],
) -> None:
    attack_rows = []
    for aid in sorted(attack_ids):
        attack_url = f"{config.attack_lookup_base}{aid.replace('.', '/')}/"
        attack_rows.append(
            f"<tr><td><a href='{html.escape(attack_url)}'>{html.escape(aid)}</a></td><td>{html.escape(', '.join(d3f_map.get(aid, [])) or 'No mapped D3FEND technique found')}</td></tr>"
        )

    op_cards = []
    for item in operation_runs:
        op_cards.append(
            f"<div class='card'><h3>{html.escape(item.get('name','operation'))}</h3><pre>{html_escape_json(item)}</pre></div>"
        )

    alert_cards = []
    for a in observed_alerts[:300]:
        alert_cards.append(
            f"<div class='card'><h3>{html.escape(str(a.get('rule',{}).get('description','Wazuh alert')))}</h3><p><strong>Time:</strong> {html.escape(extract_timestamp(a))} &nbsp; <strong>Source IP:</strong> {html.escape(str(a.get('_inferred_source_ip','unknown')))}</p><pre>{html_escape_json(a)}</pre></div>"
        )

    html_doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }}
h1,h2,h3 {{ color: #fff; }}
.card {{ background: #1c1c1c; border: 1px solid #333; border-left: 6px solid #2f7ed8; padding: 14px; margin: 14px 0; border-radius: 8px; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #0b0b0b; padding: 12px; border-radius: 6px; border: 1px solid #333; }}
table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #222; }}
a {{ color: #7db8ff; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p><strong>Generated:</strong> {html.escape(now_utc())}</p>
<h2>Session Summary</h2>
<ul>
  <li><strong>Session ID:</strong> {html.escape(session_id)}</li>
  <li><strong>Caldera:</strong> {html.escape(config.caldera_url)}</li>
  <li><strong>Wazuh:</strong> {html.escape(config.wazuh_ssh.host)}</li>
  <li><strong>Target IP:</strong> {html.escape(config.target_ip or 'not set')}</li>
  <li><strong>Operations executed:</strong> {len(operation_runs)}</li>
  <li><strong>Observed alerts:</strong> {len(observed_alerts)}</li>
  <li><strong>Observed ATT&CK IDs:</strong> {len(attack_ids)}</li>
</ul>
<h2>Caldera Operations</h2>
{''.join(op_cards) if op_cards else '<p>No operation metadata available.</p>'}
<h2>Observed ATT&amp;CK -> D3FEND</h2>
<table><tr><th>ATT&amp;CK technique</th><th>D3FEND mappings</th></tr>{''.join(attack_rows) if attack_rows else '<tr><td colspan="2">No ATT&amp;CK techniques extracted.</td></tr>'}</table>
<h2>Captured Wazuh Alerts</h2>
{''.join(alert_cards) if alert_cards else '<p>No alerts captured.</p>'}
</body></html>"""
    output_path.write_text(html_doc, encoding="utf-8")


def collect_alerts_until_done(cfg: LabConfig, shared: SharedState) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    q: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop = threading.Event()
    mon = WazuhTailMonitor(cfg, q, stop)
    mon.start()

    alerts: List[Dict[str, Any]] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    post_finish_deadline: Optional[float] = None

    try:
        while True:
            snap = shared.snapshot()
            if snap["finished"] and post_finish_deadline is None:
                post_finish_deadline = time.time() + cfg.monitor_seconds_after_last_operation
            if post_finish_deadline is not None and time.time() >= post_finish_deadline:
                break
            try:
                _, parsed = q.get(timeout=1)
            except queue.Empty:
                continue
            if parsed.get("monitor_error"):
                print(f"[!] Wazuh monitor error: {parsed['monitor_error']}", file=sys.stderr)
                continue
            source_ip = infer_source_ip(parsed, cfg)
            parsed["_inferred_source_ip"] = source_ip
            parsed["_capture_session"] = snap.get("current_operation_name", "session")
            parsed["_captured_at_utc"] = now_utc()
            alerts.append(parsed)
            grouped.setdefault(source_ip, []).append(parsed)
    finally:
        stop.set()
        mon.join(timeout=3)

    return alerts, grouped


def build_per_source_reports(cfg: LabConfig, mapper: D3fendMapper, session_dir: Path, session_id: str, grouped: Dict[str, List[Dict[str, Any]]], operation_runs: List[Dict[str, Any]]) -> None:
    by_source = session_dir / "by_source_ip"
    ensure_dir(by_source)
    rows = []
    for src, alerts in sorted(grouped.items(), key=lambda kv: kv[0]):
        src_dir = by_source / sanitize_name(src)
        ensure_dir(src_dir)
        attack_ids = {aid for a in alerts for aid in extract_attack_ids(a)}
        d3f_map = mapper.map_attack_ids(attack_ids) if attack_ids else {}
        write_json(src_dir / "alerts.json", alerts)
        generate_report(src_dir / "report.html", f"Per-source report — {src}", cfg, session_id, operation_runs, alerts, attack_ids, d3f_map)
        rows.append(f"<tr><td>{html.escape(src)}</td><td>{len(alerts)}</td><td>{html.escape(', '.join(sorted(attack_ids)) or 'none')}</td><td><a href='./{sanitize_name(src)}/report.html'>open</a></td></tr>")
    index_html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Per-source reports</title><style>body{{font-family:Arial,sans-serif;margin:24px;background:#111;color:#eee}}table{{border-collapse:collapse;width:100%;background:#1c1c1c}}th,td{{border:1px solid #333;padding:10px;text-align:left}}th{{background:#222}}a{{color:#7db8ff}}</style></head><body><h1>Per-source-IP reports</h1><table><tr><th>Source IP</th><th>Alerts</th><th>ATT&amp;CK IDs</th><th>Report</th></tr>{''.join(rows) if rows else '<tr><td colspan="4">No grouped alerts</td></tr>'}</table></body></html>"""
    (by_source / "index.html").write_text(index_html, encoding="utf-8")


def select_adversaries(caldera: CalderaClient, cfg: LabConfig) -> List[Dict[str, Any]]:
    live = []
    try:
        live = caldera.ssh_list_adversaries() if cfg.caldera_ssh else []
    except Exception:
        live = []
    if not live:
        live = caldera.list_adversaries()

    normalized = [caldera.normalize_adversary(x) for x in live]
    if cfg.caldera_adversary_ids:
        allowed = set(cfg.caldera_adversary_ids)
        normalized = [x for x in normalized if x["adversary_id"] in allowed]
    return normalized


def append_jsonl(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as f:
        try:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            f.write(json.dumps({"repr": repr(payload)}, ensure_ascii=False) + "\n")


def run(config_path: str) -> int:
    cfg = LabConfig.from_file(config_path)
    caldera = CalderaClient(cfg)
    mapper = D3fendMapper(cfg.d3fend_mappings_url)

    out_dir = Path(cfg.output_dir)
    ensure_dir(out_dir)
    session_id = f"session_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    session_dir = out_dir / session_id
    ensure_dir(session_dir)

    adversaries = select_adversaries(caldera, cfg)
    if not adversaries:
        print("[-] No adversaries found. Check Caldera API/SSH settings.", file=sys.stderr)
        return 2

    adversaries_path = session_dir / "adversaries_loaded.json"
    write_json(adversaries_path, adversaries)

    shared = SharedState()
    shared.update(overall_total=len(adversaries))
    state_path = session_dir / "live_state.json"
    write_json(state_path, shared.snapshot())

    script_path = Path(__file__).resolve()
    if cfg.launch_monitor_window:
        try:
            launch_monitor_window(
                "Caldera Live Monitor",
                ["powershell", "-NoExit", "-Command", f"python '{script_path}' --live-caldera --config '{Path(config_path).resolve()}' --state-file '{state_path.resolve()}' --adversaries-file '{adversaries_path.resolve()}'"],
            )
            launch_monitor_window(
                "Wazuh Live Monitor",
                ["powershell", "-NoExit", "-Command", f"python '{script_path}' --live-wazuh --config '{Path(config_path).resolve()}'"],
            )
        except Exception as exc:
            print(f"[!] Could not launch monitor windows: {exc}")

    alert_holder: Dict[str, Any] = {}
    def wazuh_worker():
        alerts, grouped = collect_alerts_until_done(cfg, shared)
        alert_holder["alerts"] = alerts
        alert_holder["grouped"] = grouped

    wazuh_thread = threading.Thread(target=wazuh_worker, daemon=True)
    wazuh_thread.start()

    operation_runs: List[Dict[str, Any]] = []

    for idx, adv in enumerate(adversaries, start=1):
        adv_id = adv["adversary_id"]
        op_name = f"{cfg.caldera_operation_name_prefix}-{idx:02d}-{sanitize_name(adv_id)}-{dt.datetime.now().strftime('%H%M%S')}"
        print(f"{ANSI_CYAN}[+] Starting operation {idx}/{len(adversaries)} with adversary {adv_id}{ANSI_RESET}")

        try:
            raw_op_info = caldera.create_operation(op_name, adv_id)
            if cfg.debug_caldera:
                append_jsonl(session_dir / "caldera_create_operation_debug.jsonl", {
                    "timestamp": now_utc(),
                    "operation_name": op_name,
                    "adversary_id": adv_id,
                    "raw_response": raw_op_info,
                })
            op_info = caldera._coerce_mapping(raw_op_info)
        except Exception as exc:
            op_info = {
                "name": op_name,
                "adversary_id": adv_id,
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "state": "failed_to_create",
                "started_at": now_utc(),
            }
            if cfg.debug_caldera:
                append_jsonl(session_dir / "caldera_create_operation_debug.jsonl", {
                    "timestamp": now_utc(),
                    "operation_name": op_name,
                    "adversary_id": adv_id,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                })
            operation_runs.append(op_info)
            shared.update(
                current_operation_name=op_name,
                current_adversary_id=adv_id,
                current_state="failed_to_create",
                overall_index=idx,
            )
            write_json(state_path, shared.snapshot())
            continue

        op_id = caldera.extract_operation_id(op_info)
        if not op_id:
            time.sleep(2)
            op_id = caldera.find_operation_id_by_name(op_name)
        op_id = op_id or f"unknown-{idx}"
        shared.update(
            current_operation_name=op_name,
            current_adversary_id=adv_id,
            current_operation_id=op_id,
            current_state="running",
            completed_steps=0,
            total_steps=0,
            overall_index=idx,
        )
        write_json(state_path, shared.snapshot())

        stop_prog = threading.Event()
        prog = OperationProgressMonitor(caldera, op_id, stop_prog)
        prog.start()

        started_at = time.time()
        last_line_time = 0.0
        while True:
            state = prog.last_state
            done = prog.last_completed
            total = prog.last_total
            shared.update(current_state=state, completed_steps=done, total_steps=total)
            write_json(state_path, shared.snapshot())

            now = time.time()
            if now - last_line_time >= 2:
                print(f"    {progress_bar(done, total)} {done}/{total} state={state} op_id={op_id}")
                if cfg.debug_caldera:
                    append_jsonl(session_dir / "caldera_progress_debug.jsonl", {
                        "timestamp": now_utc(),
                        "operation_name": op_name,
                        "adversary_id": adv_id,
                        "operation_id": op_id,
                        "state": state,
                        "done": done,
                        "total": total,
                    })
                last_line_time = now

            if state in {"finished", "complete", "completed", "cleanup", "closed"}:
                break
            if now - started_at > 3600:
                break
            time.sleep(1)

        stop_prog.set()
        prog.join(timeout=3)

        op_record = dict(op_info)
        op_record.update({
            "name": op_name,
            "adversary_id": adv_id,
            "operation_id": op_id,
            "finished_state": prog.last_state,
            "completed_links": prog.last_completed,
            "total_links": prog.last_total,
            "snapshots_collected": len(prog.snapshots),
        })
        operation_runs.append(op_record)

    shared.update(finished=True, current_state="finished")
    write_json(state_path, shared.snapshot())

    wazuh_thread.join(timeout=cfg.monitor_seconds_after_last_operation + 10)
    alerts = alert_holder.get("alerts", [])
    grouped = alert_holder.get("grouped", {})

    observed_attack_ids = {aid for alert in alerts for aid in extract_attack_ids(alert)}
    try:
        d3f_map = mapper.map_attack_ids(observed_attack_ids) if observed_attack_ids else {}
    except Exception:
        d3f_map = {aid: [] for aid in observed_attack_ids}

    write_json(session_dir / "operation_runs.json", operation_runs)
    if cfg.debug_wazuh:
        write_json(session_dir / "captured_alerts_debug_sample.json", alerts[:200])
    write_json(session_dir / "captured_alerts_all.json", alerts)
    write_json(session_dir / "grouped_alerts.json", grouped)
    generate_report(session_dir / "report.html", "Cyber Lab Orchestrator Report", cfg, session_id, operation_runs, alerts, observed_attack_ids, d3f_map)
    generate_attack_csv(session_dir / "attack_summary.csv", observed_attack_ids, d3f_map, cfg.attack_lookup_base)
    generate_d3fend_json(session_dir / "d3fend_bundle.json", session_id, observed_attack_ids, d3f_map, alerts)
    generate_attack_navigator_layer(session_dir / "attack_navigator_layer.json", observed_attack_ids)
    build_per_source_reports(cfg, mapper, session_dir, session_id, grouped, operation_runs)

    print(f"{ANSI_GREEN}[+] Session completed: {session_dir.resolve()}{ANSI_RESET}")
    print(f"{ANSI_GREEN}[+] HTML report: {(session_dir / 'report.html').resolve()}{ANSI_RESET}")
    print(f"{ANSI_GREEN}[+] D3FEND JSON: {(session_dir / 'd3fend_bundle.json').resolve()}{ANSI_RESET}")
    print(f"{ANSI_GREEN}[+] CSV summary: {(session_dir / 'attack_summary.csv').resolve()}{ANSI_RESET}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized cyber lab orchestrator v3")
    parser.add_argument("-c", "--config", default="config.yml", help="Path to YAML config file")
    parser.add_argument("--live-wazuh", action="store_true", help="Run the standalone Wazuh live table UI")
    parser.add_argument("--live-caldera", action="store_true", help="Run the standalone Caldera live UI")
    parser.add_argument("--state-file", help="Path to live state JSON")
    parser.add_argument("--adversaries-file", help="Path to adversaries JSON")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.live_wazuh:
        raise SystemExit(live_wazuh_ui(args.config))
    if args.live_caldera:
        if not args.state_file or not args.adversaries_file:
            print("--state-file and --adversaries-file are required with --live-caldera", file=sys.stderr)
            raise SystemExit(3)
        raise SystemExit(live_caldera_ui(args.config, args.state_file, args.adversaries_file))
    raise SystemExit(run(args.config))
