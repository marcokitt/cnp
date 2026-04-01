#!/usr/bin/env python3
"""
Cyber Lab Orchestrator v3
- Interactive Caldera selector for adversaries and agents
- Legacy API discovery helpers for adversaries, agents, abilities, operations
- Wazuh real-time table view
- Per-source-IP grouping and reports

Authorized lab use only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

try:
    import yaml
except Exception:
    print("Missing dependency: PyYAML. Install with: python -m pip install pyyaml", file=sys.stderr)
    raise

try:
    import paramiko
except Exception:
    print("Missing dependency: paramiko. Install with: python -m pip install paramiko", file=sys.stderr)
    raise


ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def now_utc() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def sanitize_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())[:120] or "unknown"

def valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False

def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def truncate(text: str, n: int) -> str:
    text = str(text).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= n else text[: max(0, n - 1)] + "…"

def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def extract_attack_ids(alert: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()
    text = json.dumps(alert, ensure_ascii=False)
    found.update({m.upper() for m in ATTACK_ID_RE.findall(text)})
    mitre_block = alert.get("rule", {}).get("mitre", {})
    if isinstance(mitre_block, dict):
        value = mitre_block.get("id", [])
        if isinstance(value, list):
            found.update({str(x).upper() for x in value})
        elif isinstance(value, str):
            found.add(value.upper())
    return found

def severity_of(alert: Dict[str, Any]) -> int:
    level = alert.get("rule", {}).get("level", 0)
    try:
        return int(level)
    except Exception:
        return 0

def iter_values(obj: Any):
    if isinstance(obj, dict):
        for _, v in obj.items():
            yield from iter_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_values(item)
    else:
        yield obj

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

@dataclass
class LabConfig:
    caldera_url: str
    caldera_api_key: str
    caldera_username: str
    caldera_password: str
    operation_name_prefix: str
    caldera_adversary_ids: List[str]
    caldera_use_legacy_api: bool
    target_agent_paw: Optional[str]

    wazuh_host: str
    wazuh_port: int
    wazuh_username: str
    wazuh_password: Optional[str]
    wazuh_key_path: Optional[str]
    wazuh_log_path: str

    target_ip: Optional[str]
    tpot_ip: Optional[str]

    d3fend_mappings_url: str
    attack_lookup_base: str

    monitor_seconds: int
    extra_monitor_seconds: int
    output_dir: str
    launch_monitor_window: bool
    preferred_source_ips: List[str]
    known_lab_ips: List[str]
    table_refresh_seconds: int
    table_max_rows: int

    @staticmethod
    def from_file(path: str) -> "LabConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        caldera_host = data["caldera"]["url"].replace("http://", "").replace("https://", "").split(":")[0]
        target_ip = data.get("lab", {}).get("target_ip")
        known_lab_ips = list(dict.fromkeys([
            ip for ip in [
                caldera_host,
                data["wazuh"].get("host"),
                target_ip,
                data.get("tpot", {}).get("ip"),
                *(data.get("runtime", {}).get("known_lab_ips", []) or []),
            ] if ip
        ]))

        return LabConfig(
            caldera_url=data["caldera"]["url"].rstrip("/"),
            caldera_api_key=data["caldera"]["api_key"],
            caldera_username=data["caldera"].get("username", ""),
            caldera_password=data["caldera"].get("password", ""),
            operation_name_prefix=data["caldera"].get("operation_name_prefix", "apt-sim"),
            caldera_adversary_ids=data["caldera"].get("adversary_ids", []) or [],
            caldera_use_legacy_api=bool(data["caldera"].get("use_legacy_api", True)),
            target_agent_paw=data["caldera"].get("target_agent_paw"),
            wazuh_host=data["wazuh"]["host"],
            wazuh_port=int(data["wazuh"].get("port", 22)),
            wazuh_username=data["wazuh"]["username"],
            wazuh_password=data["wazuh"].get("password"),
            wazuh_key_path=data["wazuh"].get("key_path"),
            wazuh_log_path=data["wazuh"].get("log_path", "/var/ossec/logs/alerts/alerts.json"),
            target_ip=target_ip,
            tpot_ip=data.get("tpot", {}).get("ip"),
            d3fend_mappings_url=data.get("mitre", {}).get("d3fend_mappings_url", "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"),
            attack_lookup_base=data.get("mitre", {}).get("attack_lookup_base", "https://attack.mitre.org/techniques/"),
            monitor_seconds=int(data.get("runtime", {}).get("monitor_seconds", 240)),
            extra_monitor_seconds=int(data.get("runtime", {}).get("extra_monitor_seconds", 360)),
            output_dir=data.get("runtime", {}).get("output_dir", "output"),
            launch_monitor_window=bool(data.get("runtime", {}).get("launch_monitor_window", True)),
            preferred_source_ips=data.get("runtime", {}).get("preferred_source_ips", []) or [],
            known_lab_ips=known_lab_ips,
            table_refresh_seconds=int(data.get("runtime", {}).get("table_refresh_seconds", 1)),
            table_max_rows=int(data.get("runtime", {}).get("table_max_rows", 15)),
        )

class CalderaClient:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg
        self.base = cfg.caldera_url
        self.session = requests.Session()
        self.session.headers.update({
            "KEY": cfg.caldera_api_key,
            "Content-Type": "application/json",
        })

    def rest(self, method: str, payload: Dict[str, Any]) -> Any:
        url = f"{self.base}/api/rest"
        response = self.session.request(method=method, url=url, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        if response.text.strip():
            return response.json()
        return {"status": "ok"}

    def list_adversaries(self) -> List[Dict[str, Any]]:
        result = self.rest("POST", {"index": "adversaries"})
        return result if isinstance(result, list) else []

    def list_agents(self) -> List[Dict[str, Any]]:
        result = self.rest("POST", {"index": "agents"})
        return result if isinstance(result, list) else []

    def list_operations(self) -> List[Dict[str, Any]]:
        result = self.rest("POST", {"index": "operations"})
        return result if isinstance(result, list) else []

    def list_abilities(self) -> List[Dict[str, Any]]:
        result = self.rest("POST", {"index": "abilities"})
        return result if isinstance(result, list) else []

    def choose_adversary(self, interactive: bool = False) -> Optional[Dict[str, Any]]:
        adversaries = self.list_adversaries()
        if not adversaries:
            return None

        if self.cfg.caldera_adversary_ids:
            wanted = set(self.cfg.caldera_adversary_ids)
            for adv in adversaries:
                adv_id = str(adv.get("adversary_id") or adv.get("id") or "")
                if adv_id in wanted:
                    return adv

        if not interactive:
            return adversaries[0]

        print("\nAvailable adversaries from Caldera:")
        for i, adv in enumerate(adversaries, start=1):
            adv_id = adv.get("adversary_id") or adv.get("id") or "unknown"
            name = adv.get("name") or adv_id
            description = truncate(adv.get("description", ""), 70)
            ordering = adv.get("atomic_ordering") or []
            print(f"{i:>2}. {adv_id:<22} | {truncate(name, 28):<28} | abilities: {len(ordering):<3} | {description}")

        while True:
            selected = input("\nSelect adversary number (blank = 1): ").strip() or "1"
            if selected.isdigit() and 1 <= int(selected) <= len(adversaries):
                return adversaries[int(selected) - 1]
            print("Invalid selection.")

    def choose_agent(self, interactive: bool = False) -> Optional[Dict[str, Any]]:
        agents = self.list_agents()
        if not agents:
            return None

        if self.cfg.target_agent_paw:
            for agent in agents:
                if str(agent.get("paw")) == self.cfg.target_agent_paw:
                    return agent

        if not interactive:
            return agents[0]

        print("\nAvailable agents from Caldera:")
        for i, agent in enumerate(agents, start=1):
            paw = agent.get("paw", "unknown")
            host = agent.get("host", "unknown")
            group = agent.get("group", "unknown")
            exe = agent.get("exe_name", "")
            trusted = agent.get("trusted", False)
            last_seen = agent.get("last_seen", "")
            print(f"{i:>2}. {paw:<20} | host: {truncate(host, 18):<18} | group: {group:<10} | trusted: {str(trusted):<5} | {truncate(exe, 14):<14} | {truncate(last_seen, 20)}")

        while True:
            selected = input("\nSelect agent number (blank = 1): ").strip() or "1"
            if selected.isdigit() and 1 <= int(selected) <= len(agents):
                return agents[int(selected) - 1]
            print("Invalid selection.")

    def create_operation_legacy(self, name: str, adversary_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        payload = {
            "index": "operations",
            "name": name,
            "adversary_id": adversary_id,
            "planner": "atomic",
            "source": "basic",
            "jitter": "2/8",
            "obfuscator": "plain-text",
        }
        if group:
            payload["group"] = group
        result = self.rest("PUT", payload)
        return result if isinstance(result, dict) else {"raw": result}

class D3fendMapper:
    def __init__(self, mappings_url: str) -> None:
        self.mappings_url = mappings_url
        self.loaded = False
        self.attack_to_d3fend: Dict[str, Set[str]] = {}

    def load(self) -> None:
        if self.loaded:
            return
        r = requests.get(self.mappings_url, timeout=45)
        r.raise_for_status()
        data = r.json()

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                blob = json.dumps(obj, ensure_ascii=False)
                attack_ids = {m.upper() for m in ATTACK_ID_RE.findall(blob)}
                d3f_ids = set(re.findall(r"d3f:[A-Za-z0-9_]+", blob))
                for attack_id in attack_ids:
                    self.attack_to_d3fend.setdefault(attack_id, set()).update(d3f_ids)
                for value in obj.values():
                    walk(value)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)
        self.loaded = True

    def map_attack_ids(self, attack_ids: Set[str]) -> Dict[str, List[str]]:
        self.load()
        return {aid: sorted(self.attack_to_d3fend.get(aid, set())) for aid in sorted(attack_ids)}

class WazuhTailMonitor(threading.Thread):
    def __init__(self, cfg: LabConfig, line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]", stop_event: threading.Event):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.line_queue = line_queue
        self.stop_event = stop_event
        self.client: Optional[paramiko.SSHClient] = None
        self.command = f"sudo tail -n 0 -F {self.cfg.wazuh_log_path}"

    def connect(self) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": self.cfg.wazuh_host,
            "port": self.cfg.wazuh_port,
            "username": self.cfg.wazuh_username,
            "timeout": 20,
            "banner_timeout": 20,
            "auth_timeout": 20,
        }
        if self.cfg.wazuh_key_path:
            kwargs["key_filename"] = self.cfg.wazuh_key_path
        else:
            kwargs["password"] = self.cfg.wazuh_password
        self.client.connect(**kwargs)

    def run(self) -> None:
        try:
            self.connect()
            assert self.client is not None
            transport = self.client.get_transport()
            if transport is None:
                raise RuntimeError("SSH transport unavailable")
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(self.command)

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
                        parsed = self.try_parse(line)
                        self.line_queue.put((line, parsed))
                else:
                    time.sleep(0.2)
        except Exception as exc:
            self.line_queue.put((f"__MONITOR_ERROR__ {exc}", {"monitor_error": str(exc)}))
        finally:
            if self.client:
                self.client.close()

    @staticmethod
    def try_parse(line: str) -> Dict[str, Any]:
        try:
            return json.loads(line)
        except Exception:
            return {"raw": line}

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

    for ip in candidates:
        if ip in set(cfg.preferred_source_ips):
            return ip

    excluded = set(filter(None, cfg.known_lab_ips))
    if cfg.target_ip:
        excluded.add(cfg.target_ip)

    filtered = [ip for ip in candidates if ip not in excluded]
    if filtered:
        return filtered[0]

    return candidates[0] if candidates else "unknown"

def extract_timestamp(alert: Dict[str, Any]) -> str:
    return str(alert.get("timestamp") or alert.get("@timestamp") or now_utc())

def alert_matches_target(alert: Dict[str, Any], cfg: LabConfig) -> bool:
    if not cfg.target_ip:
        return True
    return cfg.target_ip in json.dumps(alert, ensure_ascii=False)

def build_session_id(operation_name: str) -> str:
    return f"{sanitize_name(operation_name)}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"

def render_table(rows: List[Dict[str, str]], header_note: str) -> None:
    clear_screen()
    print(header_note)
    print("-" * 146)
    header = f"{'TIME':<20} {'SRC IP':<16} {'AGENT':<16} {'LVL':<4} {'ATT&CK':<18} {'RULE / DESCRIPTION':<65}"
    print(header)
    print("-" * 146)
    for row in rows:
        print(f"{row['time']:<20} {row['src']:<16} {row['agent']:<16} {row['lvl']:<4} {row['attack']:<18} {row['desc']:<65}")
    print("-" * 146)

def generate_report(output_path: Path, title: str, cfg: LabConfig, session_id: str, operation_info: Dict[str, Any], observed_alerts: List[Dict[str, Any]], attack_ids: Set[str], d3f_map: Dict[str, List[str]], source_ip: Optional[str] = None) -> None:
    attack_rows = []
    for aid in sorted(attack_ids):
        mapped = d3f_map.get(aid, [])
        url = f"{cfg.attack_lookup_base}{aid.replace('.', '/')}/"
        attack_rows.append(
            f"<tr><td><a href='{html.escape(url)}'>{html.escape(aid)}</a></td><td>{html.escape(', '.join(mapped) if mapped else 'No mapped D3FEND technique found')}</td></tr>"
        )

    cards = []
    for alert in observed_alerts[:300]:
        rule = alert.get("rule", {})
        cards.append(
            f"<div class='card'><h3>Level {html.escape(str(rule.get('level', 'n/a')))} — {html.escape(str(rule.get('description', 'Wazuh alert')))}</h3>"
            f"<p><strong>Timestamp:</strong> {html.escape(extract_timestamp(alert))}<br>"
            f"<strong>Agent:</strong> {html.escape(str(alert.get('agent', {}).get('name', 'unknown')))}<br>"
            f"<strong>Source IP:</strong> {html.escape(str(alert.get('_inferred_source_ip', 'unknown')))}</p>"
            f"<pre>{html.escape(json.dumps(alert, ensure_ascii=False, indent=2))}</pre></div>"
        )

    scope_line = f"<li><strong>Source IP scope:</strong> {html.escape(source_ip)}</li>" if source_ip else ""
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }}
.card {{ background: #1c1c1c; border: 1px solid #333; border-left: 6px solid #b22222; padding: 14px; margin: 14px 0; border-radius: 8px; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #0b0b0b; padding: 12px; border-radius: 6px; border: 1px solid #333; }}
table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #222; }} a {{ color: #7db8ff; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p><strong>Generated:</strong> {html.escape(now_utc())}</p>
<ul>
<li><strong>Session ID:</strong> {html.escape(session_id)}</li>
<li><strong>Caldera:</strong> {html.escape(cfg.caldera_url)}</li>
<li><strong>Wazuh:</strong> {html.escape(cfg.wazuh_host)}</li>
<li><strong>Target:</strong> {html.escape(cfg.target_ip or 'not set')}</li>
<li><strong>T-Pot:</strong> {html.escape(cfg.tpot_ip or 'configurable / not set')}</li>
{scope_line}
</ul>
<h2>Operation Details</h2><pre>{html.escape(json.dumps(operation_info, ensure_ascii=False, indent=2))}</pre>
<h2>Observed ATT&CK Techniques</h2>
<table><tr><th>ATT&CK Technique</th><th>Mapped D3FEND techniques</th></tr>
{''.join(attack_rows) if attack_rows else '<tr><td colspan="2">No ATT&CK techniques extracted from observed alerts.</td></tr>'}
</table>
<h2>Observed Wazuh Alerts</h2>
{''.join(cards) if cards else '<p>No matching alerts captured during the observation window.</p>'}
</body></html>
"""
    output_path.write_text(doc, encoding="utf-8")

def launch_monitor_window_if_requested(config_path: str, session_dir: Path, duration_seconds: int) -> bool:
    if platform.system().lower() != "windows":
        return False
    script_path = Path(__file__).resolve()
    cmd = [
        "powershell",
        "-NoExit",
        "-Command",
        (
            f"python '{script_path}' --config '{Path(config_path).resolve()}' "
            f"--monitor-only --session-dir '{session_dir.resolve()}' --monitor-seconds {duration_seconds}"
        ),
    ]
    subprocess.Popen(["cmd", "/c", "start", "Wazuh Monitor", *cmd], shell=False)
    return True

def build_source_summaries(grouped: Dict[str, List[Dict[str, Any]]], base_dir: Path) -> None:
    by_source_dir = base_dir / "by_source_ip"
    ensure_dir(by_source_dir)
    for source_ip, alerts in grouped.items():
        src_dir = by_source_dir / sanitize_name(source_ip)
        ensure_dir(src_dir)
        write_json(src_dir / "alerts.json", alerts)
        summary = {
            "source_ip": source_ip,
            "first_seen": min(extract_timestamp(a) for a in alerts) if alerts else None,
            "last_seen": max(extract_timestamp(a) for a in alerts) if alerts else None,
            "count": len(alerts),
            "attack_ids": sorted({aid for alert in alerts for aid in extract_attack_ids(alert)}),
        }
        write_json(src_dir / "summary.json", summary)

def build_reports(cfg: LabConfig, mapper: D3fendMapper, session_dir: Path, session_id: str, operation_info: Dict[str, Any], observed_alerts: List[Dict[str, Any]], grouped: Dict[str, List[Dict[str, Any]]]) -> None:
    all_attack_ids = {aid for alert in observed_alerts for aid in extract_attack_ids(alert)}
    global_map = mapper.map_attack_ids(all_attack_ids) if all_attack_ids else {}
    generate_report(session_dir / "report.html", "Cyber Lab Orchestrator Report", cfg, session_id, operation_info, observed_alerts, all_attack_ids, global_map)

    index_rows = []
    by_source_dir = session_dir / "by_source_ip"
    ensure_dir(by_source_dir)
    for source_ip, alerts in sorted(grouped.items(), key=lambda kv: (kv[0] == "unknown", kv[0])):
        attack_ids = {aid for alert in alerts for aid in extract_attack_ids(alert)}
        d3f_map = mapper.map_attack_ids(attack_ids) if attack_ids else {}
        src_dir = by_source_dir / sanitize_name(source_ip)
        ensure_dir(src_dir)
        generate_report(src_dir / "report.html", f"Cyber Lab Report — Source IP {source_ip}", cfg, session_id, operation_info, alerts, attack_ids, d3f_map, source_ip=source_ip)
        index_rows.append(
            f"<tr><td>{html.escape(source_ip)}</td><td>{len(alerts)}</td><td>{html.escape(', '.join(sorted(attack_ids)) if attack_ids else 'none')}</td><td><a href='./{sanitize_name(source_ip)}/report.html'>open report</a></td></tr>"
        )

    index_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Per-source reports</title>
<style>body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }} table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }} th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }} th {{ background: #222; }} a {{ color: #7db8ff; }}</style>
</head><body><h1>Per-source-IP reports</h1><p><strong>Session:</strong> {html.escape(session_id)}</p>
<table><tr><th>Source IP</th><th>Alerts</th><th>ATT&CK IDs</th><th>Report</th></tr>
{''.join(index_rows) if index_rows else '<tr><td colspan="4">No grouped alerts available.</td></tr>'}
</table></body></html>"""
    (by_source_dir / "index.html").write_text(index_html, encoding="utf-8")

def monitor_loop(cfg: LabConfig, session_dir: Path, monitor_seconds: int, operation_info: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop_event = threading.Event()
    monitor = WazuhTailMonitor(cfg, line_queue, stop_event)
    monitor.start()

    observed_alerts: List[Dict[str, Any]] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    recent_rows: List[Dict[str, str]] = []

    deadline = time.time() + monitor_seconds
    last_refresh = 0.0

    try:
        while time.time() < deadline:
            now = time.time()
            try:
                line, parsed = line_queue.get(timeout=0.2)
            except queue.Empty:
                if now - last_refresh >= cfg.table_refresh_seconds:
                    render_table(
                        recent_rows[-cfg.table_max_rows:],
                        header_note=f"[+] Wazuh live monitor | session: {session_dir.name} | remaining: {int(max(0, deadline - now))}s | alerts captured: {len(observed_alerts)}",
                    )
                    last_refresh = now
                continue

            if parsed.get("monitor_error"):
                clear_screen()
                print(f"Monitor error: {parsed['monitor_error']}")
                break

            source_ip = infer_source_ip(parsed, cfg)
            parsed["_inferred_source_ip"] = source_ip
            parsed["_capture_session"] = session_dir.name
            parsed["_captured_at_utc"] = now_utc()

            if alert_matches_target(parsed, cfg):
                observed_alerts.append(parsed)
                grouped.setdefault(source_ip, []).append(parsed)

                row = {
                    "time": truncate(extract_timestamp(parsed), 20),
                    "src": truncate(source_ip, 16),
                    "agent": truncate(parsed.get("agent", {}).get("name", "unknown"), 16),
                    "lvl": str(severity_of(parsed)),
                    "attack": truncate(",".join(sorted(extract_attack_ids(parsed))) or "-", 18),
                    "desc": truncate(parsed.get("rule", {}).get("description", parsed.get("decoder", {}).get("name", "alert")), 65),
                }
                recent_rows.append(row)
                recent_rows = recent_rows[-200:]

            if now - last_refresh >= cfg.table_refresh_seconds:
                render_table(
                    recent_rows[-cfg.table_max_rows:],
                    header_note=f"[+] Wazuh live monitor | session: {session_dir.name} | remaining: {int(max(0, deadline - now))}s | alerts captured: {len(observed_alerts)}",
                )
                last_refresh = now
    finally:
        stop_event.set()
        monitor.join(timeout=3)

    write_json(session_dir / "captured_alerts_all.json", observed_alerts)
    build_source_summaries(grouped, session_dir)
    return observed_alerts, grouped

def run_monitor_only(config_path: str, session_dir: str, monitor_seconds: int) -> int:
    cfg = LabConfig.from_file(config_path)
    session_path = Path(session_dir)
    ensure_dir(session_path)
    mapper = D3fendMapper(cfg.d3fend_mappings_url)
    operation_info = {"mode": "monitor-only", "session_id": session_path.name}
    observed_alerts, grouped = monitor_loop(cfg, session_path, monitor_seconds, operation_info=operation_info)
    build_reports(cfg, mapper, session_path, session_path.name, operation_info, observed_alerts, grouped)
    print(f"\n[+] Monitor-only session saved to: {session_path.resolve()}")
    return 0

def run(config_path: str, interactive_select: bool = False, list_only: bool = False) -> int:
    cfg = LabConfig.from_file(config_path)
    out_dir = Path(cfg.output_dir)
    ensure_dir(out_dir)

    caldera = CalderaClient(cfg)

    if list_only:
        adversaries = caldera.list_adversaries()
        agents = caldera.list_agents()
        print("\nAdversaries")
        print("=" * 80)
        for adv in adversaries:
            adv_id = adv.get("adversary_id") or adv.get("id") or "unknown"
            print(f"{adv_id:<24} | {truncate(adv.get('name', ''), 35):<35} | abilities: {len(adv.get('atomic_ordering', []) or [])}")
        print("\nAgents")
        print("=" * 80)
        for agent in agents:
            print(f"{agent.get('paw', 'unknown'):<22} | host: {truncate(agent.get('host', ''), 18):<18} | group: {agent.get('group', 'unknown'):<10} | trusted: {str(agent.get('trusted', False)):<5}")
        return 0

    selected_adv = caldera.choose_adversary(interactive=interactive_select)
    if not selected_adv:
        print("[-] No adversary profiles returned by Caldera.", file=sys.stderr)
        return 2

    selected_agent = caldera.choose_agent(interactive=interactive_select)
    selected_adv_id = selected_adv.get("adversary_id") or selected_adv.get("id")
    selected_group = selected_agent.get("group") if selected_agent else "red"
    selected_paw = selected_agent.get("paw") if selected_agent else None

    operation_name = f"{cfg.operation_name_prefix}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    session_id = build_session_id(operation_name)
    session_dir = out_dir / session_id
    ensure_dir(session_dir)

    selector_info = {
        "selected_adversary": selected_adv,
        "selected_agent": selected_agent,
        "note": "Agent selection is used to choose the operation group. Caldera operations execute against agents in that group.",
    }
    write_json(session_dir / "selector_info.json", selector_info)

    print(f"[+] Selected adversary: {selected_adv_id}")
    print(f"[+] Selected agent paw: {selected_paw or 'none'}")
    print(f"[+] Selected group: {selected_group}")

    try:
        operation_info = caldera.create_operation_legacy(operation_name, adversary_id=str(selected_adv_id), group=selected_group)
    except Exception as exc:
        print(f"[-] Failed to start Caldera operation: {exc}", file=sys.stderr)
        return 3

    operation_info["_selector"] = {
        "adversary_id": selected_adv_id,
        "agent_paw": selected_paw,
        "group": selected_group,
    }
    write_json(session_dir / "operation_info.json", operation_info)

    total_monitor_seconds = cfg.monitor_seconds + cfg.extra_monitor_seconds
    if cfg.launch_monitor_window:
        try:
            if launch_monitor_window_if_requested(config_path, session_dir, total_monitor_seconds):
                print(f"[+] Separate PowerShell monitor started for {total_monitor_seconds} seconds")
                print(f"[+] Session directory: {session_dir.resolve()}")
                return 0
        except Exception as exc:
            print(f"[!] Could not open separate monitor window: {exc}")

    print("[!] Separate window not started. Falling back to inline monitor.")
    mapper = D3fendMapper(cfg.d3fend_mappings_url)
    observed_alerts, grouped = monitor_loop(cfg, session_dir, total_monitor_seconds, operation_info=operation_info)
    build_reports(cfg, mapper, session_dir, session_id, operation_info, observed_alerts, grouped)

    print(f"\n[+] Global report: {(session_dir / 'report.html').resolve()}")
    print(f"[+] Per-source reports: {(session_dir / 'by_source_ip' / 'index.html').resolve()}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cyber lab orchestrator")
    parser.add_argument("-c", "--config", default="config.yml", help="Path to YAML config file")
    parser.add_argument("--select", action="store_true", help="Interactively select adversary and agent from Caldera")
    parser.add_argument("--list-caldera", action="store_true", help="Only list adversaries and agents from Caldera")
    parser.add_argument("--monitor-only", action="store_true", help="Run only the Wazuh monitor")
    parser.add_argument("--session-dir", help="Session directory for monitor-only mode")
    parser.add_argument("--monitor-seconds", type=int, help="Override monitor duration in seconds")
    return parser

if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.monitor_only:
        if not args.session_dir:
            print("[-] --session-dir is required with --monitor-only", file=sys.stderr)
            raise SystemExit(4)
        seconds = args.monitor_seconds if args.monitor_seconds is not None else 600
        raise SystemExit(run_monitor_only(args.config, args.session_dir, seconds))
    raise SystemExit(run(args.config, interactive_select=args.select, list_only=args.list_caldera))
