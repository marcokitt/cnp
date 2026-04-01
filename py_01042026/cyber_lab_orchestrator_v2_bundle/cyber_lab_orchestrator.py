#!/usr/bin/env python3
"""
Cyber Lab Orchestrator v2
- Launches ATT&CK-aligned emulation operations on MITRE Caldera
- Can spawn a separate monitor window on Windows PowerShell
- Monitors Wazuh alerts.json live over SSH for a longer custom duration
- Splits captured logs by inferred source IP and session time
- Extracts ATT&CK technique IDs from alerts
- Maps ATT&CK -> MITRE D3FEND defensive techniques
- Generates a global HTML report and per-source-IP reports

Designed for authorized lab use only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import ipaddress
from dataclasses import dataclass
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
ANSI_RESET = "\033[0m"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class LabConfig:
    caldera_url: str
    caldera_api_key: str
    caldera_username: str
    caldera_password: str
    target_agent_paw: Optional[str]
    operation_name_prefix: str
    caldera_adversary_ids: List[str]
    caldera_use_legacy_api: bool

    wazuh_host: str
    wazuh_port: int
    wazuh_username: str
    wazuh_password: Optional[str]
    wazuh_key_path: Optional[str]
    wazuh_log_path: str
    wazuh_archive_path: Optional[str]

    target_ip: Optional[str]
    tpot_ip: Optional[str]
    tpot_notes: Optional[str]

    d3fend_mappings_url: str
    attack_lookup_base: str

    monitor_seconds: int
    extra_monitor_seconds: int
    output_dir: str
    launch_monitor_window: bool
    preferred_source_ips: List[str]
    known_lab_ips: List[str]

    @staticmethod
    def from_file(path: str) -> "LabConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        target_ip = data.get("lab", {}).get("target_ip") or data.get("target", {}).get("ip")
        known_lab_ips = list(dict.fromkeys([
            ip for ip in [
                target_ip,
                data["caldera"].get("url", "").replace("http://", "").replace("https://", "").split(":")[0] or None,
                data["wazuh"].get("host"),
                data.get("tpot", {}).get("ip"),
                *(data.get("runtime", {}).get("known_lab_ips", []) or []),
            ] if ip
        ]))

        return LabConfig(
            caldera_url=data["caldera"]["url"].rstrip("/"),
            caldera_api_key=data["caldera"]["api_key"],
            caldera_username=data["caldera"].get("username", ""),
            caldera_password=data["caldera"].get("password", ""),
            target_agent_paw=data["caldera"].get("target_agent_paw"),
            operation_name_prefix=data["caldera"].get("operation_name_prefix", "auto-op"),
            caldera_adversary_ids=data["caldera"].get("adversary_ids", []),
            caldera_use_legacy_api=bool(data["caldera"].get("use_legacy_api", True)),
            wazuh_host=data["wazuh"]["host"],
            wazuh_port=int(data["wazuh"].get("port", 22)),
            wazuh_username=data["wazuh"]["username"],
            wazuh_password=data["wazuh"].get("password"),
            wazuh_key_path=data["wazuh"].get("key_path"),
            wazuh_log_path=data["wazuh"].get("log_path", "/var/ossec/logs/alerts/alerts.json"),
            wazuh_archive_path=data["wazuh"].get("archive_path"),
            target_ip=target_ip,
            tpot_ip=data.get("tpot", {}).get("ip"),
            tpot_notes=data.get("tpot", {}).get("notes"),
            d3fend_mappings_url=data.get("mitre", {}).get(
                "d3fend_mappings_url",
                "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json",
            ),
            attack_lookup_base=data.get("mitre", {}).get(
                "attack_lookup_base", "https://attack.mitre.org/techniques/"
            ),
            monitor_seconds=int(data.get("runtime", {}).get("monitor_seconds", 240)),
            extra_monitor_seconds=int(data.get("runtime", {}).get("extra_monitor_seconds", 300)),
            output_dir=data.get("runtime", {}).get("output_dir", "output"),
            launch_monitor_window=bool(data.get("runtime", {}).get("launch_monitor_window", True)),
            preferred_source_ips=data.get("runtime", {}).get("preferred_source_ips", []) or [],
            known_lab_ips=known_lab_ips,
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

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base}{path}"
        resp = self.session.request(method, url, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp

    def list_adversaries_legacy(self) -> List[Dict[str, Any]]:
        resp = self._request("POST", "/api/rest", data=json.dumps({"index": "adversaries"}))
        return resp.json()

    def create_operation_legacy(self, name: str, adversary_id: str, group: str = "red") -> Dict[str, Any]:
        payload = {
            "index": "operations",
            "name": name,
            "group": group,
            "adversary_id": adversary_id,
            "planner": "batch",
            "source": "basic",
            "jitter": "2/8",
            "obfuscator": "plain-text",
        }
        resp = self._request("PUT", "/api/rest", data=json.dumps(payload))
        return resp.json() if resp.text.strip() else {"status": "submitted"}

    def choose_adversary(self) -> Optional[str]:
        if self.cfg.caldera_adversary_ids:
            return self.cfg.caldera_adversary_ids[0]
        try:
            adversaries = self.list_adversaries_legacy()
            for adv in adversaries:
                adv_id = adv.get("adversary_id") or adv.get("id")
                if adv_id:
                    return adv_id
        except Exception:
            return None
        return None


class D3fendMapper:
    def __init__(self, mappings_url: str) -> None:
        self.mappings_url = mappings_url
        self.loaded = False
        self.attack_to_d3fend: Dict[str, Set[str]] = {}

    def load(self) -> None:
        if self.loaded:
            return
        resp = requests.get(self.mappings_url, timeout=45)
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
        for attack_id in sorted(attack_ids):
            result[attack_id] = sorted(self.attack_to_d3fend.get(attack_id, set()))
        return result


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


def now_utc() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sanitize_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())[:120] or "unknown"


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
    level = alert.get("rule", {}).get("level", 0)
    try:
        return int(level)
    except Exception:
        return 0


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


def infer_source_ip(alert: Dict[str, Any], cfg: LabConfig) -> str:
    preferred_paths = [
        ["data", "srcip"],
        ["srcip"],
        ["predecoder", "hostname"],
        ["win", "eventdata", "sourceIp"],
        ["win", "eventdata", "SourceIp"],
        ["win", "eventdata", "source_ip"],
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

    text_candidates = find_ipv4s_in_obj(alert)
    candidates.extend(text_candidates)

    preferred = [ip for ip in candidates if ip in set(cfg.preferred_source_ips)]
    if preferred:
        return preferred[0]

    excluded = set(filter(None, cfg.known_lab_ips))
    if cfg.target_ip:
        excluded.add(cfg.target_ip)

    filtered = [ip for ip in candidates if ip not in excluded]
    if filtered:
        return filtered[0]

    if cfg.caldera_url:
        caldera_ip = cfg.caldera_url.replace("http://", "").replace("https://", "").split(":")[0]
        if caldera_ip in candidates:
            return caldera_ip

    if candidates:
        return candidates[0]
    return "unknown"


def extract_timestamp(alert: Dict[str, Any]) -> str:
    return str(alert.get("timestamp") or alert.get("@timestamp") or now_utc())


def print_live_alert(line: str, parsed: Dict[str, Any], source_ip: str = "unknown") -> None:
    level = severity_of(parsed)
    prefix = f"[WAZUH][SRC:{source_ip}]"
    if level >= 10:
        print(f"{ANSI_RED}{prefix} {line}{ANSI_RESET}")
    elif level >= 5:
        print(f"{ANSI_YELLOW}{prefix} {line}{ANSI_RESET}")
    else:
        print(f"{ANSI_GREEN}{prefix} {line}{ANSI_RESET}")


def alert_matches_target(alert: Dict[str, Any], cfg: LabConfig) -> bool:
    if not cfg.target_ip:
        return True
    blob = json.dumps(alert, ensure_ascii=False)
    return cfg.target_ip in blob


def build_session_id(operation_name: str) -> str:
    return f"{sanitize_name(operation_name)}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def generate_report(
    output_path: Path,
    title: str,
    config: LabConfig,
    session_id: str,
    operation_info: Dict[str, Any],
    observed_alerts: List[Dict[str, Any]],
    attack_ids: Set[str],
    d3f_map: Dict[str, List[str]],
    source_ip: Optional[str] = None,
) -> None:
    rows = []
    for aid in sorted(attack_ids):
        d3_list = d3f_map.get(aid, [])
        attack_url = f"{config.attack_lookup_base}{aid.replace('.', '/')}/"
        rows.append(
            f"<tr><td><a href='{html.escape(attack_url)}'>{html.escape(aid)}</a></td>"
            f"<td>{html.escape(', '.join(d3_list) if d3_list else 'No mapped D3FEND technique found')}</td></tr>"
        )

    alert_cards = []
    for item in observed_alerts[:300]:
        rule = item.get("rule", {})
        title_card = rule.get("description", "Wazuh alert")
        level = rule.get("level", "n/a")
        agent_name = item.get("agent", {}).get("name", "unknown")
        ts = extract_timestamp(item)
        inferred_src = item.get("_inferred_source_ip", "unknown")
        alert_cards.append(
            f"""
            <div class="card">
              <h3>Level {html.escape(str(level))} — {html.escape(str(title_card))}</h3>
              <p><strong>Timestamp:</strong> {html.escape(str(ts))}<br>
              <strong>Agent:</strong> {html.escape(str(agent_name))}<br>
              <strong>Inferred source IP:</strong> {html.escape(str(inferred_src))}</p>
              <pre>{html_escape_json(item)}</pre>
            </div>
            """
        )

    op_json = html_escape_json(operation_info)
    source_banner = f"<li><strong>Source IP scope:</strong> {html.escape(source_ip)}</li>" if source_ip else ""

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }}
h1, h2, h3 {{ color: #fff; }}
.card {{ background: #1c1c1c; border: 1px solid #333; border-left: 6px solid #b22222; padding: 14px; margin: 14px 0; border-radius: 8px; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #0b0b0b; padding: 12px; border-radius: 6px; border: 1px solid #333; }}
table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #222; }}
a {{ color: #7db8ff; }}
small {{ color: #bbb; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p><strong>Generated:</strong> {html.escape(now_utc())}</p>

<h2>Lab Summary</h2>
<ul>
  <li><strong>Session ID:</strong> {html.escape(session_id)}</li>
  <li><strong>Caldera:</strong> {html.escape(config.caldera_url)}</li>
  <li><strong>Wazuh:</strong> {html.escape(config.wazuh_host)}</li>
  <li><strong>Target:</strong> {html.escape(config.target_ip or 'not set')}</li>
  <li><strong>T-Pot:</strong> {html.escape(config.tpot_ip or 'configurable / not set')}</li>
  <li><strong>Observation window:</strong> {html.escape(str(config.monitor_seconds + config.extra_monitor_seconds))} seconds</li>
  {source_banner}
</ul>

<h2>Operation Details</h2>
<pre>{op_json}</pre>

<h2>Observed ATT&amp;CK Techniques</h2>
<table>
<tr><th>ATT&amp;CK Technique</th><th>Mapped D3FEND techniques</th></tr>
{''.join(rows) if rows else '<tr><td colspan="2">No ATT&CK techniques extracted from observed alerts.</td></tr>'}
</table>

<h2>Observed Wazuh Alerts</h2>
{''.join(alert_cards) if alert_cards else '<p>No matching alerts captured during the observation window.</p>'}

<h2>Recommended Next Steps</h2>
<ol>
  <li>Validate the mapped D3FEND techniques against your Windows 10 hardening baseline.</li>
  <li>Create Wazuh correlation rules using source IP + ATT&amp;CK ID + time bucket.</li>
  <li>Keep T-Pot telemetry in the same timeline to distinguish lure activity from endpoint compromise.</li>
  <li>Use one report per source IP to compare repeated attack paths and defensive coverage.</li>
</ol>

<small>This report is generated for authorized lab validation only.</small>
</body>
</html>
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
            f"python '{script_path}' "
            f"--config '{Path(config_path).resolve()}' "
            f"--monitor-only "
            f"--session-dir '{session_dir.resolve()}' "
            f"--monitor-seconds {duration_seconds}"
        )
    ]
    subprocess.Popen(["cmd", "/c", "start", "Wazuh Monitor", *cmd], shell=False)
    return True


def monitor_loop(
    cfg: LabConfig,
    session_dir: Path,
    monitor_seconds: int,
    operation_info: Optional[Dict[str, Any]] = None,
    quiet: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop_event = threading.Event()
    monitor = WazuhTailMonitor(cfg, line_queue, stop_event)
    monitor.start()

    observed_alerts: List[Dict[str, Any]] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    deadline = time.time() + monitor_seconds
    if not quiet:
        print(f"{ANSI_CYAN}[+] Monitoring Wazuh for {monitor_seconds} seconds...{ANSI_RESET}")

    try:
        while time.time() < deadline:
            try:
                line, parsed = line_queue.get(timeout=1)
            except queue.Empty:
                continue

            if parsed.get("monitor_error"):
                print(f"[-] Monitor error: {parsed['monitor_error']}", file=sys.stderr)
                continue

            source_ip = infer_source_ip(parsed, cfg)
            parsed["_inferred_source_ip"] = source_ip
            parsed["_capture_session"] = session_dir.name
            parsed["_captured_at_utc"] = now_utc()

            if not quiet:
                print_live_alert(line, parsed, source_ip)

            if alert_matches_target(parsed, cfg):
                observed_alerts.append(parsed)
                grouped.setdefault(source_ip, []).append(parsed)

    finally:
        stop_event.set()
        monitor.join(timeout=3)

    ensure_dir(session_dir)
    write_json(session_dir / "captured_alerts_all.json", observed_alerts)

    per_source_dir = session_dir / "by_source_ip"
    ensure_dir(per_source_dir)
    for source_ip, alerts in grouped.items():
        src_dir = per_source_dir / sanitize_name(source_ip)
        ensure_dir(src_dir)
        write_json(src_dir / "alerts.json", alerts)

        summary = {
            "source_ip": source_ip,
            "first_seen": min(extract_timestamp(a) for a in alerts) if alerts else None,
            "last_seen": max(extract_timestamp(a) for a in alerts) if alerts else None,
            "count": len(alerts),
            "attack_ids": sorted({attack for alert in alerts for attack in extract_attack_ids(alert)}),
        }
        write_json(src_dir / "summary.json", summary)

    return observed_alerts, grouped


def build_per_source_reports(
    cfg: LabConfig,
    mapper: D3fendMapper,
    session_dir: Path,
    session_id: str,
    operation_info: Dict[str, Any],
    grouped: Dict[str, List[Dict[str, Any]]],
) -> None:
    per_source_dir = session_dir / "by_source_ip"
    ensure_dir(per_source_dir)

    index_rows = []
    for source_ip, alerts in sorted(grouped.items(), key=lambda kv: (kv[0] == "unknown", kv[0])):
        attack_ids = {attack for alert in alerts for attack in extract_attack_ids(alert)}
        try:
            d3f_map = mapper.map_attack_ids(attack_ids) if attack_ids else {}
        except Exception:
            d3f_map = {aid: [] for aid in attack_ids}

        src_dir = per_source_dir / sanitize_name(source_ip)
        ensure_dir(src_dir)
        report_path = src_dir / "report.html"
        generate_report(
            output_path=report_path,
            title=f"Cyber Lab Report — Source IP {source_ip}",
            config=cfg,
            session_id=session_id,
            operation_info=operation_info,
            observed_alerts=alerts,
            attack_ids=attack_ids,
            d3f_map=d3f_map,
            source_ip=source_ip,
        )
        index_rows.append(
            f"<tr><td>{html.escape(source_ip)}</td><td>{len(alerts)}</td>"
            f"<td>{html.escape(', '.join(sorted(attack_ids)) if attack_ids else 'none')}</td>"
            f"<td><a href='./{sanitize_name(source_ip)}/report.html'>open report</a></td></tr>"
        )

    index_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Per-source reports</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }}
table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
th {{ background: #222; }}
a {{ color: #7db8ff; }}
</style></head>
<body>
<h1>Per-source-IP reports</h1>
<p><strong>Session:</strong> {html.escape(session_id)}</p>
<table>
<tr><th>Source IP</th><th>Alerts</th><th>ATT&amp;CK IDs</th><th>Report</th></tr>
{''.join(index_rows) if index_rows else '<tr><td colspan="4">No grouped alerts available.</td></tr>'}
</table>
</body></html>
"""
    (per_source_dir / "index.html").write_text(index_html, encoding="utf-8")


def build_global_report(
    cfg: LabConfig,
    mapper: D3fendMapper,
    session_dir: Path,
    session_id: str,
    operation_info: Dict[str, Any],
    observed_alerts: List[Dict[str, Any]],
) -> None:
    observed_attack_ids = {attack for alert in observed_alerts for attack in extract_attack_ids(alert)}
    try:
        d3f_map = mapper.map_attack_ids(observed_attack_ids) if observed_attack_ids else {}
    except Exception:
        d3f_map = {aid: [] for aid in observed_attack_ids}

    generate_report(
        output_path=session_dir / "report.html",
        title="Cyber Lab Orchestrator Report",
        config=cfg,
        session_id=session_id,
        operation_info=operation_info,
        observed_alerts=observed_alerts,
        attack_ids=observed_attack_ids,
        d3f_map=d3f_map,
    )


def monitor_only(config_path: str, session_dir: str, monitor_seconds: int) -> int:
    cfg = LabConfig.from_file(config_path)
    session_path = Path(session_dir)
    ensure_dir(session_path)
    session_id = session_path.name
    operation_info = {"mode": "monitor-only", "session_id": session_id}
    mapper = D3fendMapper(cfg.d3fend_mappings_url)

    observed_alerts, grouped = monitor_loop(
        cfg=cfg,
        session_dir=session_path,
        monitor_seconds=monitor_seconds,
        operation_info=operation_info,
        quiet=False,
    )
    build_global_report(cfg, mapper, session_path, session_id, operation_info, observed_alerts)
    build_per_source_reports(cfg, mapper, session_path, session_id, operation_info, grouped)
    print(f"[+] Monitor-only session saved to: {session_path.resolve()}")
    return 0


def run(config_path: str) -> int:
    cfg = LabConfig.from_file(config_path)
    out_dir = Path(cfg.output_dir)
    ensure_dir(out_dir)

    print(f"[+] Loaded configuration from {config_path}")
    print(f"[+] Output directory: {out_dir.resolve()}")

    caldera = CalderaClient(cfg)
    mapper = D3fendMapper(cfg.d3fend_mappings_url)

    adversary_id = caldera.choose_adversary()
    if not adversary_id:
        print("[-] Could not determine an adversary_id from Caldera. Populate caldera.adversary_ids in config.yml.", file=sys.stderr)
        return 2

    op_name = f"{cfg.operation_name_prefix}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    session_id = build_session_id(op_name)
    session_dir = out_dir / session_id
    ensure_dir(session_dir)

    print(f"[+] Selected adversary_id: {adversary_id}")
    print(f"[+] Starting operation: {op_name}")

    try:
        if cfg.caldera_use_legacy_api:
            operation_info = caldera.create_operation_legacy(op_name, adversary_id=adversary_id)
        else:
            operation_info = {"note": "API v2 selected. Adapt this block to your live /api/v2/operations schema."}
    except Exception as exc:
        print(f"[-] Failed to start Caldera operation: {exc}", file=sys.stderr)
        return 3

    write_json(session_dir / "operation_info.json", operation_info)

    total_monitor_seconds = cfg.monitor_seconds + cfg.extra_monitor_seconds
    launched = False
    if cfg.launch_monitor_window:
        try:
            launched = launch_monitor_window_if_requested(config_path, session_dir, total_monitor_seconds)
        except Exception as exc:
            print(f"[!] Could not open separate monitor window: {exc}")

    if launched:
        print(f"[+] Separate PowerShell monitor started for {total_monitor_seconds} seconds")
        print(f"[+] Session directory: {session_dir.resolve()}")
        return 0

    print("[!] Separate window not started. Falling back to inline monitor.")
    observed_alerts, grouped = monitor_loop(
        cfg=cfg,
        session_dir=session_dir,
        monitor_seconds=total_monitor_seconds,
        operation_info=operation_info,
        quiet=False,
    )

    build_global_report(cfg, mapper, session_dir, session_id, operation_info, observed_alerts)
    build_per_source_reports(cfg, mapper, session_dir, session_id, operation_info, grouped)

    print(f"[+] Global report written to: {(session_dir / 'report.html').resolve()}")
    print(f"[+] Per-source report index: {(session_dir / 'by_source_ip' / 'index.html').resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized cyber lab orchestrator")
    parser.add_argument("-c", "--config", default="config.yml", help="Path to YAML config file")
    parser.add_argument("--monitor-only", action="store_true", help="Only run the Wazuh monitor and report builder")
    parser.add_argument("--session-dir", help="Output directory for monitor-only mode")
    parser.add_argument("--monitor-seconds", type=int, help="Override monitor duration in seconds")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.monitor_only:
        if not args.session_dir:
            print("[-] --session-dir is required with --monitor-only", file=sys.stderr)
            raise SystemExit(4)
        seconds = args.monitor_seconds if args.monitor_seconds is not None else 600
        raise SystemExit(monitor_only(args.config, args.session_dir, seconds))
    raise SystemExit(run(args.config))
