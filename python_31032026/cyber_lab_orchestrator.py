#!/usr/bin/env python3
"""
Cyber Lab Orchestrator
- Launches ATT&CK-aligned emulation operations on MITRE Caldera
- Monitors Wazuh alerts.json live over SSH
- Extracts ATT&CK technique IDs from alerts
- Maps ATT&CK -> MITRE D3FEND defensive techniques
- Generates an HTML report

Designed for authorized lab use only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

try:
    import yaml
except Exception as exc:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise

try:
    import paramiko
except Exception as exc:
    print("paramiko is required: pip install paramiko", file=sys.stderr)
    raise


ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


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

    tpot_ip: Optional[str]
    tpot_notes: Optional[str]

    d3fend_mappings_url: str
    attack_lookup_base: str

    monitor_seconds: int
    output_dir: str

    @staticmethod
    def from_file(path: str) -> "LabConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

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
            tpot_ip=data.get("tpot", {}).get("ip"),
            tpot_notes=data.get("tpot", {}).get("notes"),
            d3fend_mappings_url=data.get(
                "mitre",
                {},
            ).get(
                "d3fend_mappings_url",
                "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json",
            ),
            attack_lookup_base=data.get(
                "mitre",
                {},
            ).get("attack_lookup_base", "https://attack.mitre.org/techniques/"),
            monitor_seconds=int(data.get("runtime", {}).get("monitor_seconds", 240)),
            output_dir=data.get("runtime", {}).get("output_dir", "output"),
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

    def change_operation_state_legacy(self, op_id: int, state: str = "running") -> Dict[str, Any]:
        payload = {"index": "operation", "op_id": op_id, "state": state}
        resp = self._request("POST", "/api/rest", data=json.dumps(payload))
        return resp.json() if resp.text.strip() else {"status": "submitted"}

    def get_health_v2(self) -> Dict[str, Any]:
        # Helpful probe for environments already migrated to API v2
        resp = self._request("GET", "/api/v2/health")
        return resp.json()

    def get_agents_v2(self) -> Any:
        resp = self._request("GET", "/api/v2/agents")
        return resp.json()

    def get_operations_v2(self) -> Any:
        resp = self._request("GET", "/api/v2/operations")
        return resp.json()

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


def alert_matches_target(alert: Dict[str, Any], target_ip: str = "192.168.30.24") -> bool:
    blob = json.dumps(alert, ensure_ascii=False)
    return target_ip in blob


def severity_of(alert: Dict[str, Any]) -> int:
    level = alert.get("rule", {}).get("level", 0)
    try:
        return int(level)
    except Exception:
        return 0


def print_live_alert(line: str, parsed: Dict[str, Any]) -> None:
    level = severity_of(parsed)
    prefix = "[WAZUH]"
    if level >= 10:
        print(f"{ANSI_RED}{prefix} {line}{ANSI_RESET}")
    elif level >= 5:
        print(f"{ANSI_YELLOW}{prefix} {line}{ANSI_RESET}")
    else:
        print(f"{ANSI_GREEN}{prefix} {line}{ANSI_RESET}")


def html_escape_json(obj: Any) -> str:
    return html.escape(json.dumps(obj, ensure_ascii=False, indent=2))


def generate_report(
    output_path: Path,
    config: LabConfig,
    operation_info: Dict[str, Any],
    observed_alerts: List[Dict[str, Any]],
    attack_ids: Set[str],
    d3f_map: Dict[str, List[str]],
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
    for item in observed_alerts[:100]:
        rule = item.get("rule", {})
        title = rule.get("description", "Wazuh alert")
        level = rule.get("level", "n/a")
        agent_name = item.get("agent", {}).get("name", "unknown")
        ts = item.get("timestamp", item.get("@timestamp", "n/a"))
        alert_cards.append(
            f"""
            <div class="card">
              <h3>Level {html.escape(str(level))} — {html.escape(str(title))}</h3>
              <p><strong>Timestamp:</strong> {html.escape(str(ts))}<br>
              <strong>Agent:</strong> {html.escape(str(agent_name))}</p>
              <pre>{html_escape_json(item)}</pre>
            </div>
            """
        )

    op_json = html_escape_json(operation_info)

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cyber Lab Report</title>
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
<h1>Cyber Lab Orchestrator Report</h1>
<p><strong>Generated:</strong> {html.escape(now_utc())}</p>

<h2>Lab Summary</h2>
<ul>
  <li><strong>Caldera:</strong> {html.escape(config.caldera_url)}</li>
  <li><strong>Wazuh:</strong> {html.escape(config.wazuh_host)}</li>
  <li><strong>T-Pot:</strong> {html.escape(config.tpot_ip or "configurable / not set")}</li>
  <li><strong>Observation window:</strong> {html.escape(str(config.monitor_seconds))} seconds</li>
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
  <li>Convert the highest-confidence detections into Wazuh custom rules and active responses.</li>
  <li>Route T-Pot telemetry into Wazuh to correlate attacker touchpoints with endpoint evidence.</li>
  <li>Build separate red, detect, and defend scorecards for each technique.</li>
</ol>

<small>This report is generated for authorized lab validation only.</small>
</body>
</html>
"""
    output_path.write_text(doc, encoding="utf-8")


def run(config_path: str) -> int:
    cfg = LabConfig.from_file(config_path)
    out_dir = Path(cfg.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Loaded configuration from {config_path}")
    print(f"[+] Output directory: {out_dir.resolve()}")

    caldera = CalderaClient(cfg)
    mapper = D3fendMapper(cfg.d3fend_mappings_url)

    line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop_event = threading.Event()
    monitor = WazuhTailMonitor(cfg, line_queue, stop_event)
    monitor.start()

    adversary_id = caldera.choose_adversary()
    if not adversary_id:
        print("[-] Could not determine an adversary_id from Caldera. Populate caldera.adversary_ids in config.yml.", file=sys.stderr)
        stop_event.set()
        return 2

    op_name = f"{cfg.operation_name_prefix}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    print(f"[+] Selected adversary_id: {adversary_id}")
    print(f"[+] Starting operation: {op_name}")

    operation_info: Dict[str, Any] = {}
    try:
        if cfg.caldera_use_legacy_api:
            operation_info = caldera.create_operation_legacy(op_name, adversary_id=adversary_id)
        else:
            operation_info = {
                "note": "API v2 selected. Adapt this block to your live /api/v2/operations schema.",
                "health": caldera.get_health_v2(),
            }
    except Exception as exc:
        print(f"[-] Failed to start Caldera operation: {exc}", file=sys.stderr)
        stop_event.set()
        return 3

    observed_alerts: List[Dict[str, Any]] = []
    observed_attack_ids: Set[str] = set()

    print(f"[+] Monitoring Wazuh for {cfg.monitor_seconds} seconds...")
    deadline = time.time() + cfg.monitor_seconds

    while time.time() < deadline:
        try:
            line, parsed = line_queue.get(timeout=1)
        except queue.Empty:
            continue

        if parsed.get("monitor_error"):
            print(f"[-] Monitor error: {parsed['monitor_error']}", file=sys.stderr)
            continue

        print_live_alert(line, parsed)

        if alert_matches_target(parsed):
            observed_alerts.append(parsed)
            observed_attack_ids.update(extract_attack_ids(parsed))

    stop_event.set()
    monitor.join(timeout=3)

    print(f"[+] Observed {len(observed_alerts)} matching Wazuh alerts")
    print(f"[+] Extracted ATT&CK IDs: {sorted(observed_attack_ids) if observed_attack_ids else 'none'}")

    try:
        d3f_map = mapper.map_attack_ids(observed_attack_ids)
    except Exception as exc:
        print(f"[!] D3FEND mapping failed: {exc}", file=sys.stderr)
        d3f_map = {aid: [] for aid in observed_attack_ids}

    report_path = out_dir / "report.html"
    generate_report(report_path, cfg, operation_info, observed_alerts, observed_attack_ids, d3f_map)

    json_path = out_dir / "captured_alerts.json"
    json_path.write_text(json.dumps(observed_alerts, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] Report written to: {report_path.resolve()}")
    print(f"[+] Raw alerts written to: {json_path.resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized cyber lab orchestrator")
    parser.add_argument("-c", "--config", default="config.yml", help="Path to YAML config file")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    raise SystemExit(run(args.config))
