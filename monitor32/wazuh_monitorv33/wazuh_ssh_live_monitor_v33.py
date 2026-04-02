#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import html
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import paramiko
import yaml
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
RUNNING = True


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)

SRC_IP_PATHS = [
    ["srcip"],
    ["data", "srcip"],
    ["data", "src_ip"],
    ["data", "source_ip"],
    ["data", "SourceIp"],
    ["source", "ip"],
    ["network", "src_ip"],
    ["network", "client", "ip"],
    ["win", "eventdata", "sourceIp"],
    ["win", "eventdata", "SourceIp"],
]

FULL_LOG_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FULL_LOG_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class EventRow:
    timestamp: str
    agent: str
    agent_id: str
    rule_id: str
    level: str
    groups: str
    decoder: str
    location: str
    src_ip: str
    mitre_ids: str
    mitre_tactics: str
    mitre_techniques: str
    description: str
    full_log: str
    suspicious: bool = False
    suspicious_reason: str = ""


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def safe_get(dct: Dict[str, Any], path: List[str], default: str = "") -> Any:
    cur: Any = dct
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return default if cur is None else cur


def as_list_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(x) for x in value if str(x).strip())
    return str(value)


def normalize_mitre(obj: Dict[str, Any]) -> tuple[str, str, str]:
    mitre = safe_get(obj, ["rule", "mitre"], {})
    if isinstance(mitre, dict):
        ids = as_list_string(mitre.get("id", ""))
        tactics = as_list_string(mitre.get("tactic", ""))
        techniques = as_list_string(mitre.get("technique", "")) or as_list_string(mitre.get("technique_name", ""))
        if ids or tactics or techniques:
            return ids, tactics, techniques
    text = json.dumps(obj, ensure_ascii=False)
    ids = ", ".join(sorted(set(m.upper() for m in FULL_LOG_MITRE_RE.findall(text))))
    return ids, "", ""


def valid_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except Exception:
        return False


def extract_src_ip(obj: Dict[str, Any], full_log: str) -> str:
    for path in SRC_IP_PATHS:
        value = safe_get(obj, path, "")
        if isinstance(value, list):
            for item in value:
                ip = str(item).strip()
                if valid_ipv4(ip):
                    return ip
        else:
            ip = str(value).strip()
            if valid_ipv4(ip):
                return ip
    for ip in FULL_LOG_IP_RE.findall(full_log or ""):
        if valid_ipv4(ip) and not ip.startswith("127."):
            return ip
    return "-"


def normalize_event(obj: Dict[str, Any], show_preview: bool, preview_len: int) -> EventRow:
    timestamp = str(safe_get(obj, ["timestamp"], "-"))
    agent = str(safe_get(obj, ["agent", "name"], "-"))
    agent_id = str(safe_get(obj, ["agent", "id"], "-"))
    rule_id = str(safe_get(obj, ["rule", "id"], "-"))
    level = str(safe_get(obj, ["rule", "level"], "-"))
    groups = as_list_string(safe_get(obj, ["rule", "groups"], "-"))
    decoder = str(safe_get(obj, ["decoder", "name"], "-"))
    location = str(safe_get(obj, ["location"], "-"))
    description = str(safe_get(obj, ["rule", "description"], "")).strip()
    full_log = str(safe_get(obj, ["full_log"], "")).strip()
    mitre_ids, mitre_tactics, mitre_techniques = normalize_mitre(obj)
    src_ip = extract_src_ip(obj, full_log)
    if not description:
        description = full_log[:preview_len] if full_log else "-"
    if show_preview and full_log:
        description = f"{description} | {full_log[:preview_len]}"
    return EventRow(
        timestamp=timestamp,
        agent=agent,
        agent_id=agent_id,
        rule_id=rule_id,
        level=level,
        groups=groups,
        decoder=decoder,
        location=location,
        src_ip=src_ip,
        mitre_ids=mitre_ids or "-",
        mitre_tactics=mitre_tactics or "-",
        mitre_techniques=mitre_techniques or "-",
        description=description,
        full_log=full_log,
    )


def match_groups(row_groups: str, include_groups: List[str], exclude_groups: List[str]) -> bool:
    normalized = {g.strip().lower() for g in row_groups.split(",") if g.strip()}
    include_groups = [g.strip().lower() for g in include_groups if str(g).strip()]
    exclude_groups = [g.strip().lower() for g in exclude_groups if str(g).strip()]
    if include_groups and not any(g in normalized for g in include_groups):
        return False
    if exclude_groups and any(g in normalized for g in exclude_groups):
        return False
    return True


def matches_filters(row: EventRow, filters_cfg: Dict[str, Any]) -> bool:
    contains = str(filters_cfg.get("contains", "") or "").strip().lower()
    min_level = int(filters_cfg.get("min_level", 0) or 0)
    only_groups = filters_cfg.get("only_groups", []) or []
    exclude_groups = filters_cfg.get("exclude_groups", []) or []
    only_attacker_ip = bool(filters_cfg.get("only_with_source_ip", False))
    only_mitre = bool(filters_cfg.get("only_with_mitre", False))
    try:
        if int(row.level) < min_level:
            return False
    except Exception:
        return False
    if only_attacker_ip and row.src_ip == "-":
        return False
    if only_mitre and row.mitre_ids == "-":
        return False
    if not match_groups(row.groups, only_groups, exclude_groups):
        return False
    if contains:
        haystack = " ".join([row.timestamp, row.agent, row.agent_id, row.rule_id, row.level, row.groups, row.decoder, row.location, row.src_ip, row.mitre_ids, row.mitre_tactics, row.mitre_techniques, row.description, row.full_log]).lower()
        if contains not in haystack:
            return False
    return True


def mark_suspicious(row: EventRow, detection_cfg: Dict[str, Any]) -> EventRow:
    keywords = [str(x).lower() for x in detection_cfg.get("suspicious_keywords", [])]
    rule_ids = {str(x).strip() for x in detection_cfg.get("suspicious_rule_ids", []) if str(x).strip()}
    groups = {str(x).strip().lower() for x in detection_cfg.get("suspicious_groups", []) if str(x).strip()}
    suspicious_min_level = int(detection_cfg.get("suspicious_min_level", 5) or 5)
    haystack = " ".join([row.timestamp, row.agent, row.agent_id, row.rule_id, row.level, row.groups, row.decoder, row.location, row.src_ip, row.mitre_ids, row.mitre_tactics, row.mitre_techniques, row.description, row.full_log]).lower()
    reasons = []
    for kw in keywords:
        if kw and kw in haystack:
            reasons.append(f"keyword:{kw}")
    if row.rule_id in rule_ids:
        reasons.append(f"rule:{row.rule_id}")
    row_groups = {g.strip().lower() for g in row.groups.split(",") if g.strip()}
    for g in row_groups.intersection(groups):
        reasons.append(f"group:{g}")
    try:
        if int(row.level) >= suspicious_min_level:
            reasons.append(f"level>={suspicious_min_level}")
    except Exception:
        pass
    if row.mitre_ids != "-":
        reasons.append("mitre")
    if row.src_ip != "-":
        reasons.append("srcip")
    if reasons:
        row.suspicious = True
        row.suspicious_reason = ", ".join(sorted(set(reasons)))
    return row


def level_style(level: str) -> str:
    try:
        n = int(level)
        if n <= 4:
            return "green"
        if n <= 8:
            return "yellow"
        if n <= 12:
            return "bold red"
        return "white on red"
    except Exception:
        return "white"


def build_main_table(rows: List[EventRow]) -> Table:
    table = Table(title="Wazuh SSH Live Monitor v3.3", box=box.SIMPLE_HEAVY, expand=True, show_lines=False)
    table.add_column("Time", style="cyan", no_wrap=True, width=24)
    table.add_column("Agent", style="bold white", no_wrap=True, width=14)
    table.add_column("Rule", style="magenta", no_wrap=True, width=7)
    table.add_column("Lvl", no_wrap=True, width=4)
    table.add_column("Src IP", style="bright_cyan", no_wrap=True, width=15)
    table.add_column("MITRE", style="bright_magenta", width=14, overflow="fold")
    table.add_column("Tactic", style="yellow", width=14, overflow="fold")
    table.add_column("Description", style="white", overflow="fold")
    for row in rows:
        desc_text = Text(row.description or "-")
        if row.suspicious:
            desc_text.stylize("bold red")
        table.add_row(row.timestamp, row.agent, row.rule_id, Text(row.level, style=level_style(row.level)), row.src_ip, row.mitre_ids, row.mitre_tactics, desc_text)
    return table


def build_suspicious_table(rows: List[EventRow]) -> Table:
    table = Table(title="Eventi sospetti", box=box.SIMPLE, expand=True, show_lines=False)
    table.add_column("Time", style="cyan", no_wrap=True, width=24)
    table.add_column("Agent", style="bold white", no_wrap=True, width=14)
    table.add_column("Src IP", style="bright_cyan", no_wrap=True, width=15)
    table.add_column("MITRE", style="bright_magenta", width=14, overflow="fold")
    table.add_column("Technique", style="yellow", width=18, overflow="fold")
    table.add_column("Reason", style="red", width=24, overflow="fold")
    table.add_column("Description", style="white", overflow="fold")
    for row in rows:
        table.add_row(row.timestamp, row.agent, row.src_ip, row.mitre_ids, row.mitre_techniques, row.suspicious_reason or "-", row.description or "-")
    return table


def build_layout(rows_main: List[EventRow], rows_suspicious: List[EventRow], stats: Dict[str, int], source_path: str, ssh_host: str) -> Group:
    footer = Panel(
        (
            f"[bold]SSH:[/bold] {ssh_host}    "
            f"[bold]Source:[/bold] {source_path}    "
            f"[bold]Ricevuti:[/bold] {stats['received']}    "
            f"[bold]Visualizzati:[/bold] {stats['shown']}    "
            f"[bold]Filtrati:[/bold] {stats['filtered']}    "
            f"[bold]Sospetti:[/bold] {stats['suspicious']}    "
            f"[bold]Con IP:[/bold] {stats['with_ip']}    "
            f"[bold]Con MITRE:[/bold] {stats['with_mitre']}    "
            f"[bold]HTML:[/bold] {stats['html_written']}    "
            f"[bold]JSON errati:[/bold] {stats['json_errors']}    "
            f"[bold]Reconnect:[/bold] {stats['reconnects']}"
        ),
        title="Stato",
        border_style="blue",
    )
    return Group(build_main_table(rows_main), build_suspicious_table(rows_suspicious), footer)


class CSVExporter:
    def __init__(self, cfg: Dict[str, Any]):
        export_cfg = cfg.get("export", {})
        self.enabled = bool(export_cfg.get("enable_csv", False))
        self.csv_path = str(export_cfg.get("csv_path", "wazuh_live_export.csv"))
        self.flush_every = int(export_cfg.get("flush_every", 1) or 1)
        self.counter = 0
        self.file = None
        self.writer = None

    def open(self):
        if not self.enabled:
            return
        file_exists = os.path.exists(self.csv_path)
        self.file = open(self.csv_path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.file, fieldnames=["timestamp", "agent", "agent_id", "rule_id", "level", "groups", "decoder", "location", "src_ip", "mitre_ids", "mitre_tactics", "mitre_techniques", "description", "full_log", "suspicious", "suspicious_reason"])
        if not file_exists or os.path.getsize(self.csv_path) == 0:
            self.writer.writeheader()
            self.file.flush()

    def write(self, row: EventRow):
        if not self.enabled or not self.writer:
            return
        self.writer.writerow(asdict(row))
        self.counter += 1
        if self.counter >= self.flush_every:
            self.file.flush()
            self.counter = 0

    def close(self):
        if self.file:
            self.file.flush()
            self.file.close()


class JSONLExporter:
    def __init__(self, cfg: Dict[str, Any]):
        export_cfg = cfg.get("export", {})
        self.enabled = bool(export_cfg.get("enable_jsonl", False))
        self.path = str(export_cfg.get("jsonl_path", "wazuh_live_export.jsonl"))
        self.file = None

    def open(self):
        if self.enabled:
            self.file = open(self.path, "a", encoding="utf-8")

    def write(self, row: EventRow):
        if self.enabled and self.file:
            self.file.write(json.dumps(asdict(row), ensure_ascii=False) + "\n")
            self.file.flush()

    def close(self):
        if self.file:
            self.file.flush()
            self.file.close()


class HTMLExporter:
    START_MARKER = "<!--EVENT_ROWS_START-->"
    END_MARKER = "<!--EVENT_ROWS_END-->"

    def __init__(self, cfg: Dict[str, Any]):
        export_cfg = cfg.get("export", {})
        self.enabled = bool(export_cfg.get("enable_html", True))
        self.path = Path(str(export_cfg.get("html_path", "wazuh_live_report.html")))
        self.max_rows = int(export_cfg.get("html_max_rows", 500) or 500)
        self.title = str(export_cfg.get("html_title", "Wazuh Live Defensive Report"))
        self.refresh_seconds = int(export_cfg.get("html_refresh_seconds", 5) or 5)

    def open(self):
        if not self.enabled:
            return
        if self.path.parent and str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(self._template(), encoding="utf-8")
        else:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            if self.START_MARKER not in content or self.END_MARKER not in content:
                self.path.write_text(self._template(), encoding="utf-8")

    def _template(self) -> str:
        title = html.escape(self.title)
        now = html.escape(time.strftime("%Y-%m-%d %H:%M:%S"))
        return f"""<!doctype html>
<html lang=\"it\">
<head>
<meta charset=\"utf-8\">
<meta http-equiv=\"refresh\" content=\"{self.refresh_seconds}\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<style>
body {{ font-family: Arial, Helvetica, sans-serif; background:#0b1220; color:#e5e7eb; margin:0; padding:18px; }}
header {{ margin-bottom:16px; }}
h1 {{ margin:0 0 6px 0; font-size:24px; }}
.small {{ color:#94a3b8; font-size:12px; }}
.panel {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:14px; margin-bottom:16px; }}
table {{ width:100%; border-collapse:collapse; table-layout:fixed; }}
th, td {{ padding:8px 10px; border-bottom:1px solid #1f2937; vertical-align:top; word-wrap:break-word; }}
th {{ text-align:left; background:#0f172a; position:sticky; top:0; }}
tr:nth-child(even) {{ background:#0f172a; }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:bold; }}
.level-low {{ background:#14532d; color:#dcfce7; }}
.level-med {{ background:#78350f; color:#fef3c7; }}
.level-high {{ background:#7f1d1d; color:#fee2e2; }}
.level-crit {{ background:#7c2d12; color:#ffedd5; }}
.suspicious td {{ border-left:4px solid #ef4444; }}
.ip {{ color:#67e8f9; font-weight:bold; }}
.mitre {{ color:#f5d0fe; font-weight:bold; }}
.reason {{ color:#fca5a5; }}
.desc {{ white-space:pre-wrap; }}
</style>
</head>
<body>
<header>
<h1>{title}</h1>
<div class=\"small\">Aggiornamento automatico ogni {self.refresh_seconds} secondi. Report inizializzato: {now}</div>
</header>
<div class=\"panel\">
<table>
<thead>
<tr><th>Time</th><th>Agent</th><th>Rule</th><th>Lvl</th><th>Src IP</th><th>MITRE</th><th>Tactic</th><th>Technique</th><th>Reason</th><th>Description</th></tr>
</thead>
<tbody>
{self.START_MARKER}
{self.END_MARKER}
</tbody>
</table>
</div>
</body>
</html>
"""

    def _level_badge_class(self, level: str) -> str:
        try:
            n = int(level)
            if n <= 4:
                return "level-low"
            if n <= 8:
                return "level-med"
            if n <= 12:
                return "level-high"
            return "level-crit"
        except Exception:
            return "level-med"

    def _trim_rows(self, content: str) -> str:
        start = content.index(self.START_MARKER) + len(self.START_MARKER)
        end = content.index(self.END_MARKER)
        rows_html = content[start:end]
        rows = re.findall(r'<tr class="event-row.*?</tr>', rows_html, flags=re.DOTALL)
        if len(rows) <= self.max_rows:
            return content
        kept = "\n" + "\n".join(rows[-self.max_rows:]) + "\n"
        return content[:start] + kept + content[end:]

    def write(self, row: EventRow):
        if not self.enabled:
            return
        if not self.path.exists():
            self.open()
        content = self.path.read_text(encoding="utf-8", errors="replace")
        badge = self._level_badge_class(row.level)
        css_class = "event-row suspicious" if row.suspicious else "event-row"
        row_html = (
            f'<tr class="{css_class}"><td>{html.escape(row.timestamp)}</td>'
            f'<td>{html.escape(row.agent)}</td>'
            f'<td>{html.escape(row.rule_id)}</td>'
            f'<td><span class="badge {badge}">{html.escape(row.level)}</span></td>'
            f'<td class="ip">{html.escape(row.src_ip)}</td>'
            f'<td class="mitre">{html.escape(row.mitre_ids)}</td>'
            f'<td>{html.escape(row.mitre_tactics)}</td>'
            f'<td>{html.escape(row.mitre_techniques)}</td>'
            f'<td class="reason">{html.escape(row.suspicious_reason)}</td>'
            f'<td class="desc">{html.escape(row.description)}</td></tr>\n'
        )
        content = content.replace(self.END_MARKER, row_html + self.END_MARKER, 1)
        content = self._trim_rows(content)
        self.path.write_text(content, encoding="utf-8")


class SSHLogStreamer:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.client: Optional[paramiko.SSHClient] = None
        self.transport = None
        self.channel = None

    def connect(self):
        ssh_cfg = self.cfg["ssh"]
        client = paramiko.SSHClient()
        known_hosts = str(ssh_cfg.get("known_hosts", "") or "").strip()
        allow_unknown_host = bool(ssh_cfg.get("allow_unknown_host", False))
        if known_hosts and os.path.exists(known_hosts):
            client.load_host_keys(known_hosts)
        else:
            client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if allow_unknown_host else paramiko.RejectPolicy())
        connect_args = {
            "hostname": ssh_cfg["host"],
            "port": int(ssh_cfg.get("port", 22)),
            "username": ssh_cfg["username"],
            "timeout": int(ssh_cfg.get("timeout", 10)),
            "banner_timeout": int(ssh_cfg.get("timeout", 10)),
            "auth_timeout": int(ssh_cfg.get("timeout", 10)),
            "look_for_keys": False,
            "allow_agent": False,
        }
        password = str(ssh_cfg.get("password", "") or "").strip()
        key_file = str(ssh_cfg.get("key_file", "") or "").strip()
        key_passphrase = str(ssh_cfg.get("key_passphrase", "") or "").strip()
        if key_file:
            if os.path.isdir(key_file):
                raise RuntimeError(f"key_file punta a una cartella, non a una chiave privata: {key_file}")
            pkey = None
            last_error = None
            for loader in [paramiko.RSAKey.from_private_key_file, paramiko.Ed25519Key.from_private_key_file, paramiko.ECDSAKey.from_private_key_file]:
                try:
                    pkey = loader(key_file, password=key_passphrase or None)
                    break
                except Exception as e:
                    last_error = e
            if pkey is None:
                raise RuntimeError(f"Impossibile caricare la chiave SSH: {last_error}")
            connect_args["pkey"] = pkey
        elif password:
            connect_args["password"] = password
        else:
            raise RuntimeError("Config SSH non valida: serve password oppure key_file.")
        client.connect(**connect_args)
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("Transport SSH non disponibile.")
        transport.set_keepalive(int(self.cfg["runtime"].get("keepalive_sec", 30)))
        self.client = client
        self.transport = transport

    def open_stream(self):
        if not self.client:
            raise RuntimeError("SSH non connesso.")
        source = self.cfg["wazuh"].get("source", "alerts").strip().lower()
        if source == "alerts":
            path = self.cfg["wazuh"]["remote_alerts_path"]
        elif source == "archives":
            path = self.cfg["wazuh"]["remote_archives_path"]
        elif source == "custom":
            path = self.cfg["wazuh"].get("custom_path", "")
            if not path:
                raise RuntimeError("source=custom ma custom_path è vuoto.")
        else:
            raise RuntimeError(f"Sorgente Wazuh non valida: {source}")
        tail_opt = "-n 0 -F" if bool(self.cfg["runtime"].get("remote_tail_from_end", True)) else "-n +1 -F"
        cmd = f"stdbuf -oL tail {tail_opt} {path}"
        chan = self.client.get_transport().open_session()
        chan.exec_command(cmd)
        self.channel = chan
        return path

    def iter_lines(self):
        if not self.channel:
            raise RuntimeError("Canale SSH non aperto.")
        buffer = ""
        while RUNNING:
            if self.channel.recv_ready():
                buffer += self.channel.recv(65535).decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    yield line.rstrip("\r")
            else:
                if self.channel.exit_status_ready():
                    raise RuntimeError("Canale remoto terminato.")
                time.sleep(0.1)

    def close(self):
        if self.channel:
            self.channel.close()
        if self.client:
            self.client.close()
        self.channel = None
        self.client = None
        self.transport = None


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(config_path)
    rows_main: List[EventRow] = []
    rows_suspicious: List[EventRow] = []
    stats = {"received": 0, "shown": 0, "filtered": 0, "suspicious": 0, "with_ip": 0, "with_mitre": 0, "html_written": 0, "json_errors": 0, "reconnects": 0}
    max_rows_main = int(cfg["ui"].get("max_rows_main", 30))
    max_rows_suspicious = int(cfg["ui"].get("max_rows_suspicious", 12))
    refresh = int(cfg["ui"].get("refresh_per_second", 4))
    show_preview = bool(cfg["ui"].get("show_full_log_preview", False))
    preview_len = int(cfg["ui"].get("full_log_preview_len", 140))
    reconnect_delay = int(cfg["runtime"].get("reconnect_delay_sec", 3))
    ssh_host = cfg["ssh"]["host"]
    source_path = "-"
    csv_exporter = CSVExporter(cfg)
    jsonl_exporter = JSONLExporter(cfg)
    html_exporter = HTMLExporter(cfg)
    csv_exporter.open()
    jsonl_exporter.open()
    html_exporter.open()
    with Live(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host), refresh_per_second=refresh, console=console, screen=True) as live:
        while RUNNING:
            streamer = SSHLogStreamer(cfg)
            try:
                streamer.connect()
                source_path = streamer.open_stream()
                live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host))
                for line in streamer.iter_lines():
                    if not RUNNING:
                        break
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        stats["json_errors"] += 1
                        live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host))
                        continue
                    stats["received"] += 1
                    row = mark_suspicious(normalize_event(obj, show_preview, preview_len), cfg.get("detection", {}))
                    if row.src_ip != "-":
                        stats["with_ip"] += 1
                    if row.mitre_ids != "-":
                        stats["with_mitre"] += 1
                    if not matches_filters(row, cfg.get("filters", {})):
                        stats["filtered"] += 1
                        live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host))
                        continue
                    rows_main.append(row)
                    if len(rows_main) > max_rows_main:
                        rows_main = rows_main[-max_rows_main:]
                    if row.suspicious:
                        stats["suspicious"] += 1
                        rows_suspicious.append(row)
                        if len(rows_suspicious) > max_rows_suspicious:
                            rows_suspicious = rows_suspicious[-max_rows_suspicious:]
                    csv_exporter.write(row)
                    jsonl_exporter.write(row)
                    html_exporter.write(row)
                    stats["html_written"] += 1
                    stats["shown"] += 1
                    live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host))
            except (paramiko.SSHException, socket.error, EOFError, RuntimeError) as e:
                stats["reconnects"] += 1
                error_panel = Panel(f"[red]Connessione persa o stream terminato:[/red] {e}\nNuovo tentativo tra {reconnect_delay} secondi...", title="Reconnect", border_style="red")
                live.update(Group(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host), error_panel))
                time.sleep(reconnect_delay)
            finally:
                streamer.close()
    csv_exporter.close()
    jsonl_exporter.close()
    console.print("[bold green]Monitor terminato.[/bold green]")


if __name__ == "__main__":
    main()
