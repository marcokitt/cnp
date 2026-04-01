#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import json
import os
import re
import signal
import socket
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

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
    description: str
    full_log: str
    suspicious: bool = False
    suspicious_reason: str = ""
    mitre_tactic: str = "-"
    mitre_match: str = "-"
    sysmon_event_id: str = "-"
    sysmon_event_name: str = "-"
    caldera_tag: str = "-"


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def safe_get(dct: Dict[str, Any], path: List[str], default: str = "") -> str:
    cur: Any = dct
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    if cur is None:
        return default
    if isinstance(cur, list):
        return ", ".join(str(x) for x in cur)
    return str(cur)


def normalize_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def normalize_event(obj: Dict[str, Any], show_preview: bool, preview_len: int) -> EventRow:
    timestamp = safe_get(obj, ["timestamp"], "-")
    agent = safe_get(obj, ["agent", "name"], "-")
    agent_id = safe_get(obj, ["agent", "id"], "-")
    rule_id = safe_get(obj, ["rule", "id"], "-")
    level = safe_get(obj, ["rule", "level"], "-")
    groups = safe_get(obj, ["rule", "groups"], "-")
    decoder = safe_get(obj, ["decoder", "name"], "-")
    location = safe_get(obj, ["location"], "-")
    description = normalize_spaces(safe_get(obj, ["rule", "description"], ""))
    full_log = normalize_spaces(safe_get(obj, ["full_log"], ""))

    if not description:
        description = full_log[:preview_len] if full_log else "-"

    if show_preview and full_log:
        preview = full_log[:preview_len]
        description = f"{description} | {preview}"

    return EventRow(
        timestamp=timestamp,
        agent=agent,
        agent_id=agent_id,
        rule_id=rule_id,
        level=level,
        groups=groups,
        decoder=decoder,
        location=location,
        description=description,
        full_log=full_log,
    )


def haystack_for_row(row: EventRow) -> str:
    return " ".join([
        row.timestamp,
        row.agent,
        row.agent_id,
        row.rule_id,
        row.level,
        row.groups,
        row.decoder,
        row.location,
        row.description,
        row.full_log,
    ]).lower()


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
    only_rule_ids = {str(x).strip() for x in filters_cfg.get("only_rule_ids", []) or [] if str(x).strip()}
    exclude_rule_ids = {str(x).strip() for x in filters_cfg.get("exclude_rule_ids", []) or [] if str(x).strip()}

    try:
        if int(row.level) < min_level:
            return False
    except Exception:
        return False

    if not match_groups(row.groups, only_groups, exclude_groups):
        return False
    if only_rule_ids and row.rule_id not in only_rule_ids:
        return False
    if exclude_rule_ids and row.rule_id in exclude_rule_ids:
        return False
    if contains and contains not in haystack_for_row(row):
        return False
    return True


def infer_mitre(row: EventRow, mitre_cfg: Dict[str, Any]) -> Tuple[str, str]:
    if not bool(mitre_cfg.get("enabled", True)):
        return "-", "-"

    haystack = haystack_for_row(row)
    tactics_map = mitre_cfg.get("tactics_map", {}) or {}

    for tactic, patterns in tactics_map.items():
        for pattern in patterns:
            token = str(pattern).lower().strip()
            if token and token in haystack:
                return tactic, token
    return "-", "-"


def infer_sysmon(row: EventRow, sysmon_cfg: Dict[str, Any]) -> Tuple[str, str]:
    if not bool(sysmon_cfg.get("enabled", True)):
        return "-", "-"

    event_map = {str(k): str(v) for k, v in (sysmon_cfg.get("event_map", {}) or {}).items()}
    haystack = haystack_for_row(row)

    if "sysmon" not in haystack and "microsoft-windows-sysmon" not in haystack:
        return "-", "-"

    patterns = [
        r'eventid["\']?\s*[:=]\s*["\']?(\d+)',
        r'event id\s*[:=]\s*(\d+)',
        r'eventid>\s*(\d+)\s*<',
    ]

    for pattern in patterns:
        m = re.search(pattern, haystack, re.IGNORECASE)
        if m:
            eid = m.group(1)
            return eid, event_map.get(eid, "Sysmon Event")

    return "-", "Sysmon"


def infer_caldera(row: EventRow, caldera_cfg: Dict[str, Any]) -> str:
    if not bool(caldera_cfg.get("enabled", True)):
        return "-"
    haystack = haystack_for_row(row)
    for keyword in caldera_cfg.get("keywords", []) or []:
        token = str(keyword).lower().strip()
        if token and token in haystack:
            return token
    return "-"


def enrich_row(row: EventRow, cfg: Dict[str, Any]) -> EventRow:
    tactic, tactic_match = infer_mitre(row, cfg.get("mitre", {}))
    row.mitre_tactic = tactic
    row.mitre_match = tactic_match

    sysmon_id, sysmon_name = infer_sysmon(row, cfg.get("sysmon", {}))
    row.sysmon_event_id = sysmon_id
    row.sysmon_event_name = sysmon_name

    row.caldera_tag = infer_caldera(row, cfg.get("caldera", {}))
    return row


def mark_suspicious(row: EventRow, detection_cfg: Dict[str, Any]) -> EventRow:
    keywords = [str(x).lower() for x in detection_cfg.get("suspicious_keywords", [])]
    rule_ids = {str(x).strip() for x in detection_cfg.get("suspicious_rule_ids", []) if str(x).strip()}
    groups = {str(x).strip().lower() for x in detection_cfg.get("suspicious_groups", []) if str(x).strip()}
    suspicious_min_level = int(detection_cfg.get("suspicious_min_level", 5) or 5)

    haystack = haystack_for_row(row)
    reasons = []

    for kw in keywords:
        if kw and kw in haystack:
            reasons.append(f"keyword:{kw}")

    if row.rule_id in rule_ids:
        reasons.append(f"rule:{row.rule_id}")

    row_groups = {g.strip().lower() for g in row.groups.split(",") if g.strip()}
    matched_groups = row_groups.intersection(groups)
    for g in matched_groups:
        reasons.append(f"group:{g}")

    try:
        if int(row.level) >= suspicious_min_level:
            reasons.append(f"level>={suspicious_min_level}")
    except Exception:
        pass

    if row.mitre_tactic != "-":
        reasons.append(f"mitre:{row.mitre_tactic}")
    if row.sysmon_event_id != "-":
        reasons.append(f"sysmon:{row.sysmon_event_id}")
    if row.caldera_tag != "-":
        reasons.append(f"caldera:{row.caldera_tag}")

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


def cell_with_alert(value: str, alert: bool, base_style: str = "") -> Text:
    text = Text(value or "-")
    if base_style:
        text.stylize(base_style)
    if alert:
        text.stylize("bold red")
    return text


def build_main_table(rows: List[EventRow], compact_mode: bool = False) -> Table:
    table = Table(
        title="Wazuh SSH Live Monitor v3",
        box=box.SIMPLE_HEAVY,
        expand=True,
        show_lines=False,
    )

    table.add_column("Time", style="cyan", no_wrap=True, width=26)
    table.add_column("Agent", style="bold white", no_wrap=True, width=14)
    table.add_column("Rule", style="magenta", no_wrap=True, width=8)
    table.add_column("Lvl", no_wrap=True, width=5)
    table.add_column("MITRE", style="bright_blue", width=16, overflow="fold")
    table.add_column("Sysmon", style="bright_cyan", width=16, overflow="fold")
    table.add_column("Caldera", style="bright_magenta", width=10, overflow="fold")
    if not compact_mode:
        table.add_column("Groups", style="yellow", width=14, overflow="fold")
        table.add_column("Location", style="green", width=18, overflow="fold")
    table.add_column("Description", style="white", overflow="fold")

    for row in rows:
        mitre_val = row.mitre_tactic if row.mitre_tactic != "-" else "-"
        if row.mitre_match != "-" and row.mitre_tactic != "-":
            mitre_val = f"{row.mitre_tactic}\n[{row.mitre_match}]"

        sysmon_val = "-"
        if row.sysmon_event_id != "-":
            sysmon_val = f"{row.sysmon_event_id}\n{row.sysmon_event_name}"
        elif row.sysmon_event_name != "-":
            sysmon_val = row.sysmon_event_name

        values = [
            row.timestamp,
            row.agent,
            row.rule_id,
            Text(row.level, style=level_style(row.level)),
            cell_with_alert(mitre_val, row.mitre_tactic != "-"),
            cell_with_alert(sysmon_val, row.sysmon_event_id != "-"),
            cell_with_alert(row.caldera_tag, row.caldera_tag != "-"),
        ]

        if not compact_mode:
            values.extend([
                row.groups or "-",
                row.location or "-",
            ])

        values.append(cell_with_alert(row.description or "-", row.suspicious))
        table.add_row(*values)

    return table


def build_suspicious_table(rows: List[EventRow]) -> Table:
    table = Table(
        title="Eventi sospetti",
        box=box.SIMPLE,
        expand=True,
        show_lines=False,
    )

    table.add_column("Time", style="cyan", no_wrap=True, width=26)
    table.add_column("Agent", style="bold white", no_wrap=True, width=14)
    table.add_column("Lvl", no_wrap=True, width=5)
    table.add_column("MITRE", style="bright_blue", width=14, overflow="fold")
    table.add_column("Sysmon", style="bright_cyan", width=14, overflow="fold")
    table.add_column("Reason", style="red", width=30, overflow="fold")
    table.add_column("Description", style="white", overflow="fold")

    for row in rows:
        mitre_val = row.mitre_tactic if row.mitre_tactic != "-" else "-"
        sysmon_val = row.sysmon_event_id if row.sysmon_event_id != "-" else "-"
        table.add_row(
            row.timestamp,
            row.agent,
            Text(row.level, style=level_style(row.level)),
            mitre_val,
            sysmon_val,
            row.suspicious_reason or "-",
            row.description or "-",
        )
    return table


def build_layout(rows_main: List[EventRow], rows_suspicious: List[EventRow], stats: Dict[str, int], source_path: str, ssh_host: str, compact_mode: bool = False) -> Group:
    main_table = build_main_table(rows_main, compact_mode=compact_mode)
    suspicious_table = build_suspicious_table(rows_suspicious)

    footer = Panel(
        (
            f"[bold]SSH:[/bold] {ssh_host}    "
            f"[bold]Source:[/bold] {source_path}    "
            f"[bold]Ricevuti:[/bold] {stats['received']}    "
            f"[bold]Visualizzati:[/bold] {stats['shown']}    "
            f"[bold]Filtrati:[/bold] {stats['filtered']}    "
            f"[bold]Sospetti:[/bold] {stats['suspicious']}    "
            f"[bold]MITRE:[/bold] {stats['mitre_hits']}    "
            f"[bold]Sysmon:[/bold] {stats['sysmon_hits']}    "
            f"[bold]Caldera:[/bold] {stats['caldera_hits']}    "
            f"[bold]JSON errati:[/bold] {stats['json_errors']}    "
            f"[bold]Reconnect:[/bold] {stats['reconnects']}"
        ),
        title="Stato",
        border_style="blue",
    )

    return Group(main_table, suspicious_table, footer)


class Exporter:
    def __init__(self, cfg: Dict[str, Any]):
        export_cfg = cfg.get("export", {})
        self.enable_csv = bool(export_cfg.get("enable_csv", False))
        self.csv_path = str(export_cfg.get("csv_path", "wazuh_live_export.csv"))
        self.enable_jsonl = bool(export_cfg.get("enable_jsonl", False))
        self.jsonl_path = str(export_cfg.get("jsonl_path", "wazuh_live_export.jsonl"))
        self.flush_every = int(export_cfg.get("flush_every", 1) or 1)
        self.counter = 0
        self.csv_file = None
        self.csv_writer = None
        self.jsonl_file = None

    def open(self):
        fieldnames = [
            "timestamp", "agent", "agent_id", "rule_id", "level", "groups", "decoder", "location",
            "description", "full_log", "suspicious", "suspicious_reason", "mitre_tactic", "mitre_match",
            "sysmon_event_id", "sysmon_event_name", "caldera_tag"
        ]
        if self.enable_csv:
            file_exists = os.path.exists(self.csv_path)
            self.csv_file = open(self.csv_path, "a", newline="", encoding="utf-8")
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=fieldnames)
            if not file_exists or os.path.getsize(self.csv_path) == 0:
                self.csv_writer.writeheader()
                self.csv_file.flush()
        if self.enable_jsonl:
            self.jsonl_file = open(self.jsonl_path, "a", encoding="utf-8")

    def write(self, row: EventRow):
        payload = asdict(row)
        if self.enable_csv and self.csv_writer:
            self.csv_writer.writerow(payload)
        if self.enable_jsonl and self.jsonl_file:
            self.jsonl_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.counter += 1
        if self.counter >= self.flush_every:
            if self.csv_file:
                self.csv_file.flush()
            if self.jsonl_file:
                self.jsonl_file.flush()
            self.counter = 0

    def close(self):
        for handle in [self.csv_file, self.jsonl_file]:
            try:
                if handle:
                    handle.flush()
                    handle.close()
            except Exception:
                pass


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

        if allow_unknown_host:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

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
            pkey = None
            key_loaders = [
                paramiko.RSAKey.from_private_key_file,
                paramiko.Ed25519Key.from_private_key_file,
                paramiko.ECDSAKey.from_private_key_file,
            ]
            last_error = None
            for loader in key_loaders:
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
        keepalive = int(self.cfg["runtime"].get("keepalive_sec", 30))
        transport.set_keepalive(keepalive)

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
            path = self.cfg["wazuh"]["custom_path"]
            if not path:
                raise RuntimeError("source=custom ma custom_path è vuoto.")
        else:
            raise RuntimeError(f"Sorgente Wazuh non valida: {source}")

        from_end = bool(self.cfg["runtime"].get("remote_tail_from_end", True))
        tail_opt = "-n 0 -F" if from_end else "-n +1 -F"
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
                data = self.channel.recv(65535).decode("utf-8", errors="replace")
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    yield line.rstrip("\r")
            else:
                if self.channel.exit_status_ready():
                    raise RuntimeError("Canale remoto terminato.")
                time.sleep(0.1)

    def close(self):
        try:
            if self.channel:
                self.channel.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.channel = None
        self.client = None
        self.transport = None


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(config_path)

    rows_main: List[EventRow] = []
    rows_suspicious: List[EventRow] = []

    stats = {
        "received": 0,
        "shown": 0,
        "filtered": 0,
        "suspicious": 0,
        "mitre_hits": 0,
        "sysmon_hits": 0,
        "caldera_hits": 0,
        "json_errors": 0,
        "reconnects": 0,
    }

    max_rows_main = int(cfg["ui"].get("max_rows_main", 35))
    max_rows_suspicious = int(cfg["ui"].get("max_rows_suspicious", 15))
    refresh = int(cfg["ui"].get("refresh_per_second", 4))
    show_preview = bool(cfg["ui"].get("show_full_log_preview", False))
    preview_len = int(cfg["ui"].get("full_log_preview_len", 160))
    compact_mode = bool(cfg["ui"].get("compact_mode", False))
    reconnect_delay = int(cfg["runtime"].get("reconnect_delay_sec", 3))

    ssh_host = cfg["ssh"]["host"]
    source_path = "-"

    exporter = Exporter(cfg)
    exporter.open()

    with Live(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode), refresh_per_second=refresh, console=console, screen=True) as live:
        while RUNNING:
            streamer = SSHLogStreamer(cfg)
            try:
                streamer.connect()
                source_path = streamer.open_stream()
                live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode))

                for line in streamer.iter_lines():
                    if not RUNNING:
                        break
                    if not line.strip():
                        continue

                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        stats["json_errors"] += 1
                        live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode))
                        continue

                    stats["received"] += 1
                    row = normalize_event(obj, show_preview, preview_len)
                    row = enrich_row(row, cfg)
                    row = mark_suspicious(row, cfg.get("detection", {}))

                    if not matches_filters(row, cfg["filters"]):
                        stats["filtered"] += 1
                        live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode))
                        continue

                    if row.mitre_tactic != "-":
                        stats["mitre_hits"] += 1
                    if row.sysmon_event_id != "-" or row.sysmon_event_name == "Sysmon":
                        stats["sysmon_hits"] += 1
                    if row.caldera_tag != "-":
                        stats["caldera_hits"] += 1

                    rows_main.append(row)
                    if len(rows_main) > max_rows_main:
                        rows_main = rows_main[-max_rows_main:]

                    if row.suspicious:
                        stats["suspicious"] += 1
                        rows_suspicious.append(row)
                        if len(rows_suspicious) > max_rows_suspicious:
                            rows_suspicious = rows_suspicious[-max_rows_suspicious:]

                    exporter.write(row)
                    stats["shown"] += 1
                    live.update(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode))

            except (paramiko.SSHException, socket.error, EOFError, RuntimeError) as e:
                stats["reconnects"] += 1
                error_panel = Panel(
                    f"[red]Connessione persa o stream terminato:[/red] {e}\nNuovo tentativo tra {reconnect_delay} secondi...",
                    title="Reconnect",
                    border_style="red",
                )
                live.update(Group(build_layout(rows_main, rows_suspicious, stats, source_path, ssh_host, compact_mode), error_panel))
                time.sleep(reconnect_delay)
            finally:
                streamer.close()

    exporter.close()
    console.print("[bold green]Monitor terminato.[/bold green]")


if __name__ == "__main__":
    main()
