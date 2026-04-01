#!/usr/bin/env python3
"""
Cyber Lab Orchestrator v6

Focus:
- Windows "noisy" abilities more likely to generate useful Sysmon/Wazuh telemetry
- Agent-first selection
- Ranked adversaries by compatibility
- Optional auto-build of a temporary Windows-only adversary made only of noisy compatible abilities
- Robust handling of UUID/string operation IDs
- Single live console with:
  * progress bar
  * Caldera status
  * link execution stats
  * Wazuh real-time table
- Global and per-source-IP HTML reports

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
import subprocess
import sys
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


ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Names/commands that tend to produce more visible Sysmon/Wazuh telemetry on Windows
NOISY_WINDOWS_KEYWORDS = [
    "whoami", "wmic", "nltest", "gpresult", "get-process", "gwmi", "win32_", "get-wmiobject",
    "get-smbshare", "nslookup", "ipconfig", "tasklist", "net user", "net group",
    "get-nettcpconnection", "reg query", "schtasks", "systeminfo", "hostname"
]


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
    os.system("cls" if os.name == "nt" else "clear")


def truncate(text: Any, n: int) -> str:
    text = str(text).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= n else text[: max(0, n - 1)] + "…"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def deep_get(obj: Dict[str, Any], path: List[str]) -> Any:
    cur: Any = obj
    for item in path:
        if not isinstance(cur, dict) or item not in cur:
            return None
        cur = cur[item]
    return cur


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


def extract_attack_ids(alert: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()
    blob = json.dumps(alert, ensure_ascii=False)
    found.update({m.upper() for m in ATTACK_ID_RE.findall(blob)})
    mitre_block = alert.get("rule", {}).get("mitre", {})
    if isinstance(mitre_block, dict):
        value = mitre_block.get("id", [])
        if isinstance(value, list):
            found.update({str(x).upper() for x in value})
        elif isinstance(value, str):
            found.add(value.upper())
    return found


def severity_of(alert: Dict[str, Any]) -> int:
    try:
        return int(alert.get("rule", {}).get("level", 0))
    except Exception:
        return 0


def extract_timestamp(alert: Dict[str, Any]) -> str:
    return str(alert.get("timestamp") or alert.get("@timestamp") or now_utc())


def resolve_op_id(value: Any) -> Any:
    try:
        return int(value)
    except Exception:
        return value


@dataclass
class LabConfig:
    caldera_url: str
    caldera_api_key: str
    caldera_username: str
    caldera_password: str
    operation_name_prefix: str
    caldera_adversary_ids: List[str]
    target_agent_paw: Optional[str]

    wazuh_host: str
    wazuh_port: int
    wazuh_username: str
    wazuh_password: Optional[str]
    wazuh_key_path: Optional[str]
    wazuh_log_path: str

    target_ip: Optional[str]
    target_host_aliases: List[str]
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
    status_refresh_seconds: int
    auto_build_temp_adversary: bool
    max_temp_abilities: int
    noisy_only_mode: bool

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
            target_agent_paw=data["caldera"].get("target_agent_paw"),
            wazuh_host=data["wazuh"]["host"],
            wazuh_port=int(data["wazuh"].get("port", 22)),
            wazuh_username=data["wazuh"]["username"],
            wazuh_password=data["wazuh"].get("password"),
            wazuh_key_path=data["wazuh"].get("key_path"),
            wazuh_log_path=data["wazuh"].get("log_path", "/var/ossec/logs/alerts/alerts.json"),
            target_ip=target_ip,
            target_host_aliases=data.get("lab", {}).get("target_host_aliases", []) or [],
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
            status_refresh_seconds=int(data.get("runtime", {}).get("status_refresh_seconds", 2)),
            auto_build_temp_adversary=bool(data.get("runtime", {}).get("auto_build_temp_adversary", True)),
            max_temp_abilities=int(data.get("runtime", {}).get("max_temp_abilities", 8)),
            noisy_only_mode=bool(data.get("runtime", {}).get("noisy_only_mode", True)),
        )


class CalderaClient:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg
        self.base = cfg.caldera_url
        self.session = requests.Session()
        self.session.headers.update({"KEY": cfg.caldera_api_key, "Content-Type": "application/json"})

    def rest(self, method: str, payload: Dict[str, Any]) -> Any:
        url = f"{self.base}/api/rest"
        response = self.session.request(method=method, url=url, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        return response.json() if response.text.strip() else {"status": "ok"}

    def list_adversaries(self) -> List[Dict[str, Any]]:
        x = self.rest("POST", {"index": "adversaries"})
        return x if isinstance(x, list) else []

    def list_agents(self) -> List[Dict[str, Any]]:
        x = self.rest("POST", {"index": "agents"})
        return x if isinstance(x, list) else []

    def list_operations(self) -> List[Dict[str, Any]]:
        x = self.rest("POST", {"index": "operations"})
        return x if isinstance(x, list) else []

    def list_abilities(self) -> List[Dict[str, Any]]:
        x = self.rest("POST", {"index": "abilities"})
        return x if isinstance(x, list) else []

    def get_operation(self, op_id: Any) -> Optional[Dict[str, Any]]:
        for op in self.list_operations():
            if str(op.get("id")) == str(op_id):
                return op
        return None

    def set_operation_state(self, op_id: Any, state: str) -> Any:
        return self.rest("POST", {"index": "operation", "op_id": op_id, "state": state})

    def create_operation_legacy(self, name: str, adversary_id: str, group: str) -> Dict[str, Any]:
        payload = {
            "index": "operations",
            "name": name,
            "group": group,
            "adversary_id": adversary_id,
            "planner": "batch",
            "source": "basic",
            "jitter": "2/8",
            "obfuscator": "plain-text",
            "visibility": 51,
            "autonomous": 1,
            "phases_enabled": 1,
            "auto_close": 1,
        }
        x = self.rest("PUT", payload)
        return x if isinstance(x, dict) else {"raw": x}

    def save_adversary(self, adversary: Dict[str, Any]) -> Any:
        return self.rest("PUT", {"index": "adversaries", "adversary": adversary})

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
            print(f"{i:>2}. {agent.get('paw','unknown'):<20} | host: {truncate(agent.get('host','unknown'),18):<18} | group: {agent.get('group','unknown'):<12} | platform: {agent.get('platform','unknown'):<8} | exec: {truncate(','.join(agent.get('executors',[]) or []),18):<18} | trusted: {agent.get('trusted',False)}")
        while True:
            selected = input("\nSelect agent number (blank = 1): ").strip() or "1"
            if selected.isdigit() and 1 <= int(selected) <= len(agents):
                return agents[int(selected)-1]
            print("Invalid selection.")


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


def normalize_platform(value: str) -> str:
    value = (value or "").strip().lower()
    if value in {"windows", "win"}:
        return "windows"
    if value in {"linux"}:
        return "linux"
    if value in {"darwin", "mac", "macos", "osx"}:
        return "darwin"
    return value


def flatten_adversary_refs(adversary: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []

    def add_item(item: Any, source: str) -> None:
        if isinstance(item, str):
            refs.append({"ability_id": item, "embedded": None, "source": source})
        elif isinstance(item, dict):
            ability_id = item.get("ability_id") or item.get("id")
            refs.append({"ability_id": str(ability_id) if ability_id else "", "embedded": item, "source": source})

    ordering = adversary.get("atomic_ordering")
    if isinstance(ordering, list):
        for item in ordering:
            add_item(item, "atomic_ordering")

    phases = adversary.get("phases")
    if isinstance(phases, dict):
        for phase_key in sorted(phases.keys(), key=lambda x: int(str(x)) if str(x).isdigit() else str(x)):
            values = phases.get(phase_key, [])
            if isinstance(values, list):
                for item in values:
                    add_item(item, "phases")

    dedup: Dict[str, Dict[str, Any]] = {}
    for ref in refs:
        aid = ref["ability_id"]
        if not aid:
            continue
        if aid not in dedup:
            dedup[aid] = ref
        elif dedup[aid].get("embedded") is None and ref.get("embedded") is not None:
            dedup[aid] = ref
    return list(dedup.values())


def build_windows_platforms_from_embedded(ability: Dict[str, Any]) -> Dict[str, Any]:
    platforms: Dict[str, Dict[str, Any]] = {}
    executors = ability.get("executors") or []
    if not isinstance(executors, list):
        return platforms
    for ex in executors:
        if not isinstance(ex, dict):
            continue
        platform_name = normalize_platform(str(ex.get("platform", "")))
        executor_name = str(ex.get("name", "")).lower()
        if not platform_name or not executor_name:
            continue
        entry = {
            "command": ex.get("command"),
            "payloads": ex.get("payloads", []),
            "timeout": ex.get("timeout", 60),
            "cleanup": ex.get("cleanup", []),
            "parsers": ex.get("parsers", []),
        }
        if ex.get("uploads") is not None:
            entry["uploads"] = ex.get("uploads")
        platforms.setdefault(platform_name, {})[executor_name] = entry
    return platforms


def resolve_ability(ref: Dict[str, Any], ability_map: Dict[str, Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], str]:
    aid = ref.get("ability_id", "")
    embedded = ref.get("embedded")
    if aid in ability_map:
        return ability_map[aid], "live"
    if isinstance(embedded, dict):
        fixed = dict(embedded)
        fixed["ability_id"] = aid or fixed.get("ability_id") or fixed.get("id")
        if "platforms" not in fixed or not fixed.get("platforms"):
            converted = build_windows_platforms_from_embedded(fixed)
            if converted:
                fixed["platforms"] = converted
        return fixed, "embedded"
    return None, "missing"


def ability_is_compatible(ability: Dict[str, Any], agent: Dict[str, Any]) -> Tuple[bool, str]:
    agent_platform = normalize_platform(str(agent.get("platform", "")))
    agent_execs = {str(x).lower() for x in (agent.get("executors", []) or [])}

    ability_platforms = ability.get("platforms") or {}
    if isinstance(ability_platforms, dict) and ability_platforms:
        if agent_platform not in ability_platforms:
            return False, f"platform mismatch ({agent_platform})"
        executor_block = ability_platforms.get(agent_platform) or {}
        if not isinstance(executor_block, dict) or not executor_block:
            return False, "no executor block for platform"
        ability_execs = {str(x).lower() for x in executor_block.keys()}
        if not agent_execs.intersection(ability_execs):
            return False, f"executor mismatch ({','.join(sorted(agent_execs)) or 'none'})"
        return True, "compatible"

    executors = ability.get("executors")
    if isinstance(executors, list) and executors:
        matches = []
        for ex in executors:
            if not isinstance(ex, dict):
                continue
            ex_platform = normalize_platform(str(ex.get("platform", "")))
            ex_name = str(ex.get("name", "")).lower()
            if ex_platform == agent_platform:
                matches.append(ex_name)
        if not matches:
            return False, f"platform mismatch ({agent_platform})"
        if not agent_execs.intersection(set(matches)):
            return False, f"executor mismatch ({','.join(sorted(agent_execs)) or 'none'})"
        return True, "compatible"
    return False, "missing platforms/executors block"


def ability_name(ability: Dict[str, Any]) -> str:
    return str(ability.get("name") or ability.get("technique_name") or ability.get("ability_id") or ability.get("id") or "unknown")


def get_windows_executor_command(ability: Dict[str, Any]) -> str:
    platforms = ability.get("platforms") or {}
    if isinstance(platforms, dict):
        win = platforms.get("windows") or {}
        if isinstance(win, dict):
            for ex_name, ex_data in win.items():
                if isinstance(ex_data, dict):
                    return str(ex_data.get("command") or "")
    executors = ability.get("executors") or []
    if isinstance(executors, list):
        for ex in executors:
            if isinstance(ex, dict) and normalize_platform(str(ex.get("platform", ""))) == "windows":
                return str(ex.get("command") or "")
    return ""


def noisy_score(ability: Dict[str, Any]) -> int:
    score = 0
    cmd = get_windows_executor_command(ability).lower()
    name = ability_name(ability).lower()
    tactic = str(ability.get("tactic") or "").lower()
    technique = str(ability.get("technique_id") or "").upper()

    for kw in NOISY_WINDOWS_KEYWORDS:
        if kw in cmd or kw in name:
            score += 2
    if tactic in {"discovery", "collection", "credential-access", "defense-evasion"}:
        score += 1
    if technique in {"T1033", "T1057", "T1018", "T1518.001", "T1069.001", "T1135", "T1087.001", "T1016"}:
        score += 2
    if "clear-history" in cmd or "clear" == cmd.strip().lower():
        score -= 3
    return score


def compatibility_report(adversary: Dict[str, Any], agent: Dict[str, Any], abilities: List[Dict[str, Any]], noisy_only: bool = False) -> Dict[str, Any]:
    ability_map = {str(a.get("ability_id") or a.get("id")): a for a in abilities}
    refs = flatten_adversary_refs(adversary)

    compatible = []
    incompatible = []
    missing = []
    fixed_embedded_count = 0

    for ref in refs:
        ability, source_kind = resolve_ability(ref, ability_map)
        if ability is None:
            missing.append({"ability_id": ref["ability_id"], "reason": "ability not returned by Caldera and no embedded fallback"})
            continue

        if source_kind == "embedded":
            fixed_embedded_count += 1

        ok, reason = ability_is_compatible(ability, agent)
        item = {
            "ability_id": ref["ability_id"],
            "name": ability_name(ability),
            "tactic": ability.get("tactic"),
            "technique_id": ability.get("technique_id"),
            "resolution": source_kind,
            "reason": reason,
            "noisy_score": noisy_score(ability),
        }
        if ok:
            if noisy_only and item["noisy_score"] <= 0:
                item["reason"] = "compatible but filtered by noisy_only_mode"
                incompatible.append(item)
            else:
                compatible.append(item)
        else:
            incompatible.append(item)

    compatible.sort(key=lambda x: (-x["noisy_score"], str(x["name"])))
    return {
        "agent_paw": agent.get("paw"),
        "agent_host": agent.get("host"),
        "agent_platform": agent.get("platform"),
        "agent_executors": agent.get("executors", []),
        "adversary_id": adversary.get("adversary_id") or adversary.get("id"),
        "adversary_name": adversary.get("name"),
        "referenced_ability_count": len(refs),
        "compatible_count": len(compatible),
        "incompatible_count": len(incompatible),
        "missing_count": len(missing),
        "fixed_embedded_count": fixed_embedded_count,
        "compatible": compatible,
        "incompatible": incompatible,
        "missing": missing,
        "noisy_only_mode": noisy_only,
    }


def build_temp_adversary_from_compatible(agent: Dict[str, Any], source_adversary: Dict[str, Any], abilities: List[Dict[str, Any]], max_items: int, noisy_only: bool) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    ability_map = {str(a.get("ability_id") or a.get("id")): a for a in abilities}
    refs = flatten_adversary_refs(source_adversary)

    selected_refs: List[Dict[str, Any]] = []
    candidates: List[Tuple[int, Dict[str, Any]]] = []

    for ref in refs:
        ability, _ = resolve_ability(ref, ability_map)
        if ability is None:
            continue
        ok, _ = ability_is_compatible(ability, agent)
        if ok:
            score = noisy_score(ability)
            if noisy_only and score <= 0:
                continue
            candidates.append((score, ability))

    candidates.sort(key=lambda x: (-x[0], ability_name(x[1])))
    selected_ids: List[str] = []
    for score, ability in candidates[:max_items]:
        aid = str(ability.get("ability_id") or ability.get("id"))
        selected_ids.append(aid)
        selected_refs.append({
            "ability_id": aid,
            "name": ability_name(ability),
            "tactic": ability.get("tactic"),
            "technique_id": ability.get("technique_id"),
            "noisy_score": score,
            "command_preview": truncate(get_windows_executor_command(ability), 90),
        })

    temp_adv_id = f"temp-{sanitize_name(str(agent.get('paw')))}-{int(time.time())}"
    temp_adv = {
        "adversary_id": temp_adv_id,
        "name": f"Temp Windows Noisy - {source_adversary.get('name') or source_adversary.get('adversary_id')}",
        "description": f"Auto-generated from {source_adversary.get('adversary_id') or source_adversary.get('id')} for agent {agent.get('paw')}",
        "atomic_ordering": selected_ids,
    }
    return temp_adv, selected_refs


def rank_adversaries_for_agent(adversaries: List[Dict[str, Any]], agent: Dict[str, Any], abilities: List[Dict[str, Any]], noisy_only: bool) -> List[Dict[str, Any]]:
    ranked = []
    for adv in adversaries:
        compat = compatibility_report(adv, agent, abilities, noisy_only=noisy_only)
        ranked.append({"adversary": adv, "compatibility": compat})
    ranked.sort(
        key=lambda x: (
            -x["compatibility"]["compatible_count"],
            x["compatibility"]["missing_count"],
            str(x["adversary"].get("name") or x["adversary"].get("adversary_id") or "")
        )
    )
    return ranked


def choose_ranked_adversary(ranked: List[Dict[str, Any]], interactive: bool = False) -> Optional[Dict[str, Any]]:
    if not ranked:
        return None
    if not interactive:
        return ranked[0]

    print("\nRanked adversaries for selected agent:")
    for i, item in enumerate(ranked, start=1):
        adv = item["adversary"]
        compat = item["compatibility"]
        adv_id = adv.get("adversary_id") or adv.get("id") or "unknown"
        print(f"{i:>2}. {truncate(adv_id,24):<24} | {truncate(adv.get('name',adv_id),28):<28} | compatible: {compat['compatible_count']:<3} | missing: {compat['missing_count']:<3} | fixed_embedded: {compat['fixed_embedded_count']:<3}")
    while True:
        selected = input("\nSelect adversary number (blank = 1): ").strip() or "1"
        if selected.isdigit() and 1 <= int(selected) <= len(ranked):
            return ranked[int(selected)-1]
        print("Invalid selection.")


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
            "look_for_keys": False if not self.cfg.wazuh_key_path else True,
            "allow_agent": False,
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
            try:
                if self.client:
                    self.client.close()
            except Exception:
                pass

    @staticmethod
    def try_parse(line: str) -> Dict[str, Any]:
        try:
            return json.loads(line)
        except Exception:
            return {"raw": line}


class OperationPoller(threading.Thread):
    def __init__(self, client: CalderaClient, op_id: Any, refresh_seconds: int, data_holder: Dict[str, Any], stop_event: threading.Event):
        super().__init__(daemon=True)
        self.client = client
        self.op_id = op_id
        self.refresh_seconds = refresh_seconds
        self.data_holder = data_holder
        self.stop_event = stop_event

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                op = self.client.get_operation(self.op_id)
                if op:
                    self.data_holder["operation"] = op
                    self.data_holder["last_poll_utc"] = now_utc()
            except Exception as exc:
                self.data_holder["poll_error"] = str(exc)
            time.sleep(self.refresh_seconds)


def load_session_context(session_dir: Path) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    for name in ("operation_info.json", "compatibility_report.json", "selector_info.json", "operation_info_final.json"):
        p = session_dir / name
        if p.exists():
            try:
                context[name] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                context[name] = {}
    return context


def derive_target_markers(cfg: LabConfig, session_dir: Optional[Path] = None) -> Set[str]:
    markers: Set[str] = set()
    if cfg.target_ip:
        markers.add(cfg.target_ip)
    for alias in cfg.target_host_aliases:
        if alias:
            markers.add(str(alias))

    if session_dir is not None:
        ctx = load_session_context(session_dir)
        selector = ctx.get("selector_info.json", {}) or {}
        selected_agent = selector.get("selected_agent", {}) or {}
        operation_info = ctx.get("operation_info.json", {}) or {}

        for value in [
            selected_agent.get("host"),
            selected_agent.get("paw"),
            selected_agent.get("username"),
            selected_agent.get("display_name"),
            selected_agent.get("location"),
        ]:
            if value:
                markers.add(str(value))

        for ip in selected_agent.get("host_ip_addrs", []) or []:
            if ip:
                markers.add(str(ip))

        host_group = operation_info.get("host_group")
        if isinstance(host_group, list):
            for item in host_group:
                if isinstance(item, dict):
                    for value in [item.get("host"), item.get("paw"), item.get("username"), item.get("display_name")]:
                        if value:
                            markers.add(str(value))
                    for ip in item.get("host_ip_addrs", []) or []:
                        if ip:
                            markers.add(str(ip))
    return {m for m in markers if m}


def operation_group_label(op: Dict[str, Any]) -> str:
    group = op.get("group") or op.get("host_group") or "n/a"
    if isinstance(group, list):
        groups = []
        for item in group:
            if isinstance(item, dict) and item.get("group"):
                groups.append(str(item["group"]))
        return ",".join(sorted(set(groups))) if groups else "list"
    return str(group)


def link_stats(op: Dict[str, Any]) -> Dict[str, int]:
    stats = {"links_total": 0, "links_finished": 0, "links_error": 0}
    host_group = op.get("host_group")
    if isinstance(host_group, list):
        for item in host_group:
            if not isinstance(item, dict):
                continue
            for link in item.get("links", []) or []:
                stats["links_total"] += 1
                if link.get("finish"):
                    stats["links_finished"] += 1
                if str(link.get("status")) not in {"0", "None", "null"} and link.get("status") not in [0, None]:
                    stats["links_error"] += 1
    return stats


def extract_initial_operation_info(session_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ctx = load_session_context(session_dir)
    operation_info = ctx.get("operation_info.json", {}) or ctx.get("operation_info_final.json", {}) or {"mode": "monitor-only", "session_id": session_dir.name}
    compat = ctx.get("compatibility_report.json", {}) or {}
    return operation_info, compat


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


def alert_matches_target(alert: Dict[str, Any], cfg: LabConfig, target_markers: Optional[Set[str]] = None) -> bool:
    markers = set(target_markers or [])
    if cfg.target_ip:
        markers.add(cfg.target_ip)
    markers.update(cfg.target_host_aliases or [])
    if not markers:
        return True
    blob = json.dumps(alert, ensure_ascii=False)
    return any(marker and str(marker) in blob for marker in markers)


def build_session_id(operation_name: str) -> str:
    return f"{sanitize_name(operation_name)}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"


def progress_bar(done: int, total: int, width: int = 36) -> str:
    total = max(1, total)
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {int(ratio*100):>3}%"



def iso_to_epoch(value: Any) -> float:
    if not value:
        return 0.0
    try:
        s = str(value).replace("Z", "+00:00")
        return dt.datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def relevant_ability_ids(operation_info: Dict[str, Any], selector_info: Optional[Dict[str, Any]] = None) -> Set[str]:
    ids: Set[str] = set()
    adv = operation_info.get("adversary") or {}
    ordering = adv.get("atomic_ordering") or []
    if isinstance(ordering, list):
        for item in ordering:
            if isinstance(item, str):
                ids.add(item)
            elif isinstance(item, dict) and (item.get("ability_id") or item.get("id")):
                ids.add(str(item.get("ability_id") or item.get("id")))
    if selector_info:
        op_adv = selector_info.get("operation_adversary") or {}
        ordering = op_adv.get("atomic_ordering") or []
        if isinstance(ordering, list):
            for item in ordering:
                if isinstance(item, str):
                    ids.add(item)
                elif isinstance(item, dict) and (item.get("ability_id") or item.get("id")):
                    ids.add(str(item.get("ability_id") or item.get("id")))
    return ids


def decision_metrics(op: Dict[str, Any], selector_info: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    start_epoch = iso_to_epoch(op.get("start"))
    selected_paw = None
    if selector_info:
        selected_paw = ((selector_info.get("selected_agent") or {}).get("paw"))

    relevant_ids = relevant_ability_ids(op, selector_info)
    metrics = {
        "planned_total": len(relevant_ids),
        "created": 0,
        "finished": 0,
        "success": 0,
        "error": 0,
    }

    host_group = op.get("host_group")
    if not isinstance(host_group, list):
        return metrics

    seen_links: Set[str] = set()
    for agent in host_group:
        if not isinstance(agent, dict):
            continue
        paw = agent.get("paw")
        if selected_paw and paw != selected_paw:
            continue
        for link in agent.get("links", []) or []:
            if not isinstance(link, dict):
                continue
            lid = str(link.get("id") or link.get("unique") or "")
            if lid and lid in seen_links:
                continue
            if lid:
                seen_links.add(lid)

            decide_epoch = iso_to_epoch(link.get("decide"))
            if start_epoch and decide_epoch and decide_epoch < start_epoch:
                continue

            ability = link.get("ability") or {}
            ability_id = str(ability.get("ability_id") or "")
            if relevant_ids and ability_id and ability_id not in relevant_ids:
                continue

            metrics["created"] += 1
            if link.get("finish"):
                metrics["finished"] += 1
                status = link.get("status")
                if status in [0, "0", None]:
                    metrics["success"] += 1
                else:
                    metrics["error"] += 1
    return metrics


def decision_progress_bar(created: int, planned_total: int, width: int = 28) -> str:
    total = max(1, planned_total)
    ratio = max(0.0, min(1.0, created / total))
    filled = int(width * ratio)
    return "[" + "=" * filled + "." * (width - filled) + f"] {created}/{planned_total}"
def render_live_screen(session_name: str, remaining: int, total: int, observed_count: int, recent_rows: List[Dict[str, str]], op_status: Dict[str, Any], compat: Dict[str, Any], selector_info: Optional[Dict[str, Any]] = None) -> None:
    clear_screen()
    elapsed = max(0, total - remaining)
    print(f"Session: {session_name}")
    print(f"Timer : {progress_bar(elapsed, total)}  elapsed={elapsed}s remaining={remaining}s")
    print()

    op = op_status.get("operation") or {}
    state = op.get("state", "unknown")
    op_id = op.get("id", op_status.get("op_id", "n/a"))
    host_group = operation_group_label(op)
    chain = op.get("chain") or []
    facts = op.get("facts") or []
    stats = link_stats(op)
    dmetrics = decision_metrics(op, selector_info)
    print("CALDERA")
    print("-" * 120)
    print(f"op_id={op_id} | state={state} | group={host_group} | chain={len(chain) if isinstance(chain, list) else 'n/a'} | links={stats['links_total']} | finished={stats['links_finished']} | link_errors={stats['links_error']} | facts={len(facts) if isinstance(facts, list) else 'n/a'}")
    print(f"decisions: {decision_progress_bar(dmetrics['created'], dmetrics['planned_total'])} | completed={dmetrics['finished']} | success={dmetrics['success']} | error={dmetrics['error']}")
    if op_status.get("poll_error"):
        print(f"poll_error={truncate(op_status['poll_error'], 100)}")
    if op_status.get("monitor_error"):
        print(f"monitor_error={truncate(op_status['monitor_error'], 100)}")
    print()

    print("COMPATIBILITY")
    print("-" * 120)
    print(f"adversary={compat.get('adversary_id')} | agent={compat.get('agent_paw')} | platform={compat.get('agent_platform')} | compatible={compat.get('compatible_count', 0)} | incompatible={compat.get('incompatible_count', 0)} | missing={compat.get('missing_count', 0)} | noisy_only={compat.get('noisy_only_mode', False)}")
    if compat.get("compatible"):
        preview = ", ".join(f"{x['ability_id']}:{truncate(x.get('name',''), 18)}({x.get('noisy_score',0)})" for x in compat["compatible"][:4])
        print(f"sample compatible: {truncate(preview, 115)}")
    print()

    print(f"WAZUH LIVE TABLE  | captured alerts={observed_count}")
    print("-" * 146)
    header = f"{'TIME':<20} {'SRC IP':<16} {'AGENT':<16} {'LVL':<4} {'ATT&CK':<18} {'RULE / DESCRIPTION':<65}"
    print(header)
    print("-" * 146)
    for row in recent_rows:
        print(f"{row['time']:<20} {row['src']:<16} {row['agent']:<16} {row['lvl']:<4} {row['attack']:<18} {row['desc']:<65}")
    print("-" * 146)


def generate_report(output_path: Path, title: str, cfg: LabConfig, session_id: str, operation_info: Dict[str, Any], observed_alerts: List[Dict[str, Any]], attack_ids: Set[str], d3f_map: Dict[str, List[str]], compat: Dict[str, Any], source_ip: Optional[str] = None) -> None:
    rows = []
    for aid in sorted(attack_ids):
        url = f"{cfg.attack_lookup_base}{aid.replace('.', '/')}/"
        mapped = d3f_map.get(aid, [])
        rows.append(f"<tr><td><a href='{html.escape(url)}'>{html.escape(aid)}</a></td><td>{html.escape(', '.join(mapped) if mapped else 'No mapped D3FEND technique found')}</td></tr>")

    cards = []
    for alert in observed_alerts[:300]:
        cards.append(
            f"<div class='card'><h3>Level {html.escape(str(alert.get('rule', {}).get('level', 'n/a')))} — {html.escape(str(alert.get('rule', {}).get('description', 'Wazuh alert')))}</h3>"
            f"<p><strong>Timestamp:</strong> {html.escape(extract_timestamp(alert))}<br>"
            f"<strong>Agent:</strong> {html.escape(str(alert.get('agent', {}).get('name', 'unknown')))}<br>"
            f"<strong>Source IP:</strong> {html.escape(str(alert.get('_inferred_source_ip', 'unknown')))}</p>"
            f"<pre>{html.escape(json.dumps(alert, ensure_ascii=False, indent=2))}</pre></div>"
        )

    compat_html = html.escape(json.dumps(compat, ensure_ascii=False, indent=2))
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
<h2>Compatibility Check</h2><pre>{compat_html}</pre>
<h2>Observed ATT&CK Techniques</h2>
<table><tr><th>ATT&CK Technique</th><th>Mapped D3FEND techniques</th></tr>
{''.join(rows) if rows else '<tr><td colspan="2">No ATT&CK techniques extracted from observed alerts.</td></tr>'}
</table>
<h2>Observed Wazuh Alerts</h2>
{''.join(cards) if cards else '<p>No matching alerts captured during the observation window.</p>'}
</body></html>"""
    output_path.write_text(doc, encoding="utf-8")


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


def build_reports(cfg: LabConfig, mapper: D3fendMapper, session_dir: Path, session_id: str, operation_info: Dict[str, Any], observed_alerts: List[Dict[str, Any]], grouped: Dict[str, List[Dict[str, Any]]], compat: Dict[str, Any]) -> None:
    all_attack_ids = {aid for alert in observed_alerts for aid in extract_attack_ids(alert)}
    global_map = mapper.map_attack_ids(all_attack_ids) if all_attack_ids else {}
    generate_report(session_dir / "report.html", "Cyber Lab Orchestrator Report", cfg, session_id, operation_info, observed_alerts, all_attack_ids, global_map, compat)

    by_source_dir = session_dir / "by_source_ip"
    ensure_dir(by_source_dir)
    rows = []
    for source_ip, alerts in sorted(grouped.items(), key=lambda kv: (kv[0] == "unknown", kv[0])):
        attack_ids = {aid for alert in alerts for aid in extract_attack_ids(alert)}
        d3f_map = mapper.map_attack_ids(attack_ids) if attack_ids else {}
        src_dir = by_source_dir / sanitize_name(source_ip)
        ensure_dir(src_dir)
        generate_report(src_dir / "report.html", f"Cyber Lab Report — Source IP {source_ip}", cfg, session_id, operation_info, alerts, attack_ids, d3f_map, compat, source_ip=source_ip)
        rows.append(f"<tr><td>{html.escape(source_ip)}</td><td>{len(alerts)}</td><td>{html.escape(', '.join(sorted(attack_ids)) if attack_ids else 'none')}</td><td><a href='./{sanitize_name(source_ip)}/report.html'>open report</a></td></tr>")

    index_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Per-source reports</title>
<style>body {{ font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }} table {{ border-collapse: collapse; width: 100%; background: #1c1c1c; }} th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }} th {{ background: #222; }} a {{ color: #7db8ff; }}</style>
</head><body><h1>Per-source-IP reports</h1><p><strong>Session:</strong> {html.escape(session_id)}</p>
<table><tr><th>Source IP</th><th>Alerts</th><th>ATT&CK IDs</th><th>Report</th></tr>
{''.join(rows) if rows else '<tr><td colspan="4">No grouped alerts available.</td></tr>'}
</table></body></html>"""
    (by_source_dir / "index.html").write_text(index_html, encoding="utf-8")


def launch_monitor_window_if_requested(config_path: str, session_dir: Path, duration_seconds: int) -> bool:
    if platform.system().lower() != "windows":
        return False
    script_path = Path(__file__).resolve()
    cmd = [
        "powershell", "-NoExit", "-Command",
        f"python '{script_path}' --config '{Path(config_path).resolve()}' --monitor-only --session-dir '{session_dir.resolve()}' --monitor-seconds {duration_seconds}"
    ]
    subprocess.Popen(["cmd", "/c", "start", "Wazuh Monitor", *cmd], shell=False)
    return True


def monitor_loop(cfg: LabConfig, client: Optional[CalderaClient], session_dir: Path, monitor_seconds: int, operation_info: Dict[str, Any], compat: Dict[str, Any], target_markers: Optional[Set[str]] = None, selector_info: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    line_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
    stop_event = threading.Event()
    monitor = WazuhTailMonitor(cfg, line_queue, stop_event)
    monitor.start()

    op_status: Dict[str, Any] = {"op_id": operation_info.get("id")}
    if operation_info:
        op_status["operation"] = operation_info
    if target_markers is None:
        target_markers = derive_target_markers(cfg, session_dir)

    poller = None
    if client and operation_info.get("id") is not None:
        poller = OperationPoller(client, resolve_op_id(operation_info["id"]), cfg.status_refresh_seconds, op_status, stop_event)
        poller.start()

    observed_alerts: List[Dict[str, Any]] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    recent_rows: List[Dict[str, str]] = []

    deadline = time.time() + monitor_seconds
    last_refresh = 0.0

    try:
        while time.time() < deadline:
            now = time.time()
            try:
                _, parsed = line_queue.get(timeout=0.2)
            except queue.Empty:
                remaining = int(max(0, deadline - now))
                if now - last_refresh >= cfg.table_refresh_seconds:
                    render_live_screen(session_dir.name, remaining, monitor_seconds, len(observed_alerts), recent_rows[-cfg.table_max_rows:], op_status, compat, selector_info)
                    last_refresh = now
                continue

            if parsed.get("monitor_error"):
                op_status["monitor_error"] = parsed["monitor_error"]
                remaining = int(max(0, deadline - now))
                render_live_screen(session_dir.name, remaining, monitor_seconds, len(observed_alerts), recent_rows[-cfg.table_max_rows:], op_status, compat, selector_info)
                print(f"\nMonitor error: {parsed['monitor_error']}")
                break

            source_ip = infer_source_ip(parsed, cfg)
            parsed["_inferred_source_ip"] = source_ip
            parsed["_capture_session"] = session_dir.name
            parsed["_captured_at_utc"] = now_utc()

            if alert_matches_target(parsed, cfg, target_markers):
                observed_alerts.append(parsed)
                grouped.setdefault(source_ip, []).append(parsed)
                recent_rows.append({
                    "time": truncate(extract_timestamp(parsed), 20),
                    "src": truncate(source_ip, 16),
                    "agent": truncate(parsed.get("agent", {}).get("name", "unknown"), 16),
                    "lvl": str(severity_of(parsed)),
                    "attack": truncate(",".join(sorted(extract_attack_ids(parsed))) or "-", 18),
                    "desc": truncate(parsed.get("rule", {}).get("description", parsed.get("decoder", {}).get("name", "alert")), 65),
                })
                recent_rows = recent_rows[-200:]

            remaining = int(max(0, deadline - now))
            if now - last_refresh >= cfg.table_refresh_seconds:
                render_live_screen(session_dir.name, remaining, monitor_seconds, len(observed_alerts), recent_rows[-cfg.table_max_rows:], op_status, compat, selector_info)
                last_refresh = now
    finally:
        stop_event.set()
        monitor.join(timeout=3)
        if poller:
            poller.join(timeout=3)

    write_json(session_dir / "captured_alerts_all.json", observed_alerts)
    build_source_summaries(grouped, session_dir)
    write_json(session_dir / "final_operation_status.json", op_status)
    return observed_alerts, grouped, op_status


def run_monitor_only(config_path: str, session_dir: str, monitor_seconds: int) -> int:
    cfg = LabConfig.from_file(config_path)
    session_path = Path(session_dir)
    ensure_dir(session_path)
    mapper = D3fendMapper(cfg.d3fend_mappings_url)
    operation_info, compat = extract_initial_operation_info(session_path)
    operation_info.setdefault("session_id", session_path.name)
    target_markers = derive_target_markers(cfg, session_path)
    selector_info = (load_session_context(session_path).get("selector_info.json", {}) or {})
    client = CalderaClient(cfg) if operation_info.get("id") is not None else None
    observed_alerts, grouped, op_status = monitor_loop(cfg, client, session_path, monitor_seconds, operation_info, compat, target_markers=target_markers, selector_info=selector_info)
    operation_info["_polled_status"] = op_status
    write_json(session_path / "operation_info_final.json", operation_info)
    build_reports(cfg, mapper, session_path, session_path.name, operation_info, observed_alerts, grouped, compat)
    print(f"\n[+] Monitor-only session saved to: {session_path.resolve()}")
    return 0


def list_caldera_for_agent(client: CalderaClient, cfg: LabConfig, interactive_select: bool) -> int:
    agent = client.choose_agent(interactive=interactive_select)
    if not agent:
        print("[-] No agents found.")
        return 2
    abilities = client.list_abilities()
    adversaries = client.list_adversaries()
    ranked = rank_adversaries_for_agent(adversaries, agent, abilities, cfg.noisy_only_mode)
    print(f"\nSelected agent: {agent.get('paw')} | host={agent.get('host')} | platform={agent.get('platform')} | executors={','.join(agent.get('executors', []) or [])}")
    print("=" * 120)
    for item in ranked[:25]:
        adv = item["adversary"]
        compat = item["compatibility"]
        print(f"{truncate(adv.get('adversary_id') or adv.get('id'),24):<24} | {truncate(adv.get('name',''),28):<28} | compatible={compat['compatible_count']:<3} | missing={compat['missing_count']:<3} | noisy_only={compat['noisy_only_mode']}")
    return 0


def run(config_path: str, interactive_select: bool = False, list_only: bool = False) -> int:
    cfg = LabConfig.from_file(config_path)
    out_dir = Path(cfg.output_dir)
    ensure_dir(out_dir)
    client = CalderaClient(cfg)

    if list_only:
        return list_caldera_for_agent(client, cfg, interactive_select)

    agent = client.choose_agent(interactive=interactive_select)
    if not agent:
        print("[-] No agents returned by Caldera.", file=sys.stderr)
        return 2

    abilities = client.list_abilities()
    adversaries = client.list_adversaries()
    ranked = rank_adversaries_for_agent(adversaries, agent, abilities, cfg.noisy_only_mode)

    selected_item = None
    if cfg.caldera_adversary_ids:
        wanted = set(cfg.caldera_adversary_ids)
        for item in ranked:
            adv_id = str(item["adversary"].get("adversary_id") or item["adversary"].get("id"))
            if adv_id in wanted:
                selected_item = item
                break
    if selected_item is None:
        selected_item = choose_ranked_adversary(ranked, interactive=interactive_select)
    if selected_item is None:
        print("[-] No adversaries available.", file=sys.stderr)
        return 2

    selected_adv = selected_item["adversary"]
    compat = selected_item["compatibility"]

    operation_adv = selected_adv
    operation_adv_id = str(selected_adv.get("adversary_id") or selected_adv.get("id"))
    temp_adversary_info = None

    if compat["compatible_count"] == 0 and cfg.auto_build_temp_adversary:
        temp_adv, selected_refs = build_temp_adversary_from_compatible(agent, selected_adv, abilities, cfg.max_temp_abilities, cfg.noisy_only_mode)
        if selected_refs:
            try:
                client.save_adversary(temp_adv)
                operation_adv = temp_adv
                operation_adv_id = temp_adv["adversary_id"]
                temp_adversary_info = {"saved": True, "adversary": temp_adv, "selected_abilities": selected_refs}
                compat = compatibility_report(temp_adv, agent, abilities, noisy_only=cfg.noisy_only_mode)
            except Exception as exc:
                temp_adversary_info = {"saved": False, "error": str(exc), "adversary": temp_adv, "selected_abilities": selected_refs}

    if compat["compatible_count"] == 0:
        print("[-] Zero usable noisy compatible abilities for this adversary/agent pair.", file=sys.stderr)
        return 5

    operation_name = f"{cfg.operation_name_prefix}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    session_id = build_session_id(operation_name)
    session_dir = out_dir / session_id
    ensure_dir(session_dir)

    write_json(session_dir / "selector_info.json", {
        "selected_agent": agent,
        "selected_adversary": selected_adv,
        "operation_adversary": operation_adv,
        "temp_adversary_info": temp_adversary_info,
    })
    write_json(session_dir / "compatibility_report.json", compat)

    print(f"[+] Selected agent paw: {agent.get('paw')}")
    print(f"[+] Selected group: {agent.get('group')}")
    print(f"[+] Selected adversary: {selected_adv.get('adversary_id') or selected_adv.get('id')}")
    print(f"[+] Operation adversary: {operation_adv_id}")
    print(f"[+] Compatible abilities: {compat['compatible_count']} / {compat['referenced_ability_count']}")
    if temp_adversary_info and temp_adversary_info.get("saved"):
        print(f"[+] Temporary noisy adversary created with {len(temp_adversary_info.get('selected_abilities', []))} abilities")

    operation_info = client.create_operation_legacy(operation_name, adversary_id=operation_adv_id, group=str(agent.get("group") or "red"))

    op_id = operation_info.get("id")
    if op_id is None:
        ops = client.list_operations()
        candidates = [op for op in ops if str(op.get("name")) == operation_name]
        if candidates:
            def _sort_candidate(op):
                raw_id = op.get("id")
                try:
                    return (1, int(raw_id))
                except Exception:
                    return (0, str(raw_id or ""))
            candidates.sort(key=_sort_candidate, reverse=True)
            operation_info = candidates[0]
            op_id = operation_info.get("id")

    if op_id is None:
        print("[-] Operation created but op_id could not be resolved.", file=sys.stderr)
        return 6

    try:
        client.set_operation_state(resolve_op_id(op_id), "running")
        refreshed = client.get_operation(resolve_op_id(op_id))
        if refreshed:
            operation_info = refreshed
    except Exception as exc:
        operation_info["_state_transition_error"] = str(exc)

    operation_info["_selector"] = {
        "agent_paw": agent.get("paw"),
        "group": agent.get("group"),
        "selected_adversary_id": selected_adv.get("adversary_id") or selected_adv.get("id"),
        "operation_adversary_id": operation_adv_id,
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
    observed_alerts, grouped, op_status = monitor_loop(
        cfg, client, session_dir, total_monitor_seconds, operation_info, compat,
        target_markers=derive_target_markers(cfg, session_dir),
        selector_info={"selected_agent": agent, "operation_adversary": operation_adv}
    )
    operation_info["_polled_status"] = op_status
    write_json(session_dir / "operation_info_final.json", operation_info)
    build_reports(cfg, mapper, session_dir, session_id, operation_info, observed_alerts, grouped, compat)
    print(f"\n[+] Global report: {(session_dir / 'report.html').resolve()}")
    print(f"[+] Per-source reports: {(session_dir / 'by_source_ip' / 'index.html').resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cyber lab orchestrator v6")
    parser.add_argument("-c", "--config", default="config.yml", help="Path to YAML config file")
    parser.add_argument("--select", action="store_true", help="Interactively select agent and adversary")
    parser.add_argument("--list-caldera", action="store_true", help="List adversaries ranked for the selected agent")
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
