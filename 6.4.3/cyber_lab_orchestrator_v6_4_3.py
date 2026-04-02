#!/usr/bin/env python3
"""
cyber_lab_orchestrator_v6_4_3.py

Reconstructed CALDERA orchestrator based on prior version notes.
Focus: CALDERA REST API v2 + legacy fallback, real decision counting,
operation diagnostics, optional temporary adversary generation, and
session artifacts useful for Wazuh / D3FEND correlation.

This script is intentionally defensive and verbose because CALDERA API
behaviour differs slightly across releases and plugins.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"PyYAML non disponibile: {exc}")

try:
    import requests
    from requests import Response, Session
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"requests non disponibile: {exc}")


USER_AGENT = "cyber-lab-orchestrator/6.4.3"
DEFAULT_TIMEOUT = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def json_dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def ndjson_append(path: Path, obj: Any) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def normalize_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


@dataclass
class DebugConfig:
    enabled: bool = True
    launch_monitor_window: bool = False
    write_raw_samples: bool = True


@dataclass
class CalderaConfig:
    url: str
    api_key: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT
    api_mode: str = "auto"  # auto, v2, legacy
    operation_name_prefix: str = "CyberLab"
    planner_id: str = "batch"
    source_id: str = "basic"
    agent_group: str = "red"
    agent_platform: str = "windows"
    agent_executor: str = "psh"
    auto_build_temp_adversary: bool = True
    adversary_ids: List[str] = field(default_factory=list)
    autonomous: bool = True


@dataclass
class MonitorConfig:
    poll_seconds: int = 10
    max_cycles: int = 120
    stop_when_quiet_cycles: int = 6


@dataclass
class WazuhConfig:
    enabled: bool = False
    note: str = "stub section for external correlation"


@dataclass
class LabConfig:
    caldera: CalderaConfig
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    debug_caldera: DebugConfig = field(default_factory=DebugConfig)
    debug_wazuh: DebugConfig = field(default_factory=DebugConfig)

    @staticmethod
    def from_file(path: str | Path) -> "LabConfig":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return LabConfig(
            caldera=CalderaConfig(**(raw.get("caldera") or {})),
            monitor=MonitorConfig(**(raw.get("monitor") or {})),
            wazuh=WazuhConfig(**(raw.get("wazuh") or {})),
            debug_caldera=DebugConfig(**(raw.get("debug_caldera") or {})),
            debug_wazuh=DebugConfig(**(raw.get("debug_wazuh") or {})),
        )


class CalderaError(RuntimeError):
    pass


class CalderaClient:
    def __init__(self, cfg: CalderaConfig, session_dir: Path, debug_cfg: DebugConfig):
        self.cfg = cfg
        self.session_dir = session_dir
        self.debug_cfg = debug_cfg
        self.debug_path = session_dir / "debug_caldera.ndjson"
        self.http = Session()
        self.http.verify = cfg.verify_ssl
        self.http.headers.update({"User-Agent": USER_AGENT})
        self.api_mode = cfg.api_mode
        if cfg.api_key:
            self.http.headers["KEY"] = cfg.api_key
            self.http.headers["Authorization"] = cfg.api_key
        elif cfg.username and cfg.password:
            self.http.auth = (cfg.username, cfg.password)

    def _record(self, phase: str, method: str, url: str, **extra: Any) -> None:
        if self.debug_cfg.enabled:
            ndjson_append(self.debug_path, {
                "ts": utc_now(),
                "phase": phase,
                "method": method,
                "url": url,
                **extra,
            })

    def _request(self, method: str, path: str, *, phase: str, expected: Iterable[int] = (200, 201, 202), **kwargs: Any) -> Response:
        url = self.cfg.url.rstrip("/") + path
        timeout = kwargs.pop("timeout", self.cfg.timeout_seconds)
        payload = kwargs.get("json")
        self._record(phase, method, url, request_json=payload)
        resp = self.http.request(method, url, timeout=timeout, **kwargs)
        preview = None
        try:
            preview = resp.json()
        except Exception:
            preview = resp.text[:2000]
        self._record(phase + ".response", method, url, status=resp.status_code, response=preview)
        if resp.status_code not in set(expected):
            raise CalderaError(f"HTTP {resp.status_code} su {path}: {preview}")
        return resp

    def detect_api_mode(self) -> str:
        if self.api_mode in {"v2", "legacy"}:
            return self.api_mode
        try:
            self._request("GET", "/api/v2/agents", phase="detect.v2", expected=(200,))
            self.api_mode = "v2"
            return self.api_mode
        except Exception:
            self._request("GET", "/api/rest", phase="detect.legacy", expected=(200, 404))
            self.api_mode = "legacy"
            return self.api_mode

    def inventory_agents(self) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            data = self._request("GET", "/api/v2/agents", phase="agents.list", expected=(200,)).json()
            return normalize_list(data)
        data = self._request("GET", "/api/rest", phase="agents.list.legacy", params={"index": "agents"}, expected=(200,)).json()
        return normalize_list(data)

    def inventory_abilities(self) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            data = self._request("GET", "/api/v2/abilities", phase="abilities.list", expected=(200,)).json()
            return normalize_list(data)
        data = self._request("GET", "/api/rest", phase="abilities.list.legacy", params={"index": "abilities"}, expected=(200,)).json()
        return normalize_list(data)

    def inventory_adversaries(self) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            data = self._request("GET", "/api/v2/adversaries", phase="adversaries.list", expected=(200,)).json()
            return normalize_list(data)
        data = self._request("GET", "/api/rest", phase="adversaries.list.legacy", params={"index": "adversaries"}, expected=(200,)).json()
        return normalize_list(data)

    def create_adversary(self, name: str, description: str, atomic_ordering: List[str]) -> Dict[str, Any]:
        mode = self.detect_api_mode()
        payload = {
            "adversary_id": f"tmp-{uuid.uuid4().hex[:12]}",
            "name": name,
            "description": description,
            "atomic_ordering": atomic_ordering,
        }
        if mode == "v2":
            return self._request("POST", "/api/v2/adversaries", phase="adversary.create", json=payload, expected=(200, 201)).json()
        legacy_payload = {"index": "adversaries", **payload}
        return self._request("PUT", "/api/rest", phase="adversary.create.legacy", json=legacy_payload, expected=(200, 201)).json()

    def create_operation(self, name: str, adversary_id: str) -> Dict[str, Any]:
        mode = self.detect_api_mode()
        if mode == "v2":
            payload = {
                "name": name,
                "planner": {"id": self.cfg.planner_id},
                "source": {"id": self.cfg.source_id},
                "adversary": {"adversary_id": adversary_id},
                "group": self.cfg.agent_group,
                "autonomous": 1 if self.cfg.autonomous else 0,
                "state": "running",
            }
            return self._request("POST", "/api/v2/operations", phase="operation.create", json=payload, expected=(200, 201)).json()
        payload = {
            "index": "operations",
            "name": name,
            "planner": self.cfg.planner_id,
            "source": self.cfg.source_id,
            "adversary_id": adversary_id,
            "group": self.cfg.agent_group,
            "autonomous": 1 if self.cfg.autonomous else 0,
            "state": "running",
        }
        return self._request("PUT", "/api/rest", phase="operation.create.legacy", json=payload, expected=(200, 201)).json()

    def patch_operation_running(self, operation_id: str) -> Dict[str, Any]:
        mode = self.detect_api_mode()
        if mode == "v2":
            payload = {"state": "running", "autonomous": 1 if self.cfg.autonomous else 0}
            return self._request("PATCH", f"/api/v2/operations/{operation_id}", phase="operation.patch", json=payload, expected=(200,)).json()
        payload = {"index": "operations", "id": operation_id, "state": "running", "autonomous": 1 if self.cfg.autonomous else 0}
        return self._request("POST", "/api/rest", phase="operation.patch.legacy", json=payload, expected=(200,)).json()

    def get_operation(self, operation_id: str) -> Dict[str, Any]:
        mode = self.detect_api_mode()
        if mode == "v2":
            return self._request("GET", f"/api/v2/operations/{operation_id}", phase="operation.get", expected=(200,)).json()
        return self._request("GET", "/api/rest", phase="operation.get.legacy", params={"index": "operations", "id": operation_id}, expected=(200,)).json()

    def get_operation_links(self, operation_id: str) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            return normalize_list(self._request("GET", f"/api/v2/operations/{operation_id}/links", phase="links.get", expected=(200,)).json())
        return normalize_list(self._request("GET", "/api/rest", phase="links.get.legacy", params={"index": "operation_links", "op_id": operation_id}, expected=(200,)).json())

    def get_operation_potential_links(self, operation_id: str) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            return normalize_list(self._request("GET", f"/api/v2/operations/{operation_id}/potential-links", phase="potential.get", expected=(200,)).json())
        return []

    def get_operation_report(self, operation_id: str) -> Any:
        mode = self.detect_api_mode()
        if mode == "v2":
            return self._request("GET", f"/api/v2/operations/{operation_id}/report", phase="report.get", expected=(200, 404)).json()
        return self._request("GET", "/api/rest", phase="report.get.legacy", params={"index": "operation_report", "op_id": operation_id}, expected=(200, 404)).json()

    def get_operation_event_logs(self, operation_id: str) -> List[Dict[str, Any]]:
        mode = self.detect_api_mode()
        if mode == "v2":
            return normalize_list(self._request("GET", f"/api/v2/operations/{operation_id}/event-logs", phase="eventlogs.get", expected=(200, 404)).json())
        return []


def agent_summary(agent: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "paw": first_non_empty(agent.get("paw"), agent.get("id")),
        "group": agent.get("group"),
        "host": first_non_empty(agent.get("host"), agent.get("hostname"), agent.get("display_name")),
        "platform": first_non_empty(agent.get("platform"), agent.get("os")),
        "executors": normalize_list(agent.get("executors") or agent.get("executor") or []),
        "trusted": agent.get("trusted"),
        "sleep": first_non_empty(agent.get("sleep_min"), agent.get("sleep")),
        "watchdog": agent.get("watchdog"),
    }


def ability_matches(ability: Dict[str, Any], platform: str, executor: str) -> bool:
    ability_platform = str(first_non_empty(ability.get("platform"), ability.get("platforms"), "")).lower()
    platform = platform.lower()
    executor = executor.lower()

    if ability_platform and ability_platform not in platform and platform not in ability_platform:
        plats = normalize_list(ability.get("platforms"))
        if plats:
            ok = False
            for item in plats:
                if isinstance(item, str) and item.lower() == platform:
                    ok = True
                    break
                if isinstance(item, dict) and str(item.get("platform", "")).lower() == platform:
                    ok = True
                    break
            if not ok:
                return False

    execs: List[str] = []
    if "executor" in ability:
        execs.extend([str(x).lower() for x in normalize_list(ability.get("executor"))])
    if "executors" in ability:
        for item in normalize_list(ability.get("executors")):
            if isinstance(item, str):
                execs.append(item.lower())
            elif isinstance(item, dict):
                name = first_non_empty(item.get("name"), item.get("executor"), item.get("platform"))
                if name:
                    execs.append(str(name).lower())
    if execs and executor not in execs:
        return False
    return True


def select_abilities_for_temp_adversary(abilities: List[Dict[str, Any]], platform: str, executor: str) -> Tuple[List[str], List[Dict[str, Any]]]:
    selected_ids: List[str] = []
    debug_rows: List[Dict[str, Any]] = []
    seen = set()
    for ability in abilities:
        ability_id = first_non_empty(ability.get("ability_id"), ability.get("id"))
        if not ability_id or ability_id in seen:
            continue
        match = ability_matches(ability, platform, executor)
        row = {
            "ability_id": ability_id,
            "name": ability.get("name"),
            "platform": ability.get("platform"),
            "executors": ability.get("executors") or ability.get("executor"),
            "tactic": ability.get("tactic"),
            "technique": ability.get("technique_name") or ability.get("technique"),
            "match": match,
        }
        debug_rows.append(row)
        if match:
            seen.add(ability_id)
            selected_ids.append(str(ability_id))
    return selected_ids, debug_rows


def decision_metrics(links: List[Dict[str, Any]], potential_links: List[Dict[str, Any]], operation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    operation = operation or {}
    host_group = normalize_list(operation.get("host_group"))
    host_group_links = 0
    for host in host_group:
        host_group_links += len(normalize_list(host.get("links")))

    states: Dict[str, int] = {}
    for item in links:
        key = str(item.get("status") or item.get("state") or "unknown")
        states[key] = states.get(key, 0) + 1

    return {
        "links_total": len(links),
        "potential_links_total": len(potential_links),
        "decisions_real_total": len(links) + len(potential_links),
        "host_group_links_observed": host_group_links,
        "status_breakdown": states,
    }


def operation_id_from_obj(obj: Dict[str, Any]) -> str:
    return str(first_non_empty(obj.get("id"), obj.get("operation_id"), obj.get("op_id")))


def adversary_id_from_obj(obj: Dict[str, Any]) -> str:
    adv = obj.get("adversary")
    if isinstance(adv, dict):
        return str(first_non_empty(adv.get("adversary_id"), adv.get("id"), ""))
    return str(first_non_empty(obj.get("adversary_id"), obj.get("adversary"), ""))


def create_session_dir(base: Optional[str]) -> Path:
    root = Path(base) if base else Path.cwd() / "sessions"
    safe_mkdir(root)
    session_dir = root / datetime.now().strftime("session_%Y%m%d_%H%M%S")
    safe_mkdir(session_dir)
    return session_dir


def choose_adversary(client: CalderaClient, cfg: LabConfig, session_dir: Path) -> Tuple[str, Dict[str, Any]]:
    abilities = client.inventory_abilities()
    adversaries = client.inventory_adversaries()
    json_dump(session_dir / "adversaries_inventory.json", adversaries)

    if cfg.caldera.auto_build_temp_adversary:
        selected_ids, debug_rows = select_abilities_for_temp_adversary(
            abilities,
            cfg.caldera.agent_platform,
            cfg.caldera.agent_executor,
        )
        json_dump(session_dir / "selected_abilities_debug.json", debug_rows)
        if selected_ids:
            temp_adv = client.create_adversary(
                name=f"Temporary {cfg.caldera.agent_platform}/{cfg.caldera.agent_executor}",
                description="Autogenerated strict adversary for orchestrator v6.4.3",
                atomic_ordering=selected_ids,
            )
            json_dump(session_dir / "temp_adversary_used.json", temp_adv)
            return adversary_id_from_obj(temp_adv), {
                "mode": "temp",
                "selected_abilities": len(selected_ids),
                "adversary": temp_adv,
            }
        json_dump(session_dir / "temp_adversary_used.json", {
            "mode": "temp",
            "created": False,
            "reason": "No abilities matched platform/executor",
        })

    chosen: Optional[Dict[str, Any]] = None
    for adversary in adversaries:
        adv_id = adversary_id_from_obj(adversary)
        if cfg.caldera.adversary_ids and adv_id in cfg.caldera.adversary_ids:
            chosen = adversary
            break
    if not chosen and adversaries:
        chosen = adversaries[0]
    if not chosen:
        raise SystemExit("Nessun adversary disponibile in CALDERA.")

    info = {
        "mode": "existing",
        "adversary": chosen,
        "requested_ids": cfg.caldera.adversary_ids,
    }
    json_dump(session_dir / "temp_adversary_used.json", info)
    return adversary_id_from_obj(chosen), info


def print_inventory(client: CalderaClient) -> int:
    agents = client.inventory_agents()
    rows = [agent_summary(a) for a in agents]
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def monitor_operation(client: CalderaClient, cfg: LabConfig, session_dir: Path, operation_id: str) -> Dict[str, Any]:
    history: List[Dict[str, Any]] = []
    quiet_cycles = 0
    last_decisions = -1
    last_links = -1
    last_potentials = -1

    for cycle in range(1, cfg.monitor.max_cycles + 1):
        operation = client.get_operation(operation_id)
        links = client.get_operation_links(operation_id)
        potential = client.get_operation_potential_links(operation_id)
        report = client.get_operation_report(operation_id)
        event_logs = client.get_operation_event_logs(operation_id)
        metrics = decision_metrics(links, potential, operation)

        snapshot = {
            "ts": utc_now(),
            "cycle": cycle,
            "operation_state": operation.get("state"),
            "links_total": len(links),
            "potential_links_total": len(potential),
            "decisions_real_total": metrics["decisions_real_total"],
            "event_logs_total": len(event_logs),
            "report_present": bool(report),
            "report_type": type(report).__name__,
        }
        history.append(snapshot)

        json_dump(session_dir / "caldera_links.json", links)
        json_dump(session_dir / "caldera_potential_links.json", potential)
        json_dump(session_dir / "caldera_report.json", report)
        json_dump(session_dir / "caldera_event_logs.json", event_logs)
        json_dump(session_dir / "operation_current.json", operation)
        json_dump(session_dir / "caldera_poll_history.json", history)

        changed = (snapshot["decisions_real_total"] != last_decisions or len(links) != last_links or len(potential) != last_potentials)
        if changed:
            quiet_cycles = 0
        else:
            quiet_cycles += 1
        last_decisions = snapshot["decisions_real_total"]
        last_links = len(links)
        last_potentials = len(potential)

        if quiet_cycles >= cfg.monitor.stop_when_quiet_cycles:
            break
        time.sleep(max(1, cfg.monitor.poll_seconds))

    final_operation = client.get_operation(operation_id)
    final_links = client.get_operation_links(operation_id)
    final_potential = client.get_operation_potential_links(operation_id)
    final_report = client.get_operation_report(operation_id)
    final_event_logs = client.get_operation_event_logs(operation_id)
    final_metrics = decision_metrics(final_links, final_potential, final_operation)

    diagnostics = {
        "ts": utc_now(),
        "operation_id": operation_id,
        "operation_state": final_operation.get("state"),
        "metrics": final_metrics,
        "event_logs_total": len(final_event_logs),
        "report_present": bool(final_report),
        "diagnosis": derive_diagnosis(final_metrics, final_event_logs, final_report),
    }
    json_dump(session_dir / "operation_diagnostics.json", diagnostics)
    json_dump(session_dir / "wazuh_diagnostics.json", {
        "enabled": cfg.wazuh.enabled,
        "note": cfg.wazuh.note,
        "linked_operation_id": operation_id,
        "event_logs_total": len(final_event_logs),
    })
    if cfg.debug_wazuh.write_raw_samples:
        json_dump(session_dir / "debug_wazuh_raw_samples.json", final_event_logs[:20])
    return diagnostics


def derive_diagnosis(metrics: Dict[str, Any], event_logs: List[Dict[str, Any]], report: Any) -> str:
    real_total = int(metrics.get("decisions_real_total", 0))
    links_total = int(metrics.get("links_total", 0))
    if real_total > 0 and (event_logs or report):
        return "CALDERA OK"
    if real_total > 0 and not event_logs and not report:
        return "planner attivo ma report/event-logs assenti: possibile UI counter bug o telemetry mancante"
    if real_total == 0 and links_total == 0:
        return "planner sterile o adversary senza abilities eseguibili per agent/executor"
    return "stato incerto: verificare debug_caldera.ndjson e caldera_poll_history.json"


def run(cfg: LabConfig, session_dir: Path) -> int:
    client = CalderaClient(cfg.caldera, session_dir, cfg.debug_caldera)
    mode = client.detect_api_mode()
    json_dump(session_dir / "selector_info.json", {
        "api_mode": mode,
        "agent_platform": cfg.caldera.agent_platform,
        "agent_executor": cfg.caldera.agent_executor,
        "agent_group": cfg.caldera.agent_group,
    })

    adv_id, adv_info = choose_adversary(client, cfg, session_dir)
    operation_name = f"{cfg.caldera.operation_name_prefix} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    op = client.create_operation(operation_name, adv_id)
    operation_id = operation_id_from_obj(op)
    if not operation_id:
        raise SystemExit(f"Impossibile ottenere operation_id dalla risposta: {op}")
    patched = client.patch_operation_running(operation_id)

    operation_info = {
        "operation": op,
        "patched": patched,
        "operation_id": operation_id,
        "adversary_id": adv_id,
        "adversary_info": adv_info,
        "api_mode": mode,
    }
    json_dump(session_dir / "operation_info.json", operation_info)

    diagnostics = monitor_operation(client, cfg, session_dir, operation_id)
    print(json.dumps(diagnostics, indent=2, ensure_ascii=False))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CALDERA orchestrator v6.4.3")
    p.add_argument("--config", required=True, help="Percorso del file YAML di configurazione")
    p.add_argument("--session-dir", default="", help="Cartella base dove salvare gli artifact")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("inventory", help="Elenca gli agent in formato JSON")
    sub.add_parser("run", help="Crea e monitora una operation")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    cfg = LabConfig.from_file(args.config)
    session_dir = create_session_dir(args.session_dir)
    client = CalderaClient(cfg.caldera, session_dir, cfg.debug_caldera)

    if args.command == "inventory":
        return print_inventory(client)
    return run(cfg, session_dir)


if __name__ == "__main__":
    raise SystemExit(main())
