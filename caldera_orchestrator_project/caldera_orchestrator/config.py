from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import yaml


@dataclass(slots=True)
class CalderaSettings:
    host: str
    port: int
    api_key: str
    use_https: bool = False
    verify_tls: bool = False
    timeout_seconds: int = 15

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.port}/api/v2"


@dataclass(slots=True)
class OperationDefaults:
    planner_id: str
    jitter: str = "2/5"
    visibility: int = 50
    auto_close_after_completion: bool = False
    poll_interval_seconds: int = 5
    max_wait_seconds: int = 300


@dataclass(slots=True)
class LoggingSettings:
    log_dir: Path
    report_dir: Path
    save_jsonl: bool = True
    save_csv: bool = True
    save_markdown: bool = True
    save_pdf: bool = True


@dataclass(slots=True)
class ProfileSettings:
    name: str
    adversary_id: str
    target_name: str
    target_agent_paw: str = ""
    justification: str = ""
    ttp_allowlist_file: str = "./sample_profile.json"


@dataclass(slots=True)
class AppConfig:
    caldera: CalderaSettings
    operation_defaults: OperationDefaults
    logging: LoggingSettings
    profile: ProfileSettings


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(path: str | Path) -> AppConfig:
    path = Path(path)
    data = _load_yaml(path)

    caldera = CalderaSettings(**data["caldera"])
    operation_defaults = OperationDefaults(**data["operation_defaults"])

    logging_data = data["logging"]
    logging_settings = LoggingSettings(
        log_dir=Path(logging_data["log_dir"]),
        report_dir=Path(logging_data["report_dir"]),
        save_jsonl=logging_data.get("save_jsonl", True),
        save_csv=logging_data.get("save_csv", True),
        save_markdown=logging_data.get("save_markdown", True),
        save_pdf=logging_data.get("save_pdf", True),
    )

    profile = ProfileSettings(**data["profile"])
    return AppConfig(
        caldera=caldera,
        operation_defaults=operation_defaults,
        logging=logging_settings,
        profile=profile,
    )


def load_ttp_allowlist(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    ttps = data.get("ttps", [])
    if not isinstance(ttps, list):
        raise ValueError("Il file di allowlist deve contenere un array 'ttps'.")
    return ttps
