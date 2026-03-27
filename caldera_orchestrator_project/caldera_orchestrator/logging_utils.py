from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import csv
import json


ISO = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(slots=True)
class LogEvent:
    timestamp: str
    level: str
    phase: str
    attack_id: str
    technique_name: str
    target_name: str
    agent_paw: str
    operation_name: str
    operation_id: str
    planner_id: str
    adversary_id: str
    status: str
    message: str
    motivation: str
    elapsed_seconds: float | None = None
    extra: dict[str, Any] | None = None


class RunLogger:
    def __init__(self, log_dir: Path, run_id: str):
        self.log_dir = log_dir
        self.run_id = run_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[LogEvent] = []

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).strftime(ISO)

    def add(self, **kwargs: Any) -> LogEvent:
        event = LogEvent(timestamp=self.now(), **kwargs)
        self.events.append(event)
        return event

    def save_jsonl(self) -> Path:
        path = self.log_dir / f"{self.run_id}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for event in self.events:
                f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        return path

    def save_csv(self) -> Path:
        path = self.log_dir / f"{self.run_id}.csv"
        if not self.events:
            path.write_text("", encoding="utf-8")
            return path
        fieldnames = list(asdict(self.events[0]).keys())
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in self.events:
                row = asdict(event)
                row["extra"] = json.dumps(row.get("extra") or {}, ensure_ascii=False)
                writer.writerow(row)
        return path

    def save_markdown(self) -> Path:
        path = self.log_dir / f"{self.run_id}.md"
        lines = [
            f"# Operation Log — {self.run_id}",
            "",
            "| Timestamp | Level | Phase | ATT&CK | Technique | Target | Agent | Operation | Status | Message |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for event in self.events:
            lines.append(
                "| {timestamp} | {level} | {phase} | {attack_id} | {technique_name} | {target_name} | {agent_paw} | {operation_name} ({operation_id}) | {status} | {message} |".format(
                    **asdict(event)
                )
            )
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
