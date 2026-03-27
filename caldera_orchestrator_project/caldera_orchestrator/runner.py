from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import monotonic, sleep
from typing import Any

from .client import CalderaClient
from .config import AppConfig
from .logging_utils import RunLogger
from .reporting import build_pdf_report


@dataclass(slots=True)
class RunArtifacts:
    run_id: str
    jsonl_path: Path | None = None
    csv_path: Path | None = None
    markdown_path: Path | None = None
    pdf_path: Path | None = None


class OperationRunner:
    def __init__(self, config: AppConfig, client: CalderaClient, run_logger: RunLogger):
        self.config = config
        self.client = client
        self.run_logger = run_logger

    def resolve_agent(self) -> tuple[str, dict[str, Any] | None]:
        paw = self.config.profile.target_agent_paw.strip()
        if paw:
            response = self.client.get_agent_by_paw(paw)
            if response.ok and isinstance(response.data, dict):
                return paw, response.data
            raise RuntimeError(response.error or "Agente specificato non trovato")

        response = self.client.find_agent_by_hostname(self.config.profile.target_name)
        if response.ok and isinstance(response.data, dict):
            resolved_paw = str(response.data.get("paw", ""))
            return resolved_paw, response.data
        raise RuntimeError(
            response.error
            or "Impossibile associare il target ad un agente attivo. Verifica Sandcat o il nome host."
        )

    def build_payload(self, ttp: dict[str, Any], agent_paw: str) -> dict[str, Any]:
        operation_name = f"{self.config.profile.name}-{ttp.get('attack_id', 'TTP')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        return {
            "name": operation_name,
            "adversary": {"adversary_id": self.config.profile.adversary_id},
            "planner": {"planner_id": self.config.operation_defaults.planner_id},
            "state": "running",
            "jitter": self.config.operation_defaults.jitter,
            "visibility": self.config.operation_defaults.visibility,
            "group": agent_paw,
            "facts": [
                {
                    "name": "attack_id",
                    "value": ttp.get("attack_id", "UNKNOWN"),
                }
            ],
        }

    def wait_for_completion(self, operation_id: str) -> tuple[str, float, dict[str, Any] | None]:
        started = monotonic()
        max_wait = self.config.operation_defaults.max_wait_seconds
        poll_interval = self.config.operation_defaults.poll_interval_seconds

        while monotonic() - started <= max_wait:
            response = self.client.get_operation(operation_id)
            if response.ok and isinstance(response.data, dict):
                state = str(response.data.get("state") or response.data.get("status") or "unknown")
                if state.lower() in {"finished", "completed", "complete", "cleanup", "paused", "success"}:
                    return state, monotonic() - started, response.data
            sleep(poll_interval)

        return "timeout", monotonic() - started, None

    def run(self, ttps: list[dict[str, Any]], dry_run: bool = False) -> RunArtifacts:
        run_id = self.run_logger.run_id
        if dry_run:
            agent_paw = self.config.profile.target_agent_paw or "DRY-RUN-AGENT"
            agent_data = {"mode": "dry-run", "target_name": self.config.profile.target_name}
            self.run_logger.add(
                level="INFO",
                phase="preflight",
                attack_id="N/A",
                technique_name="Preflight",
                target_name=self.config.profile.target_name,
                agent_paw=agent_paw,
                operation_name="preflight",
                operation_id="",
                planner_id=self.config.operation_defaults.planner_id,
                adversary_id=self.config.profile.adversary_id,
                status="info",
                message="Dry-run: salto il controllo dell'agente remoto",
                motivation=self.config.profile.justification,
                extra={"agent": agent_data},
            )
        else:
            agent_paw, agent_data = self.resolve_agent()
            self.run_logger.add(
                level="INFO",
                phase="preflight",
                attack_id="N/A",
                technique_name="Preflight",
                target_name=self.config.profile.target_name,
                agent_paw=agent_paw,
                operation_name="preflight",
                operation_id="",
                planner_id=self.config.operation_defaults.planner_id,
                adversary_id=self.config.profile.adversary_id,
                status="info",
                message="Agente risolto correttamente",
                motivation=self.config.profile.justification,
                extra={"agent": agent_data or {}},
            )

        for ttp in ttps:
            attack_id = str(ttp.get("attack_id", "UNKNOWN"))
            technique_name = str(ttp.get("name", "Senza nome"))
            operation_name = f"{self.config.profile.name}-{attack_id}"

            self.run_logger.add(
                level="INFO",
                phase="plan",
                attack_id=attack_id,
                technique_name=technique_name,
                target_name=self.config.profile.target_name,
                agent_paw=agent_paw,
                operation_name=operation_name,
                operation_id="",
                planner_id=self.config.operation_defaults.planner_id,
                adversary_id=self.config.profile.adversary_id,
                status="info",
                message="TTP pianificata in allowlist locale",
                motivation=str(ttp.get("motivation", "")),
                extra={"objective": ttp.get("objective", ""), "phase": ttp.get("phase", "")},
            )

            if dry_run:
                self.run_logger.add(
                    level="INFO",
                    phase="dry-run",
                    attack_id=attack_id,
                    technique_name=technique_name,
                    target_name=self.config.profile.target_name,
                    agent_paw=agent_paw,
                    operation_name=operation_name,
                    operation_id="",
                    planner_id=self.config.operation_defaults.planner_id,
                    adversary_id=self.config.profile.adversary_id,
                    status="info",
                    message="Dry-run: nessuna chiamata API effettuata",
                    motivation=str(ttp.get("motivation", "")),
                )
                continue

            payload = self.build_payload(ttp, agent_paw)
            create_response = self.client.create_operation(payload)
            if not create_response.ok:
                self.run_logger.add(
                    level="ERROR",
                    phase="create-operation",
                    attack_id=attack_id,
                    technique_name=technique_name,
                    target_name=self.config.profile.target_name,
                    agent_paw=agent_paw,
                    operation_name=operation_name,
                    operation_id="",
                    planner_id=self.config.operation_defaults.planner_id,
                    adversary_id=self.config.profile.adversary_id,
                    status="error",
                    message=f"Creazione operazione fallita: {create_response.error}",
                    motivation=str(ttp.get("motivation", "")),
                    extra={"payload": payload, "response": create_response.data},
                )
                continue

            operation_data = create_response.data if isinstance(create_response.data, dict) else {}
            operation_id = str(operation_data.get("id", ""))
            state, elapsed, final_operation = self.wait_for_completion(operation_id)
            status = "success" if state != "timeout" else "error"
            message = (
                f"Operazione osservata fino a stato '{state}'"
                if operation_id
                else "Operazione creata ma ID non disponibile nella risposta"
            )

            self.run_logger.add(
                level="INFO" if status == "success" else "ERROR",
                phase="execution",
                attack_id=attack_id,
                technique_name=technique_name,
                target_name=self.config.profile.target_name,
                agent_paw=agent_paw,
                operation_name=str(operation_data.get("name", operation_name)),
                operation_id=operation_id,
                planner_id=self.config.operation_defaults.planner_id,
                adversary_id=self.config.profile.adversary_id,
                status=status,
                message=message,
                motivation=str(ttp.get("motivation", "")),
                elapsed_seconds=elapsed,
                extra={"final_state": state, "operation": final_operation or operation_data},
            )

        artifacts = RunArtifacts(run_id=run_id)
        if self.config.logging.save_jsonl:
            artifacts.jsonl_path = self.run_logger.save_jsonl()
        if self.config.logging.save_csv:
            artifacts.csv_path = self.run_logger.save_csv()
        if self.config.logging.save_markdown:
            artifacts.markdown_path = self.run_logger.save_markdown()
        if self.config.logging.save_pdf:
            pdf_path = self.config.logging.report_dir / f"{run_id}.pdf"
            artifacts.pdf_path = build_pdf_report(
                pdf_path,
                run_id=run_id,
                profile_name=self.config.profile.name,
                target_name=self.config.profile.target_name,
                justification=self.config.profile.justification,
                events=self.run_logger.events,
            )
        return artifacts
