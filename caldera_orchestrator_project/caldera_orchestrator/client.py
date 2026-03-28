from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import requests

from .config import CalderaSettings


@dataclass(slots=True)
class CalderaResponse:
    ok: bool
    status_code: int
    data: dict[str, Any] | list[Any] | str | None
    error: str | None = None


class CalderaClient:
    """Client minimo e prudente per interagire con l'API REST di Caldera.

    Il client resta volutamente concentrato su operazioni, agenti e interrogazioni basilari.
    Non tenta di forzare endpoint opzionali non presenti in tutte le versioni.
    """

    def __init__(self, settings: CalderaSettings):
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update(
            {
                "KEY": settings.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> CalderaResponse:
        url = f"{self.settings.base_url}{endpoint}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.settings.timeout_seconds,
                verify=self.settings.verify_tls,
                **kwargs,
            )
        except requests.RequestException as exc:
            return CalderaResponse(ok=False, status_code=0, data=None, error=str(exc))

        try:
            data = response.json() if response.text else None
        except ValueError:
            data = response.text

        if response.status_code >= 400:
            return CalderaResponse(
                ok=False,
                status_code=response.status_code,
                data=data,
                error=f"HTTP {response.status_code}",
            )
        return CalderaResponse(ok=True, status_code=response.status_code, data=data)

    def healthcheck(self) -> CalderaResponse:
        return self._request("GET", "/")

    def list_agents(self) -> CalderaResponse:
        return self._request("GET", "/agents")

    def get_agent_by_paw(self, paw: str) -> CalderaResponse:
        response = self.list_agents()
        if not response.ok:
            return response
        if not isinstance(response.data, list):
            return CalderaResponse(False, response.status_code, response.data, "Risposta agenti non valida")
        for agent in response.data:
            if isinstance(agent, dict) and agent.get("paw") == paw:
                return CalderaResponse(True, 200, agent)
        return CalderaResponse(False, 404, response.data, f"Agente con paw '{paw}' non trovato")

    def find_agent_by_hostname(self, hostname: str) -> CalderaResponse:
        response = self.list_agents()
        if not response.ok:
            return response
        if not isinstance(response.data, list):
            return CalderaResponse(False, response.status_code, response.data, "Risposta agenti non valida")
        normalized = hostname.strip().lower()
        for agent in response.data:
            if not isinstance(agent, dict):
                continue
            facts = " ".join(
                str(agent.get(field, "")) for field in ("host", "hostname", "display_name", "paw")
            ).lower()
            if normalized in facts:
                return CalderaResponse(True, 200, agent)
        return CalderaResponse(False, 404, response.data, f"Nessun agente corrisponde a '{hostname}'")

    def create_operation(self, payload: dict[str, Any]) -> CalderaResponse:
        return self._request("POST", "/operations", json=payload)

    def list_operations(self) -> CalderaResponse:
        return self._request("GET", "/operations")

    def get_operation(self, operation_id: str) -> CalderaResponse:
        operations = self.list_operations()
        if not operations.ok:
            return operations
        if not isinstance(operations.data, list):
            return CalderaResponse(False, operations.status_code, operations.data, "Risposta operazioni non valida")
        for operation in operations.data:
            if isinstance(operation, dict) and str(operation.get("id")) == str(operation_id):
                return CalderaResponse(True, 200, operation)
        return CalderaResponse(False, 404, operations.data, f"Operazione '{operation_id}' non trovata")
