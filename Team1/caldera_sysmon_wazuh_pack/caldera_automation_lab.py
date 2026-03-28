#!/usr/bin/env python3
"""
Automazione base per MITRE CALDERA (lab).

Configurato per:
- CALDERA URL: http://192.168.30.45:8888
- API KEY: ADMIN123
- Credenziali note del laboratorio:
  admin/admin  (red)
  red/admin    (red)
  blue/admin   (blue)

Uso rapido:
    python caldera_automation_lab.py test
    python caldera_automation_lab.py agents
    python caldera_automation_lab.py adversaries
    python caldera_automation_lab.py planners
    python caldera_automation_lab.py operations
    python caldera_automation_lab.py create-op --name "Lab Win10" --adversary ADV_ID --planner atomic
    python caldera_automation_lab.py watch --op OPERATION_ID
"""

import argparse
import json
import sys
import time
from typing import Any, Optional

import requests
from requests.auth import HTTPBasicAuth

CALDERA_HOST = "http://192.168.30.45:8888"
API_KEY = "ADMIN123"

USERS = {
    "admin_red": ("admin", "admin"),
    "red": ("red", "admin"),
    "blue": ("blue", "admin"),
}

TIMEOUT = 20

session = requests.Session()
session.headers.update({
    "KEY": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
})

def _url(path: str) -> str:
    return CALDERA_HOST.rstrip("/") + path

def request_json(method: str, path: str, *, json_data: Optional[dict] = None, auth_user: Optional[str] = None) -> Any:
    auth = None
    if auth_user:
        if auth_user not in USERS:
            raise ValueError(f"Utente logico sconosciuto: {auth_user}")
        u, p = USERS[auth_user]
        auth = HTTPBasicAuth(u, p)

    resp = session.request(method, _url(path), json=json_data, auth=auth, timeout=TIMEOUT)
    resp.raise_for_status()
    if not resp.text.strip():
        return None
    try:
        return resp.json()
    except Exception:
        return resp.text

def test_api_docs() -> None:
    print("Verifica connettività di base...")
    for p in ["/", "/api/docs"]:
        try:
            r = session.get(_url(p), timeout=TIMEOUT)
            print(f"{p} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"{p} -> errore: {e}")

def list_agents():
    return request_json("GET", "/api/v2/agents")

def list_adversaries():
    return request_json("GET", "/api/v2/adversaries")

def list_planners():
    return request_json("GET", "/api/v2/planners")

def list_operations():
    return request_json("GET", "/api/v2/operations")

def get_operation(op_id: str):
    return request_json("GET", f"/api/v2/operations/{op_id}")

def create_operation(name: str, adversary_id: str, planner_id: str = "atomic", group: str = "red",
                     jitter: str = "2/8", obfuscator: str = "plain-text", auto_close: bool = True):
    payload = {
        "name": name,
        "group": group,
        "jitter": jitter,
        "auto_close": auto_close,
        "obfuscator": obfuscator,
        "adversary": {
            "adversary_id": adversary_id
        },
        "planner": {
            "planner_id": planner_id
        }
    }
    return request_json("POST", "/api/v2/operations", json_data=payload)

def safe_windows_shortlist(adversaries: Any) -> None:
    print("Criterio prudenziale per Windows 10:")
    print("- partire da discovery ed execution semplice")
    print("- preferire executor cmd / psh / pwsh")
    print("- evitare subito tecniche con prerequisiti pesanti")
    print("- validare prima una singola ability con Sysmon e Wazuh")
    print("\nAdversary objects ricevuti:")
    print(json.dumps(adversaries, indent=2, ensure_ascii=False))

def watch_operation(op_id: str, interval: int = 5):
    while True:
        data = get_operation(op_id)
        print(json.dumps(data, indent=2, ensure_ascii=False))
        state = ""
        if isinstance(data, dict):
            state = str(data.get("state", "")).lower()
        if state in {"finished", "complete", "completed", "closed"}:
            print("Operazione terminata.")
            break
        time.sleep(interval)

def main():
    ap = argparse.ArgumentParser(description="Automazione lab CALDERA")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("test")
    sub.add_parser("agents")
    sub.add_parser("adversaries")
    sub.add_parser("planners")
    sub.add_parser("operations")

    p_create = sub.add_parser("create-op")
    p_create.add_argument("--name", required=True)
    p_create.add_argument("--adversary", required=True, help="adversary_id")
    p_create.add_argument("--planner", default="atomic")
    p_create.add_argument("--group", default="red")
    p_create.add_argument("--jitter", default="2/8")
    p_create.add_argument("--obfuscator", default="plain-text")

    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--op", required=True)
    p_watch.add_argument("--interval", type=int, default=5)

    sub.add_parser("safe-shortlist")

    args = ap.parse_args()

    try:
        if args.cmd == "test":
            test_api_docs()
        elif args.cmd == "agents":
            print(json.dumps(list_agents(), indent=2, ensure_ascii=False))
        elif args.cmd == "adversaries":
            print(json.dumps(list_adversaries(), indent=2, ensure_ascii=False))
        elif args.cmd == "planners":
            print(json.dumps(list_planners(), indent=2, ensure_ascii=False))
        elif args.cmd == "operations":
            print(json.dumps(list_operations(), indent=2, ensure_ascii=False))
        elif args.cmd == "create-op":
            out = create_operation(
                name=args.name,
                adversary_id=args.adversary,
                planner_id=args.planner,
                group=args.group,
                jitter=args.jitter,
                obfuscator=args.obfuscator
            )
            print(json.dumps(out, indent=2, ensure_ascii=False))
        elif args.cmd == "watch":
            watch_operation(args.op, args.interval)
        elif args.cmd == "safe-shortlist":
            safe_windows_shortlist(list_adversaries())
    except requests.HTTPError as e:
        print("HTTP error:", e)
        if e.response is not None:
            print("Status:", e.response.status_code)
            print("Body:", e.response.text)
        sys.exit(1)
    except Exception as e:
        print("Errore:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
