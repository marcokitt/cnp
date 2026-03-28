from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from .client import CalderaClient
from .config import load_config, load_ttp_allowlist
from .logging_utils import RunLogger
from .runner import OperationRunner


console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caldera-orchestrator",
        description=(
            "Orchestratore CLI per lanciare operazioni Caldera coerenti con un profilo locale, "
            "con logging dettagliato e report PDF finale."
        ),
    )
    parser.add_argument("--config", default="config.example.yaml", help="Percorso del file YAML di configurazione")
    parser.add_argument("--list", action="store_true", help="Mostra le TTP presenti nella allowlist locale")
    parser.add_argument("--dry-run", action="store_true", help="Mostra il piano ma non invia chiamate API")
    parser.add_argument("--run", action="store_true", help="Esegue il piano definito nella allowlist locale")
    parser.add_argument("--only", help="Esegue solo alcune TTP, separate da virgola. Esempio: T1059,T1105")
    parser.add_argument("--verbose", action="store_true", help="Mostra più dettagli durante l'esecuzione")
    return parser


def filter_ttps(ttps: list[dict[str, Any]], only: str | None) -> list[dict[str, Any]]:
    if not only:
        return ttps
    requested = {item.strip().upper() for item in only.split(",") if item.strip()}
    return [ttp for ttp in ttps if str(ttp.get("attack_id", "")).upper() in requested]


def print_ttps(ttps: list[dict[str, Any]]) -> None:
    table = Table(title="Allowlist TTP")
    table.add_column("ATT&CK ID")
    table.add_column("Nome")
    table.add_column("Fase")
    table.add_column("Motivazione")
    for ttp in ttps:
        table.add_row(
            str(ttp.get("attack_id", "")),
            str(ttp.get("name", "")),
            str(ttp.get("phase", "")),
            str(ttp.get("motivation", "")),
        )
    console.print(table)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not (args.list or args.run or args.dry_run):
        parser.print_help()
        return 1

    config = load_config(args.config)
    allowlist_path = Path(args.config).parent / config.profile.ttp_allowlist_file
    if not allowlist_path.exists():
        allowlist_path = Path(config.profile.ttp_allowlist_file)
    ttps = load_ttp_allowlist(allowlist_path)
    ttps = filter_ttps(ttps, args.only)

    if not ttps:
        console.print("[red]Nessuna TTP selezionata. Controlla --only o il file allowlist.[/red]")
        return 2

    if args.list:
        print_ttps(ttps)

    if args.run or args.dry_run:
        run_id = "preview" if args.dry_run else "live"
        run_logger = RunLogger(Path(config.logging.log_dir), run_id)
        client = CalderaClient(config.caldera)
        runner = OperationRunner(config, client, run_logger)

        console.print(f"[cyan]Profilo:[/cyan] {config.profile.name}")
        console.print(f"[cyan]Target:[/cyan] {config.profile.target_name}")
        console.print(f"[cyan]TTP in coda:[/cyan] {len(ttps)}")
        if args.verbose:
            print_ttps(ttps)

        try:
            artifacts = runner.run(ttps, dry_run=args.dry_run)
        except Exception as exc:
            console.print(f"[red]Errore durante l'esecuzione:[/red] {exc}")
            return 3

        console.print("\n[bold green]Esecuzione completata.[/bold green]")
        if artifacts.jsonl_path:
            console.print(f"- JSONL: {artifacts.jsonl_path}")
        if artifacts.csv_path:
            console.print(f"- CSV:   {artifacts.csv_path}")
        if artifacts.markdown_path:
            console.print(f"- MD:    {artifacts.markdown_path}")
        if artifacts.pdf_path:
            console.print(f"- PDF:   {artifacts.pdf_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
