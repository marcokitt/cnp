from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from fpdf import FPDF

from .logging_utils import LogEvent


class PDFReport(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "Caldera Operation Report", ln=1)
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Pagina {self.page_no()}", align="C")


def build_pdf_report(
    output_path: Path,
    run_id: str,
    profile_name: str,
    target_name: str,
    justification: str,
    events: Iterable[LogEvent],
) -> Path:
    events = list(events)
    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(180, 7, f"Run ID: {run_id}")
    pdf.multi_cell(180, 7, f"Profilo: {profile_name}")
    pdf.multi_cell(180, 7, f"Target: {target_name}")
    pdf.multi_cell(180, 7, f"Motivazione: {justification or 'N/D'}")
    pdf.ln(3)

    statuses = Counter(event.status for event in events)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Riepilogo", ln=1)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(
        180,
        7,
        f"Eventi totali: {len(events)} | Successi: {statuses.get('success', 0)} | "
        f"Errori: {statuses.get('error', 0)} | Info: {statuses.get('info', 0)}",
    )
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Dettaglio eventi", ln=1)

    for event in events:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(
            180,
            6,
            f"[{event.timestamp}] {event.attack_id} - {event.technique_name} | {event.phase} | {event.status}",
        )
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(
            180,
            5,
            f"Operation: {event.operation_name} ({event.operation_id or 'n/a'}) | Target: {event.target_name} | Agent: {event.agent_paw or 'n/a'}",
        )
        pdf.multi_cell(180, 5, f"Messaggio: {event.message}")
        if event.motivation:
            pdf.multi_cell(180, 5, f"Motivazione: {event.motivation}")
        if event.elapsed_seconds is not None:
            pdf.multi_cell(180, 5, f"Durata osservata: {event.elapsed_seconds:.1f} s")
        if event.extra:
            extra_text = "; ".join(f"{k}={v}" for k, v in event.extra.items())
            if len(extra_text) > 700:
                extra_text = extra_text[:700] + "..."
            pdf.multi_cell(180, 5, f"Extra: {extra_text}")
        pdf.ln(2)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return output_path
