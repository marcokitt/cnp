#!/usr/bin/env python3
"""
Genera un file D3FEND CAD JSON partendo da un report HTML custom e arricchendolo
con le mappature ufficiali MITRE D3FEND ottenute via REST API ufficiale.

Flusso:
1) Analizza l'HTML del report.
2) Estrae ATT&CK IDs e metadati della sessione.
3) Chiama l'endpoint ufficiale MITRE D3FEND per le inferred mappings.
4) Cerca le difese D3FEND collegate agli ATT&CK IDs trovati.
5) Produce un file CAD JSON pronto da aprire in D3FEND CAD:
   File -> Load

Riferimenti ufficiali usati dal codice:
- API docs: https://d3fend.mitre.org/api-docs/
- Inference mappings endpoint: /api/ontology/inference/d3fend-full-mappings.csv
- CAD schema/docs: https://d3fend.mitre.org/cad/docs/schema/

Dipendenze:
    pip install requests beautifulsoup4

Esempio:
    python d3fend_html_to_cad.py \
        --input d3fend_report.html \
        --output d3fend_report.cad.json \
        --title "APT Sim - DEFEND CAD"
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from bs4 import BeautifulSoup

# Endpoint ufficiali MITRE D3FEND
D3FEND_API_BASE = "https://d3fend.mitre.org"
D3FEND_INFERENCE_CSV = f"{D3FEND_API_BASE}/api/ontology/inference/d3fend-full-mappings.csv"
D3FEND_VERSION_ENDPOINT = f"{D3FEND_API_BASE}/api/version"

# Versione schema CAD: il CAD schema ufficiale espone il campo cad_schema_version numerico.
# Manteniamo un valore conservativo e semplice da leggere da CAD.
CAD_SCHEMA_VERSION = 1.0

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
D3_ID_RE = re.compile(r"\bD3-[A-Z0-9-]+\b")
D3_URI_RE = re.compile(r"\bd3f:[A-Za-z0-9_]+\b")


@dataclass
class ReportTechnique:
    attack_id: str
    technique_name: str = ""
    tactic: str = ""
    report_mapping_text: str = ""
    coverage: str = ""


@dataclass
class ReportData:
    generated: str = ""
    session: str = ""
    operation: str = ""
    observed_wazuh_ids: List[str] = field(default_factory=list)
    techniques: List[ReportTechnique] = field(default_factory=list)


@dataclass
class D3Mapping:
    attack_id: str
    d3_name: str
    d3_id: str = ""
    d3_class: str = ""
    relation: str = ""
    raw_row: Dict[str, str] = field(default_factory=dict)


# -------------------------------
# Utility generiche
# -------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip())
    return value.strip("-").lower() or "graph"


def normalize_header(name: str) -> str:
    name = name.strip().lower()
    name = name.replace("&", " and ")
    name = re.sub(r"[^a-z0-9]+", "_", name)
    return name.strip("_")


def first_present(row: Dict[str, str], candidates: Sequence[str]) -> str:
    for key in candidates:
        if key in row and str(row[key]).strip():
            return str(row[key]).strip()
    return ""


def unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


# -------------------------------
# Parsing HTML report
# -------------------------------

def parse_html_report(html_path: Path) -> ReportData:
    html = html_path.read_text(encoding="utf-8", errors="ignore")
    soup = BeautifulSoup(html, "html.parser")

    data = ReportData()

    # Generated timestamp
    body_text = soup.get_text("\n", strip=True)
    gen_match = re.search(r"Generated:\s*([0-9T:\-\.Z\+]+)", body_text, re.IGNORECASE)
    if gen_match:
        data.generated = gen_match.group(1).strip()

    # Session / Operation / Wazuh ATT&CK IDs
    panel_text = body_text
    session_match = re.search(r"Session:\s*(.+?)\s*Operation:", panel_text, re.IGNORECASE | re.DOTALL)
    if session_match:
        data.session = session_match.group(1).strip()

    operation_match = re.search(r"Operation:\s*(.+?)\s*Observed ATT&CK IDs in Wazuh:", panel_text, re.IGNORECASE | re.DOTALL)
    if operation_match:
        data.operation = operation_match.group(1).strip()

    wazuh_match = re.search(r"Observed ATT&CK IDs in Wazuh:\s*(.+)", panel_text, re.IGNORECASE)
    if wazuh_match:
        data.observed_wazuh_ids = unique_preserve_order(ATTACK_ID_RE.findall(wazuh_match.group(1)))

    # Tabella tecniche
    table = soup.find("table")
    if table:
        rows = table.find_all("tr")
        if rows:
            headers = [normalize_header(th.get_text(" ", strip=True)) for th in rows[0].find_all(["th", "td"])]
            for tr in rows[1:]:
                cells = [td.get_text(" ", strip=True) for td in tr.find_all(["td", "th"])]
                if not cells:
                    continue
                row = {headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))}
                attack_id = first_present(row, ["technique_id", "attack_id", "attack_technique_id"])
                if not attack_id:
                    found = ATTACK_ID_RE.findall(" ".join(cells))
                    attack_id = found[0] if found else ""
                if not attack_id:
                    continue
                data.techniques.append(
                    ReportTechnique(
                        attack_id=attack_id.upper(),
                        technique_name=first_present(row, ["technique_name", "attack_technique", "name"]),
                        tactic=first_present(row, ["tactic", "tactics"]),
                        report_mapping_text=first_present(row, ["d3fend_mappings", "d3fend_mapping", "mapping", "mappings"]),
                        coverage=first_present(row, ["coverage"]),
                    )
                )

    # Se nel report compaiono ATT&CK IDs fuori tabella, li preserviamo come tecniche minimali.
    known_ids = {t.attack_id for t in data.techniques}
    for attack_id in data.observed_wazuh_ids:
        if attack_id not in known_ids:
            data.techniques.append(ReportTechnique(attack_id=attack_id, technique_name="Observed in Wazuh"))

    # Deduplica finale.
    dedup: Dict[str, ReportTechnique] = {}
    for tech in data.techniques:
        if tech.attack_id not in dedup:
            dedup[tech.attack_id] = tech
        else:
            current = dedup[tech.attack_id]
            if not current.technique_name and tech.technique_name:
                current.technique_name = tech.technique_name
            if not current.tactic and tech.tactic:
                current.tactic = tech.tactic
            if not current.report_mapping_text and tech.report_mapping_text:
                current.report_mapping_text = tech.report_mapping_text
            if not current.coverage and tech.coverage:
                current.coverage = tech.coverage
    data.techniques = list(dedup.values())

    return data


# -------------------------------
# Accesso API ufficiale MITRE D3FEND
# -------------------------------

def fetch_d3fend_version(session: requests.Session) -> str:
    try:
        resp = session.get(D3FEND_VERSION_ENDPOINT, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, dict):
            # Proviamo più chiavi senza assumere troppo.
            for key in ("version", "ontology_version", "d3fend_version"):
                value = payload.get(key)
                if value:
                    return str(value)
        return "unknown"
    except Exception:
        return "unknown"


def fetch_inference_csv(session: requests.Session) -> List[Dict[str, str]]:
    resp = session.get(D3FEND_INFERENCE_CSV, timeout=120)
    resp.raise_for_status()
    resp.encoding = resp.encoding or "utf-8"
    reader = csv.DictReader(resp.text.splitlines())
    normalized_rows: List[Dict[str, str]] = []
    for row in reader:
        normalized_rows.append({normalize_header(k): (v or "").strip() for k, v in row.items() if k is not None})
    return normalized_rows


def infer_mapping_from_row(row: Dict[str, str], attack_id: str) -> Optional[D3Mapping]:
    """
    Cerca di estrarre da una riga CSV la difesa D3FEND collegata all'ATT&CK ID richiesto.
    Il CSV ufficiale MITRE può evolvere, quindi qui lavoriamo in modo elastico:
    - normalizziamo le intestazioni
    - cerchiamo l'ATT&CK ID in più colonne plausibili e, in ultima istanza, in tutta la riga
    - estraiamo nome/id/classe D3FEND da colonne note o dal testo della riga
    """
    attack_candidates = [
        "attack_technique_id",
        "offensive_technique_id",
        "attack_id",
        "technique_id",
        "attack",
        "offensive_technique",
        "offensive_id",
    ]
    row_attack = first_present(row, attack_candidates).upper()
    row_blob = " | ".join(f"{k}={v}" for k, v in row.items())

    if attack_id.upper() not in row_attack:
        found_attack_ids = [x.upper() for x in ATTACK_ID_RE.findall(row_blob)]
        if attack_id.upper() not in found_attack_ids:
            return None

    d3_name = first_present(
        row,
        [
            "defensive_technique",
            "technique",
            "d3fend_technique",
            "defense",
            "countermeasure",
            "countermeasure_technique",
        ],
    )
    d3_id = first_present(row, ["defensive_technique_id", "d3fend_technique_id", "d3_id", "defense_id"])
    relation = first_present(row, ["relation", "predicate", "binding", "mapping_relation"])
    d3_class = first_present(row, ["d3fend_class", "class", "d3f_class"])

    if not d3_id:
        m = D3_ID_RE.search(row_blob)
        if m:
            d3_id = m.group(0)

    if not d3_class:
        m = D3_URI_RE.search(row_blob)
        if m:
            d3_class = m.group(0)

    # Se il nome non è esplicito ma c'è almeno un ID D3, usiamo quello come label minimale.
    if not d3_name and d3_id:
        d3_name = d3_id

    if not d3_name and not d3_id and not d3_class:
        return None

    return D3Mapping(
        attack_id=attack_id.upper(),
        d3_name=d3_name or "Unnamed D3FEND technique",
        d3_id=d3_id,
        d3_class=d3_class,
        relation=relation,
        raw_row=row,
    )


def build_official_mappings(session: requests.Session, attack_ids: Sequence[str]) -> Dict[str, List[D3Mapping]]:
    rows = fetch_inference_csv(session)
    wanted = {x.upper() for x in attack_ids}
    results: Dict[str, List[D3Mapping]] = {x: [] for x in wanted}

    for row in rows:
        for attack_id in wanted:
            mapped = infer_mapping_from_row(row, attack_id)
            if mapped is not None:
                results[attack_id].append(mapped)

    # Deduplica per nome/id/classe
    cleaned: Dict[str, List[D3Mapping]] = {}
    for attack_id, mappings in results.items():
        seen = set()
        cleaned_list: List[D3Mapping] = []
        for m in mappings:
            key = (m.d3_name.strip(), m.d3_id.strip(), m.d3_class.strip(), m.relation.strip())
            if key in seen:
                continue
            seen.add(key)
            cleaned_list.append(m)
        cleaned[attack_id] = cleaned_list
    return cleaned


# -------------------------------
# Generazione CAD JSON
# -------------------------------

def make_node(node_id: str, node_type: str, label: str, x: float, y: float, *, d3f_class: str = "", seq: str = "") -> Dict:
    data = {
        "label": label,
        "sequence": seq,
        "user_properties": [],
    }
    if d3f_class:
        data["d3f_class"] = d3f_class

    return {
        "id": node_id,
        "type": node_type,
        "position": {"x": x, "y": y},
        "data": data,
        "measured": {"width": 240, "height": 80},
        "selected": False,
        "dragging": False,
        "width": 240,
        "height": 80,
    }


def make_edge(edge_id: str, source: str, target: str, label: str, *, d3f_property: str = "") -> Dict:
    data = {"label": label}
    if d3f_property:
        data["d3f_property"] = d3f_property

    return {
        "id": edge_id,
        "type": "default",
        "data": data,
        "markerEnd": {"type": "arrowclosed"},
        "source": source,
        "sourceHandle": "right",
        "target": target,
        "targetHandle": "left",
        "selected": False,
    }


def generate_cad_graph(
    report: ReportData,
    mappings: Dict[str, List[D3Mapping]],
    *,
    title: str,
    author: str,
    org: str,
    d3fend_version: str,
    source_html: Path,
) -> Dict:
    nodes: List[Dict] = []
    edges: List[Dict] = []

    # Nodo riassuntivo iniziale
    header_label = f"Operation: {report.operation or 'unknown'}"
    meta_node_id = "note-summary"
    summary_lines = [
        f"Session: {report.session or 'unknown'}",
        f"Generated: {report.generated or 'unknown'}",
        f"Wazuh observed: {', '.join(report.observed_wazuh_ids) if report.observed_wazuh_ids else 'none'}",
    ]
    nodes.append(make_node(meta_node_id, "note-node", header_label + "\n" + "\n".join(summary_lines), 40, 40))

    y = 180.0
    vertical_step = 180.0

    # Ordinamento stabile: prima ATT&CK IDs della tabella, poi eventuali residui.
    techniques_sorted = sorted(report.techniques, key=lambda t: t.attack_id)

    for index, tech in enumerate(techniques_sorted, start=1):
        row_y = y + (index - 1) * vertical_step
        attack_node_id = f"attack-{index}"
        label_parts = [tech.attack_id]
        if tech.technique_name:
            label_parts.append(tech.technique_name)
        if tech.tactic:
            label_parts.append(f"tactic: {tech.tactic}")
        attack_label = "\n".join(label_parts)

        # ATT&CK node: usiamo type attack-node. La classe D3FEND viene lasciata vuota se non certa.
        nodes.append(make_node(attack_node_id, "attack-node", attack_label, 80, row_y, seq=str(index)))
        edges.append(make_edge(f"e-summary-{index}", meta_node_id, attack_node_id, "documents"))

        report_note_id = f"report-note-{index}"
        report_note_lines = []
        if tech.report_mapping_text:
            report_note_lines.append(f"report mapping: {tech.report_mapping_text}")
        if tech.coverage:
            report_note_lines.append(f"coverage: {tech.coverage}")
        if tech.attack_id in report.observed_wazuh_ids:
            report_note_lines.append("observed by Wazuh")
        if not report_note_lines:
            report_note_lines.append("extracted from HTML report")
        nodes.append(make_node(report_note_id, "note-node", "\n".join(report_note_lines), 380, row_y))
        edges.append(make_edge(f"e-attack-note-{index}", attack_node_id, report_note_id, "reported"))

        official = mappings.get(tech.attack_id.upper(), [])
        if official:
            for j, mapping in enumerate(official, start=1):
                cm_id = f"cm-{index}-{j}"
                cm_label_lines = [mapping.d3_name]
                if mapping.d3_id:
                    cm_label_lines.append(mapping.d3_id)
                if mapping.relation:
                    cm_label_lines.append(f"relation: {mapping.relation}")
                d3f_class = mapping.d3_class or ""
                nodes.append(
                    make_node(
                        cm_id,
                        "countermeasure-node",
                        "\n".join(cm_label_lines),
                        720 + (j - 1) * 280,
                        row_y,
                        d3f_class=d3f_class,
                    )
                )
                edge_label = mapping.relation or "maps to"
                edges.append(make_edge(f"e-map-{index}-{j}", attack_node_id, cm_id, edge_label))
        else:
            no_map_id = f"nomap-{index}"
            nodes.append(
                make_node(
                    no_map_id,
                    "note-node",
                    "No official D3FEND mapping found via MITRE API",
                    720,
                    row_y,
                )
            )
            edges.append(make_edge(f"e-nomap-{index}", attack_node_id, no_map_id, "api lookup"))

    cad = {
        "meta": {
            "title": title,
            "authors": [author],
            "orgs": [org] if org else [],
            "description": (
                "CAD graph generated from an HTML attack report and enriched using the official "
                "MITRE D3FEND REST API inference mappings endpoint."
            ),
            "article": source_html.name,
            "d3fend_version": d3fend_version,
            "cad_schema_version": CAD_SCHEMA_VERSION,
            "published_date": now_iso(),
            "references": [
                str(source_html),
                D3FEND_INFERENCE_CSV,
                "https://d3fend.mitre.org/cad/docs/schema/",
                "https://d3fend.mitre.org/api-docs/",
            ],
            "settings": {},
        },
        "nodes": nodes,
        "edges": edges,
    }
    return cad


# -------------------------------
# Main
# -------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Converte un report HTML in un file D3FEND CAD JSON usando le API ufficiali MITRE.")
    p.add_argument("--input", required=True, help="Percorso del report HTML")
    p.add_argument("--output", required=True, help="Percorso del file CAD JSON di output")
    p.add_argument("--title", default="D3FEND CAD from HTML report", help="Titolo del grafo CAD")
    p.add_argument("--author", default="OpenAI", help="Autore da inserire nei metadati CAD")
    p.add_argument("--org", default="", help="Organizzazione da inserire nei metadati CAD")
    p.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout globale per le chiamate HTTP. Attualmente informativo; le singole richieste hanno timeout dedicati.",
    )
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    if not input_path.exists():
        print(f"[!] File input non trovato: {input_path}", file=sys.stderr)
        return 2

    report = parse_html_report(input_path)
    attack_ids = unique_preserve_order([t.attack_id for t in report.techniques] + report.observed_wazuh_ids)
    if not attack_ids:
        print("[!] Nessun ATT&CK ID trovato nel report HTML.", file=sys.stderr)
        return 3

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "d3fend-html-to-cad/1.0 (+local generation)",
            "Accept": "text/csv, application/json, */*",
        }
    )

    print(f"[*] ATT&CK IDs estratti: {', '.join(attack_ids)}")
    print(f"[*] Download mappings ufficiali da: {D3FEND_INFERENCE_CSV}")

    try:
        d3fend_version = fetch_d3fend_version(session)
        mappings = build_official_mappings(session, attack_ids)
    except requests.HTTPError as exc:
        print(f"[!] Errore HTTP verso MITRE D3FEND API: {exc}", file=sys.stderr)
        return 4
    except requests.RequestException as exc:
        print(f"[!] Errore di rete verso MITRE D3FEND API: {exc}", file=sys.stderr)
        return 5
    except Exception as exc:
        print(f"[!] Errore inatteso nella costruzione delle mappings: {exc}", file=sys.stderr)
        return 6

    cad = generate_cad_graph(
        report,
        mappings,
        title=args.title,
        author=args.author,
        org=args.org,
        d3fend_version=d3fend_version,
        source_html=input_path,
    )

    output_path.write_text(json.dumps(cad, indent=2, ensure_ascii=False), encoding="utf-8")

    mapped_total = sum(len(v) for v in mappings.values())
    print(f"[+] File CAD creato: {output_path}")
    print(f"[+] Versione D3FEND rilevata: {d3fend_version}")
    print(f"[+] Mappature ufficiali trovate: {mapped_total}")
    print("[+] Apri D3FEND CAD e usa: File -> Load")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
