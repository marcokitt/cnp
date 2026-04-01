#!/usr/bin/env python3
"""
Legge un export JSON di MITRE ATT&CK e genera un report CSV
con i mapping D3FEND ufficiali trovati tramite il CSV pubblico MITRE D3FEND.

Uso:
    python attack_to_d3fend_mapper.py --input enterprise-attack.json --output report_d3fend.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import requests


D3FEND_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"

ATTACK_ID_RE = re.compile(r"^T\\d{4}(?:\\.\\d{3})?$")


def load_attack_json(path: Path) -> dict:
    """Carica il file JSON ATT&CK esportato."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_attack_techniques(bundle: dict) -> Dict[str, str]:
    """
    Estrae un dizionario {attack_id: nome_tecnica} dal bundle JSON ATT&CK/STIX.
    Cerca soprattutto gli oggetti di tipo attack-pattern con external_id ATT&CK.
    """
    techniques: Dict[str, str] = {}

    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        return techniques

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name", "").strip()

        for ref in obj.get("external_references", []):
            if not isinstance(ref, dict):
                continue

            external_id = ref.get("external_id", "")
            source_name = ref.get("source_name", "")

            # In ATT&CK/STIX i technique IDs stanno di solito qui
            if source_name.startswith("mitre-attack") and ATTACK_ID_RE.match(external_id):
                techniques[external_id] = name or "N/A"

    return techniques


def find_attack_ids_fallback(bundle: dict) -> Set[str]:
    """
    Fallback bruto ma efficace:
    se il file non è STIX standard, cerca comunque tutte le occorrenze Txxxx / Txxxx.xxx.
    """
    text = json.dumps(bundle, ensure_ascii=False)
    return set(re.findall(r"T\\d{4}(?:\\.\\d{3})?", text))


def download_d3fend_mappings() -> str:
    """Scarica il CSV ufficiale D3FEND con le inferenze di mapping."""
    response = requests.get(D3FEND_MAPPINGS_URL, timeout=30)
    response.raise_for_status()
    return response.text


def parse_d3fend_csv(csv_text: str) -> List[dict]:
    """
    Converte il CSV in lista di dizionari.
    Il formato può evolvere nel tempo, quindi usiamo DictReader e accesso flessibile alle colonne.
    """
    rows: List[dict] = []
    reader = csv.DictReader(csv_text.splitlines())
    for row in reader:
        rows.append(row)
    return rows


def row_contains_attack_id(row: dict, attack_id: str) -> bool:
    """Verifica se una riga del CSV contiene una specifica tecnica ATT&CK."""
    for value in row.values():
        if isinstance(value, str) and attack_id in value:
            return True
    return False


def best_effort_extract_fields(row: dict) -> Tuple[str, str, str, str]:
    """
    Estrae in modo tollerante i campi più utili.
    Siccome il CSV D3FEND può cambiare, proviamo più nomi di colonna.
    """
    possible_d3fend_fields = [
        "def_tactic_label",
        "def_tech_label",
        "def_technique_label",
        "defensive_technique",
        "subject",
        "object",
    ]
    possible_relation_fields = [
        "relation",
        "predicate",
    ]
    possible_artifact_fields = [
        "artifact_label",
        "off_artifact_label",
        "digital_artifact",
        "artifact",
    ]
    possible_attack_name_fields = [
        "off_tech_label",
        "offensive_technique",
        "attack_technique",
        "object_label",
        "subject_label",
    ]

    d3fend_value = first_nonempty(row, possible_d3fend_fields)
    relation_value = first_nonempty(row, possible_relation_fields)
    artifact_value = first_nonempty(row, possible_artifact_fields)
    attack_name_value = first_nonempty(row, possible_attack_name_fields)

    return attack_name_value, d3fend_value, relation_value, artifact_value


def first_nonempty(row: dict, keys: List[str]) -> str:
    """Restituisce il primo valore non vuoto tra più chiavi candidate."""
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def build_report(attack_techniques: Dict[str, str], d3_rows: List[dict]) -> List[dict]:
    """Costruisce il report finale correlando ATT&CK e D3FEND."""
    results: List[dict] = []

    for attack_id, attack_name in sorted(attack_techniques.items()):
        matches = [row for row in d3_rows if row_contains_attack_id(row, attack_id)]

        if not matches:
            results.append({
                "attack_id": attack_id,
                "attack_name": attack_name,
                "d3fend_attack_label": "",
                "d3fend_technique": "",
                "relation": "",
                "artifact_or_context": "",
                "status": "no_mapping_found"
            })
            continue

        for row in matches:
            mapped_attack_name, d3fend_technique, relation, artifact = best_effort_extract_fields(row)
            results.append({
                "attack_id": attack_id,
                "attack_name": attack_name,
                "d3fend_attack_label": mapped_attack_name,
                "d3fend_technique": d3fend_technique,
                "relation": relation,
                "artifact_or_context": artifact,
                "status": "mapped"
            })

    return results


def save_csv(rows: List[dict], output_path: Path) -> None:
    """Salva il report in CSV."""
    fieldnames = [
        "attack_id",
        "attack_name",
        "d3fend_attack_label",
        "d3fend_technique",
        "relation",
        "artifact_or_context",
        "status",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Mappa ATT&CK JSON verso D3FEND")
    parser.add_argument("--input", required=True, help="Percorso del file JSON ATT&CK esportato")
    parser.add_argument("--output", default="report_d3fend.csv", help="CSV di output")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERRORE] File non trovato: {input_path}", file=sys.stderr)
        return 1

    bundle = load_attack_json(input_path)

    attack_techniques = extract_attack_techniques(bundle)

    # fallback se il file non è un bundle STIX pulito
    if not attack_techniques:
        fallback_ids = sorted(find_attack_ids_fallback(bundle))
        attack_techniques = {tid: "N/A" for tid in fallback_ids}

    if not attack_techniques:
        print("[ERRORE] Nessuna tecnica ATT&CK trovata nel file.", file=sys.stderr)
        return 2

    try:
        d3_csv = download_d3fend_mappings()
    except requests.RequestException as exc:
        print(f"[ERRORE] Impossibile scaricare il mapping D3FEND: {exc}", file=sys.stderr)
        return 3

    d3_rows = parse_d3fend_csv(d3_csv)
    report_rows = build_report(attack_techniques, d3_rows)
    save_csv(report_rows, output_path)

    print(f"[OK] Tecniche ATT&CK trovate: {len(attack_techniques)}")
    print(f"[OK] Report generato: {output_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())