#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
apt_to_caldera.py

Scopo
-----
Dato il nome di un gruppo APT / intrusion set di MITRE ATT&CK,
questo script:

1) interroga il server TAXII ufficiale di MITRE ATT&CK;
2) recupera le tecniche Enterprise usate dal gruppo;
3) filtra le tecniche per piattaforma (es. Windows);
4) legge le abilities YAML già presenti in CALDERA;
5) cerca un match tra tecnica ATT&CK e ability CALDERA;
6) genera automaticamente:
   - un adversary profile YAML per CALDERA;
   - un report YAML con coperture e mancanze;
   - opzionalmente delle stub abilities per le tecniche non coperte.

Perché è utile
--------------
ATT&CK descrive il "cosa" (gruppi, tecniche, procedure osservate),
ma non fornisce direttamente i comandi pronti per CALDERA.
Questo script automatizza la parte di correlazione e composizione
iniziale del profilo avversario, lasciando all'analista il controllo
sulle abilities reali e sulle eventuali stub da completare.

Fonti ufficiali di riferimento
------------------------------
- MITRE ATT&CK TAXII 2.1: https://attack-taxii.mitre.org/api/v21/
- Enterprise ATT&CK collection ID:
  x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019
- CALDERA: abilities e adversary profile in YAML, con atomic_ordering.

Dipendenze
----------
    pip install pyyaml requests stix2 taxii2-client

Esempi d'uso
------------
    python3 apt_to_caldera.py --apt "APT41"
    python3 apt_to_caldera.py --apt "Blind Eagle" --platform Windows --generate-stubs
    python3 apt_to_caldera.py --apt "Lazarus Group" --debug

Nota importante
---------------
Questo script NON genera magie dal nulla. Se una tecnica ATT&CK non ha
nessuna ability corrispondente nel tuo CALDERA, può generare una stub
ability segnaposto, ma il comando reale andrà definito da te.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import yaml
from stix2 import Filter
from stix2 import MemoryStore
from stix2 import TAXIICollectionSource
from taxii2client.v21 import Collection


# ============================================================================
# COSTANTI DI CONFIGURAZIONE
# ============================================================================

# Endpoint TAXII 2.1 ufficiale ATT&CK.
# La documentazione ufficiale indica l'API root /api/v21 e la collection
# Enterprise riportata qui sotto.
ATTACK_COLLECTION_URL = (
    "https://attack-taxii.mitre.org/api/v21/collections/"
    "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/"
)

# Percorsi di default. Personalizzali con gli argomenti CLI se il tuo
# ambiente CALDERA usa path differenti.
DEFAULT_ABILITIES_DIR = "/opt/caldera/plugins/stockpile/data/abilities"
DEFAULT_ADVERSARIES_DIR = "/opt/caldera/data/adversaries"
DEFAULT_REPORTS_DIR = "/opt/caldera/data/reports"
DEFAULT_STUBS_DIR = "/opt/caldera/data/abilities_auto"

# Fallback ufficiale: bundle STIX 2.1 pubblicato da MITRE su GitHub.
# Questo approccio è consigliato quando il TAXII server risponde con 429.
ATTACK_BUNDLE_RAW_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/apt_to_caldera")

# Ordine tattiche ATT&CK: serve solo per produrre un adversary più leggibile.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


# ============================================================================
# DATACLASS DI APPOGGIO
# ============================================================================

@dataclass
class TechniqueRecord:
    """
    Rappresenta una tecnica ATT&CK già normalizzata per il nostro flusso.

    Attributi principali:
        attack_id:  ID esterno ATT&CK (es. T1087 o T1059.001)
        name:       Nome della tecnica
        tactics:    Lista di tattiche associate
        platforms:  Piattaforme ATT&CK supportate
        stix_id:    ID STIX interno della tecnica
        description:Descrizione, se disponibile
        is_subtechnique: True se è una sub-technique
    """
    attack_id: str
    name: str
    tactics: List[str]
    platforms: List[str]
    stix_id: str
    description: str = ""
    is_subtechnique: bool = False


@dataclass
class MatchRecord:
    """
    Rappresenta il legame trovato fra tecnica ATT&CK e ability CALDERA.
    """
    attack_id: str
    technique_name: str
    tactics: List[str]
    ability_id: str
    ability_name: str
    ability_tactic: str
    ability_source_file: str


# ============================================================================
# FUNZIONI UTILI GENERICHE
# ============================================================================


def dbg(enabled: bool, message: str) -> None:
    """Stampa un messaggio di debug solo se il flag è attivo."""
    if enabled:
        print(f"[DEBUG] {message}")



def ensure_dir(path: str) -> None:
    """Crea una directory se non esiste già."""
    Path(path).mkdir(parents=True, exist_ok=True)



def sanitize_filename(value: str) -> str:
    """
    Converte una stringa in una forma adatta a diventare nome file.

    Esempio:
        "Blind Eagle / Windows" -> "blind_eagle_windows"
    """
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value



def write_yaml(path: str, data: Any) -> None:
    """Serializza un oggetto Python in YAML."""
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)



def read_yaml(path: str) -> Optional[Any]:
    """Legge un file YAML e restituisce il contenuto Python."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception as exc:
        print(f"[!] Errore leggendo YAML {path}: {exc}")
        return None



def tactic_sort_key(tactic_name: str) -> int:
    """
    Restituisce la posizione della tattica nell'ordine ATT&CK scelto.
    Le tattiche non riconosciute finiscono in coda.
    """
    try:
        return TACTIC_ORDER.index(tactic_name)
    except ValueError:
        return 999



def remove_revoked_deprecated(objects: Iterable[Any]) -> List[Any]:
    """
    Filtra gli oggetti STIX eliminando quelli revocati o deprecati.

    Questo evita di costruire avversary profile con materiale vecchio,
    dismesso o non più consigliato.
    """
    filtered: List[Any] = []
    for obj in objects:
        if obj.get("revoked", False):
            continue
        if obj.get("x_mitre_deprecated", False):
            continue
        filtered.append(obj)
    return filtered



def extract_attack_id(stix_obj: Any) -> Optional[str]:
    """
    Estrae l'ID ATT&CK esterno dagli external_references.

    Esempi di output:
        T1087
        T1059.001
    """
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None



def get_tactics_from_technique(stix_obj: Any) -> List[str]:
    """
    Estrae le tattiche ATT&CK (kill chain phases) da una tecnica.
    """
    tactics: List[str] = []
    for phase in stix_obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            phase_name = phase.get("phase_name")
            if phase_name:
                tactics.append(phase_name)
    return tactics



def attack_platform_to_caldera(platform: str) -> str:
    """
    Traduce la piattaforma ATT&CK in nomenclatura CALDERA.

    ATT&CK   -> CALDERA
    Windows  -> windows
    Linux    -> linux
    macOS    -> darwin
    """
    normalized = platform.strip().lower()
    if normalized == "windows":
        return "windows"
    if normalized == "linux":
        return "linux"
    if normalized in {"macos", "mac os", "darwin"}:
        return "darwin"
    raise ValueError(f"Piattaforma ATT&CK non supportata: {platform}")



def executor_for_platform(caldera_platform: str) -> str:
    """
    Sceglie l'executor CALDERA più plausibile per la piattaforma.

    Nota: è una scelta ragionevole di default, non una legge divina.
    Puoi sempre modificarla nelle stub generate.
    """
    if caldera_platform == "windows":
        return "psh"
    return "sh"


# ============================================================================
# VERIFICHE DI RETE / CONNETTIVITÀ TAXII
# ============================================================================


def preflight_taxii_check(debug: bool = False) -> None:
    """
    Effettua un controllo veloce verso l'endpoint della collection TAXII.

    Non è strettamente indispensabile, ma permette di intercettare subito
    problemi di connettività, proxy o TLS prima di far partire il flusso.
    """
    dbg(debug, f"Preflight HTTP verso {ATTACK_COLLECTION_URL}")
    response = requests.get(
        ATTACK_COLLECTION_URL,
        headers={"Accept": "application/taxii+json;version=2.1"},
        timeout=20,
    )
    response.raise_for_status()
    dbg(debug, f"Preflight OK: HTTP {response.status_code}")


# ============================================================================
# ATT&CK / TAXII
# ============================================================================


def load_attack_source_from_bundle(bundle_path: str, debug: bool = False) -> MemoryStore:
    """
    Carica un bundle STIX 2.1 locale e costruisce una MemoryStore interrogabile.

    Il file deve essere un JSON STIX con chiave "objects".
    """
    dbg(debug, f"Caricamento bundle STIX locale: {bundle_path}")
    with open(bundle_path, "r", encoding="utf-8") as fh:
        bundle = requests.models.complexjson.load(fh)

    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    if not objects:
        raise ValueError(f"Bundle STIX non valido o vuoto: {bundle_path}")

    dbg(debug, f"Oggetti STIX caricati dal bundle: {len(objects)}")
    return MemoryStore(stix_data=objects)



def download_attack_bundle(cache_dir: str, debug: bool = False) -> str:
    """
    Scarica il bundle STIX Enterprise ufficiale MITRE in cache locale.

    Se il file è già presente in cache, lo riusa.
    """
    ensure_dir(cache_dir)
    bundle_path = os.path.join(cache_dir, "enterprise-attack.json")

    if os.path.isfile(bundle_path) and os.path.getsize(bundle_path) > 0:
        dbg(debug, f"Bundle STIX già presente in cache: {bundle_path}")
        return bundle_path

    dbg(debug, f"Download bundle STIX da GitHub: {ATTACK_BUNDLE_RAW_URL}")
    response = requests.get(ATTACK_BUNDLE_RAW_URL, timeout=60)
    response.raise_for_status()
    with open(bundle_path, "wb") as fh:
        fh.write(response.content)

    dbg(debug, f"Bundle STIX salvato in cache: {bundle_path}")
    return bundle_path



def get_attack_source(
    debug: bool = False,
    attack_bundle: Optional[str] = None,
    cache_dir: str = DEFAULT_CACHE_DIR,
):
    """
    Restituisce una sorgente interrogabile ATT&CK.

    Ordine di precedenza:
    1) se l'utente passa --attack-bundle, usa quello;
    2) prova il TAXII ufficiale;
    3) se TAXII fallisce o risponde 429, scarica/usa il bundle STIX locale.
    """
    if attack_bundle:
        return load_attack_source_from_bundle(attack_bundle, debug=debug)

    try:
        preflight_taxii_check(debug=debug)
        collection = Collection(ATTACK_COLLECTION_URL)
        dbg(debug, "Collection TAXII Enterprise inizializzata correttamente")
        return TAXIICollectionSource(collection)
    except Exception as exc:
        dbg(debug, f"TAXII non disponibile o limitato: {exc}")
        bundle_path = download_attack_bundle(cache_dir=cache_dir, debug=debug)
        return load_attack_source_from_bundle(bundle_path, debug=debug)



def get_group_by_alias_or_name(src: TAXIICollectionSource, apt_name: str, debug: bool = False) -> Optional[Any]:
    """
    Cerca un intrusion-set prima per nome esatto, poi per alias esatto.

    Esempi validi:
        APT41
        Blind Eagle
        Lazarus Group
    """
    dbg(debug, f"Ricerca intrusion-set per name='{apt_name}'")
    by_name = remove_revoked_deprecated(src.query([
        Filter("type", "=", "intrusion-set"),
        Filter("name", "=", apt_name),
    ]))
    if by_name:
        dbg(debug, f"Trovato per nome: {by_name[0].get('name')}")
        return by_name[0]

    dbg(debug, f"Ricerca intrusion-set per alias='{apt_name}'")
    by_alias = remove_revoked_deprecated(src.query([
        Filter("type", "=", "intrusion-set"),
        Filter("aliases", "=", apt_name),
    ]))
    if by_alias:
        dbg(debug, f"Trovato per alias: {by_alias[0].get('name')}")
        return by_alias[0]

    return None



def get_group_techniques(
    src: TAXIICollectionSource,
    group_obj: Any,
    platform_name: str,
    debug: bool = False,
) -> List[TechniqueRecord]:
    """
    Recupera le tecniche usate dal gruppo, filtrandole per piattaforma.

    Flusso:
    1) recupera tutte le relazioni STIX 'uses';
    2) tiene solo quelle in cui il gruppo è source_ref;
    3) tiene solo target_ref di tipo attack-pattern;
    4) recupera i dettagli completi delle tecniche;
    5) filtra revocate/deprecate e per piattaforma ATT&CK.
    """
    group_id = group_obj.id
    dbg(debug, f"Recupero relazioni 'uses' per group_id={group_id}")

    relationships = remove_revoked_deprecated(src.query([
        Filter("type", "=", "relationship"),
        Filter("relationship_type", "=", "uses"),
    ]))

    patterns = remove_revoked_deprecated(src.query([
        Filter("type", "=", "attack-pattern"),
    ]))

    pattern_map = {p.id: p for p in patterns}
    platform_name_norm = platform_name.strip().lower()

    selected: Dict[str, TechniqueRecord] = {}

    for rel in relationships:
        if rel.source_ref != group_id:
            continue
        if not str(rel.target_ref).startswith("attack-pattern--"):
            continue

        technique = pattern_map.get(rel.target_ref)
        if not technique:
            continue

        platforms = technique.get("x_mitre_platforms", [])
        if platform_name:
            normalized_platforms = [str(p).strip().lower() for p in platforms]
            if platform_name_norm not in normalized_platforms:
                continue

        attack_id = extract_attack_id(technique)
        if not attack_id:
            continue

        record = TechniqueRecord(
            attack_id=attack_id,
            name=technique.get("name", "Unknown Technique"),
            tactics=get_tactics_from_technique(technique),
            platforms=platforms,
            stix_id=technique.id,
            description=technique.get("description", ""),
            is_subtechnique=technique.get("x_mitre_is_subtechnique", False),
        )

        # Chiave ATT&CK: evita duplicati se la tecnica compare in più relazioni.
        selected[attack_id] = record

    results = list(selected.values())
    results.sort(key=lambda t: (
        tactic_sort_key(t.tactics[0] if t.tactics else ""),
        t.attack_id,
    ))

    dbg(debug, f"Tecniche selezionate per piattaforma {platform_name}: {len(results)}")
    return results


# ============================================================================
# LETTURA ABILITIES CALDERA LOCALI
# ============================================================================


def load_caldera_abilities(base_dir: str, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Legge ricorsivamente tutte le abilities YAML da una directory CALDERA.

    CALDERA può contenere:
    - file YAML con una lista di abilities;
    - file YAML con una sola ability come dict.

    Lo script gestisce entrambi i casi.
    """
    abilities: List[Dict[str, Any]] = []

    if not os.path.isdir(base_dir):
        raise FileNotFoundError(f"Directory abilities non trovata: {base_dir}")

    dbg(debug, f"Scansione abilities in: {base_dir}")

    for root, _, files in os.walk(base_dir):
        for filename in files:
            if not filename.endswith((".yml", ".yaml")):
                continue

            full_path = os.path.join(root, filename)
            data = read_yaml(full_path)
            if data is None:
                continue

            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        item["_source_file"] = full_path
                        abilities.append(item)
            elif isinstance(data, dict):
                data["_source_file"] = full_path
                abilities.append(data)

    dbg(debug, f"Abilities lette: {len(abilities)}")
    return abilities



def ability_technique_id(ability: Dict[str, Any]) -> Optional[str]:
    """
    Estrae l'ID tecnica ATT&CK da una ability CALDERA.

    Formati osservati più comuni:
    - ability['technique_id']
    - ability['technique']['attack_id']
    """
    if ability.get("technique_id"):
        return str(ability["technique_id"]).strip()

    technique = ability.get("technique")
    if isinstance(technique, dict) and technique.get("attack_id"):
        return str(technique["attack_id"]).strip()

    return None



def ability_supports_platform(ability: Dict[str, Any], caldera_platform: str) -> bool:
    """
    Verifica se la ability dichiara supporto per la piattaforma CALDERA.
    """
    platforms = ability.get("platforms", {})
    return isinstance(platforms, dict) and caldera_platform in platforms



def build_ability_index(
    abilities: List[Dict[str, Any]],
    caldera_platform: str,
    debug: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Costruisce un indice:
        technique_id -> lista di abilities compatibili con la piattaforma

    Questo rende il matching molto più rapido e pulito.
    """
    index: Dict[str, List[Dict[str, Any]]] = {}

    for ability in abilities:
        tech_id = ability_technique_id(ability)
        if not tech_id:
            continue
        if not ability_supports_platform(ability, caldera_platform):
            continue
        index.setdefault(tech_id, []).append(ability)

    dbg(debug, f"Indice tecniche->abilities costruito su {len(index)} technique_id")
    return index


# ============================================================================
# MATCH TECNICHE -> ABILITIES
# ============================================================================


def choose_best_ability(technique: TechniqueRecord, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sceglie la ability "migliore" fra i candidati.

    Logica adottata:
    1) preferire abilities con stessa tattica principale della tecnica;
    2) altrimenti scegliere in modo stabile per nome e id.

    Questa parte è volutamente semplice ma leggibile.
    Se vorrai, più avanti potrai raffinarla con:
    - preferenze manuali tramite technique_map.yml;
    - esclusioni di abilities rumorose;
    - priorità a parser/cleanup specifici.
    """
    technique_tactics = set(technique.tactics)

    same_tactic: List[Dict[str, Any]] = []
    for ability in candidates:
        ability_tactic = str(ability.get("tactic", "")).strip()
        if ability_tactic in technique_tactics:
            same_tactic.append(ability)

    pool = same_tactic if same_tactic else candidates
    pool = sorted(pool, key=lambda a: (
        str(a.get("name", "")).lower(),
        str(a.get("id", "")).lower(),
    ))
    return pool[0]



def match_techniques_to_abilities(
    techniques: List[TechniqueRecord],
    ability_index: Dict[str, List[Dict[str, Any]]],
    debug: bool = False,
) -> Tuple[List[MatchRecord], List[TechniqueRecord]]:
    """
    Esegue il match vero e proprio.

    Output:
    - matched: tecniche con ability selezionata
    - uncovered: tecniche senza nessuna ability compatibile
    """
    matched: List[MatchRecord] = []
    uncovered: List[TechniqueRecord] = []

    for tech in techniques:
        candidates = ability_index.get(tech.attack_id, [])
        if not candidates:
            uncovered.append(tech)
            continue

        chosen = choose_best_ability(tech, candidates)
        matched.append(MatchRecord(
            attack_id=tech.attack_id,
            technique_name=tech.name,
            tactics=tech.tactics,
            ability_id=str(chosen.get("id", "")),
            ability_name=str(chosen.get("name", "Unnamed ability")),
            ability_tactic=str(chosen.get("tactic", "")),
            ability_source_file=str(chosen.get("_source_file", "")),
        ))

    dbg(debug, f"Tecniche coperte: {len(matched)}")
    dbg(debug, f"Tecniche scoperte: {len(uncovered)}")
    return matched, uncovered


# ============================================================================
# GENERAZIONE ADVERSARY PROFILE
# ============================================================================


def build_adversary_data(apt_name: str, platform_label: str, matches: List[MatchRecord]) -> Dict[str, Any]:
    """
    Costruisce il contenuto YAML dell'adversary profile.

    CALDERA userà atomic_ordering per l'ordine di esecuzione quando
    impieghi un planner che rispetta la sequenza atomica.
    """
    return {
        "id": str(uuid.uuid4()),
        "name": f"{apt_name} Auto Profile {platform_label}",
        "description": (
            f"Adversary profile generato automaticamente da MITRE ATT&CK "
            f"per {apt_name} su piattaforma {platform_label}."
        ),
        "atomic_ordering": [m.ability_id for m in matches],
    }



def write_adversary_profile(output_dir: str, apt_name: str, platform_label: str, matches: List[MatchRecord]) -> str:
    """
    Scrive l'adversary profile YAML sul filesystem.
    """
    ensure_dir(output_dir)
    filename = f"{sanitize_filename(apt_name)}_{sanitize_filename(platform_label)}_auto_adversary.yml"
    out_path = os.path.join(output_dir, filename)
    write_yaml(out_path, build_adversary_data(apt_name, platform_label, matches))
    return out_path


# ============================================================================
# REPORT FINALE
# ============================================================================


def build_report_data(
    requested_apt: str,
    platform_label: str,
    group_obj: Any,
    techniques: List[TechniqueRecord],
    matches: List[MatchRecord],
    uncovered: List[TechniqueRecord],
) -> Dict[str, Any]:
    """
    Costruisce il report YAML finale.

    Il report serve sia per controllo visivo, sia come base per capire
    dove devi creare abilities mancanti.
    """
    return {
        "input": {
            "requested_apt": requested_apt,
            "platform": platform_label,
        },
        "group": {
            "name": group_obj.get("name", ""),
            "stix_id": getattr(group_obj, "id", ""),
            "aliases": group_obj.get("aliases", []),
        },
        "summary": {
            "total_techniques": len(techniques),
            "covered_techniques": len(matches),
            "uncovered_techniques": len(uncovered),
        },
        "covered": [
            {
                "attack_id": m.attack_id,
                "technique_name": m.technique_name,
                "tactics": m.tactics,
                "ability_id": m.ability_id,
                "ability_name": m.ability_name,
                "ability_tactic": m.ability_tactic,
                "ability_source_file": m.ability_source_file,
            }
            for m in matches
        ],
        "uncovered": [
            {
                "attack_id": t.attack_id,
                "technique_name": t.name,
                "tactics": t.tactics,
                "platforms": t.platforms,
                "stix_id": t.stix_id,
                "is_subtechnique": t.is_subtechnique,
            }
            for t in uncovered
        ],
    }



def write_report(output_dir: str, apt_name: str, platform_label: str, report_data: Dict[str, Any]) -> str:
    """
    Scrive il report YAML su disco.
    """
    ensure_dir(output_dir)
    filename = f"{sanitize_filename(apt_name)}_{sanitize_filename(platform_label)}_report.yml"
    out_path = os.path.join(output_dir, filename)
    write_yaml(out_path, report_data)
    return out_path


# ============================================================================
# GENERAZIONE STUB ABILITIES
# ============================================================================


def build_stub_ability(technique: TechniqueRecord, caldera_platform: str) -> Dict[str, Any]:
    """
    Costruisce una stub ability minima.

    La stub non pretende di essere pronta alla guerra: serve come base
    ordinata da completare, senza dover creare a mano tutta la struttura YAML.
    """
    executor = executor_for_platform(caldera_platform)
    command = (
        f'Write-Host "TODO: implementare ability per {technique.attack_id} - {technique.name}"'
        if caldera_platform == "windows"
        else f'echo "TODO: implementare ability per {technique.attack_id} - {technique.name}"'
    )

    return {
        "id": str(uuid.uuid4()),
        "name": f"Placeholder - {technique.name}",
        "description": (
            f"Ability placeholder auto-generata per {technique.attack_id} - "
            f"{technique.name}. Da completare manualmente."
        ),
        "tactic": technique.tactics[0] if technique.tactics else "discovery",
        "technique": {
            "attack_id": technique.attack_id,
            "name": technique.name,
        },
        "platforms": {
            caldera_platform: {
                executor: {
                    "command": command,
                    "timeout": 60,
                }
            }
        }
    }



def write_stub_abilities(
    output_dir: str,
    apt_name: str,
    platform_label: str,
    caldera_platform: str,
    uncovered: List[TechniqueRecord],
) -> List[str]:
    """
    Scrive una stub ability YAML per ogni tecnica non coperta.

    Un file per tecnica: è più comodo da versionare, correggere e ricaricare.
    """
    target_dir = os.path.join(
        output_dir,
        f"{sanitize_filename(apt_name)}_{sanitize_filename(platform_label)}",
    )
    ensure_dir(target_dir)

    created_files: List[str] = []

    for tech in uncovered:
        stub = build_stub_ability(tech, caldera_platform)
        filename = f"{sanitize_filename(tech.attack_id)}_{sanitize_filename(tech.name)}.yml"
        path = os.path.join(target_dir, filename)

        # Per coerenza con molti file CALDERA, scriviamo una lista YAML.
        write_yaml(path, [stub])
        created_files.append(path)

    return created_files


# ============================================================================
# ARGOMENTI CLI
# ============================================================================


def parse_args() -> argparse.Namespace:
    """Definisce e legge gli argomenti da linea di comando."""
    parser = argparse.ArgumentParser(
        description="Genera un adversary profile CALDERA a partire da un gruppo APT MITRE ATT&CK."
    )
    parser.add_argument("--apt", required=True, help='Nome o alias del gruppo, es. "APT41"')
    parser.add_argument("--platform", default="Windows", help='Piattaforma ATT&CK: Windows, Linux, macOS')
    parser.add_argument("--abilities-dir", default=DEFAULT_ABILITIES_DIR, help="Directory abilities CALDERA")
    parser.add_argument("--adversaries-dir", default=DEFAULT_ADVERSARIES_DIR, help="Directory output adversaries")
    parser.add_argument("--reports-dir", default=DEFAULT_REPORTS_DIR, help="Directory output report")
    parser.add_argument("--stubs-dir", default=DEFAULT_STUBS_DIR, help="Directory output stub abilities")
    parser.add_argument("--attack-bundle", default="", help="Percorso a un bundle STIX locale enterprise-attack.json")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="Directory cache per il bundle STIX scaricato")
    parser.add_argument("--generate-stubs", action="store_true", help="Genera stub abilities per tecniche scoperte")
    parser.add_argument("--debug", action="store_true", help="Abilita output di debug")
    return parser.parse_args()



# ============================================================================
# MAIN
# ============================================================================


def main() -> int:
    """
    Flusso principale dello script.

    Ordine delle operazioni:
    1) parse argomenti;
    2) mappa piattaforma ATT&CK -> CALDERA;
    3) connessione TAXII;
    4) ricerca gruppo APT;
    5) recupero tecniche del gruppo;
    6) lettura abilities locali da CALDERA;
    7) matching tecniche -> abilities;
    8) scrittura adversary YAML;
    9) scrittura report YAML;
    10) eventuale generazione stub.
    """
    args = parse_args()

    apt_name = args.apt.strip()
    attack_platform = args.platform.strip()

    try:
        caldera_platform = attack_platform_to_caldera(attack_platform)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1

    print(f"[+] Gruppo richiesto: {apt_name}")
    print(f"[+] Piattaforma ATT&CK: {attack_platform}")
    print(f"[+] Piattaforma CALDERA: {caldera_platform}")

    try:
        # 1) Connessione alla collection Enterprise ATT&CK.
        src = get_attack_source(debug=args.debug, attack_bundle=args.attack_bundle or None, cache_dir=args.cache_dir)

        # 2) Ricerca del gruppo.
        group_obj = get_group_by_alias_or_name(src, apt_name, debug=args.debug)
        if not group_obj:
            print(f"[!] Nessun gruppo ATT&CK trovato per: {apt_name}")
            return 1

        print(f"[+] Gruppo trovato: {group_obj.get('name')}")
        aliases = group_obj.get("aliases", [])
        if aliases:
            print(f"[+] Alias noti: {', '.join(aliases)}")

        # 3) Tecniche usate dal gruppo sulla piattaforma indicata.
        techniques = get_group_techniques(
            src=src,
            group_obj=group_obj,
            platform_name=attack_platform,
            debug=args.debug,
        )
        if not techniques:
            print(f"[!] Nessuna tecnica trovata per {apt_name} su {attack_platform}")
            return 1

        print(f"[+] Tecniche ATT&CK selezionate: {len(techniques)}")

        # 4) Caricamento abilities locali di CALDERA.
        abilities = load_caldera_abilities(args.abilities_dir, debug=args.debug)
        print(f"[+] Abilities CALDERA caricate: {len(abilities)}")

        # 5) Costruzione indice technique_id -> abilities.
        ability_index = build_ability_index(abilities, caldera_platform, debug=args.debug)

        # 6) Match tecniche/abilities.
        matches, uncovered = match_techniques_to_abilities(techniques, ability_index, debug=args.debug)
        print(f"[+] Tecniche coperte: {len(matches)}")
        print(f"[+] Tecniche non coperte: {len(uncovered)}")

        # 7) Scrittura adversary profile.
        adversary_path = write_adversary_profile(
            args.adversaries_dir,
            apt_name,
            attack_platform,
            matches,
        )
        print(f"[+] Adversary profile creato: {adversary_path}")

        # 8) Scrittura report dettagliato.
        report_data = build_report_data(
            requested_apt=apt_name,
            platform_label=attack_platform,
            group_obj=group_obj,
            techniques=techniques,
            matches=matches,
            uncovered=uncovered,
        )
        report_path = write_report(args.reports_dir, apt_name, attack_platform, report_data)
        print(f"[+] Report creato: {report_path}")

        # 9) Eventuale generazione delle stub abilities.
        if args.generate_stubs:
            if uncovered:
                stub_files = write_stub_abilities(
                    args.stubs_dir,
                    apt_name,
                    attack_platform,
                    caldera_platform,
                    uncovered,
                )
                print(f"[+] Stub abilities create: {len(stub_files)}")
            else:
                print("[+] Nessuna stub necessaria: tutte le tecniche sono coperte.")

        print("[+] Operazione completata.")
        return 0

    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente.")
        return 130
    except requests.HTTPError as exc:
        print(f"[!] Errore HTTP verso ATT&CK TAXII: {exc}")
        return 1
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        return 1
    except Exception as exc:
        print(f"[!] Errore fatale: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
