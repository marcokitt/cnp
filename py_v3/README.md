# Cyber Lab Orchestrator v3

## Novità principali
- selettore interattivo per adversary e agent recuperati da Caldera
- comando `--list-caldera` per vedere subito adversaries e agents disponibili
- scelta del gruppo operativo in base all'agent selezionato
- monitor Wazuh in **visualizzazione tabellare real time**
- report globale + report per IP sorgente

## Installazione
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install requests paramiko pyyaml
copy config.example.yml config.yml
```

## 1) Elencare adversaries e agents da Caldera
```powershell
python cyber_lab_orchestrator.py -c config.yml --list-caldera
```

## 2) Avvio con selezione interattiva
```powershell
python cyber_lab_orchestrator.py -c config.yml --select
```

## 3) Avvio senza selezione
Se in `config.yml` imposti `caldera.adversary_ids` e `caldera.target_agent_paw`, lo script userà quelli.
```powershell
python cyber_lab_orchestrator.py -c config.yml
```

## 4) Solo monitor Wazuh
```powershell
python cyber_lab_orchestrator.py -c config.yml --monitor-only --session-dir output\manual_test --monitor-seconds 900
```

## Perché ora gli attacchi si vedono meglio
Prima bastava indicare un `adversary_id`, ma se il gruppo scelto non corrispondeva a un agent attivo, l'operation partiva male o restava vuota.
Ora lo script:
- legge gli agent attivi da Caldera
- ti fa scegliere l'agent
- usa il **group** dell'agent per creare l'operation
- salva in `selector_info.json` cosa è stato scelto

## Tabella live Wazuh
La schermata mostra:
- timestamp
- IP sorgente inferito
- agente Wazuh
- severity
- ATT&CK IDs
- descrizione alert

Così si legge al volo, senza annegare nel JSON.
