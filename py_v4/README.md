# Cyber Lab Orchestrator v4

## Cosa cambia davvero
- controlla prima la compatibilità tra adversary e agent
- forza esplicitamente l'operation in stato `running`
- mostra una schermata unica con:
  - barra di avanzamento
  - stato operation Caldera
  - compatibilità ability/agent
  - tabella live Wazuh
- salva:
  - `compatibility_report.json`
  - `final_operation_status.json`
  - `operation_info_final.json`

## Installazione
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install requests paramiko pyyaml
copy config.example.yml config.yml
```

## Elenco rapido da Caldera
```powershell
python cyber_lab_orchestrator.py -c config.yml --list-caldera
```

## Avvio guidato
```powershell
python cyber_lab_orchestrator.py -c config.yml --select
```

## Cosa risolve
Se prima l'operation veniva creata ma non eseguiva nulla, spesso il problema era uno di questi:
- agent group non coerente
- zero abilities compatibili con la piattaforma/executor dell'agent
- operation non realmente passata a `running`

Questa versione controlla i primi due punti e prova a correggere il terzo.

## File utili da controllare
- `selector_info.json`
- `compatibility_report.json`
- `operation_info.json`
- `final_operation_status.json`
- `captured_alerts_all.json`

## Lettura rapida della compatibilità
Se `compatible_count = 0`, l'operation può esistere ma non produrre link eseguibili.
