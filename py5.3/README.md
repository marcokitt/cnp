# Cyber Lab Orchestrator v5

## Cosa cambia
- legge prima l'agent e poi classifica gli adversary in base alla compatibilità reale
- corregge adversary malformati dove `atomic_ordering` o `phases` contengono oggetti ability completi invece dei soli ID
- se possibile costruisce un adversary temporaneo Windows-only con le ability compatibili
- continua a forzare l'operation in `running`
- mantiene barra di avanzamento, stato Caldera e tabella live Wazuh

## Installazione
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install requests paramiko pyyaml
copy config.example.yml config.yml
```

## Elenco adversary classificati per agent
```powershell
python cyber_lab_orchestrator.py -c config.yml --list-caldera --select
```

## Avvio guidato
```powershell
python cyber_lab_orchestrator.py -c config.yml --select
```

## Cosa fa quando trova adversary malformati
Se l'adversary contiene oggetti completi invece di semplici ID:
- estrae `ability_id`
- prova a recuperare la ability live da Caldera
- se non la trova, usa l'oggetto embedded come fallback
- converte gli `executors` embedded nel formato `platforms` standard
- ricontrolla la compatibilità con l'agent

## File utili
- `selector_info.json`
- `compatibility_report.json`
- `operation_info.json`
- `operation_info_final.json`
- `final_operation_status.json`
- `captured_alerts_all.json`

## Nota pratica
Se vedi `fixed_embedded_count > 0`, vuol dire che la v5 ha riparato ability embedded provenienti da adversary malformati.


## Fix v5.1
- risolve il crash quando Caldera restituisce `operation.id` in formato UUID/stringa invece che numerico
- fallback robusto per la selezione dell'operation appena creata


## Fix v5.2
- il monitor separato ora legge `operation_info.json`, `compatibility_report.json` e `selector_info.json` dalla cartella sessione
- in modalità `--monitor-only` continua a interrogare Caldera se l'operation ha già un ID
- il matching dei log Wazuh non usa solo `target_ip`, ma anche host, paw, username e host_ip_addrs dell'agent selezionato
- `final_operation_status.json` non resta più con `op_id: null` quando l'operation era già stata creata


## Fix v5.3
- rimosso il cast `int()` su `operation_info["id"]` anche nel ramo `--monitor-only`
- `OperationPoller` ora accetta anche operation ID UUID/stringa
- connessione SSH Paramiko più stabile con `allow_agent: false` e `look_for_keys: false` quando usi password
- gli errori del monitor vengono riportati a schermo in modo pulito invece di interrompere con stack trace confuso
