# Cyber Lab Orchestrator v6.4

## Obiettivo
Questa versione forza davvero il comportamento seed del planner batch:
- usa solo ability Windows seed-ready
- scarta ability con requirements
- scarta ability con placeholder `#{...}` non risolti
- usa un adversary temporaneo minimo (default 5 ability)
- verifica che l'operation usi proprio quell'adversary

## Installazione
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install requests paramiko pyyaml
copy config.example.yml config.yml
```

## Avvio guidato
```powershell
python cyber_lab_orchestrator.py -c config.yml --select
```

## Parametri chiave
```yml
runtime:
  noisy_only_mode: true
  seed_only_mode: true
  force_seed_adversary: true
  strict_seed_limit: 5
```

## Cosa cambia rispetto alla v6.3
- non seleziona più 8 ability generiche: costruisce un profilo seed rigoroso
- massimo 5 ability seed-ready
- il run si ferma se il seed adversary non viene creato o non viene usato davvero nell'operation
- monitor con `seed_adversary_applied=true/false`

## File utili
- `selector_info.json`
- `compatibility_report.json`
- `operation_info.json`
- `operation_info_final.json`
- `final_operation_status.json`
