# Cyber Lab Orchestrator v6.2

## Obiettivo
Questa versione è costruita per sbloccare davvero le decisions del planner batch:
- usa preferibilmente ability Windows "seed" senza requirements
- scarta ability con placeholder `#{...}` non risolti
- preferisce comandi "rumorosi" per Sysmon/Wazuh
- costruisce, se possibile, un adversary temporaneo seed-only

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

## Cosa cambia rispetto alla v6.1
- `seed_only_mode: true` di default
- filtra via ability con:
  - requirements
  - placeholder non risolti
  - comandi Windows vuoti
- barra decisions basata sui link reali creati/completati dal planner batch

## Modalità più permissiva
Se vuoi allargare la selezione:
```yml
runtime:
  noisy_only_mode: false
  seed_only_mode: false
```
