# Cyber Lab Orchestrator v6

## Obiettivo
Questa versione è pensata per il laboratorio blue team:
- preferisce ability Windows che generano più facilmente telemetria utile in Sysmon/Wazuh
- evita profili troppo "silenziosi"
- mostra statistiche di link eseguiti in Caldera
- mantiene report globali e per IP sorgente

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

## Come ragiona la v6
- sceglie prima l'agent
- misura la compatibilità reale con l'adversary
- calcola un `noisy_score` per le ability Windows
- se serve, costruisce un adversary temporaneo con sole ability compatibili e "rumorose"

## Esempi di ability favorite
La v6 tende a privilegiare comandi come:
- whoami
- wmic
- nltest
- gpresult
- Get-Process / gwmi
- Get-SmbShare
- nslookup
- ipconfig
- tasklist
- net user / net group
- reg query

## File utili
- `selector_info.json`
- `compatibility_report.json`
- `operation_info.json`
- `operation_info_final.json`
- `final_operation_status.json`
- `captured_alerts_all.json`

## Nota pratica
Se vuoi una selezione più ampia, imposta:
```yml
runtime:
  noisy_only_mode: false
```
