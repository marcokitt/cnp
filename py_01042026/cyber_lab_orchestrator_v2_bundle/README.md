# Cyber Lab Orchestrator v2

## Cosa migliora rispetto alla versione precedente
- Monitoraggio più lungo: `monitor_seconds + extra_monitor_seconds`
- Possibilità di avviare il monitor in una finestra PowerShell separata su Windows
- Sessione salvata in una cartella dedicata per ogni operation
- Separazione automatica dei log per IP sorgente inferito
- Report globale + report distinti per IP sorgente
- Summary JSON per ogni IP con first seen, last seen, count e ATT&CK IDs

## Installazione
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install requests paramiko pyyaml
copy config.example.yml config.yml
```

## Avvio normale
```powershell
python cyber_lab_orchestrator.py -c config.yml
```

Se `launch_monitor_window: true` e stai eseguendo su Windows, lo script:
1. avvia la operation su Caldera
2. apre una nuova finestra PowerShell
3. monitora Wazuh nella finestra separata
4. salva i risultati nella cartella della sessione

## Avvio solo monitor
```powershell
python cyber_lab_orchestrator.py -c config.yml --monitor-only --session-dir output\manual_test --monitor-seconds 900
```

## Struttura output
```text
output/
  apt-sim-20260401-120000_20260401_120001/
    operation_info.json
    captured_alerts_all.json
    report.html
    by_source_ip/
      index.html
      192.168.30.45/
        alerts.json
        summary.json
        report.html
      unknown/
        alerts.json
        summary.json
        report.html
```

## Nota pratica
Per il tuo laboratorio ha senso impostare in `preferred_source_ips` l'IP di Caldera (`192.168.30.45`), così quando il log contiene più IP lo script tende a classificare l'origine dell'attacco in modo coerente.
