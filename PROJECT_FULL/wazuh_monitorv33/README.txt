Wazuh SSH Live Monitor v3.3

Novità principali:
- monitor live via SSH
- tabella terminale con MITRE ATT&CK e Src IP
- export CSV e JSONL
- report HTML aggiornato in tempo reale con logica append prima del marker finale
- il report HTML si auto-aggiorna ogni N secondi

Avvio:
1) pip install -r requirements.txt
2) modifica config.yaml
3) python wazuh_ssh_live_monitor_v33.py

Output generati:
- wazuh_live_export.csv
- wazuh_live_export.jsonl
- wazuh_live_report.html

Nota:
Per usare archives.json devi avere logall_json attivo sul manager Wazuh.
