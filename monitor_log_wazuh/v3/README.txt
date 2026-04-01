WAZUH SSH LIVE MONITOR V3
=========================

File inclusi:
- wazuh_ssh_live_monitor_v3.py
- config.yaml
- requirements.txt

Installazione:
1) pip install -r requirements.txt
2) modifica config.yaml con host, utente e chiave/password SSH
3) avvia: python wazuh_ssh_live_monitor_v3.py

Avvio con config custom:
python wazuh_ssh_live_monitor_v3.py config.yaml

Funzioni principali:
- Lettura live via SSH di alerts.json / archives.json / percorso custom
- Riconnessione automatica
- Tabella principale + tabella eventi sospetti
- Colonna MITRE tattica inferita
- Colonna Sysmon Event ID / nome quando riconosciuto
- Rilevazione indicatori Caldera
- Export CSV + JSONL
