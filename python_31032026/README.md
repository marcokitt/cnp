# Cyber Lab Orchestrator

## Scopo
Questo script è pensato per un laboratorio autorizzato con:
- MITRE Caldera su Ubuntu
- Wazuh come SIEM / manager
- Windows 10 con Sysmon e Wazuh agent
- T-Pot come honeypot opzionale

## Cosa fa
1. Seleziona un adversary di Caldera
2. Avvia una operation
3. Effettua un monitoraggio live via SSH del file `alerts.json` di Wazuh
4. Estrae eventuali ATT&CK ID dai log
5. Mappa gli ATT&CK ID verso tecniche MITRE D3FEND
6. Genera `report.html` e `captured_alerts.json`

## Installazione
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests paramiko pyyaml
cp config.example.yml config.yml
```

## Avvio
```bash
python3 cyber_lab_orchestrator.py -c config.yml
```

## Prima di eseguirlo davvero
- Inserisci un `adversary_id` reale di Caldera nel file `config.yml`
- Verifica l'accesso SSH al server Wazuh
- Verifica che il file `/var/ossec/logs/alerts/alerts.json` venga aggiornato
- Esegui solo in ambiente di test autorizzato

## Come ricavare gli adversary_id
Con API legacy:
```bash
curl -H "KEY:ADMIN123" \
  -H "Content-Type: application/json" \
  -d '{"index":"adversaries"}' \
  http://192.168.30.45:8888/api/rest
```

## Dove guardare in Wazuh
- Alert: `/var/ossec/logs/alerts/alerts.json`
- Archivi completi: `/var/ossec/logs/archives/archives.json`

## Migliorie possibili
- Recupero automatico dell'agent PAW
- Selezione casuale o pesata delle TTP consentite
- Correlazione T-Pot -> Wazuh
- Esportazione PDF del report via wkhtmltopdf / WeasyPrint
- Arricchimento con MITRE Navigator layer
