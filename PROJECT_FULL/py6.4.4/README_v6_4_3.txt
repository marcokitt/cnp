CALDERA orchestrator v6.4.3 - ricostruzione operativa

File inclusi:
- cyber_lab_orchestrator_v6_4_3.py
- config_v6_4_3.yaml

Note chiave implementate:
1) API mode auto: prova /api/v2 e usa fallback legacy.
2) autonomous inviato come intero (1/0), evitando il bug 422.
3) Decision count reale = links + potential-links.
4) Dump artifact sessione:
   - caldera_links.json
   - caldera_potential_links.json
   - caldera_report.json
   - caldera_event_logs.json
   - caldera_poll_history.json
   - selected_abilities_debug.json
   - temp_adversary_used.json
   - operation_info.json
   - operation_diagnostics.json
   - debug_caldera.ndjson
5) Diagnosi finale automatica:
   - CALDERA OK
   - planner sterile / adversary non compatibile
   - possible UI counter bug / telemetry assente

Esempi:
python cyber_lab_orchestrator_v6_4_3.py --config config_v6_4_3.yaml inventory
python cyber_lab_orchestrator_v6_4_3.py --config config_v6_4_3.yaml run

Nota onesta:
questa versione è stata ricostruita sulla base delle informazioni disponibili in memoria di lavoro; il link share della chat non era leggibile integralmente dallo strumento web in questa sessione.
