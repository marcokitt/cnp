APT to CALDERA - guida rapida
=============================

1) Installa le dipendenze:
   pip install pyyaml requests stix2 taxii2-client

2) Esecuzione base:
   python3 apt_to_caldera.py --apt "APTXXX"

3) Con stub abilities per le tecniche non coperte:
   python3 apt_to_caldera.py --apt "nome conosciuto APT" --generate-stubs

4) Con path espliciti:
   python3 apt_to_caldera.py \
     --apt "APT41" \
     --platform Windows \
     --abilities-dir "/opt/caldera/plugins/stockpile/data/abilities" \
     --adversaries-dir "/opt/caldera/data/adversaries" \
     --reports-dir "/opt/caldera/data/reports" \
     --stubs-dir "/opt/caldera/data/abilities_auto" \
     --generate-stubs \
     --debug

Output attesi:
- adversary YAML in data/adversaries
- report YAML in data/reports
- eventuali stub abilities in data/abilities_auto

Nota pratica:
Se CALDERA non vede subito il nuovo adversary profile, verifica il refresh delle abilities/adversaries o riavvia il servizio.

VERIFICA PERCORSI CALDERA
