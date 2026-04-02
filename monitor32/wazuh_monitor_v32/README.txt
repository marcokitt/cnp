Wazuh SSH Live Monitor v3.2

Novità:
- Colonna Src IP per mostrare l'IP sorgente / attaccante quando presente nel JSON.
- Colonne MITRE ATT&CK (ID, tactic, technique) se Wazuh le fornisce nel campo rule.mitre.
- Fallback regex per intercettare gli ID MITRE nel testo dell'evento.
- Export CSV e JSONL arricchiti con campi MITRE e IP.
- Errore più chiaro se key_file punta a una cartella invece che a una chiave privata.

Avvio:
  pip install -r requirements.txt
  python wazuh_ssh_live_monitor_v32.py

Configurazione chiave SSH:
  key_file deve puntare al file della chiave privata, ad esempio:
  C:/Users/shc-user/.ssh/id_rsa

Note pratiche:
- Per vedere tutti gli eventi usa source: archives e abilita logall_json sul manager Wazuh.
- Gli IP sorgente dipendono da come il decoder Wazuh estrae i campi dell'evento.
- I dati MITRE compaiono quando la regola Wazuh include il blocco rule.mitre.
