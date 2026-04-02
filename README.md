# CNP
CNP CHIAVARI 23-03 / 03-04 2026
1. Obiettivo del progetto
Il progetto CNP nasce con l’obiettivo di realizzare un ambiente di laboratorio capace di mettere in dialogo emulazione offensiva, monitoraggio difensivo e mappatura delle contromisure. La linea tecnologica adottata ha ruotato attorno a MITRE Caldera per la simulazione dell’attacco, Wazuh per il rilevamento e la telemetria, MITRE ATT&CK per la classificazione delle tecniche e MITRE D3FEND per la strutturazione della risposta difensiva.
2. Metodo di lavoro
Le attività sono state condotte in modo incrementale. Ogni fase ha richiesto verifiche puntuali, debugging degli script Python, validazione delle integrazioni e revisione della reportistica. Dal punto di vista metodologico, il progetto ha seguito una sequenza ricorsiva: predisposizione del laboratorio, esecuzione dell’attacco simulato, osservazione degli eventi, lettura delle TTP, e modellazione della difesa.
3. Cronoprogramma commentato:

23/03/2026 09:00	Avvio del progetto CNP
[Impostazione perimetro]	Definizione del laboratorio Cyber Network Protection con approccio Red Team / Blue Team, scelta dei componenti principali e avvio della pianificazione operativa.	Avvio formale del progetto e definizione dell'architettura logica iniziale.

26/03/2026 12:00	Studio interfacce API
[Analisi tecnica Caldera]	Esame del funzionamento delle API REST di MITRE Caldera, della documentazione e delle modalità di autenticazione. Chiariti i concetti di endpoint, API key, import di adversary e gestione abilities.	Consolidata la base tecnica per l'orchestrazione automatica degli attacchi.

31/03/2026 08:00	Configurazione Wazuh
[Blue Team enablement]	Attivazione dei log lato Wazuh server, verifica archivi, controllo dell'indice e della visibilità degli eventi nella GUI.	Log presenti sul filesystem ma non correttamente esposti in Discovery.

31/03/2026 10:00	Regole Wazuh e log Sysmon
[Detection engineering]	Analisi di local_rules.xml, prove con wazuh-logtest, verifica del parsing JSON di eventi Sysmon e studio degli Event ID utili al rilevamento.	Individuata la necessità di regole custom per correlare le azioni Caldera.

31/03/2026 15:00	Automazione attacchi APT
[Scripting Python]	Sviluppo e debug dello script cyber_lab_orchestrator per eseguire attacchi simulati e generare report. Emersi problemi su build_reports e avvio delle decision/abilities.	Versione script in evoluzione verso la linea 6.x.

31/03/2026 20:00	Correlazione Caldera-Wazuh
[Obiettivo SOC]	Definizione dell'obiettivo operativo: ottenere alert Wazuh chiari quando Caldera esegue discovery, execution, privilege escalation e altre TTP sulla macchina Windows target.	Tracciata la roadmap di integrazione Red/Blue.

01/04/2026 10:00	Analisi script Caldera/Wazuh
[Versionamento]	Revisione dello script operativo, correzione errori di compatibilità, gestione forced seed adversary mode e verifica dei log lato Caldera.	Preparazione della linea applicativa 6.4.

01/04/2026 11:00	Import APT e adversary
[Threat emulation]	Valutazione dell'importazione di APT da MITRE, studio del dataset e verifica del caricamento delle abilities in Caldera.	Confermato il percorso per caricare APT29 tramite script Python.

01/04/2026 14:00	Versione 6.4 script [PROJECT FULL]
[Sviluppo]	Produzione delle revisioni 6.4, 6.4.1, 6.4.2 e 6.4.3 dello script per automatizzare attacco, monitoraggio e reporting.	Ottenuta una base di lavoro coerente, ma con criticità residue su ordine di esecuzione abilities e reportistica.

01/04/2026 19:21	Versione 6_4_3
[Debug finale di giornata]	Analisi della necessità di una versione 6_4_3 dello script per stabilizzare l'esecuzione delle abilities e migliorare la catena di attacco simulato.	Versione 6_4_3 identificata come riferimento operativo provvisorio.

02/04/2026 08:53	Report HTML ATT&CK / D3FEND
[Reporting]	Richiesta di estensione dello script per esportare report HTML dell'attacco con mappatura MITRE ATT&CK e predisposizione di output utile per la difesa D3FEND.	Definita la doppia direttrice offensiva/difensiva del progetto.

02/04/2026 09:31	Analisi tecniche fallite
[Troubleshooting Windows]	Rilevato errore PowerShell su Start-Process e -ArgumentList durante l'avvio di componenti ausiliari sul target o sistemi di supporto.	Correzione necessaria per la catena di esecuzione locale.

02/04/2026 11:01	Configurazione D3FEND con MITRE
[Difesa strutturata]	Analisi del report d'attacco e progettazione di uno script Python capace di leggere l'HTML del report, interrogare i riferimenti ufficiali MITRE D3FEND e generare un CAD difensivo.	Impostato il ponte tecnico tra TTP osservate e contromisure D3FEND.

02/04/2026 11:45	Monitor perenne Wazuh
[Live monitoring]	Evoluzione del monitor Python Wazuh verso modalità persistente con report HTML aggiornato in tempo reale, utilizzabile in ottica difensiva continua.	Attivata la visione quasi-SOC del laboratorio con report live.

02/04/2026 12:00	Scenario consolidato
[Recap operativo]	Attivato attacco simulato con Caldera tramite APT29 caricata via script Python; esportato report con TTP dell'attacco. Lato difesa, ricevuti eventi nel monitor Wazuh Python con report live, analizzate TTP MITRE e avviata la creazione del CAD di difesa in D3FEND mediante script Python dedicato.	Chiusura del ciclo iniziale Attack -> Detect -> Analyze -> Defend.

4. Valore tecnico del ciclo APT29 → Wazuh → D3FEND
Il momento di maturazione del progetto coincide con l’attivazione di un attacco simulato tramite APT29 in Caldera, caricata e resa operativa mediante script Python. L’esportazione del report con le TTP ha permesso di fissare in forma leggibile il comportamento offensivo; in parallelo, il monitor Wazuh sviluppato in Python ha ricevuto e organizzato gli eventi in tempo quasi reale, producendo report HTML aggiornati durante l’azione. Su questa base, le tecniche osservate sono state ricondotte al lessico MITRE ATT&CK e utilizzate come punto di partenza per la costruzione di un CAD difensivo in D3FEND, anch’esso assistito da script Python.
5. Risultati conseguiti
    • strutturazione del laboratorio come catena coerente di attacco, rilevamento e difesa;
    • versionamento progressivo degli script di orchestrazione e monitoraggio;
    • abilitazione della reportistica live come supporto decisionale;
    • avvio dell’integrazione concettuale tra ATT&CK e D3FEND.

   Criticità residue e sviluppi futuri:
   Permangono margini di miglioramento nella stabilità di alcune abilities, nell’ordine di esecuzione degli attacchi, nella robustezza del parsing lato monitor e nella piena automazione della generazione del CAD difensivo. Tuttavia, l’ossatura del progetto è ormai definita: non un semplice laboratorio di test, ma un banco di prova per una difesa capace di leggere il nemico mentre si muove.
Permangono margini di miglioramento nella stabilità di alcune abilities, nell’ordine di esecuzione degli attacchi, nella robustezza del parsing lato monitor e nella piena automazione della generazione del CAD difensivo. Tuttavia, l’ossatura del progetto è ormai definita: non un semplice laboratorio di test, ma un banco di prova per una difesa capace di leggere il nemico mentre si muove.

