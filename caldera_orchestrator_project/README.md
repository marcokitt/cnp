# Caldera Orchestrator CLI

Piccolo progetto Python per **orchestrare operazioni Caldera via API REST** in un laboratorio autorizzato, con tre obiettivi molto semplici:

1. usare solo una **allowlist locale** di TTP coerenti con il profilo assegnato;
2. produrre un **operation log continuo e timestampato**;
3. generare un **report finale in PDF** leggibile per il debrief.

> Questo progetto non cerca di “sparare tutto”. È costruito per il contesto del tuo corso: profilo avversario, coerenza con Attack Flow, log difendibile e uso di un agente attivo sulla macchina target.

## Perché esiste

Nel PDF del corso si vede che:

- Caldera può essere usato tramite **API REST** oltre che da interfaccia web; 
- il corso incoraggia l’**automazione**, purché compresa e difendibile;
- ogni team deve mantenere un **operation log continuo e timestampato**;
- le TTP vanno eseguite in modo coerente con il profilo assegnato, altrimenti ci sono penalità;
- per operare davvero serve almeno un **agente Sandcat attivo** sulla VM target.

## Cosa fa lo script

Lo script:

- legge la configurazione da `config.example.yaml`;
- legge una lista locale di TTP da `sample_profile.json`;
- cerca un **agente Caldera attivo** associato al target;
- crea una **operazione Caldera** per ciascuna TTP selezionata;
- osserva lo stato dell’operazione per un tempo definito;
- salva i risultati in:
  - `JSONL`
  - `CSV`
  - `Markdown`
  - `PDF`

## Struttura del progetto

```text
caldera_orchestrator_project/
├─ main.py
├─ requirements.txt
├─ config.example.yaml
├─ sample_profile.json
├─ README.md
├─ logs/
├─ reports/
└─ caldera_orchestrator/
   ├─ __init__.py
   ├─ cli.py
   ├─ client.py
   ├─ config.py
   ├─ logging_utils.py
   ├─ reporting.py
   └─ runner.py
```

## Requisiti

- Python 3.10 o superiore
- una istanza Caldera raggiungibile
- API key valida
- almeno un agente attivo sulla target

## Installazione

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configurazione

Apri `config.example.yaml` e sostituisci almeno questi valori:

- `caldera.host`
- `caldera.port`
- `caldera.api_key`
- `operation_defaults.planner_id`
- `profile.adversary_id`
- `profile.target_name`
- opzionalmente `profile.target_agent_paw`

### Nota su `target_name` e `target_agent_paw`

Il programma prova prima a usare `target_agent_paw`, se lo hai compilato.
Se è vuoto, prova a trovare un agente attivo cercando `target_name` tra i campi più comuni dell’agente.

In parole povere:

- `target_agent_paw` = indirizzo esatto del soldatino
- `target_name` = modo più comodo ma meno preciso per trovarlo

## Allowlist TTP

Il file `sample_profile.json` contiene un esempio di TTP coerenti con un profilo avversario.

Esempio:

```json
{
  "profile_name": "APT29-lab-profile",
  "ttps": [
    {
      "attack_id": "T1059",
      "name": "Command and Scripting Interpreter",
      "phase": "execution",
      "objective": "Eseguire comandi in modo controllato via Caldera",
      "motivation": "Tecnica documentata e coerente con l'attore studiato"
    }
  ]
}
```

Aggiungi qui solo tecniche coerenti con il profilo assegnato e con il tuo Attack Flow.

## Comandi disponibili

### 1. Mostrare la lista TTP

```bash
python main.py --config config.example.yaml --list
```

### 2. Simulare senza inviare richieste a Caldera

```bash
python main.py --config config.example.yaml --dry-run --verbose
```

Questo comando è utile per verificare:

- che la configurazione sia corretta;
- che la allowlist sia letta bene;
- che la selezione delle TTP funzioni.

### 3. Eseguire tutte le TTP presenti nella allowlist

```bash
python main.py --config config.example.yaml --run --verbose
```

### 4. Eseguire solo alcune TTP

```bash
python main.py --config config.example.yaml --run --only T1059,T1105 --verbose
```

## Output generati

Al termine trovi questi file:

### In `logs/`

- `*.jsonl` → log strutturato riga per riga
- `*.csv` → log tabellare
- `*.md` → riepilogo leggibile in Markdown

### In `reports/`

- `*.pdf` → report finale per il debrief

## Cosa contiene il log

Ogni evento prova a registrare:

- timestamp
- fase
- ATT&CK ID
- nome tecnica
- target
- agente
- nome operazione
- ID operazione
- planner
- adversary ID
- stato
- messaggio
- motivazione
- durata osservata
- extra tecnici

Questo è allineato con il requisito del corso: **TTP, strumento usato, timestamp, esito, motivazione operativa**.

## Limiti importanti

Qui è bene parlare chiaro.

### 1. Le API di Caldera cambiano

Il PDF del corso dice senza mezzi termini che lo snippet API è un **punto di partenza** e che versioni diverse possono avere payload e comportamenti diversi. Questo progetto segue quella filosofia: è robusto, ma potrebbe richiedere piccoli adattamenti al tuo ambiente.

### 2. Il monitoraggio dello stato non è universale

Lo script osserva le operazioni con polling sulle operazioni visibili. In alcune versioni di Caldera potresti voler adattare i campi di stato o usare endpoint più specifici.

### 3. Questo progetto non sostituisce i log difensivi

Il PDF finale è comodo, ma la verità operativa resta nei log strutturati e nello stack di detection del laboratorio.

### 4. Non usare questo progetto fuori da un perimetro autorizzato

Va usato su un laboratorio o su un ambiente esplicitamente autorizzato. Nel PDF del corso c’è anche un richiamo ai confini legali dell’accesso abusivo.

## Esempio di flusso consigliato

1. avvia Caldera;
2. verifica che Sandcat sia attivo sulla target;
3. compila il file YAML;
4. compila la allowlist JSON;
5. prova con `--dry-run`;
6. lancia `--run --verbose`;
7. controlla `logs/` e `reports/`;
8. confronta tutto con Sysmon / Sigma / Chainsaw / Hayabusa o il tuo stack.

## Personalizzazioni utili

Puoi estendere il progetto in questi modi:

- aggiungere il recupero dinamico dei profili avversario via API;
- aggiungere il mapping con Attack Flow locale;
- aggiungere tag team / round / campaign;
- esportare anche in HTML;
- integrare il commit automatico dei log in una repo privata.

## Troubleshooting rapido

### Errore di autenticazione

Controlla:

- API key
- porta
- protocollo HTTP/HTTPS

### Nessun agente trovato

Controlla:

- che Sandcat sia realmente attivo;
- `target_agent_paw`;
- `target_name`;
- raggiungibilità di rete.

### PDF non generato

Controlla che `fpdf2` sia installato:

```bash
pip install fpdf2
```

## In due righe

Questo progetto è un **orchestratore didattico e controllato** per Caldera.
Non è un cannone. È un taccuino con un motore dentro: avvia, osserva, registra, racconta.
