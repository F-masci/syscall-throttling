# SCT - Syscall Throttling

**SCT** è un modulo del kernel Linux per architettura *x86-64* che implementa un meccanismo di *System Call Throttling*.

Il modulo agisce come un monitor di sicurezza e performance, permettendo di limitare il numero di invocazioni di specifiche system call da parte di processi o utenti monitorati. Implementa una politica di throttling basata su una finestra temporale fissa (1 secondo), bloccando temporaneamente i thread che violano il limite configurato.

---

## Quick Start

Per compilare e caricare il modulo con le impostazioni di default:

```bash
# Prepara l'ambiente e genera gli header
make setup

# Compila il modulo
make

# Carica il modulo nel kernel
make load
```

Il device node verrà creato automaticamente: `/dev/sct-monitor`.

---

## Utilizzo

L'interazione con il modulo avviene tramite `ioctl` sul device file `/dev/sct-monitor`. È fornito il software di interfaccia [`client`](client/client.c) per inviare comandi.

> **Nota:** Tutte le operazioni di configurazione richiedono privilegi di **root**.

### Esempi di comandi

1\. **Registrazione Regole**:

Monitora la syscall `mkdir` (*83* su *x64*) per l'utente con UID *1000* o sull'eseguibile `/usr/bin/mkdir`.

```bash
sudo ./client add --sys 83
sudo ./client add --uid 1000
sudo ./client add --prog /usr/bin/mkdir
```

2\. **Configurazione Throttling**:

Imposta un limite di 10 chiamate al secondo e attiva il monitor.

```bash
sudo ./client limit --val 10
sudo ./client status --val 1
```

3\. **Monitoraggio**:

Visualizza le statistiche in tempo reale (thread bloccati, delay massimo).

```bash
./client get-status
./client get-stats
./client get-delay

# Oppure

cat /dev/sct-monitor
```

---

## Compilazione e Configurazione

### Requisiti

* Linux Kernel 5.x o superiore (Headers installati)
* GCC, Make
* Librerie: `libelf-dev`

### Opzioni di Build

Il comportamento del modulo può essere personalizzato passando variabili al comando `make`.

| Variabile | Default | Descrizione |
| --- | --- | --- |
| **`ENABLE_FTRACE`** | `0` | `1`: Utilizza **FTRACE** per l'hooking.<br>`0`: Utilizza la scansione della *System Call Table*. |
| **`ENABLE_LOWMEM`** | `0` | `1`: **Low Memory Mode**. Ottimizza per ridurre l'impronta di memoria e forza l'uso di **Spinlock**. |
| **`ENABLE_DEBUG`** | `0` | `1`: Abilita il logging *verbose* nel kernel ring buffer. |
| **`SYNC_METHOD`** | `RCU_PROTECTED` | `RCU_PROTECTED`: Utilizza **RCU** per proteggere le strutture dati relative alle statistiche.<br>`SPINLOCK_PROTECTED`: Utilizza gli **Spinlocks** per proteggere le strutture dati relative alle statistiche. |

Esempio di compilazione avanzata:

```bash
make ENABLE_FTRACE=1 ENABLE_LOWMEM=1
```

### Gestione Modulo

* **Caricamento:** `make load` (installa il modulo e crea il device node).
* **Rimozione:** `make unload` (rimuove il modulo e pulisce il device node).
* **Pulizia:** `make clean` (rimuove i file oggetto e binari).

---

## Dettagli Tecnici

### Sincronizzazione

Il modulo supporta due modalità di concorrenza per gestire l'accesso alle strutture dati condivise delle statistiche:

* **RCU:** Default. Ideale per scenari *read-heavy*.
* **Spinlock:** Utilizzato in modalità `ENABLE_LOWMEM` o quando espressamente richiesto.

### Throttling Algorithm

Il sistema utilizza un approccio a **finestra fissa**.
Ogni secondo, i contatori delle invocazioni vengono resettati. Se un thread supera la soglia `MAX` prima della fine della finestra, viene messo in stato di sleep in attesa di poter eseguire.

---

## Quality Assurance

Il codice è stato analizzato con i tool standard del kernel Linux per garantire conformità e stabilità.

```bash
make checkpatch  # Verifica stile (Linux Kernel Style)
make cppcheck    # Analisi statica
make sparse      # Analisi semantica (C=1)
```

---

## Test e Validazione

Il progetto include un framework di test automatizzato situato nella directory [`test`](test/). I test possono essere eseguiti direttamente sull'host o, per maggiore sicurezza, all'interno di una Macchina Virtuale gestita da *Vagrant*.

Ogni test corrisponde a una sottocartella presente in [`test`](test/) (es. [`t1`](test/t1/), [`t2`](test/t2/), ecc.).

### 1\. Test in VM

È fornito un ambiente **Vagrant** (basato su *Ubuntu 22.04*) preconfigurato che isola l'esecuzione del modulo kernel, prevenendo crash del sistema ospitante.

**Requisiti:** *Vagrant*, *VirtualBox* (o *Libvirt*).

```bash
# Avvia l'ambiente virtuale
cd test
vagrant up

# Esegui i test (eseguire dall'host, lo script comanda la VM)
./vm.sh <nome_test> [altri_test...]
```

Lo script `vm.sh` si occupa automaticamente di:

1. Sincronizzare i sorgenti con la VM.
2. Compilare modulo e client all'interno della VM.
3. Caricare il modulo.
4. Eseguire la suite di test specificata.

**Opzioni disponibili per gli script:**

* `--reload`: Scarica il modulo, lo ricompila e poi lo ricarica prima di eseguire i test.

**Esempio:**

```bash
# Esegue il test 't1' forzando la ricompilazione e il reload del modulo
./vm.sh --reload t1
```

### 2\. Test su Host Locale

È possibile eseguire i test direttamente sulla macchina di sviluppo.

> **Attenzione:** Eseguire moduli sperimentali sul kernel dell'host può causare instabilità o crash del sistema.

```bash
# Esegui i test
cd test
./local.sh <nome_test> [altri_test...]
```

**Opzioni disponibili per gli script:**

* `--reload`: Scarica il modulo, lo ricompila e poi lo ricarica prima di eseguire i test.

**Esempio:**

```bash
# Esegue i test 't1' e 't2' senza forzare la ricompilazione e il reload del modulo
./local.sh t1 t2
```

---

## Autore

**Francesco Masci** (Matricola 0365258)

**Progetto del Corso di Laurea Magistrale in Ingegneria Informatica**
*Sistemi Operativi Avanzati (e Sicurezza dei Sistemi) (A.A. 2025/2026)*
Università degli Studi di Roma "Tor Vergata"
