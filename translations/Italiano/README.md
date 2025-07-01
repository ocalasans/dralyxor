# Dralyxor

**Dralyxor** è una libreria **C++** moderna, `header-only`, ad alte prestazioni e multistrato, progettata per l'offuscamento delle stringhe a tempo di compilazione e una robusta protezione a tempo di esecuzione. La sua missione fondamentale è proteggere i segreti intrinseci della tua applicazione — come chiavi API, password, URL interni, messaggi di debug e qualsiasi letterale di stringa sensibile — dall'esposizione tramite analisi statica, ingegneria inversa e ispezione della memoria dinamica. Criptando e trasformando le stringhe al momento della compilazione e gestendo il loro accesso in modo sicuro durante l'esecuzione, **Dralyxor** assicura che nessun letterale di stringa critico esista come testo in chiaro nel tuo binario finale o rimanga non protetto in memoria più a lungo dello stretto necessario.

Costruito sulle fondamenta del **C++** moderno (richiedendo **C++14** e adattandosi intelligentemente alle funzionalità di **C++17** e **C++20**), la sua architettura avanzata presenta un sofisticato motore di trasformazione basato su "micro-programmi", offuscamento del programma di trasformazione stesso, meccanismi di integrità dei dati, difese anti-debugging e un **Accessorio di Ambito Sicuro (RAII)** per una decrittazione "just-in-time" e ri-offuscamento automatico. Ciò minimizza drasticamente l'esposizione dei dati nella memoria **RAM** e fornisce una difesa in profondità di livello professionale.

## Lingue

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Indice

- [Dralyxor](#dralyxor)
  - [Lingue](#lingue)
  - [Indice](#indice)
  - [Guida Rapida all'Integrazione e all'Uso](#guida-rapida-allintegrazione-e-alluso)
    - [Installazione](#installazione)
    - [Requisiti del Compilatore](#requisiti-del-compilatore)
    - [Pattern di Utilizzo Essenziali](#pattern-di-utilizzo-essenziali)
      - [Pattern 1: Offuscamento Locale (Stack)](#pattern-1-offuscamento-locale-stack)
      - [Pattern 2: Offuscamento Statico (Globale)](#pattern-2-offuscamento-statico-globale)
      - [Pattern 3: Offuscamento con Chiave Fornita dall'Utente](#pattern-3-offuscamento-con-chiave-fornita-dallutente)
    - [Gestione degli Errori e Integrità](#gestione-degli-errori-e-integrità)
  - [Filosofia e Architettura di Design Dettagliata](#filosofia-e-architettura-di-design-dettagliata)
    - [La Minaccia Persistente: Vulnerabilità delle Stringhe Letterali](#la-minaccia-persistente-vulnerabilità-delle-stringhe-letterali)
    - [La Soluzione Architettonica Multistrato di **Dralyxor**](#la-soluzione-architettonica-multistrato-di-dralyxor)
  - [Analisi Approfondita dei Componenti Architettonici](#analisi-approfondita-dei-componenti-architettonici)
    - [Componente 1: Il Motore di Trasformazione a Micro-Programma](#componente-1-il-motore-di-trasformazione-a-micro-programma)
      - [Potere di `consteval` e `constexpr` per la Generazione in Compilazione](#potere-di-consteval-e-constexpr-per-la-generazione-in-compilazione)
      - [Anatomia di un Micro-Programma **Dralyxor**](#anatomia-di-un-micro-programma-dralyxor)
        - [Generazione Casuale di Istruzioni e Selezione di Applicatori](#generazione-casuale-di-istruzioni-e-selezione-di-applicatori)
        - [NOP Variabili e Logici per l'Entropia](#nop-variabili-e-logici-per-lentropia)
      - [Offuscamento del Micro-Programma Stesso](#offuscamento-del-micro-programma-stesso)
      - [Il Ciclo di Vita dell'Offuscamento Statico](#il-ciclo-di-vita-delloffuscamento-statico)
    - [Componente 2: Accesso Sicuro e Minimizzazione dell'Esposizione in **RAM**](#componente-2-accesso-sicuro-e-minimizzazione-dellesposizione-in-ram)
      - [Il `Secure_Accessor` e il Principio RAII](#il-secure_accessor-e-il-principio-raii)
      - [Frammentazione della Memoria nel `Secure_Accessor`](#frammentazione-della-memoria-nel-secure_accessor)
      - [Pulizia Sicura della Memoria](#pulizia-sicura-della-memoria)
    - [Componente 3: Difese in Tempo di Esecuzione (Anti-Debugging e Anti-Tampering)](#componente-3-difese-in-tempo-di-esecuzione-anti-debugging-e-anti-tampering)
      - [Rilevamento Multi-Piattaforma di Debugger](#rilevamento-multi-piattaforma-di-debugger)
      - [Impatto sull'Operazione in Caso di Rilevamento o Violazione di Integrità](#impatto-sulloperazione-in-caso-di-rilevamento-o-violazione-di-integrità)
      - [Canary di Integrità dell'Oggetto](#canary-di-integrità-delloggetto)
      - [Checksum del Contenuto della Stringa](#checksum-del-contenuto-della-stringa)
    - [Componente 4: Generazione di Chiavi e Seed Unici e Imprevedibili](#componente-4-generazione-di-chiavi-e-seed-unici-e-imprevedibili)
      - [Fonti di Entropia per il `compile_time_seed`](#fonti-di-entropia-per-il-compile_time_seed)
      - [Semi Derivati per Trasformazioni di Contenuto](#semi-derivati-per-trasformazioni-di-contenuto)
      - [Immunità Contro Attacchi di "Replay" e Analisi di Pattern](#immunità-contro-attacchi-di-replay-e-analisi-di-pattern)
  - [Riferimento Completo dell'API Pubblica](#riferimento-completo-dellapi-pubblica)
    - [Macro di Offuscamento](#macro-di-offuscamento)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Macro di Accesso Sicuro](#macro-di-accesso-sicuro)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Funzionalità Avanzate e Buone Pratiche](#funzionalità-avanzate-e-buone-pratiche)
    - [Supporto Completo a Unicode (Wide Strings - `wchar_t`)](#supporto-completo-a-unicode-wide-strings---wchar_t)
    - [Adattamento Intelligente agli Standard **C++** e agli Ambienti (Kernel Mode)](#adattamento-intelligente-agli-standard-c-e-agli-ambienti-kernel-mode)
    - [Considerazioni sulle Prestazioni e Overhead](#considerazioni-sulle-prestazioni-e-overhead)
    - [Integrazione in una Strategia di Sicurezza a Strati](#integrazione-in-una-strategia-di-sicurezza-a-strati)
  - [Licenza](#licenza)
    - [Condizioni:](#condizioni)

## Guida Rapida all'Integrazione e all'Uso

### Installazione

**Dralyxor** è una libreria **header-only**. Non è necessaria alcuna pre-compilazione o collegamento a librerie (`.lib`/`.a`).

1. **Copia la Directory `Dralyxor`:** Ottieni l'ultima versione della libreria (clona il repository o scarica lo zip) e copia l'intera directory `Dralyxor` (contenente tutti i file `.hpp`) in una posizione accessibile dal tuo progetto (ad esempio, una cartella `libs/`, `libraries/`, o `vendor/`).
2. **Includi l'Header Principale:** Nel tuo codice sorgente, includi l'header principale `dralyxor.hpp`:
   ```cpp
   #include "percorso/per/Dralyxor/dralyxor.hpp"
   ```

Una struttura di progetto tipica:
```
/MioProgetto/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor qui
        |-- dralyxor.hpp            (Punto di ingresso principale)
        |-- obfuscated_string.hpp   (Classe Obfuscated_String)
        |-- secure_accessor.hpp     (Classe Secure_Accessor)
        |-- algorithms.hpp          (Motore di trasformazione e micro-programmi)
        |-- anti_debug.hpp          (Rilevamenti a runtime)
        |-- prng.hpp                (Generatore di numeri pseudo-casuali in compilazione)
        |-- integrity_constants.hpp (Costanti per le verifiche di integrità)
        |-- secure_memory.hpp       (Pulizia sicura della memoria)
        |-- detection.hpp           (Macro di rilevamento del compilatore/standard C++)
        `-- env_traits.hpp          (Adattamenti di type_traits per ambienti ristretti)
```

### Requisiti del Compilatore

> [!IMPORTANT]
> **Dralyxor** è stato progettato con un focus sul **C++** moderno per la massima sicurezza ed efficienza in tempo di compilazione.
>
> - **Standard C++ Minimo: C++14**. La libreria utilizza funzionalità come `constexpr` generalizzato e si adatta a `if constexpr` (quando disponibile tramite `_DRALYXOR_IF_CONSTEXPR`).
> - **Adattamento a Standard Superiori:** Rileva e utilizza ottimizzazioni o sintassi di **C++17** e **C++20** (come `consteval`, suffissi `_v` per `type_traits`) se il progetto viene compilato con questi standard. `_DRALYXOR_CONSTEVAL` viene mappato a `consteval` in C++20 e `constexpr` in C++14/17, garantendo l'esecuzione in tempo di compilazione dove possibile.
> - **Compilatori Supportati:** Testato principalmente con versioni recenti di MSVC, GCC e Clang.
> - **Ambiente di Esecuzione:** Totalmente compatibile con applicazioni in **User Mode** e ambienti **Kernel Mode** (es: driver di Windows). In Kernel Mode, dove la STL potrebbe non essere disponibile, **Dralyxor** utilizza implementazioni interne per i `type traits` necessari (vedi `env_traits.hpp`).

### Pattern di Utilizzo Essenziali

#### Pattern 1: Offuscamento Locale (Stack)

Ideale per stringhe temporanee, confinate a un ambito di funzione. La memoria viene gestita e pulita automaticamente.

```cpp
#include "Dralyxor/dralyxor.hpp" // Adatta il percorso secondo necessità
#include <iostream>

void Configure_Logging() {
    // Chiave di formattazione del log, utilizzata solo localmente.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Accesso sicuro all'interno di un ambito limitato
    {
        // Il Secure_Accessor de-offusca temporaneamente 'log_format_key' durante la sua costruzione
        // (e ri-offusca 'log_format_key' immediatamente dopo la copia nei suoi buffer interni),
        // ne permette l'accesso, e pulisce i propri buffer alla distruzione.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Controllare sempre che Get() non restituisca nullptr
            std::cout << "Utilizzando formato di log: " << accessor.Get() << std::endl;
            // Es: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Fallimento nel decifrare log_format_key (possibile tampering o rilevamento di debugger?)" << std::endl;
    } // accessor viene distrutto, i suoi buffer interni sono puliti. log_format_key rimane offuscato.
      // log_format_key sarà distrutto alla fine della funzione Configure_Logging.
}
```

#### Pattern 2: Offuscamento Statico (Globale)

Per costanti che devono persistere per tutta la durata del programma ed essere accessibili globalmente.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Per l'esempio

// URL dell'API di licenze, un segreto persistente.
// La macro DRALYXOR() crea un oggetto statico.
// La funzione Get_License_Server_URL() restituisce un riferimento a questo oggetto statico.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref è un riferimento all'Obfuscated_String statico.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Crea un Secure_Accessor per url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Contattando server di licenza a: " << accessor.Get() << std::endl;
            // Es: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulazione di successo per l'esempio
        }
        else
            std::cerr << "Fallimento nel decifrare URL del server di licenza (possibile tampering o rilevamento di debugger?)." << std::endl;
    } // accessor viene distrutto, i suoi buffer sono puliti. url_obj_ref (l'Obfuscated_String originale) rimane offuscato.

    return success;
}
```

#### Pattern 3: Offuscamento con Chiave Fornita dall'Utente

Per il massimo livello di sicurezza, puoi fornire la tua stringa di chiave segreta. Ciò fa sì che l'offuscamento dipenda da un segreto che solo tu conosci, rendendolo resistente.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// La chiave non dovrebbe mai essere in testo chiaro nel codice di produzione,
// idealmente dovrebbe provenire da un build script, una variabile d'ambiente, ecc.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Offusca un URL usando la chiave segreta. La macro termina con _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // L'uso con Secure_Accessor rimane lo stesso.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Gestione degli Errori e Integrità

Le funzioni `Obfuscated_String::Decrypt()` e `Encrypt()` restituiscono `uint64_t`:
- `0` indica successo.
- `Dralyxor::Detail::integrity_compromised_magic` (un valore costante definito in `integrity_constants.hpp`) indica che una verifica di integrità è fallita. Ciò può essere dovuto a canary dell'oggetto corrotti, checksum del contenuto inconsistente, o al rilevamento di un debugger che segnala un ambiente ostile.

Allo stesso modo, `Secure_Accessor::Get()` (o la sua conversione implicita a `const CharT*`) restituirà `nullptr` se l'inizializzazione del `Secure_Accessor` fallisce (ad esempio, se la de-crittografia dell' `Obfuscated_String` originale fallisce) o se l'integrità del `Secure_Accessor` (i suoi propri canary o checksum interni) viene compromessa durante la sua vita utile.

**È cruciale che il tuo codice controlli questi valori di ritorno per garantire la robustezza e la sicurezza dell'applicazione.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Generalmente NON chiameresti Decrypt() e Encrypt() direttamente,
    // poiché Secure_Accessor gestisce questo. Ma se ne hai bisogno per qualche motivo:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "ALERT: Fallimento nel decifrare 'my_secret' o integrità compromessa durante Decrypt()!" << std::endl;
        // Prendi una misura appropriata: termina, logga in modo sicuro, ecc.
        // L'oggetto my_secret.storage_ potrebbe essere in uno stato non valido o contenere spazzatura.
        return; // Evita di usare my_secret se Decrypt() fallisce.
    }

    // Se Decrypt() ha avuto successo, my_secret.storage_ contiene il dato decifrato.
    // **L'ACCESSO DIRETTO A storage_ È FORTEMENTE SCONSIGLIATO IN PRODUZIONE.**
    // std::cout << "Dato in my_secret.storage_ (NON FARE QUESTO): " << my_secret.storage_ << std::endl;

    // È tua responsabilità ri-crittografare se hai chiamato Decrypt() manualmente:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "ALERT: Fallimento nel ri-crittografare 'my_secret' o integrità compromessa durante Encrypt()!" << std::endl;
        // Stato incerto, potenzialmente pericoloso.
    }

    // USO RACCOMANDATO con Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Il costruttore di Secure_Accessor chiama another_secret.Decrypt(), copia, e poi another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // O: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Dato segreto via Secure_Accessor: " << data_ptr << std::endl;
            // Usa data_ptr qui
        }
        else {
            std::cerr << "ALERT: Secure_Accessor ha fallito nell'inizializzare o ottenere il puntatore a 'another_secret'!" << std::endl;
            // Ciò indica che Decrypt() all'interno del costruttore dell'accessor è fallito,
            // o c'è stato un tampering sull'accessor (canary, checksum interni).
        }
    } // accessor viene distrutto. I suoi buffer sono puliti. another_secret rimane offuscato.
}
```

## Filosofia e Architettura di Design Dettagliata

**Dralyxor** non è semplicemente una cifra XOR; è un sistema di difesa in profondità per le stringhe letterali. La sua architettura è fondata sulla premessa che una sicurezza efficace richieda molteplici livelli interconnessi e resilienza contro diverse tecniche di analisi.

### La Minaccia Persistente: Vulnerabilità delle Stringhe Letterali

Le stringhe letterali, come `"api.example.com/data?key="`, quando incorporate direttamente nel codice, vengono scritte in modo leggibile (testo in chiaro) nel binario compilato. Strumenti come `strings`, disassemblatori (IDA Pro, Ghidra) ed editor esadecimali possono estrarle trivialmente. Questa esposizione facilita:
- **Ingegneria Inversa:** Comprensione della logica interna e del flusso del programma.
- **Identificazione di Endpoint:** Scoperta di server e API backend.
- **Estrazione di Segreti:** Chiavi API, password incorporate, URL privati, query SQL, ecc.
- **Analisi della Memoria Dinamica:** Anche se un programma decifra una stringa per l'uso, se essa rimane in testo in chiaro nella **RAM** per troppo tempo, un aggressore con accesso alla memoria del processo (tramite debugger o memory dump) può trovarla.

**Dralyxor** attacca queste vulnerabilità sia a tempo di compilazione (per il binario su disco) sia a tempo di esecuzione (per la memoria **RAM**).

### La Soluzione Architettonica Multistrato di **Dralyxor**

La robustezza di **Dralyxor** emana dalla sinergia dei suoi componenti chiave:

| Componente Architettonico                  | Obiettivo Primario                                                                       | Tecnologie/Tecniche Chiave Impiegate                                                                                                                              |
| :------------------------------------------ | :--------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Motore di Trasformazione tramite Micro-Programma** | Eliminare stringhe in testo in chiaro dal binario; creare offuscamento complesso, dinamico e non banale. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, molteplici operazioni (XOR, ADD, ROT, ecc.), NOP variabili e logici, stili di applicatori variabili.        |
| **Accesso Sicuro e Minimizzazione dell'Esposizione** | Ridurre drasticamente il tempo in cui un segreto rimane decifrato nella memoria RAM.                | Pattern RAII (`Secure_Accessor`), frammentazione della memoria, pulizia sicura dei buffer (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                               |
| **Difese a Tempo di Esecuzione**               | Rilevare e reagire ad ambienti di analisi ostili e manomissione della memoria.             | Rilevamento di Debugger (API specifiche dell'OS, timing, OutputDebugString), canary di integrità dell'oggetto, checksum del contenuto della stringa.                          |
| **Generazione di Chiavi e Semi Unici**     | Garantire che ogni stringa offuscata e ogni istanza di utilizzo siano crittograficamente distinte. | `__DATE__`, `__TIME__`, `__COUNTER__`, dimensione della stringa, hashing FNV-1a per `compile_time_seed`, semi derivati per modificatori di operando e selettori. |

## Analisi Approfondita dei Componenti Architettonici

### Componente 1: Il Motore di Trasformazione a Micro-Programma

Il cuore dell'offuscamento statico e dinamico di **Dralyxor** risiede nel suo motore di trasformazione che utilizza "micro-programmi" unici per ogni stringa e contesto.

#### Potere di `consteval` e `constexpr` per la Generazione in Compilazione

Il **C++** moderno, con `consteval` (**C++20**) e `constexpr` (**C++11** in poi), permette che codice complesso sia eseguito *durante la compilazione*. **Dralyxor** utilizza `_DRALYXOR_CONSTEVAL` (che viene mappato a `consteval` o `constexpr` a seconda dello standard **C++**) per il costruttore `Obfuscated_String` e per la generazione del micro-programma.

Ciò significa che l'intero processo di:
1. Generare una sequenza pseudo-casuale di istruzioni di trasformazione (il micro-programma).
2. Offuscare il micro-programma stesso per l'archiviazione.
3. Applicare questo micro-programma (in forma temporaneamente de-offuscata) per trasformare la stringa originale, risultando nella sua forma offuscata.
Tutto ciò avviene in tempo di compilazione, prima che il binario venga generato.

#### Anatomia di un Micro-Programma **Dralyxor**

Ogni oggetto `Obfuscated_String` archivia un piccolo array di `Dralyxor::Detail::Micro_Instruction`. Una `Micro_Instruction` è una struttura semplice definita in `algorithms.hpp`:
```cpp
// In Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM
};

struct Micro_Instruction {
    Micro_Operation_Code op_code{}; // Inizializzatore predefinito {} per azzerare
    uint8_t operand{};             // Inizializzatore predefinito {} per azzerare
};

// Numero massimo di istruzioni che un micro-programma può contenere.
static constexpr size_t max_micro_instructions = 8;
```
La funzione `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` è responsabile di riempire questo array.

##### Generazione Casuale di Istruzioni e Selezione di Applicatori

- **Generazione di Istruzioni:** Utilizzando un `Dralyxor::Detail::Constexpr_PRNG` (seminato con una combinazione del `compile_time_seed` e `0xDEADBEEFC0FFEEULL`), la funzione `Generate_Micro_Program_Instructions` sceglie probabilisticamente una sequenza di operazioni:
   - `XOR`: XOR bit a bit con l'operando.
   - `ADD`: Addizione modulare con l'operando.
   - `SUB`: Sottrazione modulare con l'operando.
   - `ROTR`/`ROTL`: Rotazione di bit. L'operando (dopo il modulo) definisce il numero di shift (da 1 a 7).
   - `SWAP_NIB`: Scambia i 4 bit inferiori con i 4 bit superiori di un byte (l'operando è ignorato).
    Anche gli operandi per queste istruzioni sono generati pseudo-casualmente dal PRNG.

- **Modifica degli Operandi e Selezione degli Applicatori in Tempo di Trasformazione:** Durante l'applicazione del micro-programma (tramite `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), sia nell'offuscamento iniziale che nella de-offuscamento a runtime:
   - Un `Constexpr_PRNG prng_operand_modifier` (seminato con `base_seed`) genera una `prng_key_for_ops_in_elem` per ogni carattere della stringa. L'operando della micro-istruzione (`instr_orig.operand`) viene XORato con questa chiave prima di essere utilizzato. Ciò garantisce che lo stesso micro-programma applichi trasformazioni leggermente diverse per ogni carattere.
   - Un `Constexpr_PRNG prng_applier_selector` (seminato con `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) sceglie un `Byte_Transform_Applier` per ogni carattere. Attualmente esistono due stili:
      - `Applier_Style_Direct`: Applica l'operazione direttamente (invertendola per la de-crittografia, come ADD diventa SUB).
      - `Applier_Style_DoubleLayer`: Applica l'operazione due volte (o l'operazione e la sua inversa, a seconda della modalità di crittografia/de-crittografia) con operandi diversi, rendendo l'inversione leggermente più complessa da analizzare.

##### NOP Variabili e Logici per l'Entropia

Per aumentare la difficoltà dell'analisi manuale del micro-programma, **Dralyxor** inserisce:
- **NOP Espliciti:** Istruzioni `Micro_Operation_Code::NOP` che non fanno nulla.
- **NOP Logici:** Coppie di istruzioni che si annullano a vicenda, come `ADD K` seguito da `SUB K`, o `ROTL N_BITS` seguito da `ROTR N_BITS`. L'operando usato nella coppia è lo stesso.

Questi NOP sono inseriti probabilisticamente da `Generate_Micro_Program_Instructions`, riempiendo l'array `micro_program_` e rendendo più difficile discernere le trasformazioni effettive dalle operazioni di "rumore".

#### Offuscamento del Micro-Programma Stesso

Dopo la generazione del micro-programma e prima dell'offuscamento iniziale della stringa nel costruttore `consteval`, l'array `micro_program_` (contenuto nell'oggetto `Obfuscated_String`) viene esso stesso offuscato. Ogni `op_code` e `operand` in ogni `Micro_Instruction` viene XORato con una chiave derivata dal `compile_time_seed` (usando `Detail::Get_Micro_Program_Obfuscation_Key` e `Detail::Obfuscate_Deobfuscate_Instruction`).
Ciò significa che, anche se un aggressore riuscisse a dumpare la memoria dell'oggetto `Obfuscated_String`, il micro-programma non sarebbe nella sua forma direttamente leggibile/applicabile.

Quando `Obfuscated_String::Decrypt()` o `Encrypt()` vengono chiamate (o indirettamente dal `Secure_Accessor`), la funzione centrale `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` riceve questo micro-programma *offuscato*. Essa quindi:
1. Crea una copia temporanea del micro-programma (`local_plain_program`) sullo stack.
2. De-offusca questa copia locale usando la stessa chiave (`program_obf_key`) derivata dal seme di base passato (che è, in ultima analisi, il `compile_time_seed`).
3. Utilizza questo `local_plain_program` per trasformare i dati della stringa.
La copia locale sullo stack viene distrutta alla fine della funzione, e il `micro_program_` memorizzato nell'oggetto `Obfuscated_String` rimane offuscato.

#### Il Ciclo di Vita dell'Offuscamento Statico

1. **Codice Sorgente:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Pre-elaborazione:** La macro si espande in un'istanziazione `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (La dimensione 15 include il terminatore nullo).
3. **Valutazione `_DRALYXOR_CONSTEVAL`:**
   - Il compilatore esegue il costruttore `Obfuscated_String`.
   - `Initialize_Internal_Canaries()` imposta i canary di integrità.
   - `Generate_Micro_Program_Instructions()` (seminato con `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) crea una sequenza di `Micro_Instruction` e la memorizza in `this->micro_program_` (es: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Il numero effettivo di istruzioni viene memorizzato in `num_actual_instructions_in_program_`.
   - La stringa originale "SECRET\_API\_KEY" viene copiata in `this->storage_`.
   - Un checksum della stringa originale "SECRET\_API\_KEY" (escluso il nullo) viene calcolato da `Detail::Calculate_String_Content_Checksum` e poi offuscato da `Detail::Obfuscate_Deobfuscate_Short_Value` (usando `compile_time_seed` e `content_checksum_obf_salt`) e memorizzato in `this->_content_checksum_obfuscated`.
   - Viene chiamata `Obfuscate_Internal_Micro_Program()`: `this->micro_program_` viene offuscato sul posto (ogni istruzione viene XORata con `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - Viene chiamata `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)`. Questa funzione:
      - Crea una copia de-offuscata di `this->micro_program_` sullo stack.
      - Per ogni carattere in `storage_` (eccetto il nullo):
         - Genera `prng_key_for_ops_in_elem` e seleziona un `Byte_Transform_Applier`.
         - Applica la sequenza di micro-istruzioni (dalla copia de-offuscata) al carattere, usando l'applicatore e l'operando modificato.
      - Alla fine, `storage_` contiene la stringa offuscata (es: `[CF, 3A, D1, ..., 0x00]`).
4. **Generazione del Codice:** Il compilatore alloca spazio per `api_key_obj` e lo inizializza direttamente con:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (stringa offuscata).
   - `micro_program_`: Il micro-programma *già offuscato*.
   - `_content_checksum_obfuscated`: Il checksum del contenuto originale, *offuscato*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Il letterale `"SECRET_API_KEY"` non esiste più nel binario.

### Componente 2: Accesso Sicuro e Minimizzazione dell'Esposizione in **RAM**

#### Il `Secure_Accessor` e il Principio RAII

La protezione in tempo di compilazione è solo metà della battaglia. Una volta che la stringa deve essere utilizzata, deve essere decifrata. Se questa stringa decifrata rimane in memoria **RAM** per un periodo prolungato, diventa un bersaglio per l'analisi dinamica (memory dumps, debugger).

**Dralyxor** affronta questo problema con il `Dralyxor::Secure_Accessor`, una classe che implementa il pattern **RAII** (Resource Acquisition Is Initialization):
- **Risorsa Acquisita:** L'accesso temporaneo alla stringa in testo chiaro, frammentata e gestita dall'accessor.
- **Oggetto Gestore:** L'istanza di `Secure_Accessor`.

```cpp
// In secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Inizializzare diversi per fallire se non aggiornato
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalida l'accessor

            return;
        }

        // 1. Tenta di decifrare l'Obfuscated_String originale.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Se la decifratura ha successo, copia la stringa plaintext nei frammenti interni.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ ora è in plaintext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val è al massimo 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Riempie il resto del buffer del frammento con nulli
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksum dei frammenti
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Ri-crittografa IMMEDIATAMENTE l'Obfuscated_String originale.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Pulisce i frammenti e il buffer ricostruito.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Verifica se stesso e il genitore
            Clear_All_Internal_Buffers(); // Misura di sicurezza
            _accessor_integrity_canary1 = 0; // Invalida per accessi futuri

            return nullptr;
        }

        if (!current_access_ptr_) { // Se è la prima chiamata a Get() o se è stato pulito
            if constexpr (N_storage > 0) { // Ricostruisce solo se c'è qualcosa da ricostruire
                size_t buffer_write_idx = 0;

                for (size_t i = 0; i < fragment_count_val; ++i) {
                    size_t base_chars_in_frag = N_storage / fragment_count_val;
                    size_t chars_in_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);

                    for (size_t j = 0; j < chars_in_this_fragment; ++j) {
                        if (j < fragment_buffer_size && buffer_write_idx < N_storage)
                            reconstructed_plain_buffer_[buffer_write_idx++] = fragments_storage_[i][j];
                        else
                            break;
                    }

                    if (buffer_write_idx >= N_storage)
                        break;
                }

                // Garantisce la terminazione nulla, anche se N_storage è riempito esattamente.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Per N_storage == 0 (stringa vuota, teoricamente), non ci sono checksum
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Per superare il controllo

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // se N_storage era 0, questo è sicuro se il buffer è > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Controlla di nuovo dopo qualsiasi operazione interna per garantire l'integrità.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Flusso di Utilizzo con `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - Il costruttore di `Secure_Accessor` viene chiamato.
   - Chiama `my_obfuscated_string.Decrypt()`. Ciò comporta la de-offuscazione del `micro_program_` (in una copia locale), l'uso di esso per decifrare `my_obfuscated_string.storage_`, e quindi la verifica dei canary e del checksum del contenuto decifrato rispetto a quello atteso.
   - In caso di successo, il contenuto di `my_obfuscated_string.storage_` (ora in testo chiaro) viene copiato e diviso nei `fragments_storage_` interni del `Secure_Accessor`.
   - Viene calcolato un checksum dei `fragments_storage_` (`fragments_data_checksum_expected_`).
   - Fondamentalmente, `my_obfuscated_string.Encrypt()` viene chiamato *immediatamente dopo*, ri-offuscando `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (o `const char* ptr = accessor;` a causa della conversione implicita)
   - Viene chiamato `Secure_Accessor::Get()`.
   - Verifica i propri canary di integrità e quelli dell' `Obfuscated_String` genitore.
   - Se è il primo accesso (`current_access_ptr_` è `nullptr`), ricostruisce la stringa completa in `reconstructed_plain_buffer_` dai `fragments_storage_`.
   - Quindi verifica `fragments_data_checksum_reconstructed_` contro `fragments_data_checksum_expected_` per assicurarsi che i frammenti non siano stati alterati mentre il `Secure_Accessor` esisteva.
   - Se tutto è corretto, restituisce un puntatore a `reconstructed_plain_buffer_`.
3. L'ambito dell' `accessor` termina (esce dalla funzione, il blocco `{}` termina, ecc.).
   - Il distruttore di `Secure_Accessor` viene chiamato automaticamente.
   - Viene invocato `Clear_All_Internal_Buffers()`, che pulisce in modo sicuro (`Secure_Clear_Memory`) sia il `reconstructed_plain_buffer_` che i `fragments_storage_`.

Il risultato è che la stringa in testo chiaro esiste in forma completa solo all'interno del `Secure_Accessor` (nel `reconstructed_plain_buffer_`) e solo dopo la prima chiamata a `Get()`, per il minor tempo possibile. La stringa nell'oggetto `Obfuscated_String` originale viene ri-offuscata non appena il `Secure_Accessor` ne copia il contenuto durante la costruzione.

#### Frammentazione della Memoria nel `Secure_Accessor`

Per rendere ancora più difficile la localizzazione della stringa completa in testo chiaro in memoria, il `Secure_Accessor`, durante la sua costruzione, non solo copia la stringa decifrata, ma la divide:
1. La stringa dall' `Obfuscated_String` genitore viene decifrata.
2. Il suo contenuto viene diviso in fino a `fragment_count_val` (attualmente 4, se la stringa è abbastanza grande) pezzi, che vengono copiati in `fragments_storage_[i]`.
3. La stringa nell'oggetto `Obfuscated_String` genitore viene ri-offuscata.

Solo quando `Secure_Accessor::Get()` viene chiamato per la prima volta, questi frammenti vengono ri-assemblati nel `reconstructed_plain_buffer_`. Questa tecnica mira a "spargere" i dati sensibili, frustrando le scansioni di memoria che cercano stringhe contigue.

#### Pulizia Sicura della Memoria

Sia il distruttore di `Obfuscated_String` (tramite `Clear_Internal_Data`) che il distruttore di `Secure_Accessor` (tramite `Clear_All_Internal_Buffers`) utilizzano `Dralyxor::Detail::Secure_Clear_Memory`. Questa funzione wrapper garantisce che i buffer contenenti dati sensibili vengano azzerati in modo affidabile, impedendo l'ottimizzazione del compilatore:
- **Su Windows:** Utilizza `SecureZeroMemory` (User Mode) o `RtlSecureZeroMemory` (Kernel Mode), che sono funzioni del sistema operativo progettate specificamente per non essere ottimizzate e per azzerare la memoria in modo sicuro.
- **Su Altre Piattaforme (Linux, macOS, ecc.):** L'implementazione ora usa `memset` per riempire il blocco di memoria con zeri. `memset` opera a livello di byte, il che lo rende ideale e sicuro per azzerare sia tipi primitivi (come `char`, `int`) sia tipi complessi (come `structs`), evitando problemi di compatibilità di tipo o di operatori di assegnazione. Per garantire che la chiamata a `memset` non venga ottimizzata e rimossa dal compilatore, il puntatore del buffer viene prima passato a un puntatore `volatile`.

Questo approccio garantisce che, quando gli oggetti vengono distrutti, il contenuto sensibile venga sovrascritto, riducendo il rischio di recupero dei dati attraverso l'analisi dei dump di memoria.

### Componente 3: Difese in Tempo di Esecuzione (Anti-Debugging e Anti-Tampering)

**Dralyxor** non si affida solo all'offuscamento. Impiega un insieme di difese attive in tempo di esecuzione, localizzate principalmente in `anti_debug.hpp` e integrate nei metodi `Decrypt()` e `Encrypt()` di `Obfuscated_String`.

#### Rilevamento Multi-Piattaforma di Debugger

La funzione `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (in `anti_debug.hpp`) verifica la presenza di un debugger utilizzando tecniche specifiche del sistema operativo:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` per `ProcessDebugPort` (0x07) e `ProcessDebugFlags` (0x1F).
- **Linux:** Lettura di `/proc/self/status` e controllo del valore di `TracerPid:`. Un valore diverso da 0 indica che il processo è tracciato.
- **macOS:** Uso di `sysctl` con `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` per ottenere `kinfo_proc` e controllo del flag `P_TRACED` in `kp_proc.p_flag`.

Inoltre, all'interno di `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Esegue un ciclo di operazioni computazionali semplici e misura il tempo. Un rallentamento significativo (superiore a `timing_threshold_milliseconds = 75ms`) può indicare che un debugger sta eseguendo il single-stepping o che sono attivi breakpoint estesi. All'interno di questo ciclo, viene chiamata `Is_Debugger_Present_Tracer_Pid_Sysctl()`, e viene chiamata una funzione "esca" `Detail::Canary_Function_For_Breakpoint_Check()` (che restituisce semplicemente `0xCC`, il codice di istruzione per `int3` / breakpoint software) e il suo risultato viene XORato, rendendo più difficile l'ottimizzazione e fornendo una posizione comune per i breakpoint.
- `Detail::Perform_Output_Debug_String_Trick()` (solo Windows User Mode): Usa il comportamento di `OutputDebugStringA/W` e `GetLastError()`. Se un debugger è collegato, `GetLastError()` potrebbe essere modificato dopo la chiamata a `OutputDebugString`.

#### Impatto sull'Operazione in Caso di Rilevamento o Violazione di Integrità

Se una qualsiasi delle verifiche anti-debugging restituisce `true`, o se i canary di integrità dell' `Obfuscated_String` (`_internal_integrity_canary1/2`) sono corrotti, la funzione `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` restituirà `Detail::integrity_compromised_magic`.

Questo valore di ritorno è cruciale nelle funzioni `Obfuscated_String::Decrypt()` e `Encrypt()`:
```cpp
// Logica semplificata di Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canary dell'Obfuscated_String
        Clear_Internal_Data();
        decrypted_ = false;

        return Detail::integrity_compromised_magic;
    }

    if (!decrypted_) {
        uint64_t runtime_key_mod = Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2);

        if (runtime_key_mod == Detail::integrity_compromised_magic) {
            Clear_Internal_Data();
            decrypted_ = false;

            return Detail::integrity_compromised_magic;
        }
        // ... Verificare nuovamente i canary ...

        // SE runtime_key_mod NON È integrity_compromised_magic, ESSO NON È USATO PER CAMBIARE LA CHIAVE DI DECRITTOGRAFIA.
        // La chiave di decrittografia è sempre derivata dal 'compile_time_seed' originale.
        // Il ruolo di runtime_key_mod qui è di AGIRE COME UN FLAG di ambiente ostile.
        // Se ostile, la funzione restituisce integrity_compromised_magic e la decifratura non prosegue o viene invertita.
        
        // Transform_Compile_Time_Consistent viene chiamata con compile_time_seed (e NON con runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Verificare nuovamente checksum e canary ...
        // Se qualcosa fallisce, Clear_Internal_Data() e restituisce integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Successo
}
```

**Effetto Chiave:** Se `Calculate_Runtime_Key_Modifier` rileva un problema (debugger o canary corrotto) e restituisce `integrity_compromised_magic`, le funzioni `Decrypt()` (e similarmente `Encrypt()`) abortiscono l'operazione, puliscono i dati interni dell' `Obfuscated_String` (inclusi `storage_` e `micro_program_`), e restituiscono `integrity_compromised_magic`. Ciò impedisce che la stringa venga correttamente decifrata (o ri-cifrata) in un ambiente ostile o se l'oggetto è stato manomesso.
La stringa non viene decifrata "scorrettamente" (in spazzatura); l'operazione viene semplicemente impedita, e l'oggetto `Obfuscated_String` si auto-distrugge in termini di contenuto utile.

#### Canary di Integrità dell'Oggetto

Entrambe le classi `Obfuscated_String` e `Secure_Accessor` contengono membri canary (coppie di `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (inizializzato con `Detail::integrity_canary_value`) e `_internal_integrity_canary2` (inizializzato con `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (inizializzato con `Detail::accessor_integrity_canary_seed`) e `_accessor_integrity_canary2` (inizializzato con `~Detail::accessor_integrity_canary_seed`).

Questi canary vengono verificati in punti critici:
- Inizio e fine di `Obfuscated_String::Decrypt()` e `Encrypt()`.
- Costruttore, distruttore e `Get()` del `Secure_Accessor`.
- Prima e dopo le verifiche anti-debug in `Calculate_Runtime_Key_Modifier`.

Se questi valori canary vengono alterati (ad esempio, da un buffer overflow, una patch di memoria indiscriminata, o un hook che sovrascrive memoria adiacente), la verifica (`Verify_Internal_Canaries()` o `Verify_Internal_Accessor_Canaries()`) fallirà.
In caso di fallimento, le operazioni vengono abortite, i dati interni rilevanti vengono puliti, e viene restituito un valore di errore (`Detail::integrity_compromised_magic` o `nullptr`), segnalando una manomissione.

#### Checksum del Contenuto della Stringa

- Un checksum a 16 bit della stringa *originale in testo chiaro* (escluso il terminatore nullo) viene calcolato da `Detail::Calculate_String_Content_Checksum` in tempo di compilazione.
- Questo checksum viene quindi offuscato usando `Detail::Obfuscate_Deobfuscate_Short_Value` (con `compile_time_seed` e `content_checksum_obf_salt`) e memorizzato in `_content_checksum_obfuscated` nell'oggetto `Obfuscated_String`.
- **Durante la Decifratura (`Decrypt()`):** Dopo che `storage_` è stato trasformato (presumibilmente in testo chiaro), il suo checksum viene calcolato. Il `_content_checksum_obfuscated` viene de-offuscato per ottenere il checksum di riferimento. Se i due checksum non corrispondono, indica che:
   - La decifratura non ha ripristinato la stringa originale (forse perché l'operazione è stata abortita a causa del rilevamento di un debugger prima della trasformazione completa, o c'è stata corruzione del seme/micro-programma).
   - `storage_` (quando offuscato) o `_content_checksum_obfuscated` sono stati manomessi in memoria.
- **Durante la Cifratura (`Encrypt()`):** Prima che `storage_` (che è in testo chiaro a questo punto) venga trasformato di nuovo nella sua forma offuscata, il suo checksum viene calcolato e confrontato con quello di riferimento. Una divergenza qui significherebbe che la stringa in testo chiaro è stata alterata *all'interno di `storage_` dell' `Obfuscated_String` mentre era decifrata*, il che è una forte indicazione di manomissione della memoria o uso improprio (poiché l'accesso a `storage_` non dovrebbe essere fatto direttamente).

In entrambi i casi di fallimento del checksum, viene chiamata `Clear_Internal_Data()` e restituito `integrity_compromised_magic`.

### Componente 4: Generazione di Chiavi e Seed Unici e Imprevedibili

La sicurezza di qualsiasi sistema di cifratura si basa sulla forza e l'unicità delle sue chiavi e dei suoi semi. **Dralyxor** garantisce che ogni stringa offuscata utilizzi un insieme di parametri di cifratura fondamentalmente unico.

#### Fonti di Entropia per il `compile_time_seed`

La `static constexpr uint64_t Obfuscated_String::compile_time_seed` è il seme maestro per tutte le operazioni pseudo-casuali relative a quell'istanza della stringa. La sua generazione è ora condizionale, basata sulla presenza di una chiave fornita dall'utente:

- **Se una chiave è fornita dall'utente (usando `DRALYXOR_KEY` o `DRALYXOR_KEY_LOCAL`):**
   1. Il `key_literal` fornito viene trasformato in un hash a 64 bit in tempo di compilazione usando l'algoritmo FNV-1a.
   2. Questo hash diventa la base della `compile_time_seed`, combinato con `__COUNTER__` (per garantire l'unicità tra diversi usi della stessa chiave) e la dimensione della stringa.
      ```cpp
      // Logica semplificata
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      In questa modalità, la sicurezza dell'offuscamento dipende direttamente dalla forza e dalla segretezza della chiave fornita.

- **Se nessuna chiave è fornita (usando `DRALYXOR` o `DRALYXOR_LOCAL`):**
   - Il `compile_time_seed` viene generato utilizzando la combinazione dei seguenti fattori per massimizzare l'entropia e la variabilità:
      ```cpp
      // Dentro Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Componente 1: Variabilità tra compilazioni
          ((uint64_t)Instance_Counter << 32) ^        // Componente 2: Variabilità all'interno di una unità di compilazione
          storage_n;                                  // Componente 3: Variabilità basata sulla dimensione della stringa
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Le macro `__DATE__` (es: "Jan 01 2025") e `__TIME__` (es: "12:30:00") sono stringhe fornite dal pre-processore che cambiano ogni volta che il file viene compilato. L'hash FNV-1a di questi valori crea una base di seme che è diversa per ogni build del progetto.
   - **`Instance_Counter` (alimentato da `__COUNTER__` nella macro)**: La macro `__COUNTER__` è un contatore mantenuto dal pre-processore che si incrementa ogni volta che viene utilizzato all'interno di un'unità di compilazione. Passando questo come argomento di template, ogni uso della macro `DRALYXOR` o `DRALYXOR_LOCAL` risulterà in un `Instance_Counter` diverso e, quindi, in un `compile_time_seed` diverso, anche per stringhe letterali identiche nello stesso file sorgente.
   - **`storage_n` (dimensione della stringa)**: Anche la dimensione della stringa viene XORata, aggiungendo un ulteriore fattore di differenziazione.

Questo `compile_time_seed` (sia esso derivato dalla chiave dell'utente o generato automaticamente) viene quindi utilizzato come base per:
1. Generare il `micro_program_` (seminando il PRNG con `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Derivare la chiave di offuscamento per il `micro_program_` stesso (tramite `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Derivare la chiave di offuscamento per il `_content_checksum_obfuscated` (tramite `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Servire come `base_seed` per `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Semi Derivati per Trasformazioni di Contenuto

All'interno di `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Un `Constexpr_PRNG prng_operand_modifier(base_seed)` viene inizializzato. Per ogni carattere della stringa in trasformazione, `prng_operand_modifier.Key()` produce una `prng_key_for_ops_in_elem`. Questa chiave viene XORata con l'operando della micro-istruzione prima dell'applicazione, garantendo che l'effetto della stessa micro-istruzione sia sottilmente diverso per ogni carattere.
- Un `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` viene inizializzato. Per ogni carattere, `prng_applier_selector.Key()` viene utilizzato per scegliere tra `Applier_Style_Direct` e `Applier_Style_DoubleLayer`.

Ciò introduce un dinamismo aggiuntivo nella trasformazione di ogni carattere, anche se il micro-programma sottostante è lo stesso per tutti i caratteri di una data stringa.

#### Immunità Contro Attacchi di "Replay" e Analisi di Pattern

- **Unicità Inter-Compilazione:** Se un aggressore analizza il binario della versione 1.0 del tuo software e, con molto sforzo, riesce a rompere l'offuscamento di una stringa (in modalità a chiave automatica), questa conoscenza sarà probabilmente inutile per la versione 1.1, poiché `__DATE__ __TIME__` sarà cambiato, risultando in `compile_time_seed` e micro-programmi completamente diversi.
- **Unicità Intra-Compilazione:** Se usi `DRALYXOR("AdminPassword")` in due posti diversi nel tuo codice (o nello stesso file .cpp), `__COUNTER__` garantirà che gli oggetti `Obfuscated_String` risultanti, e quindi le loro rappresentazioni offuscate nel binario, siano diversi. Ciò impedisce a un aggressore di trovare un pattern offuscato e usarlo per localizzare tutte le altre occorrenze della stessa stringa originale.

Questa robusta generazione di semi è una pietra angolare della sicurezza di **Dralyxor** contro attacchi che dipendono dalla scoperta di un "segreto maestro" o dallo sfruttamento della ripetizione di cifre e trasformazioni.

## Riferimento Completo dell'API Pubblica

### Macro di Offuscamento

Questi sono i principali punti di ingresso per creare stringhe offuscate.

#### `DRALYXOR(str_literal)`

- **Scopo:** Crea un oggetto `Obfuscated_String` con durata statica (esiste per tutta l'esecuzione del programma). Ideale per costanti globali o stringhe che devono essere accessibili da più posizioni e persistere.
- **Archiviazione:** Memoria statica (di solito nella sezione dati del programma).
- **Implementazione:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parametri:**
   - `str_literal`: Un letterale di stringa in stile C (es., `"Hello World"`, `L"Unicode String"`).
- **Ritorno:** Un riferimento (`auto&`) all'oggetto `Obfuscated_String` statico, creato all'interno di una lambda immediatamente invocata.
- **Esempio:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url è un riferimento a un Obfuscated_String statico.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Scopo:** Crea un oggetto `Obfuscated_String` con durata automatica (di solito sullo stack, se usato all'interno di una funzione). Ideale per segreti temporanei confinati a un ambito.
- **Archiviazione:** Automatica (stack per variabili locali di funzione).
- **Implementazione:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Parametri:**
   - `str_literal`: Un letterale di stringa in stile C.
- **Ritorno:** Un oggetto `Obfuscated_String` per valore (che può essere ottimizzato con RVO/NRVO dal compilatore).
- **Esempio:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... usare temp_key con DRALYXOR_SECURE ...
   } // temp_key viene distrutto qui, il suo distruttore chiama Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Scopo:** Simile a `DRALYXOR`, crea un oggetto `Obfuscated_String` statico, ma usa una **chiave fornita dall'utente** (`key_literal`) per seminare l'offuscamento, offrendo il massimo livello di sicurezza.
- **Archiviazione:** Memoria statica (di solito nella sezione dati del programma).
- **Implementazione:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parametri:**
   - `str_literal`: Il letterale di stringa da offuscare.
   - `key_literal`: Il letterale di stringa da usare come chiave segreta.
- **Ritorno:** Un riferimento (`auto&`) all'oggetto statico `Obfuscated_String`.
- **Esempio:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Scopo:** Simile a `DRALYXOR_LOCAL`, crea un oggetto `Obfuscated_String` sullo stack, usando una **chiave fornita dall'utente**.
- **Archiviazione:** Automatica (stack per variabili locali di funzione).
- **Implementazione:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parametri:**
   - `str_literal`: Il letterale di stringa da offuscare.
   - `key_literal`: Il letterale di stringa da usare come chiave.
- **Ritorno:** Un oggetto `Obfuscated_String` per valore.
- **Esempio:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Macro di Accesso Sicuro

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Scopo:** Fornisce un accesso sicuro e temporaneo al contenuto decifrato di un oggetto `Obfuscated_String`. Questo è il **solo metodo raccomandato** per leggere la stringa.
- **Implementazione:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parametri:**
   - `obfuscated_var`: Una variabile (lvalue o rvalue che può essere collegato a un riferimento lvalue non-const) di tipo `Dralyxor::Obfuscated_String<...>`. La variabile deve essere mutabile perché il costruttore del `Secure_Accessor` chiama `Decrypt()` e `Encrypt()` su di essa.
- **Ritorno:** Un oggetto `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` per valore.
- **Uso:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // O semplicemente: const char* secret_ptr = accessor; (conversione implicita)
       
       if (secret_ptr) {
           // Usa secret_ptr qui. Punta alla stringa decifrata temporaneamente nel buffer dell'accessor.
           // Es: send_data(secret_ptr);
       }
       else {
           // Fallimento nella decrittografia o integrità. Gestire l'errore.
           // L'accessor potrebbe aver fallito nell'inizializzazione (es. my_static_secret è stato corrotto).
       }
   } // accessor viene distrutto. I suoi buffer interni (frammenti e stringa ricostruita) vengono puliti.
    // my_static_secret.storage_ è già stato ri-offuscato dal costruttore del Secure_Accessor
    // subito dopo aver copiato il contenuto nei frammenti dell'accessor.
   ```

> [!WARNING]
> Verificare sempre che il puntatore restituito da `DRALYXOR_SECURE(...).Get()` (o dalla conversione implicita) non sia `nullptr` prima di utilizzarlo. Un ritorno `nullptr` indica un fallimento nella decifratura (ad esempio, rilevamento di un debugger, corruzione di canary/checksum nell' `Obfuscated_String` genitore o nel `Secure_Accessor` stesso). L'uso di un puntatore `nullptr` risulterà in un comportamento indefinito (probabilmente un segmentation fault).

## Funzionalità Avanzate e Buone Pratiche

### Supporto Completo a Unicode (Wide Strings - `wchar_t`)

**Dralyxor** è agnostico al tipo di carattere grazie all'uso di template (`CharT`). Gestisce nativamente `char` (per stringhe ASCII/UTF-8) e `wchar_t` (per stringhe UTF-16 su Windows o UTF-32 su altri sistemi, a seconda della piattaforma e del compilatore). Basta usare il prefisso `L` per i letterali `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Messaggio Unicode: Ciao Mondo Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Esempio su Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Titolo Unicode", MB_OK);
        // Esempio con wcout:
        // #include <io.h> // Per _setmode su Windows con MSVC
        // #include <fcntl.h> // Per _O_U16TEXT su Windows con MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Imposta stdout a UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Per caratteri di 1 byte (`sizeof(CharT) == 1`), il motore di trasformazione `Micro_Program_Cipher` applica il micro-programma byte per byte. Per caratteri multibyte (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` utilizza un approccio più semplice: l'intero carattere multibyte viene XORato con una maschera derivata dalla `prng_key_for_ops_in_elem` (replicata per riempire la dimensione di `CharT`). Ad esempio, se `CharT` è `wchar_t` (2 byte) e `prng_key_for_ops_in_elem` è `0xAB`, il carattere sarà XORato con `0xABAB`.
Ciò garantisce che tutti i byte del `wchar_t` siano influenzati dall'offuscamento, anche se non dal micro-programma completo. La complessità del micro-programma contribuisce ancora indirettamente attraverso la derivazione delle chiavi del PRNG.

### Adattamento Intelligente agli Standard **C++** e agli Ambienti (Kernel Mode)

Come menzionato, **Dralyxor** si adatta:
- **Standard C++:** Richiede almeno **C++14**. Rileva e utilizza funzionalità di **C++17** e **C++20** (come `if constexpr`, `consteval`, suffissi `_v` per `type_traits`) quando il compilatore li supporta, ricorrendo ad alternative **C++14** in caso contrario. Macro come `_DRALYXOR_IF_CONSTEXPR` e `_DRALYXOR_CONSTEVAL` in `detection.hpp` gestiscono questo adattamento.
- **Kernel Mode:** Quando `_KERNEL_MODE` è definito (tipico nei progetti WDK per driver di Windows), **Dralyxor** (tramite `env_traits.hpp`) evita di includere header standard della STL come `<type_traits>` che potrebbero non essere disponibili o comportarsi in modo diverso. Invece, utilizza le proprie implementazioni `constexpr` di strumenti di base come `Dralyxor::Detail::Fallback::decay` e `Dralyxor::Detail::Fallback::remove_reference`. Ciò permette l'uso sicuro di **Dralyxor** per proteggere stringhe in componenti di sistema a basso livello.
   - Similarmente, `secure_memory.hpp` usa `RtlSecureZeroMemory` in Kernel Mode. Per altre piattaforme, come Linux, ricorre all'uso sicuro di `memset` per garantire la pulizia della memoria, adattandosi per essere compatibile con diversi tipi di dati.
   - Le verifiche anti-debug di User Mode (come `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) sono disabilitate (`#if !defined(_KERNEL_MODE)`) in Kernel Mode, poiché non si applicano o hanno equivalenti diversi. I controlli di timing possono ancora avere qualche effetto, ma la principale linea di difesa in Kernel Mode è l'offuscamento stesso.

### Considerazioni sulle Prestazioni e Overhead

- **Tempo di Compilazione:** L'offuscamento, inclusa la generazione e l'applicazione di micro-programmi, avviene interamente a tempo di compilazione. Per progetti con un numero molto elevato di stringhe offuscate, il tempo di compilazione può aumentare. Questo è un costo una tantum per compilazione.
- **Dimensione del Binario:** Ogni `Obfuscated_String` aggiunge il suo `storage_` (dimensione della stringa), il `micro_program_` (fisso a `max_micro_instructions * sizeof(Micro_Instruction)`), più alcuni byte per canary, checksum e flag. Potrebbe esserci un aumento della dimensione del binario rispetto a stringhe letterali pure, specialmente per molte stringhe piccole.
- **Tempo di Esecuzione (Runtime):**
   - **Creazione di `Obfuscated_String` (oggetti statici o locali):** Avviene a tempo di compilazione (per statici) o comporta una copia di dati pre-calcolati (per locali, ottimizzabile da RVO). Non c'è costo di "generazione" a runtime.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Verifiche dei canary (estremamente rapide).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Include i controlli anti-debug. Il controllo di timing (`Perform_Timing_Check_Generic`) è il più costoso qui, eseguendo un loop. Gli altri sono chiamate API o letture di file (Linux).
      - De-offuscamento del micro-programma (copia e XOR, rapido).
      - Trasformazione della stringa: Loop su `N_data_elements_to_transform`, e al suo interno, loop su `num_actual_instructions_in_program_`. Per ogni istruzione, una chiamata a `Byte_Transform_Applier` che esegue alcune operazioni sui byte. Il costo è O(lunghezza\_della\_stringa \* num\_istruzioni).
      - Calcolo/Verifica del checksum (`Detail::Calculate_String_Content_Checksum`): O(lunghezza\_della\_stringa \* sizeof(CharT)).
   - **Creazione di `Secure_Accessor`:**
      - Chiama `Obfuscated_String::Decrypt()`.
      - Copia la stringa nei frammenti: O(lunghezza\_della\_stringa).
      - Calcola il checksum dei frammenti (`Calculate_Current_Fragments_Checksum`): O(lunghezza\_della\_stringa).
      - Chiama `Obfuscated_String::Encrypt()`. Questo è il punto di maggiore concentrazione di overhead in una singola operazione di accesso.
   - **`Secure_Accessor::Get()`:**
      - Prima chiamata: Verifica i canary, ricostruisce la stringa dai frammenti (O(lunghezza\_della\_stringa)), verifica il checksum dei frammenti.
      - Chiamate successive (per lo stesso oggetto `Secure_Accessor`): Verifica i canary (rapido) e restituisce il puntatore già calcolato (O(1)).
- **Overhead Generale:** Per la maggior parte delle applicazioni, dove le stringhe sensibili non sono accessibili in loop ad altissima frequenza, l'overhead di runtime è generalmente accettabile, specialmente considerando il beneficio in termini di sicurezza. Il design di `Secure_Accessor` (creato solo quando necessario e con ambito strettamente limitato da RAII) è fondamentale per gestire questo costo. Testate nel vostro ambiente specifico se le prestazioni sono critiche.

### Integrazione in una Strategia di Sicurezza a Strati

> [!IMPORTANT]
> **Dralyxor** è uno strumento potente per l'**offuscamento di stringhe incorporate e la difesa contro l'analisi della memoria**, non una soluzione di crittografia generica per l'archiviazione persistente di dati su disco o la trasmissione sicura sulla rete.
>
> Dovrebbe essere usato come **uno dei molti strati** in una strategia di sicurezza completa. Nessuno strumento isolato è una soluzione miracolosa. Altre misure da considerare includono:
> - **Minimizzare i Segreti Incorporati:** Ove possibile, evitate di incorporare segreti di altissima criticità. Utilizzate alternative come:
>    - Configurazioni sicure fornite a runtime (variabili d'ambiente, file di configurazione con permessi ristretti).
>    - Servizi di gestione dei segreti (vault) come HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Validazione robusta dell'input su tutte le interfacce.
> - Principio del privilegio minimo per processi e utenti.
> - Comunicazione di rete sicura (TLS/SSL con pinning del certificato, se applicabile).
> - Hashing sicuro delle password utente (Argon2, scrypt, bcrypt).
> - Protezione del binario nel suo complesso con altre tecniche anti-reversing/anti-tampering (packer, virtualizzatori di codice, verifiche di integrità del codice), consapevoli dei compromessi che queste possono introdurre (falsi positivi degli antivirus, complessità).
> - Buone pratiche di sviluppo sicuro (Secure SDLC).

**Dralyxor** si concentra sulla risoluzione molto efficace di un problema specifico e comune: la protezione delle stringhe letterali incorporate contro l'analisi statica e la minimizzazione della loro esposizione in memoria durante l'esecuzione, rendendo la vita più difficile a chi tenta di fare ingegneria inversa sul vostro software.

## Licenza

Questa libreria è protetta dalla Licenza MIT, che permette:

- ✔️ Uso commerciale e privato
- ✔️ Modifica del codice sorgente
- ✔️ Distribuzione del codice
- ✔️ Sublicenziamento

### Condizioni:

- Mantenere l'avviso di copyright
- Includere una copia della licenza MIT

Per maggiori dettagli sulla licenza: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Tutti i diritti riservati**