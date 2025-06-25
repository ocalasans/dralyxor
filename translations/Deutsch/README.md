# Dralyxor

**Dralyxor** ist eine moderne, `header-only`, hochleistungsfähige und mehrschichtige **C++**-Bibliothek, entwickelt für die String-Obfuskation zur Kompilierzeit und robusten Laufzeitschutz. Ihre grundlegende Mission ist es, die intrinsischen Geheimnisse Ihrer Anwendung – wie API-Schlüssel, Passwörter, interne URLs, Debug-Nachrichten und jegliche sensible String-Literale – vor der Offenlegung durch statische Analyse, Reverse Engineering und dynamische Speicherinspektion zu schützen. Durch die Verschlüsselung und Transformation der Strings zum Zeitpunkt der Kompilierung und die sichere Verwaltung ihres Zugriffs zur Laufzeit stellt **Dralyxor** sicher, dass keine kritischen String-Literale als Klartext in Ihrer finalen Binärdatei existieren oder länger als unbedingt notwendig ungeschützt im Speicher verbleiben.

Aufgebaut auf den Grundlagen des modernen **C++** (benötigt **C++14** und passt sich intelligent an Funktionen von **C++17** und **C++20** an), präsentiert seine fortschrittliche Architektur eine ausgeklügelte Transformations-Engine basierend auf "Mikroprogrammen", Obfuskation des Transformationsprogramms selbst, Datenintegritätsmechanismen, Anti-Debugging-Abwehrmaßnahmen und einen **Sicheren Bereichs-Accessor (RAII)** für eine "Just-in-Time"-Entschlüsselung und automatische Re-Obfuskation. Dies minimiert drastisch die Exposition von Daten im **RAM** und bietet eine professionelle Tiefenverteidigung.

## Sprachen

- Português: [README](../../)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Inhaltsverzeichnis

- [Dralyxor](#dralyxor)
  - [Sprachen](#sprachen)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [Schnellanleitung zur Integration und Verwendung](#schnellanleitung-zur-integration-und-verwendung)
    - [Installation](#installation)
    - [Compiler-Anforderungen](#compiler-anforderungen)
    - [Wesentliche Verwendungsmuster](#wesentliche-verwendungsmuster)
      - [Muster 1: Lokale Obfuskation (Stack)](#muster-1-lokale-obfuskation-stack)
      - [Muster 2: Statische Obfuskation (Global)](#muster-2-statische-obfuskation-global)
    - [Fehlerbehandlung und Integrität](#fehlerbehandlung-und-integrität)
  - [Detaillierte Designphilosophie und Architektur](#detaillierte-designphilosophie-und-architektur)
    - [Die persistente Bedrohung: Schwachstelle von String-Literalen](#die-persistente-bedrohung-schwachstelle-von-string-literalen)
    - [Die mehrschichtige Architekturlösung von **Dralyxor**](#die-mehrschichtige-architekturlösung-von-dralyxor)
  - [Tiefergehende Analyse der Architekturkomponenten](#tiefergehende-analyse-der-architekturkomponenten)
    - [Komponente 1: Die Transformations-Engine durch Mikroprogramm](#komponente-1-die-transformations-engine-durch-mikroprogramm)
      - [Die Macht von `consteval` und `constexpr` für die Kompilierzeit-Generierung](#die-macht-von-consteval-und-constexpr-für-die-kompilierzeit-generierung)
      - [Anatomie eines **Dralyxor**-Mikroprogramms](#anatomie-eines-dralyxor-mikroprogramms)
        - [Randomisierte Generierung von Instruktionen und Auswahl von Anwendern](#randomisierte-generierung-von-instruktionen-und-auswahl-von-anwendern)
        - [Variable und logische NOPs für Entropie](#variable-und-logische-nops-für-entropie)
      - [Obfuskation des Mikroprogramms selbst](#obfuskation-des-mikroprogramms-selbst)
      - [Der Lebenszyklus der statischen Obfuskation](#der-lebenszyklus-der-statischen-obfuskation)
    - [Komponente 2: Sicherer Zugriff und Minimierung der Exposition im **RAM**](#komponente-2-sicherer-zugriff-und-minimierung-der-exposition-im-ram)
      - [Der `Secure_Accessor` und das RAII-Prinzip](#der-secure_accessor-und-das-raii-prinzip)
      - [Speicherfragmentierung im `Secure_Accessor`](#speicherfragmentierung-im-secure_accessor)
      - [Sichere Speicherbereinigung](#sichere-speicherbereinigung)
    - [Komponente 3: Laufzeitverteidigungen (Anti-Debugging und Anti-Tampering)](#komponente-3-laufzeitverteidigungen-anti-debugging-und-anti-tampering)
      - [Plattformübergreifende Erkennung von Debuggern](#plattformübergreifende-erkennung-von-debuggern)
      - [Auswirkungen auf den Betrieb bei Erkennung oder Integritätsverletzung](#auswirkungen-auf-den-betrieb-bei-erkennung-oder-integritätsverletzung)
      - [Integritäts-Canaries des Objekts](#integritäts-canaries-des-objekts)
      - [Inhalts-Checksumme des Strings](#inhalts-checksumme-des-strings)
    - [Komponente 4: Generierung einzigartiger und unvorhersehbarer Schlüssel und Seeds](#komponente-4-generierung-einzigartiger-und-unvorhersehbarer-schlüssel-und-seeds)
      - [Entropiequellen für den `compile_time_seed`](#entropiequellen-für-den-compile_time_seed)
      - [Abgeleitete Seeds für Inhaltstransformationen](#abgeleitete-seeds-für-inhaltstransformationen)
      - [Immunität gegen "Replay"-Angriffe und Musteranalyse](#immunität-gegen-replay-angriffe-und-musteranalyse)
  - [Vollständige Referenz der öffentlichen API](#vollständige-referenz-der-öffentlichen-api)
    - [Obfuskations-Makros](#obfuskations-makros)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Makro für sicheren Zugriff](#makro-für-sicheren-zugriff)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Erweiterte Funktionen und Best Practices](#erweiterte-funktionen-und-best-practices)
    - [Volle Unicode-Unterstützung (Wide Strings - `wchar_t`)](#volle-unicode-unterstützung-wide-strings---wchar_t)
    - [Intelligente Anpassung an **C++**-Standards und Umgebungen (Kernel Mode)](#intelligente-anpassung-an-c-standards-und-umgebungen-kernel-mode)
    - [Überlegungen zu Performance und Overhead](#überlegungen-zu-performance-und-overhead)
    - [Integration in eine mehrschichtige Sicherheitsstrategie](#integration-in-eine-mehrschichtige-sicherheitsstrategie)
  - [Lizenz](#lizenz)
    - [Bedingungen:](#bedingungen)

## Schnellanleitung zur Integration und Verwendung

### Installation

**Dralyxor** ist eine `header-only`-Bibliothek. Keine vorherige Kompilierung oder Verknüpfung von Bibliotheken (`.lib`/`.a`) ist erforderlich.

1.  **Kopieren Sie das Verzeichnis `Dralyxor`:** Holen Sie sich die neueste Version der Bibliothek (klonen Sie das Repository oder laden Sie das Zip herunter) und kopieren Sie das gesamte Verzeichnis `Dralyxor` (das alle `.hpp`-Dateien enthält) an einen Ort, der von Ihrem Projekt aus zugänglich ist (z. B. ein Ordner `libs/`, `libraries/` oder `vendor/`).
2.  **Fügen Sie den Haupt-Header ein:** In Ihrem Quellcode fügen Sie den Haupt-Header `dralyxor.hpp` ein:
    ```cpp
    #include "pfad/zu/Dralyxor/dralyxor.hpp"
    ```

Eine typische Projektstruktur:
```
/MeinProjekt/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor hier
        |-- dralyxor.hpp            (Haupteinstiegspunkt)
        |-- obfuscated_string.hpp   (Klasse Obfuscated_String)
        |-- secure_accessor.hpp     (Klasse Secure_Accessor)
        |-- algorithms.hpp          (Transformations-Engine und Mikroprogramme)
        |-- anti_debug.hpp          (Laufzeiterkennungen)
        |-- prng.hpp                (Pseudozufallszahlengenerator zur Kompilierzeit)
        |-- integrity_constants.hpp (Konstanten für Integritätsprüfungen)
        |-- secure_memory.hpp       (Sichere Speicherbereinigung)
        |-- detection.hpp           (Makros zur Erkennung von Compiler/C++ Standard)
        `-- env_traits.hpp          (Anpassungen von type_traits für eingeschränkte Umgebungen)
```

### Compiler-Anforderungen

> [!IMPORTANT]
> **Dralyxor** wurde mit Fokus auf modernes **C++** für maximale Sicherheit und Effizienz zur Kompilierzeit entwickelt.
>
> - **Mindest-C++-Standard: C++14**. Die Bibliothek verwendet Funktionen wie generalisiertes `constexpr` und passt sich an `if constexpr` an (wenn über `_DRALYXOR_IF_CONSTEXPR` verfügbar).
> - **Anpassung an höhere Standards:** Erkennt und verwendet Optimierungen oder Syntaxen von **C++17** und **C++20** (wie `consteval`, Suffixe `_v` für `type_traits`), wenn das Projekt mit diesen Standards kompiliert wird. `_DRALYXOR_CONSTEVAL` bildet auf `consteval` in C++20 und `constexpr` in C++14/17 ab und gewährleistet die Ausführung zur Kompilierzeit, wo immer möglich.
> - **Unterstützte Compiler:** Primär getestet mit aktuellen Versionen von MSVC, GCC und Clang.
> - **Ausführungsumgebung:** Voll kompatibel mit **User Mode**-Anwendungen und **Kernel Mode**-Umgebungen (z. B. Windows-Treiber). Im Kernel Mode, wo die STL möglicherweise nicht verfügbar ist, verwendet **Dralyxor** interne Implementierungen für notwendige `type traits` (siehe `env_traits.hpp`).

### Wesentliche Verwendungsmuster

#### Muster 1: Lokale Obfuskation (Stack)

Ideal für temporäre Strings, die auf einen Funktionsbereich beschränkt sind. Der Speicher wird automatisch verwaltet und bereinigt.

```cpp
#include "Dralyxor/dralyxor.hpp" // Passen Sie den Pfad bei Bedarf an
#include <iostream>

void Configure_Logging() {
    // Log-Formatierungsschlüssel, nur lokal verwendet.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Sicherer Zugriff innerhalb eines begrenzten Bereichs
    {
        // Der Secure_Accessor entschlüsselt 'log_format_key' temporär während seiner Konstruktion
        // (und re-obfuskiert 'log_format_key' sofort nach dem Kopieren in seine internen Puffer),
        // ermöglicht den Zugriff und bereinigt seine eigenen Puffer bei der Zerstörung.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Immer prüfen, ob Get() nicht nullptr zurückgibt
            std::cout << "Verwende Log-Format: " << accessor.Get() << std::endl;
            // Bsp.: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Fehler beim Entschlüsseln von log_format_key (möglicherweise Tampering oder Debugger-Erkennung?)" << std::endl;
    } // accessor wird zerstört, seine internen Puffer werden bereinigt. log_format_key bleibt obfuskiert.
      // log_format_key wird am Ende der Funktion Configure_Logging zerstört.
}
```

#### Muster 2: Statische Obfuskation (Global)

Für Konstanten, die während der gesamten Lebensdauer des Programms bestehen bleiben und global zugänglich sein müssen.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Für das Beispiel

// URL der Lizenz-API, ein persistentes Geheimnis.
// Das Makro DRALYXOR() erstellt ein statisches Objekt.
// Die Funktion Get_License_Server_URL() gibt eine Referenz auf dieses statische Objekt zurück.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref ist eine Referenz auf den statischen Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Erstellt einen Secure_Accessor für url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Kontaktiere Lizenzserver unter: " << accessor.Get() << std::endl;
            // Bsp.: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulation von Erfolg für das Beispiel
        }
        else
            std::cerr << "Fehler beim Entschlüsseln der Lizenzserver-URL (möglicherweise Tampering oder Debugger-Erkennung?)." << std::endl;
    } // accessor wird zerstört, seine Puffer werden bereinigt. url_obj_ref (der ursprüngliche Obfuscated_String) bleibt obfuskiert.

    return success;
}
```

### Fehlerbehandlung und Integrität

Die Funktionen `Obfuscated_String::Decrypt()` und `Encrypt()` geben `uint64_t` zurück:
- `0` zeigt Erfolg an.
- `Dralyxor::Detail::integrity_compromised_magic` (ein konstanter Wert, definiert in `integrity_constants.hpp`) zeigt an, dass eine Integritätsprüfung fehlgeschlagen ist. Dies kann auf korrupte Objekt-Canaries, eine inkonsistente Inhalts-Checksumme oder die Erkennung eines Debuggers zurückzuführen sein, die eine feindliche Umgebung signalisiert.

Ebenso gibt `Secure_Accessor::Get()` (oder seine implizite Konvertierung in `const CharT*`) `nullptr` zurück, wenn die Initialisierung des `Secure_Accessor` fehlschlägt (z. B. wenn die Entschlüsselung des ursprünglichen `Obfuscated_String` fehlschlägt) oder wenn die Integrität des `Secure_Accessor` (seine eigenen Canaries oder internen Checksummen) während seiner Lebensdauer kompromittiert wird.

**Es ist entscheidend, dass Ihr Code diese Rückgabewerte überprüft, um die Robustheit und Sicherheit der Anwendung zu gewährleisten.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Normalerweise würden Sie Decrypt() und Encrypt() NICHT direkt aufrufen,
    // da der Secure_Accessor dies verwaltet. Aber wenn Sie es aus irgendeinem Grund tun müssen:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "WARNUNG: Fehler beim Entschlüsseln von 'my_secret' oder Integrität während Decrypt() kompromittiert!" << std::endl;
        // Ergreifen Sie geeignete Maßnahmen: Beenden, sicher protokollieren usw.
        // Das Objekt my_secret.storage_ könnte sich in einem ungültigen Zustand befinden oder Müll enthalten.
        return; // Vermeiden Sie die Verwendung von my_secret, wenn Decrypt() fehlschlägt.
    }

    // Wenn Decrypt() erfolgreich war, enthält my_secret.storage_ die entschlüsselten Daten.
    // **DIREKTER ZUGRIFF AUF storage_ WIRD IN PRODUKTIONSUMGEBUNGEN STARK ABGERATEN.**
    // std::cout << "Daten in my_secret.storage_ (TUN SIE DAS NICHT): " << my_secret.storage_ << std::endl;

    // Es liegt in Ihrer Verantwortung, erneut zu verschlüsseln, wenn Sie Decrypt() manuell aufgerufen haben:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "WARNUNG: Fehler beim erneuten Verschlüsseln von 'my_secret' oder Integrität während Encrypt() kompromittiert!" << std::endl;
        // Unsicherer Zustand, potenziell gefährlich.
    }

    // EMPFOHLENE VERWENDUNG mit Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Der Konstruktor des Secure_Accessor ruft another_secret.Decrypt() auf, kopiert und dann another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Oder: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Geheime Daten über Secure_Accessor: " << data_ptr << std::endl;
            // Verwenden Sie data_ptr hier
        }
        else {
            std::cerr << "WARNUNG: Secure_Accessor konnte nicht initialisiert werden oder Zeiger für 'another_secret' nicht erhalten!" << std::endl;
            // Dies deutet darauf hin, dass Decrypt() im Konstruktor des Accessors fehlgeschlagen ist,
            // oder es gab Tampering am Accessor (Canaries, interne Checksummen).
        }
    } // accessor wird zerstört. Seine Puffer werden bereinigt. another_secret bleibt obfuskiert.
}
```

## Detaillierte Designphilosophie und Architektur

**Dralyxor** ist nicht nur eine XOR-Chiffre; es ist ein tiefgreifendes Verteidigungssystem für String-Literale. Seine Architektur basiert auf der Prämisse, dass effektive Sicherheit mehrere miteinander verbundene Schichten und Widerstandsfähigkeit gegen verschiedene Analysetechniken erfordert.

### Die persistente Bedrohung: Schwachstelle von String-Literalen

String-Literale wie `"api.example.com/data?key="`, wenn direkt in den Code eingebettet, werden lesbar (Klartext) in die kompilierte Binärdatei geschrieben. Werkzeuge wie `strings`, Disassembler (IDA Pro, Ghidra) und Hex-Editoren können sie trivial extrahieren. Diese Exposition erleichtert:
- **Reverse Engineering:** Verständnis der internen Logik und des Programmflusses.
- **Identifizierung von Endpunkten:** Entdeckung von Backend-Servern und APIs.
- **Extraktion von Geheimnissen:** API-Schlüssel, eingebettete Passwörter, private URLs, SQL-Abfragen usw.
- **Dynamische Speicheranalyse:** Selbst wenn ein Programm einen String zur Verwendung entschlüsselt, kann ein Angreifer mit Zugriff auf den Prozessspeicher (über einen Debugger oder einen Memory-Dump) ihn finden, wenn er zu lange im Klartext im **RAM** verbleibt.

**Dralyxor** bekämpft diese Schwachstellen sowohl zur Kompilierzeit (für die Binärdatei auf der Festplatte) als auch zur Laufzeit (für den **RAM**-Speicher).

### Die mehrschichtige Architekturlösung von **Dralyxor**

Die Robustheit von **Dralyxor** ergibt sich aus der Synergie seiner Schlüsselkomponenten:

| Architekturkomponente                        | Hauptziel                                                                                   | Hauptsächlich eingesetzte Technologien/Techniken                                                                                                                              |
| :------------------------------------------- | :------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Transformations-Engine durch Mikroprogramm** | Beseitigung von Klartext-Strings aus der Binärdatei; Erstellung komplexer, dynamischer und nicht-trivialer Obfuskation. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, mehrere Operationen (XOR, ADD, ROT usw.), variable und logische NOPs, variable Anwenderstile.          |
| **Sicherer Zugriff und Minimierung der Exposition** | Drastische Reduzierung der Zeit, die ein Geheimnis entschlüsselt im RAM verbleibt.             | RAII-Muster (`Secure_Accessor`), Speicherfragmentierung, sichere Pufferbereinigung (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                   |
| **Laufzeitverteidigungen**                   | Erkennung und Reaktion auf feindliche Analyseumgebungen und Speichermanipulation.         | Debugger-Erkennung (OS-spezifische APIs, Timing, OutputDebugString), Objektintegritäts-Canaries, Inhalts-Checksumme des Strings.                              |
| **Generierung einzigartiger Schlüssel und Seeds** | Sicherstellung, dass jeder obfuskierte String und jede Verwendungsinstanz kryptografisch verschieden sind. | `__DATE__`, `__TIME__`, `__COUNTER__`, Stringlänge, FNV-1a-Hashing für `compile_time_seed`, abgeleitete Seeds für Operandenmodifikatoren und Selektoren. |

## Tiefergehende Analyse der Architekturkomponenten

### Komponente 1: Die Transformations-Engine durch Mikroprogramm

Das Herzstück der statischen und dynamischen Obfuskation von **Dralyxor** liegt in seiner Transformations-Engine, die für jeden String und Kontext einzigartige "Mikroprogramme" verwendet.

#### Die Macht von `consteval` und `constexpr` für die Kompilierzeit-Generierung
Modernes **C++**, mit `consteval` (**C++20**) und `constexpr` (**C++11** und später), ermöglicht die Ausführung komplexen Codes *während der Kompilierung*. **Dralyxor** verwendet `_DRALYXOR_CONSTEVAL` (das je nach **C++**-Standard auf `consteval` oder `constexpr` abgebildet wird) für den `Obfuscated_String`-Konstruktor und für die Generierung des Mikroprogramms.

Das bedeutet, der gesamte Prozess von:
1. Generierung einer pseudozufälligen Sequenz von Transformationsanweisungen (dem Mikroprogramm).
2. Obfuskation des Mikroprogramms selbst zur Speicherung.
3. Anwendung dieses Mikroprogramms (temporär de-obfuskiert), um den ursprünglichen String zu transformieren, was zu seiner obfuskierten Form führt.
All dies geschieht zur Kompilierzeit, bevor die Binärdatei generiert wird.

#### Anatomie eines **Dralyxor**-Mikroprogramms

Jedes `Obfuscated_String`-Objekt speichert ein kleines Array von `Dralyxor::Detail::Micro_Instruction`. Eine `Micro_Instruction` ist eine einfache Struktur, definiert in `algorithms.hpp`:
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
    END_OF_PROGRAM // Obwohl vorhanden, wird es nicht aktiv verwendet, um die Ausführung des Mikroprogramms zu beenden,
                   // die Iteration wird durch 'num_actual_instructions_in_program_' gesteuert.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // Die Operation (XOR, ADD, ROTL usw.)
    uint8_t operand;            // Der von der Operation verwendete Wert
};

// Maximale Anzahl von Instruktionen, die ein Mikroprogramm enthalten kann.
static constexpr size_t max_micro_instructions = 8;
```
Die Funktion `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` ist für das Füllen dieses Arrays verantwortlich.

##### Randomisierte Generierung von Instruktionen und Auswahl von Anwendern

- **Instruktionsgenerierung:** Unter Verwendung eines `Dralyxor::Detail::Constexpr_PRNG` (initialisiert mit einer Kombination aus `compile_time_seed` und `0xDEADBEEFC0FFEEULL`) wählt die Funktion `Generate_Micro_Program_Instructions` probabilistisch eine Sequenz von Operationen aus:
    - `XOR`: Bitweises XOR mit dem Operanden.
    - `ADD`: Modulare Addition mit dem Operanden.
    - `SUB`: Modulare Subtraktion mit dem Operanden.
    - `ROTR`/`ROTL`: Bitrotation. Der Operand (nach Modulo) definiert die Anzahl der Shifts (1 bis 7).
    - `SWAP_NIB`: Tauscht die unteren 4 Bits mit den oberen 4 Bits eines Bytes (Operand wird ignoriert).
    Die Operanden für diese Instruktionen werden ebenfalls pseudozufällig vom PRNG generiert.

- **Modifikation von Operanden und Auswahl von Anwendern zur Transformationszeit:** Während der Anwendung des Mikroprogramms (durch `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), sowohl bei der initialen Obfuskation als auch bei der Laufzeit-Deobfuskation:
    - Ein `Constexpr_PRNG prng_operand_modifier` (initialisiert mit `base_seed`) generiert für jedes Zeichen des Strings einen `prng_key_for_ops_in_elem`. Der Operand der Mikroinstruktion (`instr_orig.operand`) wird vor seiner Verwendung mit diesem Schlüssel XOR-verknüpft. Dies stellt sicher, dass dasselbe Mikroprogramm leicht unterschiedliche Transformationen für jedes Zeichen anwendet.
    - Ein `Constexpr_PRNG prng_applier_selector` (initialisiert mit `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) wählt für jedes Zeichen einen `Byte_Transform_Applier` aus. Derzeit gibt es zwei Stile:
        - `Applier_Style_Direct`: Wendet die Operation direkt an (invertiert sie zur Entschlüsselung, z. B. wird ADD zu SUB).
        - `Applier_Style_DoubleLayer`: Wendet die Operation zweimal an (oder die Operation und ihre Inverse, je nach Verschlüsselungs-/Entschlüsselungsmodus) mit unterschiedlichen Operanden, was die Umkehrung etwas komplexer zu analysieren macht.

##### Variable und logische NOPs für Entropie

Um die Schwierigkeit der manuellen Analyse des Mikroprogramms zu erhöhen, fügt **Dralyxor** ein:
- **Explizite NOPs:** `Micro_Operation_Code::NOP`-Instruktionen, die nichts tun.
- **Logische NOPs:** Paare von Instruktionen, die sich gegenseitig aufheben, wie `ADD K` gefolgt von `SUB K`, oder `ROTL N_BITS` gefolgt von `ROTR N_BITS`. Der im Paar verwendete Operand ist derselbe.

Diese NOPs werden probabilistisch von `Generate_Micro_Program_Instructions` eingefügt, füllen das `micro_program_`-Array und erschweren es, die effektiven Transformationen von den "Rausch"-Operationen zu unterscheiden.

#### Obfuskation des Mikroprogramms selbst

Nach der Generierung des Mikroprogramms und vor der initialen Obfuskation des Strings im `consteval`-Konstruktor wird das Array `micro_program_` (im `Obfuscated_String`-Objekt enthalten) selbst obfuskiert. Jeder `op_code` und `operand` in jeder `Micro_Instruction` wird mit einem Schlüssel XOR-verknüpft, der vom `compile_time_seed` abgeleitet ist (unter Verwendung von `Detail::Get_Micro_Program_Obfuscation_Key` und `Detail::Obfuscate_Deobfuscate_Instruction`).
Das bedeutet, selbst wenn ein Angreifer den Speicher des `Obfuscated_String`-Objekts dumpen kann, wird das Mikroprogramm nicht in seiner direkt lesbaren/anwendbaren Form vorliegen.

Wenn `Obfuscated_String::Decrypt()` oder `Encrypt()` aufgerufen werden (oder indirekt durch den `Secure_Accessor`), erhält die zentrale Funktion `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` dieses *obfuskierte* Mikroprogramm. Sie tut dann Folgendes:
1. Erstellt eine temporäre Kopie des Mikroprogramms (`local_plain_program`) auf dem Stack.
2. De-obfuskiert diese lokale Kopie unter Verwendung desselben Schlüssels (`program_obf_key`), der vom übergebenen Basis-Seed abgeleitet ist (der letztendlich der `compile_time_seed` ist).
3. Verwendet dieses `local_plain_program`, um die Stringdaten zu transformieren.
Die lokale Kopie auf dem Stack wird am Ende der Funktion zerstört, und das im `Obfuscated_String`-Objekt gespeicherte `micro_program_` bleibt obfuskiert.

#### Der Lebenszyklus der statischen Obfuskation

1.  **Quellcode:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2.  **Präprozessierung:** Das Makro expandiert zu einer Instanziierung `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (Die Größe 15 beinhaltet den Nullterminator).
3.  **`_DRALYXOR_CONSTEVAL`-Auswertung:**
    - Der Compiler führt den `Obfuscated_String`-Konstruktor aus.
    - `Initialize_Internal_Canaries()` setzt die Integritäts-Canaries.
    - `Generate_Micro_Program_Instructions()` (initialisiert mit `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) erstellt eine Sequenz von `Micro_Instruction` und speichert sie in `this->micro_program_` (z. B. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Die tatsächliche Anzahl der Instruktionen wird in `num_actual_instructions_in_program_` gespeichert.
    - Der ursprüngliche String "SECRET\_API\_KEY" wird in `this->storage_` kopiert.
    - Eine Checksumme des ursprünglichen Strings "SECRET\_API\_KEY" (ohne Nullterminator) wird von `Detail::Calculate_String_Content_Checksum` berechnet und dann von `Detail::Obfuscate_Deobfuscate_Short_Value` (unter Verwendung von `compile_time_seed` und `content_checksum_obf_salt`) obfuskiert und in `this->_content_checksum_obfuscated` gespeichert.
    - `Obfuscate_Internal_Micro_Program()` wird aufgerufen: `this->micro_program_` wird an Ort und Stelle obfuskiert (jede Instruktion wird mit `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)` XOR-verknüpft).
    - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` wird aufgerufen. Diese Funktion:
        - Erstellt eine de-obfuskierte Kopie von `this->micro_program_` auf dem Stack.
        - Für jedes Zeichen in `storage_` (außer dem Nullterminator):
            - Generiert `prng_key_for_ops_in_elem` und wählt einen `Byte_Transform_Applier`.
            - Wendet die Sequenz von Mikroinstruktionen (aus der de-obfuskierten Kopie) auf das Zeichen an, unter Verwendung des Anwenders und des modifizierten Operanden.
        - Am Ende enthält `storage_` den obfuskierten String (z. B. `[CF, 3A, D1, ..., 0x00]`).
4.  **Codegenerierung:** Der Compiler reserviert Speicher für `api_key_obj` und initialisiert es direkt mit:
    - `storage_`: `[CF, 3A, D1, ..., 0x00]` (obfuskierter String).
    - `micro_program_`: Das *bereits obfuskierte* Mikroprogramm.
    - `_content_checksum_obfuscated`: Die Checksumme des ursprünglichen Inhalts, *obfuskiert*.
    - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Das Literal `"SECRET_API_KEY"` existiert nicht mehr in der Binärdatei.

### Komponente 2: Sicherer Zugriff und Minimierung der Exposition im **RAM**

#### Der `Secure_Accessor` und das RAII-Prinzip

Der Schutz zur Kompilierzeit ist nur die halbe Miete. Sobald der String verwendet werden muss, muss er entschlüsselt werden. Wenn dieser entschlüsselte String längere Zeit im **RAM**-Speicher verbleibt, wird er zu einem Ziel für dynamische Analysen (Memory-Dumps, Debugger).

**Dralyxor** begegnet dem mit dem `Dralyxor::Secure_Accessor`, einer Klasse, die das **RAII**-Muster (Resource Acquisition Is Initialization) implementiert:
- **Erworbene Ressource:** Der temporäre Zugriff auf den Klartext-String, fragmentiert und vom Accessor verwaltet.
- **Verwaltungsobjekt:** Die Instanz von `Secure_Accessor`.

```cpp
// In secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Initialisieren Sie unterschiedlich, um bei Nichtaktualisierung zu fehlschlagen
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalidiert den Accessor

            return;
        }

        // 1. Versucht, den ursprünglichen Obfuscated_String zu entschlüsseln.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Wenn die Entschlüsselung erfolgreich ist, kopieren Sie den Klartext-String in die internen Fragmente.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ ist jetzt im Klartext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val ist maximal 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Füllt den Rest des Fragmentpuffers mit Nullen
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksumme der Fragmente
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Re-verschlüsseln Sie SOFORT den ursprünglichen Obfuscated_String.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Bereinigt Fragmente und rekonstruierten Puffer.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Überprüft sich selbst und das Elternobjekt
            Clear_All_Internal_Buffers(); // Sicherheitsmaßnahme
            _accessor_integrity_canary1 = 0; // Invalidiert für zukünftige Zugriffe

            return nullptr;
        }

        if (!current_access_ptr_) { // Wenn es der erste Aufruf von Get() ist oder wenn er bereinigt wurde
            if constexpr (N_storage > 0) { // Rekonstruiert nur, wenn etwas zu rekonstruieren ist
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

                // Stellt Nullterminierung sicher, auch wenn N_storage genau gefüllt ist.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Für N_storage == 0 (leerer String, theoretisch), keine Checksummen
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Um die Prüfung zu bestehen

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // wenn N_storage 0 war, ist dies sicher, wenn der Puffer > 0 ist
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Überprüft erneut nach jeder internen Operation, um die Integrität zu gewährleisten.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Verwendungsfluss mit `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
    - Der Konstruktor von `Secure_Accessor` wird aufgerufen.
    - Er ruft `my_obfuscated_string.Decrypt()` auf. Dies beinhaltet das De-obfuskieren des `micro_program_` (in eine lokale Kopie), dessen Verwendung zur Entschlüsselung von `my_obfuscated_string.storage_` und die anschließende Überprüfung von Canaries und der Inhalts-Checksumme des entschlüsselten Inhalts gegen den erwarteten Wert.
    - Bei Erfolg wird der Inhalt von `my_obfuscated_string.storage_` (jetzt Klartext) kopiert und in die internen `fragments_storage_` des `Secure_Accessor` aufgeteilt.
    - Eine Checksumme der `fragments_storage_` (`fragments_data_checksum_expected_`) wird berechnet.
    - Entscheidend ist, dass `my_obfuscated_string.Encrypt()` *unmittelbar danach* aufgerufen wird, wodurch `my_obfuscated_string.storage_` wieder obfuskiert wird.
2. `const char* ptr = accessor.Get();` (oder `const char* ptr = accessor;` aufgrund der impliziten Konvertierung)
    - `Secure_Accessor::Get()` wird aufgerufen.
    - Er überprüft seine eigenen Integritäts-Canaries und die des übergeordneten `Obfuscated_String`.
    - Beim ersten Zugriff (`current_access_ptr_` ist `nullptr`) rekonstruiert er den vollständigen String in `reconstructed_plain_buffer_` aus den `fragments_storage_`.
    - Anschließend überprüft er `fragments_data_checksum_reconstructed_` gegen `fragments_data_checksum_expected_`, um sicherzustellen, dass die Fragmente während der Existenz des `Secure_Accessor` nicht manipuliert wurden.
    - Wenn alles korrekt ist, gibt er einen Zeiger auf `reconstructed_plain_buffer_` zurück.
3. Der Gültigkeitsbereich des `accessor` endet (Funktion wird verlassen, `{}`-Block endet usw.).
    - Der Destruktor von `Secure_Accessor` wird automatisch aufgerufen.
    - `Clear_All_Internal_Buffers()` wird aufgerufen, wodurch sowohl `reconstructed_plain_buffer_` als auch die `fragments_storage_` sicher bereinigt werden (`Secure_Clear_Memory`).

Das Ergebnis ist, dass der Klartext-String nur innerhalb des `Secure_Accessor` (im `reconstructed_plain_buffer_`) in vollständiger Form existiert und erst nach dem ersten Aufruf von `Get()` für die kürzestmögliche Zeit. Der String im ursprünglichen `Obfuscated_String`-Objekt wird wieder obfuskiert, sobald der `Secure_Accessor` seinen Inhalt während der Konstruktion kopiert.

#### Speicherfragmentierung im `Secure_Accessor`

Um das Auffinden des vollständigen Klartext-Strings im Speicher weiter zu erschweren, kopiert der `Secure_Accessor` während seiner Konstruktion den entschlüsselten String nicht nur, sondern teilt ihn auch auf:
1. Der String aus dem übergeordneten `Obfuscated_String` wird entschlüsselt.
2. Sein Inhalt wird in bis zu `fragment_count_val` (derzeit 4, wenn der String groß genug ist) Teile aufgeteilt, die in `fragments_storage_[i]` kopiert werden.
3. Der String im übergeordneten `Obfuscated_String`-Objekt wird wieder obfuskiert.

Erst wenn `Secure_Accessor::Get()` zum ersten Mal aufgerufen wird, werden diese Fragmente im `reconstructed_plain_buffer_` wieder zusammengesetzt. Diese Technik zielt darauf ab, sensible Daten zu "verteilen" und Speicher-Scans zu frustrieren, die nach kontinuierlichen Strings suchen.

#### Sichere Speicherbereinigung

Sowohl der Destruktor von `Obfuscated_String` (über `Clear_Internal_Data`) als auch der Destruktor von `Secure_Accessor` (über `Clear_All_Internal_Buffers`) verwenden `Dralyxor::Detail::Secure_Clear_Memory` (Template für Arrays) oder `Dralyxor::Detail::Secure_Clear_Memory_Raw` (für rohe Zeiger, obwohl `Secure_Clear_Memory` in den Destruktoren häufiger verwendet wird). Diese Wrapper-Funktion:
- Verwendet `SecureZeroMemory` (Windows User Mode) oder `RtlSecureZeroMemory` (Windows Kernel Mode), sofern verfügbar, bei denen es sich um Betriebssystemfunktionen handelt, die so konzipiert sind, dass sie vom Compiler nicht wegoptimiert werden.
- Greift auf anderen Plattformen oder wenn die spezifischen Windows-Funktionen nicht verfügbar sind, auf eine Schleife mit einem `volatile T* p`-Zeiger zurück. Das `volatile` ist ein Versuch, den Compiler anzuweisen, das Schreiben von Nullen nicht zu optimieren. Dies stellt sicher, dass sensible Inhalte überschrieben werden, wenn Objekte zerstört oder Puffer explizit bereinigt werden, wodurch das Risiko der Datenwiederherstellung verringert wird.

### Komponente 3: Laufzeitverteidigungen (Anti-Debugging und Anti-Tampering)

**Dralyxor** verlässt sich nicht nur auf Obfuskation. Es setzt eine Reihe aktiver Laufzeitverteidigungen ein, die sich hauptsächlich in `anti_debug.hpp` befinden und in die Methoden `Decrypt()` und `Encrypt()` des `Obfuscated_String` integriert sind.

#### Plattformübergreifende Erkennung von Debuggern

Die Funktion `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (in `anti_debug.hpp`) überprüft die Anwesenheit eines Debuggers mithilfe betriebssystemspezifischer Techniken:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` für `ProcessDebugPort` (0x07) und `ProcessDebugFlags` (0x1F).
- **Linux:** Lesen von `/proc/self/status` und Überprüfung des Wertes von `TracerPid:`. Ein Wert ungleich 0 zeigt an, dass der Prozess verfolgt wird.
- **macOS:** Verwendung von `sysctl` mit `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` um `kinfo_proc` zu erhalten und Überprüfung des `P_TRACED`-Flags in `kp_proc.p_flag`.

Zusätzlich innerhalb von `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Führt eine Schleife einfacher Rechenoperationen aus und misst die Zeit. Eine signifikante Verlangsamung (über `timing_threshold_milliseconds = 75ms`) kann darauf hindeuten, dass ein Debugger im Einzelschrittmodus arbeitet oder umfangreiche Breakpoints aktiv sind. Innerhalb dieser Schleife wird `Is_Debugger_Present_Tracer_Pid_Sysctl()` aufgerufen, und eine "Köder"-Funktion `Detail::Canary_Function_For_Breakpoint_Check()` (die einfach `0xCC`, den Instruktionscode für `int3` / Software-Breakpoint, zurückgibt) wird aufgerufen und ihr Ergebnis XOR-verknüpft, was die Optimierung erschwert und einen häufigen Ort für Breakpoints bietet.
- `Detail::Perform_Output_Debug_String_Trick()` (nur Windows User Mode): Nutzt das Verhalten von `OutputDebugStringA/W` und `GetLastError()`. Wenn ein Debugger angehängt ist, kann `GetLastError()` nach dem Aufruf von `OutputDebugString` modifiziert werden.

#### Auswirkungen auf den Betrieb bei Erkennung oder Integritätsverletzung

Wenn eine der Anti-Debugging-Prüfungen `true` zurückgibt oder wenn die Integritäts-Canaries des `Obfuscated_String` (`_internal_integrity_canary1/2`) beschädigt sind, gibt die Funktion `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` `Detail::integrity_compromised_magic` zurück.

Dieser Rückgabewert ist entscheidend in den Funktionen `Obfuscated_String::Decrypt()` und `Encrypt()`:
```cpp
// Vereinfachte Logik von Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canaries des Obfuscated_String
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
        // ... Canaries erneut überprüfen ...

        // WENN runtime_key_mod NICHT integrity_compromised_magic IST, WIRD ER NICHT VERWENDET, UM DEN ENTSCHLÜSSELUNGSSCHLÜSSEL ZU ÄNDERN.
        // Der Entschlüsselungsschlüssel wird immer vom ursprünglichen 'compile_time_seed' abgeleitet.
        // Die Rolle von runtime_key_mod besteht hier darin, ALS INDIKATOR für eine feindliche Umgebung ZU DIENEN.
        // Wenn feindlich, gibt die Funktion integrity_compromised_magic zurück und die Entschlüsselung wird nicht fortgesetzt oder rückgängig gemacht.
        
        // Transform_Compile_Time_Consistent wird mit compile_time_seed (und NICHT mit runtime_key_mod) aufgerufen
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* Entschlüsselungsmodus */);
        
        // ... Checksumme und Canaries erneut überprüfen ...
        // Wenn etwas fehlschlägt, Clear_Internal_Data() und gibt integrity_compromised_magic zurück.
        decrypted_ = true;
    }

    return 0; // Erfolg
}
```

**Haupteffekt:** Wenn `Calculate_Runtime_Key_Modifier` ein Problem erkennt (Debugger oder beschädigter Canary) und `integrity_compromised_magic` zurückgibt, brechen die Funktionen `Decrypt()` (und ähnlich `Encrypt()`) die Operation ab, bereinigen die internen Daten des `Obfuscated_String` (einschließlich `storage_` und `micro_program_`) und geben `integrity_compromised_magic` zurück. Dies verhindert, dass der String in einer feindlichen Umgebung korrekt entschlüsselt (oder wieder verschlüsselt) wird oder wenn das Objekt manipuliert wurde.
Der String wird nicht "falsch" (zu Müll) entschlüsselt; die Operation wird einfach verhindert, und das `Obfuscated_String`-Objekt zerstört sich selbst in Bezug auf nützlichen Inhalt.

#### Integritäts-Canaries des Objekts

Beide Klassen, `Obfuscated_String` und `Secure_Accessor`, enthalten Canary-Member (Paare von `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initialisiert mit `Detail::integrity_canary_value`) und `_internal_integrity_canary2` (initialisiert mit `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initialisiert mit `Detail::accessor_integrity_canary_seed`) und `_accessor_integrity_canary2` (initialisiert mit `~Detail::accessor_integrity_canary_seed`).

Diese Canaries werden an kritischen Punkten überprüft:
- Beginn und Ende von `Obfuscated_String::Decrypt()` und `Encrypt()`.
- Konstruktor, Destruktor und `Get()` des `Secure_Accessor`.
- Vor und nach den Anti-Debug-Prüfungen in `Calculate_Runtime_Key_Modifier`.

Wenn diese Canary-Werte geändert werden (z. B. durch einen Pufferüberlauf, einen wahllosen Speicher-Patch oder einen Hook, der benachbarten Speicher überschreibt), schlägt die Überprüfung (`Verify_Internal_Canaries()` oder `Verify_Internal_Accessor_Canaries()`) fehl.
Im Fehlerfall werden die Operationen abgebrochen, die relevanten internen Daten bereinigt und ein Fehlerwert (`Detail::integrity_compromised_magic` oder `nullptr`) zurückgegeben, was auf Manipulation hinweist.

#### Inhalts-Checksumme des Strings

- Eine 16-Bit-Checksumme des *ursprünglichen Klartext-Strings* (ohne Nullterminator) wird zur Kompilierzeit von `Detail::Calculate_String_Content_Checksum` berechnet.
- Diese Checksumme wird dann mit `Detail::Obfuscate_Deobfuscate_Short_Value` (mit `compile_time_seed` und `content_checksum_obf_salt`) obfuskiert und in `_content_checksum_obfuscated` im `Obfuscated_String`-Objekt gespeichert.
- **Beim Entschlüsseln (`Decrypt()`):** Nachdem `storage_` transformiert wurde (vermeintlich in Klartext), wird seine Checksumme berechnet. Das `_content_checksum_obfuscated` wird de-obfuskiert, um die Referenz-Checksumme zu erhalten. Wenn die beiden Checksummen nicht übereinstimmen, deutet dies darauf hin, dass:
    - Die Entschlüsselung den ursprünglichen String nicht wiederhergestellt hat (vielleicht weil die Operation aufgrund der Debugger-Erkennung vor der vollständigen Transformation abgebrochen wurde oder es eine Beschädigung des Seeds/Mikroprogramms gab).
    - `storage_` (wenn obfuskiert) oder `_content_checksum_obfuscated` im Speicher manipuliert wurden.
- **Beim Verschlüsseln (`Encrypt()`):** Bevor `storage_` (das sich an diesem Punkt im Klartext befindet) wieder in seine obfuskierte Form transformiert wird, wird seine Checksumme berechnet und mit der Referenz verglichen. Eine Abweichung hier würde bedeuten, dass der Klartext-String *innerhalb von `storage_` des `Obfuscated_String` geändert wurde, während er entschlüsselt war*, was ein starker Hinweis auf Speichermanipulation oder unsachgemäße Verwendung ist (da der Zugriff auf `storage_` nicht direkt erfolgen sollte).

In beiden Fällen eines Checksummenfehlers wird `Clear_Internal_Data()` aufgerufen und `integrity_compromised_magic` zurückgegeben.

### Komponente 4: Generierung einzigartiger und unvorhersehbarer Schlüssel und Seeds

Die Sicherheit jedes Verschlüsselungssystems beruht auf der Stärke und Einzigartigkeit seiner Schlüssel und Seeds. **Dralyxor** stellt sicher, dass jeder obfuskierte String einen Satz von grundsätzlich einzigartigen Verschlüsselungsparametern verwendet.

#### Entropiequellen für den `compile_time_seed`

Der `static constexpr uint64_t Obfuscated_String::compile_time_seed` ist der Master-Seed für alle pseudozufälligen Operationen in Bezug auf diese String-Instanz. Er wird in `consteval` wie folgt generiert:
```cpp
// Innerhalb von Obfuscated_String<CharT, storage_n, Instance_Counter>
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponente 1: Variabilität zwischen Kompilierungen
    ((uint64_t)Instance_Counter << 32) ^        // Komponente 2: Variabilität innerhalb einer Kompilierungseinheit
    storage_n;                                  // Komponente 3: Variabilität basierend auf der Stringlänge
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Die Makros `__DATE__` (z. B. "Jan 01 2025") und `__TIME__` (z. B. "12:30:00") sind vom Präprozessor bereitgestellte Strings, die sich bei jeder Kompilierung der Datei ändern. Der FNV-1a-Hash dieser Werte erzeugt eine Seed-Basis, die für jeden Build des Projekts unterschiedlich ist.
- **`Instance_Counter` (gespeist durch `__COUNTER__` im Makro `DRALYXOR`/`DRALYXOR_LOCAL`)**: Das Makro `__COUNTER__` ist ein vom Präprozessor verwalteter Zähler, der bei jeder Verwendung innerhalb einer Kompilierungseinheit inkrementiert wird. Indem dies als Template-Argument `int Instance_Counter` an `Obfuscated_String` übergeben wird, führt jede Verwendung des Makros `DRALYXOR` oder `DRALYXOR_LOCAL` zu einem anderen `Instance_Counter` und somit zu einem anderen `compile_time_seed`, selbst für identische String-Literale in derselben Quelldatei.
- **`storage_n` (Stringlänge einschließlich Nullterminator)**: Die Stringlänge wird ebenfalls XOR-verknüpft, was einen weiteren Differenzierungsfaktor hinzufügt.

Dieser `compile_time_seed` wird dann als Basis verwendet für:
1. Generierung des `micro_program_` (Initialisierung des PRNG mit `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Ableitung des Obfuskationsschlüssels für das `micro_program_` selbst (über `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Ableitung des Obfuskationsschlüssels für `_content_checksum_obfuscated` (über `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Dient als `base_seed` für `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Abgeleitete Seeds für Inhaltstransformationen

Innerhalb von `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Ein `Constexpr_PRNG prng_operand_modifier(base_seed)` wird initialisiert. Für jedes zu transformierende Zeichen des Strings erzeugt `prng_operand_modifier.Key()` einen `prng_key_for_ops_in_elem`. Dieser Schlüssel wird vor der Anwendung mit dem Operanden der Mikroinstruktion XOR-verknüpft, um sicherzustellen, dass die Wirkung derselben Mikroinstruktion für jedes Zeichen subtil unterschiedlich ist.
- Ein `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` wird initialisiert. Für jedes Zeichen wird `prng_applier_selector.Key()` verwendet, um zwischen `Applier_Style_Direct` und `Applier_Style_DoubleLayer` zu wählen.

Dies führt eine zusätzliche Dynamik in die Transformation jedes Zeichens ein, selbst wenn das zugrunde liegende Mikroprogramm für alle Zeichen eines gegebenen Strings dasselbe ist.

#### Immunität gegen "Replay"-Angriffe und Musteranalyse

- **Inter-Kompilierungs-Einzigartigkeit:** Wenn ein Angreifer die Binärdatei der Version 1.0 Ihrer Software analysiert und es mit viel Aufwand schafft, die Obfuskation eines Strings zu brechen, wird dieses Wissen für Version 1.1 wahrscheinlich nutzlos sein, da sich `__DATE__ __TIME__` geändert haben wird, was zu völlig unterschiedlichen `compile_time_seed`s und Mikroprogrammen führt.
- **Intra-Kompilierungs-Einzigartigkeit:** Wenn Sie `DRALYXOR("AdminPassword")` an zwei verschiedenen Stellen in Ihrem Code (oder in derselben .cpp-Datei) verwenden, stellt `__COUNTER__` sicher, dass die resultierenden `Obfuscated_String`-Objekte und somit ihre obfuskierten Darstellungen in der Binärdatei (sowohl `storage_` als auch `micro_program_`) unterschiedlich sind. Dies verhindert, dass ein Angreifer ein obfuskiertes Muster findet und es verwendet, um alle anderen Vorkommen desselben ursprünglichen Strings zu lokalisieren, oder ein entdecktes Mikroprogramm verwendet, um andere Strings zu entschlüsseln.

Diese robuste Seed-Generierung ist ein Eckpfeiler der Sicherheit von **Dralyxor** gegen Angriffe, die darauf abzielen, ein "Master-Geheimnis" zu entdecken oder die Wiederholung von Chiffren und Transformationen auszunutzen.

## Vollständige Referenz der öffentlichen API

### Obfuskations-Makros

Dies sind die Haupteinstiegspunkte zur Erstellung obfuskierter Strings.

#### `DRALYXOR(str_literal)`

- **Zweck:** Erstellt ein `Obfuscated_String`-Objekt mit statischer Lebensdauer (existiert während der gesamten Programmausführung). Ideal für globale Konstanten oder Strings, auf die von mehreren Stellen aus zugegriffen werden muss und die persistent sein sollen.
- **Speicherung:** Statischer Speicher (normalerweise im Datensegment des Programms).
- **Implementierung (vereinfacht):**
  ```cpp
  #define DRALYXOR(str_literal) \
      []() -> auto& { \
          /* Das Makro __COUNTER__ gewährleistet einen einzigartigen Instance_Counter für jede Verwendung */ \
          /* decltype(*str_literal) leitet den Zeichentyp ab (char, wchar_t) */ \
          /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) berechnet die Größe einschließlich Nullterminator */ \
          static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
              typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
              (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
              __COUNTER__ \
          >(str_literal); \
          return obfuscated_static_string; \
      }()
  ```

- **Parameter:**
  - `str_literal`: Ein C-Style-String-Literal (z. B. `"Hello World"`, `L"Unicode String"`).
- **Rückgabe:** Eine Referenz (`auto&`) auf das statische `Obfuscated_String`-Objekt, das innerhalb einer sofort aufgerufenen Lambda-Funktion erstellt wird.
- **Beispiel:**
  ```cpp
  static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
  // api_endpoint_url ist eine Referenz auf einen statischen Obfuscated_String.
  ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Zweck:** Erstellt ein `Obfuscated_String`-Objekt mit automatischer Lebensdauer (normalerweise auf dem Stack, wenn innerhalb einer Funktion verwendet). Ideal für temporäre Geheimnisse, die auf einen Gültigkeitsbereich beschränkt sind.
- **Speicherung:** Automatisch (Stack für lokale Variablen von Funktionen).
- **Implementierung (vereinfacht):**
  ```cpp
  #define DRALYXOR_LOCAL(str_literal) \
      Dralyxor::Obfuscated_String< \
          typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
          (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
          __COUNTER__ \
      >(str_literal)
  ```
- **Parameter:**
  - `str_literal`: Ein C-Style-String-Literal.
- **Rückgabe:** Ein `Obfuscated_String`-Objekt per Wert (das vom Compiler mit RVO/NRVO optimiert werden kann).
- **Beispiel:**
  ```cpp
  void process_data() {
      auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
      // ... temp_key mit DRALYXOR_SECURE verwenden ...
  } // temp_key wird hier zerstört, sein Destruktor ruft Clear_Internal_Data() auf.
  ```

### Makro für sicheren Zugriff

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Zweck:** Bietet sicheren und temporären Zugriff auf den entschlüsselten Inhalt eines `Obfuscated_String`-Objekts. Dies ist die **einzig empfohlene Methode**, um den String zu lesen.
- **Implementierung (vereinfacht):**
  ```cpp
  #define DRALYXOR_SECURE(obfuscated_var) \
      Dralyxor::Secure_Accessor< \
          typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
      >(obfuscated_var)
  ```

- **Parameter:**
  - `obfuscated_var`: Eine Variable (Lvalue oder Rvalue, die an eine nicht-const Lvalue-Referenz gebunden werden kann) vom Typ `Dralyxor::Obfuscated_String<...>`. Die Variable muss veränderbar sein, da der Konstruktor des `Secure_Accessor` `Decrypt()` und `Encrypt()` darauf aufruft.
- **Rückgabe:** Ein `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>`-Objekt per Wert.
- **Verwendung:**
  ```cpp
  auto& my_static_secret = DRALYXOR("My Top Secret");
  // ...
  {
      auto accessor = DRALYXOR_SECURE(my_static_secret);
      const char* secret_ptr = accessor.Get(); // Oder einfach: const char* secret_ptr = accessor; (implizite Konvertierung)
      
      if (secret_ptr) {
          // Verwenden Sie secret_ptr hier. Er zeigt auf den temporär im Puffer des Accessors entschlüsselten String.
          // Bsp.: send_data(secret_ptr);
      }
      else {
          // Fehler bei der Entschlüsselung oder Integrität. Behandeln Sie den Fehler.
          // Der Accessor konnte möglicherweise nicht initialisiert werden (z. B. my_static_secret wurde beschädigt).
      }
  } // accessor wird zerstört. Seine internen Puffer (Fragmente und rekonstruierter String) werden bereinigt.
    // my_static_secret.storage_ wurde bereits vom Konstruktor des Secure_Accessor wieder obfuskiert,
    // unmittelbar nach dem Kopieren des Inhalts in die Fragmente des Accessors.
  ```

> [!WARNING]
> Überprüfen Sie immer, ob der von `DRALYXOR_SECURE(...).Get()` (oder durch die implizite Konvertierung) zurückgegebene Zeiger nicht `nullptr` ist, bevor Sie ihn verwenden. Eine `nullptr`-Rückgabe weist auf einen Fehler bei der Entschlüsselung hin (z. B. Debugger-Erkennung, Beschädigung von Canaries/Checksummen im übergeordneten `Obfuscated_String` oder im `Secure_Accessor` selbst). Die Verwendung eines `nullptr`-Zeigers führt zu undefiniertem Verhalten (wahrscheinlich ein Segmentierungsfehler).

## Erweiterte Funktionen und Best Practices

### Volle Unicode-Unterstützung (Wide Strings - `wchar_t`)

**Dralyxor** ist dank der Verwendung von Templates (`CharT`) agnostisch gegenüber dem Zeichentyp. Es verarbeitet nativ `char` (für ASCII/UTF-8-Strings) und `wchar_t` (für UTF-16-Strings unter Windows oder UTF-32-Strings auf anderen Systemen, abhängig von Plattform und Compiler). Verwenden Sie einfach das Präfix `L` für `wchar_t`-Literale:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Unicode-Nachricht: Hallo Welt Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Beispiel unter Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Unicode-Titel", MB_OK);
        // Beispiel mit wcout:
        // #include <io.h> // Für _setmode unter Windows mit MSVC
        // #include <fcntl.h> // Für _O_U16TEXT unter Windows mit MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Konfiguriert stdout für UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Für 1-Byte-Zeichen (`sizeof(CharT) == 1`) wendet die Transformations-Engine `Micro_Program_Cipher` das Mikroprogramm Byte für Byte an. Für Multibyte-Zeichen (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` verwendet einen einfacheren Ansatz: Das gesamte Multibyte-Zeichen wird mit einer Maske XOR-verknüpft, die von `prng_key_for_ops_in_elem` abgeleitet ist (repliziert, um die Größe von `CharT` zu füllen). Wenn beispielsweise `CharT` `wchar_t` (2 Bytes) ist und `prng_key_for_ops_in_elem` `0xAB` ist, wird das Zeichen mit `0xABAB` XOR-verknüpft.
Dies stellt sicher, dass alle Bytes des `wchar_t` von der Obfuskation betroffen sind, auch wenn nicht durch das vollständige Mikroprogramm. Die Komplexität des Mikroprogramms trägt immer noch indirekt durch die Ableitung der PRNG-Schlüssel bei.

### Intelligente Anpassung an **C++**-Standards und Umgebungen (Kernel Mode)

Wie bereits erwähnt, passt sich **Dralyxor** an:
- **C++-Standards:** Benötigt mindestens **C++14**. Erkennt und verwendet Funktionen von **C++17** und **C++20** (wie `if constexpr`, `consteval`, `_v`-Suffixe für `type_traits`), wenn der Compiler diese unterstützt, und greift andernfalls auf **C++14**-Alternativen zurück. Makros wie `_DRALYXOR_IF_CONSTEXPR` und `_DRALYXOR_CONSTEVAL` in `detection.hpp` verwalten diese Anpassung.
- **Kernel Mode:** Wenn `_KERNEL_MODE` definiert ist (typisch in WDK-Projekten für Windows-Treiber), vermeidet **Dralyxor** (über `env_traits.hpp`) das Einbinden von Standard-STL-Headern wie `<type_traits>`, die möglicherweise nicht verfügbar sind oder sich anders verhalten. Stattdessen verwendet es seine eigenen `constexpr`-Implementierungen grundlegender Werkzeuge wie `Dralyxor::Detail::Fallback::decay` und `Dralyxor::Detail::Fallback::remove_reference`. Dies ermöglicht die sichere Verwendung von **Dralyxor** zum Schutz von Strings in Low-Level-Systemkomponenten.
    - Ähnlich verwendet `secure_memory.hpp` `RtlSecureZeroMemory` im Kernel Mode.
    - User-Mode-Anti-Debug-Prüfungen (wie `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) werden im Kernel Mode deaktiviert (`#if !defined(_KERNEL_MODE)`), da sie nicht zutreffen oder unterschiedliche Äquivalente haben. Die Timing-Prüfungen können immer noch eine gewisse Wirkung haben, aber die Hauptverteidigungslinie im Kernel Mode ist die Obfuskation selbst.

### Überlegungen zu Performance und Overhead

- **Kompilierzeit:** Die Obfuskation, einschließlich der Generierung und Anwendung von Mikroprogrammen, erfolgt vollständig zur Kompilierzeit. Bei Projekten mit einer sehr großen Anzahl obfuskierter Strings kann sich die Kompilierzeit erhöhen. Dies sind einmalige Kosten pro Kompilierung.
- **Binärgröße:** Jedes `Obfuscated_String` fügt sein `storage_` (Stringlänge), das `micro_program_` (festgelegt auf `max_micro_instructions * sizeof(Micro_Instruction)`) sowie einige Bytes für Canaries, Checksumme und Flags hinzu. Im Vergleich zu reinen String-Literalen kann es zu einer Erhöhung der Binärgröße kommen, insbesondere bei vielen kleinen Strings.
- **Laufzeit (Runtime):**
    - **Erstellung von `Obfuscated_String` (statische oder lokale Objekte):** Erfolgt zur Kompilierzeit (für statische) oder beinhaltet eine Kopie vorkompilierter Daten (für lokale, optimierbar durch RVO). Es gibt keine "Generierungs"-Kosten zur Laufzeit.
    - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
        - Überprüfung von Canaries (extrem schnell).
        - `Detail::Calculate_Runtime_Key_Modifier()`: Beinhaltet die Anti-Debug-Prüfungen. Die Timing-Prüfung (`Perform_Timing_Check_Generic`) ist hier die aufwendigste und führt eine Schleife aus. Die anderen sind API-Aufrufe oder Dateilesevorgänge (Linux).
        - De-Obfuskation des Mikroprogramms (Kopie und XOR, schnell).
        - Transformation des Strings: Schleife über `N_data_elements_to_transform`, und darin Schleife über `num_actual_instructions_in_program_`. Für jede Instruktion ein Aufruf an den `Byte_Transform_Applier`, der einige Byte-Operationen durchführt. Die Kosten sind O(Stringlänge \* Anzahl\_Instruktionen).
        - Berechnung/Überprüfung der Checksumme (`Detail::Calculate_String_Content_Checksum`): O(Stringlänge \* sizeof(CharT)).
    - **Erstellung von `Secure_Accessor`:**
        - Ruft `Obfuscated_String::Decrypt()` auf.
        - Kopiert String in Fragmente: O(Stringlänge).
        - Berechnet Checksumme der Fragmente (`Calculate_Current_Fragments_Checksum`): O(Stringlänge).
        - Ruft `Obfuscated_String::Encrypt()` auf. Dies ist der Punkt mit dem größten Overhead in einer einzelnen Zugriffsoperation.
    - **`Secure_Accessor::Get()`:**
        - Erster Aufruf: Überprüft Canaries, rekonstruiert String aus Fragmenten (O(Stringlänge)), überprüft Checksumme der Fragmente.
        - Nachfolgende Aufrufe (für dasselbe `Secure_Accessor`-Objekt): Überprüft Canaries (schnell) und gibt bereits berechneten Zeiger zurück (O(1)).
- **Gesamter Overhead:** Für die meisten Anwendungen, bei denen sensible Strings nicht in Hochfrequenzschleifen zugegriffen werden, ist der Laufzeit-Overhead im Allgemeinen akzeptabel, insbesondere angesichts des Sicherheitsvorteils. Das Design des `Secure_Accessor` (nur bei Bedarf erstellt und mit streng begrenztem Gültigkeitsbereich durch RAII) ist grundlegend für die Verwaltung dieser Kosten. Testen Sie in Ihrer spezifischen Umgebung, wenn die Leistung kritisch ist.

### Integration in eine mehrschichtige Sicherheitsstrategie

> [!IMPORTANT]
> **Dralyxor** ist ein leistungsstarkes Werkzeug zur **Obfuskation eingebetteter Strings und zur Verteidigung gegen Speicheranalyse**, keine generische Verschlüsselungslösung für die persistente Speicherung von Daten auf Festplatten oder die sichere Übertragung über das Netzwerk.
>
> Es sollte als **eine von vielen Schichten** in einer umfassenden Sicherheitsstrategie verwendet werden. Kein einzelnes Werkzeug ist eine Patentlösung. Weitere zu berücksichtigende Maßnahmen sind:
> - **Minimierung eingebetteter Geheimnisse:** Vermeiden Sie nach Möglichkeit das Einbetten hochkritischer Geheimnisse. Nutzen Sie Alternativen wie:
>     - Sichere Konfigurationen, die zur Laufzeit bereitgestellt werden (Umgebungsvariablen, Konfigurationsdateien mit eingeschränkten Berechtigungen).
>     - Geheimnisverwaltungsdienste (Vaults) wie HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Robuste Eingabevalidierung an allen Schnittstellen.
> - Prinzip des geringsten Privilegs für Prozesse und Benutzer.
> - Sichere Netzwerkkommunikation (TLS/SSL mit Zertifikats-Pinning, falls zutreffend).
> - Sicheres Hashing von Benutzerpasswörtern (Argon2, scrypt, bcrypt).
> - Schutz der Binärdatei als Ganzes mit anderen Anti-Reversing-/Anti-Tampering-Techniken (Packer, Code-Virtualisierer, Integritätsprüfungen des Codes), unter Berücksichtigung der Kompromisse, die diese mit sich bringen können (Fehlalarme von Antivirenprogrammen, Komplexität).
> - Gute Praktiken der sicheren Entwicklung (Secure SDLC).

**Dralyxor** konzentriert sich darauf, ein spezifisches und häufiges Problem sehr gut zu lösen: den Schutz eingebetteter String-Literale vor statischer Analyse und die Minimierung ihrer Exposition im Speicher während der Ausführung, was Reverse Engineers das Leben schwerer macht.

## Lizenz

Diese Bibliothek ist unter der MIT-Lizenz geschützt, die Folgendes erlaubt:

- ✔️ Kommerzielle und private Nutzung
- ✔️ Änderung des Quellcodes
- ✔️ Verteilung des Codes
- ✔️ Sublicensing

### Bedingungen:

- Beibehaltung des Urheberrechtshinweises
- Beifügung einer Kopie der MIT-Lizenz

Weitere Details zur Lizenz: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Alle Rechte vorbehalten**