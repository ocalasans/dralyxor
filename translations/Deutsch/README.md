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
    - [Wesentliche Nutzungsmuster](#wesentliche-nutzungsmuster)
      - [Muster 1: Lokale Verschleierung (Stack)](#muster-1-lokale-verschleierung-stack)
      - [Muster 2: Statische Verschleierung (Global)](#muster-2-statische-verschleierung-global)
      - [Muster 3: Verschleierung mit benutzerdefiniertem Schlüssel](#muster-3-verschleierung-mit-benutzerdefiniertem-schlüssel)
    - [Fehlerbehandlung und Integrität](#fehlerbehandlung-und-integrität)
  - [Detaillierte Designphilosophie und Architektur](#detaillierte-designphilosophie-und-architektur)
    - [Die persistente Bedrohung: Schwachstelle von String-Literalen](#die-persistente-bedrohung-schwachstelle-von-string-literalen)
    - [Die mehrschichtige Architekturlösung von **Dralyxor**](#die-mehrschichtige-architekturlösung-von-dralyxor)
  - [Tiefergehende Analyse der Architekturkomponenten](#tiefergehende-analyse-der-architekturkomponenten)
    - [Komponente 1: Die Mikroprogramm-Transformations-Engine](#komponente-1-die-mikroprogramm-transformations-engine)
      - [Die Macht von `consteval` und `constexpr` für die Erzeugung zur Kompilierzeit](#die-macht-von-consteval-und-constexpr-für-die-erzeugung-zur-kompilierzeit)
      - [Anatomie eines **Dralyxor**-Mikroprogramms](#anatomie-eines-dralyxor-mikroprogramms)
        - [Randomisierte Generierung von Anweisungen und Auswahl von Anwendern](#randomisierte-generierung-von-anweisungen-und-auswahl-von-anwendern)
        - [Variable und logische NOPs für Entropie](#variable-und-logische-nops-für-entropie)
      - [Verschleierung des Mikroprogramms selbst](#verschleierung-des-mikroprogramms-selbst)
      - [Der Lebenszyklus der statischen Verschleierung](#der-lebenszyklus-der-statischen-verschleierung)
    - [Komponente 2: Sicherer Zugriff und Minimierung der Exposition im RAM](#komponente-2-sicherer-zugriff-und-minimierung-der-exposition-im-ram)
      - [Der `Secure_Accessor` und das RAII-Prinzip](#der-secure_accessor-und-das-raii-prinzip)
      - [Speicherfragmentierung im `Secure_Accessor`](#speicherfragmentierung-im-secure_accessor)
      - [Sicheres Löschen des Speichers](#sicheres-löschen-des-speichers)
    - [Komponente 3: Laufzeit-Abwehrmechanismen (Anti-Debugging und Anti-Tampering)](#komponente-3-laufzeit-abwehrmechanismen-anti-debugging-und-anti-tampering)
      - [Plattformübergreifende Erkennung von Debuggern](#plattformübergreifende-erkennung-von-debuggern)
      - [Auswirkungen auf den Betrieb bei Erkennung oder Integritätsverletzung](#auswirkungen-auf-den-betrieb-bei-erkennung-oder-integritätsverletzung)
      - [Integritäts-Canaries des Objekts](#integritäts-canaries-des-objekts)
      - [Prüfsumme des Zeichenketteninhalts](#prüfsumme-des-zeichenketteninhalts)
    - [Komponente 4: Erzeugung einzigartiger und unvorhersehbarer Schlüssel und Seeds](#komponente-4-erzeugung-einzigartiger-und-unvorhersehbarer-schlüssel-und-seeds)
      - [Entropiequellen für den `compile_time_seed`](#entropiequellen-für-den-compile_time_seed)
      - [Abgeleitete Seeds für Inhalts-Transformationen](#abgeleitete-seeds-für-inhalts-transformationen)
      - [Immunität gegen "Replay"-Angriffe und Musteranalyse](#immunität-gegen-replay-angriffe-und-musteranalyse)
  - [Vollständige Referenz der öffentlichen API](#vollständige-referenz-der-öffentlichen-api)
    - [Obfuskations-Makros](#obfuskations-makros)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
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

**Dralyxor** ist eine **header-only** Bibliothek. Es ist keine Vorkompilierung oder Verknüpfung von Bibliotheken (`.lib`/`.a`) erforderlich.

1.  **Kopieren Sie das `Dralyxor`-Verzeichnis:** Holen Sie sich die neueste Version der Bibliothek (klonen Sie das Repository oder laden Sie das Zip herunter) und kopieren Sie das gesamte `Dralyxor`-Verzeichnis (das alle `.hpp`-Dateien enthält) an einen Ort, der von Ihrem Projekt aus zugänglich ist (z. B. einen Ordner `libs/`, `libraries/` oder `vendor/`).
2.  **Binden Sie den Haupt-Header ein:** Binden Sie in Ihrem Quellcode den Haupt-Header `dralyxor.hpp` ein:
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
        |-- dralyxor.hpp            (Haupt-Einstiegspunkt)
        |-- obfuscated_string.hpp   (Klasse Obfuscated_String)
        |-- secure_accessor.hpp     (Klasse Secure_Accessor)
        |-- algorithms.hpp          (Transformations-Engine und Mikroprogramme)
        |-- anti_debug.hpp          (Laufzeit-Erkennungen)
        |-- prng.hpp                (Pseudozufallszahlengenerator zur Kompilierzeit)
        |-- integrity_constants.hpp (Konstanten für Integritätsprüfungen)
        |-- secure_memory.hpp       (Sicheres Löschen des Speichers)
        |-- detection.hpp           (Erkennungs-Makros für Compiler/C++ Standard)
        `-- env_traits.hpp          (Anpassungen von type_traits für eingeschränkte Umgebungen)
```

### Compiler-Anforderungen

> [!IMPORTANT]
> **Dralyxor** wurde mit einem Fokus auf modernes **C++** entwickelt, um maximale Sicherheit und Effizienz zur Kompilierzeit zu gewährleisten.
>
> - **Minimaler C++ Standard: C++14**. Die Bibliothek verwendet Funktionen wie verallgemeinertes `constexpr` und passt sich an `if constexpr` an (wenn über `_DRALYXOR_IF_CONSTEXPR` verfügbar).
> - **Anpassung an höhere Standards:** Erkennt und verwendet Optimierungen oder Syntaxen von **C++17** und **C++20** (wie `consteval`, `_v`-Suffixe für `type_traits`), wenn das Projekt mit diesen Standards kompiliert wird. `_DRALYXOR_CONSTEVAL` wird auf `consteval` in C++20 und `constexpr` in C++14/17 abgebildet, um die Ausführung zur Kompilierzeit zu gewährleisten, wo immer dies möglich ist.
> - **Unterstützte Compiler:** Hauptsächlich mit aktuellen Versionen von MSVC, GCC und Clang getestet.
> - **Laufzeitumgebung:** Vollständig kompatibel mit Anwendungen im **User Mode** und Umgebungen im **Kernel Mode** (z. B. Windows-Treiber). Im Kernel Mode, wo die STL möglicherweise nicht verfügbar ist, verwendet **Dralyxor** interne Implementierungen für notwendige `type traits` (siehe `env_traits.hpp`).

### Wesentliche Nutzungsmuster

#### Muster 1: Lokale Verschleierung (Stack)

Ideal für temporäre Zeichenketten, die auf den Gültigkeitsbereich einer Funktion beschränkt sind. Der Speicher wird automatisch verwaltet und bereinigt.

```cpp
#include "Dralyxor/dralyxor.hpp" // Passen Sie den Pfad bei Bedarf an
#include <iostream>

void Configure_Logging() {
    // Schlüssel für das Log-Format, der nur lokal verwendet wird.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Sicherer Zugriff innerhalb eines begrenzten Gültigkeitsbereichs
    {
        // Der Secure_Accessor entschlüsselt 'log_format_key' temporär bei seiner Konstruktion
        // (und verschleiert 'log_format_key' sofort nach dem Kopieren in seine internen Puffer wieder),
        // ermöglicht den Zugriff und bereinigt seine eigenen Puffer bei der Zerstörung.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Überprüfen Sie immer, ob Get() nicht nullptr zurückgibt
            std::cout << "Verwende Log-Format: " << accessor.Get() << std::endl;
            // Bsp: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Entschlüsselung von log_format_key fehlgeschlagen (mögliches Tampering oder Debugger-Erkennung?)" << std::endl;
    } // accessor wird zerstört, seine internen Puffer werden bereinigt. log_format_key bleibt verschleiert.
      // log_format_key wird am Ende der Funktion Configure_Logging zerstört.
}
```

#### Muster 2: Statische Verschleierung (Global)

Für Konstanten, die über die gesamte Lebensdauer des Programms bestehen bleiben und global zugänglich sein müssen.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Für das Beispiel

// URL des Lizenz-API-Servers, ein persistentes Geheimnis.
// Das Makro DRALYXOR() erstellt ein statisches Objekt.
// Die Funktion Get_License_Server_URL() gibt eine Referenz auf dieses statische Objekt zurück.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref ist eine Referenz auf das statische Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Erstellt einen Secure_Accessor für url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Kontaktiere Lizenzserver unter: " << accessor.Get() << std::endl;
            // Bsp: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulation eines Erfolgs für das Beispiel
        }
        else
            std::cerr << "Entschlüsselung der Lizenzserver-URL fehlgeschlagen (mögliches Tampering oder Debugger-Erkennung?)." << std::endl;
    } // accessor wird zerstört, seine Puffer werden bereinigt. url_obj_ref (das ursprüngliche Obfuscated_String) bleibt verschleiert.

    return success;
}
```

#### Muster 3: Verschleierung mit benutzerdefiniertem Schlüssel

Für maximale Sicherheit können Sie Ihre eigene geheime Schlüsselzeichenkette bereitstellen. Dies macht die Verschleierung von einem Geheimnis abhängig, das nur Sie kennen, und macht sie widerstandsfähiger.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// Der Schlüssel sollte niemals im Klartext im Produktionscode stehen,
// idealerweise sollte er aus einem Build-Skript, einer Umgebungsvariablen usw. stammen.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Verschleiert eine URL mit dem geheimen Schlüssel. Das Makro endet mit _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Die Verwendung mit Secure_Accessor bleibt gleich.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Fehlerbehandlung und Integrität

Die Funktionen `Obfuscated_String::Decrypt()` und `Encrypt()` geben `uint64_t` zurück:
- `0` zeigt einen Erfolg an.
- `Dralyxor::Detail::integrity_compromised_magic` (ein konstanter Wert, der in `integrity_constants.hpp` definiert ist) zeigt an, dass eine Integritätsprüfung fehlgeschlagen ist. Dies kann auf beschädigte Canaries des Objekts, eine inkonsistente Prüfsumme des Inhalts oder die Erkennung eines Debuggers zurückzuführen sein, was auf eine feindliche Umgebung hindeutet.

Ebenso gibt `Secure_Accessor::Get()` (oder seine implizite Konvertierung zu `const CharT*`) `nullptr` zurück, wenn die Initialisierung des `Secure_Accessor` fehlschlägt (z. B. wenn die Entschlüsselung des ursprünglichen `Obfuscated_String` fehlschlägt) oder wenn die Integrität des `Secure_Accessor` (seine eigenen Canaries oder internen Prüfsummen) während seiner Lebensdauer beeinträchtigt wird.

**Es ist entscheidend, dass Ihr Code diese Rückgabewerte überprüft, um die Robustheit und Sicherheit der Anwendung zu gewährleisten.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Normalerweise würden Sie Decrypt() und Encrypt() NICHT direkt aufrufen,
    // da der Secure_Accessor dies verwaltet. Aber falls Sie es aus irgendeinem Grund müssen:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "WARNUNG: Entschlüsselung von 'my_secret' fehlgeschlagen oder Integrität während Decrypt() kompromittiert!" << std::endl;
        // Ergreifen Sie geeignete Maßnahmen: Beenden, sicher protokollieren usw.
        // Das Objekt my_secret.storage_ könnte sich in einem ungültigen Zustand oder mit Müll befinden.
        return; // Vermeiden Sie die Verwendung von my_secret, wenn Decrypt() fehlschlägt.
    }

    // Wenn Decrypt() erfolgreich war, enthält my_secret.storage_ die entschlüsselten Daten.
    // **DIREKTER ZUGRIFF AUF storage_ IST IN PRODUKTION DRINGEND ABZURATEN.**
    // std::cout << "Daten in my_secret.storage_ (TUN SIE DAS NICHT): " << my_secret.storage_ << std::endl;

    // Es liegt in Ihrer Verantwortung, erneut zu verschlüsseln, wenn Sie Decrypt() manuell aufgerufen haben:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "WARNUNG: Neuverschlüsselung von 'my_secret' fehlgeschlagen oder Integrität während Encrypt() kompromittiert!" << std::endl;
        // Unsicherer Zustand, potenziell gefährlich.
    }

    // EMPFOHLENE VERWENDUNG mit Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Der Konstruktor des Secure_Accessor ruft another_secret.Decrypt() auf, kopiert und dann another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Oder: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Geheime Daten via Secure_Accessor: " << data_ptr << std::endl;
            // Verwenden Sie data_ptr hier
        }
        else {
            std::cerr << "WARNUNG: Secure_Accessor konnte nicht initialisiert werden oder den Zeiger für 'another_secret' abrufen!" << std::endl;
            // Dies deutet darauf hin, dass Decrypt() im Konstruktor des Accessors fehlgeschlagen ist,
            // oder es gab Manipulationen am Accessor (Canaries, interne Prüfsummen).
        }
    } // accessor wird zerstört. Seine Puffer werden bereinigt. another_secret bleibt verschleiert.
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

### Komponente 1: Die Mikroprogramm-Transformations-Engine

Das Herzstück der statischen und dynamischen Verschleierung von **Dralyxor** liegt in seiner Transformations-Engine, die einzigartige "Mikroprogramme" für jede Zeichenkette und jeden Kontext verwendet.

#### Die Macht von `consteval` und `constexpr` für die Erzeugung zur Kompilierzeit

Modernes **C++**, mit `consteval` (**C++20**) und `constexpr` (**C++11** und später), ermöglicht es, komplexen Code *während der Kompilierung* auszuführen. **Dralyxor** verwendet `_DRALYXOR_CONSTEVAL` (das je nach **C++**-Standard auf `consteval` oder `constexpr` abgebildet wird) für den `Obfuscated_String`-Konstruktor und für die Generierung des Mikroprogramms.

Das bedeutet, dass der gesamte Prozess von:
1. Erzeugung einer pseudozufälligen Sequenz von Transformationsanweisungen (das Mikroprogramm).
2. Verschleierung des Mikroprogramms selbst für die Speicherung.
3. Anwendung dieses Mikroprogramms (in vorübergehend entschlüsselter Form), um die ursprüngliche Zeichenkette zu transformieren, was zu ihrer verschleierten Form führt.
All dies geschieht zur Kompilierzeit, bevor die Binärdatei erzeugt wird.

#### Anatomie eines **Dralyxor**-Mikroprogramms

Jedes `Obfuscated_String`-Objekt speichert ein kleines Array von `Dralyxor::Detail::Micro_Instruction`. Eine `Micro_Instruction` ist eine einfache Struktur, die in `algorithms.hpp` definiert ist:
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
    Micro_Operation_Code op_code{}; // Standardinitialisierer {} zur Nullsetzung
    uint8_t operand{};             // Standardinitialisierer {} zur Nullsetzung
};

// Maximale Anzahl von Anweisungen, die ein Mikroprogramm enthalten kann.
static constexpr size_t max_micro_instructions = 8;
```
Die Funktion `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` ist für das Füllen dieses Arrays verantwortlich.

##### Randomisierte Generierung von Anweisungen und Auswahl von Anwendern

- **Generierung von Anweisungen:** Mithilfe eines `Dralyxor::Detail::Constexpr_PRNG` (initialisiert mit einer Kombination aus dem `compile_time_seed` und `0xDEADBEEFC0FFEEULL`) wählt die Funktion `Generate_Micro_Program_Instructions` probabilistisch eine Sequenz von Operationen:
   - `XOR`: Bitweises XOR mit dem Operanden.
   - `ADD`: Modulare Addition mit dem Operanden.
   - `SUB`: Modulare Subtraktion mit dem Operanden.
   - `ROTR`/`ROTL`: Bit-Rotation. Der Operand (nach Modulo) definiert die Anzahl der Shifts (1 bis 7).
   - `SWAP_NIB`: Tauscht die unteren 4 Bits mit den oberen 4 Bits eines Bytes aus (Operand wird ignoriert).
    Die Operanden für diese Anweisungen werden ebenfalls pseudozufällig vom PRNG generiert.

- **Modifikation von Operanden und Auswahl von Anwendern zur Transformationszeit:** Während der Anwendung des Mikroprogramms (durch `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), sowohl bei der initialen Verschleierung als auch bei der Entschlüsselung zur Laufzeit:
   - Ein `Constexpr_PRNG prng_operand_modifier` (initialisiert mit `base_seed`) generiert einen `prng_key_for_ops_in_elem` für jedes Zeichen der Zeichenkette. Der Operand der Mikroanweisung (`instr_orig.operand`) wird mit diesem Schlüssel XOR-verknüpft, bevor er verwendet wird. Dies stellt sicher, dass dasselbe Mikroprogramm leicht unterschiedliche Transformationen für jedes Zeichen anwendet.
   - Ein `Constexpr_PRNG prng_applier_selector` (initialisiert mit `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) wählt einen `Byte_Transform_Applier` für jedes Zeichen aus. Derzeit gibt es zwei Stile:
      - `Applier_Style_Direct`: Wendet die Operation direkt an (invertiert sie zur Entschlüsselung, z. B. wird aus ADD SUB).
      - `Applier_Style_DoubleLayer`: Wendet die Operation zweimal an (oder die Operation und ihre Umkehrung, je nach Verschlüsselungs-/Entschlüsselungsmodus) mit unterschiedlichen Operanden, was die Umkehrung etwas komplexer in der Analyse macht.

##### Variable und logische NOPs für Entropie

Um die manuelle Analyse des Mikroprogramms zu erschweren, fügt **Dralyxor** ein:
- **Explizite NOPs:** `Micro_Operation_Code::NOP`-Anweisungen, die nichts tun.
- **Logische NOPs:** Paare von Anweisungen, die sich gegenseitig aufheben, wie `ADD K` gefolgt von `SUB K` oder `ROTL N_BITS` gefolgt von `ROTR N_BITS`. Der im Paar verwendete Operand ist derselbe.

Diese NOPs werden probabilistisch von `Generate_Micro_Program_Instructions` eingefügt, füllen das `micro_program_`-Array und erschweren es, die effektiven Transformationen von den "Rausch"-Operationen zu unterscheiden.

#### Verschleierung des Mikroprogramms selbst

Nach der Generierung des Mikroprogramms und vor der initialen Verschleierung der Zeichenkette im `consteval`-Konstruktor wird das `micro_program_`-Array (im `Obfuscated_String`-Objekt enthalten) selbst verschleiert. Jeder `op_code` und `operand` in jeder `Micro_Instruction` wird mit einem Schlüssel XOR-verknüpft, der vom `compile_time_seed` abgeleitet ist (unter Verwendung von `Detail::Get_Micro_Program_Obfuscation_Key` und `Detail::Obfuscate_Deobfuscate_Instruction`).
Das bedeutet, selbst wenn ein Angreifer den Speicher des `Obfuscated_String`-Objekts dumpen kann, wird das Mikroprogramm nicht in seiner direkt lesbaren/anwendbaren Form vorliegen.

Wenn `Obfuscated_String::Decrypt()` oder `Encrypt()` aufgerufen werden (oder indirekt durch den `Secure_Accessor`), erhält die zentrale Funktion `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` dieses *verschleierte* Mikroprogramm. Sie führt dann folgende Schritte aus:
1. Erstellt eine temporäre Kopie des Mikroprogramms (`local_plain_program`) auf dem Stack.
2. Entschlüsselt diese lokale Kopie unter Verwendung desselben Schlüssels (`program_obf_key`), der aus dem übergebenen Basis-Seed abgeleitet wird (der letztendlich der `compile_time_seed` ist).
3. Verwendet dieses `local_plain_program`, um die Daten der Zeichenkette zu transformieren.
Die lokale Kopie auf dem Stack wird am Ende der Funktion zerstört, und das im `Obfuscated_String`-Objekt gespeicherte `micro_program_` bleibt verschleiert.

#### Der Lebenszyklus der statischen Verschleierung

1. **Quellcode:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Präprozessor:** Das Makro wird zu einer Instanziierung `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");` erweitert. (Die Größe 15 schließt den Null-Terminator ein).
3. **`_DRALYXOR_CONSTEVAL` Auswertung:**
   - Der Compiler führt den `Obfuscated_String`-Konstruktor aus.
   - `Initialize_Internal_Canaries()` setzt die Integritäts-Canaries.
   - `Generate_Micro_Program_Instructions()` (initialisiert mit `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) erstellt eine Sequenz von `Micro_Instruction` und speichert sie in `this->micro_program_` (z. B. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Die tatsächliche Anzahl der Anweisungen wird in `num_actual_instructions_in_program_` gespeichert.
   - Die ursprüngliche Zeichenkette "SECRET\_API\_KEY" wird in `this->storage_` kopiert.
   - Eine Prüfsumme der ursprünglichen Zeichenkette "SECRET\_API\_KEY" (ohne Null-Terminator) wird von `Detail::Calculate_String_Content_Checksum` berechnet und dann von `Detail::Obfuscate_Deobfuscate_Short_Value` verschleiert (unter Verwendung von `compile_time_seed` und `content_checksum_obf_salt`) und in `this->_content_checksum_obfuscated` gespeichert.
   - `Obfuscate_Internal_Micro_Program()` wird aufgerufen: `this->micro_program_` wird an Ort und Stelle verschleiert (jede Anweisung wird mit `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)` XOR-verknüpft).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` wird aufgerufen. Diese Funktion:
      - Erstellt eine entschlüsselte Kopie von `this->micro_program_` auf dem Stack.
      - Für jedes Zeichen in `storage_` (außer dem Null-Terminator):
         - Generiert `prng_key_for_ops_in_elem` und wählt einen `Byte_Transform_Applier`.
         - Wendet die Sequenz der Mikroanweisungen (aus der entschlüsselten Kopie) auf das Zeichen an, unter Verwendung des Anwenders und des modifizierten Operanden.
      - Am Ende enthält `storage_` die verschleierte Zeichenkette (z. B. `[CF, 3A, D1, ..., 0x00]`).
4. **Codegenerierung:** Der Compiler weist Speicherplatz für `api_key_obj` zu und initialisiert ihn direkt mit:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (verschleierte Zeichenkette).
   - `micro_program_`: Das *bereits verschleierte* Mikroprogramm.
   - `_content_checksum_obfuscated`: Die *verschleierte* Prüfsumme des ursprünglichen Inhalts.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Das Literal `"SECRET_API_KEY"` existiert nicht mehr in der Binärdatei.

### Komponente 2: Sicherer Zugriff und Minimierung der Exposition im RAM

#### Der `Secure_Accessor` und das RAII-Prinzip

Der Schutz zur Kompilierzeit ist nur die halbe Miete. Sobald die Zeichenkette verwendet werden muss, muss sie entschlüsselt werden. Wenn diese entschlüsselte Zeichenkette für längere Zeit im **RAM** verbleibt, wird sie zu einem Ziel für dynamische Analysen (Memory Dumps, Debugger).

**Dralyxor** löst dieses Problem mit dem `Dralyxor::Secure_Accessor`, einer Klasse, die das **RAII**-Muster (Resource Acquisition Is Initialization) implementiert:
- **Erworbene Ressource:** Der temporäre Zugriff auf die Klartext-Zeichenkette, fragmentiert und vom Accessor verwaltet.
- **Verwaltungsobjekt:** Die Instanz von `Secure_Accessor`.

```cpp
// In secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Anders initialisieren, um bei Nicht-Aktualisierung zu scheitern
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalidiert den Accessor

            return;
        }

        // 1. Versucht, das ursprüngliche Obfuscated_String zu entschlüsseln.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Wenn die Entschlüsselung erfolgreich war, wird die Klartext-Zeichenkette in die internen Fragmente kopiert.
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

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Prüfsumme der Fragmente
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Verschlüsselt das ursprüngliche Obfuscated_String SOFORT wieder.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Bereinigt Fragmente und den rekonstruierten Puffer.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Überprüft sich selbst und das übergeordnete Element
            Clear_All_Internal_Buffers(); // Sicherheitsmaßnahme
            _accessor_integrity_canary1 = 0; // Invalidiert für zukünftige Zugriffe

            return nullptr;
        }

        if (!current_access_ptr_) { // Wenn es der erste Aufruf von Get() ist oder wenn bereinigt wurde
            if constexpr (N_storage > 0) { // Rekonstruiert nur, wenn es etwas zu rekonstruieren gibt
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

                // Stellt die Nullterminierung sicher, auch wenn N_storage exakt gefüllt ist.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Für N_storage == 0 (leere Zeichenkette, theoretisch), gibt es keine Prüfsummen
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Um die Prüfung zu bestehen

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // Wenn N_storage 0 war, ist dies sicher, wenn der Puffer > 0 ist
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Überprüft erneut nach jeder internen Operation, um die Integrität sicherzustellen.
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
   - Er ruft `my_obfuscated_string.Decrypt()` auf. Dies beinhaltet das Entschlüsseln des `micro_program_` (in eine lokale Kopie), dessen Verwendung zur Entschlüsselung von `my_obfuscated_string.storage_` und die anschließende Überprüfung der Canaries und der Prüfsumme des entschlüsselten Inhalts mit dem erwarteten Wert.
   - Bei Erfolg wird der Inhalt von `my_obfuscated_string.storage_` (jetzt Klartext) in die internen `fragments_storage_` des `Secure_Accessor` kopiert und aufgeteilt.
   - Eine Prüfsumme der `fragments_storage_` (`fragments_data_checksum_expected_`) wird berechnet.
   - Entscheidend ist, dass `my_obfuscated_string.Encrypt()` *unmittelbar danach* aufgerufen wird, wodurch `my_obfuscated_string.storage_` wieder verschleiert wird.
2. `const char* ptr = accessor.Get();` (oder `const char* ptr = accessor;` aufgrund der impliziten Konvertierung)
   - `Secure_Accessor::Get()` wird aufgerufen.
   - Es überprüft seine eigenen Integritäts-Canaries und die des übergeordneten `Obfuscated_String`.
   - Wenn es der erste Zugriff ist (`current_access_ptr_` ist `nullptr`), rekonstruiert es die vollständige Zeichenkette in `reconstructed_plain_buffer_` aus den `fragments_storage_`.
   - Es überprüft dann `fragments_data_checksum_reconstructed_` gegen `fragments_data_checksum_expected_`, um sicherzustellen, dass die Fragmente nicht manipuliert wurden, während der `Secure_Accessor` existierte.
   - Wenn alles korrekt ist, gibt es einen Zeiger auf `reconstructed_plain_buffer_` zurück.
3. Der Gültigkeitsbereich des `accessor` endet (Funktion wird verlassen, `{}`-Block endet usw.).
   - Der Destruktor von `Secure_Accessor` wird automatisch aufgerufen.
   - `Clear_All_Internal_Buffers()` wird aufgerufen, das sowohl `reconstructed_plain_buffer_` als auch die `fragments_storage_` sicher löscht (`Secure_Clear_Memory`).

Das Ergebnis ist, dass die Klartext-Zeichenkette in ihrer vollständigen Form nur innerhalb des `Secure_Accessor` (in `reconstructed_plain_buffer_`) und nur nach dem ersten Aufruf von `Get()` für die kürzest mögliche Zeit existiert. Die Zeichenkette im ursprünglichen `Obfuscated_String`-Objekt wird wieder verschleiert, sobald der `Secure_Accessor` während seiner Konstruktion ihren Inhalt kopiert hat.

#### Speicherfragmentierung im `Secure_Accessor`

Um die Lokalisierung der vollständigen Klartext-Zeichenkette im Speicher weiter zu erschweren, kopiert der `Secure_Accessor` während seiner Konstruktion die entschlüsselte Zeichenkette nicht nur, sondern teilt sie auch auf:
1. Die Zeichenkette aus dem übergeordneten `Obfuscated_String` wird entschlüsselt.
2. Ihr Inhalt wird in bis zu `fragment_count_val` (derzeit 4, wenn die Zeichenkette groß genug ist) Teile aufgeteilt, die in `fragments_storage_[i]` kopiert werden.
3. Die Zeichenkette im übergeordneten `Obfuscated_String`-Objekt wird wieder verschleiert.

Erst wenn `Secure_Accessor::Get()` zum ersten Mal aufgerufen wird, werden diese Fragmente in `reconstructed_plain_buffer_` wieder zusammengesetzt. Diese Technik zielt darauf ab, die sensiblen Daten zu "verteilen" und Speicherscans, die nach zusammenhängenden Zeichenketten suchen, zu vereiteln.

#### Sicheres Löschen des Speichers

Sowohl der Destruktor von `Obfuscated_String` (über `Clear_Internal_Data`) als auch der Destruktor von `Secure_Accessor` (über `Clear_All_Internal_Buffers`) verwenden `Dralyxor::Detail::Secure_Clear_Memory`. diese Wrapper-Funktion stellt sicher, dass Puffer mit sensiblen Daten zuverlässig genullt werden, und verhindert eine Compiler-Optimierung:
- **Unter Windows:** Verwendet `SecureZeroMemory` (User Mode) oder `RtlSecureZeroMemory` (Kernel Mode), welche Betriebssystemfunktionen sind, die speziell dafür entwickelt wurden, nicht optimiert zu werden und den Speicher sicher zu nullen.
- **Auf anderen Plattformen (Linux, macOS, etc.):** Die Implementierung verwendet jetzt `memset`, um den Speicherblock mit Nullen zu füllen. `memset` arbeitet auf Byte-Ebene, was es ideal und sicher macht, sowohl primitive Typen (wie `char`, `int`) als auch komplexe Typen (wie `structs`) zu nullen, und so Probleme mit Typkompatibilität oder Zuweisungsoperatoren vermeidet. Um sicherzustellen, dass der `memset`-Aufruf vom Compiler nicht optimiert und entfernt wird, wird der Pufferzeiger zuerst an einen `volatile`-Zeiger übergeben.

Dieser Ansatz stellt sicher, dass, wenn die Objekte zerstört werden, der sensible Inhalt überschrieben wird, was das Risiko der Datenwiederherstellung durch Analyse von Speicher-Dumps verringert.

### Komponente 3: Laufzeit-Abwehrmechanismen (Anti-Debugging und Anti-Tampering)

**Dralyxor** verlässt sich nicht nur auf Verschleierung. Es setzt eine Reihe von aktiven Laufzeit-Abwehrmechanismen ein, die sich hauptsächlich in `anti_debug.hpp` befinden und in die `Decrypt()`- und `Encrypt()`-Methoden des `Obfuscated_String` integriert sind.

#### Plattformübergreifende Erkennung von Debuggern

Die Funktion `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (in `anti_debug.hpp`) überprüft das Vorhandensein eines Debuggers unter Verwendung betriebssystemspezifischer Techniken:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` für `ProcessDebugPort` (0x07) und `ProcessDebugFlags` (0x1F).
- **Linux:** Lesen von `/proc/self/status` und Überprüfung des Werts von `TracerPid:`. Ein Wert ungleich 0 zeigt an, dass der Prozess verfolgt wird.
- **macOS:** Verwendung von `sysctl` mit `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` um `kinfo_proc` zu erhalten und Überprüfung des `P_TRACED`-Flags in `kp_proc.p_flag`.

Zusätzlich innerhalb von `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Führt eine Schleife mit einfachen Rechenoperationen aus und misst die Zeit. Eine signifikante Verlangsamung (über `timing_threshold_milliseconds = 75ms`) kann darauf hindeuten, dass ein Debugger im Einzelschrittmodus arbeitet oder dass umfangreiche Breakpoints aktiv sind. Innerhalb dieser Schleife wird `Is_Debugger_Present_Tracer_Pid_Sysctl()` aufgerufen, und eine "Köder"-Funktion `Detail::Canary_Function_For_Breakpoint_Check()` (die einfach `0xCC` zurückgibt, den Opcode für `int3` / Software-Breakpoint) wird aufgerufen und ihr Ergebnis XOR-verknüpft, was die Optimierung erschwert und einen häufigen Ort für Breakpoints bietet.
- `Detail::Perform_Output_Debug_String_Trick()` (nur Windows User Mode): Nutzt das Verhalten von `OutputDebugStringA/W` und `GetLastError()`. Wenn ein Debugger angehängt ist, kann `GetLastError()` nach dem Aufruf von `OutputDebugString` modifiziert werden.

#### Auswirkungen auf den Betrieb bei Erkennung oder Integritätsverletzung

Wenn eine der Anti-Debugging-Prüfungen `true` zurückgibt oder wenn die Integritäts-Canaries des `Obfuscated_String` (`_internal_integrity_canary1/2`) beschädigt sind, gibt die Funktion `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` `Detail::integrity_compromised_magic` zurück.

Dieser Rückgabewert ist in den Funktionen `Obfuscated_String::Decrypt()` und `Encrypt()` entscheidend:
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

        // WENN runtime_key_mod NICHT integrity_compromised_magic ist, WIRD ER NICHT VERWENDET, UM DEN ENTSCHLÜSSELUNGSSCHLÜSSEL ZU ÄNDERN.
        // Der Entschlüsselungsschlüssel wird immer aus dem ursprünglichen 'compile_time_seed' abgeleitet.
        // Die Rolle des runtime_key_mod ist hier, ALS EIN FLAG für eine feindliche Umgebung ZU AGIEREN.
        // Wenn die Umgebung feindlich ist, gibt die Funktion integrity_compromised_magic zurück, und die Entschlüsselung wird nicht fortgesetzt oder rückgängig gemacht.
        
        // Transform_Compile_Time_Consistent wird mit compile_time_seed (und NICHT mit runtime_key_mod) aufgerufen
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Prüfsumme und Canaries erneut überprüfen ...
        // Wenn etwas fehlschlägt, Clear_Internal_Data() und gibt integrity_compromised_magic zurück.
        decrypted_ = true;
    }

    return 0; // Erfolg
}
```

**Schlüsseleffekt:** Wenn `Calculate_Runtime_Key_Modifier` ein Problem erkennt (Debugger oder beschädigter Canary) und `integrity_compromised_magic` zurückgibt, brechen die Funktionen `Decrypt()` (und ähnlich `Encrypt()`) die Operation ab, löschen die internen Daten des `Obfuscated_String` (einschließlich `storage_` und `micro_program_`) und geben `integrity_compromised_magic` zurück. Dies verhindert, dass die Zeichenkette in einer feindlichen Umgebung korrekt entschlüsselt (oder neu verschlüsselt) wird oder wenn das Objekt manipuliert wurde.
Die Zeichenkette wird nicht "falsch" entschlüsselt (zu Müll); die Operation wird einfach verhindert, und das `Obfuscated_String`-Objekt zerstört sich selbst in Bezug auf seinen nützlichen Inhalt.

#### Integritäts-Canaries des Objekts

Sowohl die Klassen `Obfuscated_String` als auch `Secure_Accessor` enthalten Canary-Mitglieder (Paare von `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initialisiert mit `Detail::integrity_canary_value`) und `_internal_integrity_canary2` (initialisiert mit `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initialisiert mit `Detail::accessor_integrity_canary_seed`) und `_accessor_integrity_canary2` (initialisiert mit `~Detail::accessor_integrity_canary_seed`).

Diese Canaries werden an kritischen Punkten überprüft:
- Beginn und Ende von `Obfuscated_String::Decrypt()` und `Encrypt()`.
- Konstruktor, Destruktor und `Get()` des `Secure_Accessor`.
- Vor und nach den Anti-Debug-Prüfungen in `Calculate_Runtime_Key_Modifier`.

Wenn diese Canary-Werte geändert werden (z. B. durch einen Pufferüberlauf, einen wahllosen Speicher-Patch oder einen Hook, der benachbarten Speicher überschreibt), schlägt die Überprüfung (`Verify_Internal_Canaries()` oder `Verify_Internal_Accessor_Canaries()`) fehl.
Im Falle eines Fehlers werden die Operationen abgebrochen, die relevanten internen Daten gelöscht und ein Fehlerwert (`Detail::integrity_compromised_magic` oder `nullptr`) zurückgegeben, der eine Manipulation signalisiert.

#### Prüfsumme des Zeichenketteninhalts

- Eine 16-Bit-Prüfsumme der *ursprünglichen Klartext*-Zeichenkette (ohne den Null-Terminator) wird zur Kompilierzeit von `Detail::Calculate_String_Content_Checksum` berechnet.
- Diese Prüfsumme wird dann mit `Detail::Obfuscate_Deobfuscate_Short_Value` verschleiert (mit `compile_time_seed` und `content_checksum_obf_salt`) und in `_content_checksum_obfuscated` im `Obfuscated_String`-Objekt gespeichert.
- **Beim Entschlüsseln (`Decrypt()`):** Nachdem `storage_` transformiert wurde (vermutlich in Klartext), wird seine Prüfsumme berechnet. Das `_content_checksum_obfuscated` wird entschlüsselt, um die Referenzprüfsumme zu erhalten. Wenn die beiden Prüfsummen nicht übereinstimmen, deutet dies darauf hin, dass:
   - Die Entschlüsselung die ursprüngliche Zeichenkette nicht wiederhergestellt hat (vielleicht weil die Operation aufgrund der Debugger-Erkennung vor der vollständigen Transformation abgebrochen wurde oder weil der Seed/das Mikroprogramm beschädigt wurde).
   - Der `storage_` (im verschleierten Zustand) oder das `_content_checksum_obfuscated` im Speicher manipuliert wurde.
- **Beim Verschlüsseln (`Encrypt()`):** Bevor `storage_` (das sich zu diesem Zeitpunkt im Klartext befindet) zurück in seine verschleierte Form transformiert wird, wird seine Prüfsumme berechnet und mit der Referenz verglichen. Eine Abweichung hier würde bedeuten, dass die Klartext-Zeichenkette *innerhalb des `storage_` des `Obfuscated_String` geändert wurde, während es entschlüsselt war*, was ein starkes Indiz für Speichermanipulation oder unsachgemäße Verwendung ist (da der Zugriff auf `storage_` nicht direkt erfolgen sollte).

In beiden Fällen eines Prüfsummenfehlers wird `Clear_Internal_Data()` aufgerufen und `integrity_compromised_magic` zurückgegeben.

### Komponente 4: Erzeugung einzigartiger und unvorhersehbarer Schlüssel und Seeds

Die Sicherheit jedes Verschlüsselungssystems beruht auf der Stärke und Einzigartigkeit seiner Schlüssel und Seeds. **Dralyxor** stellt sicher, dass jede verschleierte Zeichenkette einen fundamental einzigartigen Satz von Verschlüsselungsparametern verwendet.

#### Entropiequellen für den `compile_time_seed`

Der `static constexpr uint64_t Obfuscated_String::compile_time_seed` ist der Master-Seed für alle pseudozufälligen Operationen, die sich auf diese Instanz der Zeichenkette beziehen. Seine Erzeugung ist nun bedingt und basiert auf dem Vorhandensein eines vom Benutzer bereitgestellten Schlüssels:

- **Wenn ein Schlüssel vom Benutzer bereitgestellt wird (mit `DRALYXOR_KEY` oder `DRALYXOR_KEY_LOCAL`):**
   1. Das bereitgestellte `key_literal` wird zur Kompilierzeit mit dem FNV-1a-Algorithmus in einen 64-Bit-Hash umgewandelt.
   2. Dieser Hash wird zur Basis des `compile_time_seed`, kombiniert mit `__COUNTER__` (um die Einzigartigkeit zwischen verschiedenen Verwendungen desselben Schlüssels zu gewährleisten) und der Länge der Zeichenkette.
      ```cpp
      // Vereinfachte Logik
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      In diesem Modus hängt die Sicherheit der Verschleierung direkt von der Stärke und dem Geheimnis des bereitgestellten Schlüssels ab.

- **Wenn kein Schlüssel bereitgestellt wird (mit `DRALYXOR` oder `DRALYXOR_LOCAL`):**
   - Der `compile_time_seed` wird durch die Kombination der folgenden Faktoren erzeugt, um die Entropie und Variabilität zu maximieren:
      ```cpp
      // Innerhalb von Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
           Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponente 1: Variabilität zwischen Kompilierungen
           ((uint64_t)Instance_Counter << 32) ^        // Komponente 2: Variabilität innerhalb einer Kompilationseinheit
           storage_n;                                  // Komponente 3: Variabilität basierend auf der Länge der Zeichenkette
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Die Makros `__DATE__` (z. B. "Jan 01 2025") und `__TIME__` (z. B. "12:30:00") sind vom Präprozessor bereitgestellte Zeichenketten, die sich bei jeder Kompilierung der Datei ändern. Der FNV-1a-Hash dieser Werte erzeugt einen Basis-Seed, der für jeden Build des Projekts unterschiedlich ist.
   - **`Instance_Counter` (gespeist durch `__COUNTER__` im Makro)**: Das Makro `__COUNTER__` ist ein vom Präprozessor verwalteter Zähler, der bei jeder Verwendung innerhalb einer Kompilationseinheit inkrementiert wird. Indem dies als Template-Argument übergeben wird, führt jede Verwendung des `DRALYXOR`- oder `DRALYXOR_LOCAL`-Makros zu einem unterschiedlichen `Instance_Counter` und somit zu einem unterschiedlichen `compile_time_seed`, selbst für identische Zeichenketten-Literale in derselben Quelldatei.
   - **`storage_n` (Länge der Zeichenkette)**: Die Länge der Zeichenkette wird ebenfalls XOR-verknüpft, was einen weiteren Differenzierungsfaktor hinzufügt.

Dieser `compile_time_seed` (ob vom Benutzerschlüssel abgeleitet oder automatisch generiert) wird dann als Basis für Folgendes verwendet:
1. Erzeugung des `micro_program_` (Initialisierung des PRNG mit `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Ableitung des Verschleierungsschlüssels für das `micro_program_` selbst (über `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Ableitung des Verschleierungsschlüssels für das `_content_checksum_obfuscated` (über `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Dient als `base_seed` für `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Abgeleitete Seeds für Inhalts-Transformationen

Innerhalb von `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Ein `Constexpr_PRNG prng_operand_modifier(base_seed)` wird initialisiert. Für jedes Zeichen der zu transformierenden Zeichenkette erzeugt `prng_operand_modifier.Key()` einen `prng_key_for_ops_in_elem`. Dieser Schlüssel wird vor der Anwendung mit dem Operanden der Mikroanweisung XOR-verknüpft, um sicherzustellen, dass die Wirkung derselben Mikroanweisung für jedes Zeichen geringfügig anders ist.
- Ein `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` wird initialisiert. Für jedes Zeichen wird `prng_applier_selector.Key()` verwendet, um zwischen `Applier_Style_Direct` und `Applier_Style_DoubleLayer` zu wählen.

Dies führt eine zusätzliche Dynamik in die Transformation jedes Zeichens ein, selbst wenn das zugrunde liegende Mikroprogramm für alle Zeichen einer gegebenen Zeichenkette dasselbe ist.

#### Immunität gegen "Replay"-Angriffe und Musteranalyse

- **Inter-Kompilations-Einzigartigkeit:** Wenn ein Angreifer die Binärdatei der Version 1.0 Ihrer Software analysiert und es mit viel Aufwand schafft, die Verschleierung einer Zeichenkette (im automatischen Schlüsselmodus) zu brechen, wird dieses Wissen für die Version 1.1 wahrscheinlich nutzlos sein, da sich `__DATE__ __TIME__` geändert hat, was zu völlig unterschiedlichen `compile_time_seed`s und Mikroprogrammen führt.
- **Intra-Kompilations-Einzigartigkeit:** Wenn Sie `DRALYXOR("AdminPassword")` an zwei verschiedenen Stellen in Ihrem Code (oder in derselben .cpp-Datei) verwenden, stellt `__COUNTER__` sicher, dass die resultierenden `Obfuscated_String`-Objekte und damit ihre verschleierten Darstellungen in der Binärdatei unterschiedlich sind. Dies verhindert, dass ein Angreifer ein verschleiertes Muster findet und es verwendet, um alle anderen Vorkommen derselben ursprünglichen Zeichenkette zu lokalisieren.

Diese robuste Generierung von Seeds ist ein Eckpfeiler der Sicherheit von **Dralyxor** gegen Angriffe, die darauf beruhen, ein "Master-Geheimnis" zu entdecken oder die Wiederholung von Chiffren und Transformationen auszunutzen.

## Vollständige Referenz der öffentlichen API

### Obfuskations-Makros

Dies sind die Haupt-Einstiegspunkte zur Erstellung verschleierter Zeichenketten.

#### `DRALYXOR(str_literal)`

- **Zweck:** Erstellt ein `Obfuscated_String`-Objekt mit statischer Lebensdauer (existiert während der gesamten Programmausführung). Ideal für globale Konstanten oder Zeichenketten, die von mehreren Stellen aus zugänglich sein müssen und persistent sein sollen.
- **Speicherort:** Statischer Speicher (normalerweise im Datenbereich des Programms).
- **Implementierung:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parameter:**
   - `str_literal`: Ein C-Style-String-Literal (z. B. `"Hello World"`, `L"Unicode String"`).
- **Rückgabe:** Eine Referenz (`auto&`) auf das statische `Obfuscated_String`-Objekt, das innerhalb einer sofort aufgerufenen Lambda-Funktion erstellt wird.
- **Beispiel:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url ist eine Referenz auf ein statisches Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Zweck:** Erstellt ein `Obfuscated_String`-Objekt mit automatischer Lebensdauer (normalerweise auf dem Stack, wenn innerhalb einer Funktion verwendet). Ideal für temporäre Geheimnisse, die auf einen Gültigkeitsbereich beschränkt sind.
- **Speicherort:** Automatisch (Stack für lokale Funktionsvariablen).
- **Implementierung:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
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

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Zweck:** Ähnlich wie `DRALYXOR`, erstellt ein statisches `Obfuscated_String`-Objekt, verwendet aber einen **vom Benutzer bereitgestellten Schlüssel** (`key_literal`), um die Verschleierung zu initialisieren, was die höchste Sicherheitsstufe bietet.
- **Speicherort:** Statischer Speicher (normalerweise im Datenbereich des Programms).
- **Implementierung:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parameter:**
   - `str_literal`: Das zu verschleiernde String-Literal.
   - `key_literal`: Das als geheimer Schlüssel zu verwendende String-Literal.
- **Rückgabe:** Eine Referenz (`auto&`) auf das statische `Obfuscated_String`-Objekt.
- **Beispiel:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Zweck:** Ähnlich wie `DRALYXOR_LOCAL`, erstellt ein `Obfuscated_String`-Objekt auf dem Stack, unter Verwendung eines **vom Benutzer bereitgestellten Schlüssels**.
- **Speicherort:** Automatisch (Stack für lokale Funktionsvariablen).
- **Implementierung:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parameter:**
   - `str_literal`: Das zu verschleiernde String-Literal.
   - `key_literal`: Das als Schlüssel zu verwendende String-Literal.
- **Rückgabe:** Ein `Obfuscated_String`-Objekt per Wert.
- **Beispiel:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Makro für sicheren Zugriff

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Zweck:** Bietet sicheren und temporären Zugriff auf den entschlüsselten Inhalt eines `Obfuscated_String`-Objekts. Dies ist die **einzig empfohlene Methode**, um die Zeichenkette zu lesen.
- **Implementierung:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parameter:**
   - `obfuscated_var`: Eine Variable (L-Wert oder R-Wert, der an eine nicht-konstante L-Wert-Referenz gebunden werden kann) vom Typ `Dralyxor::Obfuscated_String<...>`. Die Variable muss veränderbar sein, da der Konstruktor des `Secure_Accessor` `Decrypt()` und `Encrypt()` darauf aufruft.
- **Rückgabe:** Ein `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>`-Objekt per Wert.
- **Verwendung:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Oder nur: const char* secret_ptr = accessor; (implizite Konvertierung)
      
       if (secret_ptr) {
           // Verwenden Sie secret_ptr hier. Er zeigt auf die temporär entschlüsselte Zeichenkette im Puffer des Accessors.
           // Bsp: send_data(secret_ptr);
       }
       else {
           // Entschlüsselung oder Integrität fehlgeschlagen. Behandeln Sie den Fehler.
           // Der Accessor konnte möglicherweise nicht initialisiert werden (z. B. weil my_static_secret beschädigt wurde).
       }
   } // accessor wird zerstört. Seine internen Puffer (Fragmente und rekonstruierte Zeichenkette) werden bereinigt.
     // my_static_secret.storage_ wurde bereits durch den Konstruktor des Secure_Accessor wieder verschleiert,
     // direkt nach dem Kopieren des Inhalts in die Fragmente des Accessors.
   ```

> [!WARNING]
> Überprüfen Sie immer, ob der von `DRALYXOR_SECURE(...).Get()` (oder durch die implizite Konvertierung) zurückgegebene Zeiger nicht `nullptr` ist, bevor Sie ihn verwenden. Eine `nullptr`-Rückgabe weist auf einen Fehler bei der Entschlüsselung hin (z. B. Erkennung eines Debuggers, Beschädigung von Canaries/Prüfsummen im übergeordneten `Obfuscated_String` oder im `Secure_Accessor` selbst). Die Verwendung eines `nullptr`-Zeigers führt zu undefiniertem Verhalten (wahrscheinlich eine Speicherzugriffsverletzung).

## Erweiterte Funktionen und Best Practices

### Volle Unicode-Unterstützung (Wide Strings - `wchar_t`)

**Dralyxor** ist dank der Verwendung von Templates (`CharT`) agnostisch gegenüber dem Zeichentyp. Es verarbeitet nativ `char` (für ASCII/UTF-8-Zeichenketten) und `wchar_t` (für UTF-16-Zeichenketten unter Windows oder UTF-32 auf anderen Systemen, abhängig von Plattform und Compiler). Verwenden Sie einfach das Präfix `L` für `wchar_t`-Literale:
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

Für 1-Byte-Zeichen (`sizeof(CharT) == 1`) wendet die `Micro_Program_Cipher`-Transformations-Engine das Mikroprogramm Byte für Byte an. Für Multibyte-Zeichen (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` verwendet einen einfacheren Ansatz: Das gesamte Multibyte-Zeichen wird mit einer Maske XOR-verknüpft, die aus dem `prng_key_for_ops_in_elem` abgeleitet wird (repliziert, um die Größe des `CharT` zu füllen). Wenn `CharT` beispielsweise `wchar_t` (2 Bytes) ist und `prng_key_for_ops_in_elem` `0xAB` ist, wird das Zeichen mit `0xABAB` XOR-verknüpft.
Dies stellt sicher, dass alle Bytes des `wchar_t` von der Verschleierung betroffen sind, auch wenn es nicht durch das vollständige Mikroprogramm geschieht. Die Komplexität des Mikroprogramms trägt immer noch indirekt durch die Ableitung der PRNG-Schlüssel bei.

### Intelligente Anpassung an **C++**-Standards und Umgebungen (Kernel Mode)

Wie bereits erwähnt, passt sich **Dralyxor** an:
- **C++ Standards:** Benötigt mindestens **C++14**. Erkennt und nutzt Funktionen von **C++17** und **C++20** (wie `if constexpr`, `consteval`, `_v`-Suffixe für `type_traits`), wenn der Compiler sie unterstützt, und greift andernfalls auf **C++14**-Alternativen zurück. Makros wie `_DRALYXOR_IF_CONSTEXPR` und `_DRALYXOR_CONSTEVAL` in `detection.hpp` verwalten diese Anpassung.
- **Kernel Mode:** Wenn `_KERNEL_MODE` definiert ist (typisch für WDK-Projekte für Windows-Treiber), vermeidet **Dralyxor** (über `env_traits.hpp`) das Einbinden von Standard-STL-Headern wie `<type_traits>`, die möglicherweise nicht verfügbar sind oder sich anders verhalten. Stattdessen verwendet es seine eigenen `constexpr`-Implementierungen von grundlegenden Werkzeugen wie `Dralyxor::Detail::Fallback::decay` und `Dralyxor::Detail::Fallback::remove_reference`. Dies ermöglicht die sichere Verwendung von **Dralyxor** zum Schutz von Zeichenketten in Systemkomponenten auf niedriger Ebene.
   - Ähnlich verwendet `secure_memory.hpp` `RtlSecureZeroMemory` im Kernel Mode. Für andere Plattformen wie Linux greift es auf die sichere Verwendung von `memset` zurück, um die Speicherbereinigung zu gewährleisten und sich an verschiedene Datentypen anzupassen.
   - Die Anti-Debug-Prüfungen im User Mode (wie `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) sind im Kernel Mode deaktiviert (`#if !defined(_KERNEL_MODE)`), da sie nicht zutreffen oder andere Entsprechungen haben. Die Timing-Prüfungen können immer noch eine gewisse Wirkung haben, aber die Hauptverteidigungslinie im Kernel Mode ist die Verschleierung selbst.

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
>    - Sichere Konfigurationen, die zur Laufzeit bereitgestellt werden (Umgebungsvariablen, Konfigurationsdateien mit eingeschränkten Berechtigungen).
>    - Geheimnisverwaltungsdienste (Vaults) wie HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
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