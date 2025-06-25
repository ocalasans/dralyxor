# Dralyxor

**Dralyxor** är ett modernt, `header-only`, högpresterande och flerskiktat **C++**-bibliotek, designat för strängobfuskering vid kompileringstid och robust skydd vid körtid. Dess grundläggande uppdrag är att skydda din applikations inneboende hemligheter – såsom API-nycklar, lösenord, interna URL:er, felsökningsmeddelanden och alla känsliga strängliteraler – från exponering genom statisk analys, reverse engineering och dynamisk minnesinspektion. Genom att kryptera och transformera strängar vid kompileringstillfället och hantera deras åtkomst säkert vid körtid, säkerställer **Dralyxor** att inga kritiska strängliteraler existerar som klartext i din slutliga binärfil eller förblir oskyddade i minnet längre än absolut nödvändigt.

Byggt på grunderna i modern **C++** (kräver **C++14** och anpassar sig intelligent till funktioner i **C++17** och **C++20**), presenterar dess avancerade arkitektur en sofistikerad transformeringsmotor baserad på "mikroprogram", obfuskering av själva transformeringsprogrammet, dataintegritetsmekanismer, anti-debugging-försvar och en **Scoped Secure Accessor (RAII)** för "just-in-time"-dekryptering och automatisk återobfuskering. Detta minimerar drastiskt exponeringen av data i **RAM**-minnet och tillhandahåller ett djupgående försvar på professionell nivå.

## Språk

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Türkçe: [README](../Turkce/README.md)

## Innehållsförteckning

- [Dralyxor](#dralyxor)
  - [Språk](#språk)
  - [Innehållsförteckning](#innehållsförteckning)
  - [Snabbguide för Integration och Användning](#snabbguide-för-integration-och-användning)
    - [Installation](#installation)
    - [Kompilatorkrav](#kompilatorkrav)
    - [Grundläggande Användningsmönster](#grundläggande-användningsmönster)
      - [Mönster 1: Lokal (Stack) Obfuskering](#mönster-1-lokal-stack-obfuskering)
      - [Mönster 2: Statisk (Global) Obfuskering](#mönster-2-statisk-global-obfuskering)
    - [Felhantering och Integritet](#felhantering-och-integritet)
  - [Detaljerad Designfilosofi och Arkitektur](#detaljerad-designfilosofi-och-arkitektur)
    - [Det Ständiga Hotet: Sårbarheten hos Strängliteraler](#det-ständiga-hotet-sårbarheten-hos-strängliteraler)
    - [Dralyxors Flerskiktade Arkitektoniska Lösning](#dralyxors-flerskiktade-arkitektoniska-lösning)
  - [Djupgående Analys av Arkitektoniska Komponenter](#djupgående-analys-av-arkitektoniska-komponenter)
    - [Komponent 1: Transformeringsmotorn med Mikroprogram](#komponent-1-transformeringsmotorn-med-mikroprogram)
      - [Kraften hos `consteval` och `constexpr` för Generering vid Kompileringstid](#kraften-hos-consteval-och-constexpr-för-generering-vid-kompileringstid)
      - [Anatomin hos ett Dralyxor Mikroprogram](#anatomin-hos-ett-dralyxor-mikroprogram)
        - [Slumpmässig Generering av Instruktioner och Val av Applikatorer](#slumpmässig-generering-av-instruktioner-och-val-av-applikatorer)
        - [Variabla och Logiska NOP:ar för Entropi](#variabla-och-logiska-nopar-för-entropi)
      - [Obfuskering av Själva Mikroprogrammet](#obfuskering-av-själva-mikroprogrammet)
      - [Livscykeln för Statisk Obfuskering](#livscykeln-för-statisk-obfuskering)
    - [Komponent 2: Säker Åtkomst och Minimering av Exponering i RAM](#komponent-2-säker-åtkomst-och-minimering-av-exponering-i-ram)
      - [`Secure_Accessor` och RAII-Principen](#secure_accessor-och-raii-principen)
      - [Minnesfragmentering i `Secure_Accessor`](#minnesfragmentering-i-secure_accessor)
      - [Säker Minnesrensning](#säker-minnesrensning)
    - [Komponent 3: Körtidsförsvar (Anti-Debugging och Anti-Tampering)](#komponent-3-körtidsförsvar-anti-debugging-och-anti-tampering)
      - [Multi-Plattformsdetektering av Debuggers](#multi-plattformsdetektering-av-debuggers)
      - [Påverkan på Drift vid Detektering eller Integritetsbrott](#påverkan-på-drift-vid-detektering-eller-integritetsbrott)
      - [Objektintegritets-Canaries](#objektintegritets-canaries)
      - [Checksumma för Stränginnehåll](#checksumma-för-stränginnehåll)
    - [Komponent 4: Generering av Unika och Oförutsägbara Nycklar och Seeds](#komponent-4-generering-av-unika-och-oförutsägbara-nycklar-och-seeds)
      - [Entropikällor för `compile_time_seed`](#entropikällor-för-compile_time_seed)
      - [Härledda Seeds för Innehållstransformationer](#härledda-seeds-för-innehållstransformationer)
      - [Immunitet mot "Replay"-attacker och Mönsteranalys](#immunitet-mot-replay-attacker-och-mönsteranalys)
  - [Fullständig Referens för Publikt API](#fullständig-referens-för-publikt-api)
    - [Obfuskeringsmakron](#obfuskeringsmakron)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Säker Åtkomst-Makro](#säker-åtkomst-makro)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Avancerade Funktioner och God Praxis](#avancerade-funktioner-och-god-praxis)
    - [Fullständigt Stöd för Unicode (Wide Strings - `wchar_t`)](#fullständigt-stöd-för-unicode-wide-strings---wchar_t)
    - [Intelligent Anpassning till C++ Standarder och Miljöer (Kernel Mode)](#intelligent-anpassning-till-c-standarder-och-miljöer-kernel-mode)
    - [Prestanda- och Overhead-Överväganden](#prestanda--och-overhead-överväganden)
    - [Integration i en Flerskiktad Säkerhetsstrategi](#integration-i-en-flerskiktad-säkerhetsstrategi)
  - [Licens](#licens)
    - [Villkor:](#villkor)

## Snabbguide för Integration och Användning

### Installation

**Dralyxor** är ett **header-only**-bibliotek. Ingen förkompilering eller länkning av bibliotek (`.lib`/`.a`) krävs.

1.  **Kopiera Katalogen `Dralyxor`:** Hämta den senaste versionen av biblioteket (klona repositoriet eller ladda ner zip-filen) och kopiera hela katalogen `Dralyxor` (som innehåller alla `.hpp`-filer) till en plats som är tillgänglig för ditt projekt (t.ex. en mapp `libs/`, `libraries/`, eller `vendor/`).
2.  **Inkludera Huvudheadern:** I din källkod, inkludera huvudheadern `dralyxor.hpp`:
    ```cpp
    #include "sökväg/till/Dralyxor/dralyxor.hpp"
    ```

En typisk projektstruktur:
```
/MittProjekt/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor här
        |-- dralyxor.hpp            (Huvudingångspunkt)
        |-- obfuscated_string.hpp   (Klassen Obfuscated_String)
        |-- secure_accessor.hpp     (Klassen Secure_Accessor)
        |-- algorithms.hpp          (Transformeringsmotor och mikroprogram)
        |-- anti_debug.hpp          (Körtidsdetekteringar)
        |-- prng.hpp                (Pseudo-slumptalsgenerator vid kompileringstid)
        |-- integrity_constants.hpp (Konstanter för integritetskontroller)
        |-- secure_memory.hpp       (Säker minnesrensning)
        |-- detection.hpp           (Detekteringsmakron för kompilator/C++-standard)
        `-- env_traits.hpp          (Anpassningar av type_traits för begränsade miljöer)
```

### Kompilatorkrav

> [!IMPORTANT]
> **Dralyxor** har designats med fokus på modern **C++** för maximal säkerhet och effektivitet vid kompileringstid.
>
> - **Minsta C++ Standard: C++14**. Biblioteket använder funktioner som generaliserad `constexpr` och anpassar sig för `if constexpr` (när tillgängligt via `_DRALYXOR_IF_CONSTEXPR`).
> - **Anpassning till Högre Standarder:** Upptäcker och använder optimeringar eller syntax från **C++17** och **C++20** (såsom `consteval`, `_v`-suffix för `type_traits`) om projektet kompileras med dessa standarder. `_DRALYXOR_CONSTEVAL` mappas till `consteval` i C++20 och `constexpr` i C++14/17, vilket garanterar exekvering vid kompileringstid där det är möjligt.
> - **Stödda Kompilatorer:** Primärt testat med de senaste versionerna av MSVC, GCC och Clang.
> - **Körtidsmiljö:** Fullt kompatibelt med **User Mode**-applikationer och **Kernel Mode**-miljöer (t.ex. Windows-drivrutiner). I Kernel Mode, där STL kanske inte är tillgängligt, använder **Dralyxor** interna implementationer för nödvändiga `type traits` (se `env_traits.hpp`).

### Grundläggande Användningsmönster

#### Mönster 1: Lokal (Stack) Obfuskering

Idealiskt för temporära strängar, begränsade till ett funktions-scope. Minnet hanteras och rensas automatiskt.

```cpp
#include "Dralyxor/dralyxor.hpp" // Anpassa sökvägen efter behov
#include <iostream>

void Configure_Logging() {
    // Loggformateringsnyckel, används endast lokalt.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Säker åtkomst inom ett begränsat scope
    {
        // Secure_Accessor deobfuskerar temporärt 'log_format_key' under sin konstruktion
        // (och återobfuskerar 'log_format_key' omedelbart efter kopiering till sina interna buffertar),
        // tillåter åtkomst, och rensar sina egna buffertar vid destruktion.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Kontrollera alltid att Get() inte returnerar nullptr
            std::cout << "Använder loggformat: " << accessor.Get() << std::endl;
            // Ex: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Misslyckades med att dekryptera log_format_key (möjlig tampering eller debugger-detektering?)" << std::endl;
    } // accessor förstörs, dess interna buffertar rensas. log_format_key förblir obfuskerad.
      // log_format_key kommer att förstöras i slutet av funktionen Configure_Logging.
}
```

#### Mönster 2: Statisk (Global) Obfuskering

För konstanter som behöver bestå under programmets livstid och vara globalt åtkomliga.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // För exemplet

// API URL för licenser, en beständig hemlighet.
// Makrot DRALYXOR() skapar ett statiskt objekt.
// Funktionen Get_License_Server_URL() returnerar en referens till detta statiska objekt.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref är en referens till det statiska Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Skapar en Secure_Accessor för url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Kontaktar licensserver på: " << accessor.Get() << std::endl;
            // Ex: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulerar framgång för exemplet
        }
        else
            std::cerr << "Misslyckades med att dekryptera licensserverns URL (möjlig tampering eller debugger-detektering?)." << std::endl;
    } // accessor förstörs, dess buffertar rensas. url_obj_ref (det ursprungliga Obfuscated_String) förblir obfuskerad.

    return success;
}
```

### Felhantering och Integritet

Funktionerna `Obfuscated_String::Decrypt()` och `Encrypt()` returnerar `uint64_t`:
- `0` indikerar framgång.
- `Dralyxor::Detail::integrity_compromised_magic` (ett konstant värde definierat i `integrity_constants.hpp`) indikerar att en integritetskontroll misslyckades. Detta kan bero på korrupta objekt-canaries, inkonsekvent innehålls-checksumma, eller detektering av en debugger som signalerar en fientlig miljö.

På samma sätt kommer `Secure_Accessor::Get()` (eller dess implicita konvertering till `const CharT*`) att returnera `nullptr` om initialiseringen av `Secure_Accessor` misslyckas (t.ex. om dekrypteringen av det ursprungliga `Obfuscated_String` misslyckas) eller om integriteten hos `Secure_Accessor` (dess egna canaries eller interna checksummor) komprometteras under dess livstid.

**Det är avgörande att din kod kontrollerar dessa returvärden för att säkerställa applikationens robusthet och säkerhet.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Viktig Data!");

    // Du skulle vanligtvis INTE anropa Decrypt() och Encrypt() direkt,
    // eftersom Secure_Accessor hanterar detta. Men om du behöver av någon anledning:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "VARNING: Misslyckades med att dekryptera 'my_secret' eller integritet komprometterad under Decrypt()!" << std::endl;
        // Vidta lämplig åtgärd: avsluta, logga säkert, etc.
        // Objektet my_secret.storage_ kan vara i ett ogiltigt eller skräptillstånd.
        return; // Undvik att använda my_secret om Decrypt() misslyckas.
    }

    // Om Decrypt() lyckades, innehåller my_secret.storage_ dekrypterad data.
    // **DIREKT ÅTKOMST TILL storage_ REKOMMENDERAS STARKT INTE I PRODUKTION.**
    // std::cout << "Data i my_secret.storage_ (GÖR INTE SÅ HÄR): " << my_secret.storage_ << std::endl;

    // Det är ditt ansvar att återkryptera om du anropade Decrypt() manuellt:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "VARNING: Misslyckades med att återkryptera 'my_secret' eller integritet komprometterad under Encrypt()!" << std::endl;
        // Osäkert tillstånd, potentiellt farligt.
    }

    // REKOMMENDERAD ANVÄNDNING med Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Annan Databit!");
    {
        // Secure_Accessor-konstruktorn anropar another_secret.Decrypt(), kopierar, och sedan another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Eller: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Hemlig data via Secure_Accessor: " << data_ptr << std::endl;
            // Använd data_ptr här
        }
        else {
            std::cerr << "VARNING: Secure_Accessor misslyckades med att initiera eller hämta pekare för 'another_secret'!" << std::endl;
            // Detta indikerar att Decrypt() inuti accessor-konstruktorn misslyckades,
            // eller att det skett tampering med accessor (canaries, interna checksummor).
        }
    } // accessor förstörs. Dess buffertar rensas. another_secret förblir obfuskerad.
}
```

## Detaljerad Designfilosofi och Arkitektur

**Dralyxor** är inte bara en XOR-chiffer; det är ett djupgående försvarssystem för strängliteraler. Dess arkitektur grundar sig på premissen att effektiv säkerhet kräver flera sammankopplade lager och motståndskraft mot olika analystekniker.

### Det Ständiga Hotet: Sårbarheten hos Strängliteraler

Strängliteraler, som `"api.example.com/data?key="`, när de är inbäddade direkt i koden, skrivs i läsbar form (klartext) i den kompilerade binärfilen. Verktyg som `strings`, disassemblers (IDA Pro, Ghidra) och hex-editorer kan extrahera dem trivialt. Denna exponering underlättar:
- **Reverse Engineering:** Förståelse av programmets interna logik och flöde.
- **Identifiering av Endpoints:** Upptäckt av backend-servrar och API:er.
- **Extrahering av Hemligheter:** API-nycklar, inbäddade lösenord, privata URL:er, SQL-frågor, etc.
- **Dynamisk Minnesanalys:** Även om ett program dekrypterar en sträng för användning, om den förblir i klartext i **RAM** under lång tid, kan en angripare med åtkomst till processens minne (via en debugger eller minnesdump) hitta den.

**Dralyxor** attackerar dessa sårbarheter både vid kompileringstid (för binärfilen på disk) och vid körtid (för **RAM**-minnet).

### Dralyxors Flerskiktade Arkitektoniska Lösning

Robustheten hos **Dralyxor** härrör från synergin mellan dess nyckelkomponenter:

| Arkitektonisk Komponent                     | Primärt Mål                                                                        | Använda Nyckelteknologier/Tekniker                                                                                                                              |
| :------------------------------------------ | :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Transformeringsmotor med Mikroprogram**   | Eliminera klartextsträngar från binärfilen; skapa komplex, dynamisk och icke-trivial obfuskering.   | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, flera operationer (XOR, ADD, ROT, etc.), variabla och logiska NOP:ar, varierande applikatorstilar.         |
| **Säker Åtkomst och Minimering av Exponering** | Drastiskt reducera tiden en hemlighet är dekrypterad i RAM-minnet.                       | RAII-mönster (`Secure_Accessor`), minnesfragmentering, säker rensning av buffertar (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Körtidsförsvar**                         | Upptäcka och reagera på fientliga analysmiljöer och minnesmanipulation.                 | Debugger-detektering (OS-specifika API:er, timing, OutputDebugString), objektintegritets-canaries, checksumma för stränginnehåll.                              |
| **Generering av Unika Nycklar och Seeds**    | Säkerställa att varje obfuskerad sträng och varje användningsinstans är kryptografiskt distinkta. | `__DATE__`, `__TIME__`, `__COUNTER__`, strängstorlek, FNV-1a-hashing för `compile_time_seed`, härledda seeds för operandmodifierare och selektorer. |

## Djupgående Analys av Arkitektoniska Komponenter

### Komponent 1: Transformeringsmotorn med Mikroprogram

Hjärtat i **Dralyxors** statiska och dynamiska obfuskering ligger i dess transformeringsmotor som använder unika "mikroprogram" för varje sträng och kontext.

#### Kraften hos `consteval` och `constexpr` för Generering vid Kompileringstid
Modern **C++**, med `consteval` (**C++20**) och `constexpr` (**C++11** och framåt), tillåter att komplex kod exekveras *under kompileringen*. **Dralyxor** använder `_DRALYXOR_CONSTEVAL` (som mappas till `consteval` eller `constexpr` beroende på **C++**-standard) för `Obfuscated_String`-konstruktorn och för generering av mikroprogrammet.

Detta innebär att hela processen med att:
1. Generera en pseudo-slumpmässig sekvens av transformeringsinstruktioner (mikroprogrammet).
2. Obfuskera själva mikroprogrammet för lagring.
3. Applicera detta mikroprogram (temporärt de-obfuskerat) för att transformera den ursprungliga strängen, vilket resulterar i dess obfuskerade form.
Allt detta sker vid kompileringstid, innan binärfilen genereras.

#### Anatomin hos ett Dralyxor Mikroprogram

Varje `Obfuscated_String`-objekt lagrar en liten array av `Dralyxor::Detail::Micro_Instruction`. En `Micro_Instruction` är en enkel struktur definierad i `algorithms.hpp`:
```cpp
// I Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM // Även om närvarande, används inte aktivt för att avsluta mikroprogrammets exekvering,
                   // iterationen styrs av 'num_actual_instructions_in_program_'.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // Operationen (XOR, ADD, ROTL, etc.)
    uint8_t operand;            // Värdet som används av operationen
};

// Maximalt antal instruktioner ett mikroprogram kan innehålla.
static constexpr size_t max_micro_instructions = 8;
```
Funktionen `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` ansvarar för att fylla denna array.

##### Slumpmässig Generering av Instruktioner och Val av Applikatorer

- **Generering av Instruktioner:** Med hjälp av en `Dralyxor::Detail::Constexpr_PRNG` (seedad med en kombination av `compile_time_seed` och `0xDEADBEEFC0FFEEULL`), väljer funktionen `Generate_Micro_Program_Instructions` probabilistiskt en sekvens av operationer:
    - `XOR`: Bitvis XOR med operanden.
    - `ADD`: Modulär addition med operanden.
    - `SUB`: Modulär subtraktion med operanden.
    - `ROTR`/`ROTL`: Bitrotation. Operanden (efter modulo) definierar antalet skiftningar (1 till 7).
    - `SWAP_NIB`: Byter de 4 lägre bitarna med de 4 övre bitarna i en byte (operanden ignoreras).
    Operanderna för dessa instruktioner genereras också pseudo-slumpmässigt av PRNG.

- **Modifiering av Operander och Val av Applikatorer vid Transformationstid:** Under appliceringen av mikroprogrammet (av `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), både vid den initiala obfuskeringen och vid de-obfuskering vid körtid:
    - En `Constexpr_PRNG prng_operand_modifier` (seedad med `base_seed`) genererar en `prng_key_for_ops_in_elem` för varje tecken i strängen. Mikroinstruktionens operand (`instr_orig.operand`) XOR:as med denna nyckel innan den används. Detta säkerställer att samma mikroprogram applicerar något olika transformationer för varje tecken.
    - En `Constexpr_PRNG prng_applier_selector` (seedad med `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) väljer en `Byte_Transform_Applier` för varje tecken. För närvarande finns det två stilar:
        - `Applier_Style_Direct`: Applicerar operationen direkt (inverterar den för dekryptering, som att ADD blir SUB).
        - `Applier_Style_DoubleLayer`: Applicerar operationen två gånger (eller operationen och dess invers, beroende på krypterings-/dekrypteringsläge) med olika operander, vilket gör reverseringen något mer komplex att analysera.

##### Variabla och Logiska NOP:ar för Entropi

För att öka svårigheten att manuellt analysera mikroprogrammet, infogar **Dralyxor**:
- **Explicita NOP:ar:** Instruktioner `Micro_Operation_Code::NOP` som inte gör någonting.
- **Logiska NOP:ar:** Par av instruktioner som tar ut varandra, som `ADD K` följt av `SUB K`, eller `ROTL N_BITS` följt av `ROTR N_BITS`. Operanden som används i paret är densamma.

Dessa NOP:ar infogas probabilistiskt av `Generate_Micro_Program_Instructions`, fyller arrayen `micro_program_` och gör det svårare att urskilja de effektiva transformationerna från "brus"-operationer.

#### Obfuskering av Själva Mikroprogrammet

Efter genereringen av mikroprogrammet och före den initiala obfuskeringen av strängen i `consteval`-konstruktorn, obfuskeras själva arrayen `micro_program_` (som finns i `Obfuscated_String`-objektet). Varje `op_code` och `operand` i varje `Micro_Instruction` XOR:as med en nyckel härledd från `compile_time_seed` (med hjälp av `Detail::Get_Micro_Program_Obfuscation_Key` och `Detail::Obfuscate_Deobfuscate_Instruction`).
Detta innebär att även om en angripare lyckas dumpa minnet från `Obfuscated_String`-objektet, kommer mikroprogrammet inte att vara i sin direkt läsbara/applicerbara form.

När `Obfuscated_String::Decrypt()` eller `Encrypt()` anropas (eller indirekt av `Secure_Accessor`), tar den centrala funktionen `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` emot detta *obfuskerade* mikroprogram. Den gör sedan följande:
1. Skapar en temporär kopia av mikroprogrammet (`local_plain_program`) på stacken.
2. De-obfuskerar denna lokala kopia med samma nyckel (`program_obf_key`) härledd från den överförda grundläggande seeden (som i slutändan är `compile_time_seed`).
3. Använder detta `local_plain_program` för att transformera strängdatan.
Den lokala kopian på stacken förstörs i slutet av funktionen, och `micro_program_` lagrat i `Obfuscated_String`-objektet förblir obfuskerat.

#### Livscykeln för Statisk Obfuskering

1.  **Källkod:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2.  **Förbearbetning:** Makrot expanderar till en instansiering `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (Storleken 15 inkluderar null-terminatorn).
3.  **`_DRALYXOR_CONSTEVAL`-Evaluering:**
    - Kompilatorn exekverar `Obfuscated_String`-konstruktorn.
    - `Initialize_Internal_Canaries()` ställer in integritets-canaries.
    - `Generate_Micro_Program_Instructions()` (seedad med `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) skapar en sekvens av `Micro_Instruction` och lagrar den i `this->micro_program_` (t.ex. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Det faktiska antalet instruktioner lagras i `num_actual_instructions_in_program_`.
    - Den ursprungliga strängen "SECRET\_API\_KEY" kopieras till `this->storage_`.
    - En checksumma av den ursprungliga strängen "SECRET\_API\_KEY" (exklusive null) beräknas av `Detail::Calculate_String_Content_Checksum` och obfuskeras sedan av `Detail::Obfuscate_Deobfuscate_Short_Value` (med `compile_time_seed` och `content_checksum_obf_salt`) och lagras i `this->_content_checksum_obfuscated`.
    - `Obfuscate_Internal_Micro_Program()` anropas: `this->micro_program_` obfuskeras på plats (varje instruktion XOR:as med `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
    - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` anropas. Denna funktion:
        - Skapar en de-obfuskerad kopia av `this->micro_program_` på stacken.
        - För varje tecken i `storage_` (förutom null):
            - Genererar `prng_key_for_ops_in_elem` och väljer en `Byte_Transform_Applier`.
            - Applicerar sekvensen av mikroinstruktioner (från den de-obfuskerade kopian) på tecknet, med hjälp av applikatorn och den modifierade operanden.
        - Till slut innehåller `storage_` den obfuskerade strängen (t.ex. `[CF, 3A, D1, ..., 0x00]`).
4.  **Kodgenerering:** Kompilatorn allokerar utrymme för `api_key_obj` och initialiserar det direkt med:
    - `storage_`: `[CF, 3A, D1, ..., 0x00]` (obfuskerad sträng).
    - `micro_program_`: Mikroprogrammet *redan obfuskerat*.
    - `_content_checksum_obfuscated`: Checksumman för det ursprungliga innehållet, *obfuskerad*.
    - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Literalen `"SECRET_API_KEY"` existerar inte längre i binärfilen.

### Komponent 2: Säker Åtkomst och Minimering av Exponering i RAM

#### `Secure_Accessor` och RAII-Principen

Skydd vid kompileringstid är bara halva striden. När strängen behöver användas måste den dekrypteras. Om denna dekrypterade sträng förblir i **RAM**-minnet under en längre period blir den ett mål för dynamisk analys (minnesdumpar, debuggers).

**Dralyxor** hanterar detta med `Dralyxor::Secure_Accessor`, en klass som implementerar **RAII**-mönstret (Resource Acquisition Is Initialization):
- **Resurs Förvärvad:** Temporär åtkomst till strängen i klartext, fragmenterad och hanterad av accessorn.
- **Hanterande Objekt:** Instansen av `Secure_Accessor`.

```cpp
// I secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Initiera olika för att misslyckas om inte uppdaterad
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invaliderar accessorn

            return;
        }

        // 1. Försöker dekryptera det ursprungliga Obfuscated_String.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Om dekrypteringen lyckas, kopiera klartextsträngen till de interna fragmenten.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ är nu i klartext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val är högst 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Fyll resten av fragmentbufferten med nollor
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksumma för fragmenten
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Återkryptera OMEDELBART det ursprungliga Obfuscated_String.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Rensar fragment och rekonstruerad buffert.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Kontrollerar sig själv och föräldern
            Clear_All_Internal_Buffers(); // Säkerhetsåtgärd
            _accessor_integrity_canary1 = 0; // Invaliderar för framtida åtkomster

            return nullptr;
        }

        if (!current_access_ptr_) { // Om det är första anropet till Get() eller om den har rensats
            if constexpr (N_storage > 0) { // Rekonstruerar endast om det finns något att rekonstruera
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

                // Garanterar null-terminering, även om N_storage fylls exakt.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // För N_storage == 0 (tom sträng, teoretiskt), inga checksummor
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // För att klara kontrollen

                if (N_storage > 0) // Detta är säkert om N_storage är 0, men reconstructed_plain_buffer_ måste vara > 0 i storlek.
                    reconstructed_plain_buffer_[0] = (CharT)0; // Förutsatt att reconstructed_plain_buffer_ är minst 1.
            }

            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Kontrollera igen efter varje intern operation för att säkerställa integritet.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Användningsflöde med `DRALYXOR_SECURE`:**
1.  `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
    - Konstruktorn för `Secure_Accessor` anropas.
    - Den anropar `my_obfuscated_string.Decrypt()`. Detta innefattar de-obfuskering av `micro_program_` (till en lokal kopia), användning av den för att dekryptera `my_obfuscated_string.storage_`, och sedan kontroll av canaries och innehållets checksumma mot den förväntade.
    - Om framgångsrikt, kopieras innehållet i `my_obfuscated_string.storage_` (nu klartext) och delas upp i de interna `fragments_storage_` i `Secure_Accessor`.
    - En checksumma för `fragments_storage_` (`fragments_data_checksum_expected_`) beräknas.
    - Avgörande nog anropas `my_obfuscated_string.Encrypt()` *omedelbart efteråt*, vilket återobfuskerar `my_obfuscated_string.storage_`.
2.  `const char* ptr = accessor.Get();` (eller `const char* ptr = accessor;` på grund av implicit konvertering)
    - `Secure_Accessor::Get()` anropas.
    - Den kontrollerar sina egna integritets-canaries och de hos det överordnade `Obfuscated_String`.
    - Om det är den första åtkomsten (`current_access_ptr_` är `nullptr`), rekonstruerar den den fullständiga strängen i `reconstructed_plain_buffer_` från `fragments_storage_`.
    - Den kontrollerar sedan `fragments_data_checksum_reconstructed_` mot `fragments_data_checksum_expected_` för att säkerställa att fragmenten inte har manipulerats medan `Secure_Accessor` existerade.
    - Om allt är korrekt, returneras en pekare till `reconstructed_plain_buffer_`.
3.  Scopet för `accessor` avslutas (lämnar funktionen, blocket `{}` avslutas, etc.).
    - Destruktorn för `Secure_Accessor` anropas automatiskt.
    - `Clear_All_Internal_Buffers()` anropas, vilket säkert rensar (`Secure_Clear_Memory`) både `reconstructed_plain_buffer_` och `fragments_storage_`.

Resultatet är att strängen i klartext existerar i fullständig form endast inuti `Secure_Accessor` (i `reconstructed_plain_buffer_`) och endast efter det första anropet till `Get()`, under så kort tid som möjligt. Strängen i det ursprungliga `Obfuscated_String`-objektet återobfuskeras så snart `Secure_Accessor` kopierar dess innehåll under konstruktionen.

#### Minnesfragmentering i `Secure_Accessor`

För att ytterligare försvåra lokaliseringen av den kompletta klartextsträngen i minnet, delar `Secure_Accessor`, under sin konstruktion, inte bara upp den dekrypterade strängen, utan:
1.  Strängen från det överordnade `Obfuscated_String` dekrypteras.
2.  Dess innehåll delas upp i upp till `fragment_count_val` (för närvarande 4, om strängen är tillräckligt lång) delar, som kopieras till `fragments_storage_[i]`.
3.  Strängen i det överordnade `Obfuscated_String`-objektet återobfuskeras.

Först när `Secure_Accessor::Get()` anropas för första gången återmonteras dessa fragment i `reconstructed_plain_buffer_`. Denna teknik syftar till att "sprida ut" känslig data och därigenom försvåra minnesskanningar som letar efter sammanhängande strängar.

#### Säker Minnesrensning

Både destruktorn för `Obfuscated_String` (via `Clear_Internal_Data`) och destruktorn för `Secure_Accessor` (via `Clear_All_Internal_Buffers`) använder `Dralyxor::Detail::Secure_Clear_Memory` (template för arrayer) eller `Dralyxor::Detail::Secure_Clear_Memory_Raw` (för råa pekare, även om `Secure_Clear_Memory` är mer använd i destruktorerna). Denna wrapper-funktion:
- Använder `SecureZeroMemory` (Windows User Mode) eller `RtlSecureZeroMemory` (Windows Kernel Mode) när de är tillgängliga, vilka är operativsystemfunktioner designade för att inte optimeras bort av kompilatorn.
- Återgår till en loop med en `volatile T* p`-pekare på andra plattformar eller när de Windows-specifika funktionerna inte är tillgängliga. `volatile` är ett försök att instruera kompilatorn att inte optimera bort skrivningen av nollor. Detta säkerställer att när objekt förstörs eller buffertar explicit rensas, skrivs det känsliga innehållet över, vilket minskar risken för dataåterställning.

### Komponent 3: Körtidsförsvar (Anti-Debugging och Anti-Tampering)

**Dralyxor** förlitar sig inte bara på obfuskering. Det använder en uppsättning aktiva körtidsförsvar, huvudsakligen lokaliserade i `anti_debug.hpp` och integrerade i metoderna `Decrypt()` och `Encrypt()` i `Obfuscated_String`.

#### Multi-Plattformsdetektering av Debuggers

Funktionen `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (i `anti_debug.hpp`) kontrollerar förekomsten av en debugger med hjälp av operativsystemspecifika tekniker:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` för `ProcessDebugPort` (0x07) och `ProcessDebugFlags` (0x1F).
- **Linux:** Läsning av `/proc/self/status` och kontroll av värdet på `TracerPid:`. Ett värde skilt från 0 indikerar att processen spåras.
- **macOS:** Användning av `sysctl` med `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` för att hämta `kinfo_proc` och kontroll av flaggan `P_TRACED` i `kp_proc.p_flag`.

Dessutom, inuti `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Utför en loop med enkla beräkningsoperationer och mäter tiden. En betydande fördröjning (över `timing_threshold_milliseconds = 75ms`) kan indikera att en debugger kör single-stepping eller att omfattande brytpunkter är aktiva. Inom denna loop anropas `Is_Debugger_Present_Tracer_Pid_Sysctl()`, och en "lockbete"-funktion `Detail::Canary_Function_For_Breakpoint_Check()` (som helt enkelt returnerar `0xCC`, instruktionskoden för `int3` / mjukvarubryktpunkt) anropas och dess resultat XOR:as, vilket försvårar optimering och tillhandahåller en vanlig plats för brytpunkter.
- `Detail::Perform_Output_Debug_String_Trick()` (endast Windows User Mode): Använder beteendet hos `OutputDebugStringA/W` och `GetLastError()`. Om en debugger är ansluten kan `GetLastError()` ändras efter anropet till `OutputDebugString`.

#### Påverkan på Drift vid Detektering eller Integritetsbrott

Om någon av anti-debugging-kontrollerna returnerar `true`, eller om integritets-canaries i `Obfuscated_String` (`_internal_integrity_canary1/2`) är korrupta, kommer funktionen `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` att returnera `Detail::integrity_compromised_magic`.

Detta returvärde är avgörande i funktionerna `Obfuscated_String::Decrypt()` och `Encrypt()`:
```cpp
// Förenklad logik för Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canaries för Obfuscated_String
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
        // ... Kontrollera canaries igen ...

        // OM runtime_key_mod INTE är integrity_compromised_magic, ANVÄNDS DEN INTE FÖR ATT ÄNDRA DEKRYPTERINGSNYCKELN.
        // Dekrypteringsnyckeln härleds alltid från den ursprungliga 'compile_time_seed'.
        // Rollen för runtime_key_mod här är ATT AGERA SOM EN INDIKATOR på en fientlig miljö.
        // Om fientlig, returnerar funktionen integrity_compromised_magic och dekrypteringen fortsätter inte eller återställs.
        
        // Transform_Compile_Time_Consistent anropas med compile_time_seed (och INTE med runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Kontrollera checksumma och canaries igen ...
        // Om något misslyckas, Clear_Internal_Data() och returnera integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Framgång
}
```

**Nyckeleffekt:** Om `Calculate_Runtime_Key_Modifier` upptäcker ett problem (debugger eller korrupt canary) och returnerar `integrity_compromised_magic`, avbryter funktionerna `Decrypt()` (och på liknande sätt `Encrypt()`) operationen, rensar den interna datan i `Obfuscated_String` (inklusive `storage_` och `micro_program_`), och returnerar `integrity_compromised_magic`. Detta förhindrar att strängen dekrypteras korrekt (eller återkrypteras) i en fientlig miljö eller om objektet har manipulerats.
Strängen dekrypteras inte "felaktigt" (till skräp); operationen förhindras helt enkelt, och `Obfuscated_String`-objektet självförstörs med avseende på användbart innehåll.

#### Objektintegritets-Canaries

Både klasserna `Obfuscated_String` och `Secure_Accessor` innehåller canary-medlemmar (par av `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initialiserad med `Detail::integrity_canary_value`) och `_internal_integrity_canary2` (initialiserad med `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initialiserad med `Detail::accessor_integrity_canary_seed`) och `_accessor_integrity_canary2` (initialiserad med `~Detail::accessor_integrity_canary_seed`).

Dessa canaries kontrolleras vid kritiska punkter:
- Början och slutet av `Obfuscated_String::Decrypt()` och `Encrypt()`.
- Konstruktor, destruktor och `Get()` för `Secure_Accessor`.
- Före och efter anti-debug-kontrollerna i `Calculate_Runtime_Key_Modifier`.

Om dessa canary-värden ändras (t.ex. genom en buffer overflow, en urskillningslös minnespatch, eller en hook som skriver över närliggande minne), kommer kontrollen (`Verify_Internal_Canaries()` eller `Verify_Internal_Accessor_Canaries()`) att misslyckas.
Vid misslyckande avbryts operationerna, relevant intern data rensas, och ett felvärde (`Detail::integrity_compromised_magic` eller `nullptr`) returneras, vilket signalerar manipulation.

#### Checksumma för Stränginnehåll

- En 16-bitars checksumma av den *ursprungliga klartextsträngen* (exklusive null-terminatorn) beräknas av `Detail::Calculate_String_Content_Checksum` vid kompileringstid.
- Denna checksumma obfuskeras sedan med `Detail::Obfuscate_Deobfuscate_Short_Value` (med `compile_time_seed` och `content_checksum_obf_salt`) och lagras i `_content_checksum_obfuscated` i `Obfuscated_String`-objektet.
- **Vid Dekryptering (`Decrypt()`):** Efter att `storage_` har transformerats (förmodligen till klartext), beräknas dess checksumma. `_content_checksum_obfuscated` de-obfuskeras för att få referenschecksumman. Om de två checksummorna inte stämmer överens, indikerar det att:
    - Dekrypteringen inte återställde den ursprungliga strängen (kanske för att operationen avbröts på grund av debugger-detektering före fullständig transformation, eller så skedde korruption av seed/mikroprogram).
    - `storage_` (när den var obfuskerad) eller `_content_checksum_obfuscated` har manipulerats i minnet.
- **Vid Kryptering (`Encrypt()`):** Innan `storage_` (som är i klartext vid denna tidpunkt) transformeras tillbaka till sin obfuskerade form, beräknas dess checksumma och jämförs med referensen. En avvikelse här skulle innebära att klartextsträngen har ändrats *inuti `storage_` på `Obfuscated_String` medan den var dekrypterad*, vilket är en stark indikation på minnesmanipulation eller felaktig användning (eftersom direkt åtkomst till `storage_` inte ska ske).

I båda fallen av checksumma-fel anropas `Clear_Internal_Data()` och `integrity_compromised_magic` returneras.

### Komponent 4: Generering av Unika och Oförutsägbara Nycklar och Seeds

Säkerheten i vilket krypteringssystem som helst vilar på styrkan och unikheten hos dess nycklar och seeds. **Dralyxor** säkerställer att varje obfuskerad sträng använder en uppsättning krypteringsparametrar som är fundamentalt unika.

#### Entropikällor för `compile_time_seed`

`static constexpr uint64_t Obfuscated_String::compile_time_seed` är huvud-seeden för alla pseudo-slumpmässiga operationer relaterade till den specifika stränginstansen. Den genereras i `consteval` enligt följande:
```cpp
// Inuti Obfuscated_String<CharT, storage_n, Instance_Counter>
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponent 1: Variabilitet mellan kompileringar
    ((uint64_t)Instance_Counter << 32) ^        // Komponent 2: Variabilitet inom en kompileringsenhet
    storage_n;                                  // Komponent 3: Variabilitet baserad på strängstorlek
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Makrona `__DATE__` (t.ex. "Jan 01 2025") och `__TIME__` (t.ex. "12:30:00") är strängar som tillhandahålls av förprocessorn och som ändras varje gång filen kompileras. FNV-1a-hashen av dessa värden skapar en seed-bas som är olika för varje build av projektet.
- **`Instance_Counter` (matas av `__COUNTER__` i makrot `DRALYXOR`/`DRALYXOR_LOCAL`)**: Makrot `__COUNTER__` är en räknare som underhålls av förprocessorn och som ökar varje gång den används inom en kompileringsenhet. Genom att skicka detta som ett template-argument `int Instance_Counter` till `Obfuscated_String`, kommer varje användning av makrot `DRALYXOR` eller `DRALYXOR_LOCAL` att resultera i en annorlunda `Instance_Counter` och därmed en annorlunda `compile_time_seed`, även för identiska strängliteraler i samma källfil.
- **`storage_n` (strängstorlek inklusive null)**: Strängens storlek XOR:as också, vilket lägger till ytterligare en differentieringsfaktor.

Detta `compile_time_seed` används sedan som bas för:
1. Generering av `micro_program_` (genom att seeda PRNG med `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Härledning av obfuskeringsnyckeln för själva `micro_program_` (via `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Härledning av obfuskeringsnyckeln för `_content_checksum_obfuscated` (via `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Att tjäna som `base_seed` för `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Härledda Seeds för Innehållstransformationer

Inuti `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- En `Constexpr_PRNG prng_operand_modifier(base_seed)` initialiseras. För varje tecken i strängen som transformeras, producerar `prng_operand_modifier.Key()` en `prng_key_for_ops_in_elem`. Denna nyckel XOR:as med mikroinstruktionens operand före applicering, vilket säkerställer att effekten av samma mikroinstruktion är subtilt annorlunda för varje tecken.
- En `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` initialiseras. För varje tecken används `prng_applier_selector.Key()` för att välja mellan `Applier_Style_Direct` och `Applier_Style_DoubleLayer`.

Detta introducerar ytterligare dynamik i transformationen av varje tecken, även om det underliggande mikroprogrammet är detsamma för alla tecken i en given sträng.

#### Immunitet mot "Replay"-attacker och Mönsteranalys

- **Unikhet Mellan Kompileringar:** Om en angripare analyserar binärfilen från version 1.0 av din programvara och, med stor ansträngning, lyckas knäcka obfuskeringen av en sträng, kommer den kunskapen troligen att vara värdelös för version 1.1, eftersom `__DATE__ __TIME__` kommer att ha ändrats, vilket resulterar i helt olika `compile_time_seed`:s och mikroprogram.
- **Unikhet Inom Kompilering:** Om du använder `DRALYXOR("AdminPassword")` på två olika ställen i din kod (eller i samma .cpp-fil), kommer `__COUNTER__` att säkerställa att de resulterande `Obfuscated_String`-objekten, och därmed deras obfuskerade representationer i binärfilen (både `storage_` och `micro_program_`), är olika. Detta förhindrar att en angripare hittar ett obfuskerat mönster och använder det för att lokalisera alla andra förekomster av samma ursprungliga sträng, eller använder ett upptäckt mikroprogram för att dekryptera andra strängar.

Denna robusta generering av seeds är en hörnsten i **Dralyxors** säkerhet mot attacker som förlitar sig på att upptäcka en "huvudhemlighet" eller utnyttja upprepning av chiffer och transformationer.

## Fullständig Referens för Publikt API

### Obfuskeringsmakron

Dessa är de huvudsakliga ingångspunkterna för att skapa obfuskerade strängar.

#### `DRALYXOR(str_literal)`

- **Syfte:** Skapar ett `Obfuscated_String`-objekt med statisk livstid (existerar under hela programmets exekvering). Idealiskt för globala konstanter eller strängar som behöver åtkomst från flera platser och bestå.
- **Lagring:** Statiskt minne (vanligtvis i programmets datasektion).
- **Implementation (förenklad):**
    ```cpp
    #define DRALYXOR(str_literal) \
        []() -> auto& { \
            /* Makrot __COUNTER__ garanterar en unik Instance_Counter för varje användning */ \
            /* decltype(*str_literal) härleder teckentypen (char, wchar_t) */ \
            /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) beräknar storleken inklusive null */ \
            static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
                typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
                (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
                __COUNTER__ \
            >(str_literal); \
            return obfuscated_static_string; \
        }()
    ```

- **Parametrar:**
    - `str_literal`: En C-stils strängliteral (t.ex. `"Hello World"`, `L"Unicode String"`).
- **Returvärde:** En referens (`auto&`) till det statiska `Obfuscated_String`-objektet, skapat inuti en omedelbart anropad lambda.
- **Exempel:**
    ```cpp
    static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
    // api_endpoint_url är en referens till ett statiskt Obfuscated_String.
    ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Syfte:** Skapar ett `Obfuscated_String`-objekt med automatisk livstid (vanligtvis på stacken, om det används inuti en funktion). Idealiskt för temporära hemligheter begränsade till ett scope.
- **Lagring:** Automatisk (stack för lokala funktionsvariabler).
- **Implementation (förenklad):**
    ```cpp
    #define DRALYXOR_LOCAL(str_literal) \
        Dralyxor::Obfuscated_String< \
            typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
            (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
            __COUNTER__ \
        >(str_literal)
    ```
- **Parametrar:**
    - `str_literal`: En C-stils strängliteral.
- **Returvärde:** Ett `Obfuscated_String`-objekt per värde (som kan optimeras med RVO/NRVO av kompilatorn).
- **Exempel:**
    ```cpp
    void process_data() {
        auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
        // ... använd temp_key med DRALYXOR_SECURE ...
    } // temp_key förstörs här, dess destruktor anropar Clear_Internal_Data().
    ```

### Säker Åtkomst-Makro

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Syfte:** Tillhandahåller säker och temporär åtkomst till det dekrypterade innehållet i ett `Obfuscated_String`-objekt. Detta är den **enda rekommenderade metoden** för att läsa strängen.
- **Implementation (förenklad):**
    ```cpp
    #define DRALYXOR_SECURE(obfuscated_var) \
        Dralyxor::Secure_Accessor< \
            typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
        >(obfuscated_var)
    ```

- **Parametrar:**
    - `obfuscated_var`: En variabel (lvalue eller rvalue som kan bindas till en icke-konstant lvalue-referens) av typen `Dralyxor::Obfuscated_String<...>`. Variabeln måste vara muterbar eftersom `Secure_Accessor`-konstruktorn anropar `Decrypt()` och `Encrypt()` på den.
- **Returvärde:** Ett `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>`-objekt per värde.
- **Användning:**
    ```cpp
    auto& my_static_secret = DRALYXOR("My Top Secret");
    // ...
    {
        auto accessor = DRALYXOR_SECURE(my_static_secret);
        const char* secret_ptr = accessor.Get(); // Eller bara: const char* secret_ptr = accessor; (implicit konvertering)
       
        if (secret_ptr) {
            // Använd secret_ptr här. Den pekar på den temporärt dekrypterade strängen i accessorns buffert.
            // Ex: send_data(secret_ptr);
        }
        else {
            // Fel vid dekryptering eller integritetsfel. Hantera felet.
            // Accessorn kan ha misslyckats med att initiera (t.ex. my_static_secret var korrupt).
        }
    } // accessor förstörs. Dess interna buffertar (fragment och rekonstruerad sträng) rensas.
      // my_static_secret.storage_ har redan återobfuskerats av Secure_Accessor-konstruktorn
      // direkt efter kopiering av innehållet till accessorns fragment.
    ```

> [!WARNING]
> Kontrollera alltid att pekaren som returneras av `DRALYXOR_SECURE(...).Get()` (eller genom implicit konvertering) inte är `nullptr` innan du använder den. Ett `nullptr`-returvärde indikerar ett fel vid dekryptering (t.ex. debugger-detektering, korruption av canaries/checksummor i det överordnade `Obfuscated_String` eller i själva `Secure_Accessor`). Användning av en `nullptr`-pekare kommer att resultera i odefinierat beteende (troligen en segmenteringsfel).

## Avancerade Funktioner och God Praxis

### Fullständigt Stöd för Unicode (Wide Strings - `wchar_t`)

**Dralyxor** är agnostiskt mot teckentyp tack vare användningen av templates (`CharT`). Det hanterar naturligt `char` (för ASCII/UTF-8-strängar) och `wchar_t` (för UTF-16-strängar på Windows eller UTF-32 på andra system, beroende på plattform och kompilator). Använd bara prefixet `L` för `wchar_t`-literaler:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Unicode-Meddelande: Hej Världen Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Exempel på Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Unicode-Titel", MB_OK);
        // Exempel med wcout:
        // #include <io.h> // För _setmode på Windows med MSVC
        // #include <fcntl.h> // För _O_U16TEXT på Windows med MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Konfigurerar stdout för UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

För 1-byte tecken (`sizeof(CharT) == 1`), applicerar transformeringsmotorn `Micro_Program_Cipher` mikroprogrammet byte för byte. För multibyte-tecken (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` använder en enklare metod: hela multibyte-tecknet XOR:as med en mask härledd från `prng_key_for_ops_in_elem` (replikerad för att fylla `CharT`:s storlek). Till exempel, om `CharT` är `wchar_t` (2 bytes) och `prng_key_for_ops_in_elem` är `0xAB`, kommer tecknet att XOR:as med `0xABAB`.
Detta säkerställer att alla bytes i `wchar_t` påverkas av obfuskeringen, även om det inte är genom hela mikroprogrammet. Mikroprogrammets komplexitet bidrar fortfarande indirekt genom härledningen av PRNG-nycklarna.

### Intelligent Anpassning till C++ Standarder och Miljöer (Kernel Mode)

Som nämnts anpassar sig **Dralyxor**:
- **C++ Standarder:** Kräver minst **C++14**. Upptäcker och använder funktioner från **C++17** och **C++20** (som `if constexpr`, `consteval`, `_v`-suffix för `type_traits`) när kompilatorn stöder dem, och återgår till **C++14**-alternativ annars. Makron som `_DRALYXOR_IF_CONSTEXPR` och `_DRALYXOR_CONSTEVAL` i `detection.hpp` hanterar denna anpassning.
- **Kernel Mode:** När `_KERNEL_MODE` är definierat (typiskt i WDK-projekt för Windows-drivrutiner), undviker **Dralyxor** (via `env_traits.hpp`) att inkludera standard STL-headers som `<type_traits>` som kanske inte är tillgängliga eller beter sig annorlunda. Istället använder det sina egna `constexpr`-implementationer av grundläggande verktyg som `Dralyxor::Detail::Fallback::decay` och `Dralyxor::Detail::Fallback::remove_reference`. Detta möjliggör säker användning av **Dralyxor** för att skydda strängar i lågnivåsystemkomponenter.
    - På liknande sätt använder `secure_memory.hpp` `RtlSecureZeroMemory` i Kernel Mode.
    - Anti-debug-kontroller för User Mode (som `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) är inaktiverade (`#if !defined(_KERNEL_MODE)`) i Kernel Mode, eftersom de inte är tillämpliga eller har andra motsvarigheter. Timing-kontroller kan fortfarande ha viss effekt, men den huvudsakliga försvarslinjen i Kernel Mode är själva obfuskeringen.

### Prestanda- och Overhead-Överväganden

- **Kompileringstid:** Obfuskeringen, inklusive generering och applicering av mikroprogram, sker helt vid kompileringstid. För projekt med ett mycket stort antal obfuskerade strängar kan kompileringstiden öka. Detta är en engångskostnad per kompilering.
- **Binärfilsstorlek:** Varje `Obfuscated_String` lägger till sin `storage_` (strängstorlek), `micro_program_` (fast vid `max_micro_instructions * sizeof(Micro_Instruction)`), plus några bytes för canaries, checksumma och flaggor. Det kan bli en ökning av binärfilens storlek jämfört med rena strängliteraler, särskilt för många små strängar.
- **Körtid (Runtime):**
    - **Skapande av `Obfuscated_String` (statiska eller lokala objekt):** Sker vid kompileringstid (för statiska) eller innefattar en kopia av förberäknad data (för lokala, optimerbart med RVO). Ingen "genererings"-kostnad vid körtid.
    - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
        - Kontroll av canaries (extremt snabbt).
        - `Detail::Calculate_Runtime_Key_Modifier()`: Inkluderar anti-debug-kontroller. Timing-kontrollen (`Perform_Timing_Check_Generic`) är den mest kostsamma här och kör en loop. De andra är API-anrop eller filläsningar (Linux).
        - De-obfuskering av mikroprogrammet (kopiering och XOR, snabbt).
        - Strängtransformation: Loop över `N_data_elements_to_transform`, och inuti den, loop över `num_actual_instructions_in_program_`. För varje instruktion, ett anrop till `Byte_Transform_Applier` som gör några byte-operationer. Kostnaden är O(stränglängd \* antal\_instruktioner).
        - Beräkning/Kontroll av checksumma (`Detail::Calculate_String_Content_Checksum`): O(stränglängd \* sizeof(CharT)).
    - **Skapande av `Secure_Accessor`:**
        - Anropar `Obfuscated_String::Decrypt()`.
        - Kopierar sträng till fragment: O(stränglängd).
        - Beräknar checksumma för fragment (`Calculate_Current_Fragments_Checksum`): O(stränglängd).
        - Anropar `Obfuscated_String::Encrypt()`. Detta är punkten med störst koncentration av overhead i en enskild åtkomstoperation.
    - **`Secure_Accessor::Get()`:**
        - Första anropet: Kontrollerar canaries, rekonstruerar sträng från fragment (O(stränglängd)), kontrollerar checksumma för fragment.
        - Efterföljande anrop (för samma `Secure_Accessor`-objekt): Kontrollerar canaries (snabbt) och returnerar redan beräknad pekare (O(1)).
- **Generell Overhead:** För de flesta applikationer, där känsliga strängar inte åtkomsts i högfrekventa loopar, är körtids-overhead vanligtvis acceptabel, särskilt med tanke på säkerhetsfördelen. Designen av `Secure_Accessor` (skapad endast när det behövs och med strikt begränsat scope av RAII) är grundläggande för att hantera denna kostnad. Testa i din specifika miljö om prestanda är kritisk.

### Integration i en Flerskiktad Säkerhetsstrategi

> [!IMPORTANT]
> **Dralyxor** är ett kraftfullt verktyg för **obfuskering av inbäddade strängar och försvar mot minnesanalys**, inte en generisk krypteringslösning för beständig datalagring på disk eller säker överföring över nätverk.
>
> Det bör användas som **ett av många lager** i en omfattande säkerhetsstrategi. Inget enskilt verktyg är en silverkula. Andra åtgärder att överväga inkluderar:
> - **Minimera Inbäddade Hemligheter:** Undvik att bädda in hemligheter med mycket hög kriticitet när det är möjligt. Använd alternativ som:
>     - Säkra konfigurationer som tillhandahålls vid körtid (miljövariabler, konfigurationsfiler med begränsade behörigheter).
>     - Tjänster för hantering av hemligheter (vaults) som HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Robust indatavalidering på alla gränssnitt.
> - Principen om minsta möjliga behörighet för processer och användare.
> - Säker nätverkskommunikation (TLS/SSL med certificate pinning, om tillämpligt).
> - Säker hashing av användarlösenord (Argon2, scrypt, bcrypt).
> - Skydd av binärfilen som helhet med andra anti-reversing/anti-tampering-tekniker (packers, kodvirtualiserare, integritetskontroller av kod), medveten om de kompromisser dessa kan medföra (falska positiva från antivirusprogram, komplexitet).
> - God praxis för säker utveckling (Secure SDLC).

**Dralyxor** fokuserar på att lösa ett specifikt och vanligt problem mycket väl: skyddet av inbäddade strängliteraler mot statisk analys och minimering av deras exponering i minnet under exekvering, vilket försvårar livet för den som försöker utföra reverse engineering på din programvara.

## Licens

Detta bibliotek skyddas under MIT-licensen, som tillåter:

- ✔️ Kommersiell och privat användning
- ✔️ Modifiering av källkoden
- ✔️ Distribution av koden
- ✔️ Sublicensiering

### Villkor:

- Behåll upphovsrättsmeddelandet
- Inkludera en kopia av MIT-licensen

För mer information om licensen: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Alla rättigheter förbehållna**