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
    - [Grundläggande användningsmönster](#grundläggande-användningsmönster)
      - [Mönster 1: Lokal obfuskering (Stack)](#mönster-1-lokal-obfuskering-stack)
      - [Mönster 2: Statisk obfuskering (Global)](#mönster-2-statisk-obfuskering-global)
      - [Mönster 3: Obfuskering med användarspecificerad nyckel](#mönster-3-obfuskering-med-användarspecificerad-nyckel)
    - [Felhantering och integritet](#felhantering-och-integritet)
  - [Detaljerad Designfilosofi och Arkitektur](#detaljerad-designfilosofi-och-arkitektur)
    - [Det Ständiga Hotet: Sårbarheten hos Strängliteraler](#det-ständiga-hotet-sårbarheten-hos-strängliteraler)
    - [Dralyxors Flerskiktade Arkitektoniska Lösning](#dralyxors-flerskiktade-arkitektoniska-lösning)
  - [Djupgående Analys av Arkitektoniska Komponenter](#djupgående-analys-av-arkitektoniska-komponenter)
    - [Komponent 1: Transformationsmotorn med mikroprogram](#komponent-1-transformationsmotorn-med-mikroprogram)
      - [Kraften i `consteval` och `constexpr` för generering vid kompileringstid](#kraften-i-consteval-och-constexpr-för-generering-vid-kompileringstid)
      - [Anatomin hos ett **Dralyxor**-mikroprogram](#anatomin-hos-ett-dralyxor-mikroprogram)
        - [Slumpmässig generering av instruktioner och val av applikatorer](#slumpmässig-generering-av-instruktioner-och-val-av-applikatorer)
        - [Variabla och logiska NOPs för entropi](#variabla-och-logiska-nops-för-entropi)
      - [Obfuskering av själva mikroprogrammet](#obfuskering-av-själva-mikroprogrammet)
      - [Livscykeln för statisk obfuskering](#livscykeln-för-statisk-obfuskering)
    - [Komponent 2: Säker åtkomst och minimering av exponering i **RAM**](#komponent-2-säker-åtkomst-och-minimering-av-exponering-i-ram)
      - [Secure\_Accessor och RAII-principen](#secure_accessor-och-raii-principen)
      - [Minnesfragmentering i Secure\_Accessor](#minnesfragmentering-i-secure_accessor)
      - [Säker minnesrensning](#säker-minnesrensning)
    - [Komponent 3: Körningsförsvar (Anti-Debugging och Anti-Tampering)](#komponent-3-körningsförsvar-anti-debugging-och-anti-tampering)
      - [Multi-plattformsdetektering av debuggers](#multi-plattformsdetektering-av-debuggers)
      - [Inverkan på drift vid detektering eller integritetsbrott](#inverkan-på-drift-vid-detektering-eller-integritetsbrott)
      - [Objektintegritets-canaries](#objektintegritets-canaries)
      - [Checksumma för stränginnehåll](#checksumma-för-stränginnehåll)
    - [Komponent 4: Generering av unika och oförutsägbara nycklar och frön (seeds)](#komponent-4-generering-av-unika-och-oförutsägbara-nycklar-och-frön-seeds)
      - [Entropikällor för `compile_time_seed`](#entropikällor-för-compile_time_seed)
      - [Härledda frön (seeds) för innehållstransformationer](#härledda-frön-seeds-för-innehållstransformationer)
      - [Immunitet mot "Replay"-attacker och mönsteranalys](#immunitet-mot-replay-attacker-och-mönsteranalys)
  - [Fullständig Referens för Publikt API](#fullständig-referens-för-publikt-api)
    - [Obfuskeringsmakron](#obfuskeringsmakron)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Makro för säker åtkomst](#makro-för-säker-åtkomst)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Avancerade Funktioner och God Praxis](#avancerade-funktioner-och-god-praxis)
    - [Fullständigt Stöd för Unicode (Wide Strings - `wchar_t`)](#fullständigt-stöd-för-unicode-wide-strings---wchar_t)
    - [Intelligent Anpassning till **C++** Standarder och Miljöer (Kernel Mode)](#intelligent-anpassning-till-c-standarder-och-miljöer-kernel-mode)
    - [Prestanda- och Overhead-Överväganden](#prestanda--och-overhead-överväganden)
    - [Integration i en Flerskiktad Säkerhetsstrategi](#integration-i-en-flerskiktad-säkerhetsstrategi)
  - [Licens](#licens)
    - [Villkor:](#villkor)

## Snabbguide för Integration och Användning

### Installation

**Dralyxor** är ett **header-only**-bibliotek. Ingen förkompilering eller länkning av bibliotek (`.lib`/`.a`) krävs.

1. **Kopiera `Dralyxor`-katalogen:** Hämta den senaste versionen av biblioteket (klona repot eller ladda ner zip-filen) och kopiera hela `Dralyxor`-katalogen (som innehåller alla `.hpp`-filer) till en plats som är tillgänglig för ditt projekt (t.ex. en `libs/`, `libraries/`, eller `vendor/`-mapp).
2. **Inkludera huvudheader:** Inkludera huvudheadern `dralyxor.hpp` i din källkod:
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
        |-- dralyxor.hpp            (Huvudsaklig ingångspunkt)
        |-- obfuscated_string.hpp   (Klass Obfuscated_String)
        |-- secure_accessor.hpp     (Klass Secure_Accessor)
        |-- algorithms.hpp          (Transformationsmotor och mikroprogram)
        |-- anti_debug.hpp          (Runtime-detekteringar)
        |-- prng.hpp                (Pseudo-slumptalsgenerator för kompileringstid)
        |-- integrity_constants.hpp (Konstanter för integritetskontroller)
        |-- secure_memory.hpp       (Säker minnesrensning)
        |-- detection.hpp           (Makron för detektering av kompilator/C++-standard)
        `-- env_traits.hpp          (Anpassningar av type_traits för begränsade miljöer)
```

### Kompilatorkrav

> [!IMPORTANT]
> **Dralyxor** är utformat med fokus på modern **C++** för maximal säkerhet och effektivitet vid kompileringstid.
>
> - **Lägsta C++-standard: C++14**. Biblioteket använder funktioner som generaliserad `constexpr` och anpassar sig för `if constexpr` (när tillgängligt via `_DRALYXOR_IF_CONSTEXPR`).
> - **Anpassning till högre standarder:** Upptäcker och använder optimeringar eller syntax från **C++17** och **C++20** (som `consteval`, `_v`-suffix för `type_traits`) om projektet kompileras med dessa standarder. `_DRALYXOR_CONSTEVAL` mappas till `consteval` i C++20 och `constexpr` i C++14/17, vilket säkerställer exekvering vid kompileringstid där det är möjligt.
> - **Stödda kompilatorer:** Främst testat med de senaste versionerna av MSVC, GCC och Clang.
> - **Körningsmiljö:** Fullt kompatibel med **User Mode**-applikationer och **Kernel Mode**-miljöer (t.ex. Windows-drivrutiner). I Kernel Mode, där STL kanske inte är tillgängligt, använder **Dralyxor** interna implementationer för nödvändiga `type traits` (se `env_traits.hpp`).

### Grundläggande användningsmönster

#### Mönster 1: Lokal obfuskering (Stack)

Idealiskt för temporära strängar som är begränsade till en funktions scope. Minnet hanteras och rensas automatiskt.

```cpp
#include "Dralyxor/dralyxor.hpp" // Justera sökvägen vid behov
#include <iostream>

void Configure_Logging() {
    // Loggformateringsnyckel, används endast lokalt.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Säker åtkomst inom ett begränsat scope
    {
        // Secure_Accessor deobfuskerar tillfälligt 'log_format_key' under sin konstruktion
        // (och återobfuskerar 'log_format_key' omedelbart efter kopiering till sina interna buffertar),
        // tillåter åtkomst och rensar sina egna buffertar vid destruktion.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Kontrollera alltid att Get() inte returnerar nullptr
            std::cout << "Använder loggformat: " << accessor.Get() << std::endl;
            // Ex: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Misslyckades med att dekryptera log_format_key (möjlig manipulering eller debugger-detektering?)" << std::endl;
    } // accessor förstörs, dess interna buffertar rensas. log_format_key förblir obfuskerad.
      // log_format_key kommer att förstöras i slutet av funktionen Configure_Logging.
}
```

#### Mönster 2: Statisk obfuskering (Global)

För konstanter som behöver bestå under programmets livstid och nås globalt.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // För exemplet

// URL för licens-API, en beständig hemlighet.
// Makrot DRALYXOR() skapar ett statiskt objekt.
// Funktionen Get_License_Server_URL() returnerar en referens till detta statiska objekt.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref är en referens till det statiska Obfuscated_String-objektet.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Skapar en Secure_Accessor för url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Kontaktar licensserver på: " << accessor.Get() << std::endl;
            // Ex: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulering av framgång för exemplet
        }
        else
            std::cerr << "Misslyckades med att dekryptera URL för licensserver (möjlig manipulering eller debugger-detektering?)." << std::endl;
    } // accessor förstörs, dess buffertar rensas. url_obj_ref (det ursprungliga Obfuscated_String-objektet) förblir obfuskerad.

    return success;
}
```

#### Mönster 3: Obfuskering med användarspecificerad nyckel

För maximal säkerhetsnivå kan du ange din egen hemliga nyckelsträng. Detta gör att obfuskeringen beror på en hemlighet som bara du känner till, vilket gör den motståndskraftig.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// Nyckeln får aldrig finnas i klartext i produktionskod,
// den bör helst komma från ett byggskript, en miljövariabel, etc.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Obfuskerar en URL med den hemliga nyckeln. Makrot slutar med _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Användningen med Secure_Accessor är densamma.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Felhantering och integritet

Funktionerna `Obfuscated_String::Decrypt()` och `Encrypt()` returnerar `uint64_t`:
- `0` indikerar framgång.
- `Dralyxor::Detail::integrity_compromised_magic` (ett konstantvärde definierat i `integrity_constants.hpp`) indikerar att en integritetskontroll misslyckades. Detta kan bero på korrupta objekt-canaries, en inkonsekvent innehålls-checksumma, eller detektering av en debugger som signalerar en fientlig miljö.

På samma sätt kommer `Secure_Accessor::Get()` (eller dess implicita konvertering till `const CharT*`) att returnera `nullptr` om initieringen av `Secure_Accessor` misslyckas (t.ex. om dekrypteringen av det ursprungliga `Obfuscated_String`-objektet misslyckas) eller om integriteten hos `Secure_Accessor` (dess egna canaries eller interna checksummor) komprometteras under dess livstid.

**Det är avgörande att din kod kontrollerar dessa returvärden för att säkerställa applikationens robusthet och säkerhet.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Du skulle normalt sett INTE anropa Decrypt() och Encrypt() direkt,
    // eftersom Secure_Accessor hanterar detta. Men om du av någon anledning behöver:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "VARNING: Misslyckades med att dekryptera 'my_secret' eller integritet komprometterad under Decrypt()!" << std::endl;
        // Vidta lämplig åtgärd: avsluta, logga säkert, etc.
        // Objektet my_secret.storage_ kan vara i ett ogiltigt tillstånd eller innehålla skräp.
        return; // Undvik att använda my_secret om Decrypt() misslyckas.
    }

    // Om Decrypt() lyckades, innehåller my_secret.storage_ den dekrypterade datan.
    // **DIREKT ÅTKOMST TILL storage_ AVråds STarkt FRÅN I PRODUKTION.**
    // std::cout << "Data i my_secret.storage_ (GÖR INTE SÅ HÄR): " << my_secret.storage_ << std::endl;

    // Det är ditt ansvar att återkryptera om du anropade Decrypt() manuellt:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "VARNING: Misslyckades med att återkryptera 'my_secret' eller integritet komprometterad under Encrypt()!" << std::endl;
        // Osäkert tillstånd, potentiellt farligt.
    }

    // REKOMMENDERAD ANVÄNDNING med Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Konstruktorn för Secure_Accessor anropar another_secret.Decrypt(), kopierar och sedan another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Eller: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Hemlig data via Secure_Accessor: " << data_ptr << std::endl;
            // Använd data_ptr här
        }
        else {
            std::cerr << "VARNING: Secure_Accessor misslyckades med att initiera eller hämta pekare för 'another_secret'!" << std::endl;
            // Detta indikerar att Decrypt() inuti accessorns konstruktor misslyckades,
            // eller att det förekom manipulering av accessorn (canaries, interna checksummor).
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

### Komponent 1: Transformationsmotorn med mikroprogram

Kärnan i **Dralyxor**s statiska och dynamiska obfuskering ligger i dess transformationsmotor, som använder unika "mikroprogram" för varje sträng och kontext.

#### Kraften i `consteval` och `constexpr` för generering vid kompileringstid

Modern **C++**, med `consteval` (**C++20**) och `constexpr` (**C++11** och framåt), tillåter komplex kod att exekveras *under kompileringen*. **Dralyxor** använder `_DRALYXOR_CONSTEVAL` (som mappas till `consteval` eller `constexpr` beroende på **C++**-standard) för konstruktorn i `Obfuscated_String` och för genereringen av mikroprogrammet.

Detta innebär att hela processen att:
1. Generera en pseudo-slumpmässig sekvens av transformationsinstruktioner (mikroprogrammet).
2. Obfuskera själva mikroprogrammet för lagring.
3. Tillämpa detta mikroprogram (temporärt deobfuskerat) för att omvandla den ursprungliga strängen, vilket resulterar i dess obfuskerade form.
Allt detta sker vid kompileringstid, innan binärfilen genereras.

#### Anatomin hos ett **Dralyxor**-mikroprogram

Varje `Obfuscated_String`-objekt lagrar en liten array av `Dralyxor::Detail::Micro_Instruction`. En `Micro_Instruction` är en enkel struct definierad i `algorithms.hpp`:
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
    END_OF_PROGRAM
};

struct Micro_Instruction {
    Micro_Operation_Code op_code{}; // Standardinitialiserare {} för att nollställa
    uint8_t operand{};             // Standardinitialiserare {} för att nollställa
};

// Maximalt antal instruktioner som ett mikroprogram kan innehålla.
static constexpr size_t max_micro_instructions = 8;
```
Funktionen `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` är ansvarig för att fylla denna array.

##### Slumpmässig generering av instruktioner och val av applikatorer

- **Generering av instruktioner:** Med hjälp av en `Dralyxor::Detail::Constexpr_PRNG` (seedad med en kombination av `compile_time_seed` och `0xDEADBEEFC0FFEEULL`), väljer funktionen `Generate_Micro_Program_Instructions` probabilistiskt en sekvens av operationer:
   - `XOR`: Bitvis XOR med operanden.
   - `ADD`: Modulär addition med operanden.
   - `SUB`: Modulär subtraktion med operanden.
   - `ROTR`/`ROTL`: Bitrotation. Operanden (efter modulo) definierar antalet skiftningar (1 till 7).
   - `SWAP_NIB`: Byter de 4 lägre bitarna med de 4 övre bitarna i en byte (operanden ignoreras).
    Operanderna för dessa instruktioner genereras också pseudo-slumpmässigt av PRNG:n.

- **Modifiering av operander och val av applikatorer vid transformation:** Under tillämpningen av mikroprogrammet (av `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), både vid den initiala obfuskeringen och vid deobfuskeringen i runtime:
   - En `Constexpr_PRNG prng_operand_modifier` (seedad med `base_seed`) genererar en `prng_key_for_ops_in_elem` för varje tecken i strängen. Mikroinstruktionens operand (`instr_orig.operand`) XORas med denna nyckel innan den används. Detta säkerställer att samma mikroprogram tillämpar något olika transformationer för varje tecken.
   - En `Constexpr_PRNG prng_applier_selector` (seedad med `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) väljer en `Byte_Transform_Applier` för varje tecken. För närvarande finns det två stilar:
      - `Applier_Style_Direct`: Tillämpar operationen direkt (och inverterar den för dekryptering, t.ex. blir ADD till SUB).
      - `Applier_Style_DoubleLayer`: Tillämpar operationen två gånger (eller operationen och dess invers, beroende på krypterings-/dekrypteringsläge) med olika operander, vilket gör reverseringen något mer komplex att analysera.

##### Variabla och logiska NOPs för entropi

För att öka svårigheten att manuellt analysera mikroprogrammet infogar **Dralyxor**:
- **Explicita NOPs:** `Micro_Operation_Code::NOP`-instruktioner som inte gör någonting.
- **Logiska NOPs:** Par av instruktioner som upphäver varandra, som `ADD K` följt av `SUB K`, eller `ROTL N_BITS` följt av `ROTR N_BITS`. Operanden som används i paret är densamma.

Dessa NOPs infogas probabilistiskt av `Generate_Micro_Program_Instructions`, vilket fyller `micro_program_`-arrayen och gör det svårare att skilja de faktiska transformationerna från "brus"-operationer.

#### Obfuskering av själva mikroprogrammet

Efter att mikroprogrammet har genererats och före den initiala obfuskeringen av strängen i `consteval`-konstruktorn, obfuskeras själva `micro_program_`-arrayen (som finns i `Obfuscated_String`-objektet). Varje `op_code` och `operand` i varje `Micro_Instruction` XORas med en nyckel som härleds från `compile_time_seed` (med hjälp av `Detail::Get_Micro_Program_Obfuscation_Key` och `Detail::Obfuscate_Deobfuscate_Instruction`).
Detta innebär att även om en angripare lyckas dumpa minnet för `Obfuscated_String`-objektet, kommer mikroprogrammet inte att vara i sin direkt läsbara/tillämpbara form.

När `Obfuscated_String::Decrypt()` eller `Encrypt()` anropas (eller indirekt av `Secure_Accessor`), tar den centrala funktionen `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` emot detta *obfuskerade* mikroprogram. Den gör sedan följande:
1. Skapar en temporär kopia av mikroprogrammet (`local_plain_program`) på stacken.
2. Deobfuskerar denna lokala kopia med samma nyckel (`program_obf_key`) som härleds från det givna grund-seedet (som i slutändan är `compile_time_seed`).
3. Använder denna `local_plain_program` för att transformera strängdatan.
Den lokala kopian på stacken förstörs när funktionen avslutas, och `micro_program_` som lagras i `Obfuscated_String`-objektet förblir obfuskerad.

#### Livscykeln för statisk obfuskering

1. **Källkod:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Förbearbetning:** Makrot expanderar till en instansiering `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (Storleken 15 inkluderar null-terminatorn).
3. **`_DRALYXOR_CONSTEVAL`-utvärdering:**
   - Kompilatorn exekverar `Obfuscated_String`-konstruktorn.
   - `Initialize_Internal_Canaries()` sätter integritets-canaries.
   - `Generate_Micro_Program_Instructions()` (seedad med `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) skapar en sekvens av `Micro_Instruction` och lagrar den i `this->micro_program_` (t.ex. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Det faktiska antalet instruktioner lagras i `num_actual_instructions_in_program_`.
   - Den ursprungliga strängen "SECRET\_API\_KEY" kopieras till `this->storage_`.
   - En checksumma av den ursprungliga strängen "SECRET\_API\_KEY" (exklusive noll) beräknas av `Detail::Calculate_String_Content_Checksum` och obfuskeras sedan av `Detail::Obfuscate_Deobfuscate_Short_Value` (med `compile_time_seed` och `content_checksum_obf_salt`) och lagras i `this->_content_checksum_obfuscated`.
   - `Obfuscate_Internal_Micro_Program()` anropas: `this->micro_program_` obfuskeras på plats (varje instruktion XORas med `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` anropas. Denna funktion:
      - Skapar en deobfuskerad kopia av `this->micro_program_` på stacken.
      - För varje tecken i `storage_` (förutom noll):
         - Genererar `prng_key_for_ops_in_elem` och väljer en `Byte_Transform_Applier`.
         - Tillämpar sekvensen av mikroinstruktioner (från den deobfuskerade kopian) på tecknet, med hjälp av applikatorn och den modifierade operanden.
      - I slutet innehåller `storage_` den obfuskerade strängen (t.ex. `[CF, 3A, D1, ..., 0x00]`).
4. **Kodgenerering:** Kompilatorn allokerar utrymme för `api_key_obj` och initierar det direkt med:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (obfuskerad sträng).
   - `micro_program_`: Det *redan obfuskerade* mikroprogrammet.
   - `_content_checksum_obfuscated`: Checksumman för det ursprungliga innehållet, *obfuskerad*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Literalen `"SECRET_API_KEY"` existerar inte längre i binärfilen.

### Komponent 2: Säker åtkomst och minimering av exponering i **RAM**

#### Secure_Accessor och RAII-principen

Skydd vid kompileringstid är bara halva striden. När en sträng behöver användas måste den dekrypteras. Om denna dekrypterade sträng ligger kvar i **RAM**-minnet under en längre tid blir den ett mål för dynamisk analys (minnesdumpar, debuggers).

**Dralyxor** hanterar detta med `Dralyxor::Secure_Accessor`, en klass som implementerar **RAII**-mönstret (Resource Acquisition Is Initialization):
- **Resurs förvärvad:** Den temporära åtkomsten till strängen i klartext, fragmenterad och hanterad av accessorn.
- **Hanteringsobjekt:** Instansen av `Secure_Accessor`.

```cpp
// I secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Initiera olika för att misslyckas om den inte uppdateras
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Ogiltigförklarar accessorn

            return;
        }

        // 1. Försöker dekryptera det ursprungliga Obfuscated_String-objektet.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Om dekrypteringen lyckas, kopieras klartextsträngen till de interna fragmenten.
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
                        fragments_storage_[i][j] = (CharT)0; // Fyller resten av fragmentbufferten med nollor
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksumma för fragmenten
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Återkryptera det ursprungliga Obfuscated_String-objektet OMEDELBART.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Rensar fragment och den återuppbyggda bufferten.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Kontrollerar sig själv och föräldern
            Clear_All_Internal_Buffers(); // Säkerhetsåtgärd
            _accessor_integrity_canary1 = 0; // Ogiltigförklarar för framtida åtkomster

            return nullptr;
        }

        if (!current_access_ptr_) { // Om det är det första anropet till Get() eller om den har rensats
            if constexpr (N_storage > 0) { // Återuppbygger endast om det finns något att återuppbygga
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

                // Säkerställer null-terminering, även om N_storage är exakt fyllt.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // För N_storage == 0 (tom sträng, teoretiskt), inga checksummor
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // För att klara kontrollen

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // om N_storage var 0, är detta säkert om bufferten är > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Kontrollerar igen efter varje intern operation för att säkerställa integriteten.
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
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - Konstruktorn för `Secure_Accessor` anropas.
   - Den anropar `my_obfuscated_string.Decrypt()`. Detta innebär att deobfuskera `micro_program_` (till en lokal kopia), använda det för att dekryptera `my_obfuscated_string.storage_`, och sedan verifiera canaries och checksumman av det dekrypterade innehållet mot det förväntade.
   - Om det lyckas, kopieras innehållet i `my_obfuscated_string.storage_` (nu i klartext) och delas upp i `fragments_storage_` inuti `Secure_Accessor`.
   - En checksumma för `fragments_storage_` (`fragments_data_checksum_expected_`) beräknas.
   - Avgörande är att `my_obfuscated_string.Encrypt()` anropas *omedelbart efteråt*, vilket återobfuskerar `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (eller `const char* ptr = accessor;` på grund av implicit konvertering)
   - `Secure_Accessor::Get()` anropas.
   - Den kontrollerar sina egna integritets-canaries och de för det överordnade `Obfuscated_String`-objektet.
   - Om det är första åtkomsten (`current_access_ptr_` är `nullptr`), rekonstruerar den den fullständiga strängen i `reconstructed_plain_buffer_` från `fragments_storage_`.
   - Den kontrollerar sedan `fragments_data_checksum_reconstructed_` mot `fragments_data_checksum_expected_` för att säkerställa att fragmenten inte har manipulerats medan `Secure_Accessor` existerade.
   - Om allt är korrekt returnerar den en pekare till `reconstructed_plain_buffer_`.
3. Scopet för `accessor` avslutas (lämnar funktionen, `{}`, blocket avslutas etc.).
   - Destruktorn för `Secure_Accessor` anropas automatiskt.
   - `Clear_All_Internal_Buffers()` anropas, vilket säkert rensar (`Secure_Clear_Memory`) både `reconstructed_plain_buffer_` och `fragments_storage_`.

Resultatet är att strängen i klartext existerar i sin helhet endast inuti `Secure_Accessor` (i `reconstructed_plain_buffer_`) och endast efter det första anropet till `Get()`, under så kort tid som möjligt. Strängen i det ursprungliga `Obfuscated_String`-objektet återobfuskeras så snart `Secure_Accessor` har kopierat dess innehåll under sin konstruktion.

#### Minnesfragmentering i Secure_Accessor

För att ytterligare försvåra lokaliseringen av den fullständiga strängen i klartext i minnet, delar `Secure_Accessor` inte bara upp strängen under sin konstruktion, utan delar upp den:
1. Strängen från det överordnade `Obfuscated_String`-objektet dekrypteras.
2. Dess innehåll delas upp i upp till `fragment_count_val` (för närvarande 4, om strängen är tillräckligt stor) bitar, som kopieras till `fragments_storage_[i]`.
3. Strängen i det överordnade `Obfuscated_String`-objektet återobfuskeras.

Det är först när `Secure_Accessor::Get()` anropas för första gången som dessa fragment återmonteras i `reconstructed_plain_buffer_`. Denna teknik syftar till att "sprida ut" känsliga data, vilket motverkar minnesskanningar som letar efter sammanhängande strängar.

#### Säker minnesrensning

Både destruktorn för `Obfuscated_String` (via `Clear_Internal_Data`) och destruktorn för `Secure_Accessor` (via `Clear_All_Internal_Buffers`) använder `Dralyxor::Detail::Secure_Clear_Memory`. Denna wrapper-funktion säkerställer att buffertar som innehåller känslig data nollställs på ett tillförlitligt sätt, vilket förhindrar optimering av kompilatorn:
- **På Windows:** Använder `SecureZeroMemory` (User Mode) eller `RtlSecureZeroMemory` (Kernel Mode), vilket är operativsystemfunktioner som är särskilt utformade för att inte optimeras bort och för att säkert nollställa minnet.
- **På andra plattformar (Linux, macOS, etc.):** Implementationen använder nu `memset` för att fylla minnesblocket med nollor. `memset` arbetar på bytenivå, vilket gör den idealisk och säker för att nollställa både primitiva typer (som `char`, `int`) och komplexa typer (som `structs`), vilket undviker problem med typkompatibilitet eller tilldelningsoperatorer. För att säkerställa att `memset`-anropet inte optimeras bort av kompilatorn, castas buffertpekaren först till en `volatile` pekare.

Detta tillvägagångssätt säkerställer att när objekten förstörs, skrivs det känsliga innehållet över, vilket minskar risken för dataåterhämtning genom analys av minnesdumpar.

### Komponent 3: Körningsförsvar (Anti-Debugging och Anti-Tampering)

**Dralyxor** förlitar sig inte bara på obfuskering. Den använder en uppsättning aktiva försvar vid körning, huvudsakligen placerade i `anti_debug.hpp` och integrerade i `Decrypt()`- och `Encrypt()`-metoderna i `Obfuscated_String`.

#### Multi-plattformsdetektering av debuggers

Funktionen `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (i `anti_debug.hpp`) kontrollerar förekomsten av en debugger med hjälp av operativsystemspecifika tekniker:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` för `ProcessDebugPort` (0x07) och `ProcessDebugFlags` (0x1F).
- **Linux:** Läser `/proc/self/status` och kontrollerar värdet på `TracerPid:`. Ett värde annat än 0 indikerar att processen spåras.
- **macOS:** Använder `sysctl` med `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` för att få `kinfo_proc` och kontrollerar `P_TRACED`-flaggan i `kp_proc.p_flag`.

Dessutom, inuti `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Utför en loop av enkla beräkningsoperationer och mäter tiden. En betydande fördröjning (över `timing_threshold_milliseconds = 75ms`) kan indikera att en debugger stegar igenom koden eller att omfattande brytpunkter är aktiva. Inuti denna loop anropas `Is_Debugger_Present_Tracer_Pid_Sysctl()`, och en "lockbete"-funktion `Detail::Canary_Function_For_Breakpoint_Check()` (som helt enkelt returnerar `0xCC`, instruktionskoden för `int3` / programvarubrytpunkt) anropas och dess resultat XORas, vilket försvårar optimering och ger en vanlig plats för brytpunkter.
- `Detail::Perform_Output_Debug_String_Trick()` (endast Windows User Mode): Använder beteendet hos `OutputDebugStringA/W` och `GetLastError()`. Om en debugger är ansluten kan `GetLastError()` ändras efter anropet till `OutputDebugString`.

#### Inverkan på drift vid detektering eller integritetsbrott

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

        // OM runtime_key_mod INTE ÄR integrity_compromised_magic, ANVÄNDS DET INTE FÖR ATT ÄNDRA DEKRYPTERINGSNYCKELN.
        // Dekrypteringsnyckeln härleds alltid från det ursprungliga 'compile_time_seed'.
        // Rollen för runtime_key_mod här är ATT AGERA SOM EN FLAGGA för en fientlig miljö.
        // Om miljön är fientlig, returnerar funktionen integrity_compromised_magic och dekrypteringen fortsätter inte eller återställs.
        
        // Transform_Compile_Time_Consistent anropas med compile_time_seed (och INTE med runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Kontrollera checksumma och canaries igen ...
        // Om något misslyckas, Clear_Internal_Data() och returnerar integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Framgång
}
```

**Nyckeleffekt:** Om `Calculate_Runtime_Key_Modifier` upptäcker ett problem (debugger eller korrupt canary) och returnerar `integrity_compromised_magic`, avbryter `Decrypt()` (och på liknande sätt `Encrypt()`) operationen, rensar den interna datan i `Obfuscated_String` (inklusive `storage_` och `micro_program_`), och returnerar `integrity_compromised_magic`. Detta förhindrar att strängen dekrypteras korrekt (eller återkrypteras) i en fientlig miljö eller om objektet har manipulerats.
Strängen dekrypteras inte "felaktigt" (till skräp); operationen förhindras helt enkelt, och `Obfuscated_String`-objektet självförstörs vad gäller användbart innehåll.

#### Objektintegritets-canaries

Båda klasserna `Obfuscated_String` och `Secure_Accessor` innehåller canary-medlemmar (par av `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initierad med `Detail::integrity_canary_value`) och `_internal_integrity_canary2` (initierad med `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initierad med `Detail::accessor_integrity_canary_seed`) och `_accessor_integrity_canary2` (initierad med `~Detail::accessor_integrity_canary_seed`).

Dessa canaries kontrolleras vid kritiska punkter:
- Början och slutet av `Obfuscated_String::Decrypt()` och `Encrypt()`.
- Konstruktor, destruktor och `Get()` för `Secure_Accessor`.
- Före och efter anti-debug-kontroller i `Calculate_Runtime_Key_Modifier`.

Om dessa canary-värden ändras (t.ex. genom en buffer overflow, en godtycklig minnespatch, eller en hook som skriver över närliggande minne), kommer verifieringen (`Verify_Internal_Canaries()` eller `Verify_Internal_Accessor_Canaries()`) att misslyckas.
Vid misslyckande avbryts operationerna, relevant intern data rensas, och ett felvärde (`Detail::integrity_compromised_magic` eller `nullptr`) returneras, vilket signalerar manipulering.

#### Checksumma för stränginnehåll

- En 16-bitars checksumma av den *ursprungliga klartextsträngen* (exklusive null-terminatorn) beräknas av `Detail::Calculate_String_Content_Checksum` vid kompileringstid.
- Denna checksumma obfuskeras sedan med `Detail::Obfuscate_Deobfuscate_Short_Value` (med `compile_time_seed` och `content_checksum_obf_salt`) och lagras i `_content_checksum_obfuscated` i `Obfuscated_String`-objektet.
- **Vid dekryptering (`Decrypt()`):** Efter att `storage_` har transformerats (förmodligen till klartext), beräknas dess checksumma. `_content_checksum_obfuscated` deobfuskeras för att få referenschecksumman. Om de två checksummorna inte stämmer överens, indikerar det att:
   - Dekrypteringen inte återställde den ursprungliga strängen (kanske för att operationen avbröts på grund av debugger-detektering före fullständig transformation, eller så har seedet/mikroprogrammet korrumperats).
   - `storage_` (i obfuskerad form) eller `_content_checksum_obfuscated` har manipulerats i minnet.
- **Vid kryptering (`Encrypt()`):** Innan `storage_` (som är i klartext vid denna punkt) transformeras tillbaka till sin obfuskerade form, beräknas dess checksumma och jämförs med referensen. En avvikelse här skulle innebära att klartextsträngen har ändrats *inuti `Obfuscated_String`-objektets `storage_` medan den var dekrypterad*, vilket är en stark indikation på minnesmanipulering eller felaktig användning (eftersom direkt åtkomst till `storage_` inte ska ske).

I båda fallen av misslyckad checksumma anropas `Clear_Internal_Data()` och `integrity_compromised_magic` returneras.

### Komponent 4: Generering av unika och oförutsägbara nycklar och frön (seeds)

Säkerheten i vilket krypteringssystem som helst vilar på styrkan och unikheten hos dess nycklar och seeds. **Dralyxor** säkerställer att varje obfuskerad sträng använder en uppsättning fundamentalt unika krypteringsparametrar.

#### Entropikällor för `compile_time_seed`

`static constexpr uint64_t Obfuscated_String::compile_time_seed` är master-seedet för alla pseudo-slumpmässiga operationer relaterade till den specifika stränginstansen. Dess generering är nu villkorlig, baserad på om en användardefinierad nyckel finns:

- **Om en nyckel tillhandahålls av användaren (med `DRALYXOR_KEY` eller `DRALYXOR_KEY_LOCAL`):**
   1. Den angivna `key_literal` transformeras till en 64-bitars hash vid kompileringstid med FNV-1a-algoritmen.
   2. Denna hash blir grunden för `compile_time_seed`, kombinerat med `__COUNTER__` (för att säkerställa unikhet mellan olika användningar av samma nyckel) och strängens längd.
      ```cpp
      // Förenklad logik
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      I detta läge beror obfuskeringens säkerhet direkt på den angivna nyckelns styrka och hemlighet.

- **Om ingen nyckel tillhandahålls (med `DRALYXOR` eller `DRALYXOR_LOCAL`):**
   - `compile_time_seed` genereras med en kombination av följande faktorer för att maximera entropi och variabilitet:
      ```cpp
      // Inuti Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponent 1: Variabilitet mellan kompileringar
          ((uint64_t)Instance_Counter << 32) ^        // Komponent 2: Variabilitet inom en kompileringsenhet
          storage_n;                                  // Komponent 3: Variabilitet baserad på stränglängd
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Makrona `__DATE__` (t.ex. "Jan 01 2025") och `__TIME__` (t.ex. "12:30:00") är strängar som tillhandahålls av förprocessorn och ändras varje gång filen kompileras. FNV-1a-hashen av dessa värden skapar en grund för seedet som är annorlunda för varje bygge av projektet.
   - **`Instance_Counter` (matas av `__COUNTER__` i makrot)**: Makrot `__COUNTER__` är en räknare som underhålls av förprocessorn och ökar varje gång den används inom en kompileringsenhet. Genom att skicka detta som ett mallargument kommer varje användning av `DRALYXOR`- eller `DRALYXOR_LOCAL`-makrot att resultera i en annorlunda `Instance_Counter` och därmed ett annorlunda `compile_time_seed`, även för identiska strängliteraler i samma källfil.
   - **`storage_n` (strängens längd)**: Strängens längd XORas också in, vilket lägger till ytterligare en differentierande faktor.

Detta `compile_time_seed` (oavsett om det härleds från användarens nyckel eller genereras automatiskt) används sedan som grund för:
1. Att generera `micro_program_` (genom att seeda PRNG:n med `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Att härleda obfuskeringsnyckeln för själva `micro_program_` (via `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Att härleda obfuskeringsnyckeln för `_content_checksum_obfuscated` (via `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Att fungera som `base_seed` för `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Härledda frön (seeds) för innehållstransformationer

Inuti `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- En `Constexpr_PRNG prng_operand_modifier(base_seed)` initieras. För varje tecken i strängen som transformeras, producerar `prng_operand_modifier.Key()` en `prng_key_for_ops_in_elem`. Denna nyckel XORas med mikroinstruktionens operand före tillämpning, vilket säkerställer att effekten av samma mikroinstruktion är subtilt annorlunda för varje tecken.
- En `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` initieras. För varje tecken används `prng_applier_selector.Key()` för att välja mellan `Applier_Style_Direct` och `Applier_Style_DoubleLayer`.

Detta introducerar en ytterligare dynamik i transformationen av varje tecken, även om det underliggande mikroprogrammet är detsamma för alla tecken i en given sträng.

#### Immunitet mot "Replay"-attacker och mönsteranalys

- **Unikhet mellan kompileringar:** Om en angripare analyserar binärfilen från version 1.0 av din programvara och, med stor ansträngning, lyckas bryta obfuskeringen av en sträng (i automatiskt nyckelläge), kommer den kunskapen sannolikt att vara värdelös för version 1.1, eftersom `__DATE__ __TIME__` kommer att ha ändrats, vilket resulterar i helt olika `compile_time_seed`s och mikroprogram.
- **Unikhet inom kompilering:** Om du använder `DRALYXOR("AdminPassword")` på två olika platser i din kod (eller i samma .cpp-fil), kommer `__COUNTER__` att säkerställa att de resulterande `Obfuscated_String`-objekten, och därmed deras obfuskerade representationer i binärfilen, är olika. Detta förhindrar en angripare från att hitta ett obfuskerat mönster och använda det för att lokalisera alla andra förekomster av samma ursprungliga sträng.

Denna robusta generering av seeds är en hörnsten i **Dralyxor**s säkerhet mot attacker som förlitar sig på att upptäcka en "master-hemlighet" eller att utnyttja upprepning av chiffer och transformationer.

## Fullständig Referens för Publikt API

### Obfuskeringsmakron

Dessa är de huvudsakliga ingångspunkterna för att skapa obfuskerade strängar.

#### `DRALYXOR(str_literal)`

- **Syfte:** Skapar ett `Obfuscated_String`-objekt med statisk livslängd (existerar under hela programmets körning). Idealiskt för globala konstanter eller strängar som behöver nås från flera platser och bestå.
- **Lagring:** Statiskt minne (vanligtvis i programmets datasektion).
- **Implementering:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parametrar:**
   - `str_literal`: En C-stil strängliteral (t.ex. `"Hello World"`, `L"Unicode String"`).
- **Retur:** En referens (`auto&`) till det statiska `Obfuscated_String`-objektet, skapat inuti en omedelbart anropad lambda.
- **Exempel:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url är en referens till en statisk Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Syfte:** Skapar ett `Obfuscated_String`-objekt med automatisk livslängd (vanligtvis på stacken, om det används inuti en funktion). Idealiskt för temporära hemligheter begränsade till ett scope.
- **Lagring:** Automatiskt (stack för lokala funktionsvariabler).
- **Implementering:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Parametrar:**
   - `str_literal`: En C-stil strängliteral.
- **Retur:** Ett `Obfuscated_String`-objekt per värde (vilket kan optimeras med RVO/NRVO av kompilatorn).
- **Exempel:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... använd temp_key med DRALYXOR_SECURE ...
   } // temp_key förstörs här, dess destruktor anropar Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Syfte:** Liknar `DRALYXOR`, skapar ett statiskt `Obfuscated_String`-objekt, men använder en **användarspecificerad nyckel** (`key_literal`) för att seeda obfuskeringen, vilket ger den högsta säkerhetsnivån.
- **Lagring:** Statiskt minne (vanligtvis i programmets datasektion).
- **Implementering:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parametrar:**
   - `str_literal`: Strängliteralen som ska obfuskeras.
   - `key_literal`: Strängliteralen som ska användas som hemlig nyckel.
- **Retur:** En referens (`auto&`) till det statiska `Obfuscated_String`-objektet.
- **Exempel:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Syfte:** Liknar `DRALYXOR_LOCAL`, skapar ett `Obfuscated_String`-objekt på stacken, med en **användarspecificerad nyckel**.
- **Lagring:** Automatiskt (stack för lokala funktionsvariabler).
- **Implementering:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parametrar:**
   - `str_literal`: Strängliteralen som ska obfuskeras.
   - `key_literal`: Strängliteralen som ska användas som nyckel.
- **Retur:** Ett `Obfuscated_String`-objekt per värde.
- **Exempel:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Makro för säker åtkomst

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Syfte:** Ger säker och temporär åtkomst till det dekrypterade innehållet i ett `Obfuscated_String`-objekt. Detta är den **enda rekommenderade metoden** för att läsa strängen.
- **Implementering:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parametrar:**
   - `obfuscated_var`: En variabel (lvalue eller rvalue som kan bindas till en icke-konstant lvalue-referens) av typen `Dralyxor::Obfuscated_String<...>`. Variabeln måste vara muterbar eftersom `Secure_Accessor`s konstruktor anropar `Decrypt()` och `Encrypt()` på den.
- **Retur:** Ett `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>`-objekt per värde.
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
           // Dekrypterings- eller integritetsfel. Hantera felet.
           // Accessorn kan ha misslyckats med att initiera (t.ex. my_static_secret var korrupt).
       }
   } // accessor förstörs. Dess interna buffertar (fragment och rekonstruerad sträng) rensas.
    // my_static_secret.storage_ har redan återobfuskerats av Secure_Accessor-konstruktorn
    // direkt efter att innehållet kopierats till accessorns fragment.
   ```

> [!WARNING]
> Kontrollera alltid att pekaren som returneras av `DRALYXOR_SECURE(...).Get()` (eller genom den implicita konverteringen) inte är `nullptr` innan du använder den. Ett `nullptr`-returvärde indikerar ett dekrypteringsfel (till exempel debugger-detektering, korruption av canaries/checksummor i det överordnade `Obfuscated_String`-objektet eller i själva `Secure_Accessor`). Att använda en `nullptr`-pekare kommer att leda till odefinierat beteende (troligen en segmenteringsfel).

## Avancerade Funktioner och God Praxis

### Fullständigt Stöd för Unicode (Wide Strings - `wchar_t`)

**Dralyxor** är agnostisk till teckentyp tack vare användningen av mallar (`CharT`). Den hanterar `char` (för ASCII/UTF-8-strängar) och `wchar_t` (för UTF-16-strängar på Windows eller UTF-32 på andra system, beroende på plattform och kompilator) naturligt. Använd bara `L`-prefixet för `wchar_t`-literaler:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Unicode-meddelande: Hej Världen Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Exempel på Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Unicode-titel", MB_OK);
        // Exempel med wcout:
        // #include <io.h> // För _setmode på Windows med MSVC
        // #include <fcntl.h> // För _O_U16TEXT på Windows med MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Konfigurerar stdout för UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

För 1-byte tecken (`sizeof(CharT) == 1`) tillämpar transformationsmotorn `Micro_Program_Cipher` mikroprogrammet byte för byte. För multibyte-tecken (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` använder ett enklare tillvägagångssätt: hela multibyte-tecknet XORas med en mask som härleds från `prng_key_for_ops_in_elem` (replikerad för att fylla storleken på `CharT`). Till exempel, om `CharT` är `wchar_t` (2 bytes) och `prng_key_for_ops_in_elem` är `0xAB`, kommer tecknet att XORas med `0xABAB`.
Detta säkerställer att alla bytes i `wchar_t` påverkas av obfuskeringen, även om det inte är genom hela mikroprogrammet. Mikroprogrammets komplexitet bidrar fortfarande indirekt genom härledningen av nycklarna från PRNG:n.

### Intelligent Anpassning till **C++** Standarder och Miljöer (Kernel Mode)

Som nämnts anpassar sig **Dralyxor**:
- **C++-standarder:** Kräver minst **C++14**. Upptäcker och använder funktioner från **C++17** och **C++20** (som `if constexpr`, `consteval`, `_v`-suffix för `type_traits`) när kompilatorn stöder dem, och återgår till **C++14**-alternativ annars. Makron som `_DRALYXOR_IF_CONSTEXPR` och `_DRALYXOR_CONSTEVAL` i `detection.hpp` hanterar denna anpassning.
- **Kernel Mode:** När `_KERNEL_MODE` är definierat (typiskt i WDK-projekt för Windows-drivrutiner), undviker **Dralyxor** (via `env_traits.hpp`) att inkludera standard STL-headers som `<type_traits>` som kanske inte är tillgängliga eller beter sig annorlunda. Istället använder den sina egna `constexpr`-implementationer av grundläggande verktyg som `Dralyxor::Detail::Fallback::decay` och `Dralyxor::Detail::Fallback::remove_reference`. Detta möjliggör säker användning av **Dralyxor** för att skydda strängar i systemkomponenter på låg nivå.
   - På liknande sätt använder `secure_memory.hpp` `RtlSecureZeroMemory` i Kernel Mode. För andra plattformar, som Linux, återgår den till säker användning av `memset` för att säkerställa minnesrensning, anpassad för att vara kompatibel med olika datatyper.
   - Anti-debug-kontrollerna för User Mode (som `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) är inaktiverade (`#if !defined(_KERNEL_MODE)`) i Kernel Mode, eftersom de inte är tillämpliga eller har olika ekvivalenter. Tidskontrollerna kan fortfarande ha viss effekt, men den primära försvarslinjen i Kernel Mode är själva obfuskeringen.

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
>    - Säkra konfigurationer som tillhandahålls vid körtid (miljövariabler, konfigurationsfiler med begränsade behörigheter).
>    - Tjänster för hantering av hemligheter (vaults) som HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
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