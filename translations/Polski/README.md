# Dralyxor

**Dralyxor** to nowoczesna, `header-only`, wysokowydajna i wielowarstwowa biblioteka **C++**, zaprojektowana do zaciemniania ciągów znaków w czasie kompilacji oraz solidnej ochrony w czasie wykonania. Jej podstawową misją jest ochrona wewnętrznych sekretów Twojej aplikacji — takich jak klucze API, hasła, wewnętrzne adresy URL, komunikaty debugowania i wszelkie wrażliwe literały ciągów znaków — przed ujawnieniem poprzez analizę statyczną, inżynierię wsteczną i dynamiczną inspekcję pamięci. Poprzez szyfrowanie i transformację ciągów znaków w momencie kompilacji oraz bezpieczne zarządzanie ich dostępem w czasie wykonania, **Dralyxor** zapewnia, że żadne krytyczne literały ciągów znaków nie istnieją jako czysty tekst w Twoim finalnym pliku binarnym ani nie pozostają niezabezpieczone w pamięci dłużej niż jest to absolutnie konieczne.

Zbudowany na fundamentach nowoczesnego **C++** (wymagający **C++14** i inteligentnie dostosowujący się do funkcji **C++17** i **C++20**), jego zaawansowana architektura obejmuje wyrafinowany silnik transformacji oparty na "mikroprogramach", zaciemnianie samego programu transformacji, mechanizmy integralności danych, obronę przed debugowaniem oraz **Bezpieczny Akcesor Zasięgu (RAII)** do deszyfrowania "just-in-time" i automatycznego ponownego zaciemniania. To drastycznie minimalizuje ekspozycję danych w pamięci **RAM** i zapewnia profesjonalną obronę w głąb.

## Języki

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Spis treści

- [Dralyxor](#dralyxor)
  - [Języki](#języki)
  - [Spis treści](#spis-treści)
  - [Szybki przewodnik po integracji i użytkowaniu](#szybki-przewodnik-po-integracji-i-użytkowaniu)
    - [Instalacja](#instalacja)
    - [Wymagania dotyczące kompilatora](#wymagania-dotyczące-kompilatora)
    - [Podstawowe wzorce użycia](#podstawowe-wzorce-użycia)
      - [Wzorzec 1: Lokalne zaciemnianie (Stos)](#wzorzec-1-lokalne-zaciemnianie-stos)
      - [Wzorzec 2: Statyczne zaciemnianie (Globalne)](#wzorzec-2-statyczne-zaciemnianie-globalne)
    - [Obsługa błędów i integralność](#obsługa-błędów-i-integralność)
  - [Szczegółowa filozofia projektowania i architektura](#szczegółowa-filozofia-projektowania-i-architektura)
    - [Trwałe zagrożenie: Podatność literałów stringowych](#trwałe-zagrożenie-podatność-literałów-stringowych)
    - [Wielowarstwowe rozwiązanie architektoniczne **Dralyxor**](#wielowarstwowe-rozwiązanie-architektoniczne-dralyxor)
  - [Głęboka analiza komponentów architektonicznych](#głęboka-analiza-komponentów-architektonicznych)
    - [Komponent 1: Silnik transformacji przez Mikroprogram](#komponent-1-silnik-transformacji-przez-mikroprogram)
      - [Moc `consteval` i `constexpr` do generowania w czasie kompilacji](#moc-consteval-i-constexpr-do-generowania-w-czasie-kompilacji)
      - [Anatomia Mikroprogramu **Dralyxor**](#anatomia-mikroprogramu-dralyxor)
        - [Randomizowana generacja instrukcji i wybór aplikatorów](#randomizowana-generacja-instrukcji-i-wybór-aplikatorów)
        - [Zmienne i logiczne NOP-y dla entropii](#zmienne-i-logiczne-nop-y-dla-entropii)
      - [Zaciemnianie samego Mikroprogramu](#zaciemnianie-samego-mikroprogramu)
      - [Cykl życia statycznego zaciemniania](#cykl-życia-statycznego-zaciemniania)
    - [Komponent 2: Bezpieczny dostęp i minimalizacja ekspozycji w **RAM**](#komponent-2-bezpieczny-dostęp-i-minimalizacja-ekspozycji-w-ram)
      - [`Secure_Accessor` i zasada RAII](#secure_accessor-i-zasada-raii)
      - [Fragmentacja pamięci w `Secure_Accessor`](#fragmentacja-pamięci-w-secure_accessor)
      - [Bezpieczne czyszczenie pamięci](#bezpieczne-czyszczenie-pamięci)
    - [Komponent 3: Ochrona w czasie wykonania (Anti-Debugging i Anti-Tampering)](#komponent-3-ochrona-w-czasie-wykonania-anti-debugging-i-anti-tampering)
      - [Wieloplatformowe wykrywanie debuggerów](#wieloplatformowe-wykrywanie-debuggerów)
      - [Wpływ na działanie w przypadku wykrycia lub naruszenia integralności](#wpływ-na-działanie-w-przypadku-wykrycia-lub-naruszenia-integralności)
      - [Kanarki integralności obiektu](#kanarki-integralności-obiektu)
      - [Suma kontrolna zawartości stringu](#suma-kontrolna-zawartości-stringu)
    - [Komponent 4: Generowanie unikalnych i nieprzewidywalnych kluczy i nasion](#komponent-4-generowanie-unikalnych-i-nieprzewidywalnych-kluczy-i-nasion)
      - [Źródła entropii dla `compile_time_seed`](#źródła-entropii-dla-compile_time_seed)
      - [Pochodne nasiona dla transformacji zawartości](#pochodne-nasiona-dla-transformacji-zawartości)
      - [Odporność na ataki typu "replay" i analizę wzorców](#odporność-na-ataki-typu-replay-i-analizę-wzorców)
  - [Pełna dokumentacja publicznego API](#pełna-dokumentacja-publicznego-api)
    - [Makra zaciemniania](#makra-zaciemniania)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Makro bezpiecznego dostępu](#makro-bezpiecznego-dostępu)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Zaawansowane funkcje i dobre praktyki](#zaawansowane-funkcje-i-dobre-praktyki)
    - [Pełne wsparcie dla Unicode (Szerokie stringi - `wchar_t`)](#pełne-wsparcie-dla-unicode-szerokie-stringi---wchar_t)
    - [Inteligentne dostosowywanie się do standardów **C++** i środowisk (Kernel Mode)](#inteligentne-dostosowywanie-się-do-standardów-c-i-środowisk-kernel-mode)
    - [Uwagi dotyczące wydajności i narzutu](#uwagi-dotyczące-wydajności-i-narzutu)
    - [Integracja ze strategią bezpieczeństwa warstwowego](#integracja-ze-strategią-bezpieczeństwa-warstwowego)
  - [Licencja](#licencja)
    - [Warunki:](#warunki)

## Szybki przewodnik po integracji i użytkowaniu

### Instalacja

**Dralyxor** to biblioteka typu **header-only**. Nie jest wymagana wcześniejsza kompilacja ani linkowanie bibliotek (`.lib`/`.a`).

1.  **Skopiuj Katalog `Dralyxor`:** Pobierz najnowszą wersję biblioteki (sklonuj repozytorium lub pobierz plik zip) i skopiuj cały katalog `Dralyxor` (zawierający wszystkie pliki `.hpp`) do lokalizacji dostępnej dla Twojego projektu (np. folder `libs/`, `libraries/` lub `vendor/`).
2.  **Dołącz Główny Plik Nagłówkowy:** W swoim kodzie źródłowym dołącz główny plik nagłówkowy `dralyxor.hpp`:
   ```cpp
   #include "sciezka/do/Dralyxor/dralyxor.hpp"
   ```

Typowa struktura projektu:
```
/MójProjekt/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor tutaj
        |-- dralyxor.hpp            (Główny punkt wejścia)
        |-- obfuscated_string.hpp   (Klasa Obfuscated_String)
        |-- secure_accessor.hpp     (Klasa Secure_Accessor)
        |-- algorithms.hpp          (Silnik transformacji i mikroprogramy)
        |-- anti_debug.hpp          (Wykrywanie w czasie wykonania)
        |-- prng.hpp                (Generator liczb pseudolosowych w czasie kompilacji)
        |-- integrity_constants.hpp (Stałe do weryfikacji integralności)
        |-- secure_memory.hpp       (Bezpieczne czyszczenie pamięci)
        |-- detection.hpp           (Makra wykrywania kompilatora/standardu C++)
        `-- env_traits.hpp          (Adaptacje type_traits dla ograniczonych środowisk)
```

### Wymagania dotyczące kompilatora

> [!IMPORTANT]
> **Dralyxor** został zaprojektowany z myślą o nowoczesnym **C++** dla maksymalnego bezpieczeństwa i wydajności w czasie kompilacji.
>
> - **Minimalny Standard C++: C++14**. Biblioteka wykorzystuje funkcje takie jak uogólnione `constexpr` i dostosowuje się do `if constexpr` (gdy dostępne poprzez `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptacja do Wyższych Standardów:** Wykrywa i wykorzystuje optymalizacje lub składnie **C++17** i **C++20** (takie jak `consteval`, sufiksy `_v` dla `type_traits`), jeśli projekt jest kompilowany z tymi standardami. `_DRALYXOR_CONSTEVAL` mapuje na `consteval` w C++20 i `constexpr` w C++14/17, zapewniając wykonanie w czasie kompilacji tam, gdzie to możliwe.
> - **Wspierane Kompilatory:** Testowany głównie z najnowszymi MSVC, GCC i Clang.
> - **Środowisko Wykonawcze:** W pełni kompatybilny z aplikacjami **User Mode** oraz środowiskami **Kernel Mode** (np. sterowniki Windows). W Kernel Mode, gdzie STL może nie być dostępna, **Dralyxor** wykorzystuje wewnętrzne implementacje niezbędnych `type traits` (patrz `env_traits.hpp`).

### Podstawowe wzorce użycia

#### Wzorzec 1: Lokalne zaciemnianie (Stos)

Idealne dla tymczasowych ciągów znaków, ograniczonych do zakresu funkcji. Pamięć jest automatycznie zarządzana i czyszczona.

```cpp
#include "Dralyxor/dralyxor.hpp" // Dostosuj ścieżkę w razie potrzeby
#include <iostream>

void Konfiguruj_Logowanie() {
    // Klucz formatowania logu, używany tylko lokalnie.
    auto klucz_formatu_logu = DRALYXOR_LOCAL("ZnacznikCzasu={ts}, Poziom={lvl}, Wiadomosc={msg}");

    // Bezpieczny dostęp w ograniczonym zakresie
    {
        // Secure_Accessor tymczasowo odszyfrowuje 'klucz_formatu_logu' podczas jego konstrukcji
        // (i ponownie zaciemnia 'klucz_formatu_logu' natychmiast po skopiowaniu do swoich wewnętrznych buforów),
        // umożliwia dostęp i czyści własne bufory przy zniszczeniu.
        auto akcesor = DRALYXOR_SECURE(klucz_formatu_logu);

        if (akcesor.Get()) { // Zawsze sprawdzaj, czy Get() nie zwraca nullptr
            std::cout << "Używany format logu: " << akcesor.Get() << std::endl;
            // Np.: logger.SetFormat(akcesor.Get());
        }
        else
            std::cerr << "Nie udało się odszyfrować klucza_formatu_logu (możliwe manipulowanie lub wykrycie debuggera?)" << std::endl;
    } // akcesor jest niszczony, jego wewnętrzne bufory są czyszczone. klucz_formatu_logu pozostaje zaciemniony.
      // klucz_formatu_logu zostanie zniszczony na końcu funkcji Konfiguruj_Logowanie.
}
```

#### Wzorzec 2: Statyczne zaciemnianie (Globalne)

Dla stałych, które muszą istnieć przez cały okres życia programu i być dostępne globalnie.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Dla przykładu

// URL API licencji, trwały sekret.
// Makro DRALYXOR() tworzy obiekt statyczny.
// Funkcja Pobierz_URL_Serwera_Licencji() zwraca referencję do tego obiektu statycznego.
static auto& Pobierz_URL_Serwera_Licencji() {
    static auto& url_licencji = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return url_licencji;
}

bool Zweryfikuj_Licencje(const std::string& klucz_uzytkownika) {
    auto& ref_obj_url = Pobierz_URL_Serwera_Licencji(); // ref_obj_url to referencja do statycznego Obfuscated_String.
    bool sukces = false;
    {
        auto akcesor = DRALYXOR_SECURE(ref_obj_url); // Tworzy Secure_Accessor dla ref_obj_url.

        if (akcesor.Get()) {
            std::cout << "Kontaktowanie się z serwerem licencji pod adresem: " << akcesor.Get() << std::endl;
            // Np.: sukces = http_client.Check(akcesor.Get(), klucz_uzytkownika);
            sukces = true; // Symulacja sukcesu dla przykładu
        }
        else
            std::cerr << "Nie udało się odszyfrować URL serwera licencji (możliwe manipulowanie lub wykrycie debuggera?)." << std::endl;
    } // akcesor jest niszczony, jego bufory są czyszczone. ref_obj_url (oryginalny Obfuscated_String) pozostaje zaciemniony.

    return sukces;
}
```

### Obsługa błędów i integralność

Funkcje `Obfuscated_String::Decrypt()` i `Encrypt()` zwracają `uint64_t`:
- `0` oznacza sukces.
- `Dralyxor::Detail::integrity_compromised_magic` (stała wartość zdefiniowana w `integrity_constants.hpp`) wskazuje, że weryfikacja integralności nie powiodła się. Może to być spowodowane uszkodzeniem kanarków obiektu, niespójną sumą kontrolną zawartości lub wykryciem debuggera sygnalizującego wrogie środowisko.

Podobnie, `Secure_Accessor::Get()` (lub jego niejawna konwersja na `const CharT*`) zwróci `nullptr`, jeśli inicjalizacja `Secure_Accessor` nie powiedzie się (np. jeśli odszyfrowanie oryginalnego `Obfuscated_String` nie powiedzie się) lub jeśli integralność `Secure_Accessor` (jego własne kanarki lub wewnętrzne sumy kontrolne) zostanie naruszona podczas jego życia.

**Kluczowe jest, aby Twój kod sprawdzał te wartości zwrotne w celu zapewnienia solidności i bezpieczeństwa aplikacji.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Przyklad_Obslugi_Bledow() {
    auto moj_sekret = DRALYXOR_LOCAL("Wazne Dane!");

    // Zazwyczaj NIE wywoływałbyś Decrypt() i Encrypt() bezpośrednio,
    // ponieważ Secure_Accessor tym zarządza. Ale jeśli potrzebujesz z jakiegoś powodu:
    if (moj_sekret.Decrypt() != 0) {
        std::cerr << "OSTRZEŻENIE: Nie udało się odszyfrować 'moj_sekret' lub integralność została naruszona podczas Decrypt()!" << std::endl;
        // Podejmij odpowiednie działania: zakończ, zaloguj w bezpieczny sposób itp.
        // Obiekt moj_sekret.storage_ może być w nieprawidłowym stanie lub zawierać śmieci.
        return; // Unikaj używania moj_sekret, jeśli Decrypt() zawiedzie.
    }

    // Jeśli Decrypt() się powiodło, moj_sekret.storage_ zawiera odszyfrowane dane.
    // **BEZPOŚREDNI DOSTĘP DO storage_ JEST STANOWCZO ODRADZANY W PRODUKCJI.**
    // std::cout << "Dane w moj_sekret.storage_ (NIE RÓB TEGO): " << moj_sekret.storage_ << std::endl;

    // Twoim obowiązkiem jest ponowne zaszyfrowanie, jeśli wywołałeś Decrypt() ręcznie:
    if (moj_sekret.Encrypt() != 0) {
        std::cerr << "OSTRZEŻENIE: Nie udało się ponownie zaszyfrować 'moj_sekret' lub integralność została naruszona podczas Encrypt()!" << std::endl;
        // Niepewny stan, potencjalnie niebezpieczny.
    }

    // ZALECANE UŻYCIE z Secure_Accessor:
    auto inny_sekret = DRALYXOR_LOCAL("Inny Kawałek Danych!");
    {
        // Konstruktor Secure_Accessor wywołuje inny_sekret.Decrypt(), kopiuje, a następnie inny_sekret.Encrypt().
        auto akcesor = DRALYXOR_SECURE(inny_sekret);
        const char* wskaznik_danych = akcesor.Get(); // Lub: const char* wskaznik_danych = akcesor;

        if (wskaznik_danych) {
            std::cout << "Tajne dane przez Secure_Accessor: " << wskaznik_danych << std::endl;
            // Użyj wskaznik_danych tutaj
        }
        else {
            std::cerr << "OSTRZEŻENIE: Secure_Accessor nie udało się zainicjalizować lub uzyskać wskaźnika do 'inny_sekret'!" << std::endl;
            // Oznacza to, że Decrypt() w konstruktorze akcesora zawiodło,
            // lub doszło do manipulacji akcesorem (kanarki, wewnętrzne sumy kontrolne).
        }
    } // akcesor jest niszczony. Jego bufory są czyszczone. inny_sekret pozostaje zaciemniony.
}
```

## Szczegółowa filozofia projektowania i architektura

**Dralyxor** to nie tylko szyfr XOR; to system obrony w głąb dla literałów stringowych. Jego architektura opiera się na założeniu, że skuteczne bezpieczeństwo wymaga wielu połączonych warstw i odporności na różne techniki analizy.

### Trwałe zagrożenie: Podatność literałów stringowych

Literały stringowe, takie jak `"api.example.com/data?key="`, gdy są bezpośrednio osadzone w kodzie, są zapisywane w czytelnej formie (czysty tekst) w skompilowanym pliku binarnym. Narzędzia takie jak `strings`, deasembler (IDA Pro, Ghidra) i edytory heksadecymalne mogą je trywialnie wyodrębnić. Ta ekspozycja ułatwia:
- **Inżynierię Wsteczną:** Zrozumienie wewnętrznej logiki i przepływu programu.
- **Identyfikację Endpointów:** Odkrywanie serwerów i backendowych API.
- **Ekstrakcję Sekretów:** Kluczy API, osadzonych haseł, prywatnych URL-i, zapytań SQL itp.
- **Analizę Pamięci Dynamicznej:** Nawet jeśli program odszyfruje string do użycia, jeśli pozostanie on w czystym tekście w **RAM** przez zbyt długi czas, atakujący z dostępem do pamięci procesu (przez debugger lub zrzut pamięci) może go znaleźć.

**Dralyxor** atakuje te podatności zarówno w czasie kompilacji (dla pliku binarnego na dysku), jak i w czasie wykonania (dla pamięci **RAM**).

### Wielowarstwowe rozwiązanie architektoniczne **Dralyxor**

Solidność **Dralyxor** wynika z synergii jego kluczowych komponentów:

| Komponent Architektoniczny                | Główny Cel                                                                               | Kluczowe Zastosowane Technologie/Techniki                                                                                                                              |
| :------------------------------------------ | :--------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Silnik Transformacji przez Mikroprogram** | Eliminacja stringów w czystym tekście z pliku binarnego; tworzenie złożonego, dynamicznego i nietrywialnego zaciemnienia. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, wielokrotne operacje (XOR, ADD, ROT, itp.), zmienne i logiczne NOP-y, zmienne style aplikatorów.         |
| **Bezpieczny Dostęp i Minimalizacja Ekspozycji** | Drastyczne skrócenie czasu, przez który sekret jest odszyfrowany w pamięci RAM.          | Wzorzec RAII (`Secure_Accessor`), fragmentacja pamięci, bezpieczne czyszczenie buforów (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Ochrona w Czasie Wykonania**             | Wykrywanie i reagowanie na wrogie środowiska analizy i manipulację pamięcią.            | Wykrywanie Debuggerów (specyficzne dla OS API, timing, OutputDebugString), kanarki integralności obiektu, suma kontrolna zawartości stringu.                              |
| **Generowanie Unikalnych Kluczy i Nasion**  | Zapewnienie, że każdy zaciemniony string i każda instancja użycia są kryptograficznie odrębne. | `__DATE__`, `__TIME__`, `__COUNTER__`, rozmiar stringu, hashowanie FNV-1a dla `compile_time_seed`, pochodne nasiona dla modyfikatorów operandów i selektorów. |

## Głęboka analiza komponentów architektonicznych

### Komponent 1: Silnik transformacji przez Mikroprogram

Sercem statycznego i dynamicznego zaciemniania w **Dralyxor** jest jego silnik transformacji, który wykorzystuje unikalne "mikroprogramy" dla każdego stringu i kontekstu.

#### Moc `consteval` i `constexpr` do generowania w czasie kompilacji
Nowoczesny **C++**, z `consteval` (**C++20**) i `constexpr` (**C++11** i nowsze), pozwala na wykonanie złożonego kodu *podczas kompilacji*. **Dralyxor** wykorzystuje `_DRALYXOR_CONSTEVAL` (który mapuje na `consteval` lub `constexpr` w zależności od standardu **C++**) dla konstruktora `Obfuscated_String` oraz do generowania mikroprogramu.

Oznacza to, że cały proces:
1. Generowania pseudolosowej sekwencji instrukcji transformacji (mikroprogramu).
2. Zaciemniania samego mikroprogramu do przechowywania.
3. Stosowania tego mikroprogramu (w tymczasowo odszyfrowanej formie) do transformacji oryginalnego stringu, co skutkuje jego zaciemnioną formą.
Wszystko to dzieje się w czasie kompilacji, zanim zostanie wygenerowany plik binarny.

#### Anatomia Mikroprogramu **Dralyxor**

Każdy obiekt `Obfuscated_String` przechowuje małą tablicę `Dralyxor::Detail::Micro_Instruction`. `Micro_Instruction` to prosta struktura zdefiniowana w `algorithms.hpp`:
```cpp
// W Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM // Chociaż obecne, nie jest aktywnie używane do zakończenia wykonania mikroprogramu,
                   // iteracja jest kontrolowana przez 'num_actual_instructions_in_program_'.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // Operacja (XOR, ADD, ROTL, itp.)
    uint8_t operand;            // Wartość używana przez operację
};

// Maksymalna liczba instrukcji, jakie może zawierać mikroprogram.
static constexpr size_t max_micro_instructions = 8;
```
Funkcja `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` jest odpowiedzialna за wypełnienie tej tablicy.

##### Randomizowana generacja instrukcji i wybór aplikatorów

- **Generacja Instrukcji:** Używając `Dralyxor::Detail::Constexpr_PRNG` (zasianego kombinacją `compile_time_seed` i `0xDEADBEEFC0FFEEULL`), funkcja `Generate_Micro_Program_Instructions` probabilistycznie wybiera sekwencję operacji:
   - `XOR`: Bitowy XOR z operandem.
   - `ADD`: Dodawanie modularne z operandem.
   - `SUB`: Odejmowanie modularne z operandem.
   - `ROTR`/`ROTL`: Rotacja bitów. Operand (po modulo) definiuje liczbę przesunięć (1 do 7).
   - `SWAP_NIB`: Zamienia 4 dolne bity z 4 górnymi bitami bajtu (operand jest ignorowany).
    Operandy dla tych instrukcji są również generowane pseudolosowo przez PRNG.

- **Modyfikacja Operandów i Wybór Aplikatorów w Czasie Transformacji:** Podczas stosowania mikroprogramu (przez `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), zarówno przy początkowym zaciemnianiu, jak i przy odszyfrowywaniu w czasie wykonania:
   - `Constexpr_PRNG prng_operand_modifier` (zasiany `base_seed`) generuje `prng_key_for_ops_in_elem` dla każdego znaku stringu. Operand mikroinstrukcji (`instr_orig.operand`) jest XORowany z tym kluczem przed użyciem. Gwarantuje to, że ten sam mikroprogram stosuje nieco inne transformacje dla każdego znaku.
   - `Constexpr_PRNG prng_applier_selector` (zasiany `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) wybiera `Byte_Transform_Applier` dla każdego znaku. Obecnie istnieją dwa style:
      - `Applier_Style_Direct`: Stosuje operację bezpośrednio (odwracając ją do deszyfrowania, np. ADD staje się SUB).
      - `Applier_Style_DoubleLayer`: Stosuje operację dwukrotnie (lub operację i jej odwrotność, w zależności od trybu szyfrowania/deszyfrowania) z różnymi operandami, czyniąc odwrócenie nieco bardziej złożonym do analizy.

##### Zmienne i logiczne NOP-y dla entropii

Aby zwiększyć trudność ręcznej analizy mikroprogramu, **Dralyxor** wstawia:
- **Jawne NOP-y:** Instrukcje `Micro_Operation_Code::NOP`, które nic nie robią.
- **Logiczne NOP-y:** Pary instrukcji, które wzajemnie się znoszą, takie jak `ADD K` po którym następuje `SUB K`, lub `ROTL N_BITS` po którym następuje `ROTR N_BITS`. Operand użyty w parze jest taki sam.

Te NOP-y są wstawiane probabilistycznie przez `Generate_Micro_Program_Instructions`, wypełniając tablicę `micro_program_` i utrudniając rozróżnienie efektywnych transformacji od operacji "szumu".

#### Zaciemnianie samego Mikroprogramu

Po wygenerowaniu mikroprogramu i przed początkowym zaciemnieniem stringu w konstruktorze `consteval`, tablica `micro_program_` (zawarta w obiekcie `Obfuscated_String`) jest sama zaciemniana. Każdy `op_code` i `operand` w każdej `Micro_Instruction` jest XORowany z kluczem pochodzącym z `compile_time_seed` (używając `Detail::Get_Micro_Program_Obfuscation_Key` i `Detail::Obfuscate_Deobfuscate_Instruction`).
Oznacza to, że nawet jeśli atakujący zdoła zrzucić pamięć obiektu `Obfuscated_String`, mikroprogram nie będzie w swojej bezpośrednio czytelnej/stosowalnej formie.

Gdy wywoływane są `Obfuscated_String::Decrypt()` lub `Encrypt()` (lub pośrednio przez `Secure_Accessor`), centralna funkcja `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` otrzymuje ten *zaciemniony* mikroprogram. Następnie:
1. Tworzy tymczasową kopię mikroprogramu (`local_plain_program`) na stosie.
2. Odszyfrowuje tę lokalną kopię używając tego samego klucza (`program_obf_key`) pochodzącego z przekazanego nasiona bazowego (którym ostatecznie jest `compile_time_seed`).
3. Używa tego `local_plain_program` do transformacji danych stringu.
Lokalna kopia na stosie jest niszczona na końcu funkcji, a `micro_program_` przechowywany w obiekcie `Obfuscated_String` pozostaje zaciemniony.

#### Cykl życia statycznego zaciemniania

1.  **Kod Źródłowy:** `auto obj_klucza_api = DRALYXOR_LOCAL("SEKRETNY_KLUCZ_API");`
2.  **Preprocesowanie:** Makro rozszerza się do instancjacji `Dralyxor::Obfuscated_String<char, 19, __COUNTER__>("SEKRETNY_KLUCZ_API");`. (Rozmiar 19 zawiera terminator null).
3.  **Ewaluacja `_DRALYXOR_CONSTEVAL`:**
    -   Kompilator wykonuje konstruktor `Obfuscated_String`.
    -   `Initialize_Internal_Canaries()` ustawia kanarki integralności.
    -   `Generate_Micro_Program_Instructions()` (zasiane `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) tworzy sekwencję `Micro_Instruction` i przechowuje ją w `this->micro_program_` (np. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Rzeczywista liczba instrukcji jest przechowywana w `num_actual_instructions_in_program_`.
    -   Oryginalny string "SEKRETNY\_KLUCZ\_API" jest kopiowany do `this->storage_`.
    -   Suma kontrolna oryginalnego stringu "SEKRETNY\_KLUCZ\_API" (z wyłączeniem null) jest obliczana przez `Detail::Calculate_String_Content_Checksum`, a następnie zaciemniana przez `Detail::Obfuscate_Deobfuscate_Short_Value` (używając `compile_time_seed` i `content_checksum_obf_salt`) i przechowywana w `this->_content_checksum_obfuscated`.
    -   Wywoływane jest `Obfuscate_Internal_Micro_Program()`: `this->micro_program_` jest zaciemniany w miejscu (każda instrukcja XORowana z `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
    -   Wywoływane jest `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)`. Ta funkcja:
        -   Tworzy odszyfrowaną kopię `this->micro_program_` на stosie.
        -   Dla każdego znaku w `storage_` (z wyjątkiem null):
            -   Generuje `prng_key_for_ops_in_elem` i wybiera `Byte_Transform_Applier`.
            -   Stosuje sekwencję mikroinstrukcji (z odszyfrowanej kopii) do znaku, używając aplikatora i zmodyfikowanego operanda.
        -   Na końcu `storage_` zawiera zaciemniony string (np. `[CF, 3A, D1, ..., 0x00]`).
4.  **Generacja Kodu:** Kompilator alokuje miejsce dla `obj_klucza_api` i inicjalizuje je bezpośrednio:
    -   `storage_`: `[CF, 3A, D1, ..., 0x00]` (zaciemniony string).
    -   `micro_program_`: *Już zaciemniony* mikroprogram.
    -   `_content_checksum_obfuscated`: Suma kontrolna oryginalnej zawartości, *zaciemniona*.
    -   `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Literał `"SEKRETNY_KLUCZ_API"` nie istnieje już w pliku binarnym.

### Komponent 2: Bezpieczny dostęp i minimalizacja ekspozycji w **RAM**

#### `Secure_Accessor` i zasada RAII

Ochrona w czasie kompilacji to tylko połowa bitwy. Gdy string musi zostać użyty, musi zostać odszyfrowany. Jeśli ten odszyfrowany string pozostanie w pamięci **RAM** przez dłuższy czas, staje się celem analizy dynamicznej (zrzuty pamięci, debuggery).

**Dralyxor** rozwiązuje ten problem za pomocą `Dralyxor::Secure_Accessor`, klasy implementującej wzorzec **RAII** (Resource Acquisition Is Initialization):
- **Zasób Pozyskany:** Tymczasowy dostęp do stringu w czystym tekście, sfragmentowanego i zarządzanego przez akcesor.
- **Obiekt Zarządzający:** Instancja `Secure_Accessor`.

```cpp
// W secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Zainicjuj różne, aby zawieść, jeśli nie zaktualizowane
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Unieważnia akcesor

            return;
        }

        // 1. Próbuje odszyfrować oryginalny Obfuscated_String.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Jeśli odszyfrowanie powiedzie się, kopiuje string w czystym tekście do wewnętrznych fragmentów.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ jest teraz w czystym tekście
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val to maksymalnie 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Wypełnij resztę bufora fragmentu zerami
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Suma kontrolna fragmentów
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. NATYCHMIAST ponownie szyfruje oryginalny Obfuscated_String.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Czyści fragmenty i zrekonstruowany bufor.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Sprawdza siebie i rodzica
            Clear_All_Internal_Buffers(); // Środek bezpieczeństwa
            _accessor_integrity_canary1 = 0; // Unieważnia dla przyszłych dostępów

            return nullptr;
        }

        if (!current_access_ptr_) { // Jeśli to pierwsze wywołanie Get() lub jeśli został wyczyszczony
            if constexpr (N_storage > 0) { // Rekonstruuje tylko, jeśli jest co rekonstruować
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

                // Gwarantuje zakończenie zerem, nawet jeśli N_storage jest dokładnie wypełnione.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Dla N_storage == 0 (teoretycznie pusty string), nie ma sum kontrolnych
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Aby przejść sprawdzenie

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // jeśli N_storage było 0, jest to bezpieczne, jeśli bufor > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Sprawdza ponownie po każdej operacji wewnętrznej, aby zapewnić integralność.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Przepływ Użycia z `DRALYXOR_SECURE`:**
1. `auto akcesor = DRALYXOR_SECURE(moj_zaciemniony_string);`
   - Wywoływany jest konstruktor `Secure_Accessor`.
   - Wywołuje `moj_zaciemniony_string.Decrypt()`. Obejmuje to odszyfrowanie `micro_program_` (do lokalnej kopii), użycie go do odszyfrowania `moj_zaciemniony_string.storage_`, a następnie sprawdzenie kanarków i sumy kontrolnej odszyfrowanej zawartości z oczekiwaną.
   - Jeśli się powiedzie, zawartość `moj_zaciemniony_string.storage_` (teraz czysty tekst) jest kopiowana i dzielona na wewnętrzne `fragments_storage_` `Secure_Accessor`.
   - Obliczana jest suma kontrolna `fragments_storage_` (`fragments_data_checksum_expected_`).
   - Co kluczowe, `moj_zaciemniony_string.Encrypt()` jest wywoływane *natychmiast po tym*, ponownie zaciemniając `moj_zaciemniony_string.storage_`.
2. `const char* ptr = akcesor.Get();` (lub `const char* ptr = akcesor;` z powodu niejawnej konwersji)
   - Wywoływane jest `Secure_Accessor::Get()`.
   - Sprawdza własne kanarki integralności oraz kanarki nadrzędnego `Obfuscated_String`.
   - Jeśli to pierwszy dostęp (`current_access_ptr_` jest `nullptr`), rekonstruuje pełny string w `reconstructed_plain_buffer_` z `fragments_storage_`.
   - Następnie sprawdza `fragments_data_checksum_reconstructed_` z `fragments_data_checksum_expected_`, aby upewnić się, że fragmenty nie zostały zmanipulowane podczas istnienia `Secure_Accessor`.
   - Jeśli wszystko jest w porządku, zwraca wskaźnik do `reconstructed_plain_buffer_`.
3. Kończy się zakres `akcesor` (opuszcza funkcję, kończy się blok `{}`, itp.).
   - Destruktor `Secure_Accessor` jest wywoływany automatycznie.
   - Wywoływane jest `Clear_All_Internal_Buffers()`, które bezpiecznie czyści (`Secure_Clear_Memory`) zarówno `reconstructed_plain_buffer_`, jak i `fragments_storage_`.

Rezultat jest taki, że string w czystym tekście istnieje w pełnej formie tylko wewnątrz `Secure_Accessor` (w `reconstructed_plain_buffer_`) i tylko po pierwszym wywołaniu `Get()`, przez możliwie najkrótszy czas. String w oryginalnym obiekcie `Obfuscated_String` jest ponownie zaciemniany, gdy tylko `Secure_Accessor` skopiuje jego zawartość podczas konstrukcji.

#### Fragmentacja pamięci w `Secure_Accessor`

Aby jeszcze bardziej utrudnić zlokalizowanie pełnego stringu w czystym tekście w pamięci, `Secure_Accessor`, podczas swojej konstrukcji, nie tylko kopiuje odszyfrowany string, ale go dzieli:
1. String z nadrzędnego `Obfuscated_String` jest odszyfrowywany.
2. Jego zawartość jest dzielona na maksymalnie `fragment_count_val` (obecnie 4, jeśli string jest wystarczająco duży) części, które są kopiowane do `fragments_storage_[i]`.
3. String w nadrzędnym obiekcie `Obfuscated_String` jest ponownie zaciemniany.

Dopiero gdy `Secure_Accessor::Get()` jest wywoływane po raz pierwszy, te fragmenty są ponownie składane w `reconstructed_plain_buffer_`. Ta technika ma na celu "rozproszenie" wrażliwych danych, frustrując skanowania pamięci poszukujące ciągłych stringów.

#### Bezpieczne czyszczenie pamięci

Zarówno destruktor `Obfuscated_String` (poprzez `Clear_Internal_Data`), jak i destruktor `Secure_Accessor` (poprzez `Clear_All_Internal_Buffers`) używają `Dralyxor::Detail::Secure_Clear_Memory` (szablon dla tablic) lub `Dralyxor::Detail::Secure_Clear_Memory_Raw` (dla surowych wskaźników, chociaż `Secure_Clear_Memory` jest częściej używane w destruktorach). Ta funkcja opakowująca:
- Używa `SecureZeroMemory` (Windows User Mode) lub `RtlSecureZeroMemory` (Windows Kernel Mode), gdy są dostępne, które są funkcjami systemu operacyjnego zaprojektowanymi tak, aby nie były optymalizowane przez kompilator.
- Ucieka się do pętli ze wskaźnikiem `volatile T* p` na innych platformach lub gdy specyficzne funkcje Windows nie są dostępne. `volatile` jest próbą poinstruowania kompilatora, aby nie optymalizował zapisu zer. Gwarantuje to, że gdy obiekty są niszczone lub bufory są jawnie czyszczone, wrażliwa zawartość jest nadpisywana, zmniejszając ryzyko odzyskania danych.

### Komponent 3: Ochrona w czasie wykonania (Anti-Debugging i Anti-Tampering)

**Dralyxor** nie polega wyłącznie na zaciemnianiu. Stosuje zestaw aktywnych zabezpieczeń w czasie wykonania, zlokalizowanych głównie w `anti_debug.hpp` i zintegrowanych z metodami `Decrypt()` i `Encrypt()` `Obfuscated_String`.

#### Wieloplatformowe wykrywanie debuggerów

Funkcja `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (w `anti_debug.hpp`) sprawdza obecność debuggera przy użyciu technik specyficznych dla systemu operacyjnego:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` dla `ProcessDebugPort` (0x07) i `ProcessDebugFlags` (0x1F).
- **Linux:** Odczyt `/proc/self/status` i sprawdzanie wartości `TracerPid:`. Wartość inna niż 0 wskazuje, że proces jest śledzony.
- **macOS:** Użycie `sysctl` z `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` do uzyskania `kinfo_proc` i sprawdzenie flagi `P_TRACED` w `kp_proc.p_flag`.

Dodatkowo, wewnątrz `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Wykonuje pętlę prostych operacji obliczeniowych i mierzy czas. Znaczne spowolnienie (powyżej `timing_threshold_milliseconds = 75ms`) może wskazywać, że debugger wykonuje krokowo lub że aktywne są rozległe punkty przerwania. W tej pętli wywoływane jest `Is_Debugger_Present_Tracer_Pid_Sysctl()`, a funkcja "przynęta" `Detail::Canary_Function_For_Breakpoint_Check()` (która po prostu zwraca `0xCC`, kod instrukcji dla `int3` / programowego punktu przerwania) jest wywoływana, a jej wynik jest XORowany, co utrudnia optymalizację i zapewnia wspólne miejsce dla punktów przerwania.
- `Detail::Perform_Output_Debug_String_Trick()` (tylko Windows User Mode): Wykorzystuje zachowanie `OutputDebugStringA/W` i `GetLastError()`. Jeśli debugger jest dołączony, `GetLastError()` może zostać zmodyfikowane po wywołaniu `OutputDebugString`.

#### Wpływ na działanie w przypadku wykrycia lub naruszenia integralności

Jeśli którekolwiek ze sprawdzeń anty-debugowania zwróci `true` lub jeśli kanarki integralności `Obfuscated_String` (`_internal_integrity_canary1/2`) są uszkodzone, funkcja `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` zwróci `Detail::integrity_compromised_magic`.

Ta zwracana wartość jest kluczowa w funkcjach `Obfuscated_String::Decrypt()` i `Encrypt()`:
```cpp
// Uproszczona logika Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Kanarki Obfuscated_String
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
        // ... Ponownie sprawdź kanarki ...

        // JEŚLI runtime_key_mod NIE JEST integrity_compromised_magic, NIE JEST ON UŻYWANY DO ZMIANY KLUCZA DESZYFRACJI.
        // Klucz deszyfracji jest zawsze pochodną oryginalnego 'compile_time_seed'.
        // Rola runtime_key_mod tutaj polega na DZIAŁANIU JAKO SYGNALIZATOR wrogiego środowiska.
        // Jeśli jest wrogie, funkcja zwraca integrity_compromised_magic, a deszyfracja nie jest kontynuowana lub jest odwracana.
        
        // Transform_Compile_Time_Consistent jest wywoływana z compile_time_seed (a NIE z runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* tryb deszyfracji */);
        
        // ... Ponownie sprawdź sumę kontrolną i kanarki ...
        // Jeśli coś zawiedzie, Clear_Internal_Data() i zwraca integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Sukces
}
```

**Kluczowy Efekt:** Jeśli `Calculate_Runtime_Key_Modifier` wykryje problem (debugger lub uszkodzony kanarek) i zwróci `integrity_compromised_magic`, funkcje `Decrypt()` (i podobnie `Encrypt()`) przerywają operację, czyszczą wewnętrzne dane `Obfuscated_String` (w tym `storage_` i `micro_program_`) i zwracają `integrity_compromised_magic`. Uniemożliwia to poprawne odszyfrowanie (lub ponowne zaszyfrowanie) stringu w wrogim środowisku lub jeśli obiekt został zmanipulowany.
String nie jest odszyfrowywany "niepoprawnie" (na śmieci); operacja jest po prostu uniemożliwiana, a obiekt `Obfuscated_String` samo-niszczy się pod względem użytecznej zawartości.

#### Kanarki integralności obiektu

Obie klasy `Obfuscated_String` i `Secure_Accessor` zawierają elementy kanarkowe (pary `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (inicjalizowany `Detail::integrity_canary_value`) i `_internal_integrity_canary2` (inicjalizowany `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (inicjalizowany `Detail::accessor_integrity_canary_seed`) i `_accessor_integrity_canary2` (inicjalizowany `~Detail::accessor_integrity_canary_seed`).

Te kanarki są sprawdzane w krytycznych punktach:
- Początek i koniec `Obfuscated_String::Decrypt()` i `Encrypt()`.
- Konstruktor, destruktor i `Get()` `Secure_Accessor`.
- Przed i po sprawdzeniach anty-debugowania w `Calculate_Runtime_Key_Modifier`.

Jeśli te wartości kanarkowe zostaną zmienione (np. przez przepełnienie bufora, niedyskryminacyjne załatanie pamięci lub hak, który nadpisuje sąsiednią pamięć), weryfikacja (`Verify_Internal_Canaries()` lub `Verify_Internal_Accessor_Canaries()`) nie powiedzie się.
W przypadku niepowodzenia operacje są przerywane, odpowiednie dane wewnętrzne są czyszczone, a wartość błędu (`Detail::integrity_compromised_magic` lub `nullptr`) jest zwracana, sygnalizując manipulację.

#### Suma kontrolna zawartości stringu

- 16-bitowa suma kontrolna oryginalnego stringu *w czystym tekście* (z wyłączeniem terminatora null) jest obliczana przez `Detail::Calculate_String_Content_Checksum` w czasie kompilacji.
- Ta suma kontrolna jest następnie zaciemniana przy użyciu `Detail::Obfuscate_Deobfuscate_Short_Value` (z `compile_time_seed` i `content_checksum_obf_salt`) i przechowywana w `_content_checksum_obfuscated` w obiekcie `Obfuscated_String`.
- **Podczas Odszyfrowywania (`Decrypt()`):** Po transformacji `storage_` (przypuszczalnie do czystego tekstu), obliczana jest jego suma kontrolna. `_content_checksum_obfuscated` jest odszyfrowywany w celu uzyskania referencyjnej sumy kontrolnej. Jeśli obie sumy kontrolne się nie zgadzają, wskazuje to, że:
   - Odszyfrowanie nie przywróciło oryginalnego stringu (być może dlatego, że operacja została przerwana z powodu wykrycia debuggera przed pełną transformacją, lub doszło do uszkodzenia nasiona/mikroprogramu).
   - `storage_` (gdy zaciemniony) lub `_content_checksum_obfuscated` zostały zmanipulowane w pamięci.
- **Podczas Szyfrowania (`Encrypt()`):** Zanim `storage_` (który jest w tym momencie w czystym tekście) zostanie przekształcony z powrotem do swojej zaciemnionej formy, obliczana jest jego suma kontrolna i porównywana z referencyjną. Rozbieżność tutaj oznaczałaby, że string w czystym tekście został zmieniony *wewnątrz `storage_` `Obfuscated_String` podczas gdy był odszyfrowany*, co jest silnym wskaźnikiem manipulacji pamięcią lub niewłaściwego użycia (ponieważ dostęp do `storage_` nie powinien być bezpośredni).

W obu przypadkach niepowodzenia sumy kontrolnej wywoływane jest `Clear_Internal_Data()`, a `integrity_compromised_magic` jest zwracane.

### Komponent 4: Generowanie unikalnych i nieprzewidywalnych kluczy i nasion

Bezpieczeństwo każdego systemu szyfrowania opiera się na sile i unikalności jego kluczy i nasion. **Dralyxor** zapewnia, że każdy zaciemniony string wykorzystuje fundamentalnie unikalny zestaw parametrów szyfrowania.

#### Źródła entropii dla `compile_time_seed`

`static constexpr uint64_t Obfuscated_String::compile_time_seed` to nadrzędne nasiono dla wszystkich operacji pseudolosowych dotyczących tej instancji stringu. Jest generowane w `consteval` w następujący sposób:
```cpp
// Wewnątrz Obfuscated_String<CharT, storage_n, Instance_Counter>
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponent 1: Zmienność między kompilacjami
    ((uint64_t)Instance_Counter << 32) ^        // Komponent 2: Zmienność w obrębie jednostki kompilacji
    storage_n;                                  // Komponent 3: Zmienność oparta na rozmiarze stringu
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Makra `__DATE__` (np. "Jan 01 2025") i `__TIME__` (np. "12:30:00") to stringi dostarczane przez preprocesor, które zmieniają się za każdym razem, gdy plik jest kompilowany. Hash FNV-1a tych wartości tworzy bazę nasiona, która jest inna dla każdej kompilacji projektu.
- **`Instance_Counter` (zasilany przez `__COUNTER__` w makrze `DRALYXOR`/`DRALYXOR_LOCAL`)**: Makro `__COUNTER__` to licznik utrzymywany przez preprocesor, który zwiększa się za każdym razem, gdy jest używany w obrębie jednostki kompilacji. Przekazując go jako argument szablonu `int Instance_Counter` do `Obfuscated_String`, każde użycie makra `DRALYXOR` lub `DRALYXOR_LOCAL` spowoduje inny `Instance_Counter`, a zatem inny `compile_time_seed`, nawet dla identycznych literałów stringowych w tym samym pliku źródłowym.
- **`storage_n` (rozmiar stringu wliczając null)**: Rozmiar stringu jest również XORowany, dodając kolejny czynnik różnicujący.

Ten `compile_time_seed` jest następnie używany jako baza do:
1. Generowania `micro_program_` (zasiewając PRNG `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Wyprowadzania klucza zaciemniania dla samego `micro_program_` (poprzez `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Wyprowadzania klucza zaciemniania dla `_content_checksum_obfuscated` (poprzez `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Służenia jako `base_seed` dla `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Pochodne nasiona dla transformacji zawartości

Wewnątrz `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Inicjalizowany jest `Constexpr_PRNG prng_operand_modifier(base_seed)`. Dla każdego transformowanego znaku stringu `prng_operand_modifier.Key()` produkuje `prng_key_for_ops_in_elem`. Ten klucz jest XORowany z operandem mikroinstrukcji przed zastosowaniem, zapewniając, że efekt tej samej mikroinstrukcji jest subtelnie różny dla każdego znaku.
- Inicjalizowany jest `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)`. Dla każdego znaku `prng_applier_selector.Key()` jest używany do wyboru między `Applier_Style_Direct` a `Applier_Style_DoubleLayer`.

Wprowadza to dodatkowy dynamizm w transformacji każdego znaku, nawet jeśli podstawowy mikroprogram jest taki sam dla wszystkich znaków danego stringu.

#### Odporność na ataki typu "replay" i analizę wzorców

- **Unikalność Międzykompilacyjna:** Jeśli atakujący przeanalizuje binarny plik wersji 1.0 Twojego oprogramowania i, z dużym wysiłkiem, zdoła złamać zaciemnienie stringu, ta wiedza prawdopodobnie będzie bezużyteczna dla wersji 1.1, ponieważ `__DATE__ __TIME__` się zmieni, co spowoduje zupełnie inne `compile_time_seed` i mikroprogramy.
- **Unikalność Wewnątrzkompilacyjna:** Jeśli użyjesz `DRALYXOR("HasłoAdmina")` w dwóch różnych miejscach w swoim kodzie (lub w tym samym pliku .cpp), `__COUNTER__` zapewni, że wynikowe obiekty `Obfuscated_String`, a zatem ich zaciemnione reprezentacje w pliku binarnym (zarówno `storage_`, jak i `micro_program_`), będą różne. Uniemożliwia to atakującemu znalezienie zaciemnionego wzorca i użycie go do zlokalizowania wszystkich innych wystąpień tego samego oryginalnego stringu lub użycie odkrytego mikroprogramu do odszyfrowania innych stringów.

Ta solidna generacja nasion jest kamieniem węgielnym bezpieczeństwa **Dralyxor** przed atakami, które polegają na odkryciu "głównego sekretu" lub wykorzystaniu powtarzalności szyfrów i transformacji.

## Pełna dokumentacja publicznego API

### Makra zaciemniania

Są to główne punkty wejścia do tworzenia zaciemnionych stringów.

#### `DRALYXOR(str_literal)`

- **Cel:** Tworzy obiekt `Obfuscated_String` o statycznym czasie życia (istnieje przez cały okres działania programu). Idealny dla stałych globalnych lub stringów, które muszą być dostępne z wielu miejsc i trwać.
- **Przechowywanie:** Pamięć statyczna (zwykle w sekcji danych programu).
- **Implementacja (uproszczona):**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           /* Makro __COUNTER__ zapewnia unikalny Instance_Counter dla każdego użycia */ \
           /* decltype(*str_literal) wnioskuje typ znaku (char, wchar_t) */ \
           /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) oblicza rozmiar wliczając null */ \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
               typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
               (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
               __COUNTER__ \
           >(str_literal); \
           return obfuscated_static_string; \
       }()
   ```

- **Parametry:**
   - `str_literal`: Literał stringowy w stylu C (np. `"Witaj Świecie"`, `L"Ciąg Znaków Unicode"`).
- **Zwraca:** Referencję (`auto&`) do statycznego obiektu `Obfuscated_String`, utworzonego wewnątrz natychmiast wywoływanej lambdy.
- **Przykład:**
   ```cpp
   static auto& url_endpointu_api = DRALYXOR("https://service.example.com/api");
   // url_endpointu_api to referencja do statycznego Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Cel:** Tworzy obiekt `Obfuscated_String` o automatycznym czasie życia (zwykle na stosie, jeśli używany wewnątrz funkcji). Idealny dla tymczasowych sekretów ograniczonych do zakresu.
- **Przechowywanie:** Automatyczne (stos dla lokalnych zmiennych funkcji).
- **Implementacja (uproszczona):**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) \
       Dralyxor::Obfuscated_String< \
           typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
           (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
           __COUNTER__ \
       >(str_literal)
   ```
- **Parametry:**
   - `str_literal`: Literał stringowy w stylu C.
- **Zwraca:** Obiekt `Obfuscated_String` przez wartość (który może być zoptymalizowany przez RVO/NRVO przez kompilator).
- **Przykład:**
   ```cpp
   void przetwarzaj_dane() {
       auto klucz_tymczasowy = DRALYXOR_LOCAL("TymczasowyKluczPrzetwarzania123");
       // ... użyj klucz_tymczasowy z DRALYXOR_SECURE ...
   } // klucz_tymczasowy jest tutaj niszczony, jego destruktor wywołuje Clear_Internal_Data().
   ```

### Makro bezpiecznego dostępu

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Cel:** Zapewnia bezpieczny i tymczasowy dostęp do odszyfrowanej zawartości obiektu `Obfuscated_String`. Jest to **jedyna zalecana metoda** odczytu stringu.
- **Implementacja (uproszczona):**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) \
       Dralyxor::Secure_Accessor< \
           typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
       >(obfuscated_var)
   ```

- **Parametry:**
   - `obfuscated_var`: Zmienna (lvalue lub rvalue, które może być powiązane z niestałą referencją lvalue) typu `Dralyxor::Obfuscated_String<...>`. Zmienna musi być modyfikowalna, ponieważ konstruktor `Secure_Accessor` wywołuje na niej `Decrypt()` i `Encrypt()`.
- **Zwraca:** Obiekt `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` przez wartość.
- **Użycie:**
   ```cpp
   auto& moj_statyczny_sekret = DRALYXOR("Mój Największy Sekret");
   // ...
   {
       auto akcesor = DRALYXOR_SECURE(moj_statyczny_sekret);
       const char* wskaznik_sekretu = akcesor.Get(); // Lub po prostu: const char* wskaznik_sekretu = akcesor; (niejawna konwersja)
       
       if (wskaznik_sekretu) {
           // Użyj wskaznik_sekretu tutaj. Wskazuje na tymczasowo odszyfrowany string w buforze akcesora.
           // Np.: wyslij_dane(wskaznik_sekretu);
       }
       else {
           // Błąd deszyfracji lub integralności. Obsłuż błąd.
           // Akcesor mógł nie zainicjalizować się poprawnie (np. moj_statyczny_sekret został uszkodzony).
       }
   } // akcesor jest niszczony. Jego wewnętrzne bufory (fragmenty i zrekonstruowany string) są czyszczone.
    // moj_statyczny_sekret.storage_ został już ponownie zaciemniony przez konstruktor Secure_Accessor
    // natychmiast po skopiowaniu zawartości do fragmentów akcesora.
   ```

> [!WARNING]
> Zawsze sprawdzaj, czy wskaźnik zwrócony przez `DRALYXOR_SECURE(...).Get()` (lub przez niejawną konwersję) nie jest `nullptr` przed jego użyciem. Zwrócenie `nullptr` wskazuje na błąd deszyfracji (np. wykrycie debuggera, uszkodzenie kanarków/sum kontrolnych w nadrzędnym `Obfuscated_String` lub w samym `Secure_Accessor`). Użycie wskaźnika `nullptr` spowoduje niezdefiniowane zachowanie (prawdopodobnie błąd segmentacji).

## Zaawansowane funkcje i dobre praktyki

### Pełne wsparcie dla Unicode (Szerokie stringi - `wchar_t`)

**Dralyxor** jest agnostyczny wobec typu znaku dzięki użyciu szablonów (`CharT`). Natywnie obsługuje `char` (dla stringów ASCII/UTF-8) i `wchar_t` (dla stringów UTF-16 w Windows lub UTF-32 w innych systemach, w zależności od platformy i kompilatora). Wystarczy użyć prefiksu `L` dla literałów `wchar_t`:
```cpp
auto szeroka_wiadomosc = DRALYXOR_LOCAL(L"Wiadomość Unicode: Witaj Świecie Ω ❤️");
{
    auto akcesor = DRALYXOR_SECURE(szeroka_wiadomosc);

    if (akcesor.Get()) {
        // Przykład w Windows:
        // MessageBoxW(nullptr, akcesor.Get(), L"Tytuł Unicode", MB_OK);
        // Przykład z wcout:
        // #include <io.h> // Dla _setmode w Windows z MSVC
        // #include <fcntl.h> // Dla _O_U16TEXT w Windows z MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Konfiguruje stdout na UTF-16
        // std::wcout << L"Szeroka Wiadomość: " << akcesor.Get() << std::endl;
    }
}
```

Dla znaków 1-bajtowych (`sizeof(CharT) == 1`), silnik transformacji `Micro_Program_Cipher` stosuje mikroprogram bajt po bajcie. Dla znaków wielobajtowych (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` używa prostszego podejścia: cały wielobajtowy znak jest XORowany z maską pochodzącą z `prng_key_for_ops_in_elem` (replikowaną, aby wypełnić rozmiar `CharT`). Na przykład, jeśli `CharT` to `wchar_t` (2 bajty) i `prng_key_for_ops_in_elem` to `0xAB`, znak zostanie XORowany z `0xABAB`.
Gwarantuje to, że wszystkie bajty `wchar_t` są objęte zaciemnianiem, nawet jeśli nie przez pełny mikroprogram. Złożoność mikroprogramu nadal przyczynia się pośrednio poprzez wyprowadzanie kluczy PRNG.

### Inteligentne dostosowywanie się do standardów **C++** i środowisk (Kernel Mode)

Jak wspomniano, **Dralyxor** dostosowuje się:
- **Standardy C++:** Wymaga co najmniej **C++14**. Wykrywa i wykorzystuje funkcje **C++17** i **C++20** (takie jak `if constexpr`, `consteval`, sufiksy `_v` dla `type_traits`), gdy kompilator je obsługuje, uciekając się do alternatyw **C++14** w przeciwnym razie. Makra takie jak `_DRALYXOR_IF_CONSTEXPR` i `_DRALYXOR_CONSTEVAL` w `detection.hpp` zarządzają tą adaptacją.
- **Kernel Mode:** Gdy `_KERNEL_MODE` jest zdefiniowane (typowe w projektach WDK dla sterowników Windows), **Dralyxor** (poprzez `env_traits.hpp`) unika dołączania standardowych nagłówków STL, takich jak `<type_traits>`, które mogą nie być dostępne lub zachowywać się inaczej. Zamiast tego używa własnych implementacji `constexpr` podstawowych narzędzi, takich jak `Dralyxor::Detail::Fallback::decay` i `Dralyxor::Detail::Fallback::remove_reference`. Umożliwia to bezpieczne użycie **Dralyxor** do ochrony stringów w niskopoziomowych komponentach systemowych.
   - Podobnie `secure_memory.hpp` używa `RtlSecureZeroMemory` w Kernel Mode.
   - Sprawdzenia anty-debugowania trybu użytkownika (takie jak `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) są wyłączane (`#if !defined(_KERNEL_MODE)`) w Kernel Mode, ponieważ nie mają zastosowania lub mają inne odpowiedniki. Sprawdzenia czasowe mogą nadal mieć pewien efekt, ale główną linią obrony w Kernel Mode jest samo zaciemnianie.

### Uwagi dotyczące wydajności i narzutu

- **Czas Kompilacji:** Zaciemnianie, w tym generowanie i stosowanie mikroprogramów, odbywa się w całości w czasie kompilacji. W przypadku projektów z bardzo dużą liczbą zaciemnionych stringów czas kompilacji może wzrosnąć. Jest to jednorazowy koszt na kompilację.
- **Rozmiar Pliku Binarnego:** Każdy `Obfuscated_String` dodaje swój `storage_` (rozmiar stringu), `micro_program_` (stały na `max_micro_instructions * sizeof(Micro_Instruction)`), oraz kilka bajtów na kanarki, sumę kontrolną i flagi. Może wystąpić wzrost rozmiaru pliku binarnego w porównaniu do czystych literałów stringowych, szczególnie w przypadku wielu małych stringów.
- **Czas Wykonania (Runtime):**
   - **Tworzenie `Obfuscated_String` (obiekty statyczne lub lokalne):** Odbywa się w czasie kompilacji (dla statycznych) lub obejmuje kopiowanie wstępnie obliczonych danych (dla lokalnych, optymalizowalne przez RVO). Nie ma kosztu "generowania" w czasie wykonania.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Sprawdzanie kanarków (ekstremalnie szybkie).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Obejmuje sprawdzenia anty-debugowania. Sprawdzenie czasowe (`Perform_Timing_Check_Generic`) jest tutaj najbardziej kosztowne, wykonując pętlę. Pozostałe to wywołania API lub odczyty plików (Linux).
      - Odszyfrowanie mikroprogramu (kopiowanie i XOR, szybkie).
      - Transformacja stringu: Pętla po `N_data_elements_to_transform`, a w niej pętla po `num_actual_instructions_in_program_`. Dla każdej instrukcji wywołanie `Byte_Transform_Applier`, który wykonuje kilka operacji na bajtach. Koszt to O(długość\_stringu \* liczba\_instrukcji).
      - Obliczanie/Weryfikacja sumy kontrolnej (`Detail::Calculate_String_Content_Checksum`): O(długość\_stringu \* sizeof(CharT)).
   - **Tworzenie `Secure_Accessor`:**
      - Wywołuje `Obfuscated_String::Decrypt()`.
      - Kopiuje string do fragmentów: O(długość\_stringu).
      - Oblicza sumę kontrolną fragmentów (`Calculate_Current_Fragments_Checksum`): O(długość\_stringu).
      - Wywołuje `Obfuscated_String::Encrypt()`. Jest to punkt największej koncentracji narzutu w pojedynczej operacji dostępu.
   - **`Secure_Accessor::Get()`:**
      - Pierwsze wywołanie: Sprawdza kanarki, rekonstruuje string z fragmentów (O(długość\_stringu)), sprawdza sumę kontrolną fragmentów.
      - Kolejne wywołania (dla tego samego obiektu `Secure_Accessor`): Sprawdza kanarki (szybkie) i zwraca już obliczony wskaźnik (O(1)).
- **Ogólny Narzut:** Dla większości aplikacji, gdzie wrażliwe stringi nie są dostępne w pętlach o bardzo wysokiej częstotliwości, narzut w czasie wykonania jest zazwyczaj akceptowalny, szczególnie biorąc pod uwagę korzyści związane z bezpieczeństwem. Projekt `Secure_Accessor` (tworzony tylko w razie potrzeby i o ściśle ograniczonym zakresie przez RAII) jest fundamentalny do zarządzania tym kosztem. Przetestuj w swoim specyficznym środowisku, jeśli wydajność jest krytyczna.

### Integracja ze strategią bezpieczeństwa warstwowego

> [!IMPORTANT]
> **Dralyxor** jest potężnym narzędziem do **zaciemniania osadzonych stringów i obrony przed analizą pamięci**, a nie generycznym rozwiązaniem kryptograficznym do trwałego przechowywania danych na dysku lub bezpiecznej transmisji sieciowej.
>
> Powinien być używany jako **jedna z wielu warstw** w kompleksowej strategii bezpieczeństwa. Żadne pojedyncze narzędzie nie jest panaceum. Inne środki, które należy wziąć pod uwagę, to:
> - **Minimalizowanie Osadzonych Sekretów:** Zawsze, gdy to możliwe, unikaj osadzania sekretów o bardzo wysokiej krytyczności. Wykorzystaj alternatywy, takie jak:
>    - Bezpieczne konfiguracje dostarczane w czasie wykonania (zmienne środowiskowe, pliki konfiguracyjne z ograniczonymi uprawnieniami).
>    - Usługi zarządzania sekretami (magazyny) takie jak HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Solidna walidacja danych wejściowych we wszystkich interfejsach.
> - Zasada najmniejszych uprawnień dla procesów i użytkowników.
> - Bezpieczna komunikacja sieciowa (TLS/SSL z przypinaniem certyfikatów, jeśli dotyczy).
> - Bezpieczne hashowanie haseł użytkowników (Argon2, scrypt, bcrypt).
> - Ochrona pliku binarnego jako całości innymi technikami anty-rewersyjnymi/anty-manipulacyjnymi (packery, wirtualizatory kodu, weryfikacje integralności kodu), będąc świadomym kompromisów, jakie mogą one wprowadzić (fałszywe alarmy antywirusowe, złożoność).
> - Dobre praktyki bezpiecznego programowania (Secure SDLC).

**Dralyxor** koncentruje się na bardzo dobrym rozwiązaniu konkretnego i powszechnego problemu: ochrony osadzonych literałów stringowych przed analizą statyczną i minimalizacji ich ekspozycji w pamięci podczas wykonywania, utrudniając życie tym, którzy próbują przeprowadzić inżynierię wsteczną Twojego oprogramowania.

## Licencja

Ta biblioteka jest chroniona na mocy Licencji MIT, która zezwala na:

- ✔️ Użytek komercyjny i prywatny
- ✔️ Modyfikację kodu źródłowego
- ✔️ Dystrybucję kodu
- ✔️ Sublicencjonowanie

### Warunki:

- Zachowanie informacji o prawach autorskich
- Dołączenie kopii licencji MIT

Więcej szczegółów na temat licencji: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Wszelkie prawa zastrzeżone**