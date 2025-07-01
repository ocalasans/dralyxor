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
    - [Podstawowe wzorce użytkowania](#podstawowe-wzorce-użytkowania)
      - [Wzorzec 1: Lokalne zaciemnianie (stosu)](#wzorzec-1-lokalne-zaciemnianie-stosu)
      - [Wzorzec 2: Statyczne zaciemnianie (globalne)](#wzorzec-2-statyczne-zaciemnianie-globalne)
      - [Wzorzec 3: Zaciemnianie z kluczem dostarczonym przez użytkownika](#wzorzec-3-zaciemnianie-z-kluczem-dostarczonym-przez-użytkownika)
    - [Obsługa błędów i integralność](#obsługa-błędów-i-integralność)
  - [Szczegółowa filozofia projektowania i architektura](#szczegółowa-filozofia-projektowania-i-architektura)
    - [Trwałe zagrożenie: Podatność literałów stringowych](#trwałe-zagrożenie-podatność-literałów-stringowych)
    - [Wielowarstwowe rozwiązanie architektoniczne **Dralyxor**](#wielowarstwowe-rozwiązanie-architektoniczne-dralyxor)
  - [Głęboka analiza komponentów architektonicznych](#głęboka-analiza-komponentów-architektonicznych)
    - [Komponent 1: Silnik transformacji oparty na mikroprogramach](#komponent-1-silnik-transformacji-oparty-na-mikroprogramach)
      - [Moc `consteval` i `constexpr` do generowania w czasie kompilacji](#moc-consteval-i-constexpr-do-generowania-w-czasie-kompilacji)
      - [Anatomia mikroprogramu Dralyxor](#anatomia-mikroprogramu-dralyxor)
        - [Losowe generowanie instrukcji i wybór aplikatorów](#losowe-generowanie-instrukcji-i-wybór-aplikatorów)
        - [Zmienne i logiczne NOP-y dla entropii](#zmienne-i-logiczne-nop-y-dla-entropii)
      - [Zaciemnianie samego mikroprogramu](#zaciemnianie-samego-mikroprogramu)
      - [Cykl życia statycznego zaciemniania](#cykl-życia-statycznego-zaciemniania)
    - [Komponent 2: Bezpieczny dostęp i minimalizacja ekspozycji w pamięci RAM](#komponent-2-bezpieczny-dostęp-i-minimalizacja-ekspozycji-w-pamięci-ram)
      - [`Secure_Accessor` i zasada RAII](#secure_accessor-i-zasada-raii)
      - [Fragmentacja pamięci w `Secure_Accessor`](#fragmentacja-pamięci-w-secure_accessor)
      - [Bezpieczne czyszczenie pamięci](#bezpieczne-czyszczenie-pamięci)
    - [Komponent 3: Ochrona w czasie wykonania (Anti-Debugging i Anti-Tampering)](#komponent-3-ochrona-w-czasie-wykonania-anti-debugging-i-anti-tampering)
      - [Wieloplatformowe wykrywanie debuggerów](#wieloplatformowe-wykrywanie-debuggerów)
      - [Wpływ na działanie w przypadku wykrycia lub naruszenia integralności](#wpływ-na-działanie-w-przypadku-wykrycia-lub-naruszenia-integralności)
      - [Kanarki integralności obiektu](#kanarki-integralności-obiektu)
      - [Suma kontrolna zawartości ciągu znaków](#suma-kontrolna-zawartości-ciągu-znaków)
    - [Komponent 4: Generowanie unikalnych i nieprzewidywalnych kluczy i ziaren (seeds)](#komponent-4-generowanie-unikalnych-i-nieprzewidywalnych-kluczy-i-ziaren-seeds)
      - [Źródła entropii dla `compile_time_seed`](#źródła-entropii-dla-compile_time_seed)
      - [Pochodne ziarna dla transformacji zawartości](#pochodne-ziarna-dla-transformacji-zawartości)
      - [Odporność na ataki typu "replay" i analizę wzorców](#odporność-na-ataki-typu-replay-i-analizę-wzorców)
  - [Pełna dokumentacja publicznego API](#pełna-dokumentacja-publicznego-api)
    - [Makra zaciemniające](#makra-zaciemniające)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Makro bezpiecznego dostępu](#makro-bezpiecznego-dostępu)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Zaawansowane funkcje i dobre praktyki](#zaawansowane-funkcje-i-dobre-praktyki)
    - [Pełne wsparcie dla Unicode (szerokie ciągi znaków - `wchar_t`)](#pełne-wsparcie-dla-unicode-szerokie-ciągi-znaków---wchar_t)
    - [Inteligentna adaptacja do standardów C++ i środowisk (Kernel Mode)](#inteligentna-adaptacja-do-standardów-c-i-środowisk-kernel-mode)
    - [Uwagi dotyczące wydajności i narzutu](#uwagi-dotyczące-wydajności-i-narzutu)
    - [Integracja ze strategią bezpieczeństwa warstwowego](#integracja-ze-strategią-bezpieczeństwa-warstwowego)
  - [Licencja](#licencja)
    - [Warunki:](#warunki)

## Szybki przewodnik po integracji i użytkowaniu

### Instalacja

**Dralyxor** to biblioteka typu **header-only**. Nie jest wymagana żadna wstępna kompilacja ani linkowanie bibliotek (`.lib`/`.a`).

1. **Skopiuj katalog `Dralyxor`:** Pobierz najnowszą wersję biblioteki (sklonuj repozytorium lub pobierz plik zip) i skopiuj cały katalog `Dralyxor` (zawierający wszystkie pliki `.hpp`) do lokalizacji dostępnej dla Twojego projektu (np. do folderu `libs/`, `libraries/` lub `vendor/`).
2. **Dołącz główny nagłówek:** W swoim kodzie źródłowym dołącz główny plik nagłówkowy `dralyxor.hpp`:
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
        |-- integrity_constants.hpp (Stałe do sprawdzania integralności)
        |-- secure_memory.hpp       (Bezpieczne czyszczenie pamięci)
        |-- detection.hpp           (Makra do wykrywania standardu kompilatora/C++)
        `-- env_traits.hpp          (Adaptacje type_traits dla środowisk ograniczonych)
```

### Wymagania dotyczące kompilatora

> [!IMPORTANT]
> **Dralyxor** został zaprojektowany z naciskiem na nowoczesny **C++**, aby zapewnić maksymalne bezpieczeństwo i wydajność w czasie kompilacji.
>
> - **Minimalny standard C++: C++14**. Biblioteka wykorzystuje funkcje takie jak uogólniony `constexpr` i adaptuje się do `if constexpr` (gdy jest dostępny za pośrednictwem `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptacja do wyższych standardów:** Wykrywa i wykorzystuje optymalizacje lub składnię z **C++17** i **C++20** (takie jak `consteval`, sufiksy `_v` dla `type_traits`), jeśli projekt jest kompilowany z tymi standardami. `_DRALYXOR_CONSTEVAL` mapuje się na `consteval` w C++20 i `constexpr` w C++14/17, zapewniając wykonanie w czasie kompilacji tam, gdzie to możliwe.
> - **Wspierane kompilatory:** Testowane głównie na najnowszych wersjach MSVC, GCC i Clang.
> - **Środowisko wykonawcze:** W pełni kompatybilna z aplikacjami **User Mode** oraz środowiskami **Kernel Mode** (np. sterownikami Windows). W trybie Kernel Mode, gdzie STL może być niedostępny, **Dralyxor** używa wewnętrznych implementacji niezbędnych `type traits` (patrz `env_traits.hpp`).

### Podstawowe wzorce użytkowania

#### Wzorzec 1: Lokalne zaciemnianie (stosu)

Idealne dla tymczasowych ciągów znaków, ograniczonych do zakresu funkcji. Pamięć jest zarządzana i czyszczona automatycznie.

```cpp
#include "Dralyxor/dralyxor.hpp" // Dostosuj ścieżkę w razie potrzeby
#include <iostream>

void Configure_Logging() {
    // Klucz formatowania logów, używany tylko lokalnie.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Bezpieczny dostęp w ograniczonym zakresie
    {
        // Secure_Accessor tymczasowo usuwa zaciemnienie 'log_format_key' podczas swojej konstrukcji
        // (i natychmiast ponownie zaciemnia 'log_format_key' po skopiowaniu do swoich wewnętrznych buforów),
        // pozwala na dostęp i czyści własne bufory przy zniszczeniu.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Zawsze sprawdzaj, czy Get() nie zwraca nullptr
            std::cout << "Używany format logu: " << accessor.Get() << std::endl;
            // Np. logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Nie udało się odszyfrować log_format_key (możliwe manipulowanie lub wykrycie debuggera?)" << std::endl;
    } // accessor jest niszczony, jego wewnętrzne bufory są czyszczone. log_format_key pozostaje zaciemniony.
      // log_format_key zostanie zniszczony na końcu funkcji Configure_Logging.
}
```

#### Wzorzec 2: Statyczne zaciemnianie (globalne)

Dla stałych, które muszą istnieć przez cały okres życia programu i być dostępne globalnie.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Dla przykładu

// URL API licencji, trwały sekret.
// Makro DRALYXOR() tworzy obiekt statyczny.
// Funkcja Get_License_Server_URL() zwraca referencję do tego obiektu statycznego.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref jest referencją do statycznego Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Tworzy Secure_Accessor dla url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Łączenie z serwerem licencji pod adresem: " << accessor.Get() << std::endl;
            // Np. success = http_client.Check(accessor.Get(), user_key);
            success = true; // Symulacja sukcesu dla przykładu
        }
        else
            std::cerr << "Nie udało się odszyfrować URL serwera licencji (możliwe manipulowanie lub wykrycie debuggera?)." << std::endl;
    } // accessor jest niszczony, jego bufory są czyszczone. url_obj_ref (oryginalny Obfuscated_String) pozostaje zaciemniony.

    return success;
}
```

#### Wzorzec 3: Zaciemnianie z kluczem dostarczonym przez użytkownika

Dla maksymalnego poziomu bezpieczeństwa możesz podać własny tajny klucz. Sprawia to, że zaciemnianie zależy od sekretu znanego tylko Tobie, co czyni je odpornym.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// Klucz nigdy nie powinien znajdować się w kodzie produkcyjnym w postaci jawnej,
// idealnie powinien pochodzić ze skryptu budowania, zmiennej środowiskowej itp.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Zaciemnia URL używając tajnego klucza. Makro kończy się na _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Użycie z Secure_Accessor pozostaje bez zmian.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Obsługa błędów i integralność

Funkcje `Obfuscated_String::Decrypt()` i `Encrypt()` zwracają `uint64_t`:
- `0` oznacza sukces.
- `Dralyxor::Detail::integrity_compromised_magic` (stała wartość zdefiniowana w `integrity_constants.hpp`) wskazuje, że sprawdzenie integralności nie powiodło się. Może to być spowodowane uszkodzeniem kanarków obiektu, niespójną sumą kontrolną zawartości lub wykryciem debuggera, co sygnalizuje wrogie środowisko.

Podobnie `Secure_Accessor::Get()` (lub jego niejawna konwersja na `const CharT*`) zwróci `nullptr`, jeśli inicjalizacja `Secure_Accessor` nie powiedzie się (np. jeśli deszyfrowanie oryginalnego `Obfuscated_String` nie powiedzie się) lub jeśli integralność `Secure_Accessor` (jego własne kanarki lub wewnętrzne sumy kontrolne) zostanie naruszona w czasie jego życia.

**Kluczowe jest, aby Twój kod sprawdzał te wartości zwrotne, aby zapewnić solidność i bezpieczeństwo aplikacji.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Zazwyczaj NIE powinno się wywoływać Decrypt() i Encrypt() bezpośrednio,
    // ponieważ zarządza tym Secure_Accessor. Ale jeśli z jakiegoś powodu jest to konieczne:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "OSTRZEŻENIE: Nie udało się odszyfrować 'my_secret' lub naruszono integralność podczas Decrypt()!" << std::endl;
        // Podejmij odpowiednie działania: zakończ, zaloguj w bezpieczny sposób itp.
        // Obiekt my_secret.storage_ może być w stanie nieprawidłowym lub zawierać śmieci.
        return; // Unikaj używania my_secret, jeśli Decrypt() się nie powiedzie.
    }

    // Jeśli Decrypt() się powiódł, my_secret.storage_ zawiera odszyfrowane dane.
    // **BEZPOŚREDNI DOSTĘP DO storage_ JEST ZDECYDOWANIE ODRADZANY W KODZIE PRODUKCYJNYM.**
    // std::cout << "Dane w my_secret.storage_ (NIE RÓB TEGO): " << my_secret.storage_ << std::endl;

    // Jesteś odpowiedzialny za ponowne zaszyfrowanie, jeśli wywołałeś Decrypt() ręcznie:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "OSTRZEŻENIE: Nie udało się ponownie zaszyfrować 'my_secret' lub naruszono integralność podczas Encrypt()!" << std::endl;
        // Stan niepewny, potencjalnie niebezpieczny.
    }

    // ZALECANE UŻYCIE z Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Konstruktor Secure_Accessor wywołuje another_secret.Decrypt(), kopiuje, a następnie another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Lub: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Tajne dane przez Secure_Accessor: " << data_ptr << std::endl;
            // Użyj data_ptr tutaj
        }
        else {
            std::cerr << "OSTRZEŻENIE: Secure_Accessor nie udało się zainicjalizować lub uzyskać wskaźnika do 'another_secret'!" << std::endl;
            // Oznacza to, że Decrypt() wewnątrz konstruktora accessor-a nie powiódł się,
            // lub nastąpiła manipulacja accessor-a (kanarki, wewnętrzne sumy kontrolne).
        }
    } // accessor jest niszczony. Jego bufory są czyszczone. another_secret pozostaje zaciemniony.
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

### Komponent 1: Silnik transformacji oparty na mikroprogramach

Serce statycznego i dynamicznego zaciemniania w **Dralyxor** leży w jego silniku transformacji, który wykorzystuje unikalne "mikroprogramy" dla każdego ciągu znaków i kontekstu.

#### Moc `consteval` i `constexpr` do generowania w czasie kompilacji

Nowoczesny **C++**, z `consteval` (**C++20**) i `constexpr` (**C++11** i nowsze), pozwala na wykonywanie złożonego kodu *podczas kompilacji*. **Dralyxor** używa `_DRALYXOR_CONSTEVAL` (które mapuje się na `consteval` lub `constexpr` w zależności od standardu **C++**) dla konstruktora `Obfuscated_String` i generowania mikroprogramu.

Oznacza to, że cały proces:
1. Generowania pseudolosowej sekwencji instrukcji transformacji (mikroprogramu).
2. Zaciemniania samego mikroprogramu w celu przechowywania.
3. Zastosowania tego mikroprogramu (tymczasowo odciemnionego), aby przekształcić oryginalny ciąg znaków, co skutkuje jego zaciemnioną formą.
Wszystko to dzieje się w czasie kompilacji, zanim zostanie wygenerowany plik binarny.

#### Anatomia mikroprogramu Dralyxor

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
    END_OF_PROGRAM
};

struct Micro_Instruction {
    Micro_Operation_Code op_code{}; // Domyślny inicjalizator {} do zerowania
    uint8_t operand{};             // Domyślny inicjalizator {} do zerowania
};

// Maksymalna liczba instrukcji, które może zawierać mikroprogram.
static constexpr size_t max_micro_instructions = 8;
```
Funkcja `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` jest odpowiedzialna za wypełnienie tej tablicy.

##### Losowe generowanie instrukcji i wybór aplikatorów

- **Generowanie Instrukcji:** Używając `Dralyxor::Detail::Constexpr_PRNG` (z ziarnem będącym kombinacją `compile_time_seed` i `0xDEADBEEFC0FFEEULL`), funkcja `Generate_Micro_Program_Instructions` probabilistycznie wybiera sekwencję operacji:
   - `XOR`: Bitowy XOR z operandem.
   - `ADD`: Dodawanie modularne z operandem.
   - `SUB`: Odejmowanie modularne z operandem.
   - `ROTR`/`ROTL`: Rotacja bitów. Operand (po modulo) określa liczbę przesunięć (1 do 7).
   - `SWAP_NIB`: Zamienia 4 dolne bity z 4 górnymi bitami bajtu (operand jest ignorowany).
    Operandy dla tych instrukcji są również generowane pseudolosowo przez PRNG.

- **Modyfikacja operandów i wybór aplikatorów w czasie transformacji:** Podczas stosowania mikroprogramu (przez `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), zarówno przy początkowym zaciemnianiu, jak i przy odciemnianiu w czasie wykonania:
   - `Constexpr_PRNG prng_operand_modifier` (z ziarnem `base_seed`) generuje `prng_key_for_ops_in_elem` dla każdego znaku w ciągu. Operand mikroinstrukcji (`instr_orig.operand`) jest poddawany operacji XOR z tym kluczem przed użyciem. Gwarantuje to, że ten sam mikroprogram stosuje nieco inne transformacje dla każdego znaku.
   - `Constexpr_PRNG prng_applier_selector` (z ziarnem `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) wybiera `Byte_Transform_Applier` dla każdego znaku. Obecnie istnieją dwa style:
      - `Applier_Style_Direct`: Stosuje operację bezpośrednio (odwracając ją przy deszyfrowaniu, np. ADD staje się SUB).
      - `Applier_Style_DoubleLayer`: Stosuje operację dwukrotnie (lub operację i jej odwrotność, w zależności od trybu szyfrowania/deszyfrowania) z różnymi operandami, co sprawia, że odwrócenie jest nieco bardziej złożone do analizy.

##### Zmienne i logiczne NOP-y dla entropii

Aby zwiększyć trudność ręcznej analizy mikroprogramu, **Dralyxor** wstawia:
- **Jawne NOP-y:** Instrukcje `Micro_Operation_Code::NOP`, które nic nie robią.
- **Logiczne NOP-y:** Pary instrukcji, które wzajemnie się znoszą, jak `ADD K` po którym następuje `SUB K`, lub `ROTL N_BITS` po którym następuje `ROTR N_BITS`. Operand używany w parze jest ten sam.

Te NOP-y są wstawiane probabilistycznie przez `Generate_Micro_Program_Instructions`, wypełniając tablicę `micro_program_` i utrudniając odróżnienie skutecznych transformacji od operacji "szumu".

#### Zaciemnianie samego mikroprogramu

Po wygenerowaniu mikroprogramu i przed początkowym zaciemnieniem ciągu znaków w konstruktorze `consteval`, tablica `micro_program_` (zawarta w obiekcie `Obfuscated_String`) jest sama w sobie zaciemniana. Każdy `op_code` i `operand` w każdej `Micro_Instruction` jest poddawany operacji XOR z kluczem pochodzącym z `compile_time_seed` (używając `Detail::Get_Micro_Program_Obfuscation_Key` i `Detail::Obfuscate_Deobfuscate_Instruction`).
Oznacza to, że nawet jeśli atakujący zdoła zrzucić pamięć obiektu `Obfuscated_String`, mikroprogram nie będzie w swojej bezpośrednio czytelnej/stosowalnej formie.

Gdy wywoływane są `Obfuscated_String::Decrypt()` lub `Encrypt()` (lub pośrednio przez `Secure_Accessor`), centralna funkcja `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` otrzymuje ten *zaciemniony* mikroprogram. Następnie:
1. Tworzy tymczasową kopię mikroprogramu (`local_plain_program`) na stosie.
2. Usuwa zaciemnienie tej lokalnej kopii, używając tego samego klucza (`program_obf_key`) pochodzącego z przekazanego ziarna bazowego (którym ostatecznie jest `compile_time_seed`).
3. Używa tego `local_plain_program` do transformacji danych ciągu znaków.
Lokalna kopia na stosie jest niszczona na końcu funkcji, a `micro_program_` przechowywany w obiekcie `Obfuscated_String` pozostaje zaciemniony.

#### Cykl życia statycznego zaciemniania

1. **Kod źródłowy:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Przetwarzanie wstępne:** Makro rozszerza się na instancjację `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (Rozmiar 15 obejmuje terminator zerowy).
3. **Ewaluacja `_DRALYXOR_CONSTEVAL`:**
   - Kompilator wykonuje konstruktor `Obfuscated_String`.
   - `Initialize_Internal_Canaries()` ustawia kanarki integralności.
   - `Generate_Micro_Program_Instructions()` (z ziarnem `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) tworzy sekwencję `Micro_Instruction` i przechowuje ją w `this->micro_program_` (np. `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Rzeczywista liczba instrukcji jest przechowywana w `num_actual_instructions_in_program_`.
   - Oryginalny ciąg znaków "SECRET\_API\_KEY" jest kopiowany do `this->storage_`.
   - Suma kontrolna oryginalnego ciągu "SECRET\_API\_KEY" (z wyłączeniem zera) jest obliczana przez `Detail::Calculate_String_Content_Checksum`, a następnie zaciemniana przez `Detail::Obfuscate_Deobfuscate_Short_Value` (używając `compile_time_seed` i `content_checksum_obf_salt`) i przechowywana w `this->_content_checksum_obfuscated`.
   - Wywoływane jest `Obfuscate_Internal_Micro_Program()`: `this->micro_program_` jest zaciemniany na miejscu (każda instrukcja poddawana operacji XOR z `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - Wywoływane jest `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)`. Ta funkcja:
      - Tworzy odciemnioną kopię `this->micro_program_` na stosie.
      - Dla każdego znaku w `storage_` (z wyjątkiem zera):
         - Generuje `prng_key_for_ops_in_elem` i wybiera `Byte_Transform_Applier`.
         - Stosuje sekwencję mikroinstrukcji (z odciemnionej kopii) do znaku, używając aplikatora i zmodyfikowanego operanda.
      - Na końcu `storage_` zawiera zaciemniony ciąg znaków (np. `[CF, 3A, D1, ..., 0x00]`).
4. **Generowanie kodu:** Kompilator alokuje przestrzeń dla `api_key_obj` i inicjalizuje ją bezpośrednio z:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (zaciemniony ciąg znaków).
   - `micro_program_`: *już zaciemniony* mikroprogram.
   - `_content_checksum_obfuscated`: suma kontrolna oryginalnej zawartości, *zaciemniona*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Literał `"SECRET_API_KEY"` nie istnieje już w pliku binarnym.

### Komponent 2: Bezpieczny dostęp i minimalizacja ekspozycji w pamięci RAM

#### `Secure_Accessor` i zasada RAII

Ochrona w czasie kompilacji to tylko połowa sukcesu. Kiedy ciąg znaków musi być użyty, musi zostać odszyfrowany. Jeśli ten odszyfrowany ciąg pozostanie w pamięci **RAM** przez dłuższy czas, staje się celem dla analizy dynamicznej (zrzuty pamięci, debuggery).

**Dralyxor** radzi sobie z tym za pomocą `Dralyxor::Secure_Accessor`, klasy implementującej wzorzec **RAII** (Resource Acquisition Is Initialization):
- **Pozyskiwany Zasób:** Tymczasowy dostęp do jawnego tekstu ciągu, pofragmentowany i zarządzany przez akcesor.
- **Obiekt Zarządzający:** Instancja `Secure_Accessor`.

```cpp
// W secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Inicjalizuj różnymi wartościami, aby zawiodło, jeśli nie zostanie zaktualizowane
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

        // 2. Jeśli odszyfrowanie się powiedzie, kopiuje jawny tekst do wewnętrznych fragmentów.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ jest teraz tekstem jawnym
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val wynosi co najwyżej 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Wypełnia resztę bufora fragmentu zerami

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

                // Zapewnia zakończenie zerem, nawet jeśli N_storage jest dokładnie wypełniony.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Dla N_storage == 0 (pusty ciąg znaków, teoretycznie), nie ma sum kontrolnych
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Aby przejść sprawdzenie

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // jeśli N_storage było 0, jest to bezpieczne, jeśli bufor jest > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Sprawdza ponownie po każdej wewnętrznej operacji, aby zapewnić integralność.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Przepływ użycia z `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - Wywoływany jest konstruktor `Secure_Accessor`.
   - Wywołuje `my_obfuscated_string.Decrypt()`. Obejmuje to odciemnienie `micro_program_` (do lokalnej kopii), użycie go do odszyfrowania `my_obfuscated_string.storage_`, a następnie sprawdzenie kanarków i sumy kontrolnej odszyfrowanej zawartości z oczekiwaną.
   - Jeśli się powiedzie, zawartość `my_obfuscated_string.storage_` (teraz jawny tekst) jest kopiowana i dzielona na wewnętrzne `fragments_storage_` w `Secure_Accessor`.
   - Obliczana jest suma kontrolna `fragments_storage_` (`fragments_data_checksum_expected_`).
   - Co kluczowe, `my_obfuscated_string.Encrypt()` jest wywoływane *natychmiast po tym*, ponownie zaciemniając `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (lub `const char* ptr = accessor;` z powodu niejawnej konwersji)
   - Wywoływana jest funkcja `Secure_Accessor::Get()`.
   - Sprawdza własne kanarki integralności oraz kanarki nadrzędnego `Obfuscated_String`.
   - Jeśli jest to pierwszy dostęp (`current_access_ptr_` to `nullptr`), rekonstruuje pełny ciąg znaków w `reconstructed_plain_buffer_` z `fragments_storage_`.
   - Następnie sprawdza `fragments_data_checksum_reconstructed_` z `fragments_data_checksum_expected_`, aby upewnić się, że fragmenty nie zostały naruszone podczas istnienia `Secure_Accessor`.
   - Jeśli wszystko się zgadza, zwraca wskaźnik do `reconstructed_plain_buffer_`.
3. Kończy się zakres `accessor` (wyjście z funkcji, koniec bloku `{}`, itp.).
   - Automatycznie wywoływany jest destruktor `Secure_Accessor`.
   - Wywoływane jest `Clear_All_Internal_Buffers()`, które bezpiecznie czyści (`Secure_Clear_Memory`) zarówno `reconstructed_plain_buffer_`, jak i `fragments_storage_`.

W rezultacie jawny tekst istnieje w pełnej formie tylko wewnątrz `Secure_Accessor` (w `reconstructed_plain_buffer_`) i dopiero po pierwszym wywołaniu `Get()`, przez najkrótszy możliwy czas. Ciąg znaków w oryginalnym obiekcie `Obfuscated_String` jest ponownie zaciemniany, gdy tylko `Secure_Accessor` skopiuje jego zawartość podczas konstrukcji.

#### Fragmentacja pamięci w `Secure_Accessor`

Aby jeszcze bardziej utrudnić zlokalizowanie pełnego jawnego tekstu w pamięci, `Secure_Accessor` podczas swojej konstrukcji nie tylko kopiuje odszyfrowany ciąg znaków, ale go dzieli:
1. Ciąg znaków z nadrzędnego `Obfuscated_String` jest odszyfrowywany.
2. Jego zawartość jest dzielona na maksymalnie `fragment_count_val` (obecnie 4, jeśli ciąg jest wystarczająco duży) części, które są kopiowane do `fragments_storage_[i]`.
3. Ciąg znaków w nadrzędnym obiekcie `Obfuscated_String` jest ponownie zaciemniany.

Dopiero po pierwszym wywołaniu `Secure_Accessor::Get()` te fragmenty są ponownie składane w `reconstructed_plain_buffer_`. Ta technika ma na celu "rozproszenie" wrażliwych danych, udaremniając skanowanie pamięci w poszukiwaniu ciągłych ciągów znaków.

#### Bezpieczne czyszczenie pamięci

Zarówno destruktor `Obfuscated_String` (poprzez `Clear_Internal_Data`), jak i destruktor `Secure_Accessor` (poprzez `Clear_All_Internal_Buffers`) używają `Dralyxor::Detail::Secure_Clear_Memory`. Ta funkcja opakowująca zapewnia, że bufory zawierające wrażliwe dane są zerowane w sposób niezawodny, zapobiegając optymalizacji kompilatora:
- **Na Windows:** Używa `SecureZeroMemory` (User Mode) lub `RtlSecureZeroMemory` (Kernel Mode), które są funkcjami systemu operacyjnego zaprojektowanymi specjalnie tak, aby nie być optymalizowanymi i bezpiecznie zerować pamięć.
- **Na innych platformach (Linux, macOS itp.):** Implementacja używa teraz `memset` do wypełnienia bloku pamięci zerami. `memset` działa na poziomie bajtów, co czyni go idealnym i bezpiecznym do zerowania zarówno typów pierwotnych (takich jak `char`, `int`), jak i typów złożonych (takich jak `struct`), unikając problemów ze zgodnością typów lub operatorami przypisania. Aby upewnić się, że wywołanie `memset` nie zostanie zoptymalizowane i usunięte przez kompilator, wskaźnik bufora jest najpierw przekazywany do wskaźnika `volatile`.

Takie podejście zapewnia, że gdy obiekty są niszczone, wrażliwa zawartość jest nadpisywana, co zmniejsza ryzyko odzyskania danych poprzez analizę zrzutów pamięci.

### Komponent 3: Ochrona w czasie wykonania (Anti-Debugging i Anti-Tampering)

**Dralyxor** nie polega tylko na zaciemnianiu. Stosuje zestaw aktywnych zabezpieczeń w czasie wykonania, zlokalizowanych głównie w `anti_debug.hpp` i zintegrowanych z metodami `Decrypt()` i `Encrypt()` `Obfuscated_String`.

#### Wieloplatformowe wykrywanie debuggerów

Funkcja `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (w `anti_debug.hpp`) sprawdza obecność debuggera, używając technik specyficznych dla systemu operacyjnego:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` dla `ProcessDebugPort` (0x07) i `ProcessDebugFlags` (0x1F).
- **Linux:** Odczyt `/proc/self/status` i sprawdzenie wartości `TracerPid:`. Wartość inna niż 0 wskazuje, że proces jest śledzony.
- **macOS:** Użycie `sysctl` z `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` w celu uzyskania `kinfo_proc` i sprawdzenia flagi `P_TRACED` w `kp_proc.p_flag`.

Dodatkowo, wewnątrz `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Wykonuje pętlę prostych operacji obliczeniowych i mierzy czas. Znaczące spowolnienie (powyżej `timing_threshold_milliseconds = 75ms`) może wskazywać, że debugger jest w trybie single-stepping lub aktywne są liczne punkty przerwania. Wewnątrz tej pętli wywoływane jest `Is_Debugger_Present_Tracer_Pid_Sysctl()`, a funkcja "przynęta" `Detail::Canary_Function_For_Breakpoint_Check()` (która po prostu zwraca `0xCC`, kod instrukcji `int3` / programowego punktu przerwania) jest wywoływana, a jej wynik jest poddawany operacji XOR, co utrudnia optymalizację i stanowi popularne miejsce dla punktów przerwania.
- `Detail::Perform_Output_Debug_String_Trick()` (tylko Windows User Mode): Wykorzystuje zachowanie `OutputDebugStringA/W` i `GetLastError()`. Jeśli debugger jest dołączony, `GetLastError()` może zostać zmodyfikowane po wywołaniu `OutputDebugString`.

#### Wpływ na działanie w przypadku wykrycia lub naruszenia integralności

Jeśli którekolwiek ze sprawdzeń anty-debuggingowych zwróci `true`, lub jeśli kanarki integralności `Obfuscated_String` (`_internal_integrity_canary1/2`) są uszkodzone, funkcja `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` zwróci `Detail::integrity_compromised_magic`.

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

        // JEŚLI runtime_key_mod NIE JEST integrity_compromised_magic, NIE JEST UŻYWANY DO ZMIANY KLUCZA DESZYFRUJĄCEGO.
        // Klucz deszyfrujący jest zawsze pochodną oryginalnego 'compile_time_seed'.
        // Rola runtime_key_mod tutaj to DZIAŁANIE JAKO FLAGI wrogiego środowiska.
        // Jeśli jest wrogie, funkcja zwraca integrity_compromised_magic, a deszyfrowanie nie jest kontynuowane lub jest cofane.
        
        // Transform_Compile_Time_Consistent jest wywoływane z compile_time_seed (a NIE z runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* tryb deszyfrowania */);
        
        // ... Ponownie sprawdź sumę kontrolną i kanarki ...
        // Jeśli coś zawiedzie, Clear_Internal_Data() i zwraca integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Sukces
}
```

**Kluczowy Efekt:** Jeśli `Calculate_Runtime_Key_Modifier` wykryje problem (debugger lub uszkodzony kanarek) i zwróci `integrity_compromised_magic`, funkcje `Decrypt()` (i podobnie `Encrypt()`) przerywają operację, czyszczą wewnętrzne dane `Obfuscated_String` (w tym `storage_` i `micro_program_`) i zwracają `integrity_compromised_magic`. Uniemożliwia to prawidłowe odszyfrowanie (lub ponowne zaszyfrowanie) ciągu znaków w wrogim środowisku lub jeśli obiekt został naruszony.
Ciąg znaków nie jest odszyfrowywany "nieprawidłowo" (na śmieci); operacja jest po prostu blokowana, a obiekt `Obfuscated_String` samo-niszczy się pod względem użytecznej zawartości.

#### Kanarki integralności obiektu

Obie klasy `Obfuscated_String` i `Secure_Accessor` zawierają elementy kanarkowe (pary `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (inicjalizowany `Detail::integrity_canary_value`) i `_internal_integrity_canary2` (inicjalizowany `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (inicjalizowany `Detail::accessor_integrity_canary_seed`) i `_accessor_integrity_canary2` (inicjalizowany `~Detail::accessor_integrity_canary_seed`).

Te kanarki są sprawdzane w krytycznych punktach:
- Początek i koniec `Obfuscated_String::Decrypt()` i `Encrypt()`.
- Konstruktor, destruktor i `Get()` `Secure_Accessor`.
- Przed i po sprawdzeniach anty-debug w `Calculate_Runtime_Key_Modifier`.

Jeśli te wartości kanarkowe zostaną zmienione (np. przez przepełnienie bufora, niedyskryminacyjną modyfikację pamięci lub hook, który nadpisuje sąsiednią pamięć), sprawdzenie (`Verify_Internal_Canaries()` lub `Verify_Internal_Accessor_Canaries()`) nie powiedzie się.
W przypadku niepowodzenia operacje są przerywane, odpowiednie dane wewnętrzne są czyszczone, a zwracana jest wartość błędu (`Detail::integrity_compromised_magic` lub `nullptr`), sygnalizując naruszenie.

#### Suma kontrolna zawartości ciągu znaków

- 16-bitowa suma kontrolna oryginalnego *jawnego tekstu* ciągu znaków (z wyłączeniem terminatora zerowego) jest obliczana przez `Detail::Calculate_String_Content_Checksum` w czasie kompilacji.
- Ta suma kontrolna jest następnie zaciemniana przy użyciu `Detail::Obfuscate_Deobfuscate_Short_Value` (z `compile_time_seed` i `content_checksum_obf_salt`) i przechowywana w `_content_checksum_obfuscated` w obiekcie `Obfuscated_String`.
- **Podczas deszyfrowania (`Decrypt()`):** Po przekształceniu `storage_` (prawdopodobnie do jawnego tekstu), obliczana jest jego suma kontrolna. `_content_checksum_obfuscated` jest odciemniany w celu uzyskania referencyjnej sumy kontrolnej. Jeśli te dwie sumy kontrolne się nie zgadzają, wskazuje to, że:
   - Deszyfrowanie nie przywróciło oryginalnego ciągu (być może operacja została przerwana z powodu wykrycia debuggera przed pełną transformacją, lub doszło do uszkodzenia ziarna/mikroprogramu).
   - `storage_` (gdy zaciemniony) lub `_content_checksum_obfuscated` zostały naruszone w pamięci.
- **Podczas szyfrowania (`Encrypt()`):** Zanim `storage_` (który w tym momencie jest w postaci jawnego tekstu) zostanie przekształcony z powrotem do swojej zaciemnionej formy, jego suma kontrolna jest obliczana i porównywana z referencyjną. Różnica tutaj oznaczałaby, że jawny tekst został zmieniony *wewnątrz `storage_` obiektu `Obfuscated_String` w czasie, gdy był odszyfrowany*, co jest silnym wskaźnikiem naruszenia pamięci lub niewłaściwego użycia (ponieważ dostęp do `storage_` nie powinien odbywać się bezpośrednio).

W obu przypadkach niepowodzenia sumy kontrolnej wywoływane jest `Clear_Internal_Data()` i zwracane jest `integrity_compromised_magic`.

### Komponent 4: Generowanie unikalnych i nieprzewidywalnych kluczy i ziaren (seeds)

Bezpieczeństwo każdego systemu szyfrującego opiera się na sile i unikalności jego kluczy i ziaren. **Dralyxor** zapewnia, że każdy zaciemniony ciąg znaków używa fundamentalnie unikalnego zestawu parametrów szyfrowania.

#### Źródła entropii dla `compile_time_seed`

`static constexpr uint64_t Obfuscated_String::compile_time_seed` jest głównym ziarnem dla wszystkich operacji pseudolosowych odnoszących się do tej instancji ciągu znaków. Jego generowanie jest teraz warunkowe, oparte na obecności klucza dostarczonego przez użytkownika:

- **Jeśli klucz jest dostarczany przez użytkownika (używając `DRALYXOR_KEY` lub `DRALYXOR_KEY_LOCAL`):**
   1. Dostarczony `key_literal` jest przekształcany w 64-bitowy hash w czasie kompilacji przy użyciu algorytmu FNV-1a.
   2. Ten hash staje się podstawą `compile_time_seed`, połączony z `__COUNTER__` (aby zapewnić unikalność między różnymi użyciami tego samego klucza) i rozmiarem ciągu.
      ```cpp
      // Uproszczona logika
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      W tym trybie bezpieczeństwo zaciemniania zależy bezpośrednio od siły i tajności dostarczonego klucza.

- **Jeśli nie podano klucza (używając `DRALYXOR` lub `DRALYXOR_LOCAL`):**
   - `compile_time_seed` jest generowany przy użyciu kombinacji następujących czynników w celu maksymalizacji entropii i zmienności:
      ```cpp
      // Wewnątrz Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Komponent 1: Zmienność między kompilacjami
          ((uint64_t)Instance_Counter << 32) ^        // Komponent 2: Zmienność wewnątrz jednej jednostki kompilacji
          storage_n;                                  // Komponent 3: Zmienność oparta na rozmiarze ciągu
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Makra `__DATE__` (np. "Jan 01 2025") i `__TIME__` (np. "12:30:00") to ciągi znaków dostarczane przez preprocesor, które zmieniają się za każdym razem, gdy plik jest kompilowany. Hash FNV-1a tych wartości tworzy bazowe ziarno, które jest inne dla każdego buildu projektu.
   - **`Instance_Counter` (zasilany przez `__COUNTER__` w makrze)**: Makro `__COUNTER__` to licznik utrzymywany przez preprocesor, który inkrementuje się za każdym razem, gdy jest używany w jednej jednostce kompilacji. Przekazując to jako argument szablonu, każde użycie makra `DRALYXOR` lub `DRALYXOR_LOCAL` spowoduje inny `Instance_Counter`, a zatem inny `compile_time_seed`, nawet dla identycznych literałów ciągów znaków w tym samym pliku źródłowym.
   - **`storage_n` (rozmiar ciągu)**: Rozmiar ciągu jest również poddawany operacji XOR, dodając kolejny czynnik różnicujący.

Ten `compile_time_seed` (czy to pochodzący z klucza użytkownika, czy wygenerowany automatycznie) jest następnie używany jako podstawa do:
1. Generowania `micro_program_` (zasilając PRNG ziarnem `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Wyprowadzania klucza zaciemniającego dla samego `micro_program_` (przez `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Wyprowadzania klucza zaciemniającego dla `_content_checksum_obfuscated` (przez `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Służenia jako `base_seed` dla `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Pochodne ziarna dla transformacji zawartości

Wewnątrz `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Inicjalizowany jest `Constexpr_PRNG prng_operand_modifier(base_seed)`. Dla każdego przekształcanego znaku ciągu, `prng_operand_modifier.Key()` produkuje `prng_key_for_ops_in_elem`. Ten klucz jest poddawany operacji XOR z operandem mikroinstrukcji przed zastosowaniem, zapewniając, że efekt tej samej mikroinstrukcji jest subtelnie różny dla każdego znaku.
- Inicjalizowany jest `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)`. Dla każdego znaku, `prng_applier_selector.Key()` jest używany do wyboru między `Applier_Style_Direct` a `Applier_Style_DoubleLayer`.

Wprowadza to dodatkowy dynamizm w transformacji każdego znaku, nawet jeśli podstawowy mikroprogram jest taki sam dla wszystkich znaków danego ciągu.

#### Odporność na ataki typu "replay" i analizę wzorców

- **Unikalność między-kompilacyjna:** Jeśli atakujący przeanalizuje binarny plik wersji 1.0 Twojego oprogramowania i z dużym wysiłkiem zdoła złamać zaciemnienie ciągu znaków (w trybie klucza automatycznego), ta wiedza będzie prawdopodobnie bezużyteczna dla wersji 1.1, ponieważ `__DATE__ __TIME__` się zmieni, co spowoduje całkowicie inne `compile_time_seed` i mikroprogramy.
- **Unikalność wewnątrz-kompilacyjna:** Jeśli użyjesz `DRALYXOR("AdminPassword")` w dwóch różnych miejscach w kodzie (lub w tym samym pliku .cpp), `__COUNTER__` zapewni, że wynikowe obiekty `Obfuscated_String`, a zatem ich zaciemnione reprezentacje w pliku binarnym, będą różne. Uniemożliwia to atakującemu znalezienie jednego zaciemnionego wzorca i użycie go do zlokalizowania wszystkich innych wystąpień tego samego oryginalnego ciągu.

Ta solidna generacja ziaren jest kamieniem węgielnym bezpieczeństwa **Dralyxor** przeciwko atakom, które polegają na odkryciu "głównego sekretu" lub wykorzystaniu powtarzalności szyfrów i transformacji.

## Pełna dokumentacja publicznego API

### Makra zaciemniające

To są główne punkty wejścia do tworzenia zaciemnionych ciągów znaków.

#### `DRALYXOR(str_literal)`

- **Cel:** Tworzy obiekt `Obfuscated_String` o statycznym czasie życia (istnieje przez cały czas działania programu). Idealny do globalnych stałych lub ciągów, które muszą być dostępne z wielu miejsc i muszą istnieć przez cały czas.
- **Przechowywanie:** Pamięć statyczna (zazwyczaj w sekcji danych programu).
- **Implementacja:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parametry:**
   - `str_literal`: Literał ciągu znaków w stylu C (np. `"Hello World"`, `L"Unicode String"`).
- **Zwraca:** Referencję (`auto&`) do statycznego obiektu `Obfuscated_String`, utworzonego wewnątrz natychmiast wywoływanej lambdy.
- **Przykład:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url jest referencją do statycznego Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Cel:** Tworzy obiekt `Obfuscated_String` o automatycznym czasie życia (zazwyczaj na stosie, jeśli używany w funkcji). Idealny do tymczasowych sekretów ograniczonych do jednego zakresu.
- **Przechowywanie:** Automatyczne (stos dla lokalnych zmiennych funkcji).
- **Implementacja:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Parametry:**
   - `str_literal`: Literał ciągu znaków w stylu C.
- **Zwraca:** Obiekt `Obfuscated_String` przez wartość (który może być optymalizowany przez RVO/NRVO przez kompilator).
- **Przykład:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... użyj temp_key z DRALYXOR_SECURE ...
   } // temp_key jest niszczony tutaj, jego destruktor wywołuje Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Cel:** Podobny do `DRALYXOR`, tworzy statyczny obiekt `Obfuscated_String`, ale używa **klucza dostarczonego przez użytkownika** (`key_literal`) do zasilenia zaciemniania, oferując najwyższy poziom bezpieczeństwa.
- **Przechowywanie:** Pamięć statyczna (zazwyczaj w sekcji danych programu).
- **Implementacja:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parametry:**
   - `str_literal`: Literał ciągu do zaciemnienia.
   - `key_literal`: Literał ciągu do użycia jako tajny klucz.
- **Zwraca:** Referencję (`auto&`) do statycznego obiektu `Obfuscated_String`.
- **Przykład:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Cel:** Podobny do `DRALYXOR_LOCAL`, tworzy obiekt `Obfuscated_String` na stosie, używając **klucza dostarczonego przez użytkownika**.
- **Przechowywanie:** Automatyczne (stos dla lokalnych zmiennych funkcji).
- **Implementacja:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parametry:**
   - `str_literal`: Literał ciągu do zaciemnienia.
   - `key_literal`: Literał ciągu do użycia jako klucz.
- **Zwraca:** Obiekt `Obfuscated_String` przez wartość.
- **Przykład:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Makro bezpiecznego dostępu

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Cel:** Zapewnia bezpieczny i tymczasowy dostęp do odszyfrowanej zawartości obiektu `Obfuscated_String`. Jest to **jedyna zalecana metoda** do odczytu ciągu znaków.
- **Implementacja:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parametry:**
   - `obfuscated_var`: Zmienna (lvalue lub rvalue, które może być powiązane z nie-stałą referencją lvalue) typu `Dralyxor::Obfuscated_String<...>`. Zmienna musi być modyfikowalna, ponieważ konstruktor `Secure_Accessor` wywołuje na niej `Decrypt()` i `Encrypt()`.
- **Zwraca:** Obiekt `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` przez wartość.
- **Użycie:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Lub po prostu: const char* secret_ptr = accessor; (niejawna konwersja)
       
       if (secret_ptr) {
           // Użyj secret_ptr tutaj. Wskazuje na tymczasowo odszyfrowany ciąg znaków w buforze akcesora.
           // Np. send_data(secret_ptr);
       }
       else {
           // Niepowodzenie deszyfracji lub naruszenie integralności. Obsłuż błąd.
           // Akcesor mógł nie zainicjować się poprawnie (np. my_static_secret został uszkodzony).
       }
   } // accessor jest niszczony. Jego wewnętrzne bufory (fragmenty i zrekonstruowany ciąg) są czyszczone.
    // my_static_secret.storage_ został już ponownie zaciemniony przez konstruktor Secure_Accessor
    // zaraz po skopiowaniu zawartości do fragmentów akcesora.
   ```

> [!WARNING]
> Zawsze sprawdzaj, czy wskaźnik zwrócony przez `DRALYXOR_SECURE(...).Get()` (lub przez niejawną konwersję) nie jest `nullptr` przed jego użyciem. Zwrócenie `nullptr` wskazuje na niepowodzenie deszyfracji (np. wykrycie debuggera, uszkodzenie kanarków/sum kontrolnych w nadrzędnym `Obfuscated_String` lub w samym `Secure_Accessor`). Użycie wskaźnika `nullptr` spowoduje niezdefiniowane zachowanie (prawdopodobnie błąd segmentacji).

## Zaawansowane funkcje i dobre praktyki

### Pełne wsparcie dla Unicode (szerokie ciągi znaków - `wchar_t`)

**Dralyxor** jest agnostyczny co do typu znaków dzięki użyciu szablonów (`CharT`). Obsługuje natywnie `char` (dla ciągów ASCII/UTF-8) oraz `wchar_t` (dla ciągów UTF-16 w systemie Windows lub UTF-32 w innych systemach, w zależności od platformy i kompilatora). Wystarczy użyć prefiksu `L` dla literałów `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Komunikat Unicode: Witaj Świecie Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Przykład w systemie Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Tytuł Unicode", MB_OK);
        // Przykład z wcout:
        // #include <io.h> // Dla _setmode w Windows z MSVC
        // #include <fcntl.h> // Dla _O_U16TEXT w Windows z MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Konfiguruje stdout na UTF-16
        // std::wcout << L"Wiadomość szerokoznakowa: " << accessor.Get() << std::endl;
    }
}
```

Dla znaków jednobajtowych (`sizeof(CharT) == 1`), silnik transformacji `Micro_Program_Cipher` stosuje mikroprogram bajt po bajcie. Dla znaków wielobajtowych (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` stosuje prostsze podejście: cały znak wielobajtowy jest poddawany operacji XOR z maską pochodzącą z `prng_key_for_ops_in_elem` (replikowaną, aby wypełnić rozmiar `CharT`). Na przykład, jeśli `CharT` to `wchar_t` (2 bajty), a `prng_key_for_ops_in_elem` to `0xAB`, znak zostanie poddany operacji XOR z `0xABAB`.
Zapewnia to, że wszystkie bajty `wchar_t` są objęte zaciemnieniem, nawet jeśli nie jest to pełny mikroprogram. Złożoność mikroprogramu nadal przyczynia się pośrednio poprzez wyprowadzanie kluczy z PRNG.

### Inteligentna adaptacja do standardów C++ i środowisk (Kernel Mode)

Jak wspomniano, **Dralyxor** dostosowuje się:
- **Standardy C++:** Wymaga co najmniej **C++14**. Wykrywa i wykorzystuje funkcje z **C++17** i **C++20** (takie jak `if constexpr`, `consteval`, sufiksy `_v` dla `type_traits`), gdy kompilator je obsługuje, w przeciwnym razie korzysta z alternatyw **C++14**. Makra takie jak `_DRALYXOR_IF_CONSTEXPR` i `_DRALYXOR_CONSTEVAL` w `detection.hpp` zarządzają tą adaptacją.
- **Kernel Mode:** Gdy zdefiniowane jest `_KERNEL_MODE` (typowe w projektach WDK dla sterowników Windows), **Dralyxor** (poprzez `env_traits.hpp`) unika dołączania standardowych nagłówków STL, takich jak `<type_traits>`, które mogą być niedostępne lub zachowywać się inaczej. Zamiast tego używa własnych implementacji `constexpr` podstawowych narzędzi, takich jak `Dralyxor::Detail::Fallback::decay` i `Dralyxor::Detail::Fallback::remove_reference`. Umożliwia to bezpieczne użycie **Dralyxor** do ochrony ciągów znaków w niskopoziomowych komponentach systemu.
   - Podobnie, `secure_memory.hpp` używa `RtlSecureZeroMemory` w trybie Kernel Mode. Na innych platformach, takich jak Linux, stosuje bezpieczne użycie `memset`, aby zapewnić czyszczenie pamięci, dostosowując się do zgodności z różnymi typami danych.
   - Sprawdzenia anty-debug z User Mode (takie jak `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) są wyłączone (`#if !defined(_KERNEL_MODE)`) w trybie Kernel Mode, ponieważ nie mają zastosowania lub mają inne odpowiedniki. Sprawdzanie czasu nadal może mieć pewien efekt, ale główną linią obrony w trybie Kernel Mode jest samo zaciemnienie.

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