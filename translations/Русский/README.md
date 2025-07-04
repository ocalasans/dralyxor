# Dralyxor

**Dralyxor** — это современная, `header-only`, высокопроизводительная и многоуровневая библиотека **C++**, предназначенная для обфускации строк во время компиляции и надежной защиты во время выполнения. Её основная миссия — защитить внутренние секреты вашего приложения — такие как ключи API, пароли, внутренние URL, отладочные сообщения и любые другие чувствительные строковые литералы — от раскрытия через статический анализ, реверс-инжиниринг и динамическую инспекцию памяти. Шифруя и преобразуя строки в момент компиляции и безопасно управляя их доступом во время выполнения, **Dralyxor** гарантирует, что ни один критический строковый литерал не будет существовать в виде простого текста в вашем конечном бинарном файле или оставаться незащищенным в памяти дольше, чем это строго необходимо.

Построенная на основах современного **C++** (требуя **C++14** и интеллектуально адаптируясь к возможностям **C++17** и **C++20**), её продвинутая архитектура включает в себя сложный механизм преобразования на основе "микропрограмм", обфускацию самой программы преобразования, механизмы целостности данных, защиту от отладки и **Безопасный Областной Акцессор (RAII)** для "just-in-time" дешифрования и автоматической повторной обфускации. Это значительно минимизирует время нахождения данных в **RAM** в открытом виде и обеспечивает профессиональный уровень глубокой защиты.

## Языки

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Содержание

- [Dralyxor](#dralyxor)
  - [Языки](#языки)
  - [Содержание](#содержание)
  - [Руководство по быстрой интеграции и использованию](#руководство-по-быстрой-интеграции-и-использованию)
    - [Установка](#установка)
    - [Требования к компилятору](#требования-к-компилятору)
    - [Основные шаблоны использования](#основные-шаблоны-использования)
      - [Шаблон 1: Локальная обфускация (стек)](#шаблон-1-локальная-обфускация-стек)
      - [Шаблон 2: Статическая обфускация (глобальная)](#шаблон-2-статическая-обфускация-глобальная)
      - [Шаблон 3: Обфускация с ключом, предоставленным пользователем](#шаблон-3-обфускация-с-ключом-предоставленным-пользователем)
    - [Обработка ошибок и целостность](#обработка-ошибок-и-целостность)
  - [Подробная философия и архитектура дизайна](#подробная-философия-и-архитектура-дизайна)
    - [Постоянная угроза: уязвимость строковых литералов](#постоянная-угроза-уязвимость-строковых-литералов)
    - [Многоуровневое архитектурное решение **Dralyxor**](#многоуровневое-архитектурное-решение-dralyxor)
  - [Глубокий анализ архитектурных компонентов](#глубокий-анализ-архитектурных-компонентов)
    - [Компонент 1: Движок преобразования на основе микропрограмм](#компонент-1-движок-преобразования-на-основе-микропрограмм)
      - [Мощь `consteval` и `constexpr` для генерации на этапе компиляции](#мощь-consteval-и-constexpr-для-генерации-на-этапе-компиляции)
      - [Анатомия микропрограммы **Dralyxor**](#анатомия-микропрограммы-dralyxor)
        - [Рандомизированная генерация инструкций и выбор аппликаторов](#рандомизированная-генерация-инструкций-и-выбор-аппликаторов)
        - [Переменные и логические NOP для энтропии](#переменные-и-логические-nop-для-энтропии)
      - [Обфускация самой микропрограммы](#обфускация-самой-микропрограммы)
      - [Жизненный цикл статической обфускации](#жизненный-цикл-статической-обфускации)
    - [Компонент 2: Безопасный доступ и минимизация раскрытия в **RAM**](#компонент-2-безопасный-доступ-и-минимизация-раскрытия-в-ram)
      - [`Secure_Accessor` и принцип RAII](#secure_accessor-и-принцип-raii)
      - [Фрагментация памяти в `Secure_Accessor`](#фрагментация-памяти-в-secure_accessor)
      - [Безопасная очистка памяти](#безопасная-очистка-памяти)
    - [Компонент 3: Защита во время выполнения (Anti-Debugging и Anti-Tampering)](#компонент-3-защита-во-время-выполнения-anti-debugging-и-anti-tampering)
      - [Кроссплатформенное обнаружение отладчиков](#кроссплатформенное-обнаружение-отладчиков)
      - [Влияние на работу в случае обнаружения или нарушения целостности](#влияние-на-работу-в-случае-обнаружения-или-нарушения-целостности)
      - [Канарейки целостности объекта](#канарейки-целостности-объекта)
      - [Контрольная сумма содержимого строки](#контрольная-сумма-содержимого-строки)
    - [Компонент 4: Генерация уникальных и непредсказуемых ключей и семян](#компонент-4-генерация-уникальных-и-непредсказуемых-ключей-и-семян)
      - [Источники энтропии для `compile_time_seed`](#источники-энтропии-для-compile_time_seed)
      - [Производные семена для преобразований содержимого](#производные-семена-для-преобразований-содержимого)
      - [Иммунитет к атакам «повторного воспроизведения» (Replay) и анализу шаблонов](#иммунитет-к-атакам-повторного-воспроизведения-replay-и-анализу-шаблонов)
  - [Полное руководство по публичному API](#полное-руководство-по-публичному-api)
    - [Макросы обфускации](#макросы-обфускации)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Макрос безопасного доступа](#макрос-безопасного-доступа)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Расширенные возможности и лучшие практики](#расширенные-возможности-и-лучшие-практики)
    - [Полная поддержка Unicode (широкие строки - `wchar_t`)](#полная-поддержка-unicode-широкие-строки---wchar_t)
    - [Интеллектуальная адаптация к стандартам **C++** и средам (Kernel Mode)](#интеллектуальная-адаптация-к-стандартам-c-и-средам-kernel-mode)
    - [Соображения по производительности и накладным расходам](#соображения-по-производительности-и-накладным-расходам)
    - [Интеграция в многоуровневую стратегию безопасности](#интеграция-в-многоуровневую-стратегию-безопасности)
  - [Лицензия](#лицензия)
    - [Условия:](#условия)

## Руководство по быстрой интеграции и использованию

### Установка

**Dralyxor** — это **header-only** библиотека. Предварительная компиляция или связывание с библиотеками (`.lib`/`.a`) не требуется.

1. **Скопируйте каталог `Dralyxor`:** Получите последнюю версию библиотеки (клонируйте репозиторий или скачайте zip-архив) и скопируйте весь каталог `Dralyxor` (содержащий все файлы `.hpp`) в место, доступное для вашего проекта (например, в папку `libs/`, `libraries/` или `vendor/`).
2. **Подключите основной заголовочный файл:** В вашем исходном коде подключите основной заголовочный файл `dralyxor.hpp`:
   ```cpp
   #include "путь/к/Dralyxor/dralyxor.hpp"
   ```

Типичная структура проекта:
```
/МойПроект/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor здесь
        |-- dralyxor.hpp            (Основная точка входа)
        |-- obfuscated_string.hpp   (Класс Obfuscated_String)
        |-- secure_accessor.hpp     (Класс Secure_Accessor)
        |-- algorithms.hpp          (Движок преобразований и микропрограммы)
        |-- anti_debug.hpp          (Обнаружения во время выполнения)
        |-- prng.hpp                (Генератор псевдослучайных чисел на этапе компиляции)
        |-- integrity_constants.hpp (Константы для проверок целостности)
        |-- secure_memory.hpp       (Безопасная очистка памяти)
        |-- detection.hpp           (Макросы для определения компилятора/стандарта C++)
        `-- env_traits.hpp          (Адаптации type_traits для ограниченных сред)
```

### Требования к компилятору

> [!IMPORTANT]
> **Dralyxor** был разработан с акцентом на современный **C++** для максимальной безопасности и эффективности на этапе компиляции.
>
> - **Минимальный стандарт C++: C++14**. Библиотека использует такие возможности, как обобщенный `constexpr`, и адаптируется для `if constexpr` (когда доступно через `_DRALYXOR_IF_CONSTEXPR`).
> - **Адаптация к более высоким стандартам:** Обнаруживает и использует оптимизации или синтаксис **C++17** и **C++20** (такие как `consteval`, суффиксы `_v` для `type_traits`), если проект компилируется с этими стандартами. `_DRALYXOR_CONSTEVAL` отображается в `consteval` в C++20 и `constexpr` в C++14/17, обеспечивая выполнение на этапе компиляции, где это возможно.
> - **Поддерживаемые компиляторы:** В основном протестировано с последними версиями MSVC, GCC и Clang.
> - **Среда выполнения:** Полностью совместима с приложениями в **User Mode** и средами **Kernel Mode** (например, драйверами Windows). В Kernel Mode, где STL может быть недоступна, **Dralyxor** использует внутренние реализации для необходимых `type traits` (см. `env_traits.hpp`).

### Основные шаблоны использования

#### Шаблон 1: Локальная обфускация (стек)

Идеально подходит для временных строк, ограниченных областью видимости функции. Память управляется и очищается автоматически.

```cpp
#include "Dralyxor/dralyxor.hpp" // При необходимости скорректируйте путь
#include <iostream>

void Configure_Logging() {
    // Ключ форматирования лога, используется только локально.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Безопасный доступ в ограниченной области видимости
    {
        // Secure_Accessor временно деобфусцирует 'log_format_key' во время своей конструкции
        // (и повторно обфусцирует 'log_format_key' сразу после копирования в свои внутренние буферы),
        // разрешает доступ и очищает собственные буферы при уничтожении.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Всегда проверяйте, что Get() не возвращает nullptr
            std::cout << "Используется формат лога: " << accessor.Get() << std::endl;
            // Пример: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Не удалось расшифровать log_format_key (возможно, tampering или обнаружение отладчика?)" << std::endl;
    } // accessor уничтожается, его внутренние буферы очищаются. log_format_key остается обфусцированным.
      // log_format_key будет уничтожен в конце функции Configure_Logging.
}
```

#### Шаблон 2: Статическая обфускация (глобальная)

Для констант, которые должны сохраняться в течение всего времени жизни программы и быть доступными глобально.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // для примера

// URL API лицензирования, постоянный секрет.
// Макрос DRALYXOR() создает статический объект.
// Функция Get_License_Server_URL() возвращает ссылку на этот статический объект.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref - это ссылка на статический Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Создает Secure_Accessor для url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Обращение к серверу лицензий по адресу: " << accessor.Get() << std::endl;
            // Пример: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Имитация успеха для примера
        }
        else
            std::cerr << "Не удалось расшифровать URL сервера лицензий (возможно, tampering или обнаружение отладчика?)." << std::endl;
    } // accessor уничтожается, его буферы очищаются. url_obj_ref (исходный Obfuscated_String) остается обфусцированным.

    return success;
}
```

#### Шаблон 3: Обфускация с ключом, предоставленным пользователем

Для максимального уровня безопасности вы можете предоставить свою собственную секретную ключевую строку. Это делает обфускацию зависимой от секрета, известного только вам, что повышает её устойчивость.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// Ключ никогда не должен находиться в открытом виде в производственном коде,
// в идеале он должен поступать из сборочного скрипта, переменной окружения и т. д.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Обфусцирует URL с использованием секретного ключа. Макрос заканчивается на _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Использование с Secure_Accessor остается таким же.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Обработка ошибок и целостность

Функции `Obfuscated_String::Decrypt()` и `Encrypt()` возвращают `uint64_t`:
- `0` указывает на успех.
- `Dralyxor::Detail::integrity_compromised_magic` (постоянное значение, определенное в `integrity_constants.hpp`) указывает, что проверка целостности не удалась. Это может быть связано с повреждением канареек объекта, несоответствием контрольной суммы содержимого или обнаружением отладчика, что свидетельствует о враждебной среде.

Аналогично, `Secure_Accessor::Get()` (или его неявное преобразование в `const CharT*`) вернет `nullptr`, если инициализация `Secure_Accessor` не удалась (например, если не удалась расшифровка исходного `Obfuscated_String`) или если целостность `Secure_Accessor` (его собственных канареек или внутренних контрольных сумм) была нарушена в течение его времени жизни.

**Крайне важно, чтобы ваш код проверял эти возвращаемые значения для обеспечения надежности и безопасности приложения.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Обычно вы НЕ должны вызывать Decrypt() и Encrypt() напрямую,
    // так как этим управляет Secure_Accessor. Но если по какой-то причине это необходимо:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "ВНИМАНИЕ: Не удалось расшифровать 'my_secret' или целостность была нарушена во время Decrypt()!" << std::endl;
        // Предпримите соответствующие действия: завершить программу, безопасно записать в лог и т. д.
        // Объект my_secret.storage_ может находиться в недопустимом состоянии или содержать мусор.
        return; // Избегайте использования my_secret, если Decrypt() не удался.
    }

    // Если Decrypt() прошел успешно, my_secret.storage_ содержит расшифрованные данные.
    // **ПРЯМОЙ ДОСТУП К storage_ КАТЕГОРИЧЕСКИ НЕ РЕКОМЕНДУЕТСЯ В ПРОИЗВОДСТВЕННОМ КОДЕ.**
    // std::cout << "Данные в my_secret.storage_ (НЕ ДЕЛАЙТЕ ЭТОГО): " << my_secret.storage_ << std::endl;

    // Вы несете ответственность за повторное шифрование, если вызвали Decrypt() вручную:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "ВНИМАНИЕ: Не удалось повторно зашифровать 'my_secret' или целостность была нарушена во время Encrypt()!" << std::endl;
        // Неопределенное, потенциально опасное состояние.
    }

    // РЕКОМЕНДУЕМОЕ ИСПОЛЬЗОВАНИЕ с Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Конструктор Secure_Accessor вызывает another_secret.Decrypt(), копирует, а затем another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Или: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Секретные данные через Secure_Accessor: " << data_ptr << std::endl;
            // Используйте data_ptr здесь
        }
        else {
            std::cerr << "ВНИМАНИЕ: Secure_Accessor не удалось инициализировать или получить указатель на 'another_secret'!" << std::endl;
            // Это указывает на то, что Decrypt() внутри конструктора accessor не удался,
            // или произошел tampering с accessor (канарейки, внутренние контрольные суммы).
        }
    } // accessor уничтожается. Его буферы очищаются. another_secret остается обфусцированным.
}
```

## Подробная философия и архитектура дизайна

**Dralyxor** — это не просто XOR-шифр; это система глубокой защиты для строковых литералов. Её архитектура основана на предположении, что эффективная безопасность требует множества взаимосвязанных уровней и устойчивости к различным техникам анализа.

### Постоянная угроза: уязвимость строковых литералов

Строковые литералы, такие как `"api.example.com/data?key="`, когда встроены непосредственно в код, записываются в читаемом виде (plain text) в скомпилированный бинарный файл. Инструменты, такие как `strings`, дизассемблеры (IDA Pro, Ghidra) и шестнадцатеричные редакторы, могут тривиально извлечь их. Это раскрытие облегчает:
- **Реверс-инжиниринг:** Понимание внутренней логики и потока программы.
- **Идентификация конечных точек:** Обнаружение серверов и бэкэнд API.
- **Извлечение секретов:** Ключи API, встроенные пароли, частные URL, SQL-запросы и т.д.
- **Анализ динамической памяти:** Даже если программа расшифровывает строку для использования, если она слишком долго остается в открытом виде в **RAM**, злоумышленник с доступом к памяти процесса (через отладчик или дамп памяти) может её найти.

**Dralyxor** атакует эти уязвимости как во время компиляции (для бинарного файла на диске), так и во время выполнения (для памяти **RAM**).

### Многоуровневое архитектурное решение **Dralyxor**

Надежность **Dralyxor** исходит из синергии его ключевых компонентов:

| Архитектурный компонент                     | Основная цель                                                                         | Ключевые применяемые технологии/техники                                                                                                                              |
| :------------------------------------------ | :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Движок преобразования на основе микропрограмм** | Устранить строки в открытом тексте из бинарного файла; создать сложную, динамическую и нетривиальную обфускацию.   | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, множественные операции (XOR, ADD, ROT и т.д.), переменные и логические NOPs, различные стили аппликаторов.         |
| **Безопасный доступ и минимизация раскрытия** | Значительно сократить время, в течение которого секрет находится в расшифрованном виде в RAM.             | Шаблон RAII (`Secure_Accessor`), фрагментация памяти, безопасная очистка буферов (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Защиты во время выполнения**              | Обнаруживать и реагировать на враждебные среды анализа и подделку памяти.            | Обнаружение отладчиков (специфичные для ОС API, тайминг, OutputDebugString), канарейки целостности объекта, контрольная сумма содержимого строки.                              |
| **Генерация уникальных ключей и сидов**    | Гарантировать, что каждая обфусцированная строка и каждый экземпляр использования криптографически различны. | `__DATE__`, `__TIME__`, `__COUNTER__`, размер строки, хеширование FNV-1a для `compile_time_seed`, производные сиды для модификаторов операндов и селекторов. |

## Глубокий анализ архитектурных компонентов

### Компонент 1: Движок преобразования на основе микропрограмм

Сердце статической и динамической обфускации **Dralyxor** заключается в его движке преобразований, который использует уникальные «микропрограммы» для каждой строки и контекста.

#### Мощь `consteval` и `constexpr` для генерации на этапе компиляции

Современный **C++** с `consteval` (**C++20**) и `constexpr` (начиная с **C++11**) позволяет выполнять сложный код *во время компиляции*. **Dralyxor** использует `_DRALYXOR_CONSTEVAL` (который сопоставляется с `consteval` или `constexpr` в зависимости от стандарта **C++**) для конструктора `Obfuscated_String` и для генерации микропрограммы.

Это означает, что весь процесс:
1. Генерация псевдослучайной последовательности инструкций преобразования (микропрограмма).
2. Обфускация самой микропрограммы для хранения.
3. Применение этой микропрограммы (временно деобфусцированной) для преобразования исходной строки, что приводит к ее обфусцированной форме.
Все это происходит во время компиляции, до того как будет сгенерирован бинарный файл.

#### Анатомия микропрограммы **Dralyxor**

Каждый объект `Obfuscated_String` хранит небольшой массив `Dralyxor::Detail::Micro_Instruction`. `Micro_Instruction` — это простая структура, определенная в `algorithms.hpp`:
```cpp
// В Dralyxor::Detail (algorithms.hpp)
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
    Micro_Operation_Code op_code{}; // Инициализатор по умолчанию {} для обнуления
    uint8_t operand{};             // Инициализатор по умолчанию {} для обнуления
};

// Максимальное количество инструкций, которое может содержать микропрограмма.
static constexpr size_t max_micro_instructions = 8;
```
Функция `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` отвечает за заполнение этого массива.

##### Рандомизированная генерация инструкций и выбор аппликаторов

- **Генерация инструкций:** Используя `Dralyxor::Detail::Constexpr_PRNG` (с семенем, являющимся комбинацией `compile_time_seed` и `0xDEADBEEFC0FFEEULL`), функция `Generate_Micro_Program_Instructions` вероятностно выбирает последовательность операций:
   - `XOR`: Побитовое XOR с операндом.
   - `ADD`: Модульное сложение с операндом.
   - `SUB`: Модульное вычитание с операндом.
   - `ROTR`/`ROTL`: Побитовый циклический сдвиг. Операнд (после взятия по модулю) определяет количество сдвигов (от 1 до 7).
   - `SWAP_NIB`: Меняет местами младшие 4 бита со старшими 4 битами байта (операнд игнорируется).
    Операнды для этих инструкций также генерируются псевдослучайно с помощью PRNG.

- **Модификация операндов и выбор аппликаторов во время преобразования:** Во время применения микропрограммы (через `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), как при начальной обфускации, так и при деобфускации во время выполнения:
   - `Constexpr_PRNG prng_operand_modifier` (с семенем `base_seed`) генерирует `prng_key_for_ops_in_elem` для каждого символа строки. Операнд микроинструкции (`instr_orig.operand`) подвергается операции XOR с этим ключом перед использованием. Это гарантирует, что одна и та же микропрограмма применяет немного разные преобразования к каждому символу.
   - `Constexpr_PRNG prng_applier_selector` (с семенем `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) выбирает `Byte_Transform_Applier` для каждого символа. В настоящее время существует два стиля:
      - `Applier_Style_Direct`: Применяет операцию напрямую (обращая её для расшифровки, например, ADD становится SUB).
      - `Applier_Style_DoubleLayer`: Применяет операцию дважды (или операцию и ее обратную, в зависимости от режима шифрования/расшифровки) с разными операндами, что делает обратное преобразование немного более сложным для анализа.

##### Переменные и логические NOP для энтропии

Чтобы усложнить ручной анализ микропрограммы, **Dralyxor** вставляет:
- **Явные NOP:** Инструкции `Micro_Operation_Code::NOP`, которые ничего не делают.
- **Логические NOP:** Пары инструкций, которые взаимно аннулируют друг друга, например, `ADD K` с последующим `SUB K`, или `ROTL N_BITS` с последующим `ROTR N_BITS`. Операнд, используемый в паре, одинаков.

Эти NOP вставляются вероятностным образом функцией `Generate_Micro_Program_Instructions`, заполняя массив `micro_program_` и затрудняя различение эффективных преобразований от "шумовых" операций.

#### Обфускация самой микропрограммы

После генерации микропрограммы и перед начальной обфускацией строки в конструкторе `consteval`, сам массив `micro_program_` (содержащийся в объекте `Obfuscated_String`) обфусцируется. Каждый `op_code` и `operand` в каждой `Micro_Instruction` подвергается операции XOR с ключом, полученным из `compile_time_seed` (с использованием `Detail::Get_Micro_Program_Obfuscation_Key` и `Detail::Obfuscate_Deobfuscate_Instruction`).
Это означает, что даже если злоумышленник сможет сделать дамп памяти объекта `Obfuscated_String`, микропрограмма не будет в своей прямо читаемой/применимой форме.

Когда вызываются `Obfuscated_String::Decrypt()` или `Encrypt()` (или косвенно через `Secure_Accessor`), центральная функция `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` получает эту *обфусцированную* микропрограмму. Затем она:
1. Создает временную копию микропрограммы (`local_plain_program`) на стеке.
2. Деобфусцирует эту локальную копию, используя тот же ключ (`program_obf_key`), полученный из переданного базового семени (которое, в конечном счете, является `compile_time_seed`).
3. Использует этот `local_plain_program` для преобразования данных строки.
Локальная копия на стеке уничтожается по завершении функции, а `micro_program_`, хранящийся в объекте `Obfuscated_String`, остается обфусцированным.

#### Жизненный цикл статической обфускации

1. **Исходный код:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Препроцессинг:** Макрос раскрывается в инстанцирование `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (Размер 15 включает нулевой терминатор).
3. **Оценка `_DRALYXOR_CONSTEVAL`:**
   - Компилятор выполняет конструктор `Obfuscated_String`.
   - `Initialize_Internal_Canaries()` устанавливает канарейки целостности.
   - `Generate_Micro_Program_Instructions()` (с семенем `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) создает последовательность `Micro_Instruction` и сохраняет ее в `this->micro_program_` (например, `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Фактическое количество инструкций сохраняется в `num_actual_instructions_in_program_`.
   - Исходная строка "SECRET\_API\_KEY" копируется в `this->storage_`.
   - Контрольная сумма исходной строки "SECRET\_API\_KEY" (исключая нулевой терминатор) вычисляется `Detail::Calculate_String_Content_Checksum`, затем обфусцируется `Detail::Obfuscate_Deobfuscate_Short_Value` (с использованием `compile_time_seed` и `content_checksum_obf_salt`) и сохраняется в `this->_content_checksum_obfuscated`.
   - Вызывается `Obfuscate_Internal_Micro_Program()`: `this->micro_program_` обфусцируется на месте (каждая инструкция подвергается XOR с `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - Вызывается `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)`. Эта функция:
      - Создает деобфусцированную копию `this->micro_program_` на стеке.
      - Для каждого символа в `storage_` (кроме нулевого):
         - Генерирует `prng_key_for_ops_in_elem` и выбирает `Byte_Transform_Applier`.
         - Применяет последовательность микроинструкций (из деобфусцированной копии) к символу, используя аппликатор и модифицированный операнд.
      - В итоге `storage_` содержит обфусцированную строку (например, `[CF, 3A, D1, ..., 0x00]`).
4. **Генерация кода:** Компилятор выделяет место для `api_key_obj` и инициализирует его напрямую:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (обфусцированная строка).
   - `micro_program_`: *уже обфусцированная* микропрограмма.
   - `_content_checksum_obfuscated`: Контрольная сумма исходного содержимого, *обфусцированная*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    Литерал «SECRET_API_KEY» больше не существует в бинарном файле.

### Компонент 2: Безопасный доступ и минимизация раскрытия в **RAM**

#### `Secure_Accessor` и принцип RAII

Защита на этапе компиляции — это лишь половина дела. Как только строку нужно использовать, её необходимо расшифровать. Если эта расшифрованная строка остается в **RAM** на длительное время, она становится целью для динамического анализа (дампы памяти, отладчики).

**Dralyxor** решает эту проблему с помощью `Dralyxor::Secure_Accessor`, класса, который реализует шаблон **RAII** (Resource Acquisition Is Initialization):
- **Приобретаемый ресурс:** Временный доступ к строке в виде plain text, фрагментированной и управляемой accessor.
- **Управляющий объект:** Экземпляр `Secure_Accessor`.

```cpp
// В secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Инициализируем разными, чтобы проверка не прошла, если не будет обновлено
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Делает accessor недействительным

            return;
        }

        // 1. Пытается расшифровать исходный Obfuscated_String.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Если расшифровка прошла успешно, копирует строку plaintext во внутренние фрагменты.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ теперь в виде plaintext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val не более 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Заполняет оставшуюся часть буфера фрагмента нулями
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Контрольная сумма фрагментов
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. НЕМЕДЛЕННО повторно шифрует исходный Obfuscated_String.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Очищает фрагменты и восстановленный буфер.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Проверяет себя и родителя
            Clear_All_Internal_Buffers(); // Мера безопасности
            _accessor_integrity_canary1 = 0; // Делает недействительным для будущих доступов

            return nullptr;
        }

        if (!current_access_ptr_) { // Если это первый вызов Get() или если буфер был очищен
            if constexpr (N_storage > 0) { // Восстанавливает, только если есть что восстанавливать
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

                // Гарантирует нулевое завершение, даже если N_storage полностью заполнено.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Для N_storage == 0 (теоретически, пустая строка), контрольных сумм нет
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Чтобы пройти проверку

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // если N_storage было 0, это безопасно, если буфер > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Повторно проверяет после любой внутренней операции для обеспечения целостности.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Порядок использования с `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - Вызывается конструктор `Secure_Accessor`.
   - Он вызывает `my_obfuscated_string.Decrypt()`. Это включает деобфускацию `micro_program_` (в локальную копию), использование его для расшифровки `my_obfuscated_string.storage_`, а затем проверку канареек и контрольной суммы расшифрованного содержимого с ожидаемым значением.
   - В случае успеха, содержимое `my_obfuscated_string.storage_` (теперь plain text) копируется и разделяется на внутренние `fragments_storage_` `Secure_Accessor`.
   - Вычисляется контрольная сумма `fragments_storage_` (`fragments_data_checksum_expected_`).
   - Важно отметить, что `my_obfuscated_string.Encrypt()` вызывается *сразу после*, повторно обфусцируя `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (или `const char* ptr = accessor;` из-за неявного преобразования)
   - Вызывается `Secure_Accessor::Get()`.
   - Он проверяет свои собственные канарейки целостности и канарейки родительского `Obfuscated_String`.
   - Если это первый доступ (`current_access_ptr_` равен `nullptr`), он восстанавливает полную строку в `reconstructed_plain_buffer_` из `fragments_storage_`.
   - Затем он проверяет `fragments_data_checksum_reconstructed_` с `fragments_data_checksum_expected_`, чтобы убедиться, что фрагменты не были изменены во время существования `Secure_Accessor`.
   - Если все в порядке, возвращается указатель на `reconstructed_plain_buffer_`.
3. Область видимости `accessor` заканчивается (выход из функции, завершение блока `{}`, и т.д.).
   - Автоматически вызывается деструктор `Secure_Accessor`.
   - Вызывается `Clear_All_Internal_Buffers()`, которая безопасно очищает (`Secure_Clear_Memory`) как `reconstructed_plain_buffer_`, так и `fragments_storage_`.

Результатом является то, что строка в виде plain text существует в полной форме только внутри `Secure_Accessor` (в `reconstructed_plain_buffer_`) и только после первого вызова `Get()`, в течение минимально возможного времени. Строка в исходном объекте `Obfuscated_String` повторно обфусцируется, как только `Secure_Accessor` скопирует ее содержимое во время своей конструкции.

#### Фрагментация памяти в `Secure_Accessor`

Чтобы еще больше затруднить обнаружение полной строки в plain text в памяти, `Secure_Accessor` во время своей конструкции не только копирует расшифрованную строку, но и разделяет ее:
1. Строка из родительского `Obfuscated_String` расшифровывается.
2. Ее содержимое разделяется на до `fragment_count_val` (в настоящее время 4, если строка достаточно большая) частей, которые копируются в `fragments_storage_[i]`.
3. Строка в родительском объекте `Obfuscated_String` повторно обфусцируется.

Только когда `Secure_Accessor::Get()` вызывается впервые, эти фрагменты собираются обратно в `reconstructed_plain_buffer_`. Эта техника направлена на "рассредоточение" чувствительных данных, препятствуя сканированию памяти в поиске непрерывных строк.

#### Безопасная очистка памяти

Как деструктор `Obfuscated_String` (через `Clear_Internal_Data`), так и деструктор `Secure_Accessor` (через `Clear_All_Internal_Buffers`) используют `Dralyxor::Detail::Secure_Clear_Memory`. Эта функция-обертка гарантирует, что буферы, содержащие чувствительные данные, будут надежно обнулены, предотвращая оптимизацию компилятором:
- **На Windows:** Использует `SecureZeroMemory` (User Mode) или `RtlSecureZeroMemory` (Kernel Mode), которые являются функциями операционной системы, специально разработанными для того, чтобы не быть оптимизированными и безопасно обнулять память.
- **На других платформах (Linux, macOS и т.д.):** Реализация теперь использует `memset` для заполнения блока памяти нулями. `memset` работает на уровне байтов, что делает его идеальным и безопасным для обнуления как примитивных типов (например, `char`, `int`), так и сложных типов (например, `structs`), избегая проблем совместимости типов или операторов присваивания. Чтобы гарантировать, что вызов `memset` не будет оптимизирован и удален компилятором, указатель буфера сначала приводится к `volatile`-указателю.

Этот подход гарантирует, что при уничтожении объектов чувствительное содержимое перезаписывается, снижая риск восстановления данных через анализ дампов памяти.

### Компонент 3: Защита во время выполнения (Anti-Debugging и Anti-Tampering)

**Dralyxor** не полагается только на обфускацию. Он применяет набор активных защитных мер во время выполнения, расположенных в основном в `anti_debug.hpp` и интегрированных в методы `Decrypt()` и `Encrypt()` `Obfuscated_String`.

#### Кроссплатформенное обнаружение отладчиков

Функция `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (в `anti_debug.hpp`) проверяет наличие отладчика, используя специфичные для операционной системы техники:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` для `ProcessDebugPort` (0x07) и `ProcessDebugFlags` (0x1F).
- **Linux:** Чтение `/proc/self/status` и проверка значения `TracerPid:`. Значение, отличное от 0, указывает на то, что процесс отслеживается.
- **macOS:** Использование `sysctl` с `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` для получения `kinfo_proc` и проверка флага `P_TRACED` в `kp_proc.p_flag`.

Дополнительно, внутри `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Выполняет цикл простых вычислительных операций и измеряет время. Значительное замедление (свыше `timing_threshold_milliseconds = 75ms`) может указывать на то, что отладчик работает в режиме пошагового выполнения или что активны обширные точки останова. Внутри этого цикла вызывается `Is_Debugger_Present_Tracer_Pid_Sysctl()`, а также функция-"приманка" `Detail::Canary_Function_For_Breakpoint_Check()` (которая просто возвращает `0xCC`, код инструкции для `int3` / программной точки останова), и ее результат подвергается операции XOR, что усложняет оптимизацию и предоставляет общее место для точек останова.
- `Detail::Perform_Output_Debug_String_Trick()` (только для Windows User Mode): Использует поведение `OutputDebugStringA/W` и `GetLastError()`. Если отладчик присоединен, `GetLastError()` может быть изменен после вызова `OutputDebugString`.

#### Влияние на работу в случае обнаружения или нарушения целостности

Если любая из проверок anti-debugging возвращает `true`, или если канарейки целостности `Obfuscated_String` (`_internal_integrity_canary1/2`) повреждены, функция `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` вернет `Detail::integrity_compromised_magic`.

Это возвращаемое значение является критически важным в функциях `Obfuscated_String::Decrypt()` и `Encrypt()`:
```cpp
// Упрощенная логика Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Канарейки Obfuscated_String
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
        // ... Повторная проверка канареек ...

        // ЕСЛИ runtime_key_mod НЕ РАВЕН integrity_compromised_magic, ОН НЕ ИСПОЛЬЗУЕТСЯ ДЛЯ ИЗМЕНЕНИЯ КЛЮЧА РАСШИФРОВКИ.
        // Ключ расшифровки всегда выводится из исходного 'compile_time_seed'.
        // Роль runtime_key_mod здесь — ДЕЙСТВОВАТЬ КАК ФЛАГ враждебной среды.
        // Если среда враждебная, функция возвращает integrity_compromised_magic, и расшифровка не продолжается или отменяется.
        
        // Transform_Compile_Time_Consistent вызывается с compile_time_seed (а НЕ с runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* режим расшифровки */);
        
        // ... Повторная проверка контрольной суммы и канареек ...
        // Если что-то не так, вызывается Clear_Internal_Data() и возвращается integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Успех
}
```

**Ключевой эффект:** Если `Calculate_Runtime_Key_Modifier` обнаруживает проблему (отладчик или поврежденная канарейка) и возвращает `integrity_compromised_magic`, функции `Decrypt()` (и аналогично `Encrypt()`) прерывают операцию, очищают внутренние данные `Obfuscated_String` (включая `storage_` и `micro_program_`) и возвращают `integrity_compromised_magic`. Это предотвращает правильную расшифровку (или повторное шифрование) строки во враждебной среде или в случае, если объект был изменен.
Строка не расшифровывается "неправильно" (в мусор); операция просто предотвращается, и объект `Obfuscated_String` самоуничтожается в плане полезного содержимого.

#### Канарейки целостности объекта

Оба класса `Obfuscated_String` и `Secure_Accessor` содержат члены-канарейки (пары `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (инициализируется значением `Detail::integrity_canary_value`) и `_internal_integrity_canary2` (инициализируется значением `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (инициализируется значением `Detail::accessor_integrity_canary_seed`) и `_accessor_integrity_canary2` (инициализируется значением `~Detail::accessor_integrity_canary_seed`).

Эти канарейки проверяются в критических точках:
- В начале и в конце `Obfuscated_String::Decrypt()` и `Encrypt()`.
- В конструкторе, деструкторе и `Get()` `Secure_Accessor`.
- До и после проверок anti-debug в `Calculate_Runtime_Key_Modifier`.

Если эти значения-канарейки изменены (например, из-за переполнения буфера, неразборчивого патча памяти или хука, перезаписывающего смежную память), проверка (`Verify_Internal_Canaries()` или `Verify_Internal_Accessor_Canaries()`) завершится неудачно.
В случае сбоя операции прерываются, соответствующие внутренние данные очищаются, и возвращается значение ошибки (`Detail::integrity_compromised_magic` или `nullptr`), сигнализируя о вмешательстве.

#### Контрольная сумма содержимого строки

- 16-битная контрольная сумма *исходной строки в plain text* (исключая нулевой терминатор) вычисляется `Detail::Calculate_String_Content_Checksum` во время компиляции.
- Эта контрольная сумма затем обфусцируется с использованием `Detail::Obfuscate_Deobfuscate_Short_Value` (с `compile_time_seed` и `content_checksum_obf_salt`) и сохраняется в `_content_checksum_obfuscated` в объекте `Obfuscated_String`.
- **При расшифровке (`Decrypt()`):** После преобразования `storage_` (предположительно в plain text) вычисляется его контрольная сумма. `_content_checksum_obfuscated` деобфусцируется для получения эталонной контрольной суммы. Если две контрольные суммы не совпадают, это указывает на то, что:
   - Расшифровка не восстановила исходную строку (возможно, потому что операция была прервана из-за обнаружения отладчика до полного преобразования, или произошло повреждение семени/микропрограммы).
   - `storage_` (в обфусцированном виде) или `_content_checksum_obfuscated` были изменены в памяти.
- **При шифровании (`Encrypt()`):** Прежде чем `storage_` (который в этот момент находится в виде plain text) будет преобразован обратно в свою обфусцированную форму, его контрольная сумма вычисляется и сравнивается с эталонной. Несоответствие здесь будет означать, что строка в plain text была изменена *внутри `storage_` объекта `Obfuscated_String`*, пока он был расшифрован, что является сильным признаком вмешательства в память или неправильного использования (так как прямой доступ к `storage_` не должен осуществляться).

В обоих случаях сбоя проверки контрольной суммы вызывается `Clear_Internal_Data()` и возвращается `integrity_compromised_magic`.

### Компонент 4: Генерация уникальных и непредсказуемых ключей и семян

Безопасность любой системы шифрования основывается на силе и уникальности ее ключей и семян. **Dralyxor** гарантирует, что каждая обфусцированная строка использует фундаментально уникальный набор параметров шифрования.

#### Источники энтропии для `compile_time_seed`

`static constexpr uint64_t Obfuscated_String::compile_time_seed` является главным семенем для всех псевдослучайных операций, относящихся к данному экземпляру строки. Его генерация теперь является условной и зависит от наличия ключа, предоставленного пользователем:

- **Если ключ предоставлен пользователем (с использованием `DRALYXOR_KEY` или `DRALYXOR_KEY_LOCAL`):**
   1. Предоставленный `key_literal` преобразуется в 64-битный хэш во время компиляции с использованием алгоритма FNV-1a.
   2. Этот хэш становится основой `compile_time_seed`, комбинируясь с `__COUNTER__` (для обеспечения уникальности между различными использованиями одного и того же ключа) и размером строки.
      ```cpp
      // Упрощенная логика
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      В этом режиме безопасность обфускации напрямую зависит от надежности и секретности предоставленного ключа.

- **Если ключ не предоставлен (с использованием `DRALYXOR` или `DRALYXOR_LOCAL`):**
   - `compile_time_seed` генерируется с использованием комбинации следующих факторов для максимизации энтропии и вариативности:
      ```cpp
      // Внутри Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Компонент 1: Вариативность между компиляциями
          ((uint64_t)Instance_Counter << 32) ^        // Компонент 2: Вариативность внутри одной единицы компиляции
          storage_n;                                  // Компонент 3: Вариативность на основе размера строки
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Макросы `__DATE__` (например, "Jan 01 2025") и `__TIME__` (например, "12:30:00") - это строки, предоставляемые препроцессором, которые меняются при каждой компиляции файла. Хэш FNV-1a этих значений создает основу для семени, которая отличается для каждой сборки проекта.
   - **`Instance_Counter` (получаемый из `__COUNTER__` в макросе)**: Макрос `__COUNTER__` - это счетчик, поддерживаемый препроцессором, который увеличивается при каждом его использовании в одной единице компиляции. Передавая это значение как шаблонный аргумент, каждое использование макроса `DRALYXOR` или `DRALYXOR_LOCAL` приведет к разному `Instance_Counter` и, следовательно, к разному `compile_time_seed`, даже для идентичных строковых литералов в одном и том же исходном файле.
   - **`storage_n` (размер строки)**: Размер строки также подвергается операции XOR, добавляя еще один фактор дифференциации.

Этот `compile_time_seed` (будь то полученный из пользовательского ключа или сгенерированный автоматически) затем используется в качестве основы для:
1. Генерации `micro_program_` (инициализируя PRNG семенем `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Получения ключа обфускации для самого `micro_program_` (через `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Получения ключа обфускации для `_content_checksum_obfuscated` (через `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Использования в качестве `base_seed` для `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Производные семена для преобразований содержимого

Внутри `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Инициализируется `Constexpr_PRNG prng_operand_modifier(base_seed)`. Для каждого преобразуемого символа строки `prng_operand_modifier.Key()` производит `prng_key_for_ops_in_elem`. Этот ключ подвергается операции XOR с операндом микроинструкции перед применением, что гарантирует, что эффект одной и той же микроинструкции будет незначительно отличаться для каждого символа.
- Инициализируется `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)`. Для каждого символа `prng_applier_selector.Key()` используется для выбора между `Applier_Style_Direct` и `Applier_Style_DoubleLayer`.

Это вводит дополнительную динамику в преобразование каждого символа, даже если основная микропрограмма одинакова для всех символов данной строки.

#### Иммунитет к атакам «повторного воспроизведения» (Replay) и анализу шаблонов

- **Уникальность между компиляциями:** Если злоумышленник проанализирует бинарный файл версии 1.0 вашего ПО и с большим трудом сможет взломать обфускацию строки (в режиме автоматического ключа), эти знания, скорее всего, будут бесполезны для версии 1.1, поскольку `__DATE__ __TIME__` изменится, что приведет к совершенно разным `compile_time_seed` и микропрограммам.
- **Уникальность внутри одной компиляции:** Если вы используете `DRALYXOR("AdminPassword")` в двух разных местах вашего кода (или в одном и том же .cpp файле), `__COUNTER__` обеспечит, что результирующие объекты `Obfuscated_String`, и, следовательно, их обфусцированные представления в бинарном файле, будут разными. Это мешает злоумышленнику найти один обфусцированный шаблон и использовать его для обнаружения всех других вхождений той же исходной строки.

Эта надежная генерация семян является краеугольным камнем безопасности **Dralyxor** от атак, которые зависят от обнаружения "мастер-ключа" или использования повторений шифров и преобразований.

## Полное руководство по публичному API

### Макросы обфускации

Это основные точки входа для создания обфусцированных строк.

#### `DRALYXOR(str_literal)`

- **Назначение:** Создает объект `Obfuscated_String` со статическим временем жизни (существует в течение всего времени выполнения программы). Идеально подходит для глобальных констант или строк, к которым необходимо обращаться из нескольких мест и которые должны сохраняться.
- **Хранение:** Статическая память (обычно в разделе данных программы).
- **Реализация:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Параметры:**
   - `str_literal`: Строковый литерал в стиле C (например, `"Hello World"`, `L"Unicode String"`).
- **Возвращаемое значение:** Ссылка (`auto&`) на статический объект `Obfuscated_String`, созданный внутри немедленно вызываемой лямбда-функции.
- **Пример:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url — это ссылка на статический Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Назначение:** Создает объект `Obfuscated_String` с автоматическим временем жизни (обычно на стеке, если используется внутри функции). Идеально подходит для временных секретов, ограниченных одной областью видимости.
- **Хранение:** Автоматическое (стек для локальных переменных функции).
- **Реализация:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Параметры:**
   - `str_literal`: Строковый литерал в стиле C.
- **Возвращаемое значение:** Объект `Obfuscated_String` по значению (который может быть оптимизирован с помощью RVO/NRVO компилятором).
- **Пример:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... использовать temp_key с DRALYXOR_SECURE ...
   } // temp_key уничтожается здесь, его деструктор вызывает Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Назначение:** Аналогично `DRALYXOR`, создает статический объект `Obfuscated_String`, но использует **ключ, предоставленный пользователем** (`key_literal`) для инициализации обфускации, предлагая наивысший уровень безопасности.
- **Хранение:** Статическая память (обычно в разделе данных программы).
- **Реализация:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Параметры:**
   - `str_literal`: Строковый литерал для обфускации.
   - `key_literal`: Строковый литерал, используемый в качестве секретного ключа.
- **Возвращаемое значение:** Ссылка (`auto&`) на статический объект `Obfuscated_String`.
- **Пример:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Назначение:** Аналогично `DRALYXOR_LOCAL`, создает объект `Obfuscated_String` на стеке, используя **ключ, предоставленный пользователем**.
- **Хранение:** Автоматическое (стек для локальных переменных функции).
- **Реализация:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Параметры:**
   - `str_literal`: Строковый литерал для обфускации.
   - `key_literal`: Строковый литерал, используемый в качестве ключа.
- **Возвращаемое значение:** Объект `Obfuscated_String` по значению.
- **Пример:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Макрос безопасного доступа

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Назначение:** Предоставляет безопасный и временный доступ к расшифрованному содержимому объекта `Obfuscated_String`. Это **единственный рекомендуемый метод** для чтения строки.
- **Реализация:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Параметры:**
   - `obfuscated_var`: Переменная (lvalue или rvalue, которое может быть привязано к неконстантной lvalue-ссылке) типа `Dralyxor::Obfuscated_String<...>`. Переменная должна быть изменяемой, поскольку конструктор `Secure_Accessor` вызывает на ней `Decrypt()` и `Encrypt()`.
- **Возвращаемое значение:** Объект `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` по значению.
- **Использование:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Или просто: const char* secret_ptr = accessor; (неявное преобразование)
       
       if (secret_ptr) {
           // Используйте secret_ptr здесь. Он указывает на временно расшифрованную строку в буфере accessor.
           // Пример: send_data(secret_ptr);
       }
       else {
           // Сбой расшифровки или нарушение целостности. Обработайте ошибку.
           // accessor мог не инициализироваться (например, my_static_secret был поврежден).
       }
   } // accessor уничтожается. Его внутренние буферы (фрагменты и восстановленная строка) очищаются.
    // my_static_secret.storage_ уже был повторно обфусцирован конструктором Secure_Accessor
    // сразу после копирования содержимого в фрагменты accessor.
   ```

> [!WARNING]
> Всегда проверяйте, что указатель, возвращаемый `DRALYXOR_SECURE(...).Get()` (или неявным преобразованием), не является `nullptr`, перед его использованием. Возврат `nullptr` указывает на сбой расшифровки (например, обнаружение отладчика, повреждение канареек/контрольных сумм в родительском `Obfuscated_String` или в самом `Secure_Accessor`). Использование указателя `nullptr` приведет к неопределенному поведению (вероятно, к ошибке сегментации).

## Расширенные возможности и лучшие практики

### Полная поддержка Unicode (широкие строки - `wchar_t`)

**Dralyxor** не зависит от типа символов благодаря использованию шаблонов (`CharT`). Он нативно обрабатывает `char` (для строк ASCII/UTF-8) и `wchar_t` (для строк UTF-16 в Windows или UTF-32 на других системах, в зависимости от платформы и компилятора). Просто используйте префикс `L` для литералов `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Сообщение Unicode: Привет Мир Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Пример на Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Заголовок Unicode", MB_OK);
        // Пример с wcout:
        // #include <io.h> // для _setmode на Windows с MSVC
        // #include <fcntl.h> // для _O_U16TEXT на Windows с MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Настраивает stdout для UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Для 1-байтовых символов (`sizeof(CharT) == 1`) движок преобразований `Micro_Program_Cipher` применяет микропрограмму побайтово. Для многобайтовых символов (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` использует более простой подход: весь многобайтовый символ подвергается операции XOR с маской, полученной из `prng_key_for_ops_in_elem` (реплицированной для заполнения размера `CharT`). Например, если `CharT` это `wchar_t` (2 байта) и `prng_key_for_ops_in_elem` равен `0xAB`, символ будет XOR'ен с `0xABAB`.
Это гарантирует, что все байты `wchar_t` затрагиваются обфускацией, даже если это не полная микропрограмма. Сложность микропрограммы все равно косвенно вносит свой вклад через получение ключей из PRNG.

### Интеллектуальная адаптация к стандартам **C++** и средам (Kernel Mode)

Как уже упоминалось, **Dralyxor** адаптируется:
- **Стандарты C++:** Требует как минимум **C++14**. Обнаруживает и использует возможности **C++17** и **C++20** (такие как `if constexpr`, `consteval`, суффиксы `_v` для `type_traits`), когда компилятор их поддерживает, в противном случае прибегая к альтернативам **C++14**. Макросы, такие как `_DRALYXOR_IF_CONSTEXPR` и `_DRALYXOR_CONSTEVAL` в `detection.hpp`, управляют этой адаптацией.
- **Kernel Mode:** Когда определен `_KERNEL_MODE` (типично для проектов WDK для драйверов Windows), **Dralyxor** (через `env_traits.hpp`) избегает включения стандартных заголовков STL, таких как `<type_traits>`, которые могут быть недоступны или вести себя иначе. Вместо этого он использует свои собственные `constexpr` реализации основных инструментов, таких как `Dralyxor::Detail::Fallback::decay` и `Dralyxor::Detail::Fallback::remove_reference`. Это позволяет безопасно использовать **Dralyxor** для защиты строк в низкоуровневых системных компонентах.
   - Аналогично, `secure_memory.hpp` использует `RtlSecureZeroMemory` в Kernel Mode. Для других платформ, таких как Linux, он прибегает к безопасному использованию `memset` для обеспечения очистки памяти, адаптируясь для совместимости с различными типами данных.
   - Проверки anti-debug в User Mode (такие как `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) отключаются (`#if !defined(_KERNEL_MODE)`) в Kernel Mode, поскольку они неприменимы или имеют другие эквиваленты. Проверки времени выполнения все еще могут иметь некоторый эффект, но основной линией защиты в Kernel Mode является сама обфускация.

### Соображения по производительности и накладным расходам

- **Время компиляции:** Обфускация, включая генерацию и применение микропрограмм, происходит полностью во время компиляции. Для проектов с очень большим количеством обфусцированных строк время компиляции может увеличиться. Это одноразовые затраты на каждую компиляцию.
- **Размер бинарного файла:** Каждый `Obfuscated_String` добавляет свой `storage_` (размер строки), `micro_program_` (фиксированный в `max_micro_instructions * sizeof(Micro_Instruction)`), плюс несколько байт для канареек, контрольной суммы и флагов. Может произойти увеличение размера бинарного файла по сравнению с чистыми строковыми литералами, особенно для множества небольших строк.
- **Время выполнения (Runtime):**
   - **Создание `Obfuscated_String` (статические или локальные объекты):** Происходит во время компиляции (для статических) или включает копирование предварительно вычисленных данных (для локальных, оптимизируемых RVO). Затрат на "генерацию" во время выполнения нет.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Проверки канареек (чрезвычайно быстрые).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Включает антиотладочные проверки. Проверка тайминга (`Perform_Timing_Check_Generic`) здесь самая затратная, выполняя цикл. Остальные — это вызовы API или чтения файлов (Linux).
      - Деобфускация микропрограммы (копирование и XOR, быстро).
      - Преобразование строки: Цикл по `N_data_elements_to_transform`, и внутри него цикл по `num_actual_instructions_in_program_`. Для каждой инструкции — вызов `Byte_Transform_Applier`, который выполняет несколько байтовых операций. Стоимость O(длина\_строки \* число\_инструкций).
      - Вычисление/проверка контрольной суммы (`Detail::Calculate_String_Content_Checksum`): O(длина\_строки \* sizeof(CharT)).
   - **Создание `Secure_Accessor`:**
      - Вызывает `Obfuscated_String::Decrypt()`.
      - Копирует строку во фрагменты: O(длина\_строки).
      - Вычисляет контрольную сумму фрагментов (`Calculate_Current_Fragments_Checksum`): O(длина\_строки).
      - Вызывает `Obfuscated_String::Encrypt()`. Это точка наибольшей концентрации накладных расходов в одной операции доступа.
   - **`Secure_Accessor::Get()`:**
      - Первый вызов: Проверяет канарейки, восстанавливает строку из фрагментов (O(длина\_строки)), проверяет контрольную сумму фрагментов.
      - Последующие вызовы (для того же объекта `Secure_Accessor`): Проверяет канарейки (быстро) и возвращает уже вычисленный указатель (O(1)).
- **Общие накладные расходы:** Для большинства приложений, где чувствительные строки не используются в циклах с очень высокой частотой, накладные расходы времени выполнения обычно приемлемы, особенно учитывая преимущество в безопасности. Дизайн `Secure_Accessor` (создаваемый только при необходимости и со строго ограниченной областью видимости по RAII) является фундаментальным для управления этими затратами. Протестируйте в вашей конкретной среде, если производительность критична.

### Интеграция в многоуровневую стратегию безопасности

> [!IMPORTANT]
> **Dralyxor** — это мощный инструмент для **обфускации встроенных строк и защиты от анализа памяти**, а не универсальное криптографическое решение для постоянного хранения данных на диске или безопасной передачи по сети.
>
> Его следует использовать как **один из многих уровней** в комплексной стратегии безопасности. Ни один отдельный инструмент не является панацеей. Другие меры, которые следует рассмотреть, включают:
> - **Минимизация встроенных секретов:** По возможности избегайте встраивания секретов очень высокой критичности. Используйте альтернативы, такие как:
>    - Безопасные конфигурации, предоставляемые во время выполнения (переменные среды, файлы конфигурации с ограниченными правами доступа).
>    - Службы управления секретами (хранилища), такие как HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Надежная проверка ввода на всех интерфейсах.
> - Принцип наименьших привилегий для процессов и пользователей.
> - Безопасная сетевая коммуникация (TLS/SSL с пиннингом сертификатов, если применимо).
> - Безопасное хеширование паролей пользователей (Argon2, scrypt, bcrypt).
> - Защита бинарного файла в целом с помощью других техник анти-реверсинга/анти-тамперинга (пакеры, виртуализаторы кода, проверки целостности кода), осознавая компромиссы, которые они могут внести (ложные срабатывания антивирусов, сложность).
> - Надлежащие практики безопасной разработки (Secure SDLC).

**Dralyxor** фокусируется на очень хорошем решении конкретной и распространенной проблемы: защите встроенных строковых литералов от статического анализа и минимизации их раскрытия в памяти во время выполнения, усложняя жизнь тем, кто пытается провести реверс-инжиниринг вашего программного обеспечения.

## Лицензия

Эта библиотека защищена Лицензией MIT, которая позволяет:

- ✔️ Коммерческое и частное использование
- ✔️ Изменение исходного кода
- ✔️ Распространение кода
- ✔️ Сублицензирование

### Условия:

- Сохранять уведомление об авторских правах
- Прилагать копию лицензии MIT

Для получения дополнительной информации о лицензии: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Все права защищены**