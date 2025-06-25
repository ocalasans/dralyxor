# Dralyxor

**Dralyxor** es una biblioteca **C++** moderna, `de solo cabecera` (header-only), de alto rendimiento y multicapa, diseñada para la ofuscación de cadenas en tiempo de compilación y una protección robusta en tiempo de ejecución. Su misión fundamental es blindar los secretos intrínsecos de su aplicación — como claves de API, contraseñas, URLs internas, mensajes de depuración y cualquier literal de cadena sensible — contra la exposición mediante análisis estático, ingeniería inversa e inspección de memoria dinámica. Al cifrar y transformar las cadenas en el momento de la compilación y al gestionar su acceso de forma segura en tiempo de ejecución, **Dralyxor** asegura que ningún literal de cadena crítico exista como texto plano en su binario final o permanezca desprotegido en la memoria durante más tiempo del estrictamente necesario.

Construido sobre los cimientos del **C++** moderno (requiriendo **C++14** y adaptándose inteligentemente a las características de **C++17** y **C++20**), su arquitectura avanzada presenta un sofisticado motor de transformación basado en "microprogramas", ofuscación del propio programa de transformación, mecanismos de integridad de datos, defensas anti-depuración y un **Accesor de Alcance Seguro (RAII)** para un descifrado "just-in-time" y una re-ofuscación automática. Esto minimiza drásticamente la exposición de datos en la memoria **RAM** y proporciona una defensa en profundidad de nivel profesional.

## Idiomas

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Índice

- [Dralyxor](#dralyxor)
  - [Idiomas](#idiomas)
  - [Índice](#índice)
  - [Guía de Integración y Uso Rápido](#guía-de-integración-y-uso-rápido)
    - [Instalación](#instalación)
    - [Requisitos del Compilador](#requisitos-del-compilador)
    - [Patrones de Uso Esenciales](#patrones-de-uso-esenciales)
      - [Patrón 1: Ofuscación Local (Pila)](#patrón-1-ofuscación-local-pila)
      - [Patrón 2: Ofuscación Estática (Global)](#patrón-2-ofuscación-estática-global)
    - [Manejo de Errores e Integridad](#manejo-de-errores-e-integridad)
  - [Filosofía y Arquitectura de Diseño Detallada](#filosofía-y-arquitectura-de-diseño-detallada)
    - [La Amenaza Persistente: Vulnerabilidad de las Cadenas Literales](#la-amenaza-persistente-vulnerabilidad-de-las-cadenas-literales)
    - [La Solución Arquitectónica Multicapa de **Dralyxor**](#la-solución-arquitectónica-multicapa-de-dralyxor)
  - [Análisis Profundo de los Componentes Arquitectónicos](#análisis-profundo-de-los-componentes-arquitectónicos)
    - [Componente 1: El Motor de Transformación por Microprograma](#componente-1-el-motor-de-transformación-por-microprograma)
      - [Poder de `consteval` y `constexpr` para Generación en Compilación](#poder-de-consteval-y-constexpr-para-generación-en-compilación)
      - [Anatomía de un Microprograma **Dralyxor**](#anatomía-de-un-microprograma-dralyxor)
        - [Generación Aleatorizada de Instrucciones e Selección de Aplicadores](#generación-aleatorizada-de-instrucciones-e-selección-de-aplicadores)
        - [NOPs Variables y Lógicos para Entropía](#nops-variables-y-lógicos-para-entropía)
      - [Ofuscación del Propio Microprograma](#ofuscación-del-propio-microprograma)
      - [El Ciclo de Vida de la Ofuscación Estática](#el-ciclo-de-vida-de-la-ofuscación-estática)
    - [Componente 2: Acceso Seguro y Minimización de Exposición en **RAM**](#componente-2-acceso-seguro-y-minimización-de-exposición-en-ram)
      - [El `Secure_Accessor` y el Principio RAII](#el-secure_accessor-y-el-principio-raii)
      - [Fragmentación de Memoria en el `Secure_Accessor`](#fragmentación-de-memoria-en-el-secure_accessor)
      - [Limpieza Segura de Memoria](#limpieza-segura-de-memoria)
    - [Componente 3: Defensas en Tiempo de Ejecución (Anti-Depuración y Anti-Manipulación)](#componente-3-defensas-en-tiempo-de-ejecución-anti-depuración-y-anti-manipulación)
      - [Detección Multiplataforma de Depuradores](#detección-multiplataforma-de-depuradores)
      - [Impacto en la Operación en Caso de Detección o Violación de Integridad](#impacto-en-la-operación-en-caso-de-detección-o-violación-de-integridad)
      - [Canarios de Integridad del Objeto](#canarios-de-integridad-del-objeto)
      - [Suma de Verificación (Checksum) del Contenido de la Cadena](#suma-de-verificación-checksum-del-contenido-de-la-cadena)
    - [Componente 4: Generación de Claves y Semillas Únicas e Impredecibles](#componente-4-generación-de-claves-y-semillas-únicas-e-impredecibles)
      - [Fuentes de Entropía para el `compile_time_seed`](#fuentes-de-entropía-para-el-compile_time_seed)
      - [Semillas Derivadas para Transformaciones de Contenido](#semillas-derivadas-para-transformaciones-de-contenido)
      - [Inmunidad Contra Ataques de "Replay" y Análisis de Patrones](#inmunidad-contra-ataques-de-replay-y-análisis-de-patrones)
  - [Referencia Completa de la API Pública](#referencia-completa-de-la-api-pública)
    - [Macros de Ofuscación](#macros-de-ofuscación)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Macro de Acceso Seguro](#macro-de-acceso-seguro)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Características Avanzadas y Buenas Prácticas](#características-avanzadas-y-buenas-prácticas)
    - [Soporte Total a Unicode (Cadenas Anchas - `wchar_t`)](#soporte-total-a-unicode-cadenas-anchas---wchar_t)
    - [Adaptación Inteligente a los Estándares **C++** y Entornos (Modo Kernel)](#adaptación-inteligente-a-los-estándares-c-y-entornos-modo-kernel)
    - [Consideraciones de Rendimiento y Sobrecarga](#consideraciones-de-rendimiento-y-sobrecarga)
    - [Integración en una Estrategia de Seguridad en Capas](#integración-en-una-estrategia-de-seguridad-en-capas)
  - [Licencia](#licencia)
    - [Condiciones:](#condiciones)

## Guía de Integración y Uso Rápido

### Instalación

**Dralyxor** es una biblioteca **de solo cabecera** (header-only). No se necesita compilación previa ni vinculación de bibliotecas (`.lib`/`.a`).

1.  **Copie el Directorio `Dralyxor`:** Obtenga la última versión de la biblioteca (clone el repositorio o descargue el zip) y copie todo el directorio `Dralyxor` (conteniendo todos los archivos `.hpp`) a una ubicación accesible por su proyecto (por ejemplo, una carpeta `libs/`, `libraries/`, o `vendor/`).
2.  **Incluya la Cabecera Principal:** En su código fuente, incluya la cabecera principal `dralyxor.hpp`:
    ```cpp
    #include "ruta/a/Dralyxor/dralyxor.hpp"
    ```

Una estructura de proyecto típica:
```
/MiProyecto/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor aquí
        |-- dralyxor.hpp            (Punto de entrada principal)
        |-- obfuscated_string.hpp   (Clase Obfuscated_String)
        |-- secure_accessor.hpp     (Clase Secure_Accessor)
        |-- algorithms.hpp          (Motor de transformación y microprogramas)
        |-- anti_debug.hpp          (Detecciones en tiempo de ejecución)
        |-- prng.hpp                (Generador de números pseudoaleatorios en compilación)
        |-- integrity_constants.hpp (Constantes para verificaciones de integridad)
        |-- secure_memory.hpp       (Limpieza segura de memoria)
        |-- detection.hpp           (Macros de detección de compilador/estándar C++)
        `-- env_traits.hpp          (Adaptaciones de type_traits para entornos restringidos)
```

### Requisitos del Compilador

> [!IMPORTANT]
> **Dralyxor** fue diseñado con enfoque en **C++** moderno para máxima seguridad y eficiencia en tiempo de compilación.
>
> - **Estándar C++ Mínimo: C++14**. La biblioteca utiliza características como `constexpr` generalizado y se adapta para `if constexpr` (cuando está disponible vía `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptación a Estándares Superiores:** Detecta y utiliza optimizaciones o sintaxis de **C++17** y **C++20** (como `consteval`, sufijos `_v` para `type_traits`) si el proyecto se compila con esos estándares. `_DRALYXOR_CONSTEVAL` mapea a `consteval` en C++20 y `constexpr` en C++14/17, garantizando la ejecución en tiempo de compilación donde sea posible.
> - **Compiladores Soportados:** Probado primariamente con MSVC, GCC y Clang recientes.
> - **Entorno de Ejecución:** Totalmente compatible con aplicaciones en **Modo Usuario** (User Mode) y entornos en **Modo Kernel** (Kernel Mode) (ej: drivers de Windows). En Modo Kernel, donde la STL puede no estar disponible, **Dralyxor** utiliza implementaciones internas para los `type traits` necesarios (vea `env_traits.hpp`).

### Patrones de Uso Esenciales

#### Patrón 1: Ofuscación Local (Pila)

Ideal para cadenas temporales, confinadas a un ámbito de función. La memoria es automáticamente gestionada y limpiada.

```cpp
#include "Dralyxor/dralyxor.hpp" // Ajuste la ruta según sea necesario
#include <iostream>

void Configure_Logging() {
    // Clave de formato de log, usada solo localmente.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Acceso seguro dentro de un ámbito limitado
    {
        // El Secure_Accessor descifra temporalmente 'log_format_key' durante su construcción
        // (y re-ofusca 'log_format_key' inmediatamente después de la copia a sus búferes internos),
        // permite el acceso, y limpia sus propios búferes en la destrucción.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Siempre verifique que Get() no retorne nullptr
            std::cout << "Usando formato de log: " << accessor.Get() << std::endl;
            // Ej: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Fallo al descifrar log_format_key (¿posible manipulación o detección de depurador?)" << std::endl;
    } // accessor se destruye, sus búferes internos son limpiados. log_format_key permanece ofuscado.
      // log_format_key será destruido al final de la función Configure_Logging.
}
```

#### Patrón 2: Ofuscación Estática (Global)

Para constantes que necesitan persistir durante la vida útil del programa y ser accedidas globalmente.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Para el ejemplo

// URL de la API de licencias, un secreto persistente.
// La macro DRALYXOR() crea un objeto estático.
// La función Get_License_Server_URL() retorna una referencia a este objeto estático.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref es una referencia al Obfuscated_String estático.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Crea un Secure_Accessor para url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Contactando servidor de licencias en: " << accessor.Get() << std::endl;
            // Ej: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulación de éxito para el ejemplo
        }
        else
            std::cerr << "Fallo al descifrar URL del servidor de licencias (¿posible manipulación o detección de depurador?)." << std::endl;
    } // accessor se destruye, sus búferes son limpiados. url_obj_ref (el Obfuscated_String original) permanece ofuscado.

    return success;
}
```

### Manejo de Errores e Integridad

Las funciones `Obfuscated_String::Decrypt()` y `Encrypt()` retornan `uint64_t`:
- `0` indica éxito.
- `Dralyxor::Detail::integrity_compromised_magic` (un valor constante definido en `integrity_constants.hpp`) indica que una verificación de integridad falló. Esto puede deberse a canarios del objeto corruptos, suma de verificación del contenido inconsistente, o detección de un depurador que señala un ambiente hostil.

De la misma forma, `Secure_Accessor::Get()` (o su conversión implícita a `const CharT*`) retornará `nullptr` si la inicialización del `Secure_Accessor` falla (por ejemplo, si el descifrado del `Obfuscated_String` original falla) o si la integridad del `Secure_Accessor` (sus propios canarios o sumas de verificación internas) es comprometida durante su vida útil.

**Es crucial que su código verifique estos retornos para garantizar la robustez y seguridad de la aplicación.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Generalmente NO llamaría a Decrypt() y Encrypt() directamente,
    // ya que Secure_Accessor gestiona esto. Pero si lo necesita por alguna razón:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "ALERTA: ¡Fallo al descifrar 'my_secret' o integridad comprometida durante Decrypt()!" << std::endl;
        // Tome una acción apropiada: termine, loguee de forma segura, etc.
        // El objeto my_secret.storage_ puede estar en un estado inválido o con basura.
        return; // Evite usar my_secret si Decrypt() falla.
    }

    // Si Decrypt() tuvo éxito, my_secret.storage_ contiene el dato descifrado.
    // **EL ACCESO DIRECTO A storage_ ESTÁ FUERTEMENTE DESACONSEJADO EN PRODUCCIÓN.**
    // std::cout << "Dato en my_secret.storage_ (NO HAGA ESTO): " << my_secret.storage_ << std::endl;

    // Es su responsabilidad re-cifrar si llamó a Decrypt() manualmente:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "ALERTA: ¡Fallo al re-cifrar 'my_secret' o integridad comprometida durante Encrypt()!" << std::endl;
        // Estado incierto, potencialmente peligroso.
    }

    // USO RECOMENDADO con Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // El constructor de Secure_Accessor llama a another_secret.Decrypt(), copia, y luego another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // O: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Dato secreto vía Secure_Accessor: " << data_ptr << std::endl;
            // Use data_ptr aquí
        }
        else {
            std::cerr << "ALERTA: ¡Secure_Accessor falló al inicializar u obtener puntero para 'another_secret'!" << std::endl;
            // Esto indica que el Decrypt() dentro del constructor del accessor falló,
            // o hubo manipulación en el accessor (canarios, sumas de verificación internas).
        }
    } // accessor se destruye. Sus búferes son limpiados. another_secret permanece ofuscada.
}
```

## Filosofía y Arquitectura de Diseño Detallada

**Dralyxor** no es meramente un cifrado XOR; es un sistema de defensa en profundidad para cadenas literales. Su arquitectura se fundamenta en la premisa de que la seguridad eficaz requiere múltiples capas interconectadas y resiliencia contra diversas técnicas de análisis.

### La Amenaza Persistente: Vulnerabilidad de las Cadenas Literales

Las cadenas literales, como `"api.example.com/data?key="`, cuando se incrustan directamente en el código, se graban de forma legible (texto plano) en el binario compilado. Herramientas como `strings`, desensambladores (IDA Pro, Ghidra) y editores hexadecimales pueden extraerlas trivialmente. Esta exposición facilita:
- **Ingeniería Inversa:** Comprensión de la lógica interna y flujo del programa.
- **Identificación de Endpoints:** Descubrimiento de servidores y APIs backend.
- **Extracción de Secretos:** Claves de API, contraseñas incrustadas, URLs privadas, consultas SQL, etc.
- **Análisis de Memoria Dinámica:** Incluso si un programa descifra una cadena para su uso, si permanece en texto plano en la **RAM** por mucho tiempo, un atacante con acceso a la memoria del proceso (vía depurador o volcado de memoria) puede encontrarla.

**Dralyxor** ataca estas vulnerabilidades tanto en tiempo de compilación (para el binario en disco) como en tiempo de ejecución (para la memoria **RAM**).

### La Solución Arquitectónica Multicapa de **Dralyxor**

La robustez de **Dralyxor** emana de la sinergia de sus componentes clave:

| Componente Arquitectónico                      | Objetivo Primario                                                                      | Tecnologías/Técnicas Clave Empleadas                                                                                                                              |
| :--------------------------------------------- | :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Motor de Transformación por Microprograma**    | Eliminar cadenas en texto plano del binario; crear ofuscación compleja, dinámica y no trivial. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, múltiples operaciones (XOR, ADD, ROT, etc.), NOPs variables y lógicos, estilos de aplicadores variables.         |
| **Acceso Seguro y Minimización de Exposición** | Reducir drásticamente el tiempo que un secreto permanece descifrado en la memoria RAM. | Patrón RAII (`Secure_Accessor`), fragmentación de memoria, limpieza segura de búferes (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Defensas en Tiempo de Ejecución**             | Detectar y reaccionar a entornos de análisis hostiles y adulteración de memoria.       | Detección de Depuradores (APIs específicas del SO, timing, OutputDebugString), canarios de integridad del objeto, suma de verificación (checksum) del contenido de la cadena. |
| **Generación de Claves y Semillas Únicas**    | Garantizar que cada cadena ofuscada y cada instancia de uso sean criptográficamente distintas. | `__DATE__`, `__TIME__`, `__COUNTER__`, tamaño de la cadena, hashing FNV-1a para `compile_time_seed`, semillas derivadas para modificadores de operando y selectores. |

## Análisis Profundo de los Componentes Arquitectónicos

### Componente 1: El Motor de Transformación por Microprograma

El corazón de la ofuscación estática y dinámica de **Dralyxor** reside en su motor de transformación que utiliza "microprogramas" únicos para cada cadena y contexto.

#### Poder de `consteval` y `constexpr` para Generación en Compilación
El **C++** moderno, con `consteval` (**C++20**) y `constexpr` (**C++11** en adelante), permite que código complejo sea ejecutado *durante la compilación*. **Dralyxor** utiliza `_DRALYXOR_CONSTEVAL` (que mapea a `consteval` o `constexpr` dependiendo del estándar **C++**) para el constructor `Obfuscated_String` y para la generación del microprograma.

Esto significa que todo el proceso de:
1. Generar una secuencia pseudoaleatoria de instrucciones de transformación (el microprograma).
2. Ofuscar el propio microprograma para su almacenamiento.
3. Aplicar ese microprograma (de forma descifrada temporalmente) para transformar la cadena original, resultando en su forma ofuscada.
Todo esto sucede en tiempo de compilación, antes de que se genere el binario.

#### Anatomía de un Microprograma **Dralyxor**

Cada objeto `Obfuscated_String` almacena un pequeño array de `Dralyxor::Detail::Micro_Instruction`. Una `Micro_Instruction` es una estructura simple definida en `algorithms.hpp`:
```cpp
// En Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM // Aunque presente, no se usa activamente para terminar la ejecución del microprograma,
                   // la iteración es controlada por 'num_actual_instructions_in_program_'.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // La operación (XOR, ADD, ROTL, etc.)
    uint8_t operand;            // El valor usado por la operación
};

// Número máximo de instrucciones que un microprograma puede contener.
static constexpr size_t max_micro_instructions = 8;
```
La función `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` es responsable de rellenar este array.

##### Generación Aleatorizada de Instrucciones e Selección de Aplicadores

- **Generación de Instrucciones:** Utilizando un `Dralyxor::Detail::Constexpr_PRNG` (sembrado con una combinación del `compile_time_seed` y `0xDEADBEEFC0FFEEULL`), la función `Generate_Micro_Program_Instructions` elige probabilísticamente una secuencia de operaciones:
    - `XOR`: XOR a nivel de bits con el operando.
    - `ADD`: Adición modular con el operando.
    - `SUB`: Sustracción modular con el operando.
    - `ROTR`/`ROTL`: Rotación de bits. El operando (después del módulo) define el número de desplazamientos (1 a 7).
    - `SWAP_NIB`: Intercambia los 4 bits inferiores con los 4 bits superiores de un byte (el operando se ignora).
    Los operandos para estas instrucciones también son generados pseudoaleatoriamente por el PRNG.

- **Modificación de Operandos y Selección de Aplicadores en Tiempo de Transformación:** Durante la aplicación del microprograma (por `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), tanto en la ofuscación inicial como en el descifrado en tiempo de ejecución:
    - Un `Constexpr_PRNG prng_operand_modifier` (sembrado con `base_seed`) genera una `prng_key_for_ops_in_elem` para cada carácter de la cadena. El operando de la microinstrucción (`instr_orig.operand`) se somete a XOR con esta clave antes de ser usado. Esto asegura que el mismo microprograma aplique transformaciones ligeramente diferentes para cada carácter.
    - Un `Constexpr_PRNG prng_applier_selector` (sembrado con `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) elige un `Byte_Transform_Applier` para cada carácter. Actualmente existen dos estilos:
        - `Applier_Style_Direct`: Aplica la operación directamente (invirtiéndola para el descifrado, como ADD se convierte en SUB).
        - `Applier_Style_DoubleLayer`: Aplica la operación dos veces (o la operación y su inversa, dependiendo del modo de cifrado/descifrado) con operandos diferentes, haciendo la reversión un poco más compleja de analizar.

##### NOPs Variables y Lógicos para Entropía

Para aumentar la dificultad de análisis manual del microprograma, **Dralyxor** inserta:
- **NOPs Explícitos:** Instrucciones `Micro_Operation_Code::NOP` que no hacen nada.
- **NOPs Lógicos:** Pares de instrucciones que se anulan mutuamente, como `ADD K` seguido por `SUB K`, o `ROTL N_BITS` seguido por `ROTR N_BITS`. El operando usado en el par es el mismo.

Estos NOPs son insertados probabilísticamente por `Generate_Micro_Program_Instructions`, rellenando el array `micro_program_` y haciendo más difícil discernir las transformaciones efectivas de las operaciones de "ruido".

#### Ofuscación del Propio Microprograma

Después de la generación del microprograma y antes de la ofuscación inicial de la cadena en el constructor `consteval`, el array `micro_program_` (contenido en el objeto `Obfuscated_String`) es ofuscado él mismo. Cada `op_code` y `operand` en cada `Micro_Instruction` se somete a XOR con una clave derivada del `compile_time_seed` (usando `Detail::Get_Micro_Program_Obfuscation_Key` y `Detail::Obfuscate_Deobfuscate_Instruction`).
Esto significa que, incluso si un atacante consigue volcar la memoria del objeto `Obfuscated_String`, el microprograma no estará en su forma directamente legible/aplicable.

Cuando se llama a `Obfuscated_String::Decrypt()` o `Encrypt()` (o indirectamente por el `Secure_Accessor`), la función central `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` recibe este microprograma *ofuscado*. Ella entonces:
1. Crea una copia temporal del microprograma (`local_plain_program`) en la pila.
2. Descifra esta copia local usando la misma clave (`program_obf_key`) derivada de la semilla base pasada (que es, en última instancia, el `compile_time_seed`).
3. Utiliza este `local_plain_program` para transformar los datos de la cadena.
La copia local en la pila se destruye al final de la función, y el `micro_program_` almacenado en el objeto `Obfuscated_String` permanece ofuscado.

#### El Ciclo de Vida de la Ofuscación Estática

1.  **Código Fuente:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2.  **Preprocesamiento:** La macro se expande a una instanciación `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (El tamaño 15 incluye el terminador nulo).
3.  **Evaluación `_DRALYXOR_CONSTEVAL`:**
    - El compilador ejecuta el constructor `Obfuscated_String`.
    - `Initialize_Internal_Canaries()` define los canarios de integridad.
    - `Generate_Micro_Program_Instructions()` (sembrado con `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) crea una secuencia de `Micro_Instruction` y la almacena en `this->micro_program_` (ej: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). El número real de instrucciones se almacena en `num_actual_instructions_in_program_`.
    - La cadena original "SECRET\_API\_KEY" se copia a `this->storage_`.
    - Se calcula una suma de verificación (checksum) de la cadena original "SECRET\_API\_KEY" (excluyendo el nulo) por `Detail::Calculate_String_Content_Checksum` y luego se ofusca por `Detail::Obfuscate_Deobfuscate_Short_Value` (usando `compile_time_seed` y `content_checksum_obf_salt`) y se almacena en `this->_content_checksum_obfuscated`.
    - Se llama a `Obfuscate_Internal_Micro_Program()`: el `this->micro_program_` se ofusca en el lugar (cada instrucción XORada con `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
    - Se llama a `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)`. Esta función:
        - Crea una copia descifrada del `this->micro_program_` en la pila.
        - Para cada carácter en `storage_` (excepto el nulo):
            - Genera `prng_key_for_ops_in_elem` y selecciona un `Byte_Transform_Applier`.
            - Aplica la secuencia de microinstrucciones (de la copia descifrada) al carácter, usando el aplicador y el operando modificado.
        - Al final, `storage_` contiene la cadena ofuscada (ej: `[CF, 3A, D1, ..., 0x00]`).
4.  **Generación de Código:** El compilador asigna espacio para `api_key_obj` y lo inicializa directamente con:
    - `storage_`: `[CF, 3A, D1, ..., 0x00]` (cadena ofuscada).
    - `micro_program_`: El microprograma *ya ofuscado*.
    - `_content_checksum_obfuscated`: La suma de verificación del contenido original, *ofuscada*.
    - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    El literal `"SECRET_API_KEY"` ya no existe en el binario.

### Componente 2: Acceso Seguro y Minimización de Exposición en **RAM**

#### El `Secure_Accessor` y el Principio RAII

La protección en tiempo de compilación es solo la mitad de la batalla. Una vez que la cadena necesita ser usada, debe ser descifrada. Si esta cadena descifrada permanece en la memoria **RAM** por un período prolongado, se convierte en un objetivo para análisis dinámico (volcados de memoria, depuradores).

**Dralyxor** aborda esto con `Dralyxor::Secure_Accessor`, una clase que implementa el patrón **RAII** (Resource Acquisition Is Initialization - Adquisición de Recursos es Inicialización):
- **Recurso Adquirido:** El acceso temporal a la cadena en texto plano, fragmentada y gestionada por el accesor.
- **Objeto Gestor:** La instancia de `Secure_Accessor`.

```cpp
// En secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Inicializar diferentes para fallar si no se actualiza
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalida el accesor

            return;
        }

        // 1. Intenta descifrar el Obfuscated_String original.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Si el descifrado es exitoso, copia la cadena en texto plano a los fragmentos internos.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ ahora está en texto plano
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val es como máximo 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Rellena el resto del búfer del fragmento con nulos
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Suma de verificación de los fragmentos
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Re-cifra INMEDIATAMENTE el Obfuscated_String original.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Limpia fragmentos y búfer reconstruido.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Se verifica a sí mismo y al padre
            Clear_All_Internal_Buffers(); // Medida de seguridad
            _accessor_integrity_canary1 = 0; // Invalida para accesos futuros

            return nullptr;
        }

        if (!current_access_ptr_) { // Si es la primera llamada a Get() o si fue limpiado
            if constexpr (N_storage > 0) { // Solo reconstruye si hay algo que reconstruir
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

                // Asegura terminación nula, incluso si N_storage se llena exactamente.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Para N_storage == 0 (cadena vacía, teóricamente), no hay sumas de verificación
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Para pasar la verificación

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // si N_storage era 0, esto es seguro si el búfer es > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Verifica nuevamente después de cualquier operación interna para garantizar la integridad.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Flujo de Uso con `DRALYXOR_SECURE`:**
1.  `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
    - Se llama al constructor de `Secure_Accessor`.
    - Llama a `my_obfuscated_string.Decrypt()`. Esto implica descifrar el `micro_program_` (a una copia local), usarlo para descifrar `my_obfuscated_string.storage_`, y luego verificar canarios y la suma de verificación del contenido descifrado contra el esperado.
    - Si tiene éxito, el contenido de `my_obfuscated_string.storage_` (ahora texto plano) se copia y divide en los `fragments_storage_` internos del `Secure_Accessor`.
    - Se calcula una suma de verificación de los `fragments_storage_` (`fragments_data_checksum_expected_`).
    - Crucialmente, se llama a `my_obfuscated_string.Encrypt()` *inmediatamente después*, re-ofuscando `my_obfuscated_string.storage_`.
2.  `const char* ptr = accessor.Get();` (o `const char* ptr = accessor;` debido a la conversión implícita)
    - Se llama a `Secure_Accessor::Get()`.
    - Verifica sus propios canarios de integridad y los del `Obfuscated_String` padre.
    - Si es el primer acceso (`current_access_ptr_` es `nullptr`), reconstruye la cadena completa en `reconstructed_plain_buffer_` a partir de los `fragments_storage_`.
    - Luego verifica `fragments_data_checksum_reconstructed_` contra `fragments_data_checksum_expected_` para asegurar que los fragmentos no fueron adulterados mientras existía el `Secure_Accessor`.
    - Si todo está correcto, retorna un puntero a `reconstructed_plain_buffer_`.
3.  El ámbito del `accessor` termina (sale de la función, bloque `{}` termina, etc.).
    - El destructor de `Secure_Accessor` se llama automáticamente.
    - Se invoca a `Clear_All_Internal_Buffers()`, que limpia de forma segura (`Secure_Clear_Memory`) tanto `reconstructed_plain_buffer_` como `fragments_storage_`.

El resultado es que la cadena en texto plano existe en forma completa solo dentro del `Secure_Accessor` (en `reconstructed_plain_buffer_`) y solamente después de la primera llamada a `Get()`, por el menor tiempo posible. La cadena en el objeto `Obfuscated_String` original se re-ofusca tan pronto como el `Secure_Accessor` copia su contenido durante la construcción.

#### Fragmentación de Memoria en el `Secure_Accessor`

Para dificultar aún más la localización de la cadena completa en texto plano en la memoria, el `Secure_Accessor`, durante su construcción, no solo copia la cadena descifrada, sino que la divide:
1.  Se descifra la cadena del `Obfuscated_String` padre.
2.  Su contenido se divide en hasta `fragment_count_val` (actualmente 4, si la cadena es lo suficientemente grande) pedazos, que se copian a `fragments_storage_[i]`.
3.  La cadena en el objeto `Obfuscated_String` padre se re-ofusca.

Solo cuando se llama a `Secure_Accessor::Get()` por primera vez es que estos fragmentos se re-ensamblan en `reconstructed_plain_buffer_`. Esta técnica busca "esparcir" los datos sensibles, frustrando escaneos de memoria que buscan cadenas continuas.

#### Limpieza Segura de Memoria

Tanto el destructor de `Obfuscated_String` (vía `Clear_Internal_Data`) como el destructor de `Secure_Accessor` (vía `Clear_All_Internal_Buffers`) utilizan `Dralyxor::Detail::Secure_Clear_Memory` (plantilla para arrays) o `Dralyxor::Detail::Secure_Clear_Memory_Raw` (para punteros crudos, aunque `Secure_Clear_Memory` se usa más en los destructores). Esta función envoltorio (wrapper):
- Usa `SecureZeroMemory` (Modo Usuario de Windows) o `RtlSecureZeroMemory` (Modo Kernel de Windows) cuando están disponibles, que son funciones del sistema operativo diseñadas para no ser optimizadas por el compilador.
- Recurre a un bucle con un puntero `volatile T* p` en otras plataformas o cuando las funciones específicas de Windows no están disponibles. El `volatile` es un intento de instruir al compilador a no optimizar la escritura de ceros. Esto asegura que, cuando los objetos se destruyen o los búferes se limpian explícitamente, el contenido sensible se sobrescribe, reduciendo el riesgo de recuperación de datos.

### Componente 3: Defensas en Tiempo de Ejecución (Anti-Depuración y Anti-Manipulación)

**Dralyxor** no confía solo en la ofuscación. Emplea un conjunto de defensas activas en tiempo de ejecución, localizadas principalmente en `anti_debug.hpp` e integradas en los métodos `Decrypt()` y `Encrypt()` del `Obfuscated_String`.

#### Detección Multiplataforma de Depuradores

La función `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (en `anti_debug.hpp`) verifica la presencia de un depurador usando técnicas específicas del sistema operativo:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` para `ProcessDebugPort` (0x07) y `ProcessDebugFlags` (0x1F).
- **Linux:** Lectura de `/proc/self/status` y verificación del valor de `TracerPid:`. Un valor diferente de 0 indica que el proceso está siendo rastreado.
- **macOS:** Uso de `sysctl` con `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` para obtener `kinfo_proc` y verificación del flag `P_TRACED` en `kp_proc.p_flag`.

Adicionalmente, dentro de `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Ejecuta un bucle de operaciones computacionales simples y mide el tiempo. Una lentitud significativa (por encima de `timing_threshold_milliseconds = 75ms`) puede indicar que un depurador está en ejecución paso a paso (single-stepping) o que hay puntos de interrupción extensivos activos. Dentro de este bucle, se llama a `Is_Debugger_Present_Tracer_Pid_Sysctl()`, y una función "señuelo" `Detail::Canary_Function_For_Breakpoint_Check()` (que simplemente retorna `0xCC`, el código de instrucción para `int3` / punto de interrupción de software) se llama y su resultado se XORéa, dificultando la optimización y proporcionando un lugar común para puntos de interrupción.
- `Detail::Perform_Output_Debug_String_Trick()` (solo Modo Usuario de Windows): Usa el comportamiento de `OutputDebugStringA/W` y `GetLastError()`. Si un depurador está adjunto, `GetLastError()` puede ser modificado después de la llamada a `OutputDebugString`.

#### Impacto en la Operación en Caso de Detección o Violación de Integridad

Si cualquiera de las verificaciones anti-depuración retorna `true`, o si los canarios de integridad del `Obfuscated_String` (`_internal_integrity_canary1/2`) están corruptos, la función `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` retornará `Detail::integrity_compromised_magic`.

Este valor retornado es crucial en las funciones `Obfuscated_String::Decrypt()` y `Encrypt()`:
```cpp
// Lógica simplificada de Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canarios del Obfuscated_String
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
        // ... Verificar canarios nuevamente ...

        // SI runtime_key_mod NO ES integrity_compromised_magic, ÉL NO SE USA PARA CAMBIAR LA CLAVE DE DESCIFRADO.
        // La clave de descifrado siempre se deriva del 'compile_time_seed' original.
        // El papel del runtime_key_mod aquí es ACTUAR COMO UN INDICADOR de ambiente hostil.
        // Si es hostil, la función retorna integrity_compromised_magic y el descifrado no prosigue o se revierte.
        
        // Transform_Compile_Time_Consistent se llama con compile_time_seed (y NO con runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* modo descifrado */);
        
        // ... Verificar suma de verificación y canarios nuevamente ...
        // Si algo falla, Clear_Internal_Data() y retorna integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Éxito
}
```

**Efecto Clave:** Si `Calculate_Runtime_Key_Modifier` detecta un problema (depurador o canario corrupto) y retorna `integrity_compromised_magic`, las funciones `Decrypt()` (y similarmente `Encrypt()`) abortan la operación, limpian los datos internos del `Obfuscated_String` (incluyendo `storage_` y `micro_program_`), y retornan `integrity_compromised_magic`. Esto impide que la cadena sea correctamente descifrada (o re-cifrada) en un ambiente hostil o si el objeto fue adulterado.
La cadena no se descifra "incorrectamente" (a basura); la operación simplemente se impide, y el objeto `Obfuscated_String` se autodestruye en términos de contenido útil.

#### Canarios de Integridad del Objeto

Ambas clases `Obfuscated_String` y `Secure_Accessor` contienen miembros canario (pares de `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (inicializado con `Detail::integrity_canary_value`) e `_internal_integrity_canary2` (inicializado con `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (inicializado con `Detail::accessor_integrity_canary_seed`) e `_accessor_integrity_canary2` (inicializado con `~Detail::accessor_integrity_canary_seed`).

Estos canarios se verifican en puntos críticos:
- Inicio y fin de `Obfuscated_String::Decrypt()` y `Encrypt()`.
- Constructor, destructor y `Get()` de `Secure_Accessor`.
- Antes y después de las verificaciones anti-depuración en `Calculate_Runtime_Key_Modifier`.

Si estos valores canario son alterados (por ejemplo, por un desbordamiento de búfer, un parche de memoria indiscriminado, o un hook que sobrescriba memoria adyacente), la verificación (`Verify_Internal_Canaries()` o `Verify_Internal_Accessor_Canaries()`) fallará.
En caso de falla, las operaciones se abortan, los datos internos relevantes se limpian, y un valor de error (`Detail::integrity_compromised_magic` o `nullptr`) se retorna, señalando adulteración.

#### Suma de Verificación (Checksum) del Contenido de la Cadena

- Una suma de verificación de 16 bits de la cadena *original en texto plano* (excluyendo el terminador nulo) es calculada por `Detail::Calculate_String_Content_Checksum` en tiempo de compilación.
- Esta suma de verificación es luego ofuscada usando `Detail::Obfuscate_Deobfuscate_Short_Value` (con `compile_time_seed` y `content_checksum_obf_salt`) y almacenada en `_content_checksum_obfuscated` en el objeto `Obfuscated_String`.
- **Al Descifrar (`Decrypt()`):** Después de que `storage_` es transformado (supuestamente a texto plano), se calcula su suma de verificación. El `_content_checksum_obfuscated` es descifrado para obtener la suma de verificación de referencia. Si las dos sumas de verificación no coinciden, indica que:
    - El descifrado no restauró la cadena original (quizás porque la operación fue abortada debido a la detección de depurador antes de la transformación completa, o hubo corrupción de la semilla/microprograma).
    - El `storage_` (cuando estaba ofuscado) o el `_content_checksum_obfuscated` fueron adulterados en la memoria.
- **Al Cifrar (`Encrypt()`):** Antes de que `storage_` (que está en texto plano en este punto) sea transformado de nuevo a su forma ofuscada, se calcula su suma de verificación y se compara con la de referencia. Una divergencia aquí significaría que la cadena en texto plano fue alterada *dentro del `storage_` del `Obfuscated_String` mientras estaba descifrada*, lo cual es una fuerte indicación de adulteración de la memoria o uso indebido (ya que el acceso al `storage_` no debe hacerse directamente).

En ambos casos de falla de la suma de verificación, se llama a `Clear_Internal_Data()` y se retorna `integrity_compromised_magic`.

### Componente 4: Generación de Claves y Semillas Únicas e Impredecibles

La seguridad de cualquier sistema de cifrado reposa en la fortaleza y unicidad de sus claves y semillas. **Dralyxor** garantiza que cada cadena ofuscada utilice un conjunto de parámetros de cifrado fundamentalmente único.

#### Fuentes de Entropía para el `compile_time_seed`

El `static constexpr uint64_t Obfuscated_String::compile_time_seed` es la semilla maestra para todas las operaciones pseudoaleatorias relativas a esa instancia de la cadena. Se genera en `consteval` de la siguiente forma:
```cpp
// Dentro de Obfuscated_String<CharT, storage_n, Instance_Counter>
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Componente 1: Variabilidad entre compilaciones
    ((uint64_t)Instance_Counter << 32) ^        // Componente 2: Variabilidad dentro de una unidad de compilación
    storage_n;                                  // Componente 3: Variabilidad basada en el tamaño de la cadena
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Las macros `__DATE__` (ej: "Jan 01 2025") y `__TIME__` (ej: "12:30:00") son cadenas proporcionadas por el preprocesador que cambian cada vez que el archivo es compilado. El hash FNV-1a de estos valores crea una base de semilla que es diferente para cada compilación del proyecto.
- **`Instance_Counter` (alimentado por `__COUNTER__` en la macro `DRALYXOR`/`DRALYXOR_LOCAL`)**: La macro `__COUNTER__` es un contador mantenido por el preprocesador que incrementa cada vez que se usa dentro de una unidad de compilación. Al pasar esto como un argumento de plantilla `int Instance_Counter` a `Obfuscated_String`, cada uso de la macro `DRALYXOR` o `DRALYXOR_LOCAL` resultará en un `Instance_Counter` diferente y, por lo tanto, un `compile_time_seed` diferente, incluso para cadenas literales idénticas en el mismo archivo de origen.
- **`storage_n` (tamaño de la cadena incluyendo el nulo)**: El tamaño de la cadena también se XORéa, añadiendo otro factor de diferenciación.

Este `compile_time_seed` se usa luego como base para:
1. Generar el `micro_program_` (sembrando el PRNG con `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Derivar la clave de ofuscación para el propio `micro_program_` (vía `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Derivar la clave de ofuscación para el `_content_checksum_obfuscated` (vía `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Servir como `base_seed` para `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Semillas Derivadas para Transformaciones de Contenido

Dentro de `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Se inicializa un `Constexpr_PRNG prng_operand_modifier(base_seed)`. Para cada carácter de la cadena siendo transformado, `prng_operand_modifier.Key()` produce una `prng_key_for_ops_in_elem`. Esta clave se XORéa con el operando de la microinstrución antes de la aplicación, asegurando que el efecto de la misma microinstrución sea sutilmente diferente para cada carácter.
- Se inicializa un `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)`. Para cada carácter, `prng_applier_selector.Key()` se usa para elegir entre `Applier_Style_Direct` y `Applier_Style_DoubleLayer`.

Esto introduce un dinamismo adicional en la transformación de cada carácter, incluso si el microprograma subyacente es el mismo para todos los caracteres de una cadena dada.

#### Inmunidad Contra Ataques de "Replay" y Análisis de Patrones

- **Unicidad Inter-Compilación:** Si un atacante analiza el binario de la versión 1.0 de su software y, con mucho esfuerzo, consigue romper la ofuscación de una cadena, ese conocimiento será probablemente inútil para la versión 1.1, ya que `__DATE__ __TIME__` habrá cambiado, resultando en `compile_time_seed`s y microprogramas completamente diferentes.
- **Unicidad Intra-Compilación:** Si usted usa `DRALYXOR("AdminPassword")` en dos lugares diferentes en su código (o en el mismo archivo .cpp), el `__COUNTER__` garantizará que los objetos `Obfuscated_String` resultantes, y por lo tanto sus representaciones ofuscadas en el binario (tanto el `storage_` como el `micro_program_`), sean diferentes. Esto impide que un atacante encuentre un patrón ofuscado y lo use para localizar todas las otras ocurrencias de la misma cadena original, o use un microprograma descubierto para descifrar otras cadenas.

Esta generación robusta de semillas es una piedra angular de la seguridad de **Dralyxor** contra ataques que dependen de descubrir un "secreto maestro" o de explotar la repetición de cifrados y transformaciones.

## Referencia Completa de la API Pública

### Macros de Ofuscación

Estos son los principales puntos de entrada para crear cadenas ofuscadas.

#### `DRALYXOR(str_literal)`

- **Propósito:** Crea un objeto `Obfuscated_String` con tiempo de vida estático (existe durante toda la ejecución del programa). Ideal para constantes globales o cadenas que necesitan ser accedidas desde múltiples ubicaciones y persistir.
- **Almacenamiento:** Memoria estática (normalmente en la sección de datos del programa).
- **Implementación (simplificada):**
  ```cpp
  #define DRALYXOR(str_literal) \
      []() -> auto& { \
          /* La macro __COUNTER__ garantiza un Instance_Counter único para cada uso */ \
          /* decltype(*str_literal) infiere el tipo de carácter (char, wchar_t) */ \
          /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) calcula el tamaño incluyendo el nulo */ \
          static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
              typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
              (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
              __COUNTER__ \
          >(str_literal); \
          return obfuscated_static_string; \
      }()
  ```

- **Parámetros:**
  - `str_literal`: Un literal de cadena estilo C (ej., `"Hello World"`, `L"Unicode String"`).
- **Retorno:** Una referencia (`auto&`) al objeto `Obfuscated_String` estático, creado dentro de una lambda inmediatamente invocada.
- **Ejemplo:**
  ```cpp
  static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
  // api_endpoint_url es una referencia a un Obfuscated_String estático.
  ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Propósito:** Crea un objeto `Obfuscated_String` con tiempo de vida automático (normalmente en la pila, si se usa dentro de una función). Ideal para secretos temporales confinados a un ámbito.
- **Almacenamiento:** Automático (pila para variables locales de función).
- **Implementación (simplificada):**
  ```cpp
  #define DRALYXOR_LOCAL(str_literal) \
      Dralyxor::Obfuscated_String< \
          typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
          (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
          __COUNTER__ \
      >(str_literal)
  ```
- **Parámetros:**
  - `str_literal`: Un literal de cadena estilo C.
- **Retorno:** Un objeto `Obfuscated_String` por valor (que puede ser optimizado con RVO/NRVO por el compilador).
- **Ejemplo:**
  ```cpp
  void process_data() {
      auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
      // ... usar temp_key con DRALYXOR_SECURE ...
  } // temp_key se destruye aquí, su destructor llama a Clear_Internal_Data().
  ```

### Macro de Acceso Seguro

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Propósito:** Proporciona acceso seguro y temporal al contenido descifrado de un objeto `Obfuscated_String`. Este es el **único método recomendado** para leer la cadena.
- **Implementación (simplificada):**
  ```cpp
  #define DRALYXOR_SECURE(obfuscated_var) \
      Dralyxor::Secure_Accessor< \
          typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
      >(obfuscated_var)
  ```

- **Parámetros:**
  - `obfuscated_var`: Una variable (lvalue o rvalue que pueda ser vinculada a una referencia lvalue no-const) del tipo `Dralyxor::Obfuscated_String<...>`. La variable necesita ser mutable porque el constructor del `Secure_Accessor` llama a `Decrypt()` y `Encrypt()` en ella.
- **Retorno:** Un objeto `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` por valor.
- **Uso:**
  ```cpp
  auto& my_static_secret = DRALYXOR("My Top Secret");
  // ...
  {
      auto accessor = DRALYXOR_SECURE(my_static_secret);
      const char* secret_ptr = accessor.Get(); // O simplemente: const char* secret_ptr = accessor; (conversión implícita)
      
      if (secret_ptr) {
          // Use secret_ptr aquí. Apunta a la cadena descifrada temporalmente en el búfer del accessor.
          // Ej: send_data(secret_ptr);
      }
      else {
          // Fallo en el descifrado o integridad. Maneje el error.
          // El accessor puede haber fallado al inicializar (ej., my_static_secret fue corrompido).
      }
  } // accessor se destruye. Sus búferes internos (fragmentos y cadena reconstruida) son limpiados.
   // El my_static_secret.storage_ ya fue re-ofuscado por el constructor del Secure_Accessor
   // logo después de copiar el contenido a los fragmentos del accessor.
  ```

> [!WARNING]
> Siempre verifique que el puntero retornado por `DRALYXOR_SECURE(...).Get()` (o por la conversión implícita) no sea `nullptr` antes de usarlo. Un retorno `nullptr` indica un fallo en el descifrado (por ejemplo, detección de depurador, corrupción de canarios/sumas de verificación en el `Obfuscated_String` padre o en el propio `Secure_Accessor`). El uso de un puntero `nullptr` resultará en comportamiento indefinido (probablemente un fallo de segmentación).

## Características Avanzadas y Buenas Prácticas

### Soporte Total a Unicode (Cadenas Anchas - `wchar_t`)

**Dralyxor** es agnóstico al tipo de carácter gracias al uso de plantillas (`CharT`). Maneja nativamente `char` (para cadenas ASCII/UTF-8) y `wchar_t` (para cadenas UTF-16 en Windows o UTF-32 en otros sistemas, dependiendo de la plataforma y del compilador). Basta usar el prefijo `L` para literales `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Mensaje Unicode: Hola Mundo Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Ejemplo en Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Título Unicode", MB_OK);
        // Ejemplo con wcout:
        // #include <io.h> // Para _setmode en Windows con MSVC
        // #include <fcntl.h> // Para _O_U16TEXT en Windows con MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Configura stdout para UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Para caracteres de 1 byte (`sizeof(CharT) == 1`), el motor de transformación `Micro_Program_Cipher` aplica el microprograma byte a byte. Para caracteres multibyte (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` usa un enfoque más simple: el carácter multibyte entero se XORéa con una máscara derivada de `prng_key_for_ops_in_elem` (replicada para rellenar el tamaño del `CharT`). Por ejemplo, si `CharT` es `wchar_t` (2 bytes) y `prng_key_for_ops_in_elem` es `0xAB`, el carácter será XORéado con `0xABAB`.
Esto asegura que todos los bytes del `wchar_t` sean afectados por la ofuscación, aunque no sea por el microprograma completo. La complejidad del microprograma aún contribuye indirectamente a través de la derivación de las claves del PRNG.

### Adaptación Inteligente a los Estándares **C++** y Entornos (Modo Kernel)

Como se mencionó, **Dralyxor** se adapta:
- **Estándares C++:** Requiere como mínimo **C++14**. Detecta y utiliza características de **C++17** y **C++20** (como `if constexpr`, `consteval`, sufijos `_v` para `type_traits`) cuando el compilador los soporta, recurriendo a alternativas **C++14** en caso contrario. Macros como `_DRALYXOR_IF_CONSTEXPR` y `_DRALYXOR_CONSTEVAL` en `detection.hpp` gestionan esta adaptación.
- **Modo Kernel:** Cuando `_KERNEL_MODE` está definido (típico en proyectos WDK para drivers de Windows), **Dralyxor** (vía `env_traits.hpp`) evita incluir cabeceras estándar de la STL como `<type_traits>` que pueden no estar disponibles o comportarse de forma diferente. En su lugar, usa sus propias implementaciones `constexpr` de herramientas básicas como `Dralyxor::Detail::Fallback::decay` y `Dralyxor::Detail::Fallback::remove_reference`. Esto permite el uso seguro de **Dralyxor** para proteger cadenas en componentes de sistema de bajo nivel.
  - Similarmente, `secure_memory.hpp` usa `RtlSecureZeroMemory` en Modo Kernel.
  - Las verificaciones anti-depuración del Modo Usuario (como `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) se deshabilitan (`#if !defined(_KERNEL_MODE)`) en Modo Kernel, ya que no se aplican o tienen equivalentes diferentes. Las verificaciones de tiempo (timing) aún pueden tener algún efecto, pero la principal línea de defensa en Modo Kernel es la ofuscación en sí.

### Consideraciones de Rendimiento y Sobrecarga

- **Tiempo de Compilación:** La ofuscación, incluyendo la generación y aplicación de microprogramas, ocurre enteramente en tiempo de compilación. Para proyectos con un número muy grande de cadenas ofuscadas, el tiempo de compilación puede aumentar. Este es un costo único por compilación.
- **Tamaño del Binario:** Cada `Obfuscated_String` añade su `storage_` (tamaño de la cadena), el `micro_program_` (fijo en `max_micro_instructions * sizeof(Micro_Instruction)`), más algunos bytes para canarios, suma de verificación y flags. Puede haber un aumento en el tamaño del binario comparado con cadenas literales puras, especialmente para muchas cadenas pequeñas.
- **Tiempo de Ejecución (Runtime):**
  - **Creación de `Obfuscated_String` (objetos estáticos o locales):** Ocurre en tiempo de compilación (para estáticos) o implica una copia de datos precalculados (para locales, optimizable por RVO). No hay costo de "generación" en tiempo de ejecución.
  - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
    - Verificaciones de canarios (extremadamente rápidas).
    - `Detail::Calculate_Runtime_Key_Modifier()`: Incluye las verificaciones anti-depuración. La verificación de tiempo (`Perform_Timing_Check_Generic`) es la más costosa aquí, ejecutando un bucle. Las otras son llamadas de API o lecturas de archivo (Linux).
    - Descifrado del microprograma (copia y XOR, rápido).
    - Transformación de la cadena: Bucle sobre los `N_data_elements_to_transform`, y dentro de él, bucle sobre `num_actual_instructions_in_program_`. Para cada instrucción, una llamada al `Byte_Transform_Applier` que hace algunas operaciones de byte. El costo es O(longitud_de_la_cadena * num_instrucciones).
    - Cálculo/Verificación de suma de verificación (`Detail::Calculate_String_Content_Checksum`): O(longitud_de_la_cadena * sizeof(CharT)).
  - **Creación de `Secure_Accessor`:**
    - Llama a `Obfuscated_String::Decrypt()`.
    - Copia cadena a fragmentos: O(longitud_de_la_cadena).
    - Calcula suma de verificación de fragmentos (`Calculate_Current_Fragments_Checksum`): O(longitud_de_la_cadena).
    - Llama a `Obfuscated_String::Encrypt()`. Este es el punto de mayor concentración de sobrecarga en una única operación de acceso.
  - **`Secure_Accessor::Get()`:**
    - Primera llamada: Verifica canarios, reconstruye cadena de los fragmentos (O(longitud_de_la_cadena)), verifica suma de verificación de los fragmentos.
    - Llamadas subsecuentes (para el mismo objeto `Secure_Accessor`): Verifica canarios (rápido) y retorna puntero ya calculado (O(1)).
- **Sobrecarga General:** Para la mayoría de las aplicaciones, donde las cadenas sensibles no se acceden en bucles de altísima frecuencia, la sobrecarga de tiempo de ejecución es generalmente aceptable, especialmente considerando el beneficio de seguridad. El diseño del `Secure_Accessor` (creado solo cuando es necesario y con ámbito estrictamente limitado por RAII) es fundamental para gestionar este costo. Pruebe en su entorno específico si el rendimiento es crítico.

### Integración en una Estrategia de Seguridad en Capas

> [!IMPORTANT]
> **Dralyxor** es una herramienta poderosa de **ofuscación de cadenas incrustadas y defensa contra análisis de memoria**, no una solución de criptografía genérica para almacenamiento persistente de datos en disco o transmisión segura por la red.
>
> Debe ser usado como **una de muchas capas** en una estrategia de seguridad integral. Ninguna herramienta aislada es una bala de plata. Otras medidas a considerar incluyen:
> - **Minimizar Secretos Incrustados:** Siempre que sea posible, evite incrustar secretos de altísima criticidad. Utilice alternativas como:
>   - Configuraciones seguras proporcionadas en tiempo de ejecución (variables de entorno, archivos de configuración con permisos restringidos).
>   - Servicios de gestión de secretos (bóvedas) como HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Validación de entrada robusta en todas las interfaces.
> - Principio del menor privilegio para procesos y usuarios.
> - Comunicación de red segura (TLS/SSL con anclaje de certificado - certificate pinning, si aplica).
> - Hashing seguro de contraseñas de usuario (Argon2, scrypt, bcrypt).
> - Protección del binario como un todo con otras técnicas anti-reversión/anti-manipulación (packers, virtualizadores de código, verificaciones de integridad del código), consciente de los compromisos (trade-offs) que estas pueden introducir (falsos positivos de antivirus, complejidad).
> - Buenas prácticas de desarrollo seguro (Secure SDLC).

**Dralyxor** se enfoca en resolver un problema específico y común muy bien: la protección de cadenas literales incrustadas contra análisis estático y la minimización de su exposición en memoria durante la ejecución, dificultando la vida de quien intenta hacer ingeniería inversa en su software.

## Licencia

Esta biblioteca está protegida bajo la Licencia MIT, que permite:

- ✔️ Uso comercial y privado
- ✔️ Modificación del código fuente
- ✔️ Distribución del código
- ✔️ Sublicenciamiento

### Condiciones:

- Mantener el aviso de derechos de autor
- Incluir copia de la licencia MIT

Para más detalles sobre la licencia: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Todos los derechos reservados**