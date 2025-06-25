# Dralyxor

**Dralyxor** é uma biblioteca **C++** moderna, `header-only`, de alta performance e multicamadas, projetada para a ofuscação de strings em tempo de compilação e proteção robusta em tempo de execução. Sua missão fundamental é blindar os segredos intrínsecos da sua aplicação — como chaves de API, senhas, URLs internas, mensagens de depuração e qualquer literal de string sensível — contra a exposição por meio de análise estática, engenharia reversa e inspeção de memória dinâmica. Ao criptografar e transformar as strings no momento da compilação e ao gerenciar seu acesso de forma segura em runtime, o **Dralyxor** assegura que nenhum literal de string crítico exista como texto plano no seu binário final ou permaneça desprotegido na memória por mais tempo que o estritamente necessário.

Construído sobre os alicerces do **C++** moderno (requerendo **C++14** e adaptando-se inteligentemente aos recursos de **C++17** e **C++20**), sua arquitetura avançada apresenta um sofisticado motor de transformação baseado em "micro-programas", ofuscação do próprio programa de transformação, mecanismos de integridade de dados, defesas anti-debugging, e um **Acessor de Escopo Seguro (RAII)** para uma descriptografia "just-in-time" e re-ofuscação automática. Isso minimiza drasticamente a exposição de dados na memória **RAM** e fornece uma defesa em profundidade de nível profissional.

## Idiomas

- Deutsch: [README](translations/Deutsch/README.md)
- English: [README](translations/English/README.md)
- Español: [README](translations/Espanol/README.md)
- Français: [README](translations/Francais/README.md)
- Italiano: [README](translations/Italiano/README.md)
- Polski: [README](translations/Polski/README.md)
- Русский: [README](translations/Русский/README.md)
- Svenska: [README](translations/Svenska/README.md)
- Türkçe: [README](translations/Turkce/README.md)

## Índice

- [Dralyxor](#dralyxor)
  - [Idiomas](#idiomas)
  - [Índice](#índice)
  - [Guia de Integração e Uso Rápido](#guia-de-integração-e-uso-rápido)
    - [Instalação](#instalação)
    - [Requisitos do Compilador](#requisitos-do-compilador)
    - [Padrões de Uso Essenciais](#padrões-de-uso-essenciais)
      - [Padrão 1: Ofuscação Local (Stack)](#padrão-1-ofuscação-local-stack)
      - [Padrão 2: Ofuscação Estática (Global)](#padrão-2-ofuscação-estática-global)
    - [Tratamento de Erros e Integridade](#tratamento-de-erros-e-integridade)
  - [Filosofia e Arquitetura de Design Detalhada](#filosofia-e-arquitetura-de-design-detalhada)
    - [A Ameaça Persistente: Vulnerabilidade das Strings Literais](#a-ameaça-persistente-vulnerabilidade-das-strings-literais)
    - [A Solução Arquitetônica Multicamadas do **Dralyxor**](#a-solução-arquitetônica-multicamadas-do-dralyxor)
  - [Análise Profunda dos Componentes Arquitetônicos](#análise-profunda-dos-componentes-arquitetônicos)
    - [Componente 1: O Motor de Transformação por Micro-Programa](#componente-1-o-motor-de-transformação-por-micro-programa)
      - [Poder do `consteval` e `constexpr` para Geração em Compilação](#poder-do-consteval-e-constexpr-para-geração-em-compilação)
      - [Anatomia de um Micro-Programa **Dralyxor**](#anatomia-de-um-micro-programa-dralyxor)
        - [Geração Aleatorizada de Instruções e Seleção de Aplicadores](#geração-aleatorizada-de-instruções-e-seleção-de-aplicadores)
        - [NOPs Variáveis e Lógicos para Entropia](#nops-variáveis-e-lógicos-para-entropia)
      - [Ofuscação do Próprio Micro-Programa](#ofuscação-do-próprio-micro-programa)
      - [O Ciclo de Vida da Ofuscação Estática](#o-ciclo-de-vida-da-ofuscação-estática)
    - [Componente 2: Acesso Seguro e Minimização de Exposição em **RAM**](#componente-2-acesso-seguro-e-minimização-de-exposição-em-ram)
      - [O `Secure_Accessor` e o Princípio RAII](#o-secure_accessor-e-o-princípio-raii)
      - [Fragmentação de Memória no `Secure_Accessor`](#fragmentação-de-memória-no-secure_accessor)
      - [Limpeza Segura de Memória](#limpeza-segura-de-memória)
    - [Componente 3: Defesas em Tempo de Execução (Anti-Debugging e Anti-Tampering)](#componente-3-defesas-em-tempo-de-execução-anti-debugging-e-anti-tampering)
      - [Detecção Multi-Plataforma de Debuggers](#detecção-multi-plataforma-de-debuggers)
      - [Impacto na Operação em Caso de Detecção ou Violação de Integridade](#impacto-na-operação-em-caso-de-detecção-ou-violação-de-integridade)
      - [Canários de Integridade do Objeto](#canários-de-integridade-do-objeto)
      - [Checksum de Conteúdo da String](#checksum-de-conteúdo-da-string)
    - [Componente 4: Geração de Chaves e Sementes Únicas e Imprevisíveis](#componente-4-geração-de-chaves-e-sementes-únicas-e-imprevisíveis)
      - [Fontes de Entropia para o `compile_time_seed`](#fontes-de-entropia-para-o-compile_time_seed)
      - [Sementes Derivadas para Transformações de Conteúdo](#sementes-derivadas-para-transformações-de-conteúdo)
      - [Imunidade Contra Ataques de "Replay" e Análise de Padrões](#imunidade-contra-ataques-de-replay-e-análise-de-padrões)
  - [Referência Completa da API Pública](#referência-completa-da-api-pública)
    - [Macros de Ofuscação](#macros-de-ofuscação)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Macro de Acesso Seguro](#macro-de-acesso-seguro)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Recursos Avançados e Boas Práticas](#recursos-avançados-e-boas-práticas)
    - [Suporte Total a Unicode (Wide Strings - `wchar_t`)](#suporte-total-a-unicode-wide-strings---wchar_t)
    - [Adaptação Inteligente aos Padrões **C++** e Ambientes (Kernel Mode)](#adaptação-inteligente-aos-padrões-c-e-ambientes-kernel-mode)
    - [Considerações de Performance e Overhead](#considerações-de-performance-e-overhead)
    - [Integração em uma Estratégia de Segurança em Camadas](#integração-em-uma-estratégia-de-segurança-em-camadas)
  - [Licença](#licença)
    - [Condições:](#condições)

## Guia de Integração e Uso Rápido

### Instalação

O **Dralyxor** é uma biblioteca **header-only**. Nenhuma compilação prévia ou vinculação de bibliotecas (`.lib`/`.a`) é necessária.

1. **Copie o Diretório `Dralyxor`:** Obtenha a última versão da biblioteca (clone o repositório ou baixe o zip) e copie todo o diretório `Dralyxor` (contendo todos os arquivos `.hpp`) para um local acessível pelo seu projeto (por exemplo, uma pasta `libs/`, `libraries/`, ou `vendor/`).
2. **Inclua o Cabeçalho Principal:** No seu código-fonte, inclua o cabeçalho principal `dralyxor.hpp`:
   ```cpp
   #include "caminho/para/Dralyxor/dralyxor.hpp"
   ```

Uma estrutura de projeto típica:
```
/MeuProjeto/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor aqui
        |-- dralyxor.hpp            (Ponto de entrada principal)
        |-- obfuscated_string.hpp   (Classe Obfuscated_String)
        |-- secure_accessor.hpp     (Classe Secure_Accessor)
        |-- algorithms.hpp          (Motor de transformação e micro-programas)
        |-- anti_debug.hpp          (Detecções em runtime)
        |-- prng.hpp                (Gerador de números pseudoaleatórios em compilação)
        |-- integrity_constants.hpp (Constantes para verificações de integridade)
        |-- secure_memory.hpp       (Limpeza segura de memória)
        |-- detection.hpp           (Macros de detecção de compilador/C++ padrão)
        `-- env_traits.hpp          (Adaptações de type_traits para ambientes restritos)
```

### Requisitos do Compilador

> [!IMPORTANT]
> O **Dralyxor** foi projetado com foco em **C++** moderno para máxima segurança e eficiência em tempo de compilação.
>
> - **Padrão C++ Mínimo: C++14**. A biblioteca utiliza recursos como `constexpr` generalizado e se adapta para `if constexpr` (quando disponível via `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptação a Padrões Superiores:** Detecta e utiliza otimizações ou sintaxes de **C++17** e **C++20** (como `consteval`, sufixos `_v` para `type_traits`) se o projeto for compilado com esses padrões. O `_DRALYXOR_CONSTEVAL` mapeia para `consteval` em C++20 e `constexpr` em C++14/17, garantindo a execução em tempo de compilação onde possível.
> - **Compiladores Suportados:** Testado primariamente com MSVC, GCC e Clang recentes.
> - **Ambiente de Execução:** Totalmente compatível com aplicações **User Mode** e ambientes **Kernel Mode** (ex: drivers do Windows). No Kernel Mode, onde a STL pode não estar disponível, o **Dralyxor** utiliza implementações internas para `type traits` necessários (veja `env_traits.hpp`).

### Padrões de Uso Essenciais

#### Padrão 1: Ofuscação Local (Stack)

Ideal para strings temporárias, confinadas a um escopo de função. A memória é automaticamente gerenciada e limpa.

```cpp
#include "Dralyxor/dralyxor.hpp" // Ajuste o caminho conforme necessário
#include <iostream>

void Configure_Logging() {
    // Chave de formatação de log, usada apenas localmente.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Acesso seguro dentro de um escopo limitado
    {
        // O Secure_Accessor deofusca temporariamente 'log_format_key' durante sua construção
        // (e re-ofusca 'log_format_key' imediatamente após a cópia para seus buffers internos),
        // permite o acesso, e limpa seus próprios buffers na destruição.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Sempre verifique se Get() não retorna nullptr
            std::cout << "Usando formato de log: " << accessor.Get() << std::endl;
            // Ex: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Falha ao decifrar log_format_key (possível tampering ou detecção de debugger?)" << std::endl;
    } // accessor é destruído, seus buffers internos são limpos. log_format_key permanece ofuscado.
      // log_format_key será destruído no final da função Configure_Logging.
}
```

#### Padrão 2: Ofuscação Estática (Global)

Para constantes que precisam persistir durante a vida útil do programa e ser acessadas globalmente.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Para o exemplo

// URL da API de licenças, um segredo persistente.
// A macro DRALYXOR() cria um objeto estático.
// A função Get_License_Server_URL() retorna uma referência a este objeto estático.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref é uma referência ao Obfuscated_String estático.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Cria um Secure_Accessor para url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Contatando servidor de licença em: " << accessor.Get() << std::endl;
            // Ex: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulação de sucesso para o exemplo
        }
        else
            std::cerr << "Falha ao decifrar URL do servidor de licença (possível tampering ou detecção de debugger?)." << std::endl;
    } // accessor é destruído, seus buffers são limpos. url_obj_ref (o Obfuscated_String original) permanece ofuscado.

    return success;
}
```

### Tratamento de Erros e Integridade

As funções `Obfuscated_String::Decrypt()` e `Encrypt()` retornam `uint64_t`:
- `0` indica sucesso.
- `Dralyxor::Detail::integrity_compromised_magic` (uma valor constante definido em `integrity_constants.hpp`) indica que uma verificação de integridade falhou. Isso pode ser devido a canários do objeto corrompidos, checksum do conteúdo inconsistente, ou detecção de um debugger que sinaliza um ambiente hostil.

Da mesma forma, `Secure_Accessor::Get()` (ou sua conversão implícita para `const CharT*`) retornará `nullptr` se a inicialização do `Secure_Accessor` falhar (por exemplo, se a de-criptografia do `Obfuscated_String` original falhar) ou se a integridade do `Secure_Accessor` (seus próprios canários ou checksums internos) for comprometida durante sua vida útil.

**É crucial que seu código verifique esses retornos para garantir a robustez e segurança da aplicação.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Você geralmente NÃO chamaria Decrypt() e Encrypt() diretamente,
    // pois o Secure_Accessor gerencia isso. Mas se precisar por algum motivo:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "ALERTA: Falha ao decifrar 'my_secret' ou integridade comprometida durante Decrypt()!" << std::endl;
        // Tome uma ação apropriada: termine, logue de forma segura, etc.
        // O objeto my_secret.storage_ pode estar em um estado inválido ou com lixo.
        return; // Evite usar my_secret se Decrypt() falhar.
    }

    // Se Decrypt() teve sucesso, my_secret.storage_ contém o dado decifrado.
    // **ACESSO DIRETO A storage_ É FORTEMENTE DESENCORAJADO EM PRODUÇÃO.**
    // std::cout << "Dado em my_secret.storage_ (NÃO FAÇA ISSO): " << my_secret.storage_ << std::endl;

    // É sua responsabilidade re-criptografar se você chamou Decrypt() manualmente:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "ALERTA: Falha ao re-criptografar 'my_secret' ou integridade comprometida durante Encrypt()!" << std::endl;
        // Estado incerto, potencialmente perigoso.
    }

    // USO RECOMENDADO com Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // O construtor do Secure_Accessor chama another_secret.Decrypt(), copia, e depois another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Ou: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Dado secreto via Secure_Accessor: " << data_ptr << std::endl;
            // Use data_ptr aqui
        }
        else {
            std::cerr << "ALERTA: Secure_Accessor falhou ao inicializar ou obter ponteiro para 'another_secret'!" << std::endl;
            // Isso indica que o Decrypt() dentro do construtor do accessor falhou,
            // ou houve tampering no accessor (canários, checksums internos).
        }
    } // accessor é destruído. Seus buffers são limpos. another_secret permanece ofuscada.
}
```

## Filosofia e Arquitetura de Design Detalhada

O **Dralyxor** não é meramente uma cifra XOR; é um sistema de defesa em profundidade para strings literais. Sua arquitetura é fundamentada na premissa de que a segurança eficaz requer múltiplas camadas interconectadas e resiliência contra diversas técnicas de análise.

### A Ameaça Persistente: Vulnerabilidade das Strings Literais

Strings literais, como `"api.example.com/data?key="`, quando embutidas diretamente no código, são gravadas de forma legível (plain text) no binário compilado. Ferramentas como `strings`, desassembladores (IDA Pro, Ghidra) e editores hexadecimais podem extraí-las trivialmente. Esta exposição facilita:
- **Engenharia Reversa:** Compreensão da lógica interna e fluxo do programa.
- **Identificação de Endpoints:** Descoberta de servidores e APIs backend.
- **Extração de Segredos:** Chaves de API, senhas embutidas, URLs privadas, SQL queries, etc.
- **Análise de Memória Dinâmica:** Mesmo que um programa decifre uma string para uso, se ela permanecer em plain text na **RAM** por muito tempo, um atacante com acesso à memória do processo (via depurador ou memory dump) pode encontrá-la.

O **Dralyxor** ataca essas vulnerabilidades tanto em tempo de compilação (para o binário em disco) quanto em tempo de execução (para a memória **RAM**).

### A Solução Arquitetônica Multicamadas do **Dralyxor**

A robustez do **Dralyxor** emana da sinergia de seus componentes chave:

| Componente Arquitetônico                    | Objetivo Primário                                                                      | Tecnologias/Técnicas Chave Empregadas                                                                                                                              |
| :------------------------------------------ | :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Motor de Transformação por Micro-Programa** | Eliminar strings em texto plano do binário; criar ofuscação complexa, dinâmica e não trivial.   | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, múltiplas operações (XOR, ADD, ROT, etc.), NOPs variáveis e lógicos, estilos de aplicadores variáveis.         |
| **Acesso Seguro e Minimização de Exposição** | Reduzir drasticamente o tempo que um segredo fica decifrado na memória RAM.             | Padrão RAII (`Secure_Accessor`), fragmentação de memória, limpeza segura de buffers (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Defesas em Tempo de Execução**              | Detectar e reagir a ambientes de análise hostis e adulteração de memória.            | Detecção de Debuggers (OS-specific APIs, timing, OutputDebugString), canários de integridade do objeto, checksum de conteúdo da string.                              |
| **Geração de Chaves e Sementes Únicas**    | Garantir que cada string ofuscada e cada instância de uso sejam criptograficamente distintas. | `__DATE__`, `__TIME__`, `__COUNTER__`, tamanho da string, hashing FNV-1a para `compile_time_seed`, sementes derivadas para modificadores de operando e seletores. |

## Análise Profunda dos Componentes Arquitetônicos

### Componente 1: O Motor de Transformação por Micro-Programa

O coração da ofuscação estática e dinâmica do **Dralyxor** reside em seu motor de transformação que utiliza "micro-programas" únicos para cada string e contexto.

#### Poder do `consteval` e `constexpr` para Geração em Compilação
O **C++** moderno, com `consteval` (**C++20**) e `constexpr` (**C++11** em diante), permite que código complexo seja executado *durante a compilação*. O **Dralyxor** utiliza `_DRALYXOR_CONSTEVAL` (que mapeia para `consteval` ou `constexpr` dependendo do padrão **C++**) para o construtor `Obfuscated_String` e para a geração do micro-programa.

Isto significa que todo o processo de:
1. Gerar uma sequência pseudoaleatória de instruções de transformação (o micro-programa).
2. Ofuscar o próprio micro-programa para armazenamento.
3. Aplicar esse micro-programa (de forma de-ofuscada temporariamente) para transformar a string original, resultando na sua forma ofuscada.
Tudo isso acontece em tempo de compilação, antes que o binário seja gerado.

#### Anatomia de um Micro-Programa **Dralyxor**

Cada objeto `Obfuscated_String` armazena um pequeno array de `Dralyxor::Detail::Micro_Instruction`. Uma `Micro_Instruction` é uma estrutura simples definida em `algorithms.hpp`:
```cpp
// Em Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM // Embora presente, não é ativamente usado para terminar a execução do micro-programa,
                   // a iteração é controlada pelo 'num_actual_instructions_in_program_'.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // A operação (XOR, ADD, ROTL, etc.)
    uint8_t operand;            // O valor usado pela operação
};

// Número máximo de instruções que um micro-programa pode conter.
static constexpr size_t max_micro_instructions = 8;
```
A função `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` é responsável por preencher este array.

##### Geração Aleatorizada de Instruções e Seleção de Aplicadores

- **Geração de Instruções:** Utilizando um `Dralyxor::Detail::Constexpr_PRNG` (semeado com uma combinação do `compile_time_seed` e `0xDEADBEEFC0FFEEULL`), a função `Generate_Micro_Program_Instructions` escolhe probabilisticamente uma sequência de operações:
   - `XOR`: Bitwise XOR com o operando.
   - `ADD`: Adição modular com o operando.
   - `SUB`: Subtração modular com o operando.
   - `ROTR`/`ROTL`: Rotação de bits. O operando (após módulo) define o número de shifts (1 a 7).
   - `SWAP_NIB`: Troca os 4 bits inferiores com os 4 bits superiores de um byte (operando é ignorado).
    Os operandos para essas instruções também são gerados pseudoaleatoriamente pelo PRNG.

- **Modificação de Operandos e Seleção de Aplicadores em Tempo de Transformação:** Durante a aplicação do micro-programa (por `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), tanto na ofuscação inicial quanto na de-ofuscação em runtime:
   - Um `Constexpr_PRNG prng_operand_modifier` (semeado com `base_seed`) gera uma `prng_key_for_ops_in_elem` para cada caractere da string. O operando da micro-instrução (`instr_orig.operand`) é XORado com esta chave antes de ser usado. Isso garante que o mesmo micro-programa aplique transformações ligeiramente diferentes para cada caractere.
   - Um `Constexpr_PRNG prng_applier_selector` (semeado com `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) escolhe um `Byte_Transform_Applier` para cada caractere. Atualmente existem dois estilos:
      - `Applier_Style_Direct`: Aplica a operação diretamente (invertendo-a para de-criptografia, como ADD torna-se SUB).
      - `Applier_Style_DoubleLayer`: Aplica a operação duas vezes (ou a operação e sua inversa, dependendo do modo de criptografia/de-criptografia) com operandos diferentes, tornando a reversão um pouco mais complexa de analisar.

##### NOPs Variáveis e Lógicos para Entropia

Para aumentar a dificuldade de análise manual do micro-programa, o **Dralyxor** insere:
- **NOPs Explícitos:** Instruções `Micro_Operation_Code::NOP` que não fazem nada.
- **NOPs Lógicos:** Pares de instruções que se anulam mutuamente, como `ADD K` seguido por `SUB K`, ou `ROTL N_BITS` seguido por `ROTR N_BITS`. O operando usado no par é o mesmo.

Esses NOPs são inseridos probabilisticamente pela `Generate_Micro_Program_Instructions`, preenchendo o array `micro_program_` e tornando mais difícil discernir as transformações efetivas das operações de "ruído".

#### Ofuscação do Próprio Micro-Programa

Após a geração do micro-programa e antes da ofuscação inicial da string no construtor `consteval`, o array `micro_program_` (contido no objeto `Obfuscated_String`) é ele mesmo ofuscado. Cada `op_code` e `operand` em cada `Micro_Instruction` é XORado com uma chave derivada do `compile_time_seed` (usando `Detail::Get_Micro_Program_Obfuscation_Key` e `Detail::Obfuscate_Deobfuscate_Instruction`).
Isso significa que, mesmo que um atacante consiga dumpar a memória do objeto `Obfuscated_String`, o micro-programa não estará em sua forma diretamente legível/aplicável.

Quando `Obfuscated_String::Decrypt()` ou `Encrypt()` são chamados (ou indiretamente pelo `Secure_Accessor`), a função central `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` recebe este micro-programa *ofuscado*. Ela então:
1. Cria uma cópia temporária do micro-programa (`local_plain_program`) na stack.
2. De-ofusca esta cópia local usando a mesma chave (`program_obf_key`) derivada da semente base passada (que é, em última análise, o `compile_time_seed`).
3. Utiliza este `local_plain_program` para transformar os dados da string.
A cópia local na stack é destruída ao final da função, e o `micro_program_` armazenado no objeto `Obfuscated_String` permanece ofuscado.

#### O Ciclo de Vida da Ofuscação Estática

1. **Código-Fonte:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Pré-Processamento:** O macro expande para uma instanciação `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (O tamanho 15 inclui o terminador nulo).
3. **Avaliação `_DRALYXOR_CONSTEVAL`:**
   - O compilador executa o construtor `Obfuscated_String`.
   - `Initialize_Internal_Canaries()` define os canários de integridade.
   - `Generate_Micro_Program_Instructions()` (semeado com `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) cria uma sequência de `Micro_Instruction` e armazena em `this->micro_program_` (ex: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). O número real de instruções é armazenado em `num_actual_instructions_in_program_`.
   - A string original "SECRET\_API\_KEY" é copiada para `this->storage_`.
   - Um checksum da string original "SECRET\_API\_KEY" (excluindo o nulo) é calculado por `Detail::Calculate_String_Content_Checksum` e depois ofuscado por `Detail::Obfuscate_Deobfuscate_Short_Value` (usando `compile_time_seed` e `content_checksum_obf_salt`) e armazenado em `this->_content_checksum_obfuscated`.
   - `Obfuscate_Internal_Micro_Program()` é chamada: o `this->micro_program_` é ofuscado no local (cada instrução XORada com `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` é chamada. Esta função:
      - Cria uma cópia de-ofuscada do `this->micro_program_` na stack.
      - Para cada caractere em `storage_` (exceto o nulo):
          - Gera `prng_key_for_ops_in_elem` e seleciona um `Byte_Transform_Applier`.
          - Aplica a sequência de micro-instruções (da cópia de-ofuscada) ao caractere, usando o aplicador e o operando modificado.
      - Ao final, `storage_` contém a string ofuscada (ex: `[CF, 3A, D1, ..., 0x00]`).
4. **Geração de Código:** O compilador aloca espaço para `api_key_obj` e o inicializa diretamente com:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (string ofuscada).
   - `micro_program_`: O micro-programa *já ofuscado*.
   - `_content_checksum_obfuscated`: O checksum do conteúdo original, *ofuscado*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    O literal `"SECRET_API_KEY"` não existe mais no binário.

### Componente 2: Acesso Seguro e Minimização de Exposição em **RAM**

#### O `Secure_Accessor` e o Princípio RAII

A proteção em tempo de compilação é apenas metade da batalha. Uma vez que a string precisa ser usada, ela deve ser decifrada. Se essa string decifrada permanecer na memória **RAM** por um período prolongado, ela se torna um alvo para análise dinâmica (memory dumps, debuggers).

O **Dralyxor** aborda isso com o `Dralyxor::Secure_Accessor`, uma classe que implementa o padrão **RAII** (Resource Acquisition Is Initialization):
- **Recurso Adquirido:** O acesso temporário à string em plain text, fragmentada e gerenciada pelo accessor.
- **Objeto Gerenciador:** A instância de `Secure_Accessor`.

```cpp
// Em secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Inicializar diferentes para falhar se não atualizado
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalida o accessor

            return;
        }

        // 1. Tenta decifrar o Obfuscated_String original.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Se a decifragem for bem-sucedida, copia a string plaintext para os fragmentos internos.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ agora está em plaintext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val é no máximo 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Preenche o resto do buffer do fragmento com nulos
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksum dos fragmentos
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Re-criptografa IMEDIATAMENTE o Obfuscated_String original.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Limpa fragmentos e buffer reconstruído.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Verifica a si mesmo e ao pai
            Clear_All_Internal_Buffers(); // Medida de segurança
            _accessor_integrity_canary1 = 0; // Invalida para acessos futuros

            return nullptr;
        }

        if (!current_access_ptr_) { // Se é a primeira chamada a Get() ou se foi limpo
            if constexpr (N_storage > 0) { // Somente reconstrói se houver algo para reconstruir
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

                // Garante terminação nula, mesmo que N_storage seja exatamente preenchido.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Para N_storage == 0 (string vazia, teoricamente), não há checksums
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Para passar na checagem

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // se N_storage era 0, este é seguro se o buffer for > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Verifica novamente após qualquer operação interna para garantir a integridade.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Fluxo de Uso com `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - O construtor de `Secure_Accessor` é chamado.
   - Ele chama `my_obfuscated_string.Decrypt()`. Isso envolve de-ofuscar o `micro_program_` (para uma cópia local), usá-lo para decifrar `my_obfuscated_string.storage_`, e então verificar canários e o checksum do conteúdo decifrado contra o esperado.
   - Se bem-sucedido, o conteúdo de `my_obfuscated_string.storage_` (agora plain text) é copiado e dividido nos `fragments_storage_` internos do `Secure_Accessor`.
   - Um checksum dos `fragments_storage_` (`fragments_data_checksum_expected_`) é calculado.
   - Crucialmente, `my_obfuscated_string.Encrypt()` é chamado *imediatamente depois*, re-ofuscando `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (ou `const char* ptr = accessor;` devido à conversão implícita)
   - `Secure_Accessor::Get()` é chamado.
   - Ele verifica seus próprios canários de integridade e os do `Obfuscated_String` pai.
   - Se for o primeiro acesso (`current_access_ptr_` é `nullptr`), ele reconstrói a string completa em `reconstructed_plain_buffer_` a partir dos `fragments_storage_`.
   - Ele então verifica `fragments_data_checksum_reconstructed_` contra `fragments_data_checksum_expected_` para garantir que os fragmentos não foram adulterados enquanto o `Secure_Accessor` existia.
   - Se tudo estiver correto, retorna um ponteiro para `reconstructed_plain_buffer_`.
3. O escopo do `accessor` termina (sai da função, bloco `{}` termina, etc.).
   - O destrutor de `Secure_Accessor` é chamado automaticamente.
   - `Clear_All_Internal_Buffers()` é invocado, que limpa de forma segura (`Secure_Clear_Memory`) tanto o `reconstructed_plain_buffer_` quanto os `fragments_storage_`.

O resultado é que a string em plain text existe na forma completa apenas dentro do `Secure_Accessor` (no `reconstructed_plain_buffer_`) e somente após a primeira chamada a `Get()`, pelo menor tempo possível. A string no objeto `Obfuscated_String` original é re-ofuscada assim que o `Secure_Accessor` copia seu conteúdo durante a construção.

#### Fragmentação de Memória no `Secure_Accessor`

Para dificultar ainda mais a localização da string completa em plain text na memória, o `Secure_Accessor`, durante sua construção, não apenas copia a string decifrada, mas a divide:
1. A string do `Obfuscated_String` pai é decifrada.
2. Seu conteúdo é dividido em até `fragment_count_val` (atualmente 4, se a string for grande o suficiente) pedaços, que são copiados para `fragments_storage_[i]`.
3. A string no objeto `Obfuscated_String` pai é re-ofuscada.

Somente quando `Secure_Accessor::Get()` é chamado pela primeira vez é que esses fragmentos são re-montados no `reconstructed_plain_buffer_`. Esta técnica visa "espalhar" os dados sensíveis, frustrando varreduras de memória que buscam por strings contínuas.

#### Limpeza Segura de Memória

Tanto o destrutor de `Obfuscated_String` (via `Clear_Internal_Data`) quanto o destrutor de `Secure_Accessor` (via `Clear_All_Internal_Buffers`) utilizam `Dralyxor::Detail::Secure_Clear_Memory` (template para arrays) ou `Dralyxor::Detail::Secure_Clear_Memory_Raw` (para ponteiros brutos, embora `Secure_Clear_Memory` seja mais usado nos destrutores). Esta função wrapper:
- Usa `SecureZeroMemory` (Windows User Mode) ou `RtlSecureZeroMemory` (Windows Kernel Mode) quando disponíveis, que são funções do sistema operacional projetadas para não serem otimizadas pelo compilador.
- Recorre a um loop com um ponteiro `volatile T* p` em outras plataformas ou quando as funções específicas do Windows não estão disponíveis. O `volatile` é uma tentativa de instruir o compilador a não otimizar a escrita de zeros. Isso garante que, quando os objetos são destruídos ou os buffers são explicitamente limpos, o conteúdo sensível é sobrescrito, reduzindo o risco de recuperação de dados.

### Componente 3: Defesas em Tempo de Execução (Anti-Debugging e Anti-Tampering)

O **Dralyxor** não confia apenas na ofuscação. Ele emprega um conjunto de defesas ativas em tempo de execução, localizadas principalmente em `anti_debug.hpp` e integradas nos métodos `Decrypt()` e `Encrypt()` do `Obfuscated_String`.

#### Detecção Multi-Plataforma de Debuggers

A função `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (em `anti_debug.hpp`) verifica a presença de um depurador usando técnicas específicas do sistema operacional:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` para `ProcessDebugPort` (0x07) e `ProcessDebugFlags` (0x1F).
- **Linux:** Leitura de `/proc/self/status` e checagem do valor de `TracerPid:`. Um valor diferente de 0 indica que o processo está sendo rastreado.
- **macOS:** Uso de `sysctl` com `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` para obter `kinfo_proc` e checagem do flag `P_TRACED` em `kp_proc.p_flag`.

Adicionalmente, dentro de `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Executa um loop de operações computacionais simples e mede o tempo. Uma lentidão significativa (acima de `timing_threshold_milliseconds = 75ms`) pode indicar que um depurador está em single-stepping ou que breakpoints extensivos estão ativos. Dentro deste loop, `Is_Debugger_Present_Tracer_Pid_Sysctl()` é chamado, e uma função "isca" `Detail::Canary_Function_For_Breakpoint_Check()` (que simplesmente retorna `0xCC`, o código de instrução para `int3` / breakpoint de software) é chamada e seu resultado é XORado, dificultando a otimização e fornecendo um local comum para breakpoints.
- `Detail::Perform_Output_Debug_String_Trick()` (apenas Windows User Mode): Usa o comportamento de `OutputDebugStringA/W` e `GetLastError()`. Se um depurador está anexado, `GetLastError()` pode ser modificado após a chamada a `OutputDebugString`.

#### Impacto na Operação em Caso de Detecção ou Violação de Integridade

Se qualquer uma das verificações anti-debugging retornar `true`, ou se os canários de integridade do `Obfuscated_String` (`_internal_integrity_canary1/2`) estiverem corrompidos, a função `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` retornará `Detail::integrity_compromised_magic`.

Este valor retornado é crucial nas funções `Obfuscated_String::Decrypt()` e `Encrypt()`:
```cpp
// Lógica simplificada de Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canários do Obfuscated_String
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
        // ... Verificar canários novamente ...

        // SE runtime_key_mod NÃO É integrity_compromised_magic, ELE NÃO É USADO PARA MUDAR A CHAVE DE DECRYPÇÃO.
        // A chave de decrypção é sempre derivada do 'compile_time_seed' original.
        // O papel do runtime_key_mod aqui é ATUAR COMO UM SINALIZADOR de ambiente hostil.
        // Se hostil, a função retorna integrity_compromised_magic e a decifragem não prossegue ou é revertida.
        
        // Transform_Compile_Time_Consistent é chamada com compile_time_seed (e NÃO com runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Verificar checksum e canários novamente ...
        // Se algo falhar, Clear_Internal_Data() e retorna integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Sucesso
}
```

**Efeito Chave:** Se `Calculate_Runtime_Key_Modifier` detecta um problema (debugger ou canário corrompido) e retorna `integrity_compromised_magic`, as funções `Decrypt()` (e similarmente `Encrypt()`) abortam a operação, limpam os dados internos do `Obfuscated_String` (incluindo `storage_` e `micro_program_`), e retornam `integrity_compromised_magic`. Isso impede que a string seja corretamente decifrada (ou re-cifrada) em um ambiente hostil ou se o objeto foi adulterado.
A string não é decifrada "incorretamente" (para lixo); a operação é simplesmente impedida, e o objeto `Obfuscated_String` se auto-destrói em termos de conteúdo útil.

#### Canários de Integridade do Objeto

Ambas as classes `Obfuscated_String` e `Secure_Accessor` contêm membros canário (pares de `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (inicializado com `Detail::integrity_canary_value`) e `_internal_integrity_canary2` (inicializado com `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (inicializado com `Detail::accessor_integrity_canary_seed`) e `_accessor_integrity_canary2` (inicializado com `~Detail::accessor_integrity_canary_seed`).

Esses canários são verificados em pontos críticos:
- Início e fim de `Obfuscated_String::Decrypt()` e `Encrypt()`.
- Construtor, destrutor e `Get()` do `Secure_Accessor`.
- Antes e depois das verificações anti-debug em `Calculate_Runtime_Key_Modifier`.

Se esses valores canário forem alterados (por exemplo, por um buffer overflow, um patch de memória indiscriminado, ou um hook que sobrescreva memória adjacente), a verificação (`Verify_Internal_Canaries()` ou `Verify_Internal_Accessor_Canaries()`) falhará.
Em caso de falha, as operações são abortadas, os dados internos relevantes são limpos, e um valor de erro (`Detail::integrity_compromised_magic` ou `nullptr`) é retornado, sinalizando adulteração.

#### Checksum de Conteúdo da String

- Um checksum de 16 bits da string *original em plain text* (excluindo o terminador nulo) é calculado por `Detail::Calculate_String_Content_Checksum` em tempo de compilação.
- Este checksum é então ofuscado usando `Detail::Obfuscate_Deobfuscate_Short_Value` (com `compile_time_seed` e `content_checksum_obf_salt`) e armazenado em `_content_checksum_obfuscated` no objeto `Obfuscated_String`.
- **Ao Decifrar (`Decrypt()`):** Após `storage_` ser transformado (supostamente para plain text), seu checksum é calculado. O `_content_checksum_obfuscated` é de-ofuscado para obter o checksum de referência. Se os dois checksums não baterem, indica que:
   - A decifragem não restaurou a string original (talvez porque a operação foi abortada devido à detecção de debugger antes da transformação completa, ou houve corrupção da semente/microprograma).
   - O `storage_` (quando ofuscado) ou o `_content_checksum_obfuscated` foram adulterados na memória.
- **Ao Cifrar (`Encrypt()`):** Antes de `storage_` (que está em plain text neste ponto) ser transformado de volta para sua forma ofuscada, seu checksum é calculado e comparado com o de referência. Uma divergência aqui significaria que a string em plain text foi alterada *dentro do `storage_` do `Obfuscated_String` enquanto estava decifrada*, o que é uma forte indicação de adulteração da memória ou uso indevido (já que o acesso ao `storage_` não deve ser feito diretamente).

Em ambos os casos de falha de checksum, `Clear_Internal_Data()` é chamado e `integrity_compromised_magic` é retornado.

### Componente 4: Geração de Chaves e Sementes Únicas e Imprevisíveis

A segurança de qualquer sistema de cifragem repousa na força e unicidade de suas chaves e sementes. O **Dralyxor** garante que cada string ofuscada utilize um conjunto de parâmetros de cifragem fundamentalmente único.

#### Fontes de Entropia para o `compile_time_seed`

O `static constexpr uint64_t Obfuscated_String::compile_time_seed` é a semente mestra para todas as operações pseudoaleatórias relativas àquela instância da string. Ele é gerado em `consteval` da seguinte forma:
```cpp
// Dentro de Obfuscated_String<CharT, storage_n, Instance_Counter>
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Componente 1: Variabilidade entre compilações
    ((uint64_t)Instance_Counter << 32) ^        // Componente 2: Variabilidade dentro de uma unidade de compilação
    storage_n;                                  // Componente 3: Variabilidade baseada no tamanho da string
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: O macro `__DATE__` (ex: "Jan 01 2025") e `__TIME__` (ex: "12:30:00") são strings fornecidas pelo pré-processador que mudam cada vez que o arquivo é compilado. O hash FNV-1a desses valores cria uma base de seed que é diferente para cada build do projeto.
- **`Instance_Counter` (alimentado por `__COUNTER__` na macro `DRALYXOR`/`DRALYXOR_LOCAL`)**: O macro `__COUNTER__` é um contador mantido pelo pré-processador que incrementa cada vez que é usado dentro de uma unidade de compilação. Ao passar isso como um argumento de template `int Instance_Counter` para `Obfuscated_String`, cada uso do macro `DRALYXOR` ou `DRALYXOR_LOCAL` resultará em um `Instance_Counter` diferente e, portanto, um `compile_time_seed` diferente, mesmo para strings literais idênticas no mesmo arquivo de origem.
- **`storage_n` (tamanho da string incluindo o nulo)**: O tamanho da string também é XORado, adicionando mais um fator de diferenciação.

Este `compile_time_seed` é então usado como base para:
1. Gerar o `micro_program_` (semeando o PRNG com `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Derivar a chave de ofuscação para o próprio `micro_program_` (via `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Derivar a chave de ofuscação para o `_content_checksum_obfuscated` (via `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Servir como `base_seed` para `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Sementes Derivadas para Transformações de Conteúdo

Dentro de `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Um `Constexpr_PRNG prng_operand_modifier(base_seed)` é inicializado. Para cada caractere da string sendo transformado, `prng_operand_modifier.Key()` produz uma `prng_key_for_ops_in_elem`. Esta chave é XORada com o operando da micro-instrução antes da aplicação, garantindo que o efeito da mesma micro-instrução seja sutilmente diferente para cada caractere.
- Um `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` é inicializado. Para cada caractere, `prng_applier_selector.Key()` é usado para escolher entre `Applier_Style_Direct` e `Applier_Style_DoubleLayer`.

Isso introduz um dinamismo adicional na transformação de cada caractere, mesmo que o micro-programa subjacente seja o mesmo para todos os caracteres de uma dada string.

#### Imunidade Contra Ataques de "Replay" e Análise de Padrões

- **Unicidade Inter-Compilação:** Se um atacante analisar o binário da versão 1.0 do seu software e, com muito esforço, conseguir quebrar a ofuscação de uma string, essa conhecimento será provavelmente inútil para a versão 1.1, pois o `__DATE__ __TIME__` terá mudado, resultando em `compile_time_seed`s e micro-programas completamente diferentes.
- **Unicidade Intra-Compilação:** Se você usar `DRALYXOR("AdminPassword")` em dois lugares diferentes no seu código (ou no mesmo arquivo .cpp), o `__COUNTER__` garantirá que os objetos `Obfuscated_String` resultantes, e portanto suas representações ofuscadas no binário (tanto o `storage_` quanto o `micro_program_`), sejam diferentes. Isso impede que um atacante encontre um padrão ofuscado e o use para localizar todas as outras ocorrências da mesma string original, ou use um micro-programa descoberto para decifrar outras strings.

Esta geração robusta de sementes é uma pedra angular da segurança do **Dralyxor** contra ataques que dependem de descobrir um "segredo mestre" ou de explorar a repetição de cifras e transformações.

## Referência Completa da API Pública

### Macros de Ofuscação

Estes são os principais pontos de entrada para criar strings ofuscadas.

#### `DRALYXOR(str_literal)`

- **Propósito:** Cria um objeto `Obfuscated_String` com tempo de vida estático (existe durante toda a execução do programa). Ideal para constantes globais ou strings que precisam ser acessadas de múltiplos locais e persistir.
- **Armazenamento:** Memória estática (normalmente na seção de dados do programa).
- **Implementação (simplificada):**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           /* A macro __COUNTER__ garante um Instance_Counter único para cada uso */ \
           /* decltype(*str_literal) infere o tipo de caractere (char, wchar_t) */ \
           /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) calcula o tamanho incluindo o nulo */ \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
               typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
               (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
               __COUNTER__ \
           >(str_literal); \
           return obfuscated_static_string; \
       }()
   ```

- **Parâmetros:**
   - `str_literal`: Um literal de string C-style (e.g., `"Hello World"`, `L"Unicode String"`).
- **Retorno:** Uma referência (`auto&`) ao objeto `Obfuscated_String` estático, criado dentro de uma lambda imediatamente invocada.
- **Exemplo:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url é uma referência a um Obfuscated_String estático.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Propósito:** Cria um objeto `Obfuscated_String` com tempo de vida automático (normalmente na stack, se usado dentro de uma função). Ideal para segredos temporários confinados a um escopo.
- **Armazenamento:** Automático (stack para variáveis locais de função).
- **Implementação (simplificada):**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) \
       Dralyxor::Obfuscated_String< \
           typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
           (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
           __COUNTER__ \
       >(str_literal)
   ```
- **Parâmetros:**
   - `str_literal`: Um literal de string C-style.
- **Retorno:** Um objeto `Obfuscated_String` por valor (que pode ser otimizado com RVO/NRVO pelo compilador).
- **Exemplo:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... usar temp_key com DRALYXOR_SECURE ...
   } // temp_key é destruído aqui, seu destrutor chama Clear_Internal_Data().
   ```

### Macro de Acesso Seguro

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Propósito:** Fornece acesso seguro e temporário ao conteúdo decifrado de um objeto `Obfuscated_String`. Este é o **único método recomendado** para ler a string.
- **Implementação (simplificada):**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) \
       Dralyxor::Secure_Accessor< \
           typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
       >(obfuscated_var)
   ```

- **Parâmetros:**
   - `obfuscated_var`: Uma variável (lvalue ou rvalue que possa ser vinculado a uma referência lvalue não-const) do tipo `Dralyxor::Obfuscated_String<...>`. A variável precisa ser mutável porque o construtor do `Secure_Accessor` chama `Decrypt()` e `Encrypt()` nela.
- **Retorno:** Um objeto `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` por valor.
- **Uso:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Ou apenas: const char* secret_ptr = accessor; (conversão implícita)
       
       if (secret_ptr) {
           // Use secret_ptr aqui. Ele aponta para a string decifrada temporariamente no buffer do accessor.
           // Ex: send_data(secret_ptr);
       }
       else {
           // Falha na decriptografia ou integridade. Trate o erro.
           // O accessor pode ter falhado ao inicializar (e.g., my_static_secret foi corrompido).
       }
   } // accessor é destruído. Seus buffers internos (fragmentos e string reconstruída) são limpos.
    // O my_static_secret.storage_ já foi re-ofuscado pelo construtor do Secure_Accessor
    // logo após copiar o conteúdo para os fragmentos do accessor.
   ```

> [!WARNING]
> Sempre verifique se o ponteiro retornado por `DRALYXOR_SECURE(...).Get()` (ou pela conversão implícita) não é `nullptr` antes de usá-lo. Um retorno `nullptr` indica uma falha na decriptografia (por exemplo, detecção de debugger, corrupção de canários/checksums no `Obfuscated_String` pai ou no próprio `Secure_Accessor`). O uso de um ponteiro `nullptr` resultará em comportamento indefinido (provavelmente uma falha de segmentação).

## Recursos Avançados e Boas Práticas

### Suporte Total a Unicode (Wide Strings - `wchar_t`)

O **Dralyxor** é agnóstico ao tipo de caractere graças ao uso de templates (`CharT`). Ele lida nativamente com `char` (para strings ASCII/UTF-8) e `wchar_t` (para strings UTF-16 no Windows ou UTF-32 em outros sistemas, dependendo da plataforma e do compilador). Basta usar o prefixo `L` para literais `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Mensagem Unicode: Olá Mundo Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Exemplo no Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Título Unicode", MB_OK);
        // Exemplo com wcout:
        // #include <io.h> // Para _setmode no Windows com MSVC
        // #include <fcntl.h> // Para _O_U16TEXT no Windows com MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Configura stdout para UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Para caracteres de 1 byte (`sizeof(CharT) == 1`), o motor de transformação `Micro_Program_Cipher` aplica o micro-programa byte a byte. Para caracteres multibyte (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` usa uma abordagem mais simples: o caractere multibyte inteiro é XORado com uma máscara derivada da `prng_key_for_ops_in_elem` (replicada para preencher o tamanho do `CharT`). Por exemplo, se `CharT` é `wchar_t` (2 bytes) e `prng_key_for_ops_in_elem` é `0xAB`, o caractere será XORado com `0xABAB`.
Isso garante que todos os bytes do `wchar_t` sejam afetados pela ofuscação, mesmo que não seja pelo micro-programa completo. A complexidade do micro-programa ainda contribui indiretamente através da derivação das chaves do PRNG.

### Adaptação Inteligente aos Padrões **C++** e Ambientes (Kernel Mode)

Conforme mencionado, o **Dralyxor** se adapta:
- **Padrões C++:** Requer no mínimo **C++14**. Detecta e utiliza recursos de **C++17** e **C++20** (como `if constexpr`, `consteval`, sufixos `_v` para `type_traits`) quando o compilador os suporta, recorrendo a alternativas **C++14** caso contrário. Macros como `_DRALYXOR_IF_CONSTEXPR` e `_DRALYXOR_CONSTEVAL` em `detection.hpp` gerenciam essa adaptação.
- **Kernel Mode:** Quando `_KERNEL_MODE` é definido (típico em projetos WDK para drivers do Windows), o **Dralyxor** (via `env_traits.hpp`) evita incluir cabeçalhos padrão da STL como `<type_traits>` que podem não estar disponíveis ou se comportar de forma diferente. Em vez disso, ele usa suas próprias implementações `constexpr` de ferramentas básicas como `Dralyxor::Detail::Fallback::decay` e `Dralyxor::Detail::Fallback::remove_reference`. Isso permite o uso seguro do **Dralyxor** para proteger strings em componentes de sistema de baixo nível.
   - Similarmente, `secure_memory.hpp` usa `RtlSecureZeroMemory` em Kernel Mode.
   - As verificações anti-debug de User Mode (como `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) são desabilitadas (`#if !defined(_KERNEL_MODE)`) em Kernel Mode, pois não se aplicam ou têm equivalentes diferentes. As checagens de timing ainda podem ter algum efeito, mas a principal linha de defesa em Kernel Mode é a ofuscação em si.

### Considerações de Performance e Overhead

- **Tempo de Compilação:** A ofuscação, incluindo a geração e aplicação de micro-programas, ocorre inteiramente em tempo de compilação. Para projetos com um número muito grande de strings ofuscadas, o tempo de compilação pode aumentar. Este é um custo único por compilação.
- **Tamanho do Binário:** Cada `Obfuscated_String` adiciona seu `storage_` (tamanho da string), o `micro_program_` (fixo em `max_micro_instructions * sizeof(Micro_Instruction)`), mais alguns bytes para canários, checksum e flags. Pode haver um aumento no tamanho do binário comparado a strings literais puras, especialmente para muitas strings pequenas.
- **Tempo de Execução (Runtime):**
   - **Criação de `Obfuscated_String` (objetos estáticos ou locais):** Ocorre em tempo de compilação (para estáticos) ou envolve uma cópia de dados pré-computados (para locais, otimizável por RVO). Não há custo de "geração" em runtime.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Verificações de canários (extremamente rápidas).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Inclui as checagens anti-debug. A checagem de timing (`Perform_Timing_Check_Generic`) é a mais custosa aqui, executando um loop. As outras são chamadas de API ou leituras de arquivo (Linux).
      - De-ofuscação do micro-programa (cópia e XOR, rápido).
      - Transformação da string: Loop sobre os `N_data_elements_to_transform`, e dentro dele, loop sobre `num_actual_instructions_in_program_`. Para cada instrução, uma chamada ao `Byte_Transform_Applier` que faz algumas operações de byte. Custo é O(comprimento\_da\_string \* num\_instruções).
      - Cálculo/Verificação de checksum (`Detail::Calculate_String_Content_Checksum`): O(comprimento\_da\_string \* sizeof(CharT)).
   - **Criação de `Secure_Accessor`:**
      - Chama `Obfuscated_String::Decrypt()`.
      - Copia string para fragmentos: O(comprimento\_da\_string).
      - Calcula checksum de fragmentos (`Calculate_Current_Fragments_Checksum`): O(comprimento\_da\_string).
      - Chama `Obfuscated_String::Encrypt()`. Este é o ponto de maior concentração de overhead em uma única operação de acesso.
   - **`Secure_Accessor::Get()`:**
      - Primeira chamada: Verifica canários, reconstrói string dos fragmentos (O(comprimento\_da\_string)), verifica checksum dos fragmentos.
      - Chamadas subsequentes (para o mesmo objeto `Secure_Accessor`): Verifica canários (rápido) e retorna ponteiro já calculado (O(1)).
- **Overhead Geral:** Para a maioria das aplicações, onde strings sensíveis não são acessadas em loops de altíssima frequência, o overhead de runtime é geralmente aceitável, especialmente considerando o benefício de segurança. O design do `Secure_Accessor` (criado apenas quando necessário e com escopo estritamente limitado pelo RAII) é fundamental para gerenciar esse custo. Teste em seu ambiente específico se a performance for crítica.

### Integração em uma Estratégia de Segurança em Camadas

> [!IMPORTANT]
> **Dralyxor** é uma ferramenta poderosa de **ofuscação de strings embutidas e defesa contra análise de memória**, não uma solução de criptografia genérica para armazenamento persistente de dados em disco ou transmissão segura pela rede.
>
> Ele deve ser usado como **uma das muitas camadas** em uma estratégia de segurança abrangente. Nenhuma ferramenta isolada é uma bala de prata. Outras medidas a considerar incluem:
> - **Minimizar Segredos Embutidos:** Sempre que possível, evite embutir segredos de altíssima criticidade. Utilize alternativas como:
>    - Configurações seguras fornecidas em runtime (variáveis de ambiente, arquivos de configuração com permissões restritas).
>    - Serviços de gerenciamento de segredos (vaults) como HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Validação de entrada robusta em todas as interfaces.
> - Princípio do menor privilégio para processos e usuários.
> - Comunicação de rede segura (TLS/SSL com pinning de certificado, se aplicável).
> - Hashing seguro de senhas de usuário (Argon2, scrypt, bcrypt).
> - Proteção do binário como um todo com outras técnicas anti-reversing/anti-tampering (packers, virtualizadores de código, verificações de integridade do código), ciente dos trade-offs que estas podem introduzir (falsos positivos de antivírus, complexidade).
> - Boas práticas de desenvolvimento seguro (Secure SDLC).

O **Dralyxor** foca em resolver um problema específico e comum muito bem: a proteção de strings literais embutidas contra análise estática e a minimização da sua exposição em memória durante a execução, dificultando a vida de quem tenta fazer engenharia reversa no seu software.

## Licença

Esta biblioteca está protegido sob a Licença MIT, que permite:

- ✔️ Uso comercial e privado
- ✔️ Modificação do código fonte
- ✔️ Distribuição do código
- ✔️ Sublicenciamento

### Condições:

- Manter o aviso de direitos autorais
- Incluir cópia da licença MIT

Para mais detalhes sobre a licença: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Todos os direitos reservados**