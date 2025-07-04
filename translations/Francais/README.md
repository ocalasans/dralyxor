# Dralyxor

**Dralyxor** est une bibliothèque **C++** moderne, `header-only` (uniquement en en-têtes), haute performance et multicouche, conçue pour l'obfuscation de chaînes de caractères au moment de la compilation et une protection robuste au moment de l'exécution. Sa mission fondamentale est de protéger les secrets intrinsèques de votre application — tels que les clés API, les mots de passe, les URL internes, les messages de débogage et tout littéral de chaîne sensible — contre l'exposition par analyse statique, ingénierie inverse et inspection de la mémoire dynamique. En chiffrant et en transformant les chaînes au moment de la compilation et en gérant leur accès de manière sécurisée à l'exécution, **Dralyxor** garantit qu'aucun littéral de chaîne critique n'existe en texte clair dans votre binaire final ou ne reste non protégé en mémoire plus longtemps que strictement nécessaire.

Construit sur les fondations du **C++** moderne (nécessitant **C++14** et s'adaptant intelligemment aux fonctionnalités de **C++17** et **C++20**), son architecture avancée présente un moteur de transformation sophistiqué basé sur des "micro-programmes", l'obfuscation du programme de transformation lui-même, des mécanismes d'intégrité des données, des défenses anti-débogage, et un **Accesseur à Portée Sécurisée (RAII)** pour un déchiffrement "juste-à-temps" et une ré-obfuscation automatique. Cela minimise considérablement l'exposition des données en mémoire **RAM** et fournit une défense en profondeur de niveau professionnel.

## Langues

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Table des matières

- [Dralyxor](#dralyxor)
  - [Langues](#langues)
  - [Table des matières](#table-des-matières)
  - [Guide d'Intégration et d'Utilisation Rapide](#guide-dintégration-et-dutilisation-rapide)
    - [Installation](#installation)
    - [Prérequis du Compilateur](#prérequis-du-compilateur)
    - [Modèles d'Utilisation Essentiels](#modèles-dutilisation-essentiels)
      - [Modèle 1: Obfuscation Locale (Stack)](#modèle-1-obfuscation-locale-stack)
      - [Modèle 2: Obfuscation Statique (Globale)](#modèle-2-obfuscation-statique-globale)
      - [Modèle 3: Obfuscation avec une Clé Fournie par l'Utilisateur](#modèle-3-obfuscation-avec-une-clé-fournie-par-lutilisateur)
    - [Gestion des Erreurs et Intégrité](#gestion-des-erreurs-et-intégrité)
  - [Philosophie et Architecture de Conception Détaillée](#philosophie-et-architecture-de-conception-détaillée)
    - [La Menace Persistante: Vulnérabilité des Chaînes Littérales](#la-menace-persistante-vulnérabilité-des-chaînes-littérales)
    - [La Solution Architecturale Multicouche de **Dralyxor**](#la-solution-architecturale-multicouche-de-dralyxor)
  - [Analyse Approfondie des Composants Architecturaux](#analyse-approfondie-des-composants-architecturaux)
    - [Composant 1: Le Moteur de Transformation par Micro-Programme](#composant-1-le-moteur-de-transformation-par-micro-programme)
      - [Puissance de `consteval` et `constexpr` pour la Génération à la Compilation](#puissance-de-consteval-et-constexpr-pour-la-génération-à-la-compilation)
      - [Anatomie d'un Micro-Programme **Dralyxor**](#anatomie-dun-micro-programme-dralyxor)
        - [Génération Aléatoire d'Instructions et Sélection d'Applicateurs](#génération-aléatoire-dinstructions-et-sélection-dapplicateurs)
        - [NOPs Variables et Logiques pour l'Entropie](#nops-variables-et-logiques-pour-lentropie)
      - [Obfuscation du Micro-Programme lui-même](#obfuscation-du-micro-programme-lui-même)
      - [Le Cycle de Vie de l'Obfuscation Statique](#le-cycle-de-vie-de-lobfuscation-statique)
    - [Composant 2: Accès Sécurisé et Minimisation de l'Exposition en RAM](#composant-2-accès-sécurisé-et-minimisation-de-lexposition-en-ram)
      - [Le `Secure_Accessor` et le Principe RAII](#le-secure_accessor-et-le-principe-raii)
      - [Fragmentation de la Mémoire dans le `Secure_Accessor`](#fragmentation-de-la-mémoire-dans-le-secure_accessor)
      - [Nettoyage Sécurisé de la Mémoire](#nettoyage-sécurisé-de-la-mémoire)
    - [Composant 3: Défenses à l'Exécution (Anti-Débogage et Anti-Falsification)](#composant-3-défenses-à-lexécution-anti-débogage-et-anti-falsification)
      - [Détection Multi-Plateforme de Débogueurs](#détection-multi-plateforme-de-débogueurs)
      - [Impact sur l'Opération en Cas de Détection ou de Violation d'Intégrité](#impact-sur-lopération-en-cas-de-détection-ou-de-violation-dintégrité)
      - [Canaris d'Intégrité de l'Objet](#canaris-dintégrité-de-lobjet)
      - [Checksum du Contenu de la Chaîne](#checksum-du-contenu-de-la-chaîne)
    - [Composant 4: Génération de Clés et de Graines Uniques et Imprévisibles](#composant-4-génération-de-clés-et-de-graines-uniques-et-imprévisibles)
      - [Sources d'Entropie pour le `compile_time_seed`](#sources-dentropie-pour-le-compile_time_seed)
      - [Graines Dérivées pour les Transformations de Contenu](#graines-dérivées-pour-les-transformations-de-contenu)
      - [Immunité Contre les Attaques de "Replay" et l'Analyse de Motifs](#immunité-contre-les-attaques-de-replay-et-lanalyse-de-motifs)
  - [Référence Complète de l'API Publique](#référence-complète-de-lapi-publique)
    - [Macros d'Obfuscation](#macros-dobfuscation)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Macro d'Accès Sécurisé](#macro-daccès-sécurisé)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Fonctionnalités Avancées et Bonnes Pratiques](#fonctionnalités-avancées-et-bonnes-pratiques)
    - [Prise en Charge Complète d'Unicode (Chaînes Larges - `wchar_t`)](#prise-en-charge-complète-dunicode-chaînes-larges---wchar_t)
    - [Adaptation Intelligente aux Standards **C++** et aux Environnements (Kernel Mode)](#adaptation-intelligente-aux-standards-c-et-aux-environnements-kernel-mode)
    - [Considérations de Performance et de Surcoût](#considérations-de-performance-et-de-surcoût)
    - [Intégration dans une Stratégie de Sécurité en Couches](#intégration-dans-une-stratégie-de-sécurité-en-couches)
  - [Licence](#licence)
    - [Conditions:](#conditions)

## Guide d'Intégration et d'Utilisation Rapide

### Installation

**Dralyxor** est une bibliothèque **header-only**. Aucune compilation préalable ou liaison de bibliothèques (`.lib`/`.a`) n'est nécessaire.

1. **Copiez le Répertoire `Dralyxor`:** Obtenez la dernière version de la bibliothèque (clonez le dépôt ou téléchargez le zip) et copiez tout le répertoire `Dralyxor` (contenant tous les fichiers `.hpp`) vers un emplacement accessible par votre projet (par exemple, un dossier `libs/`, `libraries/` ou `vendor/`).
2. **Incluez l'En-tête Principal:** Dans votre code source, incluez l'en-tête principal `dralyxor.hpp`:
   ```cpp
   #include "chemin/vers/Dralyxor/dralyxor.hpp"
   ```

Une structure de projet typique:
```
/MonProjet/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor ici
        |-- dralyxor.hpp            (Point d'entrée principal)
        |-- obfuscated_string.hpp   (Classe Obfuscated_String)
        |-- secure_accessor.hpp     (Classe Secure_Accessor)
        |-- algorithms.hpp          (Moteur de transformation et micro-programmes)
        |-- anti_debug.hpp          (Détections à l'exécution)
        |-- prng.hpp                (Générateur de nombres pseudo-aléatoires à la compilation)
        |-- integrity_constants.hpp (Constantes pour les vérifications d'intégrité)
        |-- secure_memory.hpp       (Nettoyage sécurisé de la mémoire)
        |-- detection.hpp           (Macros de détection de compilateur/standard C++)
        `-- env_traits.hpp          (Adaptations de type_traits pour les environnements restreints)
```

### Prérequis du Compilateur

> [!IMPORTANT]
> **Dralyxor** a été conçu en se concentrant sur le **C++** moderne pour une sécurité et une efficacité maximales à la compilation.
>
> - **Standard C++ Minimum: C++14**. La bibliothèque utilise des fonctionnalités telles que `constexpr` généralisé et s'adapte à `if constexpr` (lorsqu'il est disponible via `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptation aux Standards Supérieurs:** Détecte et utilise les optimisations ou les syntaxes de **C++17** et **C++20** (comme `consteval`, les suffixes `_v` pour `type_traits`) si le projet est compilé avec ces standards. Le `_DRALYXOR_CONSTEVAL` est mappé sur `consteval` en C++20 et `constexpr` en C++14/17, garantissant l'exécution à la compilation là où c'est possible.
> - **Compilateurs Supportés:** Testé principalement avec les versions récentes de MSVC, GCC et Clang.
> - **Environnement d'Exécution:** Entièrement compatible avec les applications **User Mode** et les environnements **Kernel Mode** (ex: pilotes Windows). En Kernel Mode, où la STL peut ne pas être disponible, **Dralyxor** utilise des implémentations internes pour les `type traits` nécessaires (voir `env_traits.hpp`).

### Modèles d'Utilisation Essentiels

#### Modèle 1: Obfuscation Locale (Stack)

Idéal pour les chaînes de caractères temporaires, confinées à la portée d'une fonction. La mémoire est automatiquement gérée et nettoyée.

```cpp
#include "Dralyxor/dralyxor.hpp" // Ajustez le chemin si nécessaire
#include <iostream>

void Configure_Logging() {
    // Clé de formatage des logs, utilisée uniquement localement.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Accès sécurisé dans une portée limitée
    {
        // Le Secure_Accessor désobscurcit temporairement 'log_format_key' lors de sa construction
        // (et ré-obscurcit 'log_format_key' immédiatement après la copie dans ses tampons internes),
        // permet l'accès, et nettoie ses propres tampons à la destruction.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Toujours vérifier que Get() ne retourne pas nullptr
            std::cout << "Utilisation du format de log: " << accessor.Get() << std::endl;
            // Ex: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Échec du déchiffrement de log_format_key (falsification possible ou détection de débogueur ?)" << std::endl;
    } // accessor est détruit, ses tampons internes sont nettoyés. log_format_key reste obscurci.
      // log_format_key sera détruit à la fin de la fonction Configure_Logging.
}
```

#### Modèle 2: Obfuscation Statique (Globale)

Pour les constantes qui doivent persister pendant toute la durée de vie du programme et être accessibles globalement.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Pour l'exemple

// URL de l'API de licences, un secret persistant.
// La macro DRALYXOR() crée un objet statique.
// La fonction Get_License_Server_URL() retourne une référence à cet objet statique.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref est une référence à l'Obfuscated_String statique.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Crée un Secure_Accessor pour url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Contact du serveur de licence à: " << accessor.Get() << std::endl;
            // Ex: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulation de succès pour l'exemple
        }
        else
            std::cerr << "Échec du déchiffrement de l'URL du serveur de licence (falsification possible ou détection de débogueur ?)." << std::endl;
    } // accessor est détruit, ses tampons sont nettoyés. url_obj_ref (l'Obfuscated_String original) reste obscurci.

    return success;
}
```

#### Modèle 3: Obfuscation avec une Clé Fournie par l'Utilisateur

Pour un niveau de sécurité maximal, vous pouvez fournir votre propre chaîne de clé secrète. Cela rend l'obfuscation dépendante d'un secret que vous seul connaissez, la rendant ainsi plus résistante.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// La clé ne doit jamais être en texte clair dans le code de production,
// idéalement, elle proviendrait d'un script de build, d'une variable d'environnement, etc.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Obscurcit une URL en utilisant la clé secrète. La macro se termine par _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // L'utilisation avec Secure_Accessor reste la même.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Gestion des Erreurs et Intégrité

Les fonctions `Obfuscated_String::Decrypt()` et `Encrypt()` retournent un `uint64_t`:
- `0` indique le succès.
- `Dralyxor::Detail::integrity_compromised_magic` (une valeur constante définie dans `integrity_constants.hpp`) indique qu'une vérification d'intégrité a échoué. Cela peut être dû à la corruption des canaris de l'objet, à un checksum de contenu incohérent, ou à la détection d'un débogueur signalant un environnement hostile.

De même, `Secure_Accessor::Get()` (ou sa conversion implicite en `const CharT*`) retournera `nullptr` si l'initialisation du `Secure_Accessor` échoue (par exemple, si le déchiffrement de l' `Obfuscated_String` original échoue) ou si l'intégrité du `Secure_Accessor` (ses propres canaris ou checksums internes) est compromise pendant sa durée de vie.

**Il est crucial que votre code vérifie ces retours pour garantir la robustesse et la sécurité de l'application.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Vous n'appelleriez généralement PAS Decrypt() et Encrypt() directement,
    // car le Secure_Accessor gère cela. Mais si vous en avez besoin pour une raison quelconque:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "ALERTE: Échec du déchiffrement de 'my_secret' ou intégrité compromise pendant Decrypt() !" << std::endl;
        // Prenez une mesure appropriée: terminez, loguez de manière sécurisée, etc.
        // L'objet my_secret.storage_ peut être dans un état invalide ou contenir des données aléatoires.
        return; // Évitez d'utiliser my_secret si Decrypt() échoue.
    }

    // Si Decrypt() a réussi, my_secret.storage_ contient les données déchiffrées.
    // **L'ACCÈS DIRECT À storage_ EST FORTEMENT DÉCONSEILLÉ EN PRODUCTION.**
    // std::cout << "Données dans my_secret.storage_ (NE FAITES PAS CELA): " << my_secret.storage_ << std::endl;

    // Il est de votre responsabilité de ré-chiffrer si vous avez appelé Decrypt() manuellement:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "ALERTE: Échec du ré-chiffrement de 'my_secret' ou intégrité compromise pendant Encrypt() !" << std::endl;
        // État incertain, potentiellement dangereux.
    }

    // UTILISATION RECOMMANDÉE avec Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Le constructeur du Secure_Accessor appelle another_secret.Decrypt(), copie, puis another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Ou: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Données secrètes via Secure_Accessor: " << data_ptr << std::endl;
            // Utilisez data_ptr ici
        }
        else {
            std::cerr << "ALERTE: Secure_Accessor n'a pas réussi à s'initialiser ou à obtenir le pointeur pour 'another_secret' !" << std::endl;
            // Cela indique que le Decrypt() dans le constructeur de l'accesseur a échoué,
            // ou qu'il y a eu une falsification de l'accesseur (canaris, checksums internes).
        }
    } // accessor est détruit. Ses tampons sont nettoyés. another_secret reste obscurci.
}
```

## Philosophie et Architecture de Conception Détaillée

**Dralyxor** n'est pas simplement un chiffre XOR ; c'est un système de défense en profondeur pour les chaînes littérales. Son architecture est fondée sur la prémisse qu'une sécurité efficace nécessite de multiples couches interconnectées et une résilience contre diverses techniques d'analyse.

### La Menace Persistante: Vulnérabilité des Chaînes Littérales

Les chaînes littérales, comme `"api.example.com/data?key="`, lorsqu'elles sont intégrées directement dans le code, sont écrites de manière lisible (texte clair) dans le binaire compilé. Des outils comme `strings`, des désassembleurs (IDA Pro, Ghidra) et des éditeurs hexadécimaux peuvent les extraire trivialement. Cette exposition facilite:
- **Ingénierie Inverse:** Compréhension de la logique interne et du flux du programme.
- **Identification des Points d'Extrémité:** Découverte des serveurs et API backend.
- **Extraction de Secrets:** Clés API, mots de passe intégrés, URL privées, requêtes SQL, etc.
- **Analyse de la Mémoire Dynamique:** Même si un programme déchiffre une chaîne pour l'utiliser, si elle reste en texte clair dans la **RAM** trop longtemps, un attaquant ayant accès à la mémoire du processus (via un débogueur ou un vidage mémoire) peut la trouver.

**Dralyxor** s'attaque à ces vulnérabilités tant au moment de la compilation (pour le binaire sur disque) qu'au moment de l'exécution (pour la mémoire **RAM**).

### La Solution Architecturale Multicouche de **Dralyxor**

La robustesse de **Dralyxor** émane de la synergie de ses composants clés:

| Composant Architectural                    | Objectif Principal                                                                      | Technologies/Techniques Clés Employées                                                                                                                              |
| :------------------------------------------ | :------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Moteur de Transformation par Micro-Programme** | Éliminer les chaînes en texte clair du binaire ; créer une obfuscation complexe, dynamique et non triviale.   | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, multiples opérations (XOR, ADD, ROT, etc.), NOPs variables et logiques, styles d'applicateurs variables.         |
| **Accès Sécurisé et Minimisation de l'Exposition** | Réduire considérablement le temps pendant lequel un secret reste déchiffré dans la mémoire RAM.             | Modèle RAII (`Secure_Accessor`), fragmentation de la mémoire, nettoyage sécurisé des tampons (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Défenses en Temps d'Exécution**              | Détecter et réagir aux environnements d'analyse hostiles et à l'altération de la mémoire.            | Détection de Débogueurs (API spécifiques à l'OS, synchronisation, OutputDebugString), canaris d'intégrité de l'objet, checksum du contenu de la chaîne.                              |
| **Génération de Clés et de Graines Uniques**    | S'assurer que chaque chaîne obfusquée et chaque instance d'utilisation soient cryptographiquement distinctes. | `__DATE__`, `__TIME__`, `__COUNTER__`, taille de la chaîne, hachage FNV-1a pour `compile_time_seed`, graines dérivées pour modificateurs d'opérande et sélecteurs. |

## Analyse Approfondie des Composants Architecturaux

### Composant 1: Le Moteur de Transformation par Micro-Programme

Le cœur de l'obfuscation statique et dynamique de **Dralyxor** réside dans son moteur de transformation qui utilise des "micro-programmes" uniques pour chaque chaîne et contexte.

#### Puissance de `consteval` et `constexpr` pour la Génération à la Compilation

Le **C++** moderne, avec `consteval` (**C++20**) et `constexpr` (**C++11** et suivants), permet d'exécuter du code complexe *pendant la compilation*. **Dralyxor** utilise `_DRALYXOR_CONSTEVAL` (qui correspond à `consteval` ou `constexpr` selon le standard **C++**) pour le constructeur de `Obfuscated_String` et pour la génération du micro-programme.

Cela signifie que tout le processus de:
1. Générer une séquence pseudo-aléatoire d'instructions de transformation (le micro-programme).
2. Obscurcir le micro-programme lui-même pour le stockage.
3. Appliquer ce micro-programme (temporairement désobscurci) pour transformer la chaîne originale, aboutissant à sa forme obscurcie.
Tout cela se produit à la compilation, avant que le binaire ne soit généré.

#### Anatomie d'un Micro-Programme **Dralyxor**

Chaque objet `Obfuscated_String` stocke un petit tableau de `Dralyxor::Detail::Micro_Instruction`. Une `Micro_Instruction` est une structure simple définie dans `algorithms.hpp`:
```cpp
// Dans Dralyxor::Detail (algorithms.hpp)
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
    Micro_Operation_Code op_code{}; // L'initialisateur par défaut {} met à zéro
    uint8_t operand{};             // L'initialisateur par défaut {} met à zéro
};

// Nombre maximal d'instructions qu'un micro-programme peut contenir.
static constexpr size_t max_micro_instructions = 8;
```
La fonction `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` est responsable de remplir ce tableau.

##### Génération Aléatoire d'Instructions et Sélection d'Applicateurs

- **Génération d'Instructions:** En utilisant un `Dralyxor::Detail::Constexpr_PRNG` (initialisé avec une combinaison du `compile_time_seed` et de `0xDEADBEEFC0FFEEULL`), la fonction `Generate_Micro_Program_Instructions` choisit de manière probabiliste une séquence d'opérations:
   - `XOR`: XOR au niveau du bit avec l'opérande.
   - `ADD`: Addition modulaire avec l'opérande.
   - `SUB`: Soustraction modulaire avec l'opérande.
   - `ROTR`/`ROTL`: Rotation de bits. L'opérande (après modulo) définit le nombre de décalages (1 à 7).
   - `SWAP_NIB`: Échange les 4 bits inférieurs avec les 4 bits supérieurs d'un octet (l'opérande est ignoré). Les opérandes pour ces instructions sont également générés de manière pseudo-aléatoire par le PRNG.

- **Modification des Opérandes et Sélection des Applicateurs au Moment de la Transformation:** Pendant l'application du micro-programme (par `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), tant lors de l'obfuscation initiale que lors de la désobscurcissement à l'exécution:
   - Un `Constexpr_PRNG prng_operand_modifier` (initialisé avec `base_seed`) génère une `prng_key_for_ops_in_elem` pour chaque caractère de la chaîne. L'opérande de la micro-instruction (`instr_orig.operand`) est XORé avec cette clé avant d'être utilisé. Cela garantit que le même micro-programme applique des transformations légèrement différentes pour chaque caractère.
   - Un `Constexpr_PRNG prng_applier_selector` (initialisé avec `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) choisit un `Byte_Transform_Applier` pour chaque caractère. Il existe actuellement deux styles:
      - `Applier_Style_Direct`: Applique l'opération directement (en l'inversant pour le déchiffrement, comme ADD devient SUB).
      - `Applier_Style_DoubleLayer`: Applique l'opération deux fois (ou l'opération et son inverse, selon le mode de chiffrement/déchiffrement) avec des opérandes différents, rendant l'inversion un peu plus complexe à analyser.

##### NOPs Variables et Logiques pour l'Entropie

Pour augmenter la difficulté de l'analyse manuelle du micro-programme, **Dralyxor** insère:
- **NOPs Explicites:** Des instructions `Micro_Operation_Code::NOP` qui ne font rien.
- **NOPs Logiques:** Des paires d'instructions qui s'annulent mutuellement, comme `ADD K` suivi de `SUB K`, ou `ROTL N_BITS` suivi de `ROTR N_BITS`. L'opérande utilisé dans la paire est le même.

Ces NOPs sont insérés de manière probabiliste par `Generate_Micro_Program_Instructions`, remplissant le tableau `micro_program_` et rendant plus difficile de discerner les transformations effectives des opérations de "bruit".

#### Obfuscation du Micro-Programme lui-même

Après la génération du micro-programme et avant l'obfuscation initiale de la chaîne dans le constructeur `consteval`, le tableau `micro_program_` (contenu dans l'objet `Obfuscated_String`) est lui-même obscurci. Chaque `op_code` et `operand` de chaque `Micro_Instruction` est XORé avec une clé dérivée du `compile_time_seed` (en utilisant `Detail::Get_Micro_Program_Obfuscation_Key` et `Detail::Obfuscate_Deobfuscate_Instruction`).
Cela signifie que, même si un attaquant parvient à vider la mémoire de l'objet `Obfuscated_String`, le micro-programme ne sera pas dans sa forme directement lisible/applicable.

Lorsque `Obfuscated_String::Decrypt()` ou `Encrypt()` sont appelés (ou indirectement par le `Secure_Accessor`), la fonction centrale `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` reçoit ce micro-programme *obscurci*. Elle procède alors comme suit:
1. Elle crée une copie temporaire du micro-programme (`local_plain_program`) sur la pile.
2. Elle désobscurcit cette copie locale en utilisant la même clé (`program_obf_key`) dérivée de la graine de base passée (qui est, en fin de compte, le `compile_time_seed`).
3. Elle utilise ce `local_plain_program` pour transformer les données de la chaîne.
La copie locale sur la pile est détruite à la fin de la fonction, et le `micro_program_` stocké dans l'objet `Obfuscated_String` reste obscurci.

#### Le Cycle de Vie de l'Obfuscation Statique

1. **Code-Source:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Pré-traitement:** La macro se développe en une instanciation `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");`. (La taille 15 inclut le terminateur nul).
3. **Évaluation `_DRALYXOR_CONSTEVAL`:**
   - Le compilateur exécute le constructeur `Obfuscated_String`.
   - `Initialize_Internal_Canaries()` définit les canaris d'intégrité.
   - `Generate_Micro_Program_Instructions()` (initialisé avec `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) crée une séquence de `Micro_Instruction` et la stocke dans `this->micro_program_` (ex: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Le nombre réel d'instructions est stocké dans `num_actual_instructions_in_program_`.
   - La chaîne originale "SECRET\_API\_KEY" est copiée dans `this->storage_`.
   - Un checksum de la chaîne originale "SECRET\_API\_KEY" (excluant le nul) est calculé par `Detail::Calculate_String_Content_Checksum` puis obscurci par `Detail::Obfuscate_Deobfuscate_Short_Value` (utilisant `compile_time_seed` et `content_checksum_obf_salt`) et stocké dans `this->_content_checksum_obfuscated`.
   - `Obfuscate_Internal_Micro_Program()` est appelée: `this->micro_program_` est obscurci sur place (chaque instruction XORée avec `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` est appelée. Cette fonction:
      - Crée une copie désobscurcie de `this->micro_program_` sur la pile.
      - Pour chaque caractère dans `storage_` (sauf le nul):
         - Génère `prng_key_for_ops_in_elem` et sélectionne un `Byte_Transform_Applier`.
         - Applique la séquence de micro-instructions (de la copie désobscurcie) au caractère, en utilisant l'applicateur et l'opérande modifié.
      - À la fin, `storage_` contient la chaîne obscurcie (ex: `[CF, 3A, D1, ..., 0x00]`).
4. **Génération de Code:** Le compilateur alloue de l'espace pour `api_key_obj` et l'initialise directement avec:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (chaîne obscurcie).
   - `micro_program_`: Le micro-programme *déjà obscurci*.
   - `_content_checksum_obfuscated`: Le checksum du contenu original, *obscurci*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`. Le littéral `"SECRET_API_KEY"` n'existe plus dans le binaire.

### Composant 2: Accès Sécurisé et Minimisation de l'Exposition en RAM

#### Le `Secure_Accessor` et le Principe RAII

La protection à la compilation n'est que la moitié de la bataille. Une fois que la chaîne doit être utilisée, elle doit être déchiffrée. Si cette chaîne déchiffrée reste en mémoire **RAM** pendant une période prolongée, elle devient une cible pour l'analyse dynamique (vidages mémoire, débogueurs).

**Dralyxor** aborde ce problème avec `Dralyxor::Secure_Accessor`, une classe qui implémente le patron de conception **RAII** (Resource Acquisition Is Initialization):
- **Ressource Acquise:** L'accès temporaire à la chaîne en clair, fragmentée et gérée par l'accesseur.
- **Objet Gestionnaire:** L'instance de `Secure_Accessor`.

```cpp
// Dans secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Initialiser différemment pour échouer si non mis à jour
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalide l'accesseur

            return;
        }

        // 1. Tente de déchiffrer l'Obfuscated_String original.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Si le déchiffrement réussit, copie la chaîne en clair dans les fragments internes.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ est maintenant en clair
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val est au maximum 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Remplit le reste du tampon du fragment avec des nuls

                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksum des fragments
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Ré-chiffre IMMÉDIATEMENT l'Obfuscated_String original.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Nettoie les fragments et le tampon reconstruit.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Vérifie soi-même et le parent
            Clear_All_Internal_Buffers(); // Mesure de sécurité
            _accessor_integrity_canary1 = 0; // Invalide pour les accès futurs

            return nullptr;
        }

        if (!current_access_ptr_) { // Si c'est le premier appel à Get() ou s'il a été nettoyé
            if constexpr (N_storage > 0) { // Reconstruit seulement s'il y a quelque chose à reconstruire
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

                // Garantit la terminaison nulle, même si N_storage est exactement rempli.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // Pour N_storage == 0 (chaîne vide, théoriquement), il n'y a pas de checksums
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Pour passer la vérification

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // si N_storage était 0, c'est sûr si le tampon est > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Vérifie à nouveau après toute opération interne pour garantir l'intégrité.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Flux d'Utilisation avec `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - Le constructeur de `Secure_Accessor` est appelé.
   - Il appelle `my_obfuscated_string.Decrypt()`. Cela implique de désobscurcir le `micro_program_` (vers une copie locale), de l'utiliser pour déchiffrer `my_obfuscated_string.storage_`, puis de vérifier les canaris et le checksum du contenu déchiffré par rapport à l'attendu.
   - En cas de succès, le contenu de `my_obfuscated_string.storage_` (maintenant en clair) est copié et divisé dans les `fragments_storage_` internes du `Secure_Accessor`.
   - Un checksum des `fragments_storage_` (`fragments_data_checksum_expected_`) est calculé.
   - Crucialement, `my_obfuscated_string.Encrypt()` est appelé *immédiatement après*, ré-obscurcissant `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (ou `const char* ptr = accessor;` en raison de la conversion implicite)
   - `Secure_Accessor::Get()` est appelé.
   - Il vérifie ses propres canaris d'intégrité et ceux de l' `Obfuscated_String` parent.
   - S'il s'agit du premier accès (`current_access_ptr_` est `nullptr`), il reconstruit la chaîne complète dans `reconstructed_plain_buffer_` à partir des `fragments_storage_`.
   - Il vérifie ensuite `fragments_data_checksum_reconstructed_` par rapport à `fragments_data_checksum_expected_` pour s'assurer que les fragments n'ont pas été altérés pendant que le `Secure_Accessor` existait.
   - Si tout est correct, il retourne un pointeur vers `reconstructed_plain_buffer_`.
3. La portée de `accessor` se termine (sortie de la fonction, fin du bloc `{}`, etc.).
   - Le destructeur de `Secure_Accessor` est appelé automatiquement.
   - `Clear_All_Internal_Buffers()` est invoqué, qui nettoie de manière sécurisée (`Secure_Clear_Memory`) à la fois le `reconstructed_plain_buffer_` et les `fragments_storage_`.

Le résultat est que la chaîne en clair n'existe sous sa forme complète qu'à l'intérieur du `Secure_Accessor` (dans le `reconstructed_plain_buffer_`) et seulement après le premier appel à `Get()`, pour la durée la plus courte possible. La chaîne dans l'objet `Obfuscated_String` original est ré-obscurcie dès que le `Secure_Accessor` a copié son contenu lors de sa construction.

#### Fragmentation de la Mémoire dans le `Secure_Accessor`

Pour rendre encore plus difficile la localisation de la chaîne complète en clair en mémoire, le `Secure_Accessor`, lors de sa construction, ne se contente pas de copier la chaîne déchiffrée, il la divise:
1. La chaîne de l' `Obfuscated_String` parent est déchiffrée.
2. Son contenu est divisé en jusqu'à `fragment_count_val` (actuellement 4, si la chaîne est assez grande) morceaux, qui sont copiés dans `fragments_storage_[i]`.
3. La chaîne dans l'objet `Obfuscated_String` parent est ré-obscurcie.

Ce n'est que lorsque `Secure_Accessor::Get()` est appelé pour la première fois que ces fragments sont ré-assemblés dans le `reconstructed_plain_buffer_`. Cette technique vise à "disperser" les données sensibles, contrecarrant les balayages de mémoire qui recherchent des chaînes continues.

#### Nettoyage Sécurisé de la Mémoire

Tant le destructeur de `Obfuscated_String` (via `Clear_Internal_Data`) que le destructeur de `Secure_Accessor` (via `Clear_All_Internal_Buffers`) utilisent `Dralyxor::Detail::Secure_Clear_Memory`. Cette fonction wrapper garantit que les tampons contenant des données sensibles sont remis à zéro de manière fiable, en empêchant l'optimisation du compilateur:
- **Sur Windows:** Utilise `SecureZeroMemory` (User Mode) ou `RtlSecureZeroMemory` (Kernel Mode), qui sont des fonctions du système d'exploitation conçues spécifiquement pour ne pas être optimisées et pour mettre la mémoire à zéro en toute sécurité.
- **Sur d'autres plateformes (Linux, macOS, etc.):** L'implémentation utilise maintenant `memset` pour remplir le bloc de mémoire avec des zéros. `memset` opère au niveau de l'octet, ce qui le rend idéal et sûr pour mettre à zéro des types primitifs (comme `char`, `int`) ainsi que des types complexes (comme les `struct`), évitant ainsi les problèmes de compatibilité de type ou d'opérateurs d'affectation. Pour garantir que l'appel à `memset` n'est pas optimisé et supprimé par le compilateur, le pointeur du tampon est d'abord passé à un pointeur `volatile`.

Cette approche garantit que, lorsque les objets sont détruits, le contenu sensible est écrasé, réduisant le risque de récupération des données par l'analyse des vidages mémoire.

### Composant 3: Défenses à l'Exécution (Anti-Débogage et Anti-Falsification)

**Dralyxor** ne se fie pas seulement à l'obfuscation. Il emploie un ensemble de défenses actives à l'exécution, principalement situées dans `anti_debug.hpp` et intégrées dans les méthodes `Decrypt()` et `Encrypt()` de l' `Obfuscated_String`.

#### Détection Multi-Plateforme de Débogueurs

La fonction `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (dans `anti_debug.hpp`) vérifie la présence d'un débogueur en utilisant des techniques spécifiques au système d'exploitation:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` pour `ProcessDebugPort` (0x07) et `ProcessDebugFlags` (0x1F).
- **Linux:** Lecture de `/proc/self/status` et vérification de la valeur de `TracerPid:`. Une valeur différente de 0 indique que le processus est tracé.
- **macOS:** Utilisation de `sysctl` avec `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` pour obtenir `kinfo_proc` et vérification du drapeau `P_TRACED` dans `kp_proc.p_flag`.

De plus, à l'intérieur de `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Exécute une boucle d'opérations de calcul simples et mesure le temps. Une lenteur significative (supérieure à `timing_threshold_milliseconds = 75ms`) peut indiquer qu'un débogueur est en mode pas à pas ou que des points d'arrêt étendus sont actifs. À l'intérieur de cette boucle, `Is_Debugger_Present_Tracer_Pid_Sysctl()` est appelé, et une fonction "leurre" `Detail::Canary_Function_For_Breakpoint_Check()` (qui retourne simplement `0xCC`, le code d'instruction pour `int3` / point d'arrêt logiciel) est appelée et son résultat est XORé, rendant l'optimisation plus difficile et fournissant un emplacement commun pour les points d'arrêt.
- `Detail::Perform_Output_Debug_String_Trick()` (uniquement en Windows User Mode): Utilise le comportement de `OutputDebugStringA/W` et `GetLastError()`. Si un débogueur est attaché, `GetLastError()` peut être modifié après l'appel à `OutputDebugString`.

#### Impact sur l'Opération en Cas de Détection ou de Violation d'Intégrité

Si l'une des vérifications anti-débogage retourne `true`, ou si les canaris d'intégrité de l' `Obfuscated_String` (`_internal_integrity_canary1/2`) sont corrompus, la fonction `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` retournera `Detail::integrity_compromised_magic`.

Cette valeur de retour est cruciale dans les fonctions `Obfuscated_String::Decrypt()` et `Encrypt()`:
```cpp
// Logique simplifiée de Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Canaris de Obfuscated_String
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
        // ... Vérifier les canaris à nouveau ...

        // SI runtime_key_mod N'EST PAS integrity_compromised_magic, IL N'EST PAS UTILISÉ POUR CHANGER LA CLÉ DE DÉCHIFFREMENT.
        // La clé de déchiffrement est toujours dérivée du 'compile_time_seed' original.
        // Le rôle du runtime_key_mod ici est D'AGIR COMME UN INDICATEUR d'un environnement hostile.
        // Si hostile, la fonction retourne integrity_compromised_magic et le déchiffrement ne se poursuit pas ou est annulé.
        
        // Transform_Compile_Time_Consistent est appelée avec compile_time_seed (et NON avec runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* mode déchiffrement */);
        
        // ... Vérifier le checksum et les canaris à nouveau ...
        // Si quelque chose échoue, Clear_Internal_Data() et retourne integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Succès
}
```

**Effet Clé:** Si `Calculate_Runtime_Key_Modifier` détecte un problème (débogueur ou canari corrompu) et retourne `integrity_compromised_magic`, les fonctions `Decrypt()` (et de même `Encrypt()`) abandonnent l'opération, nettoient les données internes de l' `Obfuscated_String` (y compris `storage_` et `micro_program_`), et retournent `integrity_compromised_magic`. Cela empêche la chaîne d'être correctement déchiffrée (ou re-chiffrée) dans un environnement hostile ou si l'objet a été falsifié.
La chaîne n'est pas déchiffrée "incorrectement" (en données aléatoires) ; l'opération est simplement empêchée, et l'objet `Obfuscated_String` s'autodétruit en termes de contenu utile.

#### Canaris d'Intégrité de l'Objet

Les deux classes `Obfuscated_String` et `Secure_Accessor` contiennent des membres canaris (paires de `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initialisé avec `Detail::integrity_canary_value`) et `_internal_integrity_canary2` (initialisé avec `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initialisé avec `Detail::accessor_integrity_canary_seed`) et `_accessor_integrity_canary2` (initialisé avec `~Detail::accessor_integrity_canary_seed`).

Ces canaris sont vérifiés à des points critiques:
- Début et fin de `Obfuscated_String::Decrypt()` et `Encrypt()`.
- Constructeur, destructeur et `Get()` du `Secure_Accessor`.
- Avant et après les vérifications anti-débogage dans `Calculate_Runtime_Key_Modifier`.

Si ces valeurs canaris sont modifiées (par exemple, par un débordement de tampon, un patch de mémoire indiscriminé, ou un hook qui écrase la mémoire adjacente), la vérification (`Verify_Internal_Canaries()` ou `Verify_Internal_Accessor_Canaries()`) échouera.
En cas d'échec, les opérations sont abandonnées, les données internes pertinentes sont nettoyées, et une valeur d'erreur (`Detail::integrity_compromised_magic` ou `nullptr`) est retournée, signalant une falsification.

#### Checksum du Contenu de la Chaîne

- Un checksum de 16 bits de la chaîne *originale en clair* (excluant le terminateur nul) est calculé par `Detail::Calculate_String_Content_Checksum` à la compilation.
- Ce checksum est ensuite obscurci en utilisant `Detail::Obfuscate_Deobfuscate_Short_Value` (avec `compile_time_seed` et `content_checksum_obf_salt`) et stocké dans `_content_checksum_obfuscated` dans l'objet `Obfuscated_String`.
- **Lors du Déchiffrement (`Decrypt()`):** Après que `storage_` a été transformé (supposément en clair), son checksum est calculé. `_content_checksum_obfuscated` est désobscurci pour obtenir le checksum de référence. Si les deux checksums ne correspondent pas, cela indique que:
   - Le déchiffrement n'a pas restauré la chaîne originale (peut-être parce que l'opération a été abandonnée en raison de la détection d'un débogueur avant la transformation complète, ou il y a eu une corruption de la graine/du microprogramme).
   - `storage_` (lorsqu'il est obscurci) ou `_content_checksum_obfuscated` ont été falsifiés en mémoire.
- **Lors du Chiffrement (`Encrypt()`):** Avant que `storage_` (qui est en clair à ce stade) ne soit re-transformé dans sa forme obscurcie, son checksum est calculé et comparé à celui de référence. une divergence ici signifierait que la chaîne en clair a été modifiée *à l'intérieur de `storage_` de `Obfuscated_String` pendant qu'elle était déchiffrée*, ce qui est une forte indication de falsification de la mémoire ou d'une utilisation inappropriée (puisque l'accès à `storage_` ne doit pas être fait directement).

Dans les deux cas d'échec de checksum, `Clear_Internal_Data()` est appelée et `integrity_compromised_magic` est retournée.

### Composant 4: Génération de Clés et de Graines Uniques et Imprévisibles

La sécurité de tout système de chiffrement repose sur la force et l'unicité de ses clés et graines. **Dralyxor** garantit que chaque chaîne obscurcie utilise un ensemble de paramètres de chiffrement fondamentalement unique.

#### Sources d'Entropie pour le `compile_time_seed`

La `static constexpr uint64_t Obfuscated_String::compile_time_seed` est la graine maîtresse pour toutes les opérations pseudo-aléatoires relatives à cette instance de la chaîne. Sa génération est maintenant conditionnelle, basée sur la présence d'une clé fournie par l'utilisateur:

- **Si une clé est fournie par l'utilisateur (en utilisant `DRALYXOR_KEY` ou `DRALYXOR_KEY_LOCAL`):**
   1. Le `key_literal` fourni est transformé en un hash de 64 bits à la compilation en utilisant l'algorithme FNV-1a.
   2. Ce hash devient la base du `compile_time_seed`, combiné avec `__COUNTER__` (pour garantir l'unicité entre différentes utilisations de la même clé) et la taille de la chaîne.
      ```cpp
      // Logique simplifiée
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      Dans ce mode, la sécurité de l'obfuscation dépend directement de la force et du secret de la clé fournie.

- **Si aucune clé n'est fournie (en utilisant `DRALYXOR` ou `DRALYXOR_LOCAL`):**
   - Le `compile_time_seed` est généré en utilisant une combinaison des facteurs suivants pour maximiser l'entropie et la variabilité:
      ```cpp
      // Dans Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Composant 1: Variabilité entre les compilations
          ((uint64_t)Instance_Counter << 32) ^        // Composant 2: Variabilité au sein d'une unité de compilation
          storage_n;                                  // Composant 3: Variabilité basée sur la taille de la chaîne
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: Les macros `__DATE__` (ex: "Jan 01 2025") et `__TIME__` (ex: "12:30:00") sont des chaînes fournies par le préprocesseur qui changent chaque fois que le fichier est compilé. Le hash FNV-1a de ces valeurs crée une graine de base qui est différente pour chaque build du projet.
   - **`Instance_Counter` (alimenté par `__COUNTER__` dans la macro)**: La macro `__COUNTER__` est un compteur maintenu par le préprocesseur qui s'incrémente chaque fois qu'il est utilisé au sein d'une unité de compilation. En passant cela comme un argument de template, chaque utilisation de la macro `DRALYXOR` ou `DRALYXOR_LOCAL` résultera en un `Instance_Counter` différent et donc, un `compile_time_seed` différent, même pour des chaînes littérales identiques dans le même fichier source.
   - **`storage_n` (taille de la chaîne)**: La taille de la chaîne est également XORée, ajoutant un autre facteur de différenciation.

Ce `compile_time_seed` (qu'il soit dérivé de la clé de l'utilisateur ou généré automatiquement) est ensuite utilisé comme base pour:
1. Générer le `micro_program_` (en initialisant le PRNG avec `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Dériver la clé d'obfuscation pour le `micro_program_` lui-même (via `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Dériver la clé d'obfuscation pour le `_content_checksum_obfuscated` (via `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Servir de `base_seed` pour `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Graines Dérivées pour les Transformations de Contenu

À l'intérieur de `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- Un `Constexpr_PRNG prng_operand_modifier(base_seed)` est initialisé. Pour chaque caractère de la chaîne en cours de transformation, `prng_operand_modifier.Key()` produit une `prng_key_for_ops_in_elem`. Cette clé est XORée avec l'opérande de la micro-instruction avant son application, garantissant que l'effet de la même micro-instruction est subtilement différent pour chaque caractère.
- Un `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` est initialisé. Pour chaque caractère, `prng_applier_selector.Key()` est utilisé pour choisir entre `Applier_Style_Direct` et `Applier_Style_DoubleLayer`.

Cela introduit un dynamisme supplémentaire dans la transformation de chaque caractère, même si le micro-programme sous-jacent est le même pour tous les caractères d'une chaîne donnée.

#### Immunité Contre les Attaques de "Replay" et l'Analyse de Motifs

- **Unicité Inter-Compilation:** Si un attaquant analyse le binaire de la version 1.0 de votre logiciel et, avec beaucoup d'efforts, réussit à briser l'obfuscation d'une chaîne (en mode de clé automatique), cette connaissance sera probablement inutile pour la version 1.1, car le `__DATE__ __TIME__` aura changé, entraînant des `compile_time_seed` et des micro-programmes complètement différents.
- **Unicité Intra-Compilation:** Si vous utilisez `DRALYXOR("AdminPassword")` à deux endroits différents dans votre code (ou dans le même fichier .cpp), le `__COUNTER__` garantira que les objets `Obfuscated_String` résultants, et donc leurs représentations obscurcies dans le binaire, seront différents. Cela empêche un attaquant de trouver un motif obscurci et de l'utiliser pour localiser toutes les autres occurrences de la même chaîne originale.

Cette génération robuste de graines est une pierre angulaire de la sécurité de **Dralyxor** contre les attaques qui dépendent de la découverte d'un "secret maître" ou de l'exploitation de la répétition des chiffrements et des transformations.

## Référence Complète de l'API Publique

### Macros d'Obfuscation

Ce sont les principaux points d'entrée pour créer des chaînes obscurcies.

#### `DRALYXOR(str_literal)`

- **Objectif:** Crée un objet `Obfuscated_String` avec une durée de vie statique (existe pendant toute l'exécution du programme). Idéal pour les constantes globales ou les chaînes qui doivent être accessibles depuis plusieurs endroits et persister.
- **Stockage:** Mémoire statique (généralement dans la section de données du programme).
- **Implémentation:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Paramètres:**
   - `str_literal`: Un littéral de chaîne de style C (par exemple, `"Hello World"`, `L"Unicode String"`).
- **Retour:** Une référence (`auto&`) à l'objet `Obfuscated_String` statique, créé à l'intérieur d'une lambda immédiatement invoquée.
- **Exemple:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url est une référence à un Obfuscated_String statique.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Objectif:** Crée un objet `Obfuscated_String` avec une durée de vie automatique (généralement sur la pile, s'il est utilisé à l'intérieur d'une fonction). Idéal pour les secrets temporaires confinés à une portée.
- **Stockage:** Automatique (pile pour les variables locales de fonction).
- **Implémentation:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Paramètres:**
   - `str_literal`: Un littéral de chaîne de style C.
- **Retour:** Un objet `Obfuscated_String` par valeur (qui peut être optimisé avec RVO/NRVO par le compilateur).
- **Exemple:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... utiliser temp_key avec DRALYXOR_SECURE ...
   } // temp_key est détruit ici, son destructeur appelle Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Objectif:** Similaire à `DRALYXOR`, crée un objet `Obfuscated_String` statique, mais utilise une **clé fournie par l'utilisateur** (`key_literal`) pour initialiser l'obfuscation, offrant le plus haut niveau de sécurité.
- **Stockage:** Mémoire statique (généralement dans la section de données du programme).
- **Implémentation:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Paramètres:**
   - `str_literal`: Le littéral de chaîne à obscurcir.
   - `key_literal`: Le littéral de chaîne à utiliser comme clé secrète.
- **Retour:** Une référence (`auto&`) à l'objet `Obfuscated_String` statique.
- **Exemple:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Objectif:** Similaire à `DRALYXOR_LOCAL`, crée un objet `Obfuscated_String` sur la pile, en utilisant une **clé fournie par l'utilisateur**.
- **Stockage:** Automatique (pile pour les variables locales de fonction).
- **Implémentation:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Paramètres:**
   - `str_literal`: Le littéral de chaîne à obscurcir.
   - `key_literal`: Le littéral de chaîne à utiliser comme clé.
- **Retour:** Un objet `Obfuscated_String` par valeur.
- **Exemple:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Macro d'Accès Sécurisé

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Objectif:** Fournit un accès sécurisé et temporaire au contenu déchiffré d'un objet `Obfuscated_String`. C'est la **seule méthode recommandée** pour lire la chaîne.
- **Implémentation:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```
- **Paramètres:**
   - `obfuscated_var`: Une variable (lvalue ou rvalue qui peut être liée à une référence lvalue non-const) de type `Dralyxor::Obfuscated_String<...>`. La variable doit être mutable car le constructeur du `Secure_Accessor` appelle `Decrypt()` et `Encrypt()` sur elle.
- **Retour:** Un objet `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` par valeur.
- **Utilisation:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Ou simplement: const char* secret_ptr = accessor; (conversion implicite)
      
       if (secret_ptr) {
           // Utilisez secret_ptr ici. Il pointe vers la chaîne déchiffrée temporairement dans le tampon de l'accesseur.
           // Ex: send_data(secret_ptr);
       }
       else {
           // Échec du déchiffrement ou de l'intégrité. Traitez l'erreur.
           // L'accesseur a peut-être échoué à s'initialiser (ex: my_static_secret a été corrompu).
       }
   } // accessor est détruit. Ses tampons internes (fragments et chaîne reconstruite) sont nettoyés.
    // my_static_secret.storage_ a déjà été ré-obscurci par le constructeur du Secure_Accessor
    // juste après la copie du contenu vers les fragments de l'accesseur.
   ```

> [!WARNING]
> Vérifiez toujours que le pointeur retourné par `DRALYXOR_SECURE(...).Get()` (ou par la conversion implicite) n'est pas `nullptr` avant de l'utiliser. Un retour `nullptr` indique un échec du déchiffrement (par exemple, détection de débogueur, corruption des canaris/checksums dans l' `Obfuscated_String` parent ou dans le `Secure_Accessor` lui-même). L'utilisation d'un pointeur `nullptr` entraînera un comportement indéfini (probablement une violation de segmentation).

## Fonctionnalités Avancées et Bonnes Pratiques

### Prise en Charge Complète d'Unicode (Chaînes Larges - `wchar_t`)

**Dralyxor** est agnostique au type de caractère grâce à l'utilisation de templates (`CharT`). Il gère nativement `char` (pour les chaînes ASCII/UTF-8) et `wchar_t` (pour les chaînes UTF-16 sur Windows ou UTF-32 sur d'autres systèmes, selon la plateforme et le compilateur). Utilisez simplement le préfixe `L` pour les littéraux `wchar_t`:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Message Unicode: Bonjour le Monde Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Exemple sur Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Titre Unicode", MB_OK);
        // Exemple avec wcout:
        // #include <io.h> // Pour _setmode sur Windows avec MSVC
        // #include <fcntl.h> // Pour _O_U16TEXT sur Windows avec MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Configure stdout pour UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

Pour les caractères d'1 octet (`sizeof(CharT) == 1`), le moteur de transformation `Micro_Program_Cipher` applique le micro-programme octet par octet. Pour les caractères multi-octets (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` utilise une approche plus simple: le caractère multi-octet entier est XORé avec un masque dérivé de la `prng_key_for_ops_in_elem` (répliquée pour remplir la taille du `CharT`). Par exemple, si `CharT` est `wchar_t` (2 octets) et que `prng_key_for_ops_in_elem` est `0xAB`, le caractère sera XORé avec `0xABAB`.
Cela garantit que tous les octets du `wchar_t` sont affectés par l'obfuscation, même si ce n'est pas par le micro-programme complet. La complexité du micro-programme contribue toujours indirectement par la dérivation des clés du PRNG.

### Adaptation Intelligente aux Standards **C++** et aux Environnements (Kernel Mode)

Comme mentionné, **Dralyxor** s'adapte:
- **Standards C++:** Requiert au minimum **C++14**. Détecte et utilise les fonctionnalités de **C++17** et **C++20** (comme `if constexpr`, `consteval`, les suffixes `_v` pour `type_traits`) lorsque le compilateur les supporte, recourant à des alternatives **C++14** dans le cas contraire. Des macros comme `_DRALYXOR_IF_CONSTEXPR` et `_DRALYXOR_CONSTEVAL` dans `detection.hpp` gèrent cette adaptation.
- **Kernel Mode:** Lorsque `_KERNEL_MODE` est défini (typique dans les projets WDK pour les pilotes Windows), **Dralyxor** (via `env_traits.hpp`) évite d'inclure les en-têtes standard de la STL comme `<type_traits>` qui pourraient ne pas être disponibles ou se comporter différemment. À la place, il utilise ses propres implémentations `constexpr` d'outils de base comme `Dralyxor::Detail::Fallback::decay` et `Dralyxor::Detail::Fallback::remove_reference`. Cela permet une utilisation sûre de **Dralyxor** pour protéger les chaînes dans les composants système de bas niveau.
   - De même, `secure_memory.hpp` utilise `RtlSecureZeroMemory` en Kernel Mode. Pour d'autres plates-formes, comme Linux, il recourt à l'utilisation sécurisée de `memset` pour garantir le nettoyage de la mémoire, s'adaptant pour être compatible avec différents types de données.
   - Les vérifications anti-débogage du User Mode (comme `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) sont désactivées (`#if !defined(_KERNEL_MODE)`) en Kernel Mode, car elles ne s'appliquent pas ou ont des équivalents différents. Les vérifications de timing peuvent encore avoir un certain effet, mais la principale ligne de défense en Kernel Mode est l'obfuscation elle-même.

### Considérations de Performance et de Surcoût

- **Temps de Compilation:** L'obfuscation, y compris la génération et l'application de micro-programmes, se produit entièrement au moment de la compilation. Pour les projets avec un très grand nombre de chaînes obfusquées, le temps de compilation peut augmenter. C'est un coût unique par compilation.
- **Taille du Binaire:** Chaque `Obfuscated_String` ajoute son `storage_` (taille de la chaîne), le `micro_program_` (fixé à `max_micro_instructions * sizeof(Micro_Instruction)`), plus quelques octets pour les canaris, le checksum et les drapeaux. Il peut y avoir une augmentation de la taille du binaire par rapport aux chaînes littérales pures, surtout pour de nombreuses petites chaînes.
- **Temps d'Exécution (Runtime):**
   - **Création de `Obfuscated_String` (objets statiques ou locaux):** Se produit au moment de la compilation (pour les statiques) ou implique une copie de données pré-calculées (pour les locaux, optimisable par RVO). Il n'y a pas de coût de "génération" à l'exécution.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Vérifications des canaris (extrêmement rapides).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Inclut les vérifications anti-débogage. La vérification de synchronisation (`Perform_Timing_Check_Generic`) est la plus coûteuse ici, exécutant une boucle. Les autres sont des appels API ou des lectures de fichiers (Linux).
      - Désobfuscation du micro-programme (copie et XOR, rapide).
      - Transformation de la chaîne: Boucle sur les `N_data_elements_to_transform`, et à l'intérieur, boucle sur `num_actual_instructions_in_program_`. Pour chaque instruction, un appel au `Byte_Transform_Applier` qui effectue quelques opérations sur les octets. Le coût est O(longueur\_de\_la\_chaîne \* nombre\_d\_instructions).
      - Calcul/Vérification du checksum (`Detail::Calculate_String_Content_Checksum`): O(longueur\_de\_la\_chaîne \* sizeof(CharT)).
   - **Création de `Secure_Accessor`:**
      - Appelle `Obfuscated_String::Decrypt()`.
      - Copie la chaîne vers les fragments: O(longueur\_de\_la\_chaîne).
      - Calcule le checksum des fragments (`Calculate_Current_Fragments_Checksum`): O(longueur\_de\_la\_chaîne).
      - Appelle `Obfuscated_String::Encrypt()`. C'est le point de plus grande concentration de surcoût en une seule opération d'accès.
   - **`Secure_Accessor::Get()`:**
      - Premier appel: Vérifie les canaris, reconstruit la chaîne à partir des fragments (O(longueur\_de\_la\_chaîne)), vérifie le checksum des fragments.
      - Appels suivants (pour le même objet `Secure_Accessor`): Vérifie les canaris (rapide) et retourne le pointeur déjà calculé (O(1)).
- **Surcoût Général:** Pour la plupart des applications, où les chaînes sensibles ne sont pas accédées dans des boucles à très haute fréquence, le surcoût d'exécution est généralement acceptable, surtout compte tenu du bénéfice en matière de sécurité. La conception du `Secure_Accessor` (créé uniquement lorsque nécessaire et avec une portée strictement limitée par RAII) est fondamentale pour gérer ce coût. Testez dans votre environnement spécifique si la performance est critique.

### Intégration dans une Stratégie de Sécurité en Couches

> [!IMPORTANT]
> **Dralyxor** est un outil puissant d'**obfuscation de chaînes intégrées et de défense contre l'analyse mémoire**, pas une solution de cryptographie générique pour le stockage persistant de données sur disque ou la transmission sécurisée sur le réseau.
>
> Il doit être utilisé comme **l'une des nombreuses couches** dans une stratégie de sécurité globale. Aucun outil isolé n'est une solution miracle. D'autres mesures à considérer incluent:
> - **Minimiser les Secrets Intégrés:** Dans la mesure du possible, évitez d'intégrer des secrets de très haute criticité. Utilisez des alternatives telles que:
>    - Configurations sécurisées fournies à l'exécution (variables d'environnement, fichiers de configuration avec permissions restreintes).
>    - Services de gestion de secrets (coffres-forts) comme HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Validation d'entrée robuste sur toutes les interfaces.
> - Principe du moindre privilège pour les processus et les utilisateurs.
> - Communication réseau sécurisée (TLS/SSL avec épinglage de certificat, le cas échéant).
> - Hachage sécurisé des mots de passe utilisateur (Argon2, scrypt, bcrypt).
> - Protection du binaire dans son ensemble avec d'autres techniques anti-reverse/anti-altération (packers, virtualiseurs de code, vérifications d'intégrité du code), en étant conscient des compromis que celles-ci peuvent introduire (faux positifs des antivirus, complexité).
> - Bonnes pratiques de développement sécurisé (Secure SDLC).

**Dralyxor** se concentre sur la résolution très efficace d'un problème spécifique et courant: la protection des chaînes littérales intégrées contre l'analyse statique et la minimisation de leur exposition en mémoire pendant l'exécution, rendant la vie plus difficile à ceux qui tentent de faire de l'ingénierie inverse sur votre logiciel.

## Licence

Cette bibliothèque est protégée par la Licence MIT, qui permet:

- ✔️ Utilisation commerciale et privée
- ✔️ Modification du code source
- ✔️ Distribution du code
- ✔️ Sous-licenciement

### Conditions:

- Conserver l'avis de droit d'auteur
- Inclure une copie de la licence MIT

Pour plus de détails sur la licence: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Tous droits réservés**