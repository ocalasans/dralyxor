# Dralyxor

**Dralyxor**, derleme zamanında string gizleme (obfuscation) ve çalışma zamanında güçlü koruma için tasarlanmış, modern, `header-only`, yüksek performanslı ve çok katmanlı bir **C++** kütüphanesidir. Temel misyonu, uygulamanızın içsel sırlarını — API anahtarları, şifreler, iç URL'ler, hata ayıklama mesajları ve herhangi bir hassas string literali gibi — statik analiz, tersine mühendislik ve dinamik bellek incelemesi yoluyla açığa çıkmaya karşı korumaktır. **Dralyxor**, stringleri derleme anında şifreleyip dönüştürerek ve çalışma zamanında erişimlerini güvenli bir şekilde yöneterek, nihai ikili dosyanızda hiçbir kritik string literalinin düz metin olarak bulunmamasını veya bellekte kesinlikle gerekli olandan daha uzun süre korunmasız kalmamasını sağlar.

Modern **C++** (en az **C++14** gerektirir ve **C++17** ve **C++20** özelliklerine akıllıca uyum sağlar) temelleri üzerine inşa edilmiş olan gelişmiş mimarisi, "mikro-programlar" tabanlı sofistike bir dönüşüm motoru, dönüşüm programının kendisinin gizlenmesi, veri bütünlüğü mekanizmaları, hata ayıklama karşıtı (anti-debugging) savunmalar ve "tam zamanında" şifre çözme ve otomatik yeniden gizleme için bir **Güvenli Kapsam Erişimi (RAII)** sunar. Bu, **RAM** belleğindeki veri maruziyetini önemli ölçüde en aza indirir ve profesyonel düzeyde derinlemesine bir savunma sağlar.

## Diller

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- English: [README](../English/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)

## İçindekiler

- [Dralyxor](#dralyxor)
  - [Diller](#diller)
  - [İçindekiler](#i̇çindekiler)
  - [Hızlı Entegrasyon ve Kullanım Kılavuzu](#hızlı-entegrasyon-ve-kullanım-kılavuzu)
    - [Kurulum](#kurulum)
    - [Derleyici Gereksinimleri](#derleyici-gereksinimleri)
    - [Temel Kullanım Desenleri](#temel-kullanım-desenleri)
      - [Desen 1: Yerel (Stack) Gizleme](#desen-1-yerel-stack-gizleme)
      - [Desen 2: Statik (Global) Gizleme](#desen-2-statik-global-gizleme)
    - [Hata Yönetimi ve Bütünlük](#hata-yönetimi-ve-bütünlük)
  - [Ayrıntılı Tasarım Felsefesi ve Mimarisi](#ayrıntılı-tasarım-felsefesi-ve-mimarisi)
    - [Süregelen Tehdit: String Literallerinin Güvenlik Açığı](#süregelen-tehdit-string-literallerinin-güvenlik-açığı)
    - [**Dralyxor**'un Çok Katmanlı Mimari Çözümü](#dralyxorun-çok-katmanlı-mimari-çözümü)
  - [Mimari Bileşenlerin Derinlemesine Analizi](#mimari-bileşenlerin-derinlemesine-analizi)
    - [Bileşen 1: Mikro-Program ile Dönüşüm Motoru](#bileşen-1-mikro-program-ile-dönüşüm-motoru)
      - [Derleme Zamanı Üretimi için `consteval` ve `constexpr` Gücü](#derleme-zamanı-üretimi-için-consteval-ve-constexpr-gücü)
      - [Bir **Dralyxor** Mikro-Programının Anatomisi](#bir-dralyxor-mikro-programının-anatomisi)
        - [Rastgele Talimat Üretimi ve Uygulayıcı Seçimi](#rastgele-talimat-üretimi-ve-uygulayıcı-seçimi)
        - [Entropi için Değişken ve Mantıksal NOP'lar](#entropi-için-değişken-ve-mantıksal-noplar)
      - [Mikro-Programın Kendisinin Gizlenmesi](#mikro-programın-kendisinin-gizlenmesi)
      - [Statik Gizlemenin Yaşam Döngüsü](#statik-gizlemenin-yaşam-döngüsü)
    - [Bileşen 2: Güvenli Erişim ve **RAM**'de Maruz Kalmanın Minimizasyonu](#bileşen-2-güvenli-erişim-ve-ramde-maruz-kalmanın-minimizasyonu)
      - [`Secure_Accessor` ve RAII Prensibi](#secure_accessor-ve-raii-prensibi)
      - [`Secure_Accessor`'da Bellek Parçalanması](#secure_accessorda-bellek-parçalanması)
      - [Güvenli Bellek Temizliği](#güvenli-bellek-temizliği)
    - [Bileşen 3: Çalışma Zamanı Savunmaları (Anti-Debugging ve Anti-Tampering)](#bileşen-3-çalışma-zamanı-savunmaları-anti-debugging-ve-anti-tampering)
      - [Çok Platformlu Hata Ayıklayıcı Tespiti](#çok-platformlu-hata-ayıklayıcı-tespiti)
      - [Tespit veya Bütünlük İhlali Durumunda İşleyişe Etkisi](#tespit-veya-bütünlük-i̇hlali-durumunda-i̇şleyişe-etkisi)
      - [Nesne Bütünlük Kanaryaları](#nesne-bütünlük-kanaryaları)
      - [String İçeriği Sağlama Toplamı](#string-i̇çeriği-sağlama-toplamı)
    - [Bileşen 4: Benzersiz ve Tahmin Edilemez Anahtar ve Tohum Üretimi](#bileşen-4-benzersiz-ve-tahmin-edilemez-anahtar-ve-tohum-üretimi)
      - [`compile_time_seed` için Entropi Kaynakları](#compile_time_seed-için-entropi-kaynakları)
      - [İçerik Dönüşümleri için Türetilmiş Tohumlar](#i̇çerik-dönüşümleri-için-türetilmiş-tohumlar)
      - ["Replay" Saldırılarına ve Desen Analizine Karşı Bağışıklık](#replay-saldırılarına-ve-desen-analizine-karşı-bağışıklık)
  - [Tam Genel API Referansı](#tam-genel-api-referansı)
    - [Gizleme Makroları](#gizleme-makroları)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
    - [Güvenli Erişim Makrosu](#güvenli-erişim-makrosu)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Gelişmiş Özellikler ve İyi Uygulamalar](#gelişmiş-özellikler-ve-i̇yi-uygulamalar)
    - [Tam Unicode Desteği (Geniş Stringler - `wchar_t`)](#tam-unicode-desteği-geniş-stringler---wchar_t)
    - [**C++** Standartlarına ve Ortamlara (Kernel Mode) Akıllı Uyum](#c-standartlarına-ve-ortamlara-kernel-mode-akıllı-uyum)
    - [Performans ve Ek Yük Hususları](#performans-ve-ek-yük-hususları)
    - [Katmanlı Bir Güvenlik Stratejisine Entegrasyon](#katmanlı-bir-güvenlik-stratejisine-entegrasyon)
  - [Lisans](#lisans)
    - [Koşullar:](#koşullar)

## Hızlı Entegrasyon ve Kullanım Kılavuzu

### Kurulum

**Dralyxor** bir **header-only** kütüphanedir. Önceden derleme veya kütüphane bağlama (`.lib`/`.a`) gerekmez.

1.  **`Dralyxor` Dizinini Kopyalayın:** Kütüphanenin en son sürümünü edinin (depoyu klonlayın veya zip dosyasını indirin) ve tüm `Dralyxor` dizinini (tüm `.hpp` dosyalarını içeren) projenizin erişebileceği bir yere kopyalayın (örneğin, `libs/`, `libraries/` veya `vendor/` klasörü).
2.  **Ana Başlık Dosyasını Ekleyin:** Kaynak kodunuzda, ana başlık dosyası `dralyxor.hpp`'yi ekleyin:
    ```cpp
    #include "yol/Dralyxor/dralyxor.hpp"
    ```

Tipik bir proje yapısı:
```
/Projem/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor buraya
        |-- dralyxor.hpp            (Ana giriş noktası)
        |-- obfuscated_string.hpp   (Obfuscated_String sınıfı)
        |-- secure_accessor.hpp     (Secure_Accessor sınıfı)
        |-- algorithms.hpp          (Dönüşüm motoru ve mikro-programlar)
        |-- anti_debug.hpp          (Çalışma zamanı tespitleri)
        |-- prng.hpp                (Derleme zamanı sözde rastgele sayı üreteci)
        |-- integrity_constants.hpp (Bütünlük kontrolleri için sabitler)
        |-- secure_memory.hpp       (Güvenli bellek temizliği)
        |-- detection.hpp           (Derleyici/C++ standardı tespit makroları)
        `-- env_traits.hpp          (Kısıtlı ortamlar için type_traits uyarlamaları)
```

### Derleyici Gereksinimleri

> [!ÖNEMLİ]
> **Dralyxor**, derleme zamanında maksimum güvenlik ve verimlilik için modern **C++** odaklı tasarlanmıştır.
>
> - **Minimum C++ Standardı: C++14**. Kütüphane, genelleştirilmiş `constexpr` gibi özellikleri kullanır ve `if constexpr` (varsa `_DRALYXOR_IF_CONSTEXPR` aracılığıyla) için uyum sağlar.
> - **Üst Standartlara Uyum:** Proje bu standartlarla derlenirse **C++17** ve **C++20**'nin (örneğin `consteval`, `type_traits` için `_v` sonekleri) optimizasyonlarını veya sözdizimlerini algılar ve kullanır. `_DRALYXOR_CONSTEVAL`, C++20'de `consteval`'e ve C++14/17'de `constexpr`'e eşlenir, mümkün olduğunda derleme zamanı yürütülmesini garanti eder.
> - **Desteklenen Derleyiciler:** Öncelikle en son MSVC, GCC ve Clang ile test edilmiştir.
> - **Çalışma Ortamı:** **Kullanıcı Modu** uygulamaları ve **Çekirdek Modu** ortamları (örneğin, Windows sürücüleri) ile tam uyumludur. Çekirdek Modunda, STL'nin mevcut olmayabileceği durumlarda, **Dralyxor** gerekli `type traits` için dahili uygulamalar kullanır (`env_traits.hpp` bakın).

### Temel Kullanım Desenleri

#### Desen 1: Yerel (Stack) Gizleme

Bir fonksiyon kapsamıyla sınırlı, geçici stringler için idealdir. Bellek otomatik olarak yönetilir ve temizlenir.

```cpp
#include "Dralyxor/dralyxor.hpp" // Yolu gerektiği gibi ayarlayın
#include <iostream>

void Configure_Logging() {
    // Sadece yerel olarak kullanılan günlük formatlama anahtarı.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Sınırlı bir kapsam içinde güvenli erişim
    {
        // Secure_Accessor, oluşturulurken 'log_format_key'i geçici olarak şifresini çözer
        // (ve iç arabelleklerine kopyaladıktan hemen sonra 'log_format_key'i yeniden gizler),
        // erişime izin verir ve yok edildiğinde kendi arabelleklerini temizler.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Her zaman Get()'in nullptr döndürmediğini kontrol edin
            std::cout << "Kullanılan günlük formatı: " << accessor.Get() << std::endl;
            // Örn: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "log_format_key şifresi çözülemedi (muhtemel kurcalama veya hata ayıklayıcı tespiti?)" << std::endl;
    } // accessor yok edilir, iç arabellekleri temizlenir. log_format_key gizli kalır.
      // log_format_key, Configure_Logging fonksiyonunun sonunda yok edilecektir.
}
```

#### Desen 2: Statik (Global) Gizleme

Programın ömrü boyunca kalması ve global olarak erişilmesi gereken sabitler için.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Örnek için

// Lisans API URL'si, kalıcı bir sır.
// DRALYXOR() makrosu statik bir nesne oluşturur.
// Get_License_Server_URL() fonksiyonu bu statik nesneye bir referans döndürür.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref, statik Obfuscated_String'e bir referanstır.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // url_obj_ref için bir Secure_Accessor oluşturur.

        if (accessor.Get()) {
            std::cout << "Lisans sunucusuyla iletişim kuruluyor: " << accessor.Get() << std::endl;
            // Örn: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Örnek için başarı simülasyonu
        }
        else
            std::cerr << "Lisans sunucusu URL'sinin şifresi çözülemedi (muhtemel kurcalama veya hata ayıklayıcı tespiti?)." << std::endl;
    } // accessor yok edilir, arabellekleri temizlenir. url_obj_ref (orijinal Obfuscated_String) gizli kalır.

    return success;
}
```

### Hata Yönetimi ve Bütünlük

`Obfuscated_String::Decrypt()` ve `Encrypt()` fonksiyonları `uint64_t` döndürür:
- `0` başarıyı gösterir.
- `Dralyxor::Detail::integrity_compromised_magic` (`integrity_constants.hpp`'de tanımlanan bir sabit değer), bir bütünlük kontrolünün başarısız olduğunu gösterir. Bu, bozuk nesne kanaryaları, tutarsız içerik sağlama toplamı veya düşmanca bir ortamı işaret eden bir hata ayıklayıcının tespit edilmesinden kaynaklanabilir.

Benzer şekilde, `Secure_Accessor::Get()` (veya `const CharT*` türüne örtük dönüşümü), `Secure_Accessor`'ın başlatılması başarısız olursa (örneğin, orijinal `Obfuscated_String`'in şifresinin çözülmesi başarısız olursa) veya `Secure_Accessor`'ın bütünlüğü (kendi kanaryaları veya dahili sağlama toplamları) ömrü boyunca tehlikeye girerse `nullptr` döndürür.

**Uygulamanın sağlamlığını ve güvenliğini sağlamak için kodunuzun bu dönüşleri kontrol etmesi kritik öneme sahiptir.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Genellikle Decrypt() ve Encrypt()'i doğrudan ÇAĞIRMAZSINIZ,
    // çünkü Secure_Accessor bunu yönetir. Ama bir sebepten ihtiyacınız olursa:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "UYARI: 'my_secret' şifresi çözülemedi veya Decrypt() sırasında bütünlük tehlikeye girdi!" << std::endl;
        // Uygun bir eylemde bulunun: sonlandırın, güvenli bir şekilde günlüğe kaydedin, vb.
        // my_secret.storage_ nesnesi geçersiz bir durumda veya çöp içerebilir.
        return; // Decrypt() başarısız olursa my_secret'ı kullanmaktan kaçının.
    }

    // Decrypt() başarılı olduysa, my_secret.storage_ çözülmüş veriyi içerir.
    // **storage_'A DOĞRUDAN ERİŞİM ÜRETİMDE KESİNLİKLE ÖNERİLMEZ.**
    // std::cout << "my_secret.storage_ içindeki veri (BUNU YAPMAYIN): " << my_secret.storage_ << std::endl;

    // Decrypt()'i manuel olarak çağırdıysanız yeniden şifrelemek sizin sorumluluğunuzdadır:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "UYARI: 'my_secret' yeniden şifrelenemedi veya Encrypt() sırasında bütünlük tehlikeye girdi!" << std::endl;
        // Belirsiz durum, potansiyel olarak tehlikeli.
    }

    // Secure_Accessor ile ÖNERİLEN KULLANIM:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Secure_Accessor'ın kurucusu another_secret.Decrypt()'i çağırır, kopyalar ve ardından another_secret.Encrypt()'i çağırır.
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Veya: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Secure_Accessor aracılığıyla gizli veri: " << data_ptr << std::endl;
            // data_ptr'ı burada kullanın
        }
        else {
            std::cerr << "UYARI: Secure_Accessor 'another_secret' için başlatılamadı veya işaretçi alınamadı!" << std::endl;
            // Bu, accessor'ın kurucusu içindeki Decrypt()'in başarısız olduğunu
            // veya accessor'da kurcalama (kanaryalar, dahili sağlama toplamları) olduğunu gösterir.
        }
    } // accessor yok edilir. Arabellekleri temizlenir. another_secret gizli kalır.
}
```

## Ayrıntılı Tasarım Felsefesi ve Mimarisi

**Dralyxor** yalnızca bir XOR şifresi değildir; string literalleri için derinlemesine bir savunma sistemidir. Mimarisi, etkili güvenliğin birden fazla birbirine bağlı katman ve çeşitli analiz tekniklerine karşı dayanıklılık gerektirdiği öncülüne dayanmaktadır.

### Süregelen Tehdit: String Literallerinin Güvenlik Açığı

`"api.example.com/data?key="` gibi string literalleri, doğrudan koda gömüldüğünde, derlenmiş ikili dosyada okunabilir biçimde (düz metin) yazılır. `strings`, çözümleyiciler (IDA Pro, Ghidra) ve onaltılık düzenleyiciler gibi araçlar bunları kolayca çıkarabilir. Bu maruziyet şunları kolaylaştırır:
- **Tersine Mühendislik:** Programın iç mantığını ve akışını anlama.
- **Uç Noktaların Tanımlanması:** Arka uç sunucularının ve API'lerin keşfi.
- **Sırların Çıkarılması:** API anahtarları, gömülü şifreler, özel URL'ler, SQL sorguları vb.
- **Dinamik Bellek Analizi:** Bir program kullanım için bir string'in şifresini çözse bile, **RAM**'de uzun süre düz metin olarak kalırsa, işlem belleğine erişimi olan bir saldırgan (hata ayıklayıcı veya bellek dökümü yoluyla) onu bulabilir.

**Dralyxor**, bu güvenlik açıklarına hem derleme zamanında (diskteki ikili dosya için) hem de çalışma zamanında (**RAM** belleği için) saldırır.

### **Dralyxor**'un Çok Katmanlı Mimari Çözümü

**Dralyxor**'un sağlamlığı, temel bileşenlerinin sinerjisinden kaynaklanır:

| Mimari Bileşen                         | Temel Amaç                                                                             | Kullanılan Temel Teknolojiler/Teknikler                                                                                                                           |
| :------------------------------------- | :------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Mikro-Program ile Dönüşüm Motoru**    | İkili dosyadan düz metin stringleri ortadan kaldırmak; karmaşık, dinamik ve önemsiz olmayan gizleme oluşturmak. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, çoklu işlemler (XOR, ADD, ROT, vb.), değişken ve mantıksal NOP'lar, değişken uygulayıcı stilleri.     |
| **Güvenli Erişim ve Maruz Kalmanın Minimizasyonu** | Bir sırrın RAM belleğinde şifresi çözülmüş olarak kaldığı süreyi önemli ölçüde azaltmak.          | RAII Deseni (`Secure_Accessor`), bellek parçalanması, arabelleklerin güvenli temizlenmesi (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                   |
| **Çalışma Zamanı Savunmaları**           | Düşmanca analiz ortamlarını ve bellek kurcalamasını tespit etmek ve bunlara tepki vermek.       | Hata Ayıklayıcı Tespiti (OS'ye özgü API'ler, zamanlama, OutputDebugString), nesne bütünlük kanaryaları, string içeriği sağlama toplamı.                        |
| **Benzersiz Anahtar ve Tohum Üretimi** | Her gizlenmiş string'in ve her kullanım örneğinin kriptografik olarak farklı olmasını sağlamak. | `__DATE__`, `__TIME__`, `__COUNTER__`, string boyutu, `compile_time_seed` için FNV-1a karma, işlenen değiştiriciler ve seçiciler için türetilmiş tohumlar. |

## Mimari Bileşenlerin Derinlemesine Analizi

### Bileşen 1: Mikro-Program ile Dönüşüm Motoru

**Dralyxor**'un statik ve dinamik gizlemesinin kalbi, her string ve bağlam için benzersiz "mikro-programlar" kullanan dönüşüm motorunda yatar.

#### Derleme Zamanı Üretimi için `consteval` ve `constexpr` Gücü
Modern **C++**, `consteval` (**C++20**) ve `constexpr` (**C++11**'den itibaren) ile karmaşık kodun *derleme sırasında* yürütülmesine olanak tanır. **Dralyxor**, `Obfuscated_String` kurucusu ve mikro-program üretimi için `_DRALYXOR_CONSTEVAL`'i (C++ standardına bağlı olarak `consteval` veya `constexpr`'e eşlenir) kullanır.

Bu, tüm sürecin:
1.  Sözde rastgele bir dönüşüm talimatları dizisi (mikro-program) üretmek.
2.  Depolama için mikro-programın kendisini gizlemek.
3.  Bu mikro-programı (geçici olarak şifresi çözülmüş biçimde) orijinal string'i dönüştürmek için uygulamak, sonuç olarak gizlenmiş formunu elde etmek.
Tüm bunlar, ikili dosya oluşturulmadan önce derleme zamanında gerçekleşir.

#### Bir **Dralyxor** Mikro-Programının Anatomisi

Her `Obfuscated_String` nesnesi, küçük bir `Dralyxor::Detail::Micro_Instruction` dizisi saklar. Bir `Micro_Instruction`, `algorithms.hpp`'de tanımlanan basit bir yapıdır:
```cpp
// Dralyxor::Detail içinde (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM // Mevcut olmasına rağmen, mikro-programın yürütülmesini sonlandırmak için aktif olarak kullanılmaz,
                   // yineleme 'num_actual_instructions_in_program_' tarafından kontrol edilir.
};

struct Micro_Instruction {
    Micro_Operation_Code op_code; // İşlem (XOR, ADD, ROTL, vb.)
    uint8_t operand;            // İşlem tarafından kullanılan değer
};

// Bir mikro-programın içerebileceği maksimum talimat sayısı.
static constexpr size_t max_micro_instructions = 8;
```
`_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` fonksiyonu bu diziyi doldurmaktan sorumludur.

##### Rastgele Talimat Üretimi ve Uygulayıcı Seçimi

- **Talimat Üretimi:** Bir `Dralyxor::Detail::Constexpr_PRNG` kullanarak (`compile_time_seed` ve `0xDEADBEEFC0FFEEULL` kombinasyonuyla tohumlanmış), `Generate_Micro_Program_Instructions` fonksiyonu olasılıksal olarak bir işlemler dizisi seçer:
   - `XOR`: İşlenenle bitsel XOR.
   - `ADD`: İşlenenle modüler toplama.
   - `SUB`: İşlenenle modüler çıkarma.
   - `ROTR`/`ROTL`: Bit döndürme. İşlenen (modülden sonra) kaydırma sayısını (1 ila 7) tanımlar.
   - `SWAP_NIB`: Bir baytın alt 4 bitini üst 4 bitiyle değiştirir (işlenen yok sayılır).
    Bu talimatların işlenenleri de PRNG tarafından sözde rastgele üretilir.

- **Dönüşüm Zamanında İşlenenlerin Değiştirilmesi ve Uygulayıcıların Seçilmesi:** Mikro-programın uygulanması sırasında (hem ilk gizlemede hem de çalışma zamanı şifre çözmede `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` tarafından):
   - Bir `Constexpr_PRNG prng_operand_modifier` (`base_seed` ile tohumlanmış) string'in her karakteri için bir `prng_key_for_ops_in_elem` üretir. Mikro-talimatın işleneni (`instr_orig.operand`) kullanılmadan önce bu anahtarla XOR'lanır. Bu, aynı mikro-programın her karakter için biraz farklı dönüşümler uygulamasını sağlar.
   - Bir `Constexpr_PRNG prng_applier_selector` (`base_seed ^ 0xAAAAAAAAAAAAAAAAULL` ile tohumlanmış) her karakter için bir `Byte_Transform_Applier` seçer. Şu anda iki stil mevcuttur:
      - `Applier_Style_Direct`: İşlemi doğrudan uygular (şifre çözme için tersine çevirerek, ADD'nin SUB olması gibi).
      - `Applier_Style_DoubleLayer`: İşlemi farklı işlenenlerle iki kez uygular (veya şifreleme/şifre çözme moduna bağlı olarak işlemi ve tersini), tersine çevirmeyi analiz etmeyi biraz daha karmaşık hale getirir.

##### Entropi için Değişken ve Mantıksal NOP'lar

Mikro-programın manuel analizinin zorluğunu artırmak için **Dralyxor** şunları ekler:
- **Açık NOP'lar:** Hiçbir şey yapmayan `Micro_Operation_Code::NOP` talimatları.
- **Mantıksal NOP'lar:** Birbirini etkisiz hale getiren talimat çiftleri, örneğin `ADD K` ardından `SUB K` veya `ROTL N_BITS` ardından `ROTR N_BITS`. Çiftte kullanılan işlenen aynıdır.

Bu NOP'lar `Generate_Micro_Program_Instructions` tarafından olasılıksal olarak eklenir, `micro_program_` dizisini doldurur ve etkili dönüşümleri "gürültü" işlemlerinden ayırt etmeyi zorlaştırır.

#### Mikro-Programın Kendisinin Gizlenmesi

Mikro-program üretildikten ve string'in `consteval` kurucusunda ilk gizlenmesinden önce, `Obfuscated_String` nesnesinde bulunan `micro_program_` dizisinin kendisi gizlenir. Her `Micro_Instruction` içindeki her `op_code` ve `operand`, `compile_time_seed`'den türetilen bir anahtarla XOR'lanır (`Detail::Get_Micro_Program_Obfuscation_Key` ve `Detail::Obfuscate_Deobfuscate_Instruction` kullanılarak).
Bu, bir saldırgan `Obfuscated_String` nesnesinin belleğini dökmeyi başarsa bile, mikro-programın doğrudan okunabilir/uygulanabilir biçiminde olmayacağı anlamına gelir.

`Obfuscated_String::Decrypt()` veya `Encrypt()` çağrıldığında (veya dolaylı olarak `Secure_Accessor` tarafından), merkezi `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` fonksiyonu bu *gizlenmiş* mikro-programı alır. Ardından:
1.  Mikro-programın yığında geçici bir kopyasını (`local_plain_program`) oluşturur.
2.  Bu yerel kopyanın şifresini, iletilen temel tohumdan (ki bu sonuçta `compile_time_seed`'dir) türetilen aynı anahtarı (`program_obf_key`) kullanarak çözer.
3.  String verilerini dönüştürmek için bu `local_plain_program`'ı kullanır.
Yığındaki yerel kopya fonksiyonun sonunda yok edilir ve `Obfuscated_String` nesnesinde saklanan `micro_program_` gizli kalır.

#### Statik Gizlemenin Yaşam Döngüsü

1.  **Kaynak Kodu:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2.  **Ön İşleme:** Makro, bir `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");` örneğine genişler. (15 boyutu null sonlandırıcıyı içerir).
3.  **`_DRALYXOR_CONSTEVAL` Değerlendirmesi:**
    - Derleyici, `Obfuscated_String` kurucusunu çalıştırır.
    - `Initialize_Internal_Canaries()` bütünlük kanaryalarını ayarlar.
    - `Generate_Micro_Program_Instructions()` (`compile_time_seed ^ 0xDEADBEEFC0FFEEULL` ile tohumlanmış) bir `Micro_Instruction` dizisi oluşturur ve `this->micro_program_`'da saklar (örn: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Gerçek talimat sayısı `num_actual_instructions_in_program_`'da saklanır.
    - Orijinal "SECRET\_API\_KEY" string'i `this->storage_`'e kopyalanır.
    - Orijinal "SECRET\_API\_KEY" string'inin (null hariç) bir sağlama toplamı `Detail::Calculate_String_Content_Checksum` tarafından hesaplanır ve ardından `Detail::Obfuscate_Deobfuscate_Short_Value` (`compile_time_seed` ve `content_checksum_obf_salt` kullanılarak) ile gizlenir ve `this->_content_checksum_obfuscated`'da saklanır.
    - `Obfuscate_Internal_Micro_Program()` çağrılır: `this->micro_program_` yerinde gizlenir (her talimat `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)` ile XOR'lanır).
    - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` çağrılır. Bu fonksiyon:
        - Yığında `this->micro_program_`'ın şifresi çözülmüş bir kopyasını oluşturur.
        - `storage_` içindeki her karakter için (null hariç):
            - `prng_key_for_ops_in_elem` üretir ve bir `Byte_Transform_Applier` seçer.
            - Mikro-talimatlar dizisini (şifresi çözülmüş kopyadan) karaktere, uygulayıcıyı ve değiştirilmiş işleneni kullanarak uygular.
        - Sonunda, `storage_` gizlenmiş string'i içerir (örn: `[CF, 3A, D1, ..., 0x00]`).
4.  **Kod Üretimi:** Derleyici, `api_key_obj` için yer ayırır ve onu doğrudan şunlarla başlatır:
    - `storage_`: `[CF, 3A, D1, ..., 0x00]` (gizlenmiş string).
    - `micro_program_`: *Zaten gizlenmiş* olan mikro-program.
    - `_content_checksum_obfuscated`: Orijinal içeriğin sağlama toplamı, *gizlenmiş*.
    - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    `"SECRET_API_KEY"` literali artık ikili dosyada mevcut değildir.

### Bileşen 2: Güvenli Erişim ve **RAM**'de Maruz Kalmanın Minimizasyonu

#### `Secure_Accessor` ve RAII Prensibi

Derleme zamanı koruması savaşın sadece yarısıdır. String'in kullanılması gerektiğinde şifresinin çözülmesi gerekir. Bu şifresi çözülmüş string **RAM** belleğinde uzun bir süre kalırsa, dinamik analiz (bellek dökümleri, hata ayıklayıcılar) için bir hedef haline gelir.

**Dralyxor**, **RAII** (Resource Acquisition Is Initialization - Kaynak Edinimi Başlatmadır) desenini uygulayan bir sınıf olan `Dralyxor::Secure_Accessor` ile bu sorunu ele alır:
- **Edinilen Kaynak:** Erişimcinin yönettiği, parçalanmış ve geçici olarak düz metin string'e erişim.
- **Yönetici Nesne:** `Secure_Accessor` örneği.

```cpp
// secure_accessor.hpp içinde (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Güncellenmezse başarısız olmak için farklı başlat
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Erişimciyi geçersiz kıl

            return;
        }

        // 1. Orijinal Obfuscated_String'in şifresini çözmeye çalışır.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Şifre çözme başarılı olursa, düz metin string'ini dahili parçalara kopyalar.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ şimdi düz metin
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val en fazla 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Parça arabelleğinin geri kalanını null'larla doldur
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Parçaların sağlama toplamı
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. Orijinal Obfuscated_String'i HEMEN yeniden şifreler.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Parçaları ve yeniden oluşturulmuş arabelleği temizler.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Kendisini ve ebeveyni doğrular
            Clear_All_Internal_Buffers(); // Güvenlik önlemi
            _accessor_integrity_canary1 = 0; // Gelecekteki erişimler için geçersiz kıl

            return nullptr;
        }

        if (!current_access_ptr_) { // Get()'e ilk çağrıysa veya temizlendiyse
            if constexpr (N_storage > 0) { // Sadece yeniden oluşturulacak bir şey varsa yeniden oluşturur
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

                // N_storage tam olarak doldurulsa bile null sonlandırmayı garanti eder.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // N_storage == 0 için (teorik olarak boş string), sağlama toplamı yoktur
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Kontrolü geçmek için

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // N_storage 0 ise, arabellek > 0 ise bu güvenlidir
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Bütünlüğü sağlamak için herhangi bir dahili işlemden sonra tekrar kontrol edin.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**`DRALYXOR_SECURE` ile Kullanım Akışı:**
1.  `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
    - `Secure_Accessor`'ın kurucusu çağrılır.
    - `my_obfuscated_string.Decrypt()`'i çağırır. Bu, `micro_program_`'ın şifresinin çözülmesini (yerel bir kopyaya), `my_obfuscated_string.storage_`'ın şifresini çözmek için kullanılmasını ve ardından kanaryaların ve şifresi çözülmüş içeriğin sağlama toplamının beklenene göre doğrulanmasını içerir.
    - Başarılı olursa, `my_obfuscated_string.storage_`'ın içeriği (şimdi düz metin) `Secure_Accessor`'ın dahili `fragments_storage_`'ına kopyalanır ve bölünür.
    - `fragments_storage_`'ın bir sağlama toplamı (`fragments_data_checksum_expected_`) hesaplanır.
    - Kritik olarak, `my_obfuscated_string.Encrypt()` *hemen ardından* çağrılır ve `my_obfuscated_string.storage_` yeniden gizlenir.
2.  `const char* ptr = accessor.Get();` (veya örtük dönüşüm nedeniyle `const char* ptr = accessor;`)
    - `Secure_Accessor::Get()` çağrılır.
    - Kendi bütünlük kanaryalarını ve ebeveyn `Obfuscated_String`'inkileri doğrular.
    - İlk erişimse (`current_access_ptr_` `nullptr` ise), `reconstructed_plain_buffer_`'da `fragments_storage_`'dan tam string'i yeniden oluşturur.
    - Ardından `fragments_storage_`'ın `Secure_Accessor` var olduğu sürece kurcalanmadığından emin olmak için `fragments_data_checksum_reconstructed_`'ı `fragments_data_checksum_expected_` ile karşılaştırır.
    - Her şey doğruysa, `reconstructed_plain_buffer_`'a bir işaretçi döndürür.
3.  `accessor`'ın kapsamı sona erer (fonksiyondan çıkar, `{}` bloğu sona erer vb.).
    - `Secure_Accessor`'ın yıkıcısı otomatik olarak çağrılır.
    - `Clear_All_Internal_Buffers()` çağrılır, bu da hem `reconstructed_plain_buffer_`'ı hem de `fragments_storage_`'ı güvenli bir şekilde (`Secure_Clear_Memory`) temizler.

Sonuç, düz metin string'in tam biçimde yalnızca `Secure_Accessor` içinde (`reconstructed_plain_buffer_`'da) ve yalnızca `Get()`'e ilk çağrıdan sonra, mümkün olan en kısa süre boyunca var olmasıdır. Orijinal `Obfuscated_String` nesnesindeki string, `Secure_Accessor` oluşturulurken içeriğini kopyaladıktan sonra yeniden gizlenir.

#### `Secure_Accessor`'da Bellek Parçalanması

Düz metin halindeki tam string'in bellekte bulunmasını daha da zorlaştırmak için `Secure_Accessor`, oluşturulması sırasında şifresi çözülmüş string'i sadece kopyalamakla kalmaz, aynı zamanda böler:
1.  Ebeveyn `Obfuscated_String`'den gelen string'in şifresi çözülür.
2.  İçeriği, `fragment_count_val` (şu anda string yeterince büyükse 4) adede kadar parçaya bölünür ve `fragments_storage_[i]`'ye kopyalanır.
3.  Ebeveyn `Obfuscated_String` nesnesindeki string yeniden gizlenir.

Yalnızca `Secure_Accessor::Get()` ilk kez çağrıldığında bu parçalar `reconstructed_plain_buffer_`'da yeniden birleştirilir. Bu teknik, hassas verileri "dağıtmayı" amaçlar ve sürekli string'ler arayan bellek taramalarını engeller.

#### Güvenli Bellek Temizliği

Hem `Obfuscated_String`'in yıkıcısı (`Clear_Internal_Data` aracılığıyla) hem de `Secure_Accessor`'ın yıkıcısı (`Clear_All_Internal_Buffers` aracılığıyla) `Dralyxor::Detail::Secure_Clear_Memory` (diziler için şablon) veya `Dralyxor::Detail::Secure_Clear_Memory_Raw` (ham işaretçiler için, ancak yıkıcılarda `Secure_Clear_Memory` daha çok kullanılır) kullanır. Bu sarmalayıcı fonksiyon:
- Mevcut olduğunda `SecureZeroMemory` (Windows Kullanıcı Modu) veya `RtlSecureZeroMemory` (Windows Çekirdek Modu) kullanır, bunlar işletim sistemi tarafından derleyici tarafından optimize edilmemesi için tasarlanmış fonksiyonlardır.
- Diğer platformlarda veya Windows'a özgü fonksiyonlar mevcut olmadığında `volatile T* p` işaretçisiyle bir döngüye başvurur. `volatile`, derleyiciye sıfır yazımını optimize etmemesini bildirme girişimidir. Bu, nesneler yok edildiğinde veya arabellekler açıkça temizlendiğinde hassas içeriğin üzerine yazılmasını sağlar, böylece veri kurtarma riskini azaltır.

### Bileşen 3: Çalışma Zamanı Savunmaları (Anti-Debugging ve Anti-Tampering)

**Dralyxor** yalnızca gizlemeye güvenmez. Esas olarak `anti_debug.hpp`'de bulunan ve `Obfuscated_String`'in `Decrypt()` ve `Encrypt()` metotlarına entegre edilmiş bir dizi aktif çalışma zamanı savunması kullanır.

#### Çok Platformlu Hata Ayıklayıcı Tespiti

`Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` fonksiyonu (`anti_debug.hpp` içinde) işletim sistemine özgü teknikler kullanarak bir hata ayıklayıcının varlığını kontrol eder:
- **Windows:** `IsDebuggerPresent()`, `ProcessDebugPort` (0x07) ve `ProcessDebugFlags` (0x1F) için `NtQueryInformationProcess`.
- **Linux:** `/proc/self/status` dosyasını okuma ve `TracerPid:` değerini kontrol etme. 0'dan farklı bir değer, işlemin izlendiğini gösterir.
- **macOS:** `kinfo_proc` almak ve `kp_proc.p_flag`'daki `P_TRACED` bayrağını kontrol etmek için `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` ile `sysctl` kullanımı.

Ek olarak, `Detail::Calculate_Runtime_Key_Modifier()` içinde:
- `Detail::Perform_Timing_Check_Generic()`: Basit hesaplama işlemlerinden oluşan bir döngü çalıştırır ve süreyi ölçer. Önemli bir yavaşlama (`timing_threshold_milliseconds = 75ms` üzerinde) bir hata ayıklayıcının tek adımlama yaptığını veya kapsamlı kesme noktalarının (breakpoint) aktif olduğunu gösterebilir. Bu döngü içinde, `Is_Debugger_Present_Tracer_Pid_Sysctl()` çağrılır ve "tuzak" bir fonksiyon olan `Detail::Canary_Function_For_Breakpoint_Check()` (sadece `0xCC` döndürür, `int3` / yazılım kesme noktası için talimat kodu) çağrılır ve sonucu XOR'lanır, bu da optimizasyonu zorlaştırır ve kesme noktaları için ortak bir konum sağlar.
- `Detail::Perform_Output_Debug_String_Trick()` (yalnızca Windows Kullanıcı Modu): `OutputDebugStringA/W` ve `GetLastError()` davranışını kullanır. Bir hata ayıklayıcı bağlıysa, `OutputDebugString` çağrısından sonra `GetLastError()` değiştirilebilir.

#### Tespit veya Bütünlük İhlali Durumunda İşleyişe Etkisi

Hata ayıklama karşıtı kontrollerden herhangi biri `true` döndürürse veya `Obfuscated_String`'in bütünlük kanaryaları (`_internal_integrity_canary1/2`) bozulmuşsa, `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` fonksiyonu `Detail::integrity_compromised_magic` döndürür.

Bu dönen değer, `Obfuscated_String::Decrypt()` ve `Encrypt()` fonksiyonlarında kritik öneme sahiptir:
```cpp
// Obfuscated_String::Decrypt()'in basitleştirilmiş mantığı
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Obfuscated_String kanaryaları
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
        // ... Kanaryaları tekrar kontrol et ...

        // EĞER runtime_key_mod integrity_compromised_magic DEĞİLSE, ŞİFRE ÇÖZME ANAHTARINI DEĞİŞTİRMEK İÇİN KULLANILMAZ.
        // Şifre çözme anahtarı her zaman orijinal 'compile_time_seed'den türetilir.
        // runtime_key_mod'un buradaki rolü, düşmanca bir ortam SİNYALİ OLARAK HAREKET ETMEKTİR.
        // Düşmanca ise, fonksiyon integrity_compromised_magic döndürür ve şifre çözme devam etmez veya geri alınır.
        
        // Transform_Compile_Time_Consistent, compile_time_seed ile çağrılır (runtime_key_mod ile DEĞİL)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* şifre çözme modu */);
        
        // ... Sağlama toplamını ve kanaryaları tekrar kontrol et ...
        // Bir şey başarısız olursa, Clear_Internal_Data() ve integrity_compromised_magic döndür.
        decrypted_ = true;
    }

    return 0; // Başarı
}
```

**Temel Etki:** `Calculate_Runtime_Key_Modifier` bir sorun tespit ederse (hata ayıklayıcı veya bozuk kanarya) ve `integrity_compromised_magic` döndürürse, `Decrypt()` (ve benzer şekilde `Encrypt()`) fonksiyonları işlemi durdurur, `Obfuscated_String`'in dahili verilerini ( `storage_` ve `micro_program_` dahil) temizler ve `integrity_compromised_magic` döndürür. Bu, string'in düşmanca bir ortamda veya nesne kurcalanmışsa doğru bir şekilde şifresinin çözülmesini (veya yeniden şifrelenmesini) engeller.
String "yanlışlıkla" (çöp verilere) şifresi çözülmez; işlem basitçe engellenir ve `Obfuscated_String` nesnesi yararlı içerik açısından kendi kendini yok eder.

#### Nesne Bütünlük Kanaryaları

Hem `Obfuscated_String` hem de `Secure_Accessor` sınıfları kanarya üyeleri (`uint32_t` çiftleri) içerir:
- `Obfuscated_String`: `_internal_integrity_canary1` (`Detail::integrity_canary_value` ile başlatılır) ve `_internal_integrity_canary2` (`~Detail::integrity_canary_value` ile başlatılır).
- `Secure_Accessor`: `_accessor_integrity_canary1` (`Detail::accessor_integrity_canary_seed` ile başlatılır) ve `_accessor_integrity_canary2` (`~Detail::accessor_integrity_canary_seed` ile başlatılır).

Bu kanaryalar kritik noktalarda kontrol edilir:
- `Obfuscated_String::Decrypt()` ve `Encrypt()`'in başı ve sonu.
- `Secure_Accessor`'ın kurucusu, yıkıcısı ve `Get()`'i.
- `Calculate_Runtime_Key_Modifier`'daki hata ayıklama karşıtı kontrollerden önce ve sonra.

Bu kanarya değerleri değiştirilirse (örneğin, bir arabellek taşması, gelişigüzel bir bellek yaması veya bitişik belleğin üzerine yazan bir kanca tarafından), doğrulama (`Verify_Internal_Canaries()` veya `Verify_Internal_Accessor_Canaries()`) başarısız olur.
Başarısızlık durumunda, işlemler durdurulur, ilgili dahili veriler temizlenir ve bir hata değeri (`Detail::integrity_compromised_magic` veya `nullptr`) döndürülerek kurcalama sinyali verilir.

#### String İçeriği Sağlama Toplamı

- Orijinal *düz metin* string'inin (null sonlandırıcı hariç) 16 bitlik bir sağlama toplamı, derleme zamanında `Detail::Calculate_String_Content_Checksum` tarafından hesaplanır.
- Bu sağlama toplamı daha sonra `Detail::Obfuscate_Deobfuscate_Short_Value` (`compile_time_seed` ve `content_checksum_obf_salt` ile) kullanılarak gizlenir ve `Obfuscated_String` nesnesindeki `_content_checksum_obfuscated`'da saklanır.
- **Şifre Çözerken (`Decrypt()`):** `storage_` dönüştürüldükten sonra (sözde düz metne), sağlama toplamı hesaplanır. Referans sağlama toplamını elde etmek için `_content_checksum_obfuscated`'ın şifresi çözülür. İki sağlama toplamı eşleşmezse, bu şunları gösterir:
   - Şifre çözme, orijinal string'i geri yüklemedi (belki de işlem, tam dönüşümden önce hata ayıklayıcı tespiti nedeniyle durduruldu veya tohum/mikroprogram bozulması oldu).
   - `storage_` (gizlenmişken) veya `_content_checksum_obfuscated` bellekte kurcalandı.
- **Şifrelerken (`Encrypt()`):** `storage_` (bu noktada düz metin halindedir) gizlenmiş formuna geri dönüştürülmeden önce, sağlama toplamı hesaplanır ve referansla karşılaştırılır. Buradaki bir uyuşmazlık, düz metin string'inin şifresi çözülmüşken *`Obfuscated_String`'in `storage_`'ı içinde* değiştirildiği anlamına gelir ki bu, bellek kurcalamasının veya yanlış kullanımın (çünkü `storage_`'a doğrudan erişilmemelidir) güçlü bir göstergesidir.

Her iki sağlama toplamı hatası durumunda da `Clear_Internal_Data()` çağrılır ve `integrity_compromised_magic` döndürülür.

### Bileşen 4: Benzersiz ve Tahmin Edilemez Anahtar ve Tohum Üretimi

Herhangi bir şifreleme sisteminin güvenliği, anahtarlarının ve tohumlarının gücüne ve benzersizliğine dayanır. **Dralyxor**, her gizlenmiş string'in temel olarak benzersiz bir şifreleme parametreleri kümesi kullanmasını sağlar.

#### `compile_time_seed` için Entropi Kaynakları

`static constexpr uint64_t Obfuscated_String::compile_time_seed`, o string örneğiyle ilgili tüm sözde rastgele işlemler için ana tohumdur. `consteval`'de şu şekilde üretilir:
```cpp
// Obfuscated_String<CharT, storage_n, Instance_Counter> içinde
static constexpr uint64_t compile_time_seed =
    Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Bileşen 1: Derlemeler arası değişkenlik
    ((uint64_t)Instance_Counter << 32) ^        // Bileşen 2: Bir derleme birimi içinde değişkenlik
    storage_n;                                  // Bileşen 3: String boyutuna dayalı değişkenlik
```

- **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: `__DATE__` (örn: "Jan 01 2025") ve `__TIME__` (örn: "12:30:00") makroları, dosya her derlendiğinde değişen, ön işlemci tarafından sağlanan stringlerdir. Bu değerlerin FNV-1a karması, projenin her yapısı için farklı olan bir tohum tabanı oluşturur.
- **`Instance_Counter` (`DRALYXOR`/`DRALYXOR_LOCAL` makrosunda `__COUNTER__` ile beslenir)**: `__COUNTER__` makrosu, bir derleme birimi içinde her kullanıldığında artan, ön işlemci tarafından tutulan bir sayaçtır. Bunu `Obfuscated_String`'e bir şablon argümanı `int Instance_Counter` olarak geçerek, `DRALYXOR` veya `DRALYXOR_LOCAL` makrosunun her kullanımı, aynı kaynak dosyadaki aynı string literalleri için bile farklı bir `Instance_Counter` ve dolayısıyla farklı bir `compile_time_seed` ile sonuçlanır.
- **`storage_n` (null dahil string boyutu)**: String boyutu da XOR'lanır, bu da başka bir farklılaştırma faktörü ekler.

Bu `compile_time_seed` daha sonra şunlar için temel olarak kullanılır:
1.  `micro_program_`'ı üretmek (PRNG'yi `compile_time_seed ^ 0xDEADBEEFC0FFEEULL` ile tohumlayarak).
2.  `micro_program_`'ın kendisi için gizleme anahtarını türetmek (`Detail::Get_Micro_Program_Obfuscation_Key` aracılığıyla).
3.  `_content_checksum_obfuscated` için gizleme anahtarını türetmek (`Detail::Obfuscate_Deobfuscate_Short_Value` aracılığıyla).
4.  `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` için `base_seed` olarak hizmet etmek.

#### İçerik Dönüşümleri için Türetilmiş Tohumlar

`Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)` içinde:
- Bir `Constexpr_PRNG prng_operand_modifier(base_seed)` başlatılır. Dönüştürülen string'in her karakteri için, `prng_operand_modifier.Key()` bir `prng_key_for_ops_in_elem` üretir. Bu anahtar, uygulamadan önce mikro-talimatın işleneniyle XOR'lanır, böylece aynı mikro-talimatın etkisinin her karakter için ustaca farklı olması sağlanır.
- Bir `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` başlatılır. Her karakter için, `prng_applier_selector.Key()` `Applier_Style_Direct` ve `Applier_Style_DoubleLayer` arasında seçim yapmak için kullanılır.

Bu, temel mikro-program belirli bir string'in tüm karakterleri için aynı olsa bile, her karakterin dönüşümüne ek bir dinamizm katar.

#### "Replay" Saldırılarına ve Desen Analizine Karşı Bağışıklık

- **Derlemeler Arası Benzersizlik:** Bir saldırgan yazılımınızın 1.0 sürümünün ikili dosyasını analiz eder ve büyük bir çabayla bir string'in gizlemesini kırmayı başarırsa, bu bilgi muhtemelen 1.1 sürümü için işe yaramaz olacaktır, çünkü `__DATE__ __TIME__` değişmiş olacak ve sonuç olarak tamamen farklı `compile_time_seed`'ler ve mikro-programlar ortaya çıkacaktır.
- **Derleme İçi Benzersizlik:** Kodunuzda (veya aynı .cpp dosyasında) iki farklı yerde `DRALYXOR("AdminPassword")` kullanırsanız, `__COUNTER__` ortaya çıkan `Obfuscated_String` nesnelerinin ve dolayısıyla ikili dosyada gizlenmiş temsillerinin (hem `storage_` hem de `micro_program_`) farklı olmasını sağlar. Bu, bir saldırganın gizlenmiş bir desen bulmasını ve bunu aynı orijinal string'in diğer tüm oluşumlarını bulmak için kullanmasını veya keşfedilen bir mikro-programı diğer stringlerin şifresini çözmek için kullanmasını engeller.

Bu sağlam tohum üretimi, **Dralyxor**'un bir "ana sır" keşfetmeye veya şifrelerin ve dönüşümlerin tekrarını istismar etmeye dayanan saldırılara karşı güvenliğinin temel taşlarından biridir.

## Tam Genel API Referansı

### Gizleme Makroları

Bunlar, gizlenmiş stringler oluşturmak için ana giriş noktalarıdır.

#### `DRALYXOR(str_literal)`

- **Amaç:** Statik ömürlü (programın tüm çalışması boyunca var olan) bir `Obfuscated_String` nesnesi oluşturur. Global sabitler veya birden fazla yerden erişilmesi ve kalıcı olması gereken stringler için idealdir.
- **Depolama:** Statik bellek (genellikle programın veri bölümünde).
- **Uygulama (basitleştirilmiş):**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           /* __COUNTER__ makrosu her kullanım için benzersiz bir Instance_Counter sağlar */ \
           /* decltype(*str_literal) karakter türünü (char, wchar_t) çıkarır */ \
           /* (sizeof(str_literal) / sizeof(decltype(*str_literal))) null dahil boyutu hesaplar */ \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String< \
               typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
               (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
               __COUNTER__ \
           >(str_literal); \
           return obfuscated_static_string; \
       }()
   ```

- **Parametreler:**
   - `str_literal`: Bir C stili string literali (örneğin, `"Hello World"`, `L"Unicode String"`).
- **Dönüş:** Hemen çağrılan bir lambda içinde oluşturulan statik `Obfuscated_String` nesnesine bir referans (`auto&`).
- **Örnek:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url, statik bir Obfuscated_String'e bir referanstır.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Amaç:** Otomatik ömürlü (bir fonksiyon içinde kullanılırsa genellikle yığında) bir `Obfuscated_String` nesnesi oluşturur. Bir kapsamla sınırlı geçici sırlar için idealdir.
- **Depolama:** Otomatik (fonksiyon yerel değişkenleri için yığın).
- **Uygulama (basitleştirilmiş):**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) \
       Dralyxor::Obfuscated_String< \
           typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, \
           (sizeof(str_literal) / sizeof(decltype(*str_literal))), \
           __COUNTER__ \
       >(str_literal)
   ```
- **Parametreler:**
   - `str_literal`: Bir C stili string literali.
- **Dönüş:** Değer olarak bir `Obfuscated_String` nesnesi (derleyici tarafından RVO/NRVO ile optimize edilebilir).
- **Örnek:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... DRALYXOR_SECURE ile temp_key kullan ...
   } // temp_key burada yok edilir, yıkıcısı Clear_Internal_Data()'yı çağırır.
   ```

### Güvenli Erişim Makrosu

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Amaç:** Bir `Obfuscated_String` nesnesinin şifresi çözülmüş içeriğine güvenli ve geçici erişim sağlar. Bu, string'i okumak için **tek önerilen yöntemdir**.
- **Uygulama (basitleştirilmiş):**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) \
       Dralyxor::Secure_Accessor< \
           typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type \
       >(obfuscated_var)
   ```

- **Parametreler:**
   - `obfuscated_var`: `Dralyxor::Obfuscated_String<...>` türünde bir değişken (lvalue veya const olmayan bir lvalue referansına bağlanabilen rvalue). Değişkenin değiştirilebilir olması gerekir çünkü `Secure_Accessor`'ın kurucusu üzerinde `Decrypt()` ve `Encrypt()` çağırır.
- **Dönüş:** Değer olarak bir `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` nesnesi.
- **Kullanım:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Veya sadece: const char* secret_ptr = accessor; (örtük dönüşüm)
       
       if (secret_ptr) {
           // secret_ptr'ı burada kullanın. Erişimcinin arabelleğindeki geçici olarak şifresi çözülmüş string'e işaret eder.
           // Örn: send_data(secret_ptr);
       }
       else {
           // Şifre çözme veya bütünlük hatası. Hatayı ele alın.
           // Erişimci başlatılamamış olabilir (örneğin, my_static_secret bozulmuş).
       }
   } // accessor yok edilir. Dahili arabellekleri (parçalar ve yeniden oluşturulmuş string) temizlenir.
    // my_static_secret.storage_, Secure_Accessor'ın kurucusu tarafından
    // içeriği erişimcinin parçalarına kopyaladıktan hemen sonra zaten yeniden gizlenmiştir.
   ```

> [!UYARI]
> `DRALYXOR_SECURE(...).Get()` (veya örtük dönüşüm) tarafından döndürülen işaretçinin kullanmadan önce `nullptr` olup olmadığını her zaman kontrol edin. `nullptr` dönüşü, bir şifre çözme hatasını (örneğin, hata ayıklayıcı tespiti, ebeveyn `Obfuscated_String`'de veya `Secure_Accessor`'ın kendisinde kanarya/sağlama toplamı bozulması) gösterir. `nullptr` bir işaretçinin kullanılması tanımsız davranışla (muhtemelen bir segmentasyon hatası) sonuçlanacaktır.

## Gelişmiş Özellikler ve İyi Uygulamalar

### Tam Unicode Desteği (Geniş Stringler - `wchar_t`)

**Dralyxor**, şablonların (`CharT`) kullanımı sayesinde karakter türünden bağımsızdır. `char` (ASCII/UTF-8 stringleri için) ve `wchar_t` (Windows'ta UTF-16 stringleri veya platforma ve derleyiciye bağlı olarak diğer sistemlerde UTF-32 stringleri için) ile doğal olarak başa çıkar. `wchar_t` literalleri için `L` önekini kullanmanız yeterlidir:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Unicode Mesajı: Merhaba Dünya Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Windows'ta örnek:
        // MessageBoxW(nullptr, accessor.Get(), L"Unicode Başlığı", MB_OK);
        // wcout ile örnek:
        // #include <io.h> // Windows'ta MSVC ile _setmode için
        // #include <fcntl.h> // Windows'ta MSVC ile _O_U16TEXT için
        // _setmode(_fileno(stdout), _O_U16TEXT); // stdout'u UTF-16 olarak ayarla
        // std::wcout << L"Geniş Mesaj: " << accessor.Get() << std::endl;
    }
}
```

1 baytlık karakterler için (`sizeof(CharT) == 1`), `Micro_Program_Cipher` dönüşüm motoru mikro-programı bayt bayt uygular. Çok baytlı karakterler için (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` daha basit bir yaklaşım kullanır: tüm çok baytlı karakter, `prng_key_for_ops_in_elem`'den türetilen bir maskeyle XOR'lanır (`CharT` boyutunu doldurmak için çoğaltılır). Örneğin, `CharT` `wchar_t` (2 bayt) ise ve `prng_key_for_ops_in_elem` `0xAB` ise, karakter `0xABAB` ile XOR'lanır.
Bu, tam mikro-program tarafından olmasa da `wchar_t`'nin tüm baytlarının gizlemeden etkilenmesini sağlar. Mikro-programın karmaşıklığı, PRNG anahtarlarının türetilmesi yoluyla dolaylı olarak hala katkıda bulunur.

### **C++** Standartlarına ve Ortamlara (Kernel Mode) Akıllı Uyum

Belirtildiği gibi, **Dralyxor** uyum sağlar:
- **C++ Standartları:** En az **C++14** gerektirir. Derleyici desteklediğinde **C++17** ve **C++20** özelliklerini (örneğin `if constexpr`, `consteval`, `type_traits` için `_v` sonekleri) algılar ve kullanır, aksi takdirde **C++14** alternatiflerine başvurur. `detection.hpp`'deki `_DRALYXOR_IF_CONSTEXPR` ve `_DRALYXOR_CONSTEVAL` gibi makrolar bu uyumu yönetir.
- **Çekirdek Modu (Kernel Mode):** `_KERNEL_MODE` tanımlandığında (Windows sürücüleri için WDK projelerinde tipiktir), **Dralyxor** (`env_traits.hpp` aracılığıyla) mevcut olmayabilecek veya farklı davranabilecek `<type_traits>` gibi standart STL başlık dosyalarını dahil etmekten kaçınır. Bunun yerine, `Dralyxor::Detail::Fallback::decay` ve `Dralyxor::Detail::Fallback::remove_reference` gibi temel araçların kendi `constexpr` uygulamalarını kullanır. Bu, **Dralyxor**'un düşük seviyeli sistem bileşenlerindeki stringleri korumak için güvenli bir şekilde kullanılmasını sağlar.
   - Benzer şekilde, `secure_memory.hpp` Çekirdek Modunda `RtlSecureZeroMemory` kullanır.
   - Kullanıcı Modu hata ayıklama karşıtı kontrolleri (`IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString` gibi) Çekirdek Modunda devre dışı bırakılır (`#if !defined(_KERNEL_MODE)`), çünkü bunlar geçerli değildir veya farklı eşdeğerleri vardır. Zamanlama kontrolleri hala bir miktar etkiye sahip olabilir, ancak Çekirdek Modundaki ana savunma hattı gizlemenin kendisidir.

### Performans ve Ek Yük Hususları

- **Derleme Süresi:** Mikro-programların üretimi ve uygulanması da dahil olmak üzere gizleme, tamamen derleme zamanında gerçekleşir. Çok sayıda gizlenmiş string içeren projeler için derleme süresi artabilir. Bu, derleme başına tek seferlik bir maliyettir.
- **İkili Dosya Boyutu:** Her `Obfuscated_String`, `storage_`'ını (string boyutu), `micro_program_`'ı (`max_micro_instructions * sizeof(Micro_Instruction)`'da sabit) artı kanaryalar, sağlama toplamı ve bayraklar için birkaç bayt ekler. Özellikle birçok küçük string için saf string literallerine kıyasla ikili dosya boyutunda bir artış olabilir.
- **Çalışma Süresi (Runtime):**
   - **`Obfuscated_String` Oluşturma (statik veya yerel nesneler):** Derleme zamanında gerçekleşir (statikler için) veya önceden hesaplanmış verilerin bir kopyasını içerir (yereller için, RVO ile optimize edilebilir). Çalışma zamanında "üretim" maliyeti yoktur.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Kanarya kontrolleri (son derece hızlı).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Hata ayıklama karşıtı kontrolleri içerir. Zamanlama kontrolü (`Perform_Timing_Check_Generic`) buradaki en maliyetli olanıdır, bir döngü çalıştırır. Diğerleri API çağrıları veya dosya okumalarıdır (Linux).
      - Mikro-programın şifresinin çözülmesi (kopyalama ve XOR, hızlı).
      - String dönüşümü: `N_data_elements_to_transform` üzerinde döngü ve içinde `num_actual_instructions_in_program_` üzerinde döngü. Her talimat için, birkaç bayt işlemi yapan bir `Byte_Transform_Applier` çağrısı. Maliyet O(string_uzunluğu \* talimat_sayısı)'dır.
      - Sağlama toplamı hesaplama/doğrulama (`Detail::Calculate_String_Content_Checksum`): O(string_uzunluğu \* sizeof(CharT)).
   - **`Secure_Accessor` Oluşturma:**
      - `Obfuscated_String::Decrypt()`'i çağırır.
      - String'i parçalara kopyalama: O(string_uzunluğu).
      - Parça sağlama toplamını hesaplama (`Calculate_Current_Fragments_Checksum`): O(string_uzunluğu).
      - `Obfuscated_String::Encrypt()`'i çağırır. Bu, tek bir erişim işlemindeki en yüksek ek yük yoğunlaşma noktasıdır.
   - **`Secure_Accessor::Get()`:**
      - İlk çağrı: Kanaryaları kontrol eder, string'i parçalardan yeniden oluşturur (O(string_uzunluğu)), parça sağlama toplamını kontrol eder.
      - Sonraki çağrılar (aynı `Secure_Accessor` nesnesi için): Kanaryaları kontrol eder (hızlı) ve zaten hesaplanmış işaretçiyi döndürür (O(1)).
- **Genel Ek Yük:** Çoğu uygulama için, hassas stringlerin çok yüksek frekanslı döngülerde erişilmediği durumlarda, çalışma zamanı ek yükü genellikle kabul edilebilir düzeydedir, özellikle güvenlik avantajı göz önüne alındığında. `Secure_Accessor`'ın tasarımı (yalnızca gerektiğinde ve RAII tarafından kesinlikle sınırlı bir kapsamda oluşturulur) bu maliyeti yönetmek için temeldir. Performans kritikse kendi özel ortamınızda test edin.

### Katmanlı Bir Güvenlik Stratejisine Entegrasyon

> [!ÖNEMLİ]
> **Dralyxor**, **gömülü stringlerin gizlenmesi ve bellek analizi savunması** için güçlü bir araçtır, diskte kalıcı veri depolama veya ağ üzerinden güvenli iletim için genel bir şifreleme çözümü değildir.
>
> Kapsamlı bir güvenlik stratejisinde **birçok katmandan biri** olarak kullanılmalıdır. Hiçbir araç tek başına sihirli bir çözüm değildir. Dikkate alınması gereken diğer önlemler şunlardır:
> - **Gömülü Sırları En Aza İndirme:** Mümkün olduğunda, çok yüksek kritiklikteki sırları gömmekten kaçının. Bunun yerine şunlar gibi alternatifler kullanın:
>    - Çalışma zamanında sağlanan güvenli yapılandırmalar (ortam değişkenleri, kısıtlı izinlere sahip yapılandırma dosyaları).
>    - HashiCorp Vault, Azure Key Vault, AWS Secrets Manager gibi sır yönetimi hizmetleri (vault'lar).
> - Tüm arayüzlerde güçlü giriş doğrulaması.
> - Süreçler ve kullanıcılar için en az ayrıcalık ilkesi.
> - Güvenli ağ iletişimi (varsa sertifika sabitleme ile TLS/SSL).
> - Kullanıcı şifrelerinin güvenli karma işlemi (Argon2, scrypt, bcrypt).
> - İkili dosyanın tamamının diğer tersine mühendislik/kurcalama karşıtı tekniklerle (paketleyiciler, kod sanallaştırıcılar, kod bütünlüğü kontrolleri) korunması, bunların getirebileceği ödünleşimlerin (antivirüs yanlış pozitifleri, karmaşıklık) farkında olarak.
> - Güvenli geliştirme için iyi uygulamalar (Güvenli SDLC).

**Dralyxor**, belirli ve yaygın bir sorunu çok iyi çözmeye odaklanır: gömülü string literallerinin statik analize karşı korunması ve çalışma sırasında bellekteki maruziyetlerinin en aza indirilmesi, yazılımınızda tersine mühendislik yapmaya çalışanların işini zorlaştırır.

## Lisans

Bu kütüphane, aşağıdakilere izin veren MIT Lisansı altında korunmaktadır:

- ✔️ Ticari ve özel kullanım
- ✔️ Kaynak kodunun değiştirilmesi
- ✔️ Kodun dağıtılması
- ✔️ Alt lisanslama

### Koşullar:

- Telif hakkı bildiriminin korunması
- MIT lisansının bir kopyasının dahil edilmesi

Lisans hakkında daha fazla ayrıntı için: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - Tüm hakları saklıdır**