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
      - [Desen 1: Yerel (Stack) Karmaşıklaştırma](#desen-1-yerel-stack-karmaşıklaştırma)
      - [Desen 2: Statik (Global) Karmaşıklaştırma](#desen-2-statik-global-karmaşıklaştırma)
      - [Desen 3: Kullanıcı Tarafından Sağlanan Anahtar ile Karmaşıklaştırma](#desen-3-kullanıcı-tarafından-sağlanan-anahtar-ile-karmaşıklaştırma)
    - [Hata Yönetimi ve Bütünlük](#hata-yönetimi-ve-bütünlük)
  - [Ayrıntılı Tasarım Felsefesi ve Mimarisi](#ayrıntılı-tasarım-felsefesi-ve-mimarisi)
    - [Süregelen Tehdit: String Literallerinin Güvenlik Açığı](#süregelen-tehdit-string-literallerinin-güvenlik-açığı)
    - [**Dralyxor**'un Çok Katmanlı Mimari Çözümü](#dralyxorun-çok-katmanlı-mimari-çözümü)
  - [Mimari Bileşenlerin Derinlemesine Analizi](#mimari-bileşenlerin-derinlemesine-analizi)
    - [Bileşen 1: Mikro-Program ile Dönüşüm Motoru](#bileşen-1-mikro-program-ile-dönüşüm-motoru)
      - [Derleme Zamanı Üretimi için `consteval` ve `constexpr` Gücü](#derleme-zamanı-üretimi-için-consteval-ve-constexpr-gücü)
      - [Bir **Dralyxor** Mikro Programının Anatomisi](#bir-dralyxor-mikro-programının-anatomisi)
        - [Rastgele Talimat Üretimi ve Uygulayıcı Seçimi](#rastgele-talimat-üretimi-ve-uygulayıcı-seçimi)
        - [Entropi için Değişken ve Mantıksal NOP'lar](#entropi-için-değişken-ve-mantıksal-noplar)
      - [Mikro Programın Kendi Kendini Karmaşıklaştırması](#mikro-programın-kendi-kendini-karmaşıklaştırması)
      - [Statik Karmaşıklaştırmanın Yaşam Döngüsü](#statik-karmaşıklaştırmanın-yaşam-döngüsü)
    - [Bileşen 2: Güvenli Erişim ve **RAM**'de Maruz Kalmanın Minimizasyonu](#bileşen-2-güvenli-erişim-ve-ramde-maruz-kalmanın-minimizasyonu)
      - [`Secure_Accessor` ve RAII Prensibi](#secure_accessor-ve-raii-prensibi)
      - [`Secure_Accessor`'da Bellek Parçalama](#secure_accessorda-bellek-parçalama)
      - [Güvenli Bellek Temizliği](#güvenli-bellek-temizliği)
    - [Bileşen 3: Çalışma Zamanı Savunmaları (Anti-Debugging ve Anti-Tampering)](#bileşen-3-çalışma-zamanı-savunmaları-anti-debugging-ve-anti-tampering)
      - [Çok Platformlu Hata Ayıklayıcı Tespiti](#çok-platformlu-hata-ayıklayıcı-tespiti)
      - [Tespit veya Bütünlük İhlali Durumunda Çalışma Üzerindeki Etkisi](#tespit-veya-bütünlük-i̇hlali-durumunda-çalışma-üzerindeki-etkisi)
      - [Nesne Bütünlük Kanaryaları](#nesne-bütünlük-kanaryaları)
      - [String İçeriği Checksum'ı](#string-i̇çeriği-checksumı)
    - [Bileşen 4: Benzersiz ve Öngörülemeyen Anahtarlar ve Tohumlar Oluşturma](#bileşen-4-benzersiz-ve-öngörülemeyen-anahtarlar-ve-tohumlar-oluşturma)
      - [`compile_time_seed` için Entropi Kaynakları](#compile_time_seed-için-entropi-kaynakları)
      - [İçerik Dönüşümleri için Türetilmiş Tohumlar](#i̇çerik-dönüşümleri-için-türetilmiş-tohumlar)
      - ["Tekrar" Saldırılarına ve Desen Analizine Karşı Bağışıklık](#tekrar-saldırılarına-ve-desen-analizine-karşı-bağışıklık)
  - [Tam Genel API Referansı](#tam-genel-api-referansı)
    - [Karmaşıklaştırma Makroları](#karmaşıklaştırma-makroları)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Güvenli Erişim Makrosu](#güvenli-erişim-makrosu)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Gelişmiş Özellikler ve İyi Uygulamalar](#gelişmiş-özellikler-ve-i̇yi-uygulamalar)
    - [Unicode için Tam Destek (Geniş Karakter Dizileri - `wchar_t`)](#unicode-için-tam-destek-geniş-karakter-dizileri---wchar_t)
    - [Akıllı Uyum: **C++** Standartları ve Ortamları (Çekirdek Modu)](#akıllı-uyum-c-standartları-ve-ortamları-çekirdek-modu)
    - [Performans ve Ek Yük Hususları](#performans-ve-ek-yük-hususları)
    - [Katmanlı Bir Güvenlik Stratejisine Entegrasyon](#katmanlı-bir-güvenlik-stratejisine-entegrasyon)
  - [Lisans](#lisans)
    - [Koşullar:](#koşullar)

## Hızlı Entegrasyon ve Kullanım Kılavuzu

### Kurulum

**Dralyxor**, **header-only** bir kütüphanedir. Önceden derleme veya kütüphane bağlama (`.lib`/`.a`) gerekmez.

1. **`Dralyxor` Dizinini Kopyalayın:** Kütüphanenin en son sürümünü edinin (depoyu klonlayın veya zip olarak indirin) ve tüm `Dralyxor` dizinini (tüm `.hpp` dosyalarını içeren) projenizin erişebileceği bir konuma (örneğin, bir `libs/`, `libraries/` veya `vendor/` klasörü) kopyalayın.
2. **Ana Başlık Dosyasını Dahil Edin:** Kaynak kodunuzda, ana başlık dosyası olan `dralyxor.hpp`'yi dahil edin:
   ```cpp
   #include "yol/icin/Dralyxor/dralyxor.hpp"
   ```

Tipik bir proje yapısı:
```
/Projem/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor burada
        |-- dralyxor.hpp            (Ana giriş noktası)
        |-- obfuscated_string.hpp   (Obfuscated_String Sınıfı)
        |-- secure_accessor.hpp     (Secure_Accessor Sınıfı)
        |-- algorithms.hpp          (Dönüşüm motoru ve mikro programlar)
        |-- anti_debug.hpp          (Çalışma zamanı tespitleri)
        |-- prng.hpp                (Derleme zamanı sözde rastgele sayı üreteci)
        |-- integrity_constants.hpp (Bütünlük kontrolleri için sabitler)
        |-- secure_memory.hpp       (Güvenli bellek temizliği)
        |-- detection.hpp           (Derleyici/C++ standardı tespit makroları)
        `-- env_traits.hpp          (Kısıtlı ortamlar için type_traits uyarlamaları)
```

### Derleyici Gereksinimleri

> [!IMPORTANT]
> **Dralyxor**, maksimum derleme zamanı güvenliği ve verimliliği için modern **C++** odaklı olarak tasarlanmıştır.
>
> - **Minimum C++ Standardı: C++14**. Kütüphane, genelleştirilmiş `constexpr` gibi özellikleri kullanır ve `if constexpr`'e uyum sağlar (mevcut olduğunda `_DRALYXOR_IF_CONSTEXPR` aracılığıyla).
> - **Daha Yüksek Standartlara Uyum:** Proje bu standartlarla derlenirse, **C++17** ve **C++20**'nin optimizasyonlarını veya sözdizimlerini (örneğin `consteval`, `type_traits` için `_v` sonekleri) algılar ve kullanır. `_DRALYXOR_CONSTEVAL`, C++20'de `consteval`'e ve C++14/17'de `constexpr`'e eşlenir, bu da mümkün olan yerlerde derleme zamanı yürütmesini garanti eder.
> - **Desteklenen Derleyiciler:** Öncelikle en son MSVC, GCC ve Clang ile test edilmiştir.
> - **Çalışma Ortamı:** **Kullanıcı Modu (User Mode)** uygulamaları ve **Çekirdek Modu (Kernel Mode)** ortamları (örn: Windows sürücüleri) ile tam uyumludur. Çekirdek Modunda, STL'nin mevcut olmayabileceği durumlarda, **Dralyxor** gerekli `type traits` için dahili uygulamaları kullanır (bkz. `env_traits.hpp`).

### Temel Kullanım Desenleri

#### Desen 1: Yerel (Stack) Karmaşıklaştırma

Bir fonksiyon kapsamıyla sınırlı, geçici string'ler için idealdir. Bellek otomatik olarak yönetilir ve temizlenir.

```cpp
#include "Dralyxor/dralyxor.hpp" // Yolu gerektiği gibi ayarlayın
#include <iostream>

void Configure_Logging() {
    // Sadece yerel olarak kullanılan log formatlama anahtarı.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Sınırlı bir kapsam içinde güvenli erişim
    {
        // Secure_Accessor, yapımı sırasında 'log_format_key'i geçici olarak çözer
        // (ve kendi dahili tamponlarına kopyaladıktan hemen sonra 'log_format_key'i yeniden karmaşıklaştırır),
        // erişime izin verir ve imhası sırasında kendi tamponlarını temizler.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Get()'in nullptr döndürmediğini her zaman kontrol edin
            std::cout << "Kullanılan log formatı: " << accessor.Get() << std::endl;
            // Örn: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "log_format_key şifresi çözülemedi (muhtemel kurcalama veya hata ayıklayıcı tespiti?)" << std::endl;
    } // accessor imha edilir, dahili tamponları temizlenir. log_format_key karmaşık kalır.
      // log_format_key, Configure_Logging fonksiyonunun sonunda imha edilecektir.
}
```

#### Desen 2: Statik (Global) Karmaşıklaştırma

Programın ömrü boyunca kalıcı olması ve global olarak erişilmesi gereken sabitler için.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // Örnek için

// Kalıcı bir sır olan lisans API'si URL'si.
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
            std::cout << "Lisans sunucusuna şu adresten ulaşılıyor: " << accessor.Get() << std::endl;
            // Örn: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Örnek için başarı simülasyonu
        }
        else
            std::cerr << "Lisans sunucusu URL'si çözülemedi (muhtemel kurcalama veya hata ayıklayıcı tespiti?)." << std::endl;
    } // accessor imha edilir, tamponları temizlenir. url_obj_ref (orijinal Obfuscated_String) karmaşık kalır.

    return success;
}
```

#### Desen 3: Kullanıcı Tarafından Sağlanan Anahtar ile Karmaşıklaştırma

Maksimum güvenlik seviyesi için kendi gizli anahtar string'inizi sağlayabilirsiniz. Bu, karmaşıklaştırmanın sadece sizin bildiğiniz bir sırra bağlı olmasını sağlar ve onu dirençli hale getirir.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// Anahtar asla üretim kodunda açık metin olarak bulunmamalıdır,
// ideal olarak bir derleme betiği, ortam değişkeni vb. kaynaklardan gelmelidir.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Gizli anahtarı kullanarak bir URL'yi karmaşıklaştırır. Makro _KEY ile biter.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Secure_Accessor ile kullanım aynı kalır.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Hata Yönetimi ve Bütünlük

`Obfuscated_String::Decrypt()` ve `Encrypt()` fonksiyonları `uint64_t` döndürür:
- `0` başarıyı gösterir.
- `Dralyxor::Detail::integrity_compromised_magic` (`integrity_constants.hpp` dosyasında tanımlanan sabit bir değer) bir bütünlük kontrolünün başarısız olduğunu gösterir. Bu, bozulmuş nesne kanaryaları, tutarsız içerik sağlama toplamı veya düşmanca bir ortamı işaret eden bir hata ayıklayıcı tespiti nedeniyle olabilir.

Benzer şekilde, `Secure_Accessor::Get()` (veya `const CharT*`'a örtük dönüşümü) `Secure_Accessor`'ın başlatılması başarısız olursa (örneğin, orijinal `Obfuscated_String`'in şifresinin çözülmesi başarısız olursa) veya `Secure_Accessor`'ın bütünlüğü (kendi kanaryaları veya dahili sağlama toplamları) ömrü boyunca bozulursa `nullptr` döndürür.

**Uygulamanın sağlamlığını ve güvenliğini sağlamak için kodunuzun bu geri dönüşleri kontrol etmesi kritik öneme sahiptir.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // Genellikle Decrypt() ve Encrypt() fonksiyonlarını doğrudan ÇAĞIRMAZSINIZ,
    // çünkü Secure_Accessor bunu yönetir. Ama bir nedenden dolayı ihtiyacınız olursa:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "UYARI: 'my_secret' çözülemedi veya Decrypt() sırasında bütünlük bozuldu!" << std::endl;
        // Uygun bir eylemde bulunun: sonlandırın, güvenli bir şekilde loglayın vb.
        // my_secret.storage_ nesnesi geçersiz bir durumda veya çöp verilerle dolu olabilir.
        return; // Decrypt() başarısız olursa my_secret'i kullanmaktan kaçının.
    }

    // Decrypt() başarılı olduysa, my_secret.storage_ şifresi çözülmüş veriyi içerir.
    // **ÜRETİMDE storage_'E DOĞRUDAN ERİŞİM KESİNLİKLE TAVSİYE EDİLMEZ.**
    // std::cout << "my_secret.storage_ içindeki veri (BUNU YAPMAYIN): " << my_secret.storage_ << std::endl;

    // Decrypt()'i manuel olarak çağırdıysanız yeniden şifrelemek sizin sorumluluğunuzdadır:
    if (my_secret.Encrypt() != 0) {
        std::cerr << "UYARI: 'my_secret' yeniden şifrelenemedi veya Encrypt() sırasında bütünlük bozuldu!" << std::endl;
        // Belirsiz durum, potansiyel olarak tehlikeli.
    }

    // `Secure_Accessor` ile ÖNERİLEN KULLANIM:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // Secure_Accessor'ın yapıcı metodu another_secret.Decrypt() çağırır, kopyalar ve sonra another_secret.Encrypt() çağırır.
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Veya: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Secure_Accessor aracılığıyla gizli veri: " << data_ptr << std::endl;
            // data_ptr'ı burada kullanın
        }
        else {
            std::cerr << "UYARI: Secure_Accessor 'another_secret' için başlatılamadı veya işaretçi alınamadı!" << std::endl;
            // Bu, accessor'ın yapıcı metodundaki Decrypt() işleminin başarısız olduğunu
            // veya accessor'da kurcalama (kanaryalar, dahili sağlama toplamları) olduğunu gösterir.
        }
    } // accessor imha edilir. Tamponları temizlenir. another_secret karmaşık kalır.
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

**Dralyxor**'un statik ve dinamik karmaşıklaştırmasının kalbi, her bir string ve bağlam için benzersiz "mikro programlar" kullanan dönüşüm motorunda yatmaktadır.

#### Derleme Zamanı Üretimi için `consteval` ve `constexpr` Gücü

Modern **C++**, `consteval` (**C++20**) ve `constexpr` (**C++11**'den itibaren) ile karmaşık kodların *derleme sırasında* yürütülmesine olanak tanır. **Dralyxor**, `_DRALYXOR_CONSTEVAL`'i (`consteval` veya `constexpr`'e **C++** standardına bağlı olarak eşlenir) `Obfuscated_String` yapıcı metodu ve mikro program üretimi için kullanır.

Bu şu anlama gelir:
1. Sözde rastgele bir dönüşüm talimatları dizisi (mikro program) oluşturma süreci.
2. Depolama için mikro programın kendisini karmaşıklaştırma.
3. Bu mikro programı (geçici olarak çözülmüş bir şekilde) uygulayarak orijinal string'i dönüştürme ve sonuçta karmaşıklaştırılmış formunu elde etme.
Tüm bunlar, ikili dosya oluşturulmadan önce derleme zamanında gerçekleşir.

#### Bir **Dralyxor** Mikro Programının Anatomisi

Her `Obfuscated_String` nesnesi, küçük bir `Dralyxor::Detail::Micro_Instruction` dizisi saklar. `Micro_Instruction`, `algorithms.hpp` içinde tanımlanan basit bir yapıdır:
```cpp
// Dralyxor::Detail'de (algorithms.hpp)
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
    Micro_Operation_Code op_code{}; // Sıfırlamak için varsayılan başlatıcı {}
    uint8_t operand{};             // Sıfırlamak için varsayılan başlatıcı {}
};

// Bir mikro programın içerebileceği maksimum talimat sayısı.
static constexpr size_t max_micro_instructions = 8;
```
`_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` fonksiyonu bu diziyi doldurmaktan sorumludur.

##### Rastgele Talimat Üretimi ve Uygulayıcı Seçimi

- **Talimat Üretimi:** Bir `Dralyxor::Detail::Constexpr_PRNG` kullanarak (`compile_time_seed` ve `0xDEADBEEFC0FFEEULL` kombinasyonu ile tohumlanmış), `Generate_Micro_Program_Instructions` fonksiyonu olasılıksal olarak bir dizi işlem seçer:
   - `XOR`: Operant ile bit bazında XOR.
   - `ADD`: Operant ile modüler toplama.
   - `SUB`: Operant ile modüler çıkarma.
   - `ROTR`/`ROTL`: Bit rotasyonu. Operant (modülo sonrası) kaydırma sayısını (1'den 7'ye) tanımlar.
   - `SWAP_NIB`: Bir baytın alt 4 bitini üst 4 bitiyle değiştirir (operant göz ardı edilir).
    Bu talimatlar için operantlar da PRNG tarafından sözde rastgele oluşturulur.

- **Dönüşüm Zamanında Operantların Değiştirilmesi ve Uygulayıcıların Seçimi:** Mikro programın uygulanması sırasında (hem ilk karmaşıklaştırmada hem de çalışma zamanı çözümlemesinde `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` tarafından):
   - Bir `Constexpr_PRNG prng_operand_modifier` (`base_seed` ile tohumlanmış), string'in her bir karakteri için bir `prng_key_for_ops_in_elem` oluşturur. Mikro talimatın operantı (`instr_orig.operand`), kullanılmadan önce bu anahtarla XOR'lanır. Bu, aynı mikro programın her bir karakter için biraz farklı dönüşümler uygulamasını sağlar.
   - Bir `Constexpr_PRNG prng_applier_selector` (`base_seed ^ 0xAAAAAAAAAAAAAAAAULL` ile tohumlanmış), her bir karakter için bir `Byte_Transform_Applier` seçer. Şu anda iki stil bulunmaktadır:
      - `Applier_Style_Direct`: İşlemi doğrudan uygular (şifre çözme için tersine çevirerek, ADD'nin SUB olması gibi).
      - `Applier_Style_DoubleLayer`: İşlemi iki kez (veya şifreleme/şifre çözme moduna bağlı olarak işlem ve tersini) farklı operantlarla uygular, bu da tersine çevirmeyi analiz etmeyi biraz daha karmaşık hale getirir.

##### Entropi için Değişken ve Mantıksal NOP'lar

Mikro programın manuel analiz zorluğunu artırmak için **Dralyxor** şunları ekler:
- **Açık NOP'lar:** Hiçbir şey yapmayan `Micro_Operation_Code::NOP` talimatları.
- **Mantıksal NOP'lar:** Birbirini iptal eden talimat çiftleri, `ADD K`'yi takiben `SUB K` veya `ROTL N_BITS`'i takiben `ROTR N_BITS` gibi. Çiftte kullanılan operant aynıdır.

Bu NOP'lar, `Generate_Micro_Program_Instructions` tarafından olasılıksal olarak eklenir, `micro_program_` dizisini doldurur ve etkili dönüşümleri "gürültü" işlemlerinden ayırt etmeyi zorlaştırır.

#### Mikro Programın Kendi Kendini Karmaşıklaştırması

Mikro programın oluşturulmasından ve `consteval` yapıcı metodunda string'in ilk karmaşıklaştırılmasından önce, `micro_program_` dizisi (`Obfuscated_String` nesnesinde bulunur) kendisi de karmaşıklaştırılır. Her `Micro_Instruction` içindeki her `op_code` ve `operand`, `compile_time_seed`'den türetilen bir anahtarla XOR'lanır (`Detail::Get_Micro_Program_Obfuscation_Key` ve `Detail::Obfuscate_Deobfuscate_Instruction` kullanılarak).
Bu, bir saldırgan `Obfuscated_String` nesnesinin belleğini dökse bile, mikro programın doğrudan okunabilir/uygulanabilir formunda olmayacağı anlamına gelir.

`Obfuscated_String::Decrypt()` veya `Encrypt()` çağrıldığında (veya dolaylı olarak `Secure_Accessor` tarafından), merkezi `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` fonksiyonu bu *karmaşıklaştırılmış* mikro programı alır. Sonra:
1. Mikro programın geçici bir kopyasını (`local_plain_program`) stack üzerinde oluşturur.
2. Bu yerel kopyayı, aynı anahtar (`program_obf_key`) ile çözer (geçilen temel tohumdan, yani sonuçta `compile_time_seed`'den türetilmiştir).
3. Bu `local_plain_program`'ı string verilerini dönüştürmek için kullanır.
Stack'teki yerel kopya, fonksiyon sonunda imha edilir ve `Obfuscated_String` nesnesinde saklanan `micro_program_` karmaşıklaştırılmış olarak kalır.

#### Statik Karmaşıklaştırmanın Yaşam Döngüsü

1. **Kaynak Kodu:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Ön İşleme:** Makro, `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");` örneğine genişler. (15 boyutu, null sonlandırıcıyı içerir).
3. **`_DRALYXOR_CONSTEVAL` Değerlendirmesi:**
   - Derleyici `Obfuscated_String` yapıcı metodunu yürütür.
   - `Initialize_Internal_Canaries()` bütünlük kanaryalarını ayarlar.
   - `Generate_Micro_Program_Instructions()` (`compile_time_seed ^ 0xDEADBEEFC0FFEEULL` ile tohumlanmış) bir `Micro_Instruction` dizisi oluşturur ve `this->micro_program_`'a saklar (örneğin: `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). Gerçek talimat sayısı `num_actual_instructions_in_program_` içinde saklanır.
   - Orijinal string "SECRET\_API\_KEY", `this->storage_`'e kopyalanır.
   - Orijinal "SECRET\_API\_KEY" string'inin (null hariç) bir sağlama toplamı `Detail::Calculate_String_Content_Checksum` tarafından hesaplanır ve ardından `Detail::Obfuscate_Deobfuscate_Short_Value` ile (`compile_time_seed` ve `content_checksum_obf_salt` kullanarak) karmaşıklaştırılarak `this->_content_checksum_obfuscated` içinde saklanır.
   - `Obfuscate_Internal_Micro_Program()` çağrılır: `this->micro_program_` yerinde karmaşıklaştırılır (her talimat `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)` ile XOR'lanır).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` çağrılır. Bu fonksiyon:
      - `this->micro_program_`'ın şifresi çözülmüş bir kopyasını stack'te oluşturur.
      - `storage_`'daki her karakter için (null hariç):
         - `prng_key_for_ops_in_elem` oluşturur ve bir `Byte_Transform_Applier` seçer.
         - Mikro talimat dizisini (şifresi çözülmüş kopyadan) karaktere, değiştirilmiş operant ve uygulayıcıyı kullanarak uygular.
      - Sonunda, `storage_` karmaşıklaştırılmış string'i içerir (örneğin: `[CF, 3A, D1, ..., 0x00]`).
4. **Kod Üretimi:** Derleyici, `api_key_obj` için yer ayırır ve onu doğrudan şunlarla başlatır:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (karmaşıklaştırılmış string).
   - `micro_program_`: *Zaten karmaşıklaştırılmış* olan mikro program.
   - `_content_checksum_obfuscated`: Orijinal içeriğin sağlama toplamı, *karmaşıklaştırılmış*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    `"SECRET_API_KEY"` literali artık ikili dosyada mevcut değildir.

### Bileşen 2: Güvenli Erişim ve **RAM**'de Maruz Kalmanın Minimizasyonu

#### `Secure_Accessor` ve RAII Prensibi

Derleme zamanı koruması, savaşın sadece yarısıdır. String'in kullanılması gerektiğinde, şifresinin çözülmesi gerekir. Eğer bu çözülmüş string uzun bir süre **RAM** belleğinde kalırsa, dinamik analiz (bellek dökümleri, hata ayıklayıcılar) için bir hedef haline gelir.

**Dralyxor**, bu sorunu **RAII** (Resource Acquisition Is Initialization) desenini uygulayan bir sınıf olan `Dralyxor::Secure_Accessor` ile ele alır:
- **Edinilen Kaynak:** Accessor tarafından parçalanmış ve yönetilen, açık metin halindeki string'e geçici erişim.
- **Yönetici Nesne:** `Secure_Accessor` örneği.

```cpp
// secure_accessor.hpp'de (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Başarısız olması için farklı başlatın (eğer güncellenmezse)
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Accessor'ı geçersiz kılar

            return;
        }

        // 1. Orijinal Obfuscated_String'in şifresini çözmeyi dener.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. Şifre çözme başarılı olursa, düz metin string'i dahili parçalara kopyalar.
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
                        fragments_storage_[i][j] = (CharT)0; // Parça tamponunun geri kalanını null ile doldur
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
        Clear_All_Internal_Buffers(); // Parçaları ve yeniden oluşturulmuş tamponu temizler.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Kendisini ve ebeveynini kontrol eder
            Clear_All_Internal_Buffers(); // Güvenlik önlemi
            _accessor_integrity_canary1 = 0; // Gelecekteki erişimler için geçersiz kılar

            return nullptr;
        }

        if (!current_access_ptr_) { // Get() için ilk çağrı veya temizlenmişse
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
            else { // N_storage == 0 için (teorik olarak boş string), sağlama toplamları yok
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // Kontrolü geçmek için

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // N_storage 0 ise, tampon > 0 ise bu güvenlidir
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Bütünlüğü sağlamak için herhangi bir dahili işlemden sonra tekrar kontrol eder.
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
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - `Secure_Accessor`'ın yapıcı metodu çağrılır.
   - `my_obfuscated_string.Decrypt()`'i çağırır. Bu, `micro_program_`'ın şifresini çözmeyi (yerel bir kopyaya), onu `my_obfuscated_string.storage_`'ın şifresini çözmek için kullanmayı ve ardından kanaryaları ve çözülmüş içeriğin sağlama toplamını beklenene karşı kontrol etmeyi içerir.
   - Başarılı olursa, `my_obfuscated_string.storage_`'ın içeriği (şimdi düz metin) `Secure_Accessor`'ın dahili `fragments_storage_`'larına kopyalanır ve bölünür.
   - `fragments_storage_`'ların bir sağlama toplamı (`fragments_data_checksum_expected_`) hesaplanır.
   - Önemli olarak, `my_obfuscated_string.Encrypt()` *hemen ardından* çağrılır ve `my_obfuscated_string.storage_` yeniden karmaşıklaştırılır.
2. `const char* ptr = accessor.Get();` (veya `const char* ptr = accessor;` örtük dönüşüm nedeniyle)
   - `Secure_Accessor::Get()` çağrılır.
   - Kendi bütünlük kanaryalarını ve ebeveyn `Obfuscated_String`'in kanaryalarını kontrol eder.
   - İlk erişimse (`current_access_ptr_`, `nullptr` ise), tam string'i `reconstructed_plain_buffer_` içinde `fragments_storage_`'dan yeniden oluşturur.
   - Ardından `Secure_Accessor` var olduğu sürece parçaların kurcalanmadığından emin olmak için `fragments_data_checksum_reconstructed_`'ı `fragments_data_checksum_expected_` ile karşılaştırır.
   - Her şey doğruysa, `reconstructed_plain_buffer_`'a bir işaretçi döndürür.
3. `accessor`'ın kapsamı sona erer (fonksiyondan çıkar, `{}` bloğu biter, vb.).
   - `Secure_Accessor`'ın yıkıcı metodu otomatik olarak çağrılır.
   - Hem `reconstructed_plain_buffer_`'ı hem de `fragments_storage_`'ı güvenli bir şekilde temizleyen (`Secure_Clear_Memory`) `Clear_All_Internal_Buffers()` çağrılır.

Sonuç olarak, düz metin halindeki string, tam formunda yalnızca `Secure_Accessor` içinde (`reconstructed_plain_buffer_`'da) ve yalnızca `Get()`'e ilk çağrıdan sonra, mümkün olan en kısa süre için bulunur. Orijinal `Obfuscated_String` nesnesindeki string, `Secure_Accessor` yapımı sırasında içeriğini kopyaladıktan hemen sonra yeniden karmaşıklaştırılır.

#### `Secure_Accessor`'da Bellek Parçalama

Bellekteki tam düz metin string'in yerini bulmayı daha da zorlaştırmak için, `Secure_Accessor` yapımı sırasında sadece şifresi çözülmüş string'i kopyalamakla kalmaz, onu böler:
1. Ebeveyn `Obfuscated_String`'in string'i çözülür.
2. İçeriği `fragment_count_val`'e kadar (şu anda 4, string yeterince büyükse) parçaya bölünür ve `fragments_storage_[i]`'ye kopyalanır.
3. Ebeveyn `Obfuscated_String` nesnesindeki string yeniden karmaşıklaştırılır.

Sadece `Secure_Accessor::Get()` ilk kez çağrıldığında bu parçalar `reconstructed_plain_buffer_`'da yeniden birleştirilir. Bu teknik, hassas verileri "yaymayı" ve sürekli string arayan bellek taramalarını engellemeyi amaçlar.

#### Güvenli Bellek Temizliği

Hem `Obfuscated_String`'in yıkıcı metodu (`Clear_Internal_Data` aracılığıyla) hem de `Secure_Accessor`'ın yıkıcı metodu (`Clear_All_Internal_Buffers` aracılığıyla) `Dralyxor::Detail::Secure_Clear_Memory`'yi kullanır. Bu sarmalayıcı fonksiyon, hassas veriler içeren tamponların güvenilir bir şekilde sıfırlandığını ve derleyici optimizasyonunu engellediğini garanti eder:
- **Windows'ta:** `SecureZeroMemory` (Kullanıcı Modu) veya `RtlSecureZeroMemory` (Çekirdek Modu) kullanır; bunlar, işletim sisteminin özellikle optimize edilmemek ve belleği güvenli bir şekilde sıfırlamak için tasarlanmış fonksiyonlarıdır.
- **Diğer Platformlarda (Linux, macOS, vb.):** Uygulama artık bellek bloğunu sıfırlarla doldurmak için `memset` kullanıyor. `memset`, byte seviyesinde çalışır, bu da onu hem ilkel tipleri (`char`, `int` gibi) hem de karmaşık tipleri (`struct`lar gibi) sıfırlamak için ideal ve güvenli kılar, böylece tip uyumluluğu veya atama operatörleri ile ilgili sorunlardan kaçınılır. `memset` çağrısının derleyici tarafından optimize edilip kaldırılmadığından emin olmak için, tampon işaretçisi önce `volatile` bir işaretçiye aktarılır.

Bu yaklaşım, nesneler yok edildiğinde hassas içeriğin üzerine yazılmasını sağlar ve bellek dökümlerinin analizi yoluyla veri kurtarma riskini azaltır.

### Bileşen 3: Çalışma Zamanı Savunmaları (Anti-Debugging ve Anti-Tampering)

**Dralyxor** sadece karmaşıklaştırmaya güvenmez. Özellikle `anti_debug.hpp` içinde bulunan ve `Obfuscated_String`'in `Decrypt()` ve `Encrypt()` metodlarına entegre edilmiş bir dizi aktif çalışma zamanı savunması kullanır.

#### Çok Platformlu Hata Ayıklayıcı Tespiti

`Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` fonksiyonu (`anti_debug.hpp`'de), işletim sistemine özgü teknikler kullanarak bir hata ayıklayıcının varlığını kontrol eder:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` ile `ProcessDebugPort` (0x07) ve `ProcessDebugFlags` (0x1F) için.
- **Linux:** `/proc/self/status`'u okur ve `TracerPid:` değerini kontrol eder. 0'dan farklı bir değer, işlemin izlendiğini gösterir.
- **macOS:** `kinfo_proc` almak için `sysctl`'i `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` ile kullanır ve `kp_proc.p_flag` içindeki `P_TRACED` bayrağını kontrol eder.

Ek olarak, `Detail::Calculate_Runtime_Key_Modifier()` içinde:
- `Detail::Perform_Timing_Check_Generic()`: Basit hesaplama işlemleri döngüsü çalıştırır ve zamanı ölçer. Önemli bir yavaşlama (75ms'den fazla - `timing_threshold_milliseconds = 75ms`) bir hata ayıklayıcının tek adımlama yaptığını veya kapsamlı kesme noktalarının (breakpoint) aktif olduğunu gösterebilir. Bu döngü içinde, `Is_Debugger_Present_Tracer_Pid_Sysctl()` çağrılır ve `Detail::Canary_Function_For_Breakpoint_Check()` adında bir "yem" fonksiyon (sadece `0xCC` döndürür, bu `int3` / yazılım kesme noktası komut kodudur) çağrılır ve sonucu XORlanır, bu da optimizasyonu zorlaştırır ve kesme noktaları için ortak bir konum sağlar.
- `Detail::Perform_Output_Debug_String_Trick()` (sadece Windows Kullanıcı Modu): `OutputDebugStringA/W` ve `GetLastError()`'ın davranışını kullanır. Eğer bir hata ayıklayıcı bağlıysa, `OutputDebugString` çağrısından sonra `GetLastError()` değiştirilebilir.

#### Tespit veya Bütünlük İhlali Durumunda Çalışma Üzerindeki Etkisi

Eğer anti-debugging kontrollerinden herhangi biri `true` dönerse veya `Obfuscated_String`'in bütünlük kanaryaları (`_internal_integrity_canary1/2`) bozulmuşsa, `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` fonksiyonu `Detail::integrity_compromised_magic` döndürür.

Bu döndürülen değer, `Obfuscated_String::Decrypt()` ve `Encrypt()` fonksiyonlarında kritik öneme sahiptir:
```cpp
// Obfuscated_String::Decrypt() basitleştirilmiş mantığı
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

        // EĞER runtime_key_mod, integrity_compromised_magic DEĞİLSE, ŞİFRE ÇÖZME ANAHTARINI DEĞİŞTİRMEK İÇİN KULLANILMAZ.
        // Şifre çözme anahtarı her zaman orijinal 'compile_time_seed'den türetilir.
        // runtime_key_mod'un buradaki rolü, düşmanca bir ortamın SİNYALİ olarak hareket etmektir.
        // Eğer düşmancaysa, fonksiyon integrity_compromised_magic döndürür ve şifre çözme devam etmez veya geri alınır.
        
        // Transform_Compile_Time_Consistent, compile_time_seed ile çağrılır (runtime_key_mod ile DEĞİL)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Sağlama toplamını ve kanaryaları tekrar kontrol et ...
        // Bir şey başarısız olursa, Clear_Internal_Data() ve integrity_compromised_magic döndürür.
        decrypted_ = true;
    }

    return 0; // Başarı
}
```

**Anahtar Etki:** Eğer `Calculate_Runtime_Key_Modifier` bir sorun tespit ederse (hata ayıklayıcı veya bozulmuş kanarya) ve `integrity_compromised_magic` döndürürse, `Decrypt()` (ve benzer şekilde `Encrypt()`) fonksiyonları işlemi durdurur, `Obfuscated_String`'in iç verilerini (`storage_` ve `micro_program_` dahil) temizler ve `integrity_compromised_magic` döndürür. Bu, düşmanca bir ortamda veya nesne kurcalandıysa string'in doğru bir şekilde çözülmesini (veya yeniden şifrelenmesini) engeller.
String "yanlış bir şekilde" (çöp verilere) çözülmez; işlem basitçe engellenir ve `Obfuscated_String` nesnesi, faydalı içerik açısından kendi kendini yok eder.

#### Nesne Bütünlük Kanaryaları

Hem `Obfuscated_String` hem de `Secure_Accessor` sınıfları kanarya üyeleri içerir (`uint32_t` çiftleri):
- `Obfuscated_String`: `_internal_integrity_canary1` (`Detail::integrity_canary_value` ile başlatılır) ve `_internal_integrity_canary2` (`~Detail::integrity_canary_value` ile başlatılır).
- `Secure_Accessor`: `_accessor_integrity_canary1` (`Detail::accessor_integrity_canary_seed` ile başlatılır) ve `_accessor_integrity_canary2` (`~Detail::accessor_integrity_canary_seed` ile başlatılır).

Bu kanaryalar kritik noktalarda kontrol edilir:
- `Obfuscated_String::Decrypt()` ve `Encrypt()`'in başlangıcında ve sonunda.
- `Secure_Accessor`'ın yapıcı, yıkıcı ve `Get()` metodlarında.
- `Calculate_Runtime_Key_Modifier`'daki anti-debug kontrollerinden önce ve sonra.

Eğer bu kanarya değerleri değiştirilirse (örneğin, bir tampon taşması, gelişigüzel bir bellek yaması veya bitişik belleğin üzerine yazan bir hook tarafından), kontrol (`Verify_Internal_Canaries()` veya `Verify_Internal_Accessor_Canaries()`) başarısız olur.
Başarısızlık durumunda, işlemler iptal edilir, ilgili iç veriler temizlenir ve bir hata değeri (`Detail::integrity_compromised_magic` veya `nullptr`) döndürülerek kurcalama sinyali verilir.

#### String İçeriği Checksum'ı

- Orijinal *düz metin halindeki* string'in (null sonlandırıcı hariç) 16 bitlik bir sağlama toplamı, derleme zamanında `Detail::Calculate_String_Content_Checksum` tarafından hesaplanır.
- Bu sağlama toplamı daha sonra `Detail::Obfuscate_Deobfuscate_Short_Value` kullanılarak (`compile_time_seed` ve `content_checksum_obf_salt` ile) karmaşıklaştırılır ve `_content_checksum_obfuscated` içinde `Obfuscated_String` nesnesine saklanır.
- **Şifre Çözerken (`Decrypt()`):** `storage_` dönüştürüldükten (sözde düz metne) sonra, sağlama toplamı hesaplanır. Referans sağlama toplamını elde etmek için `_content_checksum_obfuscated`'in şifresi çözülür. İki sağlama toplamı eşleşmezse, bu şunu gösterir:
   - Şifre çözme orijinal string'i geri yüklemedi (belki de hata ayıklayıcı tespiti nedeniyle tam dönüşümden önce işlem iptal edildiği veya tohum/mikroprogramda bozulma olduğu için).
   - `storage_` (karmaşıklaştırılmışken) veya `_content_checksum_obfuscated` bellekte kurcalandı.
- **Şifrelerken (`Encrypt()`):** `storage_` (bu noktada düz metin halinde) karmaşıklaştırılmış formuna geri dönüştürülmeden önce, sağlama toplamı hesaplanır ve referansla karşılaştırılır. Buradaki bir uyuşmazlık, düz metin string'inin *`Obfuscated_String`'in `storage_`'ı içinde şifresi çözülmüşken değiştirildiği* anlamına gelir, bu da bellek kurcalaması veya yanlış kullanımın güçlü bir göstergesidir (`storage_`'a doğrudan erişilmemesi gerektiği için).

Her iki sağlama toplamı hatası durumunda da `Clear_Internal_Data()` çağrılır ve `integrity_compromised_magic` döndürülür.

### Bileşen 4: Benzersiz ve Öngörülemeyen Anahtarlar ve Tohumlar Oluşturma

Herhangi bir şifreleme sisteminin güvenliği, anahtarlarının ve tohumlarının gücüne ve benzersizliğine dayanır. **Dralyxor**, her karmaşıklaştırılmış string'in temelde benzersiz bir şifreleme parametreleri kümesi kullanmasını sağlar.

#### `compile_time_seed` için Entropi Kaynakları

`static constexpr uint64_t Obfuscated_String::compile_time_seed`, o string örneğiyle ilgili tüm sözde rastgele işlemler için ana tohumdur. Üretimi artık, kullanıcı tarafından sağlanan bir anahtarın varlığına bağlı olarak koşulludur:

- **Kullanıcı tarafından bir anahtar sağlanırsa (`DRALYXOR_KEY` veya `DRALYXOR_KEY_LOCAL` kullanarak):**
   1. Sağlanan `key_literal`, derleme zamanında FNV-1a algoritması kullanılarak 64-bit bir hash'e dönüştürülür.
   2. Bu hash, `__COUNTER__` (aynı anahtarın farklı kullanımları arasında benzersizliği sağlamak için) ve string boyutu ile birleştirilerek `compile_time_seed`'in temeli olur.
      ```cpp
      // Basitleştirilmiş mantık
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      Bu modda, karmaşıklaştırmanın güvenliği doğrudan sağlanan anahtarın gücüne ve gizliliğine bağlıdır.

- **Hiçbir anahtar sağlanmazsa (`DRALYXOR` veya `DRALYXOR_LOCAL` kullanarak):**
   - `compile_time_seed`, entropiyi ve değişkenliği en üst düzeye çıkarmak için aşağıdaki faktörlerin bir kombinasyonu kullanılarak oluşturulur:
      ```cpp
      // Obfuscated_String<CharT, storage_n, Instance_Counter> içinde
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Bileşen 1: Derlemeler arası değişkenlik
          ((uint64_t)Instance_Counter << 32) ^        // Bileşen 2: Bir derleme birimi içindeki değişkenlik
          storage_n;                                  // Bileşen 3: String boyutuna dayalı değişkenlik
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: `__DATE__` (örneğin: "Jan 01 2025") ve `__TIME__` (örneğin: "12:30:00") makroları, dosya her derlendiğinde değişen ön işlemci tarafından sağlanan string'lerdir. Bu değerlerin FNV-1a hash'i, projenin her derlemesi için farklı olan bir tohum tabanı oluşturur.
   - **`Instance_Counter` (makroda `__COUNTER__` ile beslenir)**: `__COUNTER__` makrosu, bir derleme birimi içinde her kullanıldığında artan bir ön işlemci sayacıdır. Bunu bir şablon argümanı olarak geçerek, `DRALYXOR` veya `DRALYXOR_LOCAL` makrosunun her kullanımı, aynı kaynak dosyasındaki aynı string literalleri için bile farklı bir `Instance_Counter` ve dolayısıyla farklı bir `compile_time_seed` ile sonuçlanır.
   - **`storage_n` (string boyutu)**: String'in boyutu da XOR'lanır, bu da ek bir farklılaştırma faktörü ekler.

Bu `compile_time_seed` (kullanıcı anahtarından türetilmiş veya otomatik olarak oluşturulmuş olsun), daha sonra aşağıdakiler için temel olarak kullanılır:
1. `micro_program_`'ı oluşturmak (PRNG'yi `compile_time_seed ^ 0xDEADBEEFC0FFEEULL` ile tohumlayarak).
2. `micro_program_`'ın kendisi için karmaşıklaştırma anahtarını türetmek (`Detail::Get_Micro_Program_Obfuscation_Key` aracılığıyla).
3. `_content_checksum_obfuscated` için karmaşıklaştırma anahtarını türetmek (`Detail::Obfuscate_Deobfuscate_Short_Value` aracılığıyla).
4. `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` için `base_seed` olarak hizmet etmek.

#### İçerik Dönüşümleri için Türetilmiş Tohumlar

`Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)` içinde:
- Bir `Constexpr_PRNG prng_operand_modifier(base_seed)` başlatılır. Dönüştürülen string'in her karakteri için `prng_operand_modifier.Key()`, bir `prng_key_for_ops_in_elem` üretir. Bu anahtar, uygulamadan önce mikro-talimatın operantıyla XOR'lanır, bu da aynı mikro-talimatın etkisinin her karakter için ince bir şekilde farklı olmasını sağlar.
- Bir `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` başlatılır. Her karakter için `prng_applier_selector.Key()`, `Applier_Style_Direct` ve `Applier_Style_DoubleLayer` arasında seçim yapmak için kullanılır.

Bu, altta yatan mikro program belirli bir string'in tüm karakterleri için aynı olsa bile, her karakterin dönüşümüne ek bir dinamizm katar.

#### "Tekrar" Saldırılarına ve Desen Analizine Karşı Bağışıklık

- **Derlemeler Arası Benzersizlik:** Bir saldırgan yazılımınızın 1.0 sürümünün ikili dosyasını analiz eder ve büyük çabayla bir string'in karmaşıklaştırmasını kırmayı başarırsa (otomatik anahtar modunda), bu bilgi muhtemelen 1.1 sürümü için işe yaramaz olacaktır, çünkü `__DATE__ __TIME__` değişmiş olacak ve tamamen farklı `compile_time_seed`'ler ve mikro programlar ile sonuçlanacaktır.
- **Derleme İçi Benzersizlik:** Kodunuzda iki farklı yerde (veya aynı .cpp dosyasında) `DRALYXOR("AdminPassword")` kullanırsanız, `__COUNTER__` sonuçta ortaya çıkan `Obfuscated_String` nesnelerinin ve dolayısıyla ikili dosyada karmaşıklaştırılmış temsillerinin farklı olmasını sağlar. Bu, bir saldırganın karmaşıklaştırılmış bir desen bulmasını ve onu aynı orijinal string'in diğer tüm oluşumlarını bulmak için kullanmasını engeller.

Bu sağlam tohum üretimi, **Dralyxor**'un bir "ana sırrı" keşfetmeye veya şifrelerin ve dönüşümlerin tekrarını istismar etmeye dayanan saldırılara karşı güvenliğinin temel taşlarından biridir.

## Tam Genel API Referansı

### Karmaşıklaştırma Makroları

Bunlar, karmaşıklaştırılmış string'ler oluşturmak için ana giriş noktalarıdır.

#### `DRALYXOR(str_literal)`

- **Amaç:** Statik ömür süresine sahip (programın tüm çalışması boyunca var olan) bir `Obfuscated_String` nesnesi oluşturur. Global sabitler veya birden fazla yerden erişilmesi gereken ve kalıcı olması gereken string'ler için idealdir.
- **Depolama:** Statik bellek (genellikle programın veri bölümünde).
- **Uygulama:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parametreler:**
   - `str_literal`: Bir C-stili string literali (örneğin, `"Hello World"`, `L"Unicode String"`).
- **Dönüş:** Anında çağrılan bir lambda içinde oluşturulan statik `Obfuscated_String` nesnesine bir referans (`auto&`).
- **Örnek:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url, statik bir Obfuscated_String'e referanstır.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Amaç:** Otomatik ömür süresine sahip (bir fonksiyon içinde kullanıldığında genellikle stack'te) bir `Obfuscated_String` nesnesi oluşturur. Bir kapsamla sınırlı geçici sırlar için idealdir.
- **Depolama:** Otomatik (fonksiyon yerel değişkenleri için stack).
- **Uygulama:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Parametreler:**
   - `str_literal`: Bir C-stili string literali.
- **Dönüş:** Değer olarak bir `Obfuscated_String` nesnesi (derleyici tarafından RVO/NRVO ile optimize edilebilir).
- **Örnek:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... DRALYXOR_SECURE ile temp_key kullanın ...
   } // temp_key burada imha edilir, yıkıcı metodu Clear_Internal_Data() çağırır.
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Amaç:** `DRALYXOR`'a benzer şekilde, statik bir `Obfuscated_String` nesnesi oluşturur, ancak karmaşıklaştırmayı tohumlamak için **kullanıcı tarafından sağlanan bir anahtar** (`key_literal`) kullanır, bu da en yüksek güvenlik seviyesini sunar.
- **Depolama:** Statik bellek (genellikle programın veri bölümünde).
- **Uygulama:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parametreler:**
   - `str_literal`: Karmaşıklaştırılacak string literali.
   - `key_literal`: Gizli anahtar olarak kullanılacak string literali.
- **Dönüş:** Statik `Obfuscated_String` nesnesine bir referans (`auto&`).
- **Örnek:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Amaç:** `DRALYXOR_LOCAL`'e benzer şekilde, **kullanıcı tarafından sağlanan bir anahtar** kullanarak stack üzerinde bir `Obfuscated_String` nesnesi oluşturur.
- **Depolama:** Otomatik (fonksiyon yerel değişkenleri için stack).
- **Uygulama:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parametreler:**
   - `str_literal`: Karmaşıklaştırılacak string literali.
   - `key_literal`: Anahtar olarak kullanılacak string literali.
- **Dönüş:** Değer olarak bir `Obfuscated_String` nesnesi.
- **Örnek:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Güvenli Erişim Makrosu

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Amaç:** Bir `Obfuscated_String` nesnesinin şifresi çözülmüş içeriğine güvenli ve geçici erişim sağlar. Bu, string'i okumak için **önerilen tek yöntemdir**.
- **Uygulama:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parametreler:**
   - `obfuscated_var`: `Dralyxor::Obfuscated_String<...>` türünde bir değişken (lvalue veya const olmayan lvalue referansına bağlanabilen bir rvalue). Değişken değiştirilebilir olmalıdır çünkü `Secure_Accessor`'ın yapıcı metodu üzerinde `Decrypt()` ve `Encrypt()`'i çağırır.
- **Dönüş:** Değer olarak bir `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` nesnesi.
- **Kullanım:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Veya sadece: const char* secret_ptr = accessor; (örtük dönüşüm)
       
       if (secret_ptr) {
           // secret_ptr'ı burada kullanın. Accessor'ın tamponunda geçici olarak çözülmüş string'i işaret eder.
           // Örn: send_data(secret_ptr);
       }
       else {
           // Şifre çözme veya bütünlük hatası. Hatayı yönetin.
           // Accessor başlatılamamış olabilir (örneğin, my_static_secret bozulmuştu).
       }
   } // accessor imha edilir. Dahili tamponları (parçalar ve yeniden oluşturulmuş string) temizlenir.
    // my_static_secret.storage_, Secure_Accessor'ın yapıcı metodu tarafından
    // içeriği accessor'ın parçalarına kopyaladıktan hemen sonra zaten yeniden karmaşıklaştırılmıştır.
   ```

> [!WARNING]
> `DRALYXOR_SECURE(...).Get()` tarafından (veya örtülü dönüşümle) döndürülen işaretçinin, onu kullanmadan önce `nullptr` olmadığını her zaman kontrol edin. Bir `nullptr` dönüşü, şifre çözme hatası (örneğin, hata ayıklayıcı tespiti, üst `Obfuscated_String`'de veya `Secure_Accessor`'ın kendisinde kanaryaların/checksum'ların bozulması) olduğunu gösterir. Bir `nullptr` işaretçisinin kullanılması tanımsız davranışla (muhtemelen bir segmentasyon hatası) sonuçlanacaktır.

## Gelişmiş Özellikler ve İyi Uygulamalar

### Unicode için Tam Destek (Geniş Karakter Dizileri - `wchar_t`)

**Dralyxor**, şablonların (`CharT`) kullanımı sayesinde karakter türünden bağımsızdır. `char` (ASCII/UTF-8 stringleri için) ve `wchar_t` (Windows'ta UTF-16 veya platform ve derleyiciye bağlı olarak diğer sistemlerde UTF-32 stringleri için) ile yerel olarak çalışır. `wchar_t` literalleri için `L` önekini kullanmanız yeterlidir:
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
        // _setmode(_fileno(stdout), _O_U16TEXT); // stdout'u UTF-16 için ayarla
        // std::wcout << L"Geniş Mesaj: " << accessor.Get() << std::endl;
    }
}
```

1 baytlık karakterler için (`sizeof(CharT) == 1`), `Micro_Program_Cipher` dönüşüm motoru mikro programı byte byte uygular. Çok baytlı karakterler için (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` daha basit bir yaklaşım kullanır: çok baytlı karakterin tamamı, `prng_key_for_ops_in_elem`'den türetilen bir maske ile XOR'lanır (`CharT` boyutunu doldurmak için çoğaltılır). Örneğin, `CharT` `wchar_t` (2 bayt) ise ve `prng_key_for_ops_in_elem` `0xAB` ise, karakter `0xABAB` ile XOR'lanır.
Bu, tam mikro programla olmasa bile `wchar_t`'nin tüm baytlarının karmaşıklaştırmadan etkilenmesini sağlar. Mikro programın karmaşıklığı, PRNG anahtarlarının türetilmesi yoluyla dolaylı olarak hala katkıda bulunur.

### Akıllı Uyum: **C++** Standartları ve Ortamları (Çekirdek Modu)

Bahsedildiği gibi, **Dralyxor** uyum sağlar:
- **C++ Standartları:** Minimum **C++14** gerektirir. Derleyici desteklediğinde **C++17** ve **C++20** özelliklerini (örneğin `if constexpr`, `consteval`, `type_traits` için `_v` sonekleri) algılar ve kullanır, aksi takdirde **C++14** alternatiflerine başvurur. `detection.hpp`'deki `_DRALYXOR_IF_CONSTEXPR` ve `_DRALYXOR_CONSTEVAL` gibi makrolar bu uyarlamayı yönetir.
- **Çekirdek Modu:** `_KERNEL_MODE` tanımlandığında (Windows sürücüleri için WDK projelerinde tipik), **Dralyxor** (`env_traits.hpp` aracılığıyla) `<type_traits>` gibi mevcut olmayabilecek veya farklı davranabilecek standart STL başlıklarını dahil etmekten kaçınır. Bunun yerine, `Dralyxor::Detail::Fallback::decay` ve `Dralyxor::Detail::Fallback::remove_reference` gibi temel araçların kendi `constexpr` uygulamalarını kullanır. Bu, **Dralyxor**'un alt düzey sistem bileşenlerindeki string'leri korumak için güvenli bir şekilde kullanılmasını sağlar.
   - Benzer şekilde, `secure_memory.hpp`, Çekirdek Modunda `RtlSecureZeroMemory` kullanır. Linux gibi diğer platformlar için, farklı veri tipleriyle uyumlu olacak şekilde uyarlanarak bellek temizliğini garanti etmek için `memset`'in güvenli kullanımına başvurur.
   - Kullanıcı Modu anti-debug kontrolleri (`IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString` gibi), Çekirdek Modunda geçerli olmadıkları veya farklı karşılıkları olduğu için devre dışı bırakılır (`#if !defined(_KERNEL_MODE)`). Zamanlama kontrolleri hala bir miktar etkiye sahip olabilir, ancak Çekirdek Modundaki ana savunma hattı karmaşıklaştırmanın kendisidir.

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