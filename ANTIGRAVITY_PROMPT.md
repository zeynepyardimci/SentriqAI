# Antigravity Master Prompt --- Sentriq AI

Önce çalışma alanının kök dizinindeki `KNOWLEDGE.md` dosyasını
**tamamını okuyup** ürün bağlamını, teknik kuralları, problem seçimini,
güvenlik ilkelerini ve teslim gereksinimlerini çıkar. Bu dosyayı
uygulama boyunca referans al. Ardından aşağıdaki görevi yerine getir.
`KNOWLEDGE.md` içinde belirtilen seçilmiş kullanıcı acısını değiştirme;
kaynak doğrulaması başarısız olursa iddiayı dürüstçe daralt ve belgele.

## Görev

Sıfırdan, Ruby on Rails 8 veya üzeriyle **Sentriq AI** adlı özgün
markalı bir AI destekli güvenlik tespiti inceleme uygulaması geliştir.
Bu bir greenfield projedir. Önce çalışma alanını incele; mevcut
dosyaları silme veya üzerine yazma. Önceden repo, commit, test, deploy
veya tamamlanmış özellik varmış gibi davranma.

Ürün, CrowdStrike Falcon'un tümünü kopyalamaya çalışmayacak. Yalnızca
güvenlik tespiti açma, ilişkili kanıtları inceleme, araştırma yürütme,
bulgu üretme ve insan analistin incelemesiyle durumu güncelleme
şeklindeki **tek bir temel dikey dilimden** ilham alacak. Uygulama, logo
ve görsel kimlik özgün olacak. CrowdStrike adını/logosunu UI'da
kullanma; yalnızca README'de ilham kaynağı olarak, bağımsızlık
uyarısıyla an.

## Başlamadan önce

1.  `KNOWLEDGE.md` dosyasını baştan sona oku.
2.  Çalışma alanını ve Git durumunu kontrol et. Mevcut dosyaları koru;
    bu görev için önceki commit yoksa bunu not et.
3.  `https://www.capterra.com/p/147662/CrowdStrike-Falcon/reviews/` ve
    `https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews`
    sayfalarını gerçekten açıp incele. Güvenlik analistinin tespitin
    nedenini/kaynağını anlamak için yaptığı manuel araştırma yükünü
    destekleyen gerçek kanıt ara. Alıntı, yorum tarihi, rol, puan veya
    istatistik uydurma. Kaynaklara erişemiyorsan bunu açıkça belirt ve
    erişilebilir gerçek kaynaklarla devam et.
4.  Bulguları `docs/PAIN_POINT_RESEARCH.md` içine kaynak bağlantıları ve
    doğrulama notlarıyla kaydet.
5.  Uygulamaya geçmeden önce kısa bir uygulama planı hazırla; sonra
    kullanıcıdan onay beklemeden devam et.

## Ana ürün akışı --- tamamı uçtan uca çalışmalı

1.  Analist uygulamaya girer ve sentetik tespitler listesini açar.
2.  Bir tespitin ayrıntılarını, önceliğini, zamanını ve ilişkili
    sentetik kanıtları görüntüler.
3.  "AI ile araştır" eylemini başlatır.
4.  Rails backend tespit ayrıntılarını ve ilişkili kanıtları toplar.
5.  Gerçek bir RAG araması bilgi tabanındaki ilgili prosedür/doküman
    parçalarını getirir.
6.  AI Investigation Agent, uygulama servislerine bağlı araçları
    kullanarak kanıtları değerlendirir.
7.  Sonuç; özet, gözlemlenen kanıtlar, olası nedenler, kanıt boşlukları,
    önerilen adımlar, kaynak referansları ve sınırlılıkları içerir.
8.  Kaynak referansları kullanıcı tarafından açılabilir ve rapordaki
    ifadeleri gerçekten destekler. Kaynak yoksa kaynak uydurulmaz;
    belirsizlik açıkça belirtilir.
9.  Analist bulguları gözden geçirir, not ekler, düzeltir, onaylar veya
    üst incelemeye gönderir.
10. Durum geçişleri ve önemli değişiklikler veritabanına kaydedilir;
    audit history görüntülenebilir.

Genel bir chatbot veya yalnızca statik dashboard üretme. Butonlar,
formlar, durum geçişleri ve AI araştırma akışı gerçekten çalışmalı. Demo
verileri sentetik olarak etiketlenmeli.

## AI ajanı ve araçlar

`KNOWLEDGE.md` içindeki AI/RAG şartlarına uy. En az şu araçların
işlevsel eşdeğerlerini oluştur:

-   `search_detections`
-   `get_detection_details`
-   `search_knowledge_base`
-   `create_investigation`
-   `add_investigation_note`
-   `request_human_review`

Araçlar gerçek Rails servislerini ve kalıcı verileri kullanmalı. Girdi
doğrulama, hata yakalama ve yetkilendirme ekle. AI çıktısını
yapılandırılmış şemayla doğrula; beklenmeyen/bozuk çıktı olduğunda
güvenli hata durumu göster. Kanıt, olası açıklama ve önerileri
birbirinden ayır. RAG kaynakları gerçek alınmış dokümanlarla eşleşsin.
Doküman içeriklerini güvenilmeyen veri kabul et ve prompt injection'ın
sistem kurallarını veya araç izinlerini aşmasını engelle.

LLM API anahtarlarını yalnızca ortam değişkenlerinden al. Harici anahtar
yoksa açıkça etiketlenmiş bir demo/fallback modu sun; fallback çıktısını
gerçek LLM çalıştırmış gibi gösterme. Canlı demoda kullanılabilir bir
LLM sağlayıcısı yapılandırmak için elinden geleni yap ve gerekli
environment variable'ları README'de belirt; secret değerlerini dosyalara
yazma.

## Durum akışı ve zaman kuralı

Sunucu tarafında doğrulanan bir durum akışı uygula. Önerilen akış:

`new → open → investigating → pending_review → solved`

Gerekiyorsa kontrollü `reopened` geçişi ekle. Geçersiz geçişler backend
tarafından reddedilmeli.

En az bir gerçek zaman/SLA kuralı uygula. Örnek: yüksek öncelikli yeni
tespit 15 dakika içinde incelemeye alınmazsa risk altında işaretlenir ve
sorumluya uyarı oluşturulur. Bu süreyi sektör standardı olarak sunma;
konfigüre edilebilir ürün varsayımı olarak belgele. Zaman mantığı için
otomatik test yaz. Deploy ortamında gerekli scheduler/worker'ı gerçekten
yapılandır ve doğrula.

## Teknik kalite ve güvenlik

-   Ruby on Rails 8+ ve PostgreSQL kullan.
-   Basit, bakımı kolay mimari kur; gereksiz teknoloji ekleme.
-   Kimlik doğrulama/yetkilendirme, CSRF/XSS/SQL injection, güvenli
    parametreler, rate limiting ve audit logging konularını değerlendir.
-   Gerçek sistemlere/endpoint'lere bağlanma veya yıkıcı güvenlik
    işlemleri yürütme; yalnızca sentetik demo verisi kullan.
-   Secret, gerçek müşteri verisi veya API anahtarı commit etme.
-   AI çıktısını güvenli render et.
-   Hatalar için boş, yükleniyor, başarılı ve başarısız UI durumları
    tasarla.
-   Test yaz ve gerçekten çalıştır. En az durum akışı, SLA, RAG kaynak
    eşleşmesi, agent tool çağrıları, bozuk LLM yanıtı, insan incelemesi,
    audit log, yetkilendirme ve prompt injection davranışını kapsa.
-   Başarısız/çalıştırılmamış testleri başarılı diye bildirme.

## Marka ve UX

Özgün Sentriq AI marka kimliği ve logo üret. Temiz, profesyonel,
güvenlik analisti iş akışına uygun arayüz tasarla. Yalnızca görsel
taklit yapma. Mobil/masaüstü uyumu, erişilebilirlik, anlamlı boş
durumlar ve anlaşılır hata mesajları sağla. CrowdStrike markasını veya
ekranlarını kopyalama.

## Canlı deploy zorunlu

Uygulamayı public URL'de deploy et; yerel demo yeterli değil. Daha önce
kullanılmadığı doğrulanmayan bir platformu "ilk kez kullandım" diye
iddia etme. Render uygun bir aday olabilir; veritabanı, worker ve
scheduler gereksinimlerini doğrula. Deploy sonrasında public URL'yi
gerçekten aç ve ana dikey dilimi uçtan uca dene. Yalnızca build/deploy
komutunun başarılı olması yeterli kanıt değildir.

Deploy başarısız olursa gerçek hata mesajını, denenen adımları ve kalan
engeli kaydet; URL veya canlı özellik uydurma. Ancak görevin tamamlanma
hedefi canlı uygulamadır, bu nedenle engel yoksa deploy'u erteleme.

## Zorunlu dosyalar

### `CHALLENGE_LOG.md`

Repo kökünde oluştur. Aşağıdaki başlıkları aynen koru:

# CHALLENGE_LOG

## Başlangıç noktası

-   Klonlanan ürün ve canlı URL
-   Geçen haftanın son commit'i (link)
-   Bu ürüne kim, neden para ödüyor?

## Acı

-   Hangi kullanıcının hangi acısı? Kaynak (şikâyet, forum, inceleme
    linki)

## Bu haftanın vaadi

-   "Şuraya kadar getirdim, üzerine şunu ekleyeceğim."

## Yapılanlar ve kanıt

-   Commit linkleri, çalışan testler, canlı demo adımları
-   Vaat edip yapamadığın ne varsa açıkça yaz

## Zaman

-   İnsan zamanı / agent zamanı (dürüstçe)
-   İlk prompt'un (olduğu gibi)

## Karar

-   Devam / pivot / öldür ve gerekçesi

Bu greenfield görevinde önceki commit yoksa bunu açıkça yaz; commit/URL
uydurma. İnsan/ajan süresini ölçmediysen "ölçülmedi" yaz. "İlk prompt"
alanına bu görevi başlatan prompt'u olduğu gibi koy; sonradan
düzenlenmiş prompt'u ilk prompt gibi sunma. Gerçek commit linklerini
ancak commit ve push gerçekleştikten sonra ekle. Yapılmayan vaatleri
dürüstçe listele. Çalışma boyunca bu dosyayı güncelle.

### `README.md`

Amaç, hedef kullanıcı, problem araştırması, ana akış, mimari, yerel
kurulum, test/seed komutları, ortam değişkenleri, AI/RAG sınırları,
sentetik veri açıklaması, canlı demo URL'si ve demo adımları bulunmalı.
CrowdStrike ile bağlantı/ortaklık olmadığına dair açık uyarı ekle.

### `docs/PAIN_POINT_RESEARCH.md`

Seçilen acının kanıtlarını ve kaynakların gerçekten incelenip
incelenmediğini, bağlantıları, kısa alıntı/paraphrase'leri ve
sınırlılıkları yaz. Kanıt uydurma.

## Git ve çalışma disiplini

-   Küçük ve anlamlı commit'ler oluştur; test veya deploy başarısını
    kanıtlamayan commit mesajları kullanma.
-   Kullanıcının mevcut dosyalarını izinsiz silme/yeniden yazma.
-   İşin sonunda git status kontrolü yap; yanlışlıkla secret veya
    gereksiz dosya commit edilmediğinden emin ol.
-   Çalışan testleri ve deploy doğrulamasını raporla.
-   Planlanan, yazılmış, test edilmiş ve canlıda doğrulanmış özellikleri
    birbirinden ayır.

## Tamamlanma ölçütleri

Görevi tamamlandı saymadan önce şu maddeleri doğrula:

-   [ ] `KNOWLEDGE.md` okundu ve gereksinimleri uygulandı.
-   [ ] Kaynak araştırması gerçek bağlantılarla belgelendi.
-   [ ] Rails 8+ uygulaması ve PostgreSQL çalışıyor.
-   [ ] Tespit → AI araştırması → RAG kaynakları → insan incelemesi →
    durum/audit akışı uçtan uca çalışıyor.
-   [ ] Durum akışı ve SLA kuralı backend ve testlerle doğrulandı.
-   [ ] AI çıktıları doğrulanıyor; kaynaklar gerçek; belirsizlikler
    açık.
-   [ ] Kritik testler çalıştırıldı ve gerçek sonuçlar kaydedildi.
-   [ ] Özgün marka/logo ve responsive arayüz hazır.
-   [ ] Public URL deploy edildi ve ana akış canlıda denendi.
-   [ ] `README.md`, `docs/PAIN_POINT_RESEARCH.md` ve `CHALLENGE_LOG.md`
    gerçeğe uygun.
-   [ ] Secret veya uydurulmuş kanıt yok.

Öncelik sırası: araştırmayı doğrula → dikey dilimi geliştir →
AI/RAG/HITL bağla → durum/SLA/audit ekle → test et → deploy et ve
doğrula → dokümantasyonu kanıtlarla tamamla. Dikey dilim çalışmadan
kapsamı genişletme.

**Şimdi başla:** önce `KNOWLEDGE.md` dosyasını oku ve workspace/Git
durumunu kontrol et; ardından planı oluştur ve uygulamayı sonuna kadar
tamamla. Kullanıcıdan gereksiz ara onaylar isteme. Herhangi bir dış
servis veya secret gerektiren adımda mevcut erişimi kontrol et, eksikse
yalnızca gerekli bilgiyi iste ve diğer bağımsız işleri sürdür.
