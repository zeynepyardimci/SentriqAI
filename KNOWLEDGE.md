# KNOWLEDGE.md

## 1. Proje özeti

**Ürün adı:** Sentriq AI (geçici ürün adı; geliştirme sırasında marka
çakışması kontrolü yapılmalı)\
**Ürün türü:** Yapay zekâ destekli güvenlik alarmı inceleme ve olay
araştırma SaaS'ı\
**Ana teknoloji:** Ruby on Rails 8 veya üzeri\
**Başlangıç durumu:** Greenfield. Bu görev için mevcut bir
uygulama/repo/commit olduğu varsayılmayacak. Çalışma alanını incele; var
olan kullanıcı dosyalarını izinsiz silme veya üzerine yazma.\
**Ana hedef:** Gerçek bir güvenlik analistinin alarmın nedenini ve olası
kaynağını anlamak için yaptığı manuel araştırmayı azaltan, uçtan uca
çalışan tek bir dikey dilim oluşturmak.

Bu belge proje boyunca kalıcı ürün ve mühendislik bağlamıdır. Uygulamaya
başlamadan önce tamamını oku. Master prompt ile çelişki varsa, güvenlik
ve dürüstlük ilkeleri korunarak kullanıcı tarafından açıkça belirtilen
gereksinimler önceliklidir. Bilmediğin bir şeyi olmuş gibi varsayma;
belirsizliği kaydet ve doğrula.

## 2. Problem ve ürün fırsatı

### Seçilen kullanıcı acısı

Güvenlik analistleri bir güvenlik tespiti/alarmla karşılaştıklarında,
alarmı tetikleyen olayları, ilişkili kanıtları ve olası saldırı
kaynağını anlamak için farklı kayıtları ve dokümanları manuel olarak
incelemek zorunda kalabilir. Bu, ilk değerlendirmeyi ve olay
incelemesini uzatabilir.

**Ürün vaadi:** Bir alarmın temel ayrıntılarını ve ilişkili kanıtları
bir araya getirip kaynak gösteren, belirsizlikleri açıkça belirten ve
insan analistin gözden geçirmesine sunulan bir araştırma özeti üretmek.
Sistem insan analistin yerini almaz ve yalnızca sentetik/demo verilerle
gerçek bir güvenlik ürünüymüş gibi davranmaz.

### Kaynak ve araştırma dürüstlüğü

Başlangıçta incelenecek kaynaklar:

-   Capterra CrowdStrike Falcon değerlendirmeleri:
    https://www.capterra.com/p/147662/CrowdStrike-Falcon/reviews/
-   G2 CrowdStrike Falcon Endpoint Protection Platform
    değerlendirmeleri:
    https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews

Bu bağlantılar araştırma başlangıç noktalarıdır; seçilen acıyı tek
başlarına kanıtlanmış gerçek olarak kabul etme. Sayfaları gerçekten aç,
erişilebilen yorumları oku ve ilgili iddiayı destekleyen kaydı doğrula.
Gerçekten bulunmayan bir alıntı, yorum tarihi, kullanıcı rolü, puan veya
istatistik uydurma. Kaynak sayfaya erişilemiyorsa bunu açıkça yaz ve
erişilebilir başka gerçek kaynaklarla desteklemeye çalış. Araştırma
sonuçlarını `docs/PAIN_POINT_RESEARCH.md` dosyasına yaz; her iddiayı
bağlantı ve mümkünse yorum başlığı/tarihiyle ilişkilendir. Yorumları
uzun uzun kopyalama; kısa alıntılar ve doğru paraphrase kullan.

Seçilen acıyı koru: **alarmın tetiklenme nedenini ve olası kaynağını
anlamak için gereken manuel araştırma yükü.** Araştırma sırasında kanıt
yetersiz çıkarsa iddiayı daralt veya belirsizliği belirt; ilgisiz yeni
bir problem seçerek kapsamı dağıtma.

## 3. Marka ve tasarım

-   Ürün adı: **Sentriq AI** (geçici; uygunluk/marka çakışması kontrol
    edilmeden hukuki olarak kullanılabilir olduğu iddia edilmemeli).
-   Kendine ait logo, renk paleti, tipografi ve arayüz dili üret.
-   CrowdStrike adını, logosunu, görsel kimliğini veya ekran tasarımını
    uygulama içinde kopyalama. CrowdStrike yalnızca `README.md` içindeki
    "Inspiration / İlham" açıklamasında anılabilir.
-   README içinde ürünün bağımsız bir demo/prototip olduğu ve
    CrowdStrike ile bağlantılı, onaylı veya ortak olmadığı açıkça
    belirtilmeli.
-   Arayüz profesyonel bir güvenlik operasyonu aracı gibi görünmeli;
    özgün olmalı, yalnızca dekoratif dashboard üretmekle yetinmemeli.
-   Erişilebilirlik, duyarlı tasarım, okunabilir hata/boş/yükleniyor
    durumları ve tutarlı bileşenler önemlidir.

## 4. Ürünün ana dikey dilimi

Tek bir uçtan uca akış bitirilecek:

1.  Analist oturum açar veya kontrollü demo erişimiyle uygulamaya girer.
2.  Sentetik güvenlik tespitleri listesini görür ve bir tespitin
    ayrıntısını açar.
3.  "AI ile araştır" eylemini başlatır.
4.  Rails tarafındaki araştırma servisi tespit ayrıntılarını ve ilgili
    sentetik kanıtları toplar.
5.  RAG katmanı ilgili bilgi tabanı dokümanlarını gerçekten arar ve
    bulunan kaynakları döndürür.
6.  AI ajanı kanıtları özetler; olası nedenleri, kanıt boşluklarını ve
    önerilen sonraki adımları yapılandırılmış biçimde üretir.
7.  Rapor kaynaklarını, sınırlılıklarını ve güven düzeyine ilişkin
    açıklamaları gösterir. Kaynaksız iddialar gerçekmiş gibi sunulmaz.
8.  Analist bulguları inceler, not ekler, kabul eder/düzeltir veya üst
    incelemeye yollar.
9.  Durum değişikliği ve önemli işlemler denetim geçmişine yazılır.

Bu akış gerçek veri modeli, servisler, kalıcı kayıtlar ve testlerle
çalışmalıdır. Yalnızca statik ekran, sahte "AI düşünüyor" animasyonu
veya genel amaçlı sohbet kutusu yeterli değildir.

## 5. Teknoloji ve mimari

### Zorunlu

-   Ruby on Rails **8+**.
-   Kalıcı veritabanı: tercihen PostgreSQL.
-   Canlı, herkese açık demo URL'si.
-   Testler ve kurulum/deploy dokümantasyonu.
-   Kök dizinde `CHALLENGE_LOG.md`.
-   Araştırma notları: `docs/PAIN_POINT_RESEARCH.md`.

### Tercih edilen basit yaklaşım

-   Rails views + Hotwire/Turbo/Stimulus veya Rails ile uyumlu, gerekli
    olduğu kadar küçük bir frontend.
-   İş mantığı için açık servis nesneleri; controller içinde büyük iş
    akışları biriktirme.
-   Background job gerekiyorsa Active Job ve deploy ortamına uygun bir
    adapter.
-   RAG için başlangıçta PostgreSQL full-text search veya pgvector gibi
    gerçekten çalışan bir çözüm. Sırf teknoloji listesi kabartmak için
    gereksiz altyapı ekleme.
-   LLM sağlayıcısı konfigürasyonla değiştirilebilir olsun. API
    anahtarlarını yalnızca ortam değişkenlerinden al; repoya secret
    koyma.
-   Harici LLM anahtarı yoksa, uygulamanın sınırlı demo modunu açıkça
    etiketle. Demo çıktısını gerçek LLM sonucu gibi gösterme. Mümkünse
    canlı demoda yapılandırılmış bir sağlayıcı kullan; aksi durumda bu
    sınırlılığı arayüzde ve README'de dürüstçe açıkla.

### Önerilen temel modeller

Model isimlerini gerçek ihtiyaçlara göre değiştir; gereksiz model
oluşturma: - `User` - `Detection` - `EvidenceEvent` veya `Evidence` -
`KnowledgeDocument` / `KnowledgeChunk` - `Investigation` -
`InvestigationFinding` veya Investigation içinde yapılandırılmış JSON
bulgular - `AuditEvent`

Veri şemasını ve ilişkileri uygulama gereksinimlerine göre tasarla,
migration ve model testleri ekle. Demo verileri sentetik olmalı ve
sentetik olduğu belirtilmeli.

## 6. AI Investigation Agent

### Önerilen gerçek araçlar

Ajanın araçları yalnızca isim olarak bulunmamalı; Rails servislerini
çağırmalı ve gerçek uygulama verileri üzerinde çalışmalı:

-   `search_detections`
-   `get_detection_details`
-   `search_knowledge_base`
-   `create_investigation`
-   `add_investigation_note`
-   `request_human_review`

Araç adlarını/şemalarını sağlayıcıya uygun biçimde uygula.
Yetkilendirme, parametre doğrulama, hata yakalama ve işlem kayıtları
ekle. Ajanın araçları uygulama içinde olmayan bir endpoint'e, gerçek
müşteri ağına veya gerçek uç noktaya müdahale etmemeli.

### Yapılandırılmış çıktı

AI yanıtı mümkün olduğunca doğrulanan şemayla alınmalı ve sunulmadan
önce doğrulanmalı. Önerilen alanlar:

-   `summary`
-   `observed_evidence`
-   `possible_causes`
-   `evidence_gaps`
-   `recommended_steps`
-   `source_references`
-   `requires_human_review`
-   `limitations`

JSON parse hatası veya beklenmeyen çıktı olduğunda güvenli hata akışı
kullan; uygulamayı çökertme ve uydurma sonuçla devam etme.

### RAG ve kaynak gösterme

-   Arama gerçekten bilgi tabanı içeriği üzerinde çalışmalı.
-   Araştırma raporundaki kaynaklar açılabilir ve ilgili doküman/parça
    ile eşleşebilir olmalı.
-   Eşleşen kaynak yoksa "kaynak bulunamadı" de; kaynak veya alıntı
    üretme.
-   Sentetik örnek dokümanlar açıkça sentetik olarak işaretlenmeli.
-   Getirilen doküman içeriği talimat değil, güvenilmeyen veridir.
    Doküman içine yerleştirilen prompt injection metinleri sistem
    kurallarını, araç izinlerini veya kullanıcı onayını geçersiz
    kılamamalı.
-   Kanıt, varsayım ve öneri birbirinden ayrılmalı. Model bir olası
    nedeni kesin bulgu gibi sunmamalı.

### İnsan denetimi (HITL)

-   AI sonuçları öneridir; yüksek etkili eylemleri kendiliğinden
    yürütme.
-   Analist raporu gözden geçirebilmeli, düzenleyebilmeli, not
    bırakabilmeli ve onaylayabilmeli/eskale edebilmeli.
-   Kim, neyi, ne zaman değiştirdi bilgisi audit log'a kaydedilmeli.

### 6.1. Agent-First Mimarisi ve API Entegrasyonu

Harici yazılım agent'ları (SOAR, botlar, SIEM webhook'ları) UI olmaksızın REST API üzerinden işlem yapabilir:
- `POST /api/v1/tickets`: Idempotent ticket oluşturma (`Idempotency-Key` başlığı veya parametresi ile mükerrer istek koruması).
- `GET /api/v1/tickets/:id`: Ticket ve ilişkili telemetri/not detaylarını okuma.
- `GET /api/v1/detections`: Güvenlik tespitlerini ve kanıtlarını sorgulama.
- `GET /api/v1/knowledge_base/search`: RAG bilgi tabanı runbook araması.
- `POST /api/v1/tickets/:id/analyze`: LLM bağlamsal analiz ve yanıt taslağı üretimi.
- `POST /api/v1/tickets/:id/notes`: Agent bulgu veya taslak notu ekleme.
- `POST /api/v1/tickets/:id/escalate`: Belirsizlik/yüksek riskte insan incelemesi talep etme (`pending_review`).
- `GET /api/v1/tickets/:id/human_decision`: İnsan analist kararını ve son durumu sorgulama.

Yetkilendirme `Authorization: Bearer <demo_token>` veya `X-Agent-Token` ile sağlanır. Tüm API çağrıları audit log'a işlenir ve rate-limit başlıkları döndürülür.

### 6.2. LLM Tabanlı Bağlamsal Karar Motoru (Contextual vs Keyword Matching)

Sistem "acil", "teşekkür", "kritik" gibi yüzeysel anahtar kelimelere dayalı if/else kuralları ile karar VERMEZ.
- LLM, cümlenin tüm anlamsal bağlamını değerlendirir. Örneğin "Dünkü acil durum tatbikatı başarıyla tamamlandı, teşekkürler" ifadesi acil kelimesi içerse de rutin bir tatbikat raporudur (`informational_retrospective`, düşük öncelik, insana devir gerektirmez).
- Aktif süreç çalıştırma ve şüpheli LOLBin telemetrisi ("powershell -enc", "certutil -urlcache") içeren olaylar ise aktif tehdit olarak sınıflandırılır ve insan onayına (`pending_review`) devredilir.
- Çelişkili veya belirsiz kanıt durumunda ajan kendiliğinden varsayım üretmez; `pending_review` durumuna geçirerek analiste devreder.
- Bilgi tabanında eşleşmeyen olaylar için sahte kaynak üretilmez ("Kaynak bulunamadı" olarak raporlanır).


## 7. Durum akışı ve zaman kuralı

Tespit/inceleme için açık ve test edilmiş bir durum akışı oluştur.
Örnek:

`new → open → investigating → pending_review → solved`

Gerektiğinde `reopened` gibi kontrollü bir geçiş desteklenebilir.
Geçersiz geçişler sunucu tarafında reddedilmeli; yalnızca arayüzde
gizlemek yeterli değildir.

En az bir işlevsel zaman kuralı/SLA olmalı. Örnek kural: **yüksek
öncelikli yeni tespit 15 dakika içinde incelemeye alınmazsa "risk
altında" olarak işaretlenir ve sorumluya bildirim/uyarı oluşturulur.**
Bu, ürün için seçilmiş yapılandırılabilir bir demo varsayımıdır;
evrensel sektör standardı diye sunma. Saat/zaman hesabı test edilebilir
olmalı ve kontrollü test zamanı kullanılmalı. Deploy ortamında
scheduler/worker gereksinimi varsa gerçekten yapılandır ve doğrula;
çalışmayan bir cron tanımını tamamlanmış gibi yazma.

## 8. Güvenlik ve veri bütünlüğü

-   Demo verileri sentetik olsun; gerçek müşteri verisi veya gerçek
    endpoint bağlantısı kullanma.
-   Kimlik doğrulama ve rol kontrollerini gerektiği ölçüde uygula; demo
    erişimini güvenli şekilde sınırla.
-   Her tespit/inceleme/not için kullanıcı yetkisini sunucu tarafında
    denetle.
-   CSRF, XSS, SQL injection, güvenli parametreler, rate limit ve hassas
    hata mesajları açısından gözden geçir.
-   API anahtarları, şifreler ve diğer secret'lar repoya yazılmamalı.
-   LLM çıktısı güvenilmeyen girdidir; HTML olarak güvenli olmayan
    biçimde render edilmemeli.
-   Prompt injection, veri sızıntısı ve araçların yetkisiz çağrılması
    için temel testler ekle.
-   Gerçek endpoint karantinası, dosya silme, hesap kapatma gibi yıkıcı
    eylemleri uygulama.
-   Gerçek ödeme akışı şart değil. Eklenirse gerçek kart bilgisi
    toplama; test modu/fake provider kullan ve bunun demo olduğunu
    açıkla.

## 9. Test ve kalite

En az şu davranışları test et: - Durum geçişleri ve geçersiz geçişlerin
reddi. - SLA zaman hesabı ve risk uyarısı. - RAG sonuçları ile rapor
kaynaklarının eşleşmesi. - Ajan araçlarının gerçek servisleri çağırması
ve geçersiz parametreleri reddetmesi. - AI çıktısı şema/JSON doğrulaması
ve hatalı sağlayıcı yanıtı. - İnsan incelemesi, onay/eskalasyon ve audit
kaydı. - Kimlik doğrulama/yetkilendirme. - Kaynak bulunmadığında modelin
kanıt uydurmaması. - Prompt injection içeren bilgi dokümanının güvenlik
kurallarını aşamaması.

Testleri gerçekten çalıştır. Başarısız veya çalıştırılmamış testleri
başarılı diye bildirme. Lint, security scan ve test çıktılarındaki
gerçek sonuçları son rapora ekle.

## 10. Canlıya alma

-   Uygulamayı yalnızca yerel bilgisayarda bırakma; görev canlı URL
    gerektiriyor.
-   Daha önce kullanılmadığı doğrulanamayan bir platformu "ilk kez
    kullanıldı" diye iddia etme. Uygun bir seçenek olarak Render
    değerlendirilebilir; gerekirse PostgreSQL ve worker/scheduler
    desteğini doğrula.
-   Üretim ortamında `RAILS_MASTER_KEY`, veritabanı URL'si ve LLM
    anahtarları gibi secret'ları güvenli ortam değişkenleriyle
    yapılandır.
-   Migration ve seed akışını doğrula.
-   Deploy sonrası gerçek public URL'yi açıp ana kullanıcı akışını dene.
    Sadece deploy komutunun başarılı olması canlı uygulamanın
    çalıştığını kanıtlamaz.
-   Deploy başarısızsa gerçek hata/engel, denenen adımlar ve kalan iş
    açıkça belgelenmeli. Canlı URL, test veya özellik sonucu
    uydurulamaz.

## 11. Zorunlu dokümantasyon ve dürüst kayıt

Kök dizinde `CHALLENGE_LOG.md` oluştur ve şu başlıkları **aynen**
kullan:

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

### CHALLENGE_LOG kuralları

-   Bu görev greenfield ise ve önceki repo/commit yoksa bunu açıkça yaz;
    eski commit veya link uydurma.
-   "Klonlanan ürün" alanında CrowdStrike Falcon'un yalnızca hangi temel
    iş akışından ilham alındığını açıkla; gerçek ürünü klonladığını veya
    entegrasyon kurduğunu iddia etme.
-   "Bu ürüne kim, neden para ödüyor?" sorusunu hedef kullanıcı ve değer
    önerisi üzerinden yanıtla; ödeme/gelir doğrulanmadıysa bunu varsayım
    olarak etiketle.
-   İnsan ve ajan zamanını ölçmediysen "ölçülmedi" yaz; süre
    tahminlerini gerçekleşmiş süre diye kaydetme.
-   "İlk prompt" alanına gerçekten bu projeyi başlatan prompt'u olduğu
    gibi koy. Sonradan yeniden yazılmış prompt'u ilk prompt diye sunma.
-   Commit bağlantıları yalnızca gerçek commit'ler oluşturulup push
    edildikten sonra eklenmeli.
-   Yapılmayan veya doğrulanamayan vaatleri açıkça listele.
-   Günlük/önemli kilometre taşlarında dosyayı güncelle; yalnızca işin
    sonunda geriye dönük, varsayımsal kayıt oluşturma.

## 12. README ve proje teslimi

README en az şunları içersin: - Ürün amacı ve hedef kullanıcı. - Sorun
araştırması ve kaynaklar. - Temel kullanıcı akışı. - Mimari ve veri
akışı. - Yerel kurulum, test ve seed komutları. - Ortam değişkenleri
örnek dosyası (secret olmadan). - AI/RAG yaklaşımı, sınırlılıklar ve
demo modunun açıklaması. - Canlı demo bağlantısı ve test adımları. -
Sentetik veri açıklaması. - CrowdStrike ile bağlantı/ortaklık olmadığına
dair açık uyarı; CrowdStrike yalnızca ilham kaynağı olarak anılabilir.

## 13. Kapsam yönetimi ve tamamlanma tanımı

Öncelik sırası: 1. Kaynak araştırmasını doğrula. 2. Rails 8+
uygulamasını ve veri modelini kur. 3. Dikey dilimin uçtan uca
çalışmasını sağla. 4. AI + RAG + kaynak gösterme + insan incelemesini
gerçek şekilde bağla. 5. Durum akışı, SLA ve audit log'u tamamla. 6.
Kritik testleri çalıştır. 7. Özgün marka ve arayüzü tamamla. 8. Canlıya
al ve public URL'de doğrula. 9. README, `docs/PAIN_POINT_RESEARCH.md` ve
`CHALLENGE_LOG.md` dosyalarını gerçek kanıtlarla güncelle.

Ek özellikleri, dikey dilim bitmeden ekleme. Yalnızca gösterişli bir
dashboard, sahte AI, çalışmayan butonlar veya doğrulanmamış deploy
"tamamlandı" sayılmaz.

Bir özellik ancak kodda mevcut, çalıştırılmış ve uygun kanıtla
doğrulanmışsa tamamlandı olarak işaretlenebilir.
