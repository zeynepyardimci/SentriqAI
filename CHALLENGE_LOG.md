# CHALLENGE_LOG

## Başlangıç noktası

- Klonlanan ürün ve canlı URL: CrowdStrike Falcon (Yalnızca tespit inceleme, kanıt toplama ve analist karar akışından ilham alınmıştır; doğrudan klonlama veya entegrasyon yoktur). Canlı URL henüz deploy edilmemiştir (Greenfield başlangıç).
- Geçen haftanın son commit'i (link): Yok. Greenfield proje, önceki commit veya repo geçmişi bulunmamaktadır.
- Bu ürüne kim, neden para ödüyor?: SOC (Security Operations Center) analistleri, MSSP'ler (Managed Security Service Providers) ve kurumsal güvenlik ekipleri; alarm başına harcanan 15-30 dakikalık manuel kök neden araştırmasını 2-3 dakikaya indirerek analist yorgunluğunu azaltmak ve kritik tehditlere müdahale süresini (MTTR) hızlandırmak için (varsayım; henüz doğrulanmış ticari gelir bulunmamaktadır).

## Acı

- Hangi kullanıcının hangi acısı? Kaynak (şikâyet, forum, inceleme linki): Güvenlik analistlerinin bir alarm tetiklendiğinde olası saldırı kaynağını ve nedenini anlamak için süreç ağaçlarını, komut satırı parametrelerini ve dahili bilgi dokümanlarını manuel inceleme yükü. Kaynaklar: `docs/PAIN_POINT_RESEARCH.md` içinde belgelenen Panther Security analizi, Abnormal Security / Strike48 SOC verileri ve r/crowdstrike ile TrustRadius üzerindeki analist iş akışı tartışmaları (G2 ve Capterra doğrudan erişimi HTTP 403 verdiği için açık kaynaklarla desteklenmiştir).

## Bu haftanın vaadi

- "Şuraya kadar getirdim, üzerine şunu ekleyeceğim.": Greenfield başlangıçtan itibaren: Rails 8+, PostgreSQL, AI Investigation Agent, RAG bilgi tabanı entegrasyonu, insan incelemesi (HITL), durum makinesi ve SLA kuralını içeren çalışan tek dikey dilim oluşturulacak, test edilecek ve canlıya alınacaktır.

## Yapılanlar ve kanıt

- Commit linkleri, çalışan testler, canlı demo adımları:
  - Çalışma alanı ve git incelendi, izole git repo başlatıldı.
  - Capterra ve G2 erişimleri test edildi; HTTP 403 engeli dürüstçe belgelendi ve açık güvenlik kaynaklarıyla `docs/PAIN_POINT_RESEARCH.md` hazırlandı.
  - Uygulama geliştirme ve test adımları sürdürülmektedir.
- Vaat edip yapamadığın ne varsa açıkça yaz: Henüz Rails uygulaması canlı ortama alınmamış ve testler tamamlanmamıştır (süreç devam etmektedir).

## Zaman

- İnsan zamanı / agent zamanı (dürüstçe): İnsan zamanı: ölçülmedi / Agent zamanı: devam ediyor (başlangıç: 2026-10-20T23:42:08+03:00)
- İlk prompt'un (olduğu gibi):
```
Önce proje kök dizinindeki `KNOWLEDGE.md` ve `ANTIGRAVITY_PROMPT.md` dosyalarının ikisini de eksiksiz oku. Bu iki dosyadaki gereksinimleri birlikte değerlendir ve özellikle `KNOWLEDGE.md` dosyasındaki proje bağlamını, teknoloji tercihlerini, seçilen kullanıcı problemini, güvenlik kurallarını ve teslim kriterlerini esas al.

Bu proje sıfırdan geliştirilecek. Mevcut dosyaları silme veya üzerine yazma. Henüz uygulama kodu yazılmadığını, önceki commit bulunmadığını ya da canlıya alındığını varsayma.

Ardından şu sırayla ilerle:

1. Workspace ve Git durumunu kontrol et.
2. İki Markdown dosyasını okuduğunu ve anladığını doğrula.
3. Ruby on Rails 8+, PostgreSQL, AI Investigation Agent, RAG, insan incelemesi, durum akışı, SLA ve özgün Sentriq AI marka kimliğini kapsayan kısa ve somut bir uygulama planı oluştur.
4. Kaynak araştırmasını yap ve doğrulanmış bulguları `docs/PAIN_POINT_RESEARCH.md` dosyasına kaydet.
5. Uygulamayı yalnızca statik ekranlardan ibaret bırakmadan uçtan uca çalışır şekilde geliştir.
6. Testleri gerçekten çalıştır, hataları gider ve `CHALLENGE_LOG.md` dosyasını gerçek kanıtlarla güncelle.
7. Uygulamayı canlıya al, public URL üzerinden ana kullanıcı akışını doğrula ve `README.md` dosyasını tamamla.

**Önemli:** Yalnızca plan sunup durma. Planı oluşturduktan sonra uygulamayı geliştirmeye devam et. Gereksiz onaylar için bekleme. Bir engelle karşılaşırsan hatayı araştır, çözüm dene ve bağımsız işlere devam et. Gerçekten kullanıcıdan bilgi veya erişim gerekiyorsa yalnızca gerekli noktada sor.

Tamamlanmamış özellikleri tamamlanmış gibi gösterme; kaynak, test sonucu, commit veya canlı URL uydurma. Harici API anahtarı yoksa bunu açıkça belirt ve güvenli alternatifleri uygula. Önceliğin çalışan dikey dilim ve canlı demodur; gereksiz özelliklerle kapsamı genişletme.

Şimdi dosyaları oku, planı çıkar ve geliştirmeye başla.
```

## Karar

- Devam / pivot / öldür ve gerekçesi: Devam. Güvenlik analistlerinin alarm kök neden araştırmasındaki manuel yük gerçek bir operasyonel darboğazdır. Çözüm tek dikey dilimle somut şekilde kanıtlanabilir.
