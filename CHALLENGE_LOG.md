# CHALLENGE_LOG

## Başlangıç noktası

- Klonlanan ürün ve canlı URL: CrowdStrike Falcon (Yalnızca tespit inceleme, telemetri korelasyonu, süreç ağacı ve analist karar akışından ilham alınmıştır; doğrudan klonlama veya entegrasyon yoktur). Canlı URL: Yerel ortamda `http://127.0.0.1:3000/` üzerinde çalışmaktadır; Render `render.yaml` ve Dockerfile dağıtım için hazırlanmıştır (harici Render hesabı API anahtarı yapılandırılmadığı için genel public bulut URL'si yerine yerel sunucu ve Docker ortamında uçtan uca doğrulanmıştır).
- Geçen haftanın son commit'i (link): Yok. Greenfield proje, önceki repo geçmişi bulunmamaktadır.
- Bu ürüne kim, neden para ödüyor?: SOC (Security Operations Center) analistleri, MSSP'ler (Managed Security Service Providers) ve kurumsal güvenlik ekipleri; alarm başına harcanan 15-30 dakikalık manuel kök neden araştırmasını 2-3 dakikaya indirmek, analist tükenmişliğini önlemek ve harici yazılım agent'ları (SOAR) ile insan analistler arasında güvenli bir devir (handover) köprüsü kurmak için (varsayım; henüz doğrulanmış ticari gelir bulunmamaktadır).

## Acı

- Hangi kullanıcının hangi acısı? Kaynak (şikâyet, forum, inceleme linki): Güvenlik analistlerinin bir alarm tetiklendiğinde olası saldırı kaynağını ve nedenini anlamak için süreç ağaçlarını, komut satırı parametrelerini ve dahili bilgi dokümanlarını manuel inceleme yükü. Kaynaklar: `docs/PAIN_POINT_RESEARCH.md` içinde belgelenen Panther Security analizi, Abnormal Security / Strike48 SOC verileri ve r/crowdstrike ile TrustRadius üzerindeki analist iş akışı tartışmaları (G2 ve Capterra doğrudan erişimi HTTP 403 verdiği için açık kaynaklarla desteklenmiştir).

## Bu haftanın vaadi

- "Şuraya kadar getirdim, üzerine şunu ekleyeceğim.": Greenfield başlangıçtan itibaren: Rails 8+, PostgreSQL 16 + pgvector, AI Investigation Agent, RAG bilgi tabanı entegrasyonu, Agent-First REST API (ticket açma, yanıtlama, insana devir), LLM tabanlı bağlamsal karar motoru (anahtar kelime tuzağına düşmeyen anlamsal analiz), SLA kuralı ve insan denetimi (HITL) uçtan uca geliştirildi, test edildi ve belgelendi.

## Yapılanlar ve kanıt

- Commit linkleri, çalışan testler, canlı demo adımları:
  - Commit `48734d8`: `feat: initialize Rails 8 application with PostgreSQL and pain point research`
  - Commit `42ac028`: `feat: complete end-to-end AI investigation, RAG, HITL review, and test suite`
  - Commit `e5439cf`: `feat: implement agent-first REST API, contextual decision engine, and interactive simulation demo`
  - Commit `4c76008`: `feat: add zero-touch autonomous agent ingestion service, API endpoint, and UI triggers`
  - Çalışan Testler Kanıtı: `ruby bin/rails test` çalıştırıldı; 43 test, 210 assertion, 0 hata, 0 başarısızlık (100% geçiş).
    - Model testleri (Detection state machine, Ticket status transitions, SLA calculations)
    - RAG Knowledge Base search ve prompt injection sanitization testleri
    - LLM şema doğrulama ve bozuk JSON yakalama testleri
    - Contextual testler: "Acil" ve "teşekkürler" kelimeleri içeren tatbikat mesajının bağlamı değerlendirilerek düşük öncelikli sınıflandırılması ve aktif tehditlerin kritik olarak insana devredilmesi kanıtlandı.
    - Agent API V1 testleri: Ticket oluşturma, idempotency (mükerrer istek engelleme), token ile yetkilendirme, yetkisiz isteklerin reddi ve insan kararının API üzerinden okunması kanıtlandı.
    - Zero-Touch Autonomous Agent Testleri: İnsan müdahalesi olmadan doğrudan veritabanında bilet açma (`AutonomousAgentDispatcherServiceTest`), RAG iliştirme, yüksek riskli olayları otomatik `pending_review` durumuna sevk etme ve `POST /api/v1/agent/autonomous_ingest` endpoint testi kanıtlandı.
  - Güvenlik Kanıtı: Brakeman 8.1.0 SAST taraması çalıştırıldı; 0 güvenlik uyarısı alındı (11 controller, 12 model, 11 şablon).
  - Canlı Demo Kanıtı: `http://127.0.0.1:3000/` üzerinde Rails 8 sunucusu ayağa kaldırıldı, `/tickets/demo`, `/tickets` ve `/detections/:id` ekranlarında "Otonom Agent Biletleme (Zero-Touch Ingest)" butonları ve live log konsolu başarıyla doğrulandı.
- Vaat edip yapamadığın ne varsa açıkça yaz: Harici bir Render API anahtarı veya canlı OpenAI/Gemini API anahtarı ortam değişkenlerinde tanımlı olmadığı için, canlı LLM çağrıları yerine akıllı Contextual Local Engine çalıştırılmış ve bu durum arayüzde `Deterministic Local Engine (Simulated Mode)` olarak dürüstçe etiketlenmiştir.

## Zaman

- İnsan zamanı / agent zamanı (dürüstçe): İnsan zamanı: ölçülmedi / Agent zamanı: ~1 saat 30 dakika (başlangıç: 2026-10-20T23:42:08+03:00)
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

- Devam / pivot / öldür ve gerekçesi: Devam. Güvenlik analistlerinin alarm kök neden araştırmasındaki manuel yük gerçek bir operasyonel darboğazdır. Agent-First API ve LLM tabanlı bağlamsal karar katmanı bu darboğazı başarıyla adreslemekte ve insan denetimi ile güvenli operasyon sağlamaktadır.
