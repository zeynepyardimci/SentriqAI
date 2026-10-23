# AGENT.md — Sentriq AI Autonomous SOC Engineering Instructions

Bu belge, Sentriq AI projesinde çalışan yapay zekâ geliştirme ajanları, otonom yazılım agent'ları ve mühendisler için proje mimarisini, çalıştırma yönergelerini, test standartlarını ve kritik güvenlik sınırlarını tanımlar.

---

## 1. Proje Özeti ve Amacı

- **Proje Adı:** Sentriq AI
- **Sektörel İlham:** CrowdStrike Falcon (Süreç ağacı, telemetri korelasyonu ve analist triyaj iş akışı)
- **Hedef Kullanıcı:** SOC (Security Operations Center) Seviye 1 Güvenlik Analistleri.
- **Çözülen Problem:** Yanlış pozitif ve düşük öncelikli alarmların analistlerin zamanını tüketmesi, alarmların neden önemli olduğunun anlaşılmasının zaman alması ve müdahale kararlarının yeterli bağlam olmadan verilmesi.
- **Ürün Vaadi:** *"Sentriq AI, güvenlik alarmlarını yalnızca biletlemez; kanıtları ve ilgili müdahale prosedürünü değerlendirerek gerekçeli bir triyaj kararı üretir, sonraki adımı önerir ve riskli müdahaleleri insan onayına bırakır."*

---

## 2. Teknoloji Yığını ve Proje Yapısı

### 2.1. Temel Bileşenler
- **Backend Çatısı:** Ruby on Rails 8.1.4 (Ruby 3.4.7)
- **Veritabanı:** PostgreSQL 16 + `pgvector` eklentisi
- **Frontend:** Vanilla CSS (Dark SOC Theme), Hotwire / Turbo (Tailwind kullanılmaz)
- **Web Sunucusu:** Puma 8.0.2 / Thruster
- **LLM Entegrasyonları:**
  - xAI Grok API (`GROK_API_KEY` / `XAI_API_KEY`)
  - Groq Llama 3.3 70B (`GROQ_API_KEY`)
  - OpenAI (`OPENAI_API_KEY`)
  - Google Gemini (`GEMINI_API_KEY`)
  - Sentriq Contextual Local Engine (API anahtarı bulunmadığında otomatik deterministik fallback)
- **RAG Altyapısı:** Ragie.ai API (`RAGIE_API_KEY`) ve yerel PostgreSQL tabanlı RAG araması (`SearchKnowledgeBaseService`)

### 2.2. Dizin Mimarisi
```
app/
├── controllers/
│   ├── api/v1/                   # Agent-first REST API controller'ları
│   │   ├── base_controller.rb   # Token tabanlı auth & hata yakalama
│   │   ├── tickets_controller.rb# Ticket CRUD, LLM triyaj, HITL endpoint'leri
│   │   ├── autonomous_agents_controller.rb # Sıfır insan müdahaleli ingest
│   │   └── detections_controller.rb
│   ├── detections_controller.rb # Web UI tespit listesi & detayları
│   ├── tickets_controller.rb    # Web UI bilet yönetimi & onay akışı
│   └── page_agent_controller.rb # In-page agent widget endpoint'leri
├── models/
│   ├── detection.rb             # EDR tespiti, durum makinesi, SLA kontrolleri
│   ├── ticket.rb                # Güvenlik bileti, durum geçişleri, HITL kararı
│   ├── evidence.rb              # Süreç, komut satırı, ağ telemetri kanıtları
│   ├── knowledge_document.rb    # Dahili SOC runbook ve prosedür dokümanları
│   ├── audit_event.rb           # Değiştirilemez denetim izi (audit log)
│   └── user.rb                  # Analistler ve API agent kullanıcıları
├── services/
│   ├── ticket_contextual_analyzer_service.rb # Canlı LLM çağrısı & schema kontrolü
│   ├── contextual_analysis_engine.rb         # Deterministik bağlamsal analiz motoru
│   ├── ticket_analysis_schema_validator.rb   # LLM çıktı doğrulama
│   ├── ragie_retrieval_service.rb            # RAG runbook eşleştirme
│   └── search_knowledge_base_service.rb     # Local RAG & prompt injection sanitization
├── jobs/
│   └── check_sla_job.rb         # Süresi dolan kritik alarmları eskalasyon job'ı
└── views/
    ├── shared/_page_agent.html.erb # In-page agent HUD bileşeni
    ├── detections/
    └── tickets/
lib/tasks/
└── sentriq_sla.rake             # SLA kontrolü için çalıştırılabilir Rake task'ı
```

---

## 3. Çalıştırma ve Geliştirme Komutları

### 3.1. Bağımlılıklar ve Veritabanı
```powershell
# Ruby bağımlılıklarını kurma
bundle install

# Veritabanını hazırlama (PostgreSQL 16)
bundle exec rails db:prepare

# Sentetik demo verilerini ve kurumsal runbook'ları yükleme
bundle exec rails db:seed
```

### 3.2. Sunucuyu Başlatma
```powershell
# Rails yerel geliştirme sunucusunu başlatma
bundle exec rails server -b 127.0.0.1 -p 3000
```
Uygulamaya tarayıcıdan erişim: `http://127.0.0.1:3000/`

### 3.3. SLA Kontrolünü Çalıştırma
```powershell
# Zaman aşımına uğrayan alarmları kontrol etme ve eskalasyona alma
bundle exec rake sentriq:check_sla
```

---

## 4. Test Standartları ve Komutları

### 4.1. Testlerin Çalıştırılması
```powershell
# Tüm test paketini çalıştırma
bundle exec rails test

# Belirli bir test dosyasını çalıştırma
bundle exec rails test test/controllers/api/v1/tickets_controller_test.rb
bundle exec rails test test/models/ticket_test.rb
bundle exec rails test test/services/ticket_contextual_analyzer_service_test.rb
```

### 4.2. Güvenlik Taraması (SAST)
```powershell
# Brakeman güvenlik denetimi (0 uyarı hedeflenir)
bundle exec brakeman -q
```

### 4.3. Test Kuralları
1. **Determinizm:** Testler harici ağ çağrılarına (OpenAI/Groq/Grok) bağımlı olmamalıdır. Birim ve entegrasyon testlerinde mock veya Contextual Local Engine kullanılmalıdır.
2. **Zaman Yolculuğu:** SLA gecikme testlerinde Rails'in `travel_to` mekanizması kullanılmalıdır.
3. **Şema Doğrulaması:** LLM çıktılarının doğrulanabilir JSON şemasına uyduğu her testte assert edilmelidir.

---

## 5. Mimari Sınırlar ve Kritik Güvenlik Kuralları

1. **İnsan Onayı (Human-in-the-Loop) Zorunluluğu:**
   - Yüksek veya kritik öncelikli tehditlerde (`priority: high|critical`) veya cihaz izolasyonu gibi riskli aksiyonlarda hiçbir otonom agent veya LLM **tek başına doğrudan sistem komutu yürütemez**.
   - Bilet `pending_review` durumuna geçirilmeli ve insan analist onayı alınmalıdır.
   - Onay sonrası yalnızca simüle edilmiş aksiyon (`simulated_host_isolation`) kaydedilmelidir. Gerçek sistemlere yıkıcı komut gönderilmez.

2. **Gizli Bilgilerin ve API Anahtarlarının Korunması:**
   - Hiçbir API anahtarı (`GROK_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `RAGIE_API_KEY`, veritabanı şifreleri) repoya commit edilmemelidir.
   - `config/initializers/filter_parameter_logging.rb` içerisinde token, api_key, authorization başlıkları filtrelenmelidir.
   - Log dosyalarına veya API yanıtlarına hassas anahtarlar yazdırılamaz.

3. **Kaynak Doğruluğu ve Halüsinasyon Yasağı:**
   - Bilgi tabanında ilgili runbook bulunamazsa açıkça `"No matching runbook found in knowledge base"` belirtilmelidir; yapay doküman uydurulamaz.
   - LLM güven skoru (`confidence`), aktüeryal bir başarı olasılığı olarak değil, model sezgisel puanı olarak etiketlenmelidir (`confidence_note`).
   - Modelin kendi ifadeleri kanıt sayılamaz; kanıt yalnızca girdideki somut telemetriden (`process_name`, `command_line`, `hash`, `ip`) derlenmelidir.

4. **Bağlamsal Analiz (Keyword Trap Önleme):**
   - Karar mekanizmaları `"acil"`, `"tatbikat"`, `"teşekkür"` gibi izole kelimelerle manipüle edilemez; cümlenin ve olayın tüm bağlamı analiz edilir.
