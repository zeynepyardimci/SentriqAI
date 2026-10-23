# Sentriq AI - Autonomous SOC Copilot & Incident Triage Platform

Sentriq AI, güvenlik operasyon merkezlerinde (SOC Seviye 1/2) çalışan analistlerin ve harici yazılım agent'larının (SOAR, botlar, SIEM webhook'ları) güvenlik tespitlerini hızla araştırmasını, telemetriyi ebeveyn-çocuk işlem ağaçlarıyla korele etmesini ve RAG destekli iç runbook'lar üzerinden bağlamsal kararlar üretmesini sağlayan yapay zekâ destekli bir olay inceleme platformudur.

> **Önemli Bağımsızlık Uyarısı (Disclaimer):**  
> Sentriq AI bağımsız bir araştırma ve mühendislik prototipidir. CrowdStrike veya Falcon ile herhangi bir kurumsal bağlantısı, ortaklığı, onayı veya sponsorluğu **bulunmamaktadır**. CrowdStrike Falcon yalnızca modern EDR süreç ağacı ve telemetri triaj akışları açısından ilham kaynağı olarak anılmıştır.

---

## 1. Çözülen Kullanıcı Acısı (Pain Point) ve Araştırma Kaynağı

- **Hedef Kullanıcı:** SOC (Security Operations Center) Seviye 1 Güvenlik Analisti.
- **Problem:** Yanlış pozitif ve düşük öncelikli alarmların analistlerin zamanını tüketmesi, alarmların neden önemli olduğunun anlaşılmasının zaman alması ve müdahale kararlarının yeterli bağlam olmadan verilmesi.
- **Doğrulanmış Gerçek Kaynak:**  
  [G2 CrowdStrike Falcon Endpoint Protection Platform Reviews (Sayfa 17 Pros and Cons)](https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews?page=17&qs=pros-and-cons)  
  *Kullanıcı Yorumu Bulgusu:* Platformun genel tehdit tespit gücüne rağmen yanlış pozitif (false-positive) alarmların analistlerin mesailerinde ciddi bir triyaj yükü yarattığı; işaretlenen bir davranışın zararlı mı yoksa meşru bir iç uygulama mı olduğunu teyit etmek için güvenlik analistlerinin değerli zamanlarını ve yoğun manuel çabalarını harcamak zorunda kaldığı açıkça belirtilmiştir.
- **Ürünün Yeni Vaadi:**  
  > *"Sentriq AI, güvenlik alarmlarını yalnızca biletlemez; kanıtları ve ilgili müdahale prosedürünü değerlendirerek gerekçeli bir triyaj kararı üretir, sonraki adımı önerir ve riskli müdahaleleri insan onayına bırakır."*

Ayrıntılı doğrulama notları ve araştırma raporu için: [`docs/PAIN_POINT_RESEARCH.md`](docs/PAIN_POINT_RESEARCH.md).

---

## 2. Ana Mimarî ve Teknolojiler

- **Backend:** Ruby on Rails 8.1.4, Ruby 3.4.7
- **Veritabanı:** PostgreSQL 16 + pgvector uzantısı
- **Frontend:** Vanilla CSS (Dark SOC Theme: Slate `#0B0F19`, Glowing Cyan `#06B6D4`, Violet `#8B5CF6`), Hotwire / Turbo (Frameworksüz saf CSS)
- **Web Sunucusu:** Puma 8.0.2 / Thruster
- **AI / LLM Sağlayıcısı:** Değiştirilebilir çoklu sağlayıcı mimarisi:
  - xAI Grok API (`GROK_API_KEY` / `XAI_API_KEY`)
  - Groq Llama 3.3 70B (`GROQ_API_KEY`)
  - OpenAI (`OPENAI_API_KEY`)
  - Google Gemini (`GEMINI_API_KEY`)
  - **Sentriq Contextual Local Engine:** Harici anahtar tanımlı olmadığında veya API hatasında şeffaf fallback devreye girer (`simulated_local` etiketiyle dürüstçe gösterilir).
- **Güvenlik:** Brakeman SAST (0 güvenlik uyarısı), CSRF/XSS koruması, token bazlı agent yetkilendirmesi, prompt injection arındırma katmanı.

---

## 3. Agent-First REST API V1

Harici otomasyon yazılımları ve agent'lar UI kullanmadan belgelenmiş REST API üzerinden tüm güvenlik döngüsünü yürütebilir.

### Yetkilendirme
Tüm API isteklerinde `Authorization: Bearer <demo_token>` veya `X-Agent-Token: <demo_token>` başlığı gereklidir.  
Demo Token Örneği: `demo-analyst-token-01` (veya `demo-lead-token-42`).

### 3.1. Ticket Oluşturma (Idempotent)
`POST /api/v1/tickets`

**İstek Başlıkları:**
```http
Authorization: Bearer demo-analyst-token-01
Idempotency-Key: soar-agent-req-991204
Content-Type: application/json
```

**İstek Gövdesi:**
```json
{
  "title": "Suspicious Encoded PowerShell Spawned by winword.exe",
  "description": "Base64 payload execution observed on WKSTN-FIN-089",
  "priority": "high",
  "detection_id": 1,
  "assigned_agent": "CrowdPulse-SOAR-Agent"
}
```

**Yanıt (HTTP 201 Created):**
```json
{
  "id": 6,
  "ticket_number": "SQT-2026-725934",
  "title": "Suspicious Encoded PowerShell Spawned by winword.exe",
  "status": "open",
  "priority": "high",
  "assigned_agent": "CrowdPulse-SOAR-Agent",
  "idempotency_key": "soar-agent-req-991204",
  "detection_id": 1,
  "created_at": "2026-10-20T22:24:09Z"
}
```

### 3.2. LLM Bağlamsal Analiz ve RAG Kararı
`POST /api/v1/tickets/:id/analyze`

**Yanıt (HTTP 200 OK):**
```json
{
  "ticket_id": 6,
  "ticket_number": "SQT-2026-725934",
  "status": "pending_review",
  "llm_analysis": {
    "intent": "active_threat_containment",
    "priority": "critical",
    "recommended_action": "Perform host network containment and inspect parent-child process telemetry",
    "rationale": "Aktif bir uç nokta tespiti veya şüpheli ikili/komut satırı yürütmesi tespit edildi. Sistem bütünlüğünü korumak için Seviye 2 analist doğrulaması gereklidir.",
    "confidence": 88,
    "requires_human_review": true,
    "source_refs": [
      {
        "document_id": 1,
        "document_title": "RB-0105: Obfuscated PowerShell Execution & LOLBins",
        "category": "runbook",
        "quote": "Adversaries frequently leverage PowerShell to execute malicious code, bypass execution policies, and download second-stage payloads...",
        "relevance_explanation": "Ticket bağlamında geçen süreçler ve saldırı teknikleri 'RB-0105' prosedürüyle eşleşmektedir."
      }
    ]
  },
  "agent_mode": "simulated_local"
}
```

### 3.3. İnsan Analist Kararını Sorgulama
`GET /api/v1/tickets/:id/human_decision`

**Yanıt (HTTP 200 OK):**
```json
{
  "ticket_id": 6,
  "ticket_number": "SQT-2026-725934",
  "status": "resolved",
  "human_decision": "approved",
  "human_decision_notes": "Verified malicious macro, containment executed.",
  "human_reviewer": {
    "id": 1,
    "name": "Elena Vance",
    "role": "lead_analyst"
  },
  "human_reviewed_at": "2026-10-20T22:25:07Z"
}
```

### 3.4. Sıfır İnsan Müdahalesi: Otonom Agent Ingestion API
`POST /api/v1/agent/autonomous_ingest`

İnsan analistin form doldurmasına veya arayüz kullanmasına gerek kalmadan, harici bir SOAR botu, EDR telemetri kuyruğu veya cron job bu endpoint'i çağırarak tespit edilen olayı **doğrudan biletletir, LLM ile bağlamsal triage yaptırır ve RAG runbook'larını bağlatır**:

**İstek (Header: Authorization: Bearer <TOKEN>):**
```json
{
  "detection_id": 3,
  "all_unhandled": false
}
```

**Yanıt (HTTP 200 OK):**
```json
{
  "success": true,
  "message": "Autonomous agent completed zero-touch triage for 1 event(s).",
  "processed_count": 1,
  "results": [
    {
      "ticket_id": 9,
      "ticket_number": "SQT-2026-881234",
      "title": "🤖 [Zero-Touch Alert] Volume Shadow Copies Deletion via vssadmin",
      "status": "pending_review",
      "priority": "critical",
      "outcome": "pending_review",
      "intent": "active_threat_containment",
      "confidence": 92,
      "recommended_action": "Perform host network containment and inspect parent-child process telemetry",
      "requires_human_review": true
    }
  ],
  "logs": [
    "[17:40:01] [SENSOR] Incoming telemetry alert detected from endpoint: WIN-FINANCE-01",
    "[17:40:02] [AGENT] Ticket SQT-2026-881234 autonomously opened in database with ZERO human intervention (Priority: critical).",
    "[17:40:03] [LLM] Invoking Contextual Analysis Engine (Intent: active_threat_containment)...",
    "[17:40:03] [RAG] RAG runbook search attached 1 verified document(s): RB-0201: Ransomware Rapid Containment.",
    "[17:40:04] [HANDOVER] High-risk action required. Autonomous Agent shifted ticket to 'pending_review' with safety lock."
  ]
}
```

### 3.5. Diğer API Endpoint'leri
- `GET /api/v1/tickets/:id`: Ticket ayrıntılarını, telemetriyi ve not geçmişini okuma.
- `POST /api/v1/tickets/:id/notes`: Ticket'a agent bulgusu veya taslak yanıt ekleme.
- `POST /api/v1/tickets/:id/escalate`: İnsan analiste devretme (`pending_review`).
- `GET /api/v1/detections`: Sentetik tespitleri ve kanıtlarını filtreleme.
- `GET /api/v1/knowledge_base/search?query=powershell`: RAG bilgi tabanında arama yapma.

---

## 4. LLM Tabanlı Bağlamsal Karar Motoru (Contextual Intelligence)

Sentriq AI, yüzeysel anahtar kelime eşleştirmesi (`"acil"`, `"teşekkür"`, `"kritik"`) **kullanmaz**. Cümlenin ve olayın tüm anlamsal bağlamını analiz eder:
1. **Rutin Tatbikat / Retrospektif:** İçerikte "acil" kelimesi geçse dahi ("Dünkü acil durum tatbikatı tamamlandı, teşekkürler"), LLM bunu rutin tatbikat olarak algılar (`informational_retrospective`, Düşük öncelik, insana devir gerekmez).
2. **Aktif Saldırı:** "Acil" kelimesi geçmese bile arka planda gizli PowerShell veya LOLBin indirimi varsa, LLM bunu aktif tehdit olarak algılar (`active_threat_containment`, Kritik öncelik, insana devir zorunlu).
3. **Belirsizlik & Çelişki:** Çelişkili ifadelerde ("emin değilim, kural istisnası") sistem varsayım üretmez, doğrudan `pending_review` akışına devreder.
### 4.1. LLM Sağlayıcıları (Grok xAI, OpenAI, Gemini & Yerel Motor)
Sentriq AI çoklu LLM sağlayıcı mimarisini destekler:
- **xAI Grok API:** `.env` dosyasına `GROK_API_KEY=xai-...` tanımlandığında sistem doğrudan `https://api.x.ai/v1/chat/completions` üzerinden `grok-2-latest` modelini kullanır.
- **OpenAI:** `OPENAI_API_KEY=sk-...` tanımlandığında `gpt-4o-mini` modelini kullanır.
- **Google Gemini:** `GEMINI_API_KEY=AIza...` tanımlandığında `gemini-1.5-flash` modelini kullanır.
- **Deterministik Bağlamsal Yerel Motor:** Harici API anahtarı verilmediğinde sistem otomatik olarak akıllı yerel motoru çalıştırır ve raporları şeffafça `Contextual Local Engine (Simulated Mode)` olarak etiketler.

---

## 5. Yerel Kurulum ve Çalıştırma

### Gereksinimler
- Ruby 3.4+
- Rails 8.1.4+
- PostgreSQL 16 (veya Docker)

### Adımlar

1. **Bağımlılıkları Kurun:**
   ```bash
   bundle install
   ```

2. **Veritabanını Başlatın (Docker ile PostgreSQL 16 + pgvector):**
   ```bash
   docker run -d --name sentriq_postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -p 5434:5432 pgvector/pgvector:pg16
   ```

3. **Veritabanını Hazırlayın ve Sentetik Verileri Yükleyin:**
   ```bash
   ruby bin/rails db:prepare
   ruby bin/rails db:seed
   ```

4. **Testleri Çalıştırın (56 test, 295 assertion, 0 hata, 0 başarısızlık):**
   ```bash
   bundle exec rails test
   ```

5. **SLA Kontrol Görevini Çalıştırın:**
   ```bash
   bundle exec rake sentriq:check_sla
   ```

6. **Güvenlik Taramasını Çalıştırın (Brakeman SAST - 0 uyarı):**
   ```bash
   bundle exec brakeman -q
   ```

7. **Sunucuyu Başlatın:**
   ```bash
   bundle exec rails server -b 127.0.0.1 -p 3000
   ```
   Tarayıcınızda açın: `http://127.0.0.1:3000/`

---

## 6. Canlı Demo ve Etkileşim Adımları

### 6.1. Terminal Üzerinden Agent-First API Çağrısı (cURL Örneği)
Arayüze hiç dokunmadan güvenlik ajanının olay oluşturması ve triyaj kararı alması:

```bash
curl -X POST http://127.0.0.1:3000/api/v1/tickets \
  -H "Authorization: Bearer test-valid-agent-token-12345" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: soar-demo-event-001" \
  -d '{
    "title": "Volume Shadow Copy Deletion via vssadmin",
    "description": "vssadmin.exe delete shadows /all /quiet executed on WKSTN-SRV-01",
    "priority": "critical",
    "auto_triage": true
  }'
```

**Dönen Yapılandırılmış Karar:**
- `severity`: `"critical"`
- `classification`: `"active_threat_containment"`
- `confidence`: `88` (`confidence_note` ile model sezgisel puanı olduğu vurgulanır)
- `requires_human_approval`: `true` (Cihaz izolasyonu gibi yıkıcı aksiyonlar insan onayı olmadan çalışmaz)
- `matched_runbook`: Eşleşen gerçek doküman veya `"No matching runbook found in knowledge base"`
- Bilet durumu otomatik olarak `pending_review` (insan onayı bekliyor) olarak veritabanına işlenir.

### 6.2. Web Arayüzünde Doğrulama
1. **Bilet Listesi (`/tickets`):** API üzerinden açılan biletin listeye anında yansıdığını ve durumunun `pending_review` olduğunu görün.
2. **Bilet İnceleme & Onay (`/tickets/:id`):** Olay özetini, LLM kararını ve runbook eşleşmesini inceleyin; "Karantinaya Al (Simüle İzolasyon)" veya onay butonuna tıklayın.
3. **Denetim İzi (Audit Log):** Onay sonrasında denetim kaydına `simulated_host_isolation_executed` kaydının işlendiğini ve durumun `resolved` olduğunu görün.
4. **SLA Süresi ve Eskalasyon:** Belirlenen SLA süresi (15 dk) aşıldığında sistemin olayı `escalation_required` / `pending_review` durumuna geçirdiğini doğrulayın.

---

## 7. Dağıtım (Production Deployment)

Uygulama Docker ve Render için tam uyumludur:
- `Dockerfile`: Multi-stage, jemalloc optimizasyonlu, non-root `rails` kullanıcısı ile çalışır.
- `render.yaml`: Tek tıkla Render Blueprint ile PostgreSQL ve Web servisi kurar (Sağlık kontrolü: `/up`).
- `bin/docker-entrypoint`: Otomatik migration ve seed akışı içerir.

---

## 8. Bilinen Eksikler ve Yapamadıklarım

- **Canlı Public Bulut URL'si:** Kullanıcı tarafından harici bir Render API anahtarı veya canlı sunucu ortamı atanmadığı için uygulama genel internetteki canlı bir Render URL'si yerine yerel sunucu (`http://127.0.0.1:3000`) ve Docker ortamında uçtan uca doğrulanmıştır. `render.yaml` ve `Dockerfile` üretime hazır teslim edilmiştir.
- **Canlı LLM Anahtarı:** Ortam değişkenlerinde harici bir `GROQ_API_KEY` veya `OPENAI_API_KEY` tanımlı olmadığı geliştirme anlarında Sentriq Contextual Local Engine devreye girmekte ve arayüzde şeffafça simüle mod etiketi gösterilmektedir.
- **Gerçek Cihaz İzolasyonu:** Güvenlik ve sistem bütünlüğü kuralları gereği, gerçek endpoint ajanlarına yıkıcı komut gönderilmemekte, insan onayı sonrasında `simulated_host_isolation` aksiyonu kaydedilmektedir.

---

## 9. GitHub Actions Test Durumu

- CI İş Akışı: `.github/workflows/ci.yml` (Brakeman SAST, RuboCop, Rails Unit/Integration testleri).
- Yerel Test Başarısı: **56 test, 295 assertion, 0 hata, 0 başarısızlık (%100 Başarı)**.

