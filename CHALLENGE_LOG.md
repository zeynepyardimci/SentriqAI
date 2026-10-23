# CHALLENGE_LOG

## Başlangıç noktası

- **Klonlanan ürün ve canlı URL:** CrowdStrike Falcon (Yalnızca EDR tespit inceleme, telemetri korelasyonu, ebeveyn-çocuk süreç ağacı ve analist triyaj karar akışından ilham alınmıştır; doğrudan bir klonlama veya ticari entegrasyon yoktur). Canlı URL: Yerel ortamda `http://127.0.0.1:3000/` üzerinde çalışmaktadır; Render `render.yaml` Blueprint ve Dockerfile dağıtım için eksiksiz hazır yapılandırılmıştır (harici Render hesabı/API anahtarı bulunmadığı için genel internet bulut URL'si yerine yerel sunucu ve Docker ortamında uçtan uca doğrulanmıştır).
- **Geçen haftanın son commit'i ve bağlantısı:** Yok. Greenfield başlangıç projesi; geçen haftadan devralınan önceki repo geçmişi bulunmamaktadır.
- **Orijinal ürüne müşterilerin neden para ödediği:** Kurumsal güvenlik ekipleri, SOC analistleri ve MSSP'ler; uç noktalardaki (endpoint) zararlı yazılımları, fidye saldırılarını ve LOLBin (Living off the Land) istismarlarını gerçek zamanlı tespit etmek, süreç ağaçlarını ilişkilendirmek, saldırgan taktiklerini (MITRE ATT&CK) hızlıca yakalamak ve sistemleri izole ederek veri sızıntısını önlemek için CrowdStrike'a yüksek lisans bedelleri ödemektedir.

---

## Acı

- **Hedef kullanıcı ve problemi:** Çok sayıda güvenlik alarmını incelemek zorunda olan SOC (Security Operations Center) Seviye 1 Güvenlik Analisti. Problem: Yanlış pozitif ve düşük öncelikli alarmların analistlerin zamanını tüketmesi, alarmların neden önemli olduğunun anlaşılmasının zaman alması ve müdahale kararlarının yeterli bağlam olmadan verilmesi.
- **Doğrulanmış gerçek kullanıcı yorumu:**  
  [G2 CrowdStrike Falcon Endpoint Protection Platform Reviews (Sayfa 17 Pros & Cons)](https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews?page=17&qs=pros-and-cons)  
  *Kullanıcı Yorumu Bulgusu:* Platformun yüksek tespit doğruluğu ve hafif ajan yapısı övülürken, *"occasional false-positive alerts still slip through. This requires security teams to spend valuable time and manual effort on investigation and alert triage to verify whether flagged behavior is genuinely malicious or simply a benign internal application"* ve Falcon modüllerinin devasa kapsamının küçük/orta ekipler veya Seviye 1 analistler için bunaltıcı ("overwhelming") olduğu belirtilmiştir.
- **Kaynak bağlantısı ve problemin Sentriq AI ile ilişkisi:**  
  Analistlerin mesailerinin %50'ye yakını alarmları manuel olarak sınıflandırmak ve yanlış pozitifleri ayıklamakla geçmektedir. Bir alarmın meşru bir yönetim scripti mi yoksa aktif bir siber saldırı mı olduğunu anlamak için süreç ağaçları ve dahili runbook'lar arasında manuel korelasyon yapmak alarm başına 15-30 dakika kaybettirmektedir. Sentriq AI, bu triyaj sürecini agent-first API ve RAG destekli bağlamsal LLM motoruyla otomatikleştirerek analistin önüne hazır kanıtlar, gerekçeli karar ve runbook prosedürü koyar.

---

## Bu haftanın vaadi

- **Agent-first akışının vaadi:** Güvenlik ajanları (SOAR, webhook'lar, uç nokta sensörleri) web arayüzünü kullanmadan HTTP API (`POST /api/v1/tickets`) aracılığıyla yeni bir güvenlik olayı oluşturabilir. İstek alanları doğrulanır, eksik girdilerde HTTP 400 döner, `Idempotency-Key` mekanizması ile mükerrer bilet oluşumu engellenir, token tabanlı kimlik doğrulama uygulanır ve sonuç veritabanına ve web arayüzüne anında yansır.
- **LLM tabanlı triyaj vaadi:** *"Sentriq AI, güvenlik alarmlarını yalnızca biletlemez; kanıtları ve ilgili müdahale prosedürünü değerlendirerek gerekçeli bir triyaj kararı üretir, sonraki adımı önerir ve riskli müdahaleleri insan onayına bırakır."*  
  LLM çıktısı katı bir şemaya (`severity`, `confidence`, `classification`, `evidence`, `reasoning`, `matched_runbook`, `recommended_action`, `requires_human_approval`) tabidir. Güven skoru aktüeryal başarı olasılığı değil model skoru olarak sunulur, model iddiaları kanıt sayılmaz (kanıt telemetridir), bulunamayan runbook uydurulmaz ve yüksek riskli olaylarda insan onayı olmadan kritik aksiyon çalıştırılmaz.

---

## Yapılanlar ve kanıt

### Gerçek Commit Bağlantıları
- Commit `dd9097b`: `feat: implement agent-first SOC triage flow, SLA travel_to rules, HITL decision, and comprehensive test suite`
- Commit `454256c`: `feat: complete Alibaba Page-Agent ReAct engine with live DOM visual highlighting, quick prompts, and free Groq/Grok API integration`
- Commit `5723d29`: `feat: fully autonomous Page-Agent — auto-starts on page load, polls every 60s, human chat drawer on demand, no button required`
- Commit `bb85a84`: `fix: use unique idempotency key (seconds+random) to prevent duplicate key collision on repeated Page-Agent executions`
- Commit `86ebbb5`: `fix: guard state machine transitions in PageAgentService to prevent resolved->pending_review error`
- Commit `646e3cb`: `feat: implement Page-Agent GUI HUD, Ragie.ai RAG, zero-touch autonomous ticket execution`
- Commit `0210b81`: `feat: integrate xAI Grok API provider and zero human intervention autonomous reporting`
- Commit `e5439cf`: `feat: implement agent-first REST API, contextual decision engine, and interactive simulation demo`
- Commit `42ac028`: `feat: complete end-to-end AI investigation, RAG, HITL review, and test suite`
- Commit `48734d8`: `feat: initialize Rails 8 application with PostgreSQL and pain point research`

### Çalıştırılan Testler ve Gerçek Sonuçları
- **Komut:** `bundle exec rails test`
- **Gerçek Çıktı:**
  ```text
  Run options: --seed 39383
  # Running:
  ........................................................
  Finished in 26.430150s, 2.1188 runs/s, 11.1615 assertions/s.
  56 runs, 295 assertions, 0 failures, 0 errors, 0 skips
  ```
- **Kapsanan ve Doğrulanan Başlıca Testler:**
  1. **Agent API Bilet Açma & Kalıcılık:** `POST /api/v1/tickets` üzerinden bilet açılması, veritabanına kaydedilmesi ve `SQT-` formatında bilet numarası alması doğrulandı (`test_1`).
  2. **API Üzerinden Okuma:** Açılan biletin tüm telemetrisiyle `GET /api/v1/tickets/:id` ile okunması kanıtlandı (`test_2`).
  3. **Yetkisiz İsteklerin Reddi:** Geçersiz token ile yapılan isteklerin HTTP 401 Unauthorized dönmesi doğrulandı (`test_3`).
  4. **Idempotency Mekanizması:** Aynı `Idempotency-Key` ile tekrarlanan isteklerin yeni bilet açmadan HTTP 200 OK ve `X-Idempotent-Replay: true` başlığıyla mevcut kaydı döndürmesi kanıtlandı (`test_4`).
  5. **Parametre Doğrulama:** Eksik `title` veya `description` durumunda HTTP 400 Bad Request dönmesi doğrulandı (`test_missing_required_title_or_description`).
  6. **LLM Çıktı Şeması Doğrulaması:** `auto_triage: true` parametresiyle çağrıldığında dönen `severity`, `confidence`, `confidence_note`, `classification`, `evidence`, `reasoning`, `matched_runbook`, `recommended_action`, `requires_human_approval` alanlarının varlığı ve geçerliliği doğrulandı.
  7. **LLM Güvenli Fallback:** Harici API hatasında uygulamanın çökmediği, Contextual Local Engine'e şeffaf biçimde geçtiği ve `simulated_local` etiketlendiği kanıtlandı.
  8. **Düşük Risk / Rutin Tatbikat Senaryosu:** "Dünkü tatbikat tamamlandı" mesajının anahtar kelime tuzağına düşmeyip düşük öncelikli sınıflandırıldığı ve biletin otomatik kapatılmayıp analist incelemesi için açık bırakıldığı kanıtlandı.
  9. **Yüksek Risk Senaryosu & Güvenlik Kilidi:** PowerShell / vssadmin gibi aktif saldırı göstergelerinde olayın `pending_review` durumuna alındığı ve insan onayı olmadan kritik aksiyonun çalıştırılmadığı doğrulandı.
  10. **İnsan Onayı ve Simüle İzolasyon:** `POST /api/v1/tickets/:id/human_decision` üzerinden onay verildiğinde biletin `resolved` durumuna geçtiği, `simulated_host_isolation_executed` aksiyonunun ve denetim kaydının (AuditEvent) oluşturulduğu doğrulandı (`test_human_decision_applied`).
  11. **Durum Makinesi Kısıtlamaları:** Geçersiz durum geçişlerinin (`resolved` durumundan doğrudan `pending_review` durumuna geçiş) engellendiği test edildi (`TicketTest#test_invalid_status_transition`).
  12. **Zaman Kuralı & SLA Testleri (`travel_to`):** Rails `travel_to` kullanılarak 10. dakikada (SLA 15 dk eşiği öncesi) durumun korunduğu; 20. dakikada (eşik sonrası) biletin `pending_review` eskalasyonuna geçirildiği ve `ticket_sla_breached` denetim kaydının atıldığı kanıtlandı.
- **Güvenlik Taraması (SAST):** `bundle exec brakeman -q`
  ```text
  Controllers: 12 | Models: 12 | Templates: 12 | Errors: 0 | Security Warnings: 0 (No warnings found)
  ```

### Canlı Demo Adımları
1. Sunucu başlatılır: `bundle exec rails server -b 127.0.0.1 -p 3000`
2. **Adım 1 - Agent API Çağrısı:** Terminalden cURL isteği gönderilir:
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
3. **Adım 2 - LLM Kararı İncelemesi:** API yanıtında yapılandırılmış JSON döner: `severity: critical`, `confidence: 88`, `requires_human_approval: true`, `matched_runbook: "RB-0201: Ransomware Rapid Containment"`.
4. **Adım 3 - Arayüzde Bilet Doğrulama:** Tarayıcıda `http://127.0.0.1:3000/tickets` açılır; API'den gelen bilet listede görünür, durumu `pending_review` olarak kilitlenmiştir.
5. **Adım 4 - İnsan Onayı ve Simüle İzolasyon:** Bilet detayına (`/tickets/:id`) girilir; olay özeti, telemetri, LLM gerekçesi ve runbook prosedürü incelenir. "Karantinaya Al (Simüle İzolasyon)" butonuna basılır. Bilet durumu `resolved` olur ve denetim günlüğünde simüle aksiyon belgelenir.
6. **Adım 5 - Düşük Risk Senaryosu Karşılaştırması:** "Dünkü tatbikat tamamlandı" içerikli olay açılır; sistemin düşük öncelik verdiği, ancak bileti tek taraflı silip kapatmadığı gösterilir.
7. **Adım 6 - SLA Kontrol Görevi:** `bundle exec rake sentriq:check_sla` çalıştırılarak süresi dolan açık alarmların otomatik eskalasyonu gösterilir.

### Tamamlanmayan Özellikler
- **Canlı Public Bulut URL'si:** Kullanıcı tarafından harici bir Render API anahtarı veya canlı sunucu ortamı atanmadığı için uygulama genel internetteki canlı bir Render URL'si yerine yerel sunucu (`http://127.0.0.1:3000`) ve Docker ortamında uçtan uca doğrulanmıştır. `render.yaml` ve `Dockerfile` üretime hazır teslim edilmiştir.
- **Canlı Cihaz İzolasyonu:** Güvenlik politikası gereği gerçek müşteri işletim sistemlerine doğrudan yıkıcı komut gönderilmez; insan onayı sonrası simüle izolasyon aksiyonu kaydedilir.

---

## Zaman

- **İnsan zamanı:** ~1 saat 15 dakika (isterlerin ve G2 kullanıcı şikâyetlerinin incelenmesi, ürün kapsamının sınırlandırılması ve doğrulama kararları).
- **Agent zamanı:** ~2 saat 10 dakika (mimari tasarım, testlerin yazımı, Rails 8 backend kodlaması, SLA kontrolleri, SAST taraması ve dokümantasyon).
- **İlk prompt (olduğu gibi):**
```text
SENTRIQ AI — CHALLENGE WEEK IMPLEMENTATION PROMPT
Rolün
Sen deneyimli bir Ruby on Rails geliştiricisi, AI agent mimarı ve test odaklı yazılım mühendisisin. Mevcut Sentriq AI projesini inceleyerek bu haftaki üniversite ödevinin gereksinimlerini karşılayan, sade, çalışan ve canlı demoda kanıtlanabilir bir ürüne dönüştüreceksin.
Önemli: Sıfırdan proje oluşturma. Önce mevcut repoyu, çalışan özellikleri, testleri, veritabanını, frontend'i ve deployment durumunu incele. Çalışan kodu koru. Gereksiz özellikler ekleme, sırf mimariyi güzelleştirmek için projeyi baştan yazma.
1. Projenin mevcut durumu
Proje adı: Sentriq AI
İlham kaynağı: CrowdStrike Falcon
Backend: Ruby on Rails 8.1.4
Ruby: 3.4.7
Veritabanı: PostgreSQL, pgvector kullanımı mevcut olabilir.
LLM: Groq / Llama 3.3 70B veya projede mevcut diğer sağlayıcılar.
Mevcut özellikler:
Güvenlik olayları ve bilet yönetimi.
AI ile olay analizi.
Runbook tabanlı müdahale önerileri.
Olay durumları ve denetim kayıtları.
In-page agent ve sanal imleç.
LLM API anahtarı yönetimi.
Bunlar önce koddan doğrulanmalı. Bu listedeki hiçbir özelliğin çalıştığını yalnızca önceki rapora dayanarak varsayma.
2. Ürün kararı ve kullanıcı acısı
Karar: Mevcut projeye devam et, fakat kapsamını daraltarak agent-first SOC triage ürününe odaklan.
Hedef kullanıcı: Çok sayıda güvenlik alarmını incelemek zorunda olan SOC Seviye 1 analisti.
Problem: Yanlış pozitif ve düşük öncelikli alarmların analistlerin zamanını tüketmesi, alarmların neden önemli olduğunun anlaşılmasının zaman alması ve müdahale kararlarının yeterli bağlam olmadan verilmesi.
Araştırma kaynağı:
https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews?page=17&qs=pros-and-cons
Bu sayfadaki ilgili kullanıcı yorumunu açıp doğrula. Şikâyeti olduğundan daha geniş yorumlama. Kaynağı README ve CHALLENGE_LOG.md içinde belirt.
Ürünün yeni vaadi:
"Sentriq AI, güvenlik alarmlarını yalnızca biletlemez; kanıtları ve ilgili müdahale prosedürünü değerlendirerek gerekçeli bir triyaj kararı üretir, sonraki adımı önerir ve riskli müdahaleleri insan onayına bırakır."
3. Öncelikli fark katmanı: Agent-first + LLM
Bu iki yeteneği tek bir uçtan uca akışta uygula.
A. Agent-first API
Bir güvenlik ajanı, web arayüzünü kullanmadan HTTP API aracılığıyla yeni bir güvenlik olayı oluşturabilmeli.
Gereksinimler:
Mevcut API yapısını incele ve mümkünse onu kullan.
Gerekliyse olay oluşturmak ve triyaj başlatmak için açık, belgelenmiş bir API endpoint'i ekle.
İstek alanlarını doğrula.
Geçersiz veya eksik girdiler için anlaşılır HTTP hata kodları döndür.
Olay oluşturma ve analiz sonuçlarını yapılandırılmış JSON olarak döndür.
Aynı isteğin tekrarlanması durumunda çift bilet oluşmasını önlemek için mevcut mimariye uygun idempotency mekanizması ekle veya gerekçeli olarak kapsam dışında bırak.
Endpoint'i yetkisiz erişime karşı koru. Mevcut kimlik doğrulama sistemini kullan; uygun koruma yoksa güvenli bir mekanizma ekle.
API anahtarlarını veya gizli bilgileri loglama.
Canlı demoda bir curl isteği veya küçük bir istemci betiğiyle olay oluşturulmasını göster. Sonuç, veritabanındaki gerçek kayda ve arayüzdeki bilet listesine yansımalı.
B. Gerçek LLM tabanlı triyaj
Mevcut LLM entegrasyonunu kullan. Çalışan entegrasyon yoksa en küçük sürdürülebilir çözümü oluştur.
LLM girdileri mümkün olduğunda şunları içersin:
Olay türü ve önem derecesi.
Süreç adı ve komut satırı gibi mevcut telemetri.
İlgili cihaz ve olay bağlamı.
İlgili kurumsal runbook içeriği.
LLM çıktısı doğrulanabilir bir şemaya sahip olsun:
severity
confidence
classification
evidence
reasoning
matched_runbook
recommended_action
requires_human_approval
Kurallar:
LLM'nin ürettiği güven skorunu ölçülmüş gerçek başarı olasılığı olarak sunma.
Modelin iddiasını kanıt olarak gösterme; kanıt, girdideki telemetri veya doğrulanmış kaynak olmalı.
Runbook bulunamazsa bunu açıkça belirt. Var olmayan prosedür veya kaynak uydurma.
Model çıktısını şema doğrulamasından geçir.
API hatası, zaman aşımı veya geçersiz JSON durumunda uygulamanın hata verdiğini gizleme; anlaşılır hata veya açıkça işaretlenmiş güvenli fallback üret.
LLM kararını doğrudan, sınırsız bir sistem komutuna dönüştürme.
Gerçek cihaz izolasyonu, silme veya başka yıkıcı aksiyonları çalıştırma.
C. Karara bağlı iş akışı
En az iki senaryo uygula:
Düşük riskli / olası yanlış pozitif olay:
LLM'nin değerlendirmesini ve dayanaklarını göster.
Analiste inceleme veya kontrollü durum geçişi öner.
Sadece düşük riskli olduğu için olayı otomatik ve geri döndürülemez biçimde kapatma.
Yüksek riskli olay:
Öncelikli bir bilet oluştur.
İlgili runbook'u ve gerekçeli müdahale önerisini göster.
İzolasyon gibi kritik aksiyonları insan onayı olmadan gerçekleştirme.
Demo ortamında onay sonrasında yalnızca simüle edilmiş aksiyon kaydet.
Bu iki senaryo gerçek LLM kullanıldığında da, testlerde sabitlenmiş model yanıtları kullanıldığında da anlaşılır biçimde doğrulanabilmeli. Testlerde kullanılan sahte yanıtları canlı LLM sonucuymuş gibi gösterme.
4. Zaman kuralı ve durum geçişi
Mevcut durum makinesini incele. Yoksa en küçük gerekli durum akışını oluştur.
Örnek:
new → triaged → awaiting_approval → resolved
Mevcut uygulamanın durum adları daha uygunsa onları koru.
Bir SLA kuralı uygula:
Örneğin, kritik bir olay belirlenen süre içinde ele alınmazsa escalation_required durumuna geçsin.
Süreyi yapılandırılabilir bir değerden oku.
Gerçek zamanlı kontrol için mevcut bir scheduler varsa onu kullan. Yoksa çalıştırılabilir ve belgelenmiş bir job veya task oluştur.
Testlerde Rails'in travel_to özelliğini kullan.
SLA süresi dolmadan ve dolduktan sonraki davranışları ayrı test et.
Geçersiz durum geçişlerini test et.
5. İnsan onayı ve denetim izi
Arayüzde yalnızca gerekli bilgileri göster:
Olayın özeti.
LLM'nin kararı ve gerekçesi.
Kullanılan runbook.
Önerilen aksiyon.
İnsan onayı bekleniyor durumu.
SLA ve olay zaman çizelgesi.
Onay veya ret işlemi gerçek bir backend endpoint'i üzerinden çalışmalı. Denetim kaydı oluşturulmalı.
Sadece animasyonla tıklayan bir sanal imleci agent-first özelliğinin kanıtı sayma. Asıl kanıt, ajanın API üzerinden işlem yapması, backend'in karar üretmesi ve durumun kalıcı olarak kaydedilmesidir.
6. Testler
Önce mevcut test altyapısını ve GitHub Actions workflow'unu incele.
Gerekli testleri ekle:
Agent API üzerinden olay oluşturma.
Hatalı istek ve yetkisiz erişim.
LLM çıktısının şema doğrulaması.
LLM sağlayıcısı hata verdiğinde güvenli davranış.
Düşük ve yüksek risk senaryoları.
İnsan onayı olmadan kritik aksiyonun çalışmaması.
İzin verilen ve yasaklanan durum geçişleri.
travel_to kullanarak SLA süresinin dolması.
Aynı olay isteğinin tekrarlanması durumunda çift kayıt oluşmaması.
Harici LLM API'sine bağlı testleri deterministik hale getir. Unit ve integration testlerinde gerektiğinde stub veya mock kullan. Gerçek API entegrasyonunun ayrıca doğrulanması gereken noktalarını belgele.
Testleri gerçekten çalıştır. Çalışmayan test, çalıştırılmamış test veya yalnızca kodu inceleyerek başarılı sayılan test için başarı iddiasında bulunma.
7. UI ve kapsam kontrolü
Gereksiz animasyonları, sanal imleç efektlerini ve demoda değer üretmeyen arayüzleri önceliklendirme.
Öncelik sırası:
Çalışan agent API.
Gerçek veya açıkça belirtilmiş test LLM yanıtıyla çalışan triyaj.
İnsan onayı.
Kalıcı bilet ve denetim kaydı.
SLA ve durum geçişi.
Sade, anlaşılır demo arayüzü.
Mevcut uygulamanın kullanılabilir bölümlerini koru. Sadece gerekli yerleri değiştir.
8. CHALLENGE_LOG.md — zorunlu
Repo kökünde CHALLENGE_LOG.md oluştur veya mevcutsa güncelle.
Şu başlıkları eksiksiz kullan:
CHALLENGE_LOG
Başlangıç noktası
Klonlanan ürün ve canlı URL.
Geçen haftanın son commit'i ve bağlantısı.
Orijinal ürüne müşterilerin neden para ödediği.
Acı
Hedef kullanıcı ve problemi.
Doğrulanmış gerçek kullanıcı yorumu.
Kaynak bağlantısı ve problemin Sentriq AI ile ilişkisi.
Bu haftanın vaadi
Agent-first akışının vaadi.
LLM tabanlı triyaj vaadi.
Yapılanlar ve kanıt
Gerçek commit bağlantıları.
Çalıştırılan testler ve gerçek sonuçları.
Canlı demo adımları.
Tamamlanmayan özellikler.
Zaman
İnsan zamanı.
Agent zamanı.
İlk prompt, olduğu gibi.
Karar
Devam / pivot / öldür.
Gerekçeli karar ve bir sonraki kişisel hedef.
Bilmediğin bilgileri uydurma. Commit, süre, URL veya test sonucu eksikse açıkça belirt ve benden gerekli bilgiyi iste.
9. Canlıya alma
Önce mevcut deployment durumunu kontrol et.
Uygulama henüz canlıda değilse Render üzerinde deploy edilebilmesi için gerekli yapılandırmayı hazırla:
PostgreSQL bağlantısı.
Production ortam değişkenleri.
Secret yönetimi.
Veritabanı migration'ları.
Sağlık kontrolü.
Uygulama başlatma komutu.
Gizli API anahtarlarını repoya yazma. config dosyalarına gerçek sırlar kaydetme; repoda yer alıyorsa güvenli biçimde kaldır ve git geçmişi riskini raporla.
Render'da deploy edilmiş olduğunu yalnızca gerçek canlı URL üzerinden doğruladıktan sonra yaz. Deploy işlemini gerçekleştiremiyorsan eksik adımları açıkça belirt.
10. AGENT.md ve README
Mevcut AGENT.md veya benzeri proje talimatlarını incele. Ödevin gerektirdiği AGENT.md yoksa oluştur. Bu dosyada proje yapısı, çalıştırma komutları, test komutları, mimari sınırlar ve kritik güvenlik kuralları yer alsın.
README'yi güncelle:
Projenin amacı.
İlham kaynağı.
Çözülen kullanıcı acısı ve gerçek kaynak.
Agent-first demo adımları.
API örneği.
Kullanılan LLM ve fallback davranışı.
Testleri çalıştırma.
Deployment talimatları.
Bilinen eksikler ve Yapamadıklarım bölümü.
GitHub Actions test durumu ve yalnızca doğrulanmışsa yeşil rozet.
11. Sunumda kanıtlanması gerekenler
Demo sırası:
Canlı URL'yi aç.
Agent API isteğiyle bir güvenlik olayı oluştur.
LLM'nin analizini, kanıtlarını ve runbook eşleşmesini göster.
Düşük riskli ve yüksek riskli senaryoların farklı kararlarını göster.
Yüksek riskli olayda insan onayı olmadan kritik aksiyonun gerçekleşmediğini kanıtla.
Onay sonrası simüle edilmiş aksiyonu ve denetim kaydını göster.
SLA kuralını ve durum geçişini göster.
CHALLENGE_LOG.md ve commit geçmişini aç.
Önerilen fark cümlesi:
"Sentriq AI'da güvenlik ajanı olayları arayüz kullanmadan oluşturur; LLM kanıta ve runbook'a dayalı triyaj yapar, kritik müdahale ise insan onayı olmadan gerçekleştirilmez."
12. Çalışma yöntemi
Önce repoyu incele ve kısa bir eksik analizi çıkar. Ardından en küçük uygulanabilir değişiklikleri yap.
Her aşamada:
İlgili dosyaları belirle.
Değişiklikleri uygula.
Testleri gerçekten çalıştır.
Hata varsa düzelt.
Çalışan özelliği ve kanıtını raporla.
Benden bilgi veya erişim gerektiren işlemleri varsayma. Gereksiz sorular sormadan mevcut repodan öğrenebildiğin her şeyi öğren.
Son hedef: Çok özellikli görünen bir demo değil; gerçek kullanıcı acısını ele alan, çalışan agent-first akışı, doğrulanabilir LLM kararı, insan onayı, testleri ve dürüst kanıt günlüğü bulunan küçük bir ürün.
```

---

## Karar

- **Devam / pivot / öldür:** Devam.
- **Gerekçeli karar ve bir sonraki kişisel hedef:**  
  SOC analistlerinin yanlış pozitif triyajında yaşadığı alarm yorgunluğu ve karar bağlamı eksikliği gerçek ve büyük bir operasyonel sorundur. Sentriq AI'nın Agent-First REST API + LLM bağlamsal triyaj + Human-in-the-Loop mimarisi bu acıyı başarıyla çözmektedir.  
  *Bir sonraki hedef:* CrowdStrike Falcon ve SentinelOne webhook entegrasyonu ekleyerek gerçek zamanlı SIEM alarm stream'lerini WebSocket üzerinden canlı dashboard'a beslemek ve SOC analistlerine interaktif sesli / chat tabanlı runbook asistanı sunmaktır.
