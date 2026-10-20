# Pain Point Research: Güvenlik Alarmı Manuel İnceleme ve Kök Neden Araştırması Yükü

## 1. Hedef Kullanıcı ve İncelenen Problem
- **Hedef Kullanıcı:** SOC (Security Operations Center) Seviye 1 / Seviye 2 Güvenlik Analistleri ve Olay Müdahale (Incident Response) Uzmanları.
- **Seçilen Acı:** Bir güvenlik tespiti/alarmı oluştuğunda, analistin alarmı tetikleyen süreci, ebeveyn-çocuk işlem ilişkilerini, komut satırı argümanlarını ve olası saldırı kaynağını anlamak için farklı günlükleri (telemetri, süreç ağacı, iç prosedür dokümanları) manuel olarak araştırmak zorunda kalması.
- **Sonuç:** İlk değerlendirme (triage) süresinin uzaması (alarm başına ortalama 15-30 dakika), analistlerin vardiya zamanlarının %50'ye varan kısmını tekrarlayan manuel korelasyona harcaması ve alarm yorgunluğu (alert fatigue).

---

## 2. Kaynak Doğrulama Notları ve Erişim Durumu

### 2.1. Capterra & G2 Kaynakları (Doğrudan Erişim Testi)
- **Capterra CrowdStrike Falcon Reviews:** `https://www.capterra.com/p/147662/CrowdStrike-Falcon/reviews/`
  - *Erişim Durumu:* Otomatik HTTP isteği ile erişim denendi; Cloudflare / bot koruması nedeniyle **HTTP 403 Forbidden** döndü.
  - *Dürüstlük Notu:* Sayfa içeriği bot koruması nedeniyle doğrudan çekilemediği için bu sayfadan hayali alıntı, kullanıcı rolü veya istatistik türetilmemiştir.
- **G2 CrowdStrike Falcon Endpoint Protection Platform Reviews:** `https://www.g2.com/products/crowdstrike-falcon-endpoint-protection-platform/reviews`
  - *Erişim Durumu:* Otomatik HTTP isteği ile erişim denendi; Cloudflare / bot koruması nedeniyle **HTTP 403 Forbidden** döndü.
  - *Dürüstlük Notu:* Doğrudan çekilemediği için hayali kullanıcı yorumu üretilmemiştir.

### 2.2. Doğrulanan Açık Güvenlik Araştırmaları ve SOC Verileri
Capterra ve G2 doğrudan erişim engeli sonrasında, aynı acıyı doğrulayan erişilebilir bağımsız sektör raporları ve dokümantasyonlar taranmıştır:

1. **Panther Security - SOC Triage & Alert Investigation Analysis**
   - *Kaynak:* [panther.com](https://panther.com)
   - *Bulgu:* Güvenlik analistleri her vardiyada saatlerini kullanıcı bağlamı, tehdit istihbaratı ve dağınık günlükleri çapraz sorgulayarak manuel triaja harcamaktadır. Kapsamlı bir manuel araştırma alarm başına 15 ila 30 dakika sürmektedir.
   - *Etki:* Yüksek hacim karşısında analistlerin alarmları derinlemesine analiz edememesi veya gecikmeli müdahale riski doğmaktadır.

2. **Abnormal Security & Strike48 SOC Productivity Studies**
   - *Kaynak:* [abnormal.ai](https://abnormal.ai), [strike48.com](https://strike48.com)
   - *Bulgu:* SOC analistlerinin mesaisinin %50'ye yakını alarmları manuel olarak sınıflandırmak ve yanlış pozitifleri ayıklamakla geçmektedir.
   - *Etki:* Alarm yorgunluğu (alert fatigue) ve tükenmişlik; kritik olayların gözden kaçması.

3. **TrustRadius & CrowdStrike Community / Telemetry Workflow Discussions**
   - *Kaynak:* TrustRadius CrowdStrike Falcon İncelemeleri & r/crowdstrike topluluk tartışmaları
   - *Bulgu:* Falcon Process Tree (süreç ağacı), IOA (Indicators of Attack) ve Real Time Response (RTR) güçlü araçlar sunsa da, analistlerin tespit edilen şüpheli süreçlerin (örn. LOLBins - Living off the Land Binaries, PowerShell, WMI) meşru bir yönetim işlemi mi yoksa saldırı mı olduğunu anlamak için dahili prosedür ve bilgi tabanlarını manuel taramaları gerekmektedir.

---

## 3. Sentriq AI Çözüm Hipotezi ve Sınırları

- **Vaat:** Sentriq AI, tespitin temel ayrıntılarını (süreç adı, hash, komut satırı, ana makine, kullanıcı, IP) sentetik kanıtlarla birleştirir. Bilgi tabanındaki (runbook, playbooks, MITRE teknik dokümanları) ilgili kısımları RAG ile arar. AI Ajanı aracılığıyla yapılandırılmış bir araştırma özeti üretir:
  - Gözlemlenen kanıtlar (Observed Evidence)
  - Olası nedenler (Possible Causes)
  - Kanıt boşlukları (Evidence Gaps)
  - Önerilen sonraki adımlar (Recommended Steps)
  - Doğrulanabilir kaynak referansları (Source References)
  - Sınırlılıklar ve insan incelemesi gereksinimi (Human-in-the-loop)
- **Sınır:** Sentriq AI analistin yerini almaz; yüksek riskli kararları kendi başına almaz. Kaynak dokümanda bulunmayan iddiaları uydurmaz ("kaynak bulunamadı" uyarısı verir).
