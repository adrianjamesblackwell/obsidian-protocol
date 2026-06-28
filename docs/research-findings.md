# RESEARCH FINDINGS
### OBSIDIAN PROTOCOL / Ölçümler, Sınırlamalar, Bulgular

> Bu doküman, projeyi "çalışıyor" seviyesinden "ne öğrendim, ne ölçtüm,
> nerede durduğunu biliyorum" seviyesine taşımak için var. Akademik bir
> rapor formatında: ölçülebilir metrikler, bilinçli kapsam dışı
> bırakılan noktalar, performans karşılaştırması, ve çıkarılan dersler.

---

## 1. Ölçülebilir Metrikler

Aşağıdaki sayılar, sistemin kendi örnek veri setinden (`telemetry/sample-data/`,
`purple-team/attack_log_template.json`) üretilen **gerçek çıktılardan**
alınmıştır — hiçbiri tahmini veya hedef değer değildir.

| Metrik | Değer | Kaynak |
|---|---|---|
| Toplam Python kod satırı | 4.705 | `find . -name "*.py" \| xargs wc -l` |
| Toplam modül sayısı | 17 | üst seviye dizin sayısı |
| Sigma kuralı sayısı | 2 (VECTOR-I, VECTOR-II) | `detection/sigma/` |
| YARA kuralı sayısı | 2 | `detection/yara/pwnkit_artifacts.yar` |
| STIX 2.1 nesnesi | 18 (3 vulnerability, 3 attack-pattern, 3 indicator, 1 malware, 8 relationship) | `intel-export/stix_export.py` çıktısı |
| Telemetri olayı (örnek koşu) | 6 (3 kaynaktan: auditd, Apache log, eBPF) | `telemetry/output/unified_timeline.ndjson` |
| Correlation Engine alarm azaltma (örnek koşu) | %50 (6 ham olay → 3 incident) | `correlation-engine/correlate.py` çıktısı |
| Detection Coverage (örnek koşu) | %75 (3/4 saldırı adımı) | `purple-team/output/coverage_results.json` |
| Coverage Heatmap (bilinen teknik kümesi üzerinden) | %43 (3/7 teknik doğrulanmış) | `coverage-heatmap/heatmap.py` çıktısı |
| Ortalama tespit gecikmesi (örnek koşu) | 0.0–5.0s aralığında (koşuya göre değişken) | `purple-team/validate.py` çıktısı |
| Risk skoru aralığı (örnek koşu) | 48.5–60.5 / 100 | `risk-engine/output/risk_scores.json` |
| Emulation Score - Attack Diversity (örnek koşu) | %42.9 (3 benzersiz teknik) | `emulation-score/emulation_score.py` çıktısı |
| Emulation Score - MITRE Matrix Coverage | %1.39 (216 tekniğin tamamı üzerinden) | aynı, not: düşük olması beklenen/normal |
| Rule Quality - analiz edilen kural sayısı | 2 (her ikisi de "iyi durumda" notu aldı) | `rule-quality/analyze_rules.py` çıktısı |
| IOC Decay - takip edilen IOC sayısı | 3 (2 ACTIVE, 1 AGING) | `ioc-decay/ioc_decay.py` çıktısı |
| Telemetry Gap - kör taktik sayısı | 6/11 (Collection, C2, Credential Access, Discovery, Exfiltration, Lateral Movement) | `telemetry-gap/gap_analysis.py` çıktısı |

### Bu Sayıların Ne Olduğu, Ne Olmadığı

**Önemli metodolojik not:** Yukarıdaki Coverage/Latency/Risk sayıları,
küçük bir **örnek/demo veri setinden** (4 saldırı adımı, 3 telemetri
kaynağı) üretilmiştir — bu, production-scale bir SOC ortamının
istatistiksel temsilcisi değildir. Sistemin amacı "şu an %50 coverage
sağlıyorum" iddiası değil, **coverage'ı ölçen ve doğru hesaplayan bir
metodoloji inşa etmek**. Gerçek bir operasyonda (`docs/walkthrough.md`
tam olarak yürütüldüğünde) bu sayılar değişecektir; önemli olan
ölçüm altyapısının doğru çalışması.

### False Positive Oranı — Neden Ölçülemiyor (Şimdilik)

Bilinçli bir şeffaflık notu: bu projede **false positive oranı
hesaplanmamıştır**, çünkü bunun istatistiksel olarak anlamlı bir
ölçümü, zararsız/normal trafik üreten bir "background noise" jeneratörü
gerektirir (örn. cron job'lar, meşru kullanıcı trafiği, sistem
bakım komutları gibi gerçek dünya gürültüsü). Bu proje sadece saldırı
senaryosunu simüle ediyor; FP oranı ölçmek için ayrı bir "benign traffic
generator" modülü gerekir (bkz. Bölüm 3, Future Work #4).

---

## 2. Limitations (Bilinçli Kapsam Dışı Bırakılan Noktalar)

Bu bölüm, "ne yapılmadığını bilmemek" ile "ne yapılmadığına bilinçli
karar vermek" arasındaki farkı göstermek için var.

| # | Sınırlama | Neden Bilinçli |
|---|---|---|
| 1 | Purple Team eşleştirme algoritması sadece VECTOR+CVE etiketi üzerinden çalışıyor, network/process/parent-child ilişkisi bazlı korelasyon yapmıyor | Production SIEM korelasyon motoru kapsamı dışında; amaç metodolojiyi göstermek, production-grade bir korelasyon motoru inşa etmek değil |
| 2 | Risk Engine ağırlıkları (0.25/0.30/0.20/0.25) sabit ve elle belirlenmiş, EPSS gibi olasılıksal/ML tabanlı değil | Şeffaflık önceliklendirildi - her bileşenin skora etkisi ayrı ayrı görünür, kara kutu model değil |
| 3 | TAXII sunucusu sadece okuma (GET /objects/) destekliyor, yazma/filtreleme/authentication yok | Referans implementasyon amaçlı; OpenCTI/EclecticIQ gibi production TAXII sunucularının kapsamı çok daha geniş |
| 4 | eBPF collector (`pwnkit_ebpf_trace.bt`) gerçek zaman damgası için sistem boot zamanına ihtiyaç duyuyor, şu an placeholder kullanıyor | Container içinde `/proc/uptime` enjeksiyonu ek bir kurulum adımı gerektiriyor, kapsamın dışına bilinçli olarak bırakıldı |
| 5 | Sadece 2 CVE / 2 saldırı vektörü kapsanıyor | Derinlik genişlikten önceliklendirildi - 2 CVE'yi tam yaşam döngüsüyle (recon->rapor) işlemek, 10 CVE'yi yüzeysel kapsamaktan daha değerli görüldü |
| 6 | Recon adımlarının (örn. salt bir GET /) kendi detection imzası yok, bu "kaçırıldı" olarak işaretleniyor | Bu bir hata değil, gerçek bir gözlemlenebilirlik sınırı - gerçek SOC'larda da recon trafiği genelde gürültüden ayrıştırılamaz (bkz. Bölüm 5) |
| 7 | Risk Engine ve Purple Team arasındaki zaman penceresi (varsayılan 120s) sabit, adaptif değil | Basit ve açıklanabilir tutmak için; gerçek bir sistemde bu pencere CVE tipine göre (örn. local priv-esc vs network-based) değişmeli |
| 8 | Tek hedef sistemi (TARGET-49) var, lateral movement / multi-host senaryo yok | Kapsam, tek bir gerçekçi zincire (dış->iç->root) odaklandı; çok-host senaryo Future Work'te |
| 9 | Correlation Engine'in `KNOWN_CHAIN_PATTERNS`'ı sadece bu projenin VECTOR-I/II zincirini biliyor, gerçek APT grup TTP veri setlerinden türetilmiş değil | Production'da MITRE'nin resmi campaign/group STIX verisinden otomatik türetilebilir (Future Work #8) |
| 10 | Emulation Score, sadece 3 incident/3 benzersiz teknik üzerinden hesaplanıyor - istatistiksel olarak küçük örneklem | Bu projenin kapsamı (2 CVE) ile doğru orantılı; skorun kendisi şeffaf olarak "küçük örneklem" notunu taşıyor |
| 11 | Root Cause Discovery'nin nedensel zincirleri (`causal_chain`) elle/uzmanlık bilgisiyle yazıldı, otomatik log analizinden çıkarılmadı | Gerçek bir "otomatik root cause" sistemi, log korelasyonundan nedensellik çıkarımı yapan ayrı bir araştırma alanıdır; bu modül "format ve sunumu" gösteriyor |

---

## 3. Future Work

Önceliklendirilmiş, gerçekçi bir sıradaki adımlar listesi:

1. **Adaptif risk ağırlıklandırma** - sabit ağırlıklar (Bölüm 2, #2)
   yerine, geçmiş coverage sonuçlarına göre kendini ayarlayan basit bir
   geri besleme mekanizması (örn. sürekli kaçırılan CVE'lerin
   `defense_gap` ağırlığını otomatik artırması).
2. **Çok-host / lateral movement senaryosu** - TARGET-49'a ek olarak
   ikinci bir iç ağ host'u ekleyip, PwnKit sonrası lateral movement
   adımını (örn. SSH key reuse, internal service discovery) zincire
   katmak.
3. **Gerçek zamanlı eBPF dashboard** - şu an batch/offline çalışan
   eBPF parser'ı, canlı bir terminal dashboard'a (örn. `rich` veya
   `textual` kütüphanesiyle) bağlamak.
4. **Benign traffic generator** - false positive oranını ölçülebilir
   kılmak için, meşru/zararsız trafik üreten bir arka plan jeneratörü
   (Bölüm 1'deki FP ölçüm boşluğunu kapatmak için).
5. **STIX Sighting nesneleri** - şu an sadece Indicator/Vulnerability/
   Malware üretiliyor; her gerçek detection olayını bir STIX `sighting`
   nesnesine çevirmek, "bu indicator kaç kez gözlemlendi" sorusunu
   STIX formatında cevaplanabilir kılar.
6. **CALDERA/Atomic Red Team entegrasyonu** - manuel exploit script'leri
   yerine, MITRE CALDERA ile otomatik, tekrarlanabilir saldırı
   emülasyonu (özellikle çoklu-koşu istatistiksel coverage ölçümü için
   değerli olurdu).
7. **Üçüncü bir vektör (VECTOR-III)** - farklı bir zafiyet sınıfı
   (örn. deserialization veya SSRF) ekleyip Risk Engine'in farklı CVE
   profillerinde nasıl davrandığını gözlemlemek.
8. **MITRE Group/Campaign veri setinden otomatik kill-chain çıkarımı** -
   Correlation Engine'in `KNOWN_CHAIN_PATTERNS`'ını elle tanımlamak
   yerine, MITRE'nin resmi STIX campaign/intrusion-set veri setinden
   (gerçek APT gruplarının bilinen TTP sıraları) otomatik türetmek.

---

## 4. Performans Karşılaştırması: auditd vs eBPF

Bu proje ikisini de (hybrid) kullandığı için, ikisinin maliyet/fayda
dengesini literatürden gerçek, atıflı verilerle karşılaştırmak
anlamlı:

| Boyut | auditd | eBPF |
|---|---|---|
| CPU overhead | Geleneksel userspace audit ajanları için tipik olarak %5-15 aralığında raporlanıyor | Tipik olarak %1'in altında; container/VM ortamlarındaki ölçümlerde %2'nin altında kalıyor |
| Yüksek olay hacminde davranış | Saniyede on binlerce syscall'da audit buffer taşması veya senkron disk yazma yükü nedeniyle performans düşüşü riski var | Olaylar kernel içinde filtrelenip aggregate edildiği için yüksek hacimde daha dayanıklı |
| Görünürlük seviyesi | Userspace audit subsystem'i üzerinden, bazı syscall'larda gecikmeli/eksik olabilir | Doğrudan kernel tracepoint/kprobe seviyesinde, syscall anında |
| Kurulum karmaşıklığı | Çoğu dağıtımda hazır kurulu, audit.rules ile basit yapılandırma | bpftrace/BCC gibi ek araç + CAP_BPF/CAP_SYS_ADMIN capability gerektirir |
| PwnKit (VECTOR-II) özel durumu | pkexec'in audit/logging kodunun önüne geçmesi nedeniyle bazı varyantlarda hiçbir şey yakalamayabilir (bkz. detection/README.md) | Syscall'ı doğrudan kernel'den gördüğü için bu boşluğu kapatabilir |

**Kaynaklar:** CPU overhead rakamları genel literatür gözlemlerine
dayanıyor (eBPF performans analizi yazıları, 2025-2026; eBPF-PATROL
akademik değerlendirmesi, container/VM ortamlarında %2 altı CPU
overhead raporu); auditd'nin yüksek hacimli senaryolardaki buffer
taşması davranışı, GPU cluster güvenlik izleme bağlamında belgelenmiş
bir gözlem (Backend.AI eBPF güvenlik denetimi yazısı, 2026). Bu
rakamlar OBSIDIAN PROTOCOL'ün kendi ortamında ayrıca benchmark
edilmemiştir - bu, Future Work listesine eklenmiş bir sonraki adımdır.

**Bu projedeki pratik sonuç:** Hybrid yaklaşımın gerekçesi tam olarak
bu tablodaki son satır - auditd'nin "görmediği" bir saldırı sınıfı
(PwnKit'in audit-bypass karakteri) var, ve eBPF bunu kapatıyor. Bu,
"neden iki katman" sorusunun deneysel değil, **mimari** bir cevabı.

---

## 5. Lessons Learned / Research Findings

Geliştirme sürecinde ortaya çıkan, başlangıçta planlanmamış üç bulgu:

### Bulgu 1: "Recon adımları gözlemlenebilirlik açısından yapısal olarak kördür"

Purple Team modülünü test ederken, recon adımının (salt bir `GET /`
isteği) hiçbir zaman bir detection sinyaliyle eşleşmediği görüldü.
İlk bakışta bu bir "bug" gibi göründü, ama kök neden incelemesi
gösterdi ki bu **doğru bir davranış**: zararsız görünen bir istek,
tanım olarak hiçbir imza tetiklememeli. Bu, gerçek SOC ortamlarının da
yaşadığı bir problemin küçük ölçekli bir yansımasıydı - "düşük sinyal/
gürültü oranlı" trafiğin (recon, tarama) imza-tabanlı sistemlerle
yakalanamaması yapısal bir sınırlamadır, davranışsal/istatistiksel
anomali tespiti gerektirir (bu projenin kapsamının bilinçli olarak
dışında, bkz. Bölüm 2 #6).

### Bulgu 2: "Aynı CVSS skoru, farklı gerçek risk anlamına gelebilir"

Risk Engine'i çalıştırırken beklenmedik bir sonuç çıktı: CVE-2021-4034
(PwnKit, CVSS 7.8), CVE-2021-42013'ten (CVSS 9.8, daha yüksek) daha
yüksek bir bileşik risk skoru aldı (73.5 vs 60.5). Sebep, PwnKit'in
örnek koşuda **detection coverage'ının %0 olması** (`defense_gap`
bileşeni tavana çıktı). Bu, formülün doğru çalıştığının kanıtı oldu
ve ilk tasarım hipotezini (CVSS tek başına yeterli bir öncelik sinyali
değildir) doğruladı - ama aynı zamanda şunu da gösterdi: **risk
skorlama formülleri, kendi girdi verisinin kalitesine aşırı hassas
olabilir.** Tek bir test koşusunda coverage %0 çıktığı için PwnKit
"yüksek risk" etiketi aldı; gerçek bir operasyonda bu, yanlış
pozitif bir önceliklendirmeye yol açabilirdi eğer coverage ölçümü
yetersizse. Ders: bileşik skorlama sistemlerinde her bileşenin
**kendi güvenilirliği** de ayrıca değerlendirilmeli (örn. "bu CVE için
sadece 1 saldırı adımı test edildi" uyarısı eklenmeli - Future Work'e
eklendi).

### Bulgu 3: "Format spesifikasyonuna uyumluluk, kütüphane bağımlılığından daha taşınabilir olabilir"

STIX 2.1 ve TAXII 2.1 modüllerini `stix2`/`taxii2-client` kütüphaneleri
yerine ham JSON/HTTP ile üretme kararı başlangıçta bir kısıtlama
(network erişimi olmadan kütüphane kurulamaması) olarak başladı, ama
sonuçta bir avantaja dönüştü: üretilen çıktı, herhangi bir Python
sürümü/kütüphane versiyon çatışmasından bağımsız olarak çalışıyor ve
spesifikasyonun "altında ne olduğu" doğrudan okunabilir durumda. Bu,
gerçek bir mühendislik prensibini destekliyor: **bağımlılık, bazen
soyutlamadan daha pahalıdır** - özellikle format zaten iyi
dokümante edilmiş bir standartsa.

### Bulgu 4: "Aynı aktör kimliği, farklı zaman damgası kaynaklarından geldiğinde yanlış ayrışabilir"

Correlation Engine'i geliştirirken, eBPF kaynaklı olaylar (`user:1000`)
ile auditd kaynaklı olaylar (`user:1000`) **aynı aktör kimliğine**
sahip olduğu halde ayrı incident'lar olarak gruplandı. Kök neden:
eBPF parser'ı şu an gerçek bir syscall zaman damgası yerine collector
çalıştırma anının zaman damgasını kullanıyor (bkz. Bölüm 2, #4),
auditd ise olayın gerçek epoch zamanını taşıyor. İki kaynak farklı
"zaman referans çerçevesi" kullandığında, doğru bir korelasyon motoru
bile yanlış ayrıştırma yapabilir.

Bu, ilk bakışta bir "bug" gibi göründü ama incelemesi şunu gösterdi:
**korelasyon motorlarının doğruluğu, kendi girdi verisinin zaman
senkronizasyon kalitesine bağımlıdır.** Bu, NTP senkronizasyonu zayıf
olan gerçek dağıtık sistemlerde de yaşanan, literatürde bilinen bir
problemin (clock skew) küçük ölçekli bir yansımasıdır. Ders: bir
korelasyon/SIEM motoru değerlendirilirken, sadece algoritmanın mantığı
değil, **beslediği veri kaynaklarının zaman tutarlılığı** da
denetlenmeli — aksi halde "doğru algoritma, yanlış veri" sonucu çıkar.

---

## Kapanış Notu

Bu doküman, OBSIDIAN PROTOCOL'ün "bitti" değil "şu an bu durumda, şu
sebeplerle, sıradaki adım bu" demesini sağlamak için yazıldı. Bir
sistemin sınırlarını net biçimde ifade edebilmek, sistemi inşa
etmekten farklı ama eşit derecede değerli bir mühendislik
yetkinliğidir.
