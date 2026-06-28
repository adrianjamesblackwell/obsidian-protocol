# SIGINT MODÜLÜ — Tehdit İstihbaratı Analizi
### OBSIDIAN PROTOCOL / Bu CVE'ler Gerçekte Kim Tarafından, Nasıl Kullanılıyor

> Bu bölüm, `threat-intel/fetch_cve_intel.py`'nin çektiği NVD/KEV
> verisinin **üzerine** kurulu bir analiz — sadece "CVSS skoru şu"
> demek yerine, gerçek kampanya verisiyle "kim, ne zaman, hangi
> sektörde" sorularını cevaplıyor. Tüm bulgular halka açık, isimli
> kaynaklara (CISA, FBI, Imperva Threat Research) dayanıyor.

---

## 1. CVE-2021-41773 / CVE-2021-42013 — Gerçek Kampanya Verisi

### Resmi durum (CISA KEV)

CISA, bu zafiyeti hem KEV kataloğuna ekledi hem de resmi notunda özel
bir uyarı bıraktı: orijinal CVE-2021-41773 patch'i yetersiz kaldığı
için asıl düzeltmenin CVE-2021-42013'te aranması gerektiğini
belirtiyor. Ayrıca CISA, bu CVE'yi **Çin destekli tehdit aktörlerinin
en sık exploit ettiği zafiyetler listesinde** sayıyor — bu, sıradan
bir "eski CVE" değil, devlet destekli aktörlerin bile hâlâ kullandığı
bir araç olduğu anlamına geliyor.

### AndroxGh0st Botnet — FBI/CISA Ortak Danışma Belgesi (AA24-016A)

Ocak 2024'te FBI ve CISA, AndroxGh0st adlı bir botnet için ortak bir
danışma belgesi (AA24-016A) yayınladı. Bu botnet:

- **Python tabanlı**, ilk olarak Aralık 2022'de Lacework tarafından tespit edildi
- Laravel framework kullanan web siteleri tarıyor, `.env` dosyalarındaki
  AWS, Microsoft 365, SendGrid, Twilio gibi servislerin kimlik bilgilerini
  çalmaya çalışıyor
- **CVE-2021-41773'ü doğrudan kullanıyor**: Apache 2.4.49/2.4.50 çalıştıran
  sunucuları tarayıp, path traversal ile dizin dışına çıkıp hassas
  dosyalara erişmeye çalışıyor
- Aynı zincirde **CVE-2017-9841** (PHPUnit RCE) ve **CVE-2018-15133**
  (Laravel deserialization) de kullanılıyor — yani bu botnet de tek
  CVE'ye güvenmiyor, senin lab'ında yaptığın gibi bir **zincir**
  kullanıyor

### Sektörel Hedefleme — Somut Sayılar (Imperva Threat Research, 2024)

Imperva'nın 2024 verisi şunu gösteriyor: bu CVE'leri (ve ilişkili
PHPUnit/Laravel zafiyetlerini) exploit etmeye çalışan saldırılarda
**30.000'den fazla benzersiz site** hedef alındı, ve bu saldırılar
**ağırlıklı olarak Finansal Hizmetler ve İş (Business) sektörlerinde**
yoğunlaştı.

Bunun pratik anlamı: bu zafiyet "rastgele internet taraması" değil —
saldırganlar, Laravel kullanan ve muhtemelen değerli API key'leri
(AWS, ödeme servisleri) barındıran hedefleri **özellikle** seçiyor.

### Imperva'nın Ek Bulgusu — Zincir Genişlemesi

Imperva, aynı kampanyada beklenmedik bir zafiyetin de (Drupal Core
CVE-2019-6340) kullanıldığını, aynı proxy IP'lerin aynı web shell'i
benzer zaman dilimlerinde dağıttığını tespit etti — yani bu aktörler
zamanla **yeni CVE'ler ekleyerek** zincirlerini genişletiyor, sabit
kalmıyor.

### Malware Payload'ları

İlk dönemde bu CVE, **Linuxsys kripto madenciliği yazılımını**
dağıtmak için kullanıldı. AndroxGh0st kampanyasında ise daha çok
kimlik bilgisi hırsızlığı ve **XMRig cryptominer** dağıtımı için
kullanıldığı gözlendi.

---

## 2. CVE-2021-4034 (PwnKit) — 13 Yıllık Gizli Zafiyet

### Zaman Çizelgesi

| Tarih | Olay |
|---|---|
| Mayıs 2009 | Zafiyetli kod polkit'in ilk public sürümüne giriyor |
| 25 Ocak 2022 | Qualys, zafiyeti kamuya açıklıyor (12+ yıl sonra) |
| 27 Ocak 2022 | İlk halka açık exploit PoC'leri yayılmaya başlıyor |
| 27 Haziran 2022 | CISA, KEV kataloğuna ekliyor |
| 18 Temmuz 2022 | Federal kurumlar için zorunlu düzeltme tarihi |

### Neden Hâlâ Önemli (2026 Perspektifi)

PwnKit'in CVSS skoru 7.8 — kritik değil ama yüksek. Ama gerçek risk
skorundan bağımsız: bu zafiyet **her büyük Linux dağıtımını** etkiledi
ve **hiçbir özel koşul gerektirmiyor** (network erişimi, özel
yapılandırma, kullanıcı etkileşimi yok). Qualys ayrıca, `pkexec`'teki
bu `argc=0` işleme mantığının **benzer SUID binary'lerde de** tekrar
edebilecek bir zafiyet sınıfı olabileceğini not etti — yani PwnKit
izole bir olay değil, bir desenin örneği.

### Local Privilege Escalation'ın Gerçek Dünya Rolü

PwnKit kendi başına uzaktan exploit edilemez (local-only). Bu yüzden
gerçek saldırı zincirlerinde hep bir "önce içeri gir" adımının
**ardından** gelir — tam olarak bu lab'ın simüle ettiği senaryo: dış
yüzeyden RCE (Apache) → local foothold → PwnKit ile root.

---

## 3. Senin Lab Deneyiminle Karşılaştırma

`threat-intel/fetch_cve_intel.py` çalıştırdığında elde edeceğin NVD/KEV
verisini, yukarıdaki gerçek kampanya verisiyle yan yana koy ve
`docs/analysis.md`'deki soruları cevapla. Özellikle şunu düşün:

**Bu lab'da exploit etmenin sana kaç dakika sürdüğü, gerçek dünyada
30.000 sitenin neden hâlâ tarandığını açıklıyor mu?** (İpucu: zorluk
seviyesi ile ölçek arasındaki ilişkiyi düşün — bir zafiyet "kolay"
olduğu için mi yoksa "yamasız sistem sayısı çok" olduğu için mi hâlâ
exploit ediliyor? İkisi farklı şeyler.)

---

## Kaynaklar

- CISA AA24-016A: [Known Indicators of Compromise Associated with Androxgh0st Malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a)
- CISA KEV Catalog: [Apache HTTP Server Path Traversal Vulnerability](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Imperva Threat Research: AndroxGh0st Botnet IOC Analysis (2024)
- Qualys Security Advisory: PwnKit (CVE-2021-4034), 25 Ocak 2022
- Red Hat Product Security: PwnKit Response Timeline
