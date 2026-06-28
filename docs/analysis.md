# OBSIDIAN PROTOCOL — Operatör Değerlendirmesi
### Gerçek Tehdit Verisi ile Operasyon Deneyiminin Karşılaştırılması

> Bu dosyayı doldurmadan önce [`docs/threat-intelligence.md`](threat-intelligence.md)'yi
> oku — orada AndroxGh0st botnet kampanyası, hedeflenen sektörler ve
> PwnKit'in 13 yıllık zaman çizelgesi gibi gerçek veriler var.

## 1. Gerçek Veri Bulguları (threat-intel/cve_intel_output.json'dan)

| CVE | CVSS Skoru | KEV'de mi? | KEV Ekleniş Tarihi | Bilinen Botnet | 2024 Hedef Sektör |
|---|---|---|---|---|---|
| CVE-2021-41773 | | | | | |
| CVE-2021-42013 | | | | | |
| CVE-2021-4034 | | | | | |

_(Bu tabloyu `fetch_cve_intel.py` çalıştırdıktan sonra gerçek verilerle doldur.)_

## 2. Resmi Risk Değerlendirmesi vs. Pratik Deneyim

**Soru 1:** CVSS skoru ile senin exploitation deneyiminin zorluk seviyesi
örtüşüyor mu? Kritik/yüksek skorlu bir zafiyeti gerçekten "kritik"
zorlukta mı buldun, yoksa beklediğinden daha kolay/zor mu oldu?

_(cevabın)_

**Soru 2:** KEV kataloğunun "additive" (asla silinmeyen) yapısı, 2021'de
bulunan bu CVE'lerin 2026'da hâlâ neden tehdit oluşturduğunu nasıl
açıklıyor? Kendi lab deneyimin, eski bir CVE'nin neden hâlâ "kolay
hedef" olduğunu somut olarak gösterdi mi?

_(cevabın)_

**Soru 3:** Bu CVE zincirinin tek bir adımı (sadece RCE veya sadece
priv-esc) yerine, ikisinin birleşimi neden gerçek dünyada daha
gerçekçi bir saldırı senaryosu temsil ediyor?

_(cevabın)_

**Soru 4:** AndroxGh0st botnetinin 2024'te Finansal Hizmetler ve İş
sektörünü 30.000+ siteyle hedeflediğini biliyoruz. Senin lab
deneyiminde bu zincirin ne kadar "kolay" veya "zor" olduğunu düşünürsek,
bu ölçekteki bir kampanyanın varlığını **zafiyetin kolaylığı** mı yoksa
**yamasız sistem sayısının çokluğu** mu daha çok açıklıyor? İkisi
arasındaki farkı kendi deneyimine dayanarak tartış.

_(cevabın)_

## 3. Savunma Önerileri (Defensive Takeaway)

Bu lab'dan çıkardığın, gerçek bir ortamda bu zinciri önlemek için
alınabilecek 3 somut önlem:

1.
2.
3.
