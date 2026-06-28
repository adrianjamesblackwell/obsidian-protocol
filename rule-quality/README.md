# RULE QUALITY ANALYZER
### OBSIDIAN PROTOCOL / "Kuralımız Var" ile "Kuralımız İyi" Arasındaki Fark

## Problem

Sigma kuralı yazmak kolaydır; iyi bir Sigma kuralı yazmak zordur.
Kurumlar genelde "X tane Sigma kuralımız var" sayısıyla övünür ama
bu kuralların false-positive riski, performans maliyeti veya
eksik alanları hakkında sistematik bir değerlendirme yapılmaz.

## Çözüm

`analyze_rules.py`, `detection/sigma/*.yml` dosyalarını statik olarak
analiz eder ve her kural için beş boyutta puan üretir:

| Boyut | Ne Ölçer |
|---|---|
| False Positive Risk | `falsepositives` alanının doluluğu ve detay seviyesi |
| Performance Cost | `contains`/`regex` deseni sayısı (tam eşleştirmeye göre maliyet) |
| Coverage | MITRE technique + CVE + dış referans yoğunluğu |
| Missing Fields | Sigma spesifikasyonunun zorunlu/önerilen alanları |
| Recommendations | Yukarıdaki dört boyuttan türetilen somut iyileştirme önerileri |

## Kullanım

```bash
python3 rule-quality/analyze_rules.py
```

## Kendi Kuralımızı Kendi Aracımızla Test Ettik

Bu motor, projenin kendi WARDEN modülündeki iki Sigma kuralına karşı
çalıştırıldı — gerçek çıktı `rule-quality/output/rule_quality_report.json`'da.
Bu "kendi ürettiğimiz şeyi kendi standardımızla denetlemek" pratiği,
kalite güvencesinin temel bir ilkesidir.

## Bilinen Sınırlama

Performans maliyeti tahmini basit bir sezgisel (contains/regex sayma)
— gerçek bir SIEM'in query planner'ı (örn. Splunk'ın search head
maliyet tahmini) çok daha karmaşık faktörlere (index boyutu, zaman
aralığı, alan kardinalitesi) bakar. Bu motor "yaklaşık bir sinyal"
veriyor, kesin bir benchmark değil.
