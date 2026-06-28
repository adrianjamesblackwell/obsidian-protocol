# DETECTION COVERAGE HEATMAP
### OBSIDIAN PROTOCOL / "Biz Gerçekten Neyi Görüyoruz?" Sorusunun Cevabı

## Problem

Bir kurum "MITRE ATT&CK kullanıyoruz" der, ama 14 taktik / 216 teknikten
(MITRE Enterprise Matrix v18) kaçını **gerçekten tespit edebildiğini**
söyleyemez. Bu kör nokta, savunma yatırımının nereye gitmesi gerektiği
sorusunu cevapsız bırakır.

## Üç Farklı Coverage Kavramı (Karıştırılmamalı)

| Kavram | Soru | Kaynak |
|---|---|---|
| **Rule Coverage** | Bu teknik için bir Sigma/YARA kuralımız var mı? | `detection/sigma/*.yml` tags alanı |
| **Validated Coverage** | Bu kural GERÇEKTEN bir saldırıyı yakaladı mı? | `purple-team/output/coverage_results.json` |
| **Observed Coverage** | Bu teknik operasyonda hiç gözlendi mi? | `correlation-engine/output/correlated_incidents.json` |

Bu üçünü ayrı tutmak metodolojik olarak kritik: **"kuralımız var" ile
"kural çalışıyor" farklı iddialardır.** Heatmap çıktısında bunu canlı
gösteren bir örnek: Privilege Escalation taktiğinde Rule Coverage %100
(Sigma kuralı var) ama Validated Coverage %0 çıkabilir (test
koşusunda kural tetiklenmedi/zamanlama uyuşmadı) — bu bir hata değil,
sistemin dürtüğü bir gerçek bulgudur.

## Kullanım

```bash
python3 coverage-heatmap/heatmap.py
```

Çıktı: terminal'de ASCII heatmap, `docs/coverage-heatmap.md`'de
Markdown tablo, `coverage-heatmap/output/coverage_heatmap.json`'da
ham veri.

## Bilinen Sınırlama

`TECHNIQUE_TO_TACTIC` tablosu şu an bu projenin bildiği 7 tekniği
kapsıyor — MITRE'nin tam 216 teknikli STIX veri setini indirip
otomatik eşleme yapmıyor. Bu yüzden yüzdeler "MITRE'nin tamamı
üzerinden" değil, "bu projenin etiketlediği teknik alt kümesi
üzerinden" hesaplanıyor — rapor bunu açıkça belirtir, gizlemez.
Gerçek bir üretim sisteminde bu tablo
[attack.mitre.org/resources/attack-data-and-tools](https://attack.mitre.org/resources/attack-data-and-tools/)
adresindeki resmi STIX bundle'dan otomatik türetilir (Future Work).
