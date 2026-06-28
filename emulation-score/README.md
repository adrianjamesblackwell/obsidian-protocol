# ADVERSARY EMULATION QUALITY SCORE
### OBSIDIAN PROTOCOL / Red Team Operasyonunun Kalitesini Ölçmek

## Problem

Kurumlar Red Team operasyonu yapar ama operasyonun **kalitesini**
ölçmez. "Red Team yaptık" ≠ "iyi bir Red Team operasyonu yaptık."

## Dört Boyut

| Boyut | Ölçer | Kaynak |
|---|---|---|
| Attack Diversity | Kaç farklı MITRE technique kullanıldı | Correlation Engine |
| MITRE Matrix Coverage | Bunların 216 tekniğin tamamına oranı | Correlation Engine |
| Noise Level | Operasyon ne kadar "odaklı" (az+yüksek-confidence) | Correlation Engine confidence skorları |
| Detection Success | WARDEN bu emulasyonu ne ölçüde yakaladı | Purple Team |

## Bu Projenin Kendi Notu: "C"

OBSIDIAN PROTOCOL'ün kendi emulation skoru bilinçli olarak düşük
çıkıyor (Coverage %1.39, genel not "C") — bu bir hata değil, **dürüst
bir ölçüm**: proje sadece 2 CVE/3 teknik kapsıyor, MITRE'nin 216
tekniğinin tamamına göre bu küçük bir kapsam. Bu motor, kendi
kapsamını şişirip yapay olarak yüksek not vermek yerine gerçek oranı
gösteriyor.

## Kullanım

```bash
python3 emulation-score/emulation_score.py
```

## Bilinen Sınırlama

`compute_noise_level` basit bir confidence-oranı sezgiselidir - gerçek
"gürültü" ölçümü (örn. operasyonun SIEM'de kaç farklı alarm tetikledi,
analist triage süresi) çok daha zengin bir veri seti gerektirir. Bu
motor, var olan Correlation Engine confidence verisinden türetilebilen
basit bir proxy kullanıyor.
