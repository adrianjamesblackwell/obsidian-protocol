# TELEMETRY GAP ANALYZER
### OBSIDIAN PROTOCOL / "Hangi Logumuz Eksik?" Sorusunun Cevabı

## Problem

Kurumlar neyi izlediklerini bilir, neyi **izlemediklerini** bilmez.
Apache logu var, DNS yok; EDR var, Sysmon yok. Her eksik kaynak,
o kaynağın kapsadığı MITRE taktiklerinde bir kör nokta yaratır.

## Çözüm

`gap_analysis.py`, sekiz yaygın telemetri kaynağının hangi MITRE
taktiklerine görünürlük sağladığını bilen bir referans tablo
kullanır, projenin hangilerini gerçekten topladığını kontrol eder,
ve sonucu üç kategoriye ayırır:

- **Tam görünür** — bu taktiği kapsayan tüm kaynaklar toplanıyor
- **Kısmi görünür** — bazı kaynaklar var, bazıları eksik
- **Kör** — bu taktiği kapsayan hiçbir kaynak toplanmıyor

## Gerçek Bulgu (Bu Projenin Kendi Durumu)

OBSIDIAN PROTOCOL şu an **6 MITRE taktiğinde tamamen kör**: Collection,
Command and Control, Credential Access, Discovery, Exfiltration,
Lateral Movement. Bu beklenen bir sonuç — proje VECTOR-I/II'nin
kapsadığı Initial Access/Execution/Privilege Escalation'a odaklandı,
ağ/EDR seviyesi telemetri bilinçli olarak kapsam dışı bırakıldı
(bkz. `docs/research-findings.md` Limitations #8).

## Önceliklendirme Mantığı

Eksik kaynaklar, **kapattıkları kör taktik sayısına** göre sıralanır
— "en fazla kör noktayı tek yatırımla kapatan kaynak" önce önerilir.
Bu projenin kendi çıktısında bu, NetFlow'u (4 kör taktik) EDR'dan
(3) ve DNS'ten (2) önce önerdi.

## Kullanım

```bash
python3 telemetry-gap/gap_analysis.py
```

## Bilinen Sınırlama

`TELEMETRY_SOURCE_COVERAGE` tablosu manuel ve sekiz kaynakla sınırlı.
Gerçek bir üretim sisteminde bu, MITRE'nin resmi "Data Sources"
veri setinden (her teknik için "hangi veri bileşeni gerekli" bilgisi)
otomatik türetilir.
