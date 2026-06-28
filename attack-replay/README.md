# ATTACK REPLAY ENGINE
### OBSIDIAN PROTOCOL / Operasyonu Adım Adım Yeniden Oynatmak

## Problem

Olay sonrası incelemeler genelde statik raporlardır. "08:20 recon,
08:28 detection" yazmak ile bunu kronolojik, adım-adım bir replay
olarak göstermek çok farklı bir anlama deneyimi yaratır.

## Çözüm

`replay.py`, telemetri + Purple Team verilerini birleştirip operasyonu
zaman sıralı bir replay olarak sunar. Her adımda: zaman damgası,
önceki adıma göre delta, OFFENSIVE/DETECTED/SIGNAL/INFO etiketi,
vector/CVE/MITRE bilgisi.

## Kullanım

```bash
# Anlık (hepsini hemen yazdır)
python3 attack-replay/replay.py

# Canlı simülasyon (gerçek zaman aralıklarını 10x hızda oynat)
python3 attack-replay/replay.py --live --speed=10
```

## Bilinen Sınırlama

`--live` modu gerçek zaman aralıklarını simüle ediyor ama maksimum
5 saniye bekleme sınırı var (örnek/test verilerinde saatler/günler
arası boşluklar olabileceği için sonsuz beklemeyi önlemek amacıyla).
Gerçek bir operasyon verisiyle (tutarlı, dakikalar içindeki zaman
damgalarıyla) bu sınır devreye girmez.
