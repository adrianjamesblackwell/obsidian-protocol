# IOC CONFIDENCE & DECAY ENGINE
### OBSIDIAN PROTOCOL / IOC Yaşlanması Problemi

## Problem

IP, domain ve hash IOC'leri hızla yaşlanır — bugünün kötü amaçlı IP'si
3 ay sonra yeniden tahsis edilmiş meşru bir bulut adresi olabilir.
Kurumlar IOC listelerini biriktirir ama nadiren temizler; bu da
zamanla false-positive oranını artırır.

## Formül

```
confidence = 100 x decay_factor(yas) x frequency_boost x source_boost

decay_factor(yas) = 0.5 ^ (yas_gun / half_life)     [half_life = 90 gun]
frequency_boost    = 1 + log10(frekans) x 0.3          [log-scale, sisirmeyi onler]
source_boost        = 1 + min(kaynak_sayisi-1, 5) x 0.15
```

**Tasarım mantığı:** Üstel azalma (decay) gerçek dünya gözlemini
yansıtıyor — bir IOC'nin güvenilirliği zamanla doğrusal değil, hızlı
başlayıp yavaşlayan bir eğriyle düşer. `frequency_boost` log-scale
çünkü bir IOC'yi 1000 kez görmek onu 100 kez görmekten "10 katı"
güvenilir yapmaz. `source_boost`, frequency'den daha güçlü ağırlıklı
çünkü bağımsız doğrulama, tekrar gözlemden daha güçlü bir sinyaldir.

## Confidence Bantları

| Bant | Skor | Aksiyon |
|---|---|---|
| ACTIVE | ≥70 | Operasyonel kullanıma uygun |
| AGING | 40-69 | Yeniden doğrulama önerilir |
| STALE | 15-39 | Aktif blokta kullanılmamalı |
| EXPIRED | <15 | Bloklisteden çıkarılmalı |

## Kullanım

```bash
python3 ioc-decay/ioc_decay.py
```

## Bilinen Sınırlama

`half_life=90 gün` sabit ve IOC tipine göre değişmiyor — gerçekte bir
IP adresinin yaşlanma hızı bir dosya hash'inden çok farklıdır (IP'ler
yeniden tahsis edilebilir, kripto hash'ler asla "yanlış" hale gelmez).
Üretim sisteminde her `ioc_type` için ayrı bir half_life parametresi
olmalı — bu projede basitlik için tek bir sabit kullanıldı.
