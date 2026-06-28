# INTEL EXPORT
### OBSIDIAN PROTOCOL / STIX 2.1 + TAXII 2.1 Çıktıları

Bu modül, operasyonun ürettiği IOC'leri ve CTI bağlamını **gerçek STIX
2.1 spesifikasyonuna** uyumlu bir bundle olarak dışa aktarır ve bunu
**minimal bir TAXII 2.1 sunucusu** üzerinden servis eder.

## Neden Kütüphanesiz (Ham JSON)

`stix2` Python kütüphanesi yaygın bir araçtır, ama bu modül kasıtlı
olarak ham JSON üretimi kullanıyor — hem ek bağımlılık gerektirmeden
çalışsın hem de "STIX formatının altında ne var" sorusunu doğrudan
gösterilebilir kılsın. Üretilen JSON, OASIS STIX 2.1 spesifikasyonuna
(nesne tipleri, zorunlu alanlar, ID formatı `tip--uuid`) tam uyumludur
ve gerçek bir STIX ayrıştırıcısına (örn. `stix2.parse()`) verilebilir.

## Üretilen STIX Nesneleri

| Tip | Sayı | İçerik |
|---|---|---|
| `vulnerability` | 3 | CVE-2021-41773, CVE-2021-42013, CVE-2021-4034 |
| `attack-pattern` | 3 | T1190, T1059, T1548.001 |
| `indicator` | 3 | Path traversal pattern, PwnKit pkexec pattern, AndroxGh0st .env tarama pattern |
| `malware` | 1 | AndroxGh0st (gerçek, isimli botnet — bkz. docs/threat-intelligence.md) |
| `relationship` | 8 | Yukarıdakileri birbirine bağlayan SRO'lar (`indicates`, `exploits`, `uses`) |

## Kullanım

### STIX Bundle Üretimi

```bash
python3 intel-export/stix_export.py
```

Çıktı: `intel-export/output/obsidian_protocol_bundle.stix2.json`

### TAXII Sunucusunu Başlatma

```bash
python3 intel-export/taxii_server.py
```

```bash
# Discovery
curl http://localhost:8888/taxii2/

# Koleksiyonlar
curl http://localhost:8888/taxii2/api/collections/

# STIX nesneleri
curl http://localhost:8888/taxii2/api/collections/obsidian-protocol-collection-001/objects/
```

### Gerçek Bir STIX İstemcisiyle Tüketim (Örnek)

```python
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v21 import Collection

collection = Collection("http://localhost:8888/taxii2/api/collections/obsidian-protocol-collection-001/")
source = TAXIICollectionSource(collection)
vulns = source.query([Filter("type", "=", "vulnerability")])
```

> Not: yukarıdaki örnek `stix2` ve `taxii2-client` kütüphanelerini
> gerektirir (`pip install stix2 taxii2-client`); bu repo'nun kendisi
> bu kütüphanelere bağımlı değildir.

## Bilinen Sınırlama

`taxii_server.py`, TAXII 2.1'in salt-okunur (read-only) "Get Objects"
akışını uygular. Yazma (POST /objects/), filtreleme query
parametreleri (`added_after`, `match[type]` vb.) ve authentication
desteklenmiyor — bunlar production TAXII sunucularının (örn. OpenCTI,
EclecticIQ) kapsadığı ama bu referans implementasyonun kapsamadığı
özellikler.
